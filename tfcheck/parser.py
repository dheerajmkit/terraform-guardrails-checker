"""Minimal HCL-ish block parser for Terraform files (stdlib only).

Supports the constructs security checks need: ``resource``/``data``/
``variable`` blocks with labels, nested blocks, attributes holding
strings/numbers/booleans, lists, object literals, function calls (kept
opaque), and heredoc strings (``<<EOF`` / ``<<-EOF``).

This is not a full HCL2 implementation. Unknown or malformed constructs
are skipped rather than crashing the parser.
"""
import re

SUPPRESS_RE = re.compile(r"#\s*tfcheck:ignore\s*=\s*([A-Za-z0-9_\-, ]+)")


class Block:
    """One parsed block, e.g. resource "aws_s3_bucket" "logs" { ... }."""

    def __init__(self, type_, labels, line):
        self.type = type_
        self.labels = labels
        self.attrs = {}
        self.blocks = []
        self.line = line

    @property
    def name(self):
        """Dotted resource name, e.g. aws_s3_bucket.logs."""
        if self.type == "resource" and len(self.labels) >= 2:
            return f"{self.labels[0]}.{self.labels[1]}"
        return ".".join([self.type] + [str(label) for label in self.labels])

    def nested(self, block_type):
        """Nested blocks of the given type (e.g. "ingress")."""
        return [b for b in self.blocks if b.type == block_type]

    def __repr__(self):  # pragma: no cover - debugging helper
        return f"Block({self.name} line={self.line})"


def find_suppressions(text):
    """Map line number -> set of suppressed rule ids from tfcheck comments.

    A ``# tfcheck:ignore=RULE-1,RULE-2`` comment applies to a block when it
    sits on the block's own opening line or on the line directly above it.
    """
    found = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        match = SUPPRESS_RE.search(line)
        if match:
            rules = {r.strip() for r in match.group(1).split(",") if r.strip()}
            found.setdefault(lineno, set()).update(rules)
    return found


def _tokenize(text):
    """Single-pass tokenizer; returns a list of (kind, value, line)."""
    tokens = []
    i, n, line = 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r":
            i += 1
            continue
        if ch == "#":  # line comment
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":  # // comment
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":  # /* */ comment
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                if text[i] == "\n":
                    line += 1
                i += 1
            i += 2
            continue
        if ch == '"':  # quoted string
            j = i + 1
            buf = []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    esc = text[j + 1]
                    buf.append({"n": "\n", "t": "\t", "r": "\r", '"': '"',
                                "\\": "\\", "$": "$"}.get(esc, esc))
                    j += 2
                else:
                    if text[j] == "\n":
                        line += 1
                    buf.append(text[j])
                    j += 1
            tokens.append(("STRING", "".join(buf), line))
            i = j + 1
            continue
        if ch == "<" and i + 1 < n and text[i + 1] == "<":  # heredoc
            j = i + 2
            if j < n and text[j] == "-":
                j += 1
            k = j
            while k < n and (text[k].isalnum() or text[k] == "_"):
                k += 1
            terminator = text[j:k]
            while k < n and text[k] != "\n":  # rest of the marker line
                k += 1
            k += 1
            start = k
            while True:
                eol = text.find("\n", k)
                if eol == -1:
                    eol = n
                if text[k:eol].strip() == terminator:
                    body = text[start:k]
                    k = eol + 1
                    break
                k = eol + 1
                if k >= n:
                    body = text[start:k]
                    break
            line += body.count("\n")
            tokens.append(("STRING", body, line))
            i = k
            continue
        if ch.isalpha() or ch == "_":  # identifier (dots allowed: var.x)
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_-."):
                j += 1
            tokens.append(("IDENT", text[i:j], line))
            i = j
            continue
        if ch.isdigit() or (ch == "-" and i + 1 < n
                            and text[i + 1].isdigit()):  # number
            j = i
            while j < n and (text[j].isdigit() or text[j] == "."):
                j += 1
            num = text[i:j]
            tokens.append(("NUMBER", float(num) if "." in num else int(num),
                           line))
            i = j
            continue
        pairs = {"{": "LBRACE", "}": "RBRACE", "[": "LBRACK", "]": "RBRACK",
                 "=": "EQ", ",": "COMMA", "(": "LPAREN", ")": "RPAREN"}
        if ch in pairs:
            tokens.append((pairs[ch], ch, line))
            i += 1
            continue
        i += 1  # skip anything else (recovery)
    tokens.append(("EOF", None, line))
    return tokens


class _Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos]

    def advance(self):
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self):
        blocks = []
        while self.peek()[0] != "EOF":
            if self.peek()[0] == "IDENT":
                blocks.append(self.parse_block())
            else:
                self.advance()  # recovery: skip stray token
        return blocks

    def parse_block(self):
        _, btype, line = self.advance()
        labels = []
        while self.peek()[0] in ("IDENT", "STRING"):
            labels.append(self.advance()[1])
        if self.peek()[0] != "LBRACE":
            raise ValueError(f"line {line}: expected '{{' after block header")
        self.advance()
        block = Block(btype, labels, line)
        while self.peek()[0] != "RBRACE":
            if self.peek()[0] == "EOF":
                raise ValueError(f"line {line}: unterminated {btype} block")
            if self.peek()[0] == "IDENT":
                nxt = self.tokens[self.pos + 1]
                if nxt[0] == "EQ":
                    name = self.advance()[1]
                    self.advance()  # consume '='
                    block.attrs[name] = self.parse_value()
                else:
                    block.blocks.append(self.parse_block())
            else:
                self.advance()  # recovery
        self.advance()  # consume '}'
        return block

    def parse_value(self):
        kind, value, line = self.advance()
        if kind in ("STRING", "NUMBER"):
            return value
        if kind == "IDENT":
            if value == "true":
                return True
            if value == "false":
                return False
            if value == "null":
                return None
            if self.peek()[0] == "LPAREN":  # function call: keep opaque
                depth = 0
                parts = [value]
                while True:
                    kind2, value2, _ = self.advance()
                    parts.append(str(value2))
                    if kind2 == "LPAREN":
                        depth += 1
                    elif kind2 == "RPAREN":
                        depth -= 1
                        if depth == 0:
                            break
                    elif kind2 == "EOF":
                        break
                return "".join(parts)
            return value  # bare reference, e.g. var.vpc_id
        if kind == "LBRACK":
            items = []
            while self.peek()[0] != "RBRACK":
                if self.peek()[0] == "EOF":
                    break
                if self.peek()[0] == "COMMA":
                    self.advance()
                    continue
                items.append(self.parse_value())
            self.advance()  # consume ']'
            return items
        if kind == "LBRACE":  # object literal, e.g. tags = { Name = "x" }
            obj = {}
            while self.peek()[0] != "RBRACE":
                if self.peek()[0] == "EOF":
                    break
                if self.peek()[0] in ("IDENT", "STRING"):
                    key = self.advance()[1]
                    if self.peek()[0] in ("EQ",):
                        self.advance()
                        obj[key] = self.parse_value()
                    else:
                        self.advance()  # recovery
                else:
                    self.advance()  # skip commas etc.
            self.advance()  # consume '}'
            return obj
        raise ValueError(f"line {line}: unexpected {kind} in attribute value")


def parse_text(text, filename="<string>"):
    """Parse Terraform source text into a list of Block objects."""
    return _Parser(_tokenize(text)).parse()


def parse_file(path):
    """Parse one .tf file into a list of Block objects."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse_text(fh.read(), path)
