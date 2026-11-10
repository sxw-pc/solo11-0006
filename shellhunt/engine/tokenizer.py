"""A deliberately small PHP-ish tokenizer.
It is not a PHP parser.  It removes comments and groups strings, variables,
words and punctuation so the detectors can reason about token proximity
without depending on a PHP runtime.
"""
from __future__ import annotations
from dataclasses import dataclass
WORD_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
WORD_CHARS = WORD_START | set("0123456789")
TWO_CHAR_OPS = {"->", "::", "=>", "==", "!=", ">=", "<=", "&&", "||", "??", ".=", "++", "--"}
@dataclass(frozen=True)
class Token:
    value: str
    kind: str
    line: int
    col: int
    start: int
    end: int
def _is_word_start(ch: str) -> bool:
    return ch in WORD_START or ord(ch) > 127
def _is_word_char(ch: str) -> bool:
    return ch in WORD_CHARS or ord(ch) > 127
def tokenize(text: str) -> list[Token]:
    """Tokenize source text; comments/whitespace/PHP tags are dropped."""
    tokens: list[Token] = []
    i, line, line_start, n = 0, 1, 0, len(text)
    def add(value: str, kind: str, start: int, end: int) -> None:
        tokens.append(Token(value, kind, line, start - line_start + 1, start, end))
    while i < n:
        ch = text[i]
        if ch in " \t\r\f\v":
            i += 1
            continue
        if ch == "\n":
            i += 1
            line += 1
            line_start = i
            continue
        if text.startswith("<?php", i) or text.startswith("<?=", i):
            i += 5 if text.startswith("<?=", i) else 4
            continue
        if text.startswith("<?", i) or text.startswith("?>", i):
            i += 2
            continue
        if text.startswith("//", i) or ch == "#":
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            lines = text.count("\n", i, end)
            if lines:
                line += lines
                line_start = text.rfind("\n", i, end) + 1
            i = end
            continue
        if ch in ("'", '"'):
            quote, start, start_line = ch, i, line
            start_col = i - line_start + 1
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                if text[i] == "\n":
                    line += 1
                    line_start = i + 1
                i += 1
            tokens.append(
                Token(
                    text[start + 1 : max(start + 1, i - 1)],
                    "string",
                    start_line,
                    start_col,
                    start,
                    i,
                )
            )
            continue
        if ch == "$" and i + 1 < n and (_is_word_start(text[i + 1]) or text[i + 1] == "{"):
            start = i
            i += 1
            if text[i] == "{":
                end = text.find("}", i)
                i = n if end < 0 else end + 1
            else:
                while i < n and _is_word_char(text[i]):
                    i += 1
            add(text[start:i], "variable", start, i)
            continue
        if _is_word_start(ch):
            start = i
            i += 1
            while i < n and _is_word_char(text[i]):
                i += 1
            add(text[start:i], "word", start, i)
            continue
        if ch.isdigit():
            start = i
            i += 1
            while i < n and (text[i].isdigit() or text[i] in ".xXabcdefABCDEF"):
                i += 1
            add(text[start:i], "number", start, i)
            continue
        pair = text[i : i + 2]
        if pair in TWO_CHAR_OPS:
            add(pair, "punct", i, i + 2)
            i += 2
            continue
        add(ch, "punct", i, i + 1)
        i += 1
    return tokens
def canonical(token: Token) -> str:
    if token.kind in ("word", "variable"):
        return token.value.lower()
    return token.value
def call_end(tokens: list[Token], open_index: int) -> int:
    """Return the index of the ')' matching tokens[open_index], or the end."""
    if open_index >= len(tokens) or tokens[open_index].value != "(":
        return open_index
    depth = 0
    for idx in range(open_index, len(tokens)):
        value = tokens[idx].value
        if value == "(":
            depth += 1
        elif value == ")":
            depth -= 1
            if depth == 0:
                return idx
    return len(tokens) - 1
def function_calls(tokens: list[Token]) -> list[tuple[str, int, int, int]]:
    """Yield (lowercase name, name_index, open_paren_index, close_index)."""
    calls = []
    for idx, token in enumerate(tokens[:-1]):
        if token.kind != "word" or tokens[idx + 1].value != "(":
            continue
        if idx > 0 and tokens[idx - 1].value in ("->", "::"):
            continue
        calls.append((token.value.lower(), idx, idx + 1, call_end(tokens, idx + 1)))
    return calls
def tokens_between(tokens: list[Token], start_index: int, end_index: int) -> list[Token]:
    return tokens[start_index : end_index + 1]
def text_span(tokens: list[Token], start_index: int, end_index: int, source: str) -> str:
    if not tokens:
        return ""
    start = tokens[max(0, start_index)].start
    end = tokens[min(len(tokens) - 1, end_index)].end
    return source[start:end]
