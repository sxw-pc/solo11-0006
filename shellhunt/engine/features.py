"""Heuristic, token-level feature extraction.
The module intentionally works on approximate tokens rather than an AST.  It
reports each signal with a 0..1 sub-score and the source lines that produced it.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any
from .tokenizer import Token, call_end, canonical, function_calls, tokenize
SUPERGLOBALS = {"$_get", "$_post", "$_request", "$_cookie", "$_files", "$_server"}
EXEC_CALLS = {
    "eval",
    "assert",
    "system",
    "exec",
    "shell_exec",
    "passthru",
    "popen",
    "proc_open",
    "pcntl_exec",
    "create_function",
}
FILE_SINKS = {
    "file_put_contents",
    "fwrite",
    "fputs",
    "move_uploaded_file",
    "copy",
    "rename",
    "chmod",
}
CALLBACK_SINKS = {
    "call_user_func",
    "call_user_func_array",
    "array_map",
    "array_filter",
    "usort",
    "uasort",
    "preg_replace_callback",
    "ob_start",
}
INPUT_SINKS = EXEC_CALLS | FILE_SINKS | CALLBACK_SINKS | {"preg_replace", "include", "require"}
ALL_WATCHED = EXEC_CALLS | FILE_SINKS | CALLBACK_SINKS
SUPER_RE = r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)"
INCLUDE_INPUT_RE = re.compile(
    rf"(?is)\b(?:include|require)(?:_once)?\s*\(?[^;]{{0,220}}?{SUPER_RE}\b"
)
VARIABLE_VARIABLE_RE = re.compile(r"\$\s*\$|\$\s*\{")
HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
COMMENT_RE = re.compile(r"//[^\n]*|#[^\n]*|/\*.*?\*/", re.DOTALL)
@dataclass
class FeatureSignal:
    name: str
    score: float
    lines: list[int] = field(default_factory=list)
    detail: str = ""
    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": round(self.score, 3),
            "lines": self.lines,
            "detail": self.detail,
        }
@dataclass
class FeatureReport:
    dangerous_functions: dict[str, list[int]]
    signals: dict[str, FeatureSignal]
    superglobal_lines: list[int]
    token_count: int
    def as_dict(self) -> dict[str, Any]:
        return {
            "dangerous_functions": self.dangerous_functions,
            "signals": {name: signal.as_dict() for name, signal in self.signals.items()},
            "superglobal_lines": self.superglobal_lines,
            "token_count": self.token_count,
        }
    def signal(self, name: str) -> FeatureSignal | None:
        return self.signals.get(name)
def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, max(0, index)) + 1
def _superglobal_args(tokens: list[Token], start: int, end: int) -> bool:
    return any(canonical(token) in SUPERGLOBALS for token in tokens[start:end])
def analyze_features(text: str, tokens: list[Token] | None = None) -> FeatureReport:
    tokens = tokens if tokens is not None else tokenize(text)
    calls = function_calls(tokens)
    dangerous: dict[str, list[int]] = {}
    direct_lines: set[int] = set()
    dynamic_lines: set[int] = set()
    exec_lines: set[int] = set()
    for name, name_idx, _open_idx, close_idx in calls:
        if name in ALL_WATCHED:
            dangerous.setdefault(name, []).append(tokens[name_idx].line)
        if name in EXEC_CALLS:
            exec_lines.add(tokens[name_idx].line)
        if name in INPUT_SINKS and _superglobal_args(tokens, name_idx + 2, close_idx):
            direct_lines.add(tokens[name_idx].line)
    for idx, token in enumerate(tokens[:-1]):
        if token.kind != "variable" or tokens[idx + 1].value != "(":
            continue
        close = call_end(tokens, idx + 1)
        if _superglobal_args(tokens, idx + 2, close):
            dynamic_lines.add(token.line)
            direct_lines.add(token.line)
    for match in INCLUDE_INPUT_RE.finditer(text):
        direct_lines.add(_line_of(text, match.start()))
    superglobal_lines = sorted(
        {token.line for token in tokens if canonical(token) in SUPERGLOBALS}
    )
    execution_score = min(1.0, 0.5 + 0.2 * max(0, len(exec_lines) - 1)) if exec_lines else 0.0
    direct_score = min(1.0, 0.7 + 0.3 * max(0, len(direct_lines) - 1)) if direct_lines else 0.0
    dynamic_score = min(1.0, 0.6 + 0.2 * max(0, len(dynamic_lines) - 1)) if dynamic_lines else 0.0
    obfuscation, obf_lines = _obfuscation(text, tokens)
    signals = {
        "dangerous_calls": FeatureSignal(
            "dangerous_calls",
            execution_score,
            sorted(exec_lines),
            f"{len(exec_lines)} execution-style call line(s)",
        ),
        "direct_input": FeatureSignal(
            "direct_input",
            direct_score,
            sorted(direct_lines),
            f"{len(direct_lines)} request-to-sink line(s)",
        ),
        "dynamic_call": FeatureSignal(
            "dynamic_call",
            dynamic_score,
            sorted(dynamic_lines),
            f"{len(dynamic_lines)} variable-function call line(s)",
        ),
        "obfuscation": FeatureSignal(
            "obfuscation",
            obfuscation,
            obf_lines,
            "concat/chr/hex/variable-variable/comment density",
        ),
    }
    for name in dangerous:
        dangerous[name] = sorted(set(dangerous[name]))
    return FeatureReport(dangerous, signals, superglobal_lines, len(tokens))
def _obfuscation(text: str, tokens: list[Token]) -> tuple[float, list[int]]:
    concat_lines, var_lines, chr_lines, hex_lines = set(), set(), set(), set()
    for idx, token in enumerate(tokens):
        if token.value in (".", ".="):
            concat_lines.add(token.line)
        if token.kind == "word" and token.value.lower() in ("chr", "ord"):
            if idx + 1 < len(tokens) and tokens[idx + 1].value == "(":
                chr_lines.add(token.line)
    for match in VARIABLE_VARIABLE_RE.finditer(text):
        var_lines.add(_line_of(text, match.start()))
    for match in HEX_ESCAPE_RE.finditer(text):
        hex_lines.add(_line_of(text, match.start()))
    comments = COMMENT_RE.findall(text)
    comment_ratio = sum(len(item) for item in comments) / max(1, len(text))
    concat_score = min(1.0, max(0, len(concat_lines) - 3) / 10)
    var_score = min(1.0, len(var_lines) / 2)
    chr_score = min(1.0, len(chr_lines) / 4)
    hex_score = min(1.0, len(hex_lines) / 8)
    comment_score = min(0.3, comment_ratio)
    score = min(
        1.0,
        0.35 * concat_score
        + 0.25 * var_score
        + 0.20 * chr_score
        + 0.15 * hex_score
        + 0.10 * comment_score,
    )
    lines = sorted(concat_lines | var_lines | chr_lines | hex_lines)
    if score > 0:
        lines = lines[:20]
    else:
        lines = []
    return score, lines
