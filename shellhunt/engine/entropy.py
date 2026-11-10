"""Shannon entropy, payload extraction and nested decoding-chain detection."""
from __future__ import annotations
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from .tokenizer import Token, function_calls, tokenize
DECODE_FUNCTIONS = {
    "base64_decode",
    "gzinflate",
    "gzuncompress",
    "gzdecode",
    "str_rot13",
    "hex2bin",
    "convert_uudecode",
    "rawurldecode",
    "urldecode",
    "strrev",
}
PAYLOAD_RE = re.compile(r"[A-Za-z0-9+/=_-]{40,}")
HIGH_ENTROPY = 4.2
@dataclass
class EntropyReport:
    overall: float
    longest_length: int
    longest_entropy: float
    suspicious_count: int
    payloads: list[dict[str, Any]] = field(default_factory=list)
    encoding_depth: int = 0
    encoding_functions: list[str] = field(default_factory=list)
    def as_dict(self) -> dict[str, Any]:
        return {
            "overall": round(self.overall, 3),
            "longest_length": self.longest_length,
            "longest_entropy": round(self.longest_entropy, 3),
            "suspicious_count": self.suspicious_count,
            "payloads": self.payloads,
            "encoding_depth": self.encoding_depth,
            "encoding_functions": self.encoding_functions,
        }
def shannon_entropy(value: str | bytes) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())
def _extract_payloads(text: str) -> list[dict[str, Any]]:
    seen, results = set(), []
    for match in PAYLOAD_RE.finditer(text):
        value = match.group(0)
        score = shannon_entropy(value)
        if score < HIGH_ENTROPY or value in seen:
            continue
        seen.add(value)
        results.append(
            {
                "length": len(value),
                "entropy": round(score, 3),
                "preview": value[:64] + ("..." if len(value) > 64 else ""),
            }
        )
    results.sort(key=lambda item: (-item["entropy"], -item["length"]))
    return results
def _decode_depth(tokens: list[Token]) -> tuple[int, list[str]]:
    decode_calls = []
    names = []
    for name, name_idx, open_idx, close_idx in function_calls(tokens):
        if name in DECODE_FUNCTIONS:
            decode_calls.append((name_idx, open_idx, close_idx))
            names.append(name)
    cache: dict[int, int] = {}
    def depth(open_idx: int, close_idx: int) -> int:
        best_inner = 0
        for inner_name_idx, inner_open, inner_close in decode_calls:
            if open_idx < inner_name_idx < close_idx and inner_close <= close_idx:
                best_inner = max(best_inner, cached_depth(inner_name_idx, inner_open, inner_close))
        return 1 + best_inner
    def cached_depth(name_idx: int, open_idx: int, close_idx: int) -> int:
        if name_idx not in cache:
            cache[name_idx] = depth(open_idx, close_idx)
        return cache[name_idx]
    maximum = 0
    for name_idx, open_idx, close_idx in decode_calls:
        maximum = max(maximum, cached_depth(name_idx, open_idx, close_idx))
    return maximum, sorted(set(names))
def analyze_entropy(text: str, tokens: list[Token] | None = None) -> EntropyReport:
    tokens = tokens if tokens is not None else tokenize(text)
    pieces = re.findall(r"\S+", text)
    longest = max(pieces, key=len) if pieces else ""
    payloads = _extract_payloads(text)
    depth, functions = _decode_depth(tokens)
    return EntropyReport(
        overall=shannon_entropy(text),
        longest_length=len(longest),
        longest_entropy=shannon_entropy(longest),
        suspicious_count=len(payloads),
        payloads=payloads[:8],
        encoding_depth=depth,
        encoding_functions=functions,
    )
