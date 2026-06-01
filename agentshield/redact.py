from __future__ import annotations

import math
import re

SECRET_NAME_RE = re.compile(
    r"(token|secret|passwd|password|pwd|apikey|api_key|access[_-]?key|private[_-]?key|client[_-]?secret|auth|bearer|session|cookie|credential)",
    re.IGNORECASE,
)

TOKEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
    re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


def looks_high_entropy(value: str) -> bool:
    cleaned = re.sub(r"[^A-Za-z0-9+/=_-]", "", value)
    return len(cleaned) >= 24 and shannon_entropy(cleaned) >= 3.8


def redact(value: str, visible: int = 4) -> str:
    if value is None:
        return ""
    text = str(value)
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub(lambda match: _redact_match(match.group(0), visible), text)
    if len(text) > 160:
        text = f"{text[:80]}...[truncated]...{text[-40:]}"
    return text


def redact_secret_value(value: str, visible: int = 4) -> str:
    if len(value) <= visible * 2:
        return "[redacted]"
    return f"{value[:visible]}...[redacted]...{value[-visible:]}"


def _redact_match(value: str, visible: int) -> str:
    if "://" in value and "@" in value:
        return re.sub(r"://([^:@\s]+):([^@\s]+)@", r"://\1:[redacted]@", value)
    if len(value) <= visible * 2:
        return "[redacted]"
    return f"{value[:visible]}...[redacted]...{value[-visible:]}"

