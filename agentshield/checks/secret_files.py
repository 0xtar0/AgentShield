from __future__ import annotations

import re
from pathlib import Path

from agentshield.models import AuditContext, Finding
from agentshield.redact import SECRET_NAME_RE, TOKEN_PATTERNS, looks_high_entropy, redact, redact_secret_value
from agentshield.utils import is_group_or_world_readable, is_group_or_world_writable, mode_octal, safe_read_text

SECRET_FILE_CANDIDATES = [
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".aws/credentials",
    ".aws/config",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".docker/config.json",
    ".config/gh/hosts.yml",
    ".config/gcloud/application_default_credentials.json",
    ".gem/credentials",
    ".m2/settings.xml",
]

SECRET_WORDS = r"token|secret|passwd|password|pwd|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth|bearer|session|cookie|credential"

ASSIGNMENT_RE = re.compile(
    rf"""(?:^|[\s/:])(?:export\s+)?["']?(?P<key>[A-Za-z0-9_.-]*(?:{SECRET_WORDS})[A-Za-z0-9_.-]*)["']?\s*(?:=|:)\s*["']?(?P<value>[^"',\s#][^"',#]*)["']?,?""",
    re.IGNORECASE,
)
XML_SECRET_RE = re.compile(rf"<(?P<key>{SECRET_WORDS})>\s*(?P<value>[^<\s][^<]*)\s*</(?P=key)>", re.IGNORECASE)
NETRC_PASSWORD_RE = re.compile(r"\bpassword\s+(?P<value>\S+)", re.IGNORECASE)


def scan_secret_files(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    for relative in SECRET_FILE_CANDIDATES:
        path = ctx.home / relative
        if not path.exists() or not path.is_file():
            continue
        findings.extend(_scan_secret_file(path))
    if not findings:
        findings.append(
            Finding(
                id="files.no_obvious_secret_file_risks",
                title="No obvious secret-bearing file risks detected",
                severity="info",
                category="secret-files",
                location=str(ctx.home),
                evidence="Known secret-bearing files were absent or did not match built-in risk heuristics.",
                remediation="Keep secret files out of repositories and restrict file permissions.",
            )
        )
    return findings


def _scan_secret_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if is_group_or_world_readable(path):
        findings.append(
            Finding(
                id="files.secret_file_permissions",
                title="Secret-bearing file is readable by group or others",
                severity="high",
                category="secret-files",
                location=str(path),
                evidence=f"Mode is {mode_octal(path)}.",
                remediation=f"Run chmod 600 {path} and verify ownership.",
            )
        )
    if is_group_or_world_writable(path):
        findings.append(
            Finding(
                id="files.secret_file_writable",
                title="Secret-bearing file is writable by group or others",
                severity="critical",
                category="secret-files",
                location=str(path),
                evidence=f"Mode is {mode_octal(path)}.",
                remediation=f"Run chmod 600 {path} and verify ownership.",
            )
        )
    try:
        content = safe_read_text(path, 512_000)
    except OSError as exc:
        return [
            Finding(
                id="files.unreadable_secret_file",
                title="Secret-bearing file could not be read",
                severity="low",
                category="secret-files",
                location=str(path),
                evidence=str(exc),
                remediation="Check permissions if this file should be included in audits.",
            )
        ]
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assignment = _parse_secret_assignment(stripped)
        if assignment:
            key, value = assignment
            severity = "high" if SECRET_NAME_RE.search(key) else "medium"
            findings.append(
                Finding(
                    id="files.secret_assignment",
                    title="Secret-like assignment found in a known credential file",
                    severity=severity,
                    category="secret-files",
                    location=f"{path}:{line_number}",
                    evidence=redact(_redact_assignment(stripped, value)),
                    remediation="Make sure this file is ignored by Git and only exposed to tools that need it.",
                    metadata={"key": key},
                )
            )
            continue
        if any(pattern.search(stripped) for pattern in TOKEN_PATTERNS):
            findings.append(
                Finding(
                    id="files.secret_pattern",
                    title="Secret-like value found in a known credential file",
                    severity="medium",
                    category="secret-files",
                    location=f"{path}:{line_number}",
                    evidence=redact(stripped),
                    remediation="Make sure this file is ignored by Git and only exposed to tools that need it.",
                )
            )
    return findings


def _parse_secret_assignment(line: str) -> tuple[str, str] | None:
    match = ASSIGNMENT_RE.search(line) or XML_SECRET_RE.search(line)
    if not match:
        match = NETRC_PASSWORD_RE.search(line)
        if match:
            value = match.group("value").strip()
            return ("password", value) if _usable_secret_value(value) else None
    if not match:
        return None
    key = match.group("key")
    value = match.group("value").strip()
    if not _usable_secret_value(value):
        return None
    return key, value


def _usable_secret_value(value: str) -> bool:
    if value.lower() in {"true", "false", "null", "none", "changeme", "example", "placeholder"}:
        return False
    if len(value) < 6 and not looks_high_entropy(value):
        return False
    return True


def _redact_assignment(line: str, value: str) -> str:
    return line.replace(value, redact_secret_value(value), 1)
