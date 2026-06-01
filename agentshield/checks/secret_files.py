from __future__ import annotations

from pathlib import Path

from agentshield.models import AuditContext, Finding
from agentshield.redact import TOKEN_PATTERNS, redact
from agentshield.utils import is_group_or_world_readable, mode_octal, safe_read_text

SECRET_FILE_CANDIDATES = [
    ".env",
    ".env.local",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".aws/credentials",
    ".aws/config",
    ".docker/config.json",
    ".config/gh/hosts.yml",
]


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

