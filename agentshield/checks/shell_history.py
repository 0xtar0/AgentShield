from __future__ import annotations

import re
from pathlib import Path

from agentshield.models import AuditContext, Finding
from agentshield.redact import TOKEN_PATTERNS, redact
from agentshield.utils import safe_read_text

HISTORY_FILES = [
    ".zsh_history",
    ".bash_history",
    ".history",
    ".fish_history",
    ".python_history",
    ".psql_history",
    ".mysql_history",
]

DANGEROUS_COMMANDS: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"curl\b.+\|\s*(sudo\s+)?(sh|bash)\b", re.I), "shell.curl_pipe_shell", "high", "Downloaded script was piped directly to a shell"),
    (re.compile(r"wget\b.+\|\s*(sudo\s+)?(sh|bash)\b", re.I), "shell.wget_pipe_shell", "high", "Downloaded script was piped directly to a shell"),
    (re.compile(r"chmod\s+(-R\s+)?777\b", re.I), "shell.chmod_777", "medium", "Command used broad world-writable permissions"),
    (re.compile(r"docker\s+login\b.+(-p|--password)\s+\S+", re.I), "shell.docker_password", "high", "Docker password appears on command line"),
    (re.compile(r"sshpass\s+-p\s+\S+", re.I), "shell.sshpass_password", "high", "SSH password appears on command line"),
    (re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+", re.I), "shell.credential_url", "critical", "Credential-bearing URL appears in shell history"),
]


def scan_shell_history(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    for filename in HISTORY_FILES:
        path = ctx.home / filename
        if not path.exists() or not path.is_file():
            continue
        try:
            content = safe_read_text(path, ctx.max_history_bytes)
        except OSError as exc:
            findings.append(
                Finding(
                    id="shell.unreadable_history",
                    title="Shell history file could not be read",
                    severity="low",
                    category="shell-history",
                    location=str(path),
                    evidence=str(exc),
                    remediation="Check file permissions if this history should be included in audits.",
                )
            )
            continue
        findings.extend(_scan_history_content(path, content))
    if not findings:
        findings.append(
            Finding(
                id="shell.no_history_risks",
                title="No risky shell history entries detected",
                severity="info",
                category="shell-history",
                location=str(ctx.home),
                evidence="Known history files were absent or did not match risky command heuristics.",
                remediation="Keep secrets out of command lines; prefer files, stdin, or credential managers.",
            )
        )
    return findings


def _scan_history_content(path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = _normalize_history_line(raw_line)
        if not line:
            continue
        for pattern in TOKEN_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        id="shell.secret_in_history",
                        title="Secret-like value appears in shell history",
                        severity="critical",
                        category="shell-history",
                        location=f"{path}:{line_number}",
                        evidence=redact(line),
                        remediation="Rotate the exposed credential, then remove it from shell history and backups.",
                    )
                )
                break
        for pattern, finding_id, severity, title in DANGEROUS_COMMANDS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        id=finding_id,
                        title=title,
                        severity=severity,
                        category="shell-history",
                        location=f"{path}:{line_number}",
                        evidence=redact(line),
                        remediation="Review whether this command exposed credentials or weakened local permissions.",
                    )
                )
    return findings


def _normalize_history_line(line: str) -> str:
    if line.startswith(": ") and ";" in line:
        return line.split(";", 1)[1].strip()
    if line.startswith("- cmd: "):
        return line.removeprefix("- cmd: ").strip()
    return line.strip()

