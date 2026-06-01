from __future__ import annotations

from pathlib import Path

from agentshield.models import AuditContext, Finding
from agentshield.redact import redact
from agentshield.utils import default_command_runner, safe_read_text


def scan_git_config(ctx: AuditContext) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    code, stdout, stderr = runner(["git", "config", "--global", "--list", "--show-origin"], 8)
    if code != 0:
        fallback = ctx.home / ".gitconfig"
        if fallback.exists():
            try:
                stdout = safe_read_text(fallback)
            except OSError as exc:
                return [_git_unavailable(str(exc))]
        else:
            return [_git_unavailable(stderr or "git config could not be read")]
    findings = _scan_git_config_text(stdout)
    if not findings:
        findings.append(
            Finding(
                id="git.no_obvious_risks",
                title="No obvious risky global Git config detected",
                severity="info",
                category="git",
                location="global git config",
                evidence="Global Git settings did not match built-in risk heuristics.",
                remediation="Continue using a secure credential helper and SSL verification.",
            )
        )
    return findings


def _git_unavailable(reason: str) -> Finding:
    return Finding(
        id="git.config_unavailable",
        title="Global Git config could not be inspected",
        severity="low",
        category="git",
        location="global git config",
        evidence=redact(reason),
        remediation="Install git or ensure ~/.gitconfig is readable if Git config should be audited.",
    )


def _scan_git_config_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        normalized = line.strip()
        lower = normalized.lower()
        location = _line_location(normalized, line_number)
        if "credential.helper=store" in lower:
            findings.append(
                Finding(
                    id="git.plaintext_credential_store",
                    title="Git is configured to store credentials in plaintext",
                    severity="high",
                    category="git",
                    location=location,
                    evidence=redact(normalized),
                    remediation="Use an OS-backed credential manager such as osxkeychain, manager-core, libsecret, or pass.",
                )
            )
        if "http.sslverify=false" in lower:
            findings.append(
                Finding(
                    id="git.ssl_verification_disabled",
                    title="Git SSL certificate verification is disabled",
                    severity="critical",
                    category="git",
                    location=location,
                    evidence=redact(normalized),
                    remediation="Run git config --global --unset http.sslVerify and fix the underlying certificate issue.",
                )
            )
        if "://oauth2:" in lower or "://x-access-token:" in lower or "github_pat_" in lower or "ghp_" in lower:
            findings.append(
                Finding(
                    id="git.tokenized_config_url",
                    title="Git config appears to contain an embedded access token",
                    severity="critical",
                    category="git",
                    location=location,
                    evidence=redact(normalized),
                    remediation="Rotate the token and replace tokenized URLs with a credential helper or SSH remote.",
                )
            )
        if "core.sshcommand=" in lower and ("stricthostkeychecking=no" in lower or "userknownhostsfile=/dev/null" in lower):
            findings.append(
                Finding(
                    id="git.unsafe_ssh_command",
                    title="Git SSH command disables host-key protection",
                    severity="high",
                    category="git",
                    location=location,
                    evidence=redact(normalized),
                    remediation="Remove unsafe SSH options from core.sshCommand.",
                )
            )
        if lower.startswith("file:") and "safe.directory=*" in lower:
            findings.append(
                Finding(
                    id="git.safe_directory_wildcard",
                    title="Git safe.directory trusts every repository",
                    severity="medium",
                    category="git",
                    location=location,
                    evidence=redact(normalized),
                    remediation="Replace safe.directory=* with explicit trusted repository paths.",
                )
            )
    return findings


def _line_location(line: str, line_number: int) -> str:
    if "\t" in line and line.startswith("file:"):
        return line.split("\t", 1)[0]
    return f"global git config:{line_number}"

