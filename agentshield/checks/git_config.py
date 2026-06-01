from __future__ import annotations

from pathlib import Path

from agentshield.models import AuditContext, Finding
from agentshield.redact import redact
from agentshield.utils import default_command_runner, safe_read_text


def scan_git_config(ctx: AuditContext) -> list[Finding]:
    fallback = ctx.home / ".gitconfig"
    if ctx.home.resolve() != Path.home().resolve():
        if fallback.exists():
            try:
                findings = _scan_git_config_text(safe_read_text(fallback))
            except OSError as exc:
                return [_git_unavailable(str(exc))]
            return findings or [_no_git_risks()]
        return [_no_git_risks(f"{fallback} does not exist.")]

    runner = ctx.command_runner or default_command_runner
    code, stdout, stderr = runner(["git", "config", "--global", "--list", "--show-origin"], 8)
    if code != 0:
        if fallback.exists():
            try:
                stdout = safe_read_text(fallback)
            except OSError as exc:
                return [_git_unavailable(str(exc))]
        else:
            if code == 1:
                return [_no_git_risks("No global Git config was found.")]
            return [_git_unavailable(stderr or "git config could not be read")]
    findings = _scan_git_config_text(stdout)
    if not findings:
        findings.append(_no_git_risks())
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


def _no_git_risks(evidence: str = "Global Git settings did not match built-in risk heuristics.") -> Finding:
    return Finding(
        id="git.no_obvious_risks",
        title="No obvious risky global Git config detected",
        severity="info",
        category="git",
        location="global git config",
        evidence=evidence,
        remediation="Continue using a secure credential helper and SSL verification.",
    )


def _scan_git_config_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    section = ""
    for line_number, line in enumerate(text.splitlines(), start=1):
        normalized = line.strip()
        if not normalized or normalized.startswith(("#", ";")):
            continue
        config_line = _strip_origin(normalized)
        if config_line.startswith("[") and config_line.endswith("]"):
            section = _normalize_section(config_line)
            continue
        effective = _effective_config_key(config_line, section)
        lower = effective.lower()
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
        if "safe.directory=*" in lower:
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


def _strip_origin(line: str) -> str:
    if "\t" in line and line.startswith("file:"):
        return line.split("\t", 1)[1].strip()
    return line


def _effective_config_key(line: str, section: str) -> str:
    collapsed = "".join(line.split())
    if "=" not in collapsed:
        return collapsed
    key, value = collapsed.split("=", 1)
    if "." in key or not section:
        return f"{key}={value}"
    return f"{section}.{key}={value}"


def _normalize_section(line: str) -> str:
    section = line.strip("[]").strip()
    if '"' not in section:
        return section.lower()
    prefix, subsection = section.split('"', 1)
    return f"{prefix.strip().lower()} {subsection.rstrip(chr(34)).strip()}"
