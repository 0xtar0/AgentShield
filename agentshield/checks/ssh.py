from __future__ import annotations

import re
import base64
import stat
from pathlib import Path

from agentshield.models import AuditContext, Finding
from agentshield.utils import is_group_or_world_readable, is_group_or_world_writable, mode_octal, safe_read_text

PRIVATE_KEY_MARKERS = [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
]


def scan_ssh(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    ssh_dir = ctx.home / ".ssh"
    if not ssh_dir.exists():
        return [
            Finding(
                id="ssh.no_directory",
                title="No SSH directory found",
                severity="info",
                category="ssh",
                location=str(ssh_dir),
                evidence="~/.ssh does not exist.",
                remediation="No action needed unless this machine should use SSH keys.",
            )
        ]
    if is_group_or_world_writable(ssh_dir):
        findings.append(
            Finding(
                id="ssh.directory_permissions",
                title="SSH directory is writable by group or others",
                severity="high",
                category="ssh",
                location=str(ssh_dir),
                evidence=f"Mode is {mode_octal(ssh_dir)}.",
                remediation="Run chmod 700 ~/.ssh and verify ownership.",
            )
        )
    for path in _iter_files(ssh_dir):
        findings.extend(_scan_ssh_file(path))
    config = ssh_dir / "config"
    if config.exists():
        findings.extend(_scan_ssh_config(config))
    known_hosts = ssh_dir / "known_hosts"
    if not known_hosts.exists():
        findings.append(
            Finding(
                id="ssh.missing_known_hosts",
                title="SSH known_hosts file is missing",
                severity="low",
                category="ssh",
                location=str(known_hosts),
                evidence="No known_hosts file was found.",
                remediation="Avoid disabling host-key checks; let SSH record trusted hosts normally.",
            )
        )
    if not findings:
        findings.append(
            Finding(
                id="ssh.no_obvious_risks",
                title="No obvious SSH risks detected",
                severity="info",
                category="ssh",
                location=str(ssh_dir),
                evidence="SSH permissions and config did not match built-in risk heuristics.",
                remediation="Continue using passphrased keys and host-key verification.",
            )
        )
    return findings


def _iter_files(directory: Path) -> list[Path]:
    try:
        return [item for item in directory.iterdir() if item.is_file()]
    except OSError:
        return []


def _scan_ssh_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = safe_read_text(path, 8192)
    except OSError:
        return findings
    is_private_key = any(marker in content for marker in PRIVATE_KEY_MARKERS)
    if not is_private_key:
        return findings
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
        findings.append(
            Finding(
                id="ssh.private_key_permissions",
                title="SSH private key is readable or writable by group/others",
                severity="critical",
                category="ssh",
                location=str(path),
                evidence=f"Mode is {mode_octal(path)}.",
                remediation=f"Run chmod 600 {path} and verify only your user owns the key.",
            )
        )
    if _looks_unencrypted_private_key(content):
        findings.append(
            Finding(
                id="ssh.unencrypted_private_key",
                title="SSH private key appears to be unencrypted",
                severity="high",
                category="ssh",
                location=str(path),
                evidence="Private key header does not indicate encryption.",
                remediation="Generate a passphrased key or add a passphrase with ssh-keygen -p.",
            )
        )
    return findings


def _looks_unencrypted_private_key(content: str) -> bool:
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in content:
        body = "".join(line.strip() for line in content.splitlines() if not line.startswith("-----"))
        try:
            decoded = base64.b64decode(body + "===")
        except Exception:
            return False
        return b"\x00\x00\x00\x04none\x00\x00\x00\x04none" in decoded[:128]
    if "ENCRYPTED" in content[:500]:
        return False
    return True


def _scan_ssh_config(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = safe_read_text(path)
    except OSError:
        return findings
    checks = [
        (r"(?im)^\s*StrictHostKeyChecking\s+no\b", "ssh.strict_host_key_checking_disabled", "high", "StrictHostKeyChecking is disabled"),
        (r"(?im)^\s*UserKnownHostsFile\s+/dev/null\b", "ssh.known_hosts_disabled", "high", "Known-host tracking is disabled"),
        (r"(?im)^\s*ForwardAgent\s+yes\b", "ssh.agent_forwarding_enabled", "medium", "SSH agent forwarding is enabled"),
    ]
    for pattern, finding_id, severity, title in checks:
        for match in re.finditer(pattern, content):
            line_number = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    id=finding_id,
                    title=title,
                    severity=severity,
                    category="ssh",
                    location=f"{path}:{line_number}",
                    evidence=match.group(0).strip(),
                    remediation="Limit this setting to a specific trusted host or remove it.",
                )
            )
    if is_group_or_world_readable(path):
        findings.append(
            Finding(
                id="ssh.config_permissions",
                title="SSH config is readable by group or others",
                severity="low",
                category="ssh",
                location=str(path),
                evidence=f"Mode is {mode_octal(path)}.",
                remediation="Run chmod 600 ~/.ssh/config if it contains hostnames, users, or key paths.",
            )
        )
    return findings
