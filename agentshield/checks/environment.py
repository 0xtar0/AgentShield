from __future__ import annotations

import os
from pathlib import Path

from agentshield.models import AuditContext, Finding
from agentshield.redact import SECRET_NAME_RE, looks_high_entropy, redact_secret_value
from agentshield.utils import is_group_or_world_writable


def scan_environment(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    for name, value in sorted(os.environ.items()):
        if not value:
            continue
        secret_named = bool(SECRET_NAME_RE.search(name))
        high_entropy = looks_high_entropy(value)
        if secret_named or high_entropy:
            findings.append(
                Finding(
                    id="env.secret_like_variable",
                    title="Secret-like value is present in the process environment",
                    severity="medium" if secret_named else "low",
                    category="environment",
                    location=f"env:{name}",
                    evidence=f"{name}={redact_secret_value(value)}",
                    remediation=(
                        "Avoid launching coding agents from shells that contain long-lived credentials. "
                        "Prefer short-lived tokens, scoped credentials, and per-tool environment files."
                    ),
                    metadata={"name": name, "secret_named": secret_named, "high_entropy": high_entropy},
                )
            )

    findings.extend(_scan_path())
    if not findings:
        findings.append(
            Finding(
                id="env.no_obvious_exposure",
                title="No obvious secret-like environment variables detected",
                severity="info",
                category="environment",
                location="process environment",
                evidence="Current process environment did not match built-in secret heuristics.",
                remediation="Continue using scoped and short-lived credentials for agent workflows.",
            )
        )
    return findings


def _scan_path() -> list[Finding]:
    findings: list[Finding] = []
    path_value = os.environ.get("PATH", "")
    for entry in [item for item in path_value.split(os.pathsep) if item]:
        path = Path(entry).expanduser()
        try:
            if path.exists() and path.is_dir() and is_group_or_world_writable(path):
                findings.append(
                    Finding(
                        id="env.path_world_writable",
                        title="PATH contains a group/world-writable directory",
                        severity="high",
                        category="environment",
                        location=str(path),
                        evidence=f"{path} is writable by group or others.",
                        remediation="Remove the directory from PATH or restrict permissions to the owning user.",
                    )
                )
        except OSError:
            continue
    return findings

