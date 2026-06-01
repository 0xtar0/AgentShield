from __future__ import annotations

import json
import re

from agentshield.models import AuditContext, Finding
from agentshield.utils import default_command_runner

SUSPICIOUS_NAME_RE = re.compile(r"(token|secret|wallet|keylogger|stealer|grabber|crypto-miner|miner)", re.I)


def scan_global_packages(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_npm(ctx))
    findings.extend(_scan_pip(ctx))
    findings.extend(_scan_pipx(ctx))
    if not findings:
        findings.append(
            Finding(
                id="packages.no_inventory",
                title="No global package inventory findings",
                severity="info",
                category="global-packages",
                location="npm/pip/pipx",
                evidence="Package managers were unavailable or had no notable global package footprint.",
                remediation="Keep global CLI packages minimal and update them regularly.",
            )
        )
    return findings


def _scan_npm(ctx: AuditContext) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    code, stdout, _ = runner(["npm", "list", "-g", "--depth=0", "--json"], 12)
    if code not in (0, 1) or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    deps = sorted((data.get("dependencies") or {}).keys())
    return _package_findings("npm", deps)


def _scan_pip(ctx: AuditContext) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    code, stdout, _ = runner(["python", "-m", "pip", "list", "--user", "--format=json"], 12)
    if code != 0 or not stdout.strip():
        code, stdout, _ = runner(["python3", "-m", "pip", "list", "--user", "--format=json"], 12)
    if code != 0 or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    deps = sorted(item.get("name", "") for item in data if item.get("name"))
    return _package_findings("pip-user", deps)


def _scan_pipx(ctx: AuditContext) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    code, stdout, _ = runner(["pipx", "list", "--json"], 12)
    if code != 0 or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    deps = sorted((data.get("venvs") or {}).keys())
    return _package_findings("pipx", deps)


def _package_findings(manager: str, packages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    if packages:
        findings.append(
            Finding(
                id=f"packages.{manager}.inventory",
                title=f"{manager} global package inventory captured",
                severity="info",
                category="global-packages",
                location=manager,
                evidence=f"{len(packages)} packages: {', '.join(packages[:30])}{'...' if len(packages) > 30 else ''}",
                remediation="Remove global packages you do not use and prefer project-local dependencies where possible.",
                metadata={"manager": manager, "count": len(packages), "packages": packages},
            )
        )
    if len(packages) >= 25:
        findings.append(
            Finding(
                id=f"packages.{manager}.large_global_surface",
                title=f"{manager} has a large global package footprint",
                severity="medium",
                category="global-packages",
                location=manager,
                evidence=f"{len(packages)} global packages are installed.",
                remediation="Reduce global packages to trusted CLIs; move build/test libraries into project environments.",
            )
        )
    for package in packages:
        if SUSPICIOUS_NAME_RE.search(package):
            findings.append(
                Finding(
                    id=f"packages.{manager}.suspicious_name",
                    title=f"{manager} global package has a suspicious name",
                    severity="medium",
                    category="global-packages",
                    location=f"{manager}:{package}",
                    evidence=package,
                    remediation="Verify that this package is expected and from a trusted source.",
                )
            )
    return findings

