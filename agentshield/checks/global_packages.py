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
    findings.extend(_scan_homebrew(ctx))
    findings.extend(_scan_pnpm(ctx))
    findings.extend(_scan_cargo(ctx))
    findings.extend(_scan_gem(ctx))
    if not findings:
        findings.append(
            Finding(
                id="packages.no_inventory",
                title="No global package inventory findings",
                severity="info",
                category="global-packages",
                location="package managers",
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
    if not isinstance(data, dict):
        return []
    deps = sorted((data.get("dependencies") or {}).keys())
    return _package_findings(ctx, "npm", deps)


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
    if not isinstance(data, list):
        return []
    deps = sorted(item.get("name", "") for item in data if item.get("name"))
    return _package_findings(ctx, "pip-user", deps)


def _scan_pipx(ctx: AuditContext) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    code, stdout, _ = runner(["pipx", "list", "--json"], 12)
    if code != 0 or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    deps = sorted((data.get("venvs") or {}).keys())
    return _package_findings(ctx, "pipx", deps)


def _scan_homebrew(ctx: AuditContext) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    code, stdout, _ = runner(["brew", "list", "--formula"], 12)
    if code != 0 or not stdout.strip():
        return []
    deps = sorted(line.strip() for line in stdout.splitlines() if line.strip())
    return _package_findings(ctx, "homebrew", deps)


def _scan_pnpm(ctx: AuditContext) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    code, stdout, _ = runner(["pnpm", "list", "-g", "--depth", "0", "--json"], 12)
    if code != 0 or not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    deps: list[str] = []
    roots = data if isinstance(data, list) else [data]
    for root in roots:
        if isinstance(root, dict):
            deps.extend((root.get("dependencies") or {}).keys())
            deps.extend((root.get("devDependencies") or {}).keys())
    return _package_findings(ctx, "pnpm", sorted(set(deps)))


def _scan_cargo(ctx: AuditContext) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    code, stdout, _ = runner(["cargo", "install", "--list"], 12)
    if code != 0 or not stdout.strip():
        return []
    deps: list[str] = []
    for line in stdout.splitlines():
        if line.startswith(" ") or not line.strip():
            continue
        name = line.split(" ", 1)[0].strip()
        if name:
            deps.append(name)
    return _package_findings(ctx, "cargo", sorted(set(deps)))


def _scan_gem(ctx: AuditContext) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    code, stdout, _ = runner(["gem", "list", "--local"], 12)
    if code != 0 or not stdout.strip():
        return []
    deps: list[str] = []
    for line in stdout.splitlines():
        name = line.split(" ", 1)[0].strip()
        if name:
            deps.append(name)
    return _package_findings(ctx, "gem", sorted(set(deps)))


def _package_findings(ctx: AuditContext, manager: str, packages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    packages = [package for package in packages if not ctx.policy.is_trusted_package(manager, package)]
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
    surface_limit = ctx.policy.max_global_packages.get(manager, 25)
    if surface_limit and len(packages) >= surface_limit:
        findings.append(
            Finding(
                id=f"packages.{manager}.large_global_surface",
                title=f"{manager} has a large global package footprint",
                severity="medium",
                category="global-packages",
                location=manager,
                evidence=f"{len(packages)} global packages are installed; policy threshold is {surface_limit}.",
                remediation="Reduce global packages to trusted CLIs, add expected tools to policy trusted_packages, or move build/test libraries into project environments.",
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
