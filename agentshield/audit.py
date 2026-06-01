from __future__ import annotations

from agentshield.checks import (
    scan_environment,
    scan_git_config,
    scan_global_packages,
    scan_secret_files,
    scan_shell_history,
    scan_ssh,
)
from agentshield.models import AuditContext, AuditReport, Finding, SEVERITY_ORDER


def run_audit(ctx: AuditContext) -> AuditReport:
    findings: list[Finding] = []
    findings.extend(scan_environment(ctx))
    if ctx.scan_shell_history:
        findings.extend(scan_shell_history(ctx))
    findings.extend(scan_ssh(ctx))
    findings.extend(scan_git_config(ctx))
    findings.extend(scan_secret_files(ctx))
    if ctx.scan_global_packages:
        findings.extend(scan_global_packages(ctx))
    findings.sort(key=lambda item: (-SEVERITY_ORDER[item.severity], item.category, item.id, item.location))
    return AuditReport(generated_at=ctx.now, home=ctx.home, findings=findings)

