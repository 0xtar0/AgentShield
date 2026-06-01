from __future__ import annotations

from pathlib import Path

from agentshield.models import AuditContext, Finding
from agentshield.redact import TOKEN_PATTERNS, redact
from agentshield.utils import default_command_runner, is_group_or_world_readable, is_group_or_world_writable, mode_octal, safe_read_text

AGENT_COMMANDS = ["codex", "claude", "cursor", "aider", "opencode", "goose"]

AGENT_CONFIG_CANDIDATES = [
    ".codex/auth.json",
    ".codex/config.toml",
    ".claude.json",
    ".claude/settings.json",
    ".config/claude/settings.json",
    ".cursor/mcp.json",
    ".cursor/config.json",
    ".config/Code/User/mcp.json",
    "Library/Application Support/Claude/claude_desktop_config.json",
]


def scan_agent_tools(ctx: AuditContext) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_installed_agent_commands(ctx))
    for relative in AGENT_CONFIG_CANDIDATES:
        path = ctx.home / relative
        if path.exists() and path.is_file():
            findings.extend(_scan_agent_config(path))
    if not findings:
        findings.append(
            Finding(
                id="agent.no_obvious_exposure",
                title="No obvious AI agent tool exposure detected",
                severity="info",
                category="agent-tools",
                location=str(ctx.home),
                evidence="Known agent CLIs and config files were absent or did not match exposure heuristics.",
                remediation="Keep agent auth files private and scope credentials per workflow.",
            )
        )
    return findings


def _scan_installed_agent_commands(ctx: AuditContext) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    installed: list[str] = []
    for command in AGENT_COMMANDS:
        code, stdout, _ = runner(["which", command], 3)
        if code == 0 and stdout.strip():
            installed.append(command)
    if not installed:
        return []
    return [
        Finding(
            id="agent.installed_cli_inventory",
            title="AI agent CLI inventory captured",
            severity="info",
            category="agent-tools",
            location="PATH",
            evidence=", ".join(installed),
            remediation="Review which CLIs can access your shell environment, repositories, and credentials.",
            metadata={"commands": installed},
        )
    ]


def _scan_agent_config(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if is_group_or_world_readable(path):
        findings.append(
            Finding(
                id="agent.config_readable",
                title="AI agent config file is readable by group or others",
                severity="high",
                category="agent-tools",
                location=str(path),
                evidence=f"Mode is {mode_octal(path)}.",
                remediation=f"Run chmod 600 {path} if it contains tokens, MCP server env vars, or account data.",
            )
        )
    if is_group_or_world_writable(path):
        findings.append(
            Finding(
                id="agent.config_writable",
                title="AI agent config file is writable by group or others",
                severity="critical",
                category="agent-tools",
                location=str(path),
                evidence=f"Mode is {mode_octal(path)}.",
                remediation=f"Run chmod 600 {path} and verify only your user owns it.",
            )
        )
    try:
        content = safe_read_text(path, 512_000)
    except OSError as exc:
        return findings + [
            Finding(
                id="agent.config_unreadable",
                title="AI agent config file could not be read",
                severity="low",
                category="agent-tools",
                location=str(path),
                evidence=str(exc),
                remediation="Check permissions if this agent config should be included in audits.",
            )
        ]
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if any(pattern.search(stripped) for pattern in TOKEN_PATTERNS):
            findings.append(
                Finding(
                    id="agent.config_secret_pattern",
                    title="Secret-like value found in AI agent config",
                    severity="high",
                    category="agent-tools",
                    location=f"{path}:{line_number}",
                    evidence=redact(stripped),
                    remediation="Move long-lived secrets out of agent config files and rotate any exposed token.",
                )
            )
        if '"env"' in stripped or "'env'" in stripped or stripped.startswith("env "):
            findings.append(
                Finding(
                    id="agent.config_env_bridge",
                    title="AI agent config appears to bridge environment variables into tools",
                    severity="medium",
                    category="agent-tools",
                    location=f"{path}:{line_number}",
                    evidence=redact(stripped),
                    remediation="Confirm MCP/tool environment variables are scoped to only the servers that need them.",
                )
            )
    return findings
