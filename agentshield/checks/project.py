from __future__ import annotations

from pathlib import Path

from agentshield.checks.secret_files import _scan_secret_file
from agentshield.models import AuditContext, Finding
from agentshield.redact import TOKEN_PATTERNS, redact
from agentshield.utils import default_command_runner, safe_read_text

IGNORED_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

SENSITIVE_FILENAMES = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "credentials",
    "credentials.toml",
    "auth.json",
    "mcp.json",
    "claude_desktop_config.json",
}

GITIGNORE_PATTERNS = [".env", ".env.*", ".npmrc", ".pypirc", ".netrc", ".aws/credentials", ".codex/auth.json"]


def scan_project(ctx: AuditContext) -> list[Finding]:
    if ctx.repo is None:
        return []
    repo = ctx.repo.expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        return [
            Finding(
                id="project.repo_unavailable",
                title="Repository path could not be inspected",
                severity="low",
                category="project",
                location=str(repo),
                evidence="Path does not exist or is not a directory.",
                remediation="Pass a valid repository directory to --repo.",
            )
        ]

    findings: list[Finding] = []
    findings.extend(_scan_gitignore(repo))
    findings.extend(_scan_repo_remotes(ctx, repo))
    for path in _iter_sensitive_files(repo):
        findings.append(
            Finding(
                id="project.sensitive_file_present",
                title="Sensitive-looking file exists inside the repository",
                severity="high",
                category="project",
                location=str(path),
                evidence=f"{path.relative_to(repo)} exists in the repository tree.",
                remediation="Ensure this file is not committed. Move real secrets outside the repo and keep only safe examples.",
            )
        )
        findings.extend(_project_secret_findings(path))
        findings.extend(_scan_project_agent_config(path))

    if not findings:
        findings.append(
            Finding(
                id="project.no_obvious_risks",
                title="No obvious repository security risks detected",
                severity="info",
                category="project",
                location=str(repo),
                evidence="Project scan did not find known sensitive filenames, tokenized remotes, or missing secret ignore patterns.",
                remediation="Continue keeping real secrets outside the repository.",
            )
        )
    return findings


def _scan_gitignore(repo: Path) -> list[Finding]:
    path = repo / ".gitignore"
    if not path.exists():
        return [
            Finding(
                id="project.gitignore_missing",
                title="Repository is missing a .gitignore file",
                severity="medium",
                category="project",
                location=str(repo),
                evidence=".gitignore was not found.",
                remediation="Add a .gitignore that excludes real secret files such as .env, .npmrc, and cloud credentials.",
            )
        ]
    try:
        content = safe_read_text(path, 128_000)
    except OSError as exc:
        return [
            Finding(
                id="project.gitignore_unreadable",
                title="Repository .gitignore could not be read",
                severity="low",
                category="project",
                location=str(path),
                evidence=str(exc),
                remediation="Check .gitignore permissions and contents.",
            )
        ]
    missing = [pattern for pattern in GITIGNORE_PATTERNS if pattern not in content]
    if not missing:
        return []
    return [
        Finding(
            id="project.gitignore_missing_secret_patterns",
            title=".gitignore is missing common secret-file patterns",
            severity="medium",
            category="project",
            location=str(path),
            evidence=", ".join(missing),
            remediation="Add missing secret-file patterns to .gitignore and keep committed examples sanitized.",
            metadata={"missing_patterns": missing},
        )
    ]


def _scan_repo_remotes(ctx: AuditContext, repo: Path) -> list[Finding]:
    runner = ctx.command_runner or default_command_runner
    code, stdout, _ = runner(["git", "-C", str(repo), "remote", "-v"], 8)
    if code != 0 or not stdout.strip():
        return []
    findings: list[Finding] = []
    for line_number, line in enumerate(stdout.splitlines(), start=1):
        if any(pattern.search(line) for pattern in TOKEN_PATTERNS):
            findings.append(
                Finding(
                    id="project.tokenized_remote",
                    title="Repository remote appears to contain an embedded credential",
                    severity="critical",
                    category="project",
                    location=f"{repo}:remote:{line_number}",
                    evidence=redact(line),
                    remediation="Rotate the token and replace the remote with an SSH URL or credential-manager-backed HTTPS URL.",
                )
            )
    return findings


def _iter_sensitive_files(repo: Path) -> list[Path]:
    found: list[Path] = []
    stack = [repo]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in IGNORED_DIRS:
                    stack.append(entry)
                continue
            if _is_sensitive_file(entry):
                found.append(entry)
    return sorted(found)


def _is_sensitive_file(path: Path) -> bool:
    if path.name in SENSITIVE_FILENAMES:
        return True
    if path.name.startswith(".env."):
        return True
    relative = path.as_posix()
    return "/.aws/credentials" in relative or "/.codex/auth.json" in relative or "/.cursor/mcp.json" in relative


def _project_secret_findings(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for finding in _scan_secret_file(path):
        if finding.severity == "info":
            continue
        findings.append(
            Finding(
                id=f"project.{finding.id}",
                title=finding.title,
                severity=finding.severity,
                category="project",
                location=finding.location,
                evidence=finding.evidence,
                remediation=finding.remediation,
                metadata=finding.metadata,
            )
        )
    return findings


def _scan_project_agent_config(path: Path) -> list[Finding]:
    if path.name not in {"mcp.json", "claude_desktop_config.json", "auth.json"}:
        return []
    try:
        content = safe_read_text(path, 512_000)
    except OSError:
        return []
    findings: list[Finding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if '"env"' in stripped or "'env'" in stripped or stripped.startswith("env "):
            findings.append(
                Finding(
                    id="project.agent_config_env_bridge",
                    title="Repository agent config appears to bridge environment variables into tools",
                    severity="medium",
                    category="project",
                    location=f"{path}:{line_number}",
                    evidence=redact(stripped),
                    remediation="Keep real MCP/tool env values outside the repository and document only placeholder examples.",
                )
            )
    return findings
