from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex

from agentshield.models import Finding


@dataclass(frozen=True)
class RemediationRecipe:
    title: str
    commands: list[str]
    manual_steps: list[str]
    caution: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "commands": self.commands,
            "manual_steps": self.manual_steps,
            "caution": self.caution,
        }


def recipe_for(finding: Finding) -> RemediationRecipe:
    path = _path_from_location(finding.location)
    if finding.id in {
        "ssh.private_key_permissions",
        "ssh.config_permissions",
        "files.secret_file_permissions",
        "agent.config_readable",
    } and path:
        return RemediationRecipe(
            title="Restrict file permissions",
            commands=[f"chmod 600 {_shell_path(path)}"],
            manual_steps=["Verify the file is owned by your user.", "Re-run AgentShield to confirm the permission finding is gone."],
        )
    if finding.id in {"ssh.directory_permissions"} and path:
        return RemediationRecipe(
            title="Restrict SSH directory permissions",
            commands=[f"chmod 700 {_shell_path(path)}"],
            manual_steps=["Verify the directory is owned by your user.", "Re-run AgentShield to confirm the permission finding is gone."],
        )
    if finding.id in {"files.secret_file_writable", "agent.config_writable"} and path:
        return RemediationRecipe(
            title="Remove group/world write access",
            commands=[f"chmod 600 {_shell_path(path)}"],
            manual_steps=["Verify no other local users or processes can modify the file."],
        )
    if finding.id == "git.ssl_verification_disabled":
        return RemediationRecipe(
            title="Re-enable Git TLS verification",
            commands=["git config --global --unset http.sslVerify"],
            manual_steps=["Fix the underlying certificate or proxy issue instead of disabling TLS verification."],
            caution="This changes global Git behavior for the current user.",
        )
    if finding.id == "git.plaintext_credential_store":
        return RemediationRecipe(
            title="Move Git credentials out of plaintext storage",
            commands=["git config --global --unset credential.helper"],
            manual_steps=[
                "Configure an OS-backed Git credential manager for your platform.",
                "Delete any plaintext credentials left in ~/.git-credentials after rotating exposed tokens.",
            ],
            caution="Rotate credentials before deleting local backups if you are unsure what was stored.",
        )
    if finding.id == "git.safe_directory_wildcard":
        return RemediationRecipe(
            title="Replace wildcard Git trust with explicit paths",
            commands=["git config --global --unset-all safe.directory"],
            manual_steps=["Add back only specific trusted repositories with git config --global --add safe.directory /path/to/repo."],
            caution="This can make Git prompt again for repositories with unusual ownership.",
        )
    if finding.id in {"git.tokenized_config_url", "shell.secret_in_history", "shell.credential_url"}:
        return RemediationRecipe(
            title="Rotate exposed credentials",
            commands=[],
            manual_steps=[
                "Rotate the exposed token or password with the provider.",
                "Remove the credential from local config, shell history, and backups.",
                "Prefer credential managers, short-lived tokens, or scoped environment files.",
            ],
            caution="Do not paste the exposed secret into issue trackers, chat, or AI tools.",
        )
    if finding.id == "ssh.unencrypted_private_key" and path:
        return RemediationRecipe(
            title="Add a passphrase to the SSH private key",
            commands=[f"ssh-keygen -p -f {_shell_path(path)}"],
            manual_steps=["Use a strong passphrase and store it in your OS keychain or SSH agent."],
        )
    if finding.id in {"ssh.strict_host_key_checking_disabled", "ssh.known_hosts_disabled", "git.unsafe_ssh_command"}:
        return RemediationRecipe(
            title="Restore SSH host-key verification",
            commands=[],
            manual_steps=[
                "Remove StrictHostKeyChecking=no and UserKnownHostsFile=/dev/null from the relevant config.",
                "Connect once to trusted hosts and verify fingerprints before accepting them.",
            ],
        )
    if finding.id == "ssh.agent_forwarding_enabled":
        return RemediationRecipe(
            title="Limit SSH agent forwarding",
            commands=[],
            manual_steps=["Disable ForwardAgent globally and enable it only for specific trusted hosts that require it."],
        )
    if finding.id in {"env.secret_like_variable", "agent.config_secret_pattern", "files.secret_assignment", "files.secret_pattern"}:
        return RemediationRecipe(
            title="Scope and rotate secret material",
            commands=[],
            manual_steps=[
                "Rotate the credential if it may have been exposed.",
                "Move long-lived secrets into a credential manager or scoped environment file.",
                "Launch coding agents only with the minimum environment they need.",
            ],
        )
    if finding.id == "project.sensitive_file_present":
        return RemediationRecipe(
            title="Remove sensitive file from repository",
            commands=[],
            manual_steps=[
                "Confirm the file contains only safe example data before committing it.",
                "Move real secrets outside the repository and add a sanitized .example file if documentation is needed.",
                "Add the file pattern to .gitignore and remove any committed secret history if necessary.",
            ],
        )
    if finding.id == "project.gitignore_missing":
        return RemediationRecipe(
            title="Add repository secret ignore rules",
            commands=[],
            manual_steps=["Create a .gitignore with patterns for .env, .env.*, .npmrc, .pypirc, .netrc, and cloud credential files."],
        )
    if finding.id == "project.gitignore_missing_secret_patterns":
        return RemediationRecipe(
            title="Extend .gitignore secret protections",
            commands=[],
            manual_steps=["Add the missing secret-file patterns listed in the finding evidence to .gitignore."],
        )
    if finding.id == "project.tokenized_remote":
        return RemediationRecipe(
            title="Remove tokenized Git remote",
            commands=[],
            manual_steps=[
                "Rotate the embedded token.",
                "Replace the remote with an SSH URL or credential-manager-backed HTTPS URL.",
                "Check commit history and local config for the same token.",
            ],
            caution="Do not paste the tokenized remote URL into issue trackers, chat, or AI tools.",
        )
    if finding.id == "project.agent_config_env_bridge":
        return RemediationRecipe(
            title="Sanitize repo-local agent config",
            commands=[],
            manual_steps=[
                "Keep only placeholder env values in committed MCP or agent config.",
                "Move real tool environment variables into local user config or CI secrets.",
            ],
        )
    if finding.id.endswith(".large_global_surface"):
        return RemediationRecipe(
            title="Reduce global package attack surface",
            commands=[],
            manual_steps=[
                "Remove unused global packages.",
                "Move project-specific tools into project-local dependencies.",
                "Add expected global tools to trusted_packages in your AgentShield policy.",
            ],
        )
    if finding.id.endswith(".suspicious_name"):
        return RemediationRecipe(
            title="Verify suspicious package",
            commands=[],
            manual_steps=[
                "Confirm the package is expected and from a trusted source.",
                "Remove it if it is unused or unrecognized.",
                "Review shell history and package-manager logs if the package is unexpected.",
            ],
        )
    return RemediationRecipe(
        title="Review finding",
        commands=[],
        manual_steps=[finding.remediation],
    )


def _path_from_location(location: str) -> str:
    path_text = location
    if ":" in path_text:
        maybe_path, maybe_line = path_text.rsplit(":", 1)
        if maybe_line.isdigit():
            path_text = maybe_path
    path = Path(path_text)
    if path_text.startswith("~") or path.is_absolute():
        return path_text
    return ""


def _shell_path(path: str) -> str:
    if path.startswith("~/"):
        return "~/" + shlex.quote(path[2:])
    return shlex.quote(path)
