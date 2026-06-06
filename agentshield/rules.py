from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    default_severity: str
    title: str

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "category": self.category,
            "default_severity": self.default_severity,
            "title": self.title,
        }


RULES = [
    Rule("agent.config_readable", "agent-tools", "high", "AI agent config file is readable by group or others"),
    Rule("agent.config_secret_pattern", "agent-tools", "high", "Secret-like value found in AI agent config"),
    Rule("agent.config_writable", "agent-tools", "critical", "AI agent config file is writable by group or others"),
    Rule("agent.config_env_bridge", "agent-tools", "medium", "AI agent config appears to bridge environment variables into tools"),
    Rule("agent.installed_cli_inventory", "agent-tools", "info", "AI agent CLI inventory captured"),
    Rule("agent.no_obvious_exposure", "agent-tools", "info", "No obvious AI agent tool exposure detected"),
    Rule("env.path_world_writable", "environment", "high", "PATH contains a group/world-writable directory"),
    Rule("env.secret_like_variable", "environment", "medium", "Secret-like value is present in the process environment"),
    Rule("files.secret_assignment", "secret-files", "high", "Secret-like assignment found in a known credential file"),
    Rule("files.secret_file_permissions", "secret-files", "high", "Secret-bearing file is readable by group or others"),
    Rule("files.secret_file_writable", "secret-files", "critical", "Secret-bearing file is writable by group or others"),
    Rule("files.secret_pattern", "secret-files", "medium", "Secret-like value found in a known credential file"),
    Rule("git.plaintext_credential_store", "git", "high", "Git is configured to store credentials in plaintext"),
    Rule("git.safe_directory_wildcard", "git", "medium", "Git safe.directory trusts every repository"),
    Rule("git.ssl_verification_disabled", "git", "critical", "Git SSL certificate verification is disabled"),
    Rule("git.tokenized_config_url", "git", "critical", "Git config appears to contain an embedded access token"),
    Rule("git.unsafe_ssh_command", "git", "high", "Git SSH command disables host-key protection"),
    Rule("packages.*.inventory", "global-packages", "info", "Global package inventory captured"),
    Rule("packages.*.large_global_surface", "global-packages", "medium", "Package manager has a large global package footprint"),
    Rule("packages.*.suspicious_name", "global-packages", "medium", "Global package has a suspicious name"),
    Rule("project.agent_config_env_bridge", "project", "medium", "Repository agent config appears to bridge environment variables into tools"),
    Rule("project.gitignore_missing", "project", "medium", "Repository is missing a .gitignore file"),
    Rule("project.gitignore_missing_secret_patterns", "project", "medium", ".gitignore is missing common secret-file patterns"),
    Rule("project.sensitive_file_present", "project", "high", "Sensitive-looking file exists inside the repository"),
    Rule("project.tokenized_remote", "project", "critical", "Repository remote appears to contain an embedded credential"),
    Rule("shell.chmod_777", "shell-history", "medium", "Command used broad world-writable permissions"),
    Rule("shell.credential_url", "shell-history", "critical", "Credential-bearing URL appears in shell history"),
    Rule("shell.curl_pipe_shell", "shell-history", "high", "Downloaded script was piped directly to a shell"),
    Rule("shell.docker_password", "shell-history", "high", "Docker password appears on command line"),
    Rule("shell.secret_in_history", "shell-history", "critical", "Secret-like value appears in shell history"),
    Rule("shell.sshpass_password", "shell-history", "high", "SSH password appears on command line"),
    Rule("shell.wget_pipe_shell", "shell-history", "high", "Downloaded script was piped directly to a shell"),
    Rule("ssh.agent_forwarding_enabled", "ssh", "medium", "SSH agent forwarding is enabled"),
    Rule("ssh.config_permissions", "ssh", "low", "SSH config is readable by group or others"),
    Rule("ssh.directory_permissions", "ssh", "high", "SSH directory is writable by group or others"),
    Rule("ssh.known_hosts_disabled", "ssh", "high", "Known-host tracking is disabled"),
    Rule("ssh.missing_known_hosts", "ssh", "low", "SSH known_hosts file is missing"),
    Rule("ssh.private_key_permissions", "ssh", "critical", "SSH private key is readable or writable by group/others"),
    Rule("ssh.strict_host_key_checking_disabled", "ssh", "high", "StrictHostKeyChecking is disabled"),
    Rule("ssh.unencrypted_private_key", "ssh", "high", "SSH private key appears to be unencrypted"),
]


def rules_for_category(category: str | None = None) -> list[Rule]:
    if category is None:
        return sorted(RULES, key=lambda rule: (rule.category, rule.id))
    return sorted((rule for rule in RULES if rule.category == category), key=lambda rule: rule.id)
