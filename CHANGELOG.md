# Changelog

## Unreleased

- Added baseline write/apply support for gradual adoption and new-finding-only CI gates.
- Added AI agent tool exposure checks for local agent CLI inventory and sensitive agent config files.
- Added policy files for ignored finding IDs, severity overrides, trusted packages, and package-count thresholds.
- Added global package inventory support for Homebrew, pnpm, cargo, and gem.
- Fixed custom `--home` audits so Git config scanning reads that home's `.gitconfig` instead of the operator's global config.
- Fixed raw Git config parsing for tokenized `[url "..."]` subsections and tab-separated assignments.
- Rejected non-positive `--max-history-bytes` values to avoid silently skipping shell history.
- Treated missing custom-home `.gitconfig` files as informational instead of low-severity warnings.

## 0.1.0

- Initial AgentShield CLI.
- Added environment, shell history, SSH, Git config, secret-file, and global package audits.
- Added HTML, JSON, Markdown, and SARIF reports.
- Added README banner, MIT license, security policy, and contribution guide.
