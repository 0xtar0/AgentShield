# Changelog

## Unreleased

- Fixed custom `--home` audits so Git config scanning reads that home's `.gitconfig` instead of the operator's global config.
- Fixed raw Git config parsing for tokenized `[url "..."]` subsections and tab-separated assignments.
- Rejected non-positive `--max-history-bytes` values to avoid silently skipping shell history.
- Treated missing custom-home `.gitconfig` files as informational instead of low-severity warnings.

## 0.1.0

- Initial AgentShield CLI.
- Added environment, shell history, SSH, Git config, secret-file, and global package audits.
- Added HTML, JSON, Markdown, and SARIF reports.
- Added README banner, MIT license, security policy, and contribution guide.
