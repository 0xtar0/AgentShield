# AgentShield

![AgentShield banner](assets/banner.png)

**Secure your dev laptop before agents touch it.**

AgentShield is a local-first security auditor for developers using AI coding agents, terminal agents, IDE assistants, and automation-heavy workflows. It scans the places where agentic tools commonly inherit power: environment variables, shell history, SSH keys, Git config, secret-bearing dotfiles, and global developer packages.

It never uploads data, never remediates without you, and redacts sensitive evidence in reports.

## Features

- Exposed environment variable audit with secret-name and high-entropy detection
- Risky shell history scanner for pasted tokens, `curl | sh`, plaintext passwords, broad chmods, and credential-bearing URLs
- SSH audit for weak file permissions, unencrypted private keys, missing `known_hosts`, and unsafe client config
- Git global config audit for plaintext credential helpers, disabled SSL verification, tokenized remotes, and unsafe SSH commands
- Secret-bearing file audit for `.env`, `.npmrc`, `.pypirc`, `.netrc`, AWS credentials, Docker auth config, and GitHub CLI hosts
- Global package inventory for npm, pip, and pipx, with warnings for suspicious package names and large global attack surfaces
- HTML, JSON, and Markdown reports suitable for local review or CI artifacts
- CI-friendly failure thresholds with `--fail-on`

## Install

```bash
python3 -m pip install -e .
```

No runtime dependencies are required.

## Quick Start

```bash
agentshield scan --output reports/agentshield.html --json-output reports/agentshield.json
```

Generate every report format:

```bash
agentshield scan --format all --output reports/agentshield.html
```

Audit another home directory, such as a test fixture or mounted workstation profile:

```bash
agentshield scan --home /Users/alex --format all
```

Use it in CI without failing unless a high-severity issue is found:

```bash
agentshield scan --fail-on high --json-output agentshield.json
```

## Example Output

```text
AgentShield audit complete
Risk score: 68/100
Findings: 2 critical, 4 high, 5 medium, 7 low, 3 info
HTML report: reports/agentshield.html
JSON report: reports/agentshield.json
```

## What AgentShield Checks

| Area | Checks |
| --- | --- |
| Environment | Secret-like names, token patterns, high-entropy values, unsafe PATH entries |
| Shell history | API keys, exported secrets, passwords in commands, credential URLs, `curl | sh`, `chmod 777` |
| SSH | Private key permissions, unencrypted keys, `.ssh` permissions, unsafe `StrictHostKeyChecking`, missing `known_hosts` |
| Git | `credential.helper=store`, `http.sslVerify=false`, tokenized URL rewrites, unsafe SSH commands |
| Secret files | `.env`, `.npmrc`, `.pypirc`, `.netrc`, AWS credentials, Docker auth, GitHub CLI hosts |
| Global packages | npm, pip, and pipx inventory, suspicious names, broad global package footprint |

## Privacy Model

AgentShield is intentionally local:

- No network calls
- No telemetry
- No dependency downloads at runtime
- Secret values are redacted before being written to reports
- Scans are read-only

## CLI

```text
usage: agentshield scan [options]

options:
  --home PATH                 Home directory to audit
  --output PATH               HTML report path
  --json-output PATH          JSON report path
  --markdown-output PATH      Markdown report path
  --format html|json|md|all   Report format convenience switch
  --skip-shell-history        Skip shell history scanning
  --skip-global-packages      Skip npm/pip/pipx inventory
  --max-history-bytes N       Bytes to read from the end of each history file
  --fail-on LEVEL             Exit non-zero on low|medium|high|critical findings
```

## Development

```bash
python3 -m unittest discover -s tests
python3 -m agentshield scan --skip-global-packages --format all
```

## Roadmap

- SARIF output for code scanning dashboards
- Optional remediation recipes
- VS Code task integration
- Policy files for team-specific baselines
- Additional package managers: Homebrew, cargo, gem, pnpm

## License

MIT
