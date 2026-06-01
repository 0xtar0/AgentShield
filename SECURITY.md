# Security Policy

AgentShield is a local read-only auditor. It should not upload secrets, mutate config, or print unredacted sensitive values.

## Reporting Vulnerabilities

Please open a private security advisory on GitHub if you find:

- Secret disclosure in generated reports
- Unsafe file writes
- Command execution that can be influenced by scanned files
- Incorrect remediation guidance that weakens workstation security

If private advisories are unavailable, open an issue with a minimal reproduction and avoid posting real credentials.

## Supported Versions

The `main` branch and the latest tagged release receive security fixes.

