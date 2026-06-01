# GitHub Action

AgentShield ships as a composite GitHub Action.

```yaml
name: AgentShield

on:
  pull_request:
  push:
    branches: [main]

jobs:
  agentshield:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: 0xtar0/AgentShield@main
        with:
          fail-on: high
          format: all
          output: reports/agentshield.html
          skip-shell-history: "true"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: agentshield-reports
          path: reports/
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/agentshield.sarif
```

For gradual adoption, commit a policy or baseline and pass it to the action:

```yaml
- uses: 0xtar0/AgentShield@main
  with:
    policy: .agentshield-policy.json
    baseline: .agentshield-baseline.json
    fail-on: medium
```
