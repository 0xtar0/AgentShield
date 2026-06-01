# Contributing

Thanks for improving AgentShield.

## Local Setup

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

## Guidelines

- Keep scans read-only.
- Redact sensitive evidence before returning findings.
- Prefer deterministic checks over network-backed vulnerability lookups.
- Add tests for new detectors and redaction behavior.
- Keep remediation guidance specific and actionable.

