import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from agentshield.baseline import apply_baseline, load_baseline, write_baseline
from agentshield.models import AuditReport, Finding


def _finding(location: str = "env:TOKEN") -> Finding:
    return Finding(
        id="env.secret_like_variable",
        title="Secret-like value is present in the process environment",
        severity="medium",
        category="environment",
        location=location,
        evidence="TOKEN=tok...[redacted]",
        remediation="Use scoped credentials.",
    )


class BaselineTests(unittest.TestCase):
    def test_write_load_and_apply_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            finding = _finding()
            report = AuditReport(
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                home=Path(tmp),
                findings=[finding, _finding("env:NEW_TOKEN")],
            )

            write_baseline(report, path)
            fingerprints = load_baseline(path)
            self.assertIn(finding.fingerprint, fingerprints)

            filtered = apply_baseline(report, {finding.fingerprint})
            self.assertEqual(len(filtered.suppressed), 1)
            self.assertEqual(len(filtered.report.findings), 1)
            self.assertEqual(filtered.report.findings[0].location, "env:NEW_TOKEN")

    def test_load_baseline_rejects_invalid_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(path)


if __name__ == "__main__":
    unittest.main()
