import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from agentshield.models import AuditReport, Finding
from agentshield.report import render_sarif


class ReportTests(unittest.TestCase):
    def test_sarif_contains_rules_and_locations(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            target = home / ".env"
            target.write_text("TOKEN=redacted\n", encoding="utf-8")
            report = AuditReport(
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                home=home,
                findings=[
                    Finding(
                        id="files.secret_assignment",
                        title="Secret assignment",
                        severity="high",
                        category="secret-files",
                        location=f"{target}:1",
                        evidence="TOKEN=[redacted]",
                        remediation="Rotate it.",
                    )
                ],
            )

            sarif = render_sarif(report)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")
            self.assertEqual(
                sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                ".env",
            )


if __name__ == "__main__":
    unittest.main()
