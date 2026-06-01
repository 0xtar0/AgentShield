import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from agentshield.models import AuditReport, Finding
from agentshield.report import render_html, render_json, render_sarif, write_markdown


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

    def test_json_and_html_include_remediation_recipe(self):
        report = AuditReport(
            generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            home=Path("/tmp"),
            findings=[
                Finding(
                    id="git.ssl_verification_disabled",
                    title="Git SSL disabled",
                    severity="critical",
                    category="git",
                    location="global git config:1",
                    evidence="http.sslVerify=false",
                    remediation="Unset it.",
                )
            ],
        )

        payload = render_json(report)
        self.assertEqual(payload["findings"][0]["remediation_recipe"]["commands"], ["git config --global --unset http.sslVerify"])
        self.assertIn("Re-enable Git TLS verification", render_html(report))

    def test_markdown_includes_recipe_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.md"
            report = AuditReport(
                generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                home=Path(tmp),
                findings=[
                    Finding(
                        id="git.ssl_verification_disabled",
                        title="Git SSL disabled",
                        severity="critical",
                        category="git",
                        location="global git config:1",
                        evidence="http.sslVerify=false",
                        remediation="Unset it.",
                    )
                ],
            )
            write_markdown(report, path)
            content = path.read_text(encoding="utf-8")
            self.assertIn("git config --global --unset http.sslVerify", content)


if __name__ == "__main__":
    unittest.main()
