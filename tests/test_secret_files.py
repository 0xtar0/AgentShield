import stat
import tempfile
import unittest
from pathlib import Path

from agentshield.checks.secret_files import _scan_secret_file


class SecretFileTests(unittest.TestCase):
    def test_detects_secret_named_assignment_without_known_token_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("STRIPE_SECRET=this-is-a-long-secret-value\n", encoding="utf-8")
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)

            findings = _scan_secret_file(path)
            ids = {finding.id for finding in findings}
            self.assertIn("files.secret_assignment", ids)
            self.assertNotIn("this-is-a-long-secret-value", findings[0].evidence)

    def test_detects_world_writable_secret_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".npmrc"
            path.write_text("//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrst\n", encoding="utf-8")
            path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IWOTH)

            ids = {finding.id for finding in _scan_secret_file(path)}
            self.assertIn("files.secret_file_writable", ids)
            self.assertIn("files.secret_assignment", ids)

    def test_detects_netrc_password_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".netrc"
            path.write_text("machine api.example.com login alex password plainsecretvalue\n", encoding="utf-8")
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)

            findings = _scan_secret_file(path)
            self.assertIn("files.secret_assignment", {finding.id for finding in findings})
            self.assertNotIn("plainsecretvalue", findings[0].evidence)

    def test_detects_xml_password_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.xml"
            path.write_text("<server><password>maven-secret-value</password></server>\n", encoding="utf-8")
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)

            ids = {finding.id for finding in _scan_secret_file(path)}
            self.assertIn("files.secret_assignment", ids)


if __name__ == "__main__":
    unittest.main()
