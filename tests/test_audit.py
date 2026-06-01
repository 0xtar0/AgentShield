import os
import stat
import tempfile
import unittest
from pathlib import Path

from agentshield.audit import run_audit
from agentshield.models import AuditContext


class AuditTests(unittest.TestCase):
    def test_detects_fixture_risks(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            ssh = home / ".ssh"
            ssh.mkdir()
            key = ssh / "id_rsa"
            key.write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n", encoding="utf-8")
            key.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
            history = home / ".bash_history"
            history.write_text("git clone https://user:supersecret@example.com/repo.git\nchmod 777 /tmp/x\n", encoding="utf-8")
            env = home / ".env"
            env.write_text("API_KEY=sk-abcdefghijklmnopqrstuvwx\n", encoding="utf-8")
            env.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)

            report = run_audit(
                AuditContext(
                    home=home,
                    scan_global_packages=False,
                    command_runner=lambda command, timeout: (0, "", ""),
                )
            )
            ids = {finding.id for finding in report.findings}
            self.assertIn("ssh.private_key_permissions", ids)
            self.assertIn("ssh.unencrypted_private_key", ids)
            self.assertIn("shell.credential_url", ids)
            self.assertIn("files.secret_file_permissions", ids)

    def test_audit_does_not_require_shell_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = run_audit(
                AuditContext(
                    home=Path(tmp),
                    scan_shell_history=False,
                    scan_global_packages=False,
                    command_runner=lambda command, timeout: (127, "", "missing"),
                )
            )
            self.assertGreater(len(report.findings), 0)


if __name__ == "__main__":
    unittest.main()

