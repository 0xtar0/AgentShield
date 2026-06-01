import unittest
import tempfile
from pathlib import Path

from agentshield.checks.git_config import _scan_git_config_text, scan_git_config
from agentshield.models import AuditContext


class GitConfigTests(unittest.TestCase):
    def test_detects_raw_ini_fallback_config(self):
        text = """
[credential]
    helper = store
[http]
    sslVerify = false
[safe]
    directory = *
"""
        ids = {finding.id for finding in _scan_git_config_text(text)}
        self.assertIn("git.plaintext_credential_store", ids)
        self.assertIn("git.ssl_verification_disabled", ids)
        self.assertIn("git.safe_directory_wildcard", ids)

    def test_detects_show_origin_config(self):
        text = "file:/Users/alex/.gitconfig\turl.https://oauth2:ghp_abcdefghijklmnopqrst@github.com/.insteadOf=https://github.com/\n"
        ids = {finding.id for finding in _scan_git_config_text(text)}
        self.assertIn("git.tokenized_config_url", ids)

    def test_detects_tokenized_raw_url_subsection(self):
        text = """
[url "https://oauth2:ghp_abcdefghijklmnopqrst@github.com/"]
    insteadOf = https://github.com/
"""
        ids = {finding.id for finding in _scan_git_config_text(text)}
        self.assertIn("git.tokenized_config_url", ids)

    def test_detects_tab_separated_raw_config_assignment(self):
        text = """
[credential]
    helper	=	store
"""
        ids = {finding.id for finding in _scan_git_config_text(text)}
        self.assertIn("git.plaintext_credential_store", ids)

    def test_custom_home_reads_that_home_gitconfig(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".gitconfig").write_text(
                """
[http]
    sslVerify = false
""",
                encoding="utf-8",
            )
            findings = scan_git_config(
                AuditContext(
                    home=home,
                    command_runner=lambda command, timeout: (0, "credential.helper=osxkeychain\n", ""),
                )
            )
            ids = {finding.id for finding in findings}
            self.assertIn("git.ssl_verification_disabled", ids)
            self.assertNotIn("git.no_obvious_risks", ids)

    def test_missing_custom_home_gitconfig_is_info_not_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = scan_git_config(AuditContext(home=Path(tmp)))
            self.assertEqual(findings[0].id, "git.no_obvious_risks")
            self.assertEqual(findings[0].severity, "info")


if __name__ == "__main__":
    unittest.main()
