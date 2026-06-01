import unittest

from agentshield.checks.git_config import _scan_git_config_text


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


if __name__ == "__main__":
    unittest.main()

