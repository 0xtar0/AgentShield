import unittest

from agentshield.redact import looks_high_entropy, redact


class RedactionTests(unittest.TestCase):
    def test_redacts_github_token(self):
        text = "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        redacted = redact(text)
        self.assertIn("[redacted]", redacted)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", redacted)

    def test_detects_high_entropy(self):
        self.assertTrue(looks_high_entropy("aZ9xQwErTy1234567890_pOiUlkJHgfDSA"))
        self.assertFalse(looks_high_entropy("not-a-secret"))


if __name__ == "__main__":
    unittest.main()

