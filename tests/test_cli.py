import argparse
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from agentshield.cli import _positive_int, main


class CliTests(unittest.TestCase):
    def test_positive_int_rejects_zero_and_negative_values(self):
        for value in ("0", "-1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                _positive_int(value)

    def test_positive_int_accepts_positive_values(self):
        self.assertEqual(_positive_int("1024"), 1024)

    def test_init_policy_writes_file_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["init-policy", "--output", str(path)]), 0)
                self.assertTrue(path.exists())
                self.assertEqual(main(["init-policy", "--output", str(path)]), 2)
                self.assertEqual(main(["init-policy", "--output", str(path), "--force"]), 0)

    def test_scan_accepts_repo_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".gitignore").write_text(".env\n.env.*\n.npmrc\n.pypirc\n.netrc\n.aws/credentials\n.codex/auth.json\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "scan",
                        "--home",
                        str(repo),
                        "--repo",
                        str(repo),
                        "--skip-shell-history",
                        "--skip-global-packages",
                        "--format",
                        "json",
                        "--output",
                        str(repo / "report.html"),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertTrue((repo / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
