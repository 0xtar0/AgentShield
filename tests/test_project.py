import tempfile
import unittest
from pathlib import Path

from agentshield.checks.project import scan_project
from agentshield.models import AuditContext


class ProjectScanTests(unittest.TestCase):
    def test_detects_sensitive_file_and_secret_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".gitignore").write_text(".env\n.env.*\n.npmrc\n.pypirc\n.netrc\n.aws/credentials\n.codex/auth.json\n", encoding="utf-8")
            (repo / ".env").write_text("API_KEY=sk-abcdefghijklmnopqrstuvwx\n", encoding="utf-8")

            findings = scan_project(AuditContext(home=repo, repo=repo, command_runner=lambda command, timeout: (1, "", "")))
            ids = {finding.id for finding in findings}
            self.assertIn("project.sensitive_file_present", ids)
            self.assertIn("project.files.secret_assignment", ids)

    def test_detects_missing_gitignore_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".gitignore").write_text("node_modules\n.env.example\n# .npmrc\n", encoding="utf-8")

            findings = scan_project(AuditContext(home=repo, repo=repo, command_runner=lambda command, timeout: (1, "", "")))
            finding = next(finding for finding in findings if finding.id == "project.gitignore_missing_secret_patterns")
            self.assertIn(".env", finding.metadata["missing_patterns"])
            self.assertIn(".npmrc", finding.metadata["missing_patterns"])

    def test_gitignore_wildcards_cover_env_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".gitignore").write_text(".env*\n.npmrc\n.pypirc\n.netrc\n.aws/credentials\n.codex/auth.json\n", encoding="utf-8")

            findings = scan_project(AuditContext(home=repo, repo=repo, command_runner=lambda command, timeout: (1, "", "")))
            self.assertEqual([finding.id for finding in findings], ["project.no_obvious_risks"])

    def test_does_not_flag_generic_credentials_or_auth_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".gitignore").write_text(".env\n.env.*\n.npmrc\n.pypirc\n.netrc\n.aws/credentials\n.codex/auth.json\n", encoding="utf-8")
            (repo / "credentials").write_text("not a cloud credential file\n", encoding="utf-8")
            (repo / "auth.json").write_text("{}\n", encoding="utf-8")

            findings = scan_project(AuditContext(home=repo, repo=repo, command_runner=lambda command, timeout: (1, "", "")))
            self.assertEqual([finding.id for finding in findings], ["project.no_obvious_risks"])

    def test_ignores_generated_report_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            reports = repo / "reports"
            reports.mkdir()
            (repo / ".gitignore").write_text(".env\n.env.*\n.npmrc\n.pypirc\n.netrc\n.aws/credentials\n.codex/auth.json\n", encoding="utf-8")
            (reports / ".env").write_text("TOKEN=sk-abcdefghijklmnopqrstuvwx\n", encoding="utf-8")

            findings = scan_project(AuditContext(home=repo, repo=repo, command_runner=lambda command, timeout: (1, "", "")))
            self.assertEqual([finding.id for finding in findings], ["project.no_obvious_risks"])

    def test_detects_tokenized_remote(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / ".gitignore").write_text(".env\n.env.*\n.npmrc\n.pypirc\n.netrc\n.aws/credentials\n.codex/auth.json\n", encoding="utf-8")

            def runner(command, timeout):
                if len(command) >= 3 and command[:2] == ["git", "-C"] and Path(command[2]) == repo.resolve():
                    return 0, "origin\thttps://oauth2:ghp_abcdefghijklmnopqrstuvwxyz1234567890@github.com/acme/repo.git (fetch)\n", ""
                return 1, "", ""

            findings = scan_project(AuditContext(home=repo, repo=repo, command_runner=runner))
            self.assertIn("project.tokenized_remote", {finding.id for finding in findings})
            self.assertTrue(all("abcdefghijklmnopqrstuvwxyz" not in finding.evidence for finding in findings))

    def test_detects_repo_agent_env_bridge(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            cursor = repo / ".cursor"
            cursor.mkdir()
            (repo / ".gitignore").write_text(".env\n.env.*\n.npmrc\n.pypirc\n.netrc\n.aws/credentials\n.codex/auth.json\n", encoding="utf-8")
            (cursor / "mcp.json").write_text('{"mcpServers": {"x": {"env": {"TOKEN": "placeholder"}}}}\n', encoding="utf-8")

            findings = scan_project(AuditContext(home=repo, repo=repo, command_runner=lambda command, timeout: (1, "", "")))
            self.assertIn("project.agent_config_env_bridge", {finding.id for finding in findings})


if __name__ == "__main__":
    unittest.main()
