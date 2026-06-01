import stat
import tempfile
import unittest
from pathlib import Path

from agentshield.checks.agent_tools import _scan_agent_config, scan_agent_tools
from agentshield.models import AuditContext


class AgentToolsTests(unittest.TestCase):
    def test_detects_agent_config_permissions_and_secret_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.json"
            path.write_text('{"token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}\n', encoding="utf-8")
            path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)

            findings = _scan_agent_config(path)
            ids = {finding.id for finding in findings}
            self.assertIn("agent.config_readable", ids)
            self.assertIn("agent.config_secret_pattern", ids)
            self.assertTrue(all("abcdefghijklmnopqrstuvwxyz" not in finding.evidence for finding in findings))

    def test_detects_agent_config_env_bridge(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp.json"
            path.write_text('{"mcpServers": {"x": {"env": {"TOKEN": "from-shell"}}}}\n', encoding="utf-8")
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)

            ids = {finding.id for finding in _scan_agent_config(path)}
            self.assertIn("agent.config_env_bridge", ids)

    def test_installed_agent_inventory_uses_runner(self):
        def runner(command, timeout):
            if command == ["which", "codex"]:
                return 0, "/opt/homebrew/bin/codex\n", ""
            return 1, "", ""

        findings = scan_agent_tools(AuditContext(home=Path("/tmp"), command_runner=runner))
        self.assertIn("agent.installed_cli_inventory", {finding.id for finding in findings})


if __name__ == "__main__":
    unittest.main()
