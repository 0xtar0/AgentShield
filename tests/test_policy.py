import tempfile
import unittest
from pathlib import Path

from agentshield.models import Finding
from agentshield.policy import apply_policy, load_policy, write_default_policy


class PolicyTests(unittest.TestCase):
    def test_write_and_load_default_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".agentshield-policy.json"
            write_default_policy(path)
            policy = load_policy(path)
            self.assertIn("npm", policy.trusted_packages)
            self.assertEqual(policy.max_global_packages["npm"], 25)

    def test_policy_ignores_and_overrides_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(
                """
{
  "ignored_ids": ["agent.installed_cli_inventory"],
  "severity_overrides": {"packages.npm.large_global_surface": "low"},
  "trusted_packages": {"npm": ["typescript"]},
  "max_global_packages": {"npm": 3}
}
""",
                encoding="utf-8",
            )
            policy = load_policy(path)
            findings = [
                Finding("agent.installed_cli_inventory", "Inventory", "info", "agent-tools", "PATH", "codex", "Review."),
                Finding("packages.npm.large_global_surface", "Large", "medium", "global-packages", "npm", "4 packages", "Trim."),
            ]
            filtered = apply_policy(findings, policy)
            self.assertEqual(len(filtered), 1)
            self.assertEqual(filtered[0].severity, "low")
            self.assertTrue(policy.is_trusted_package("npm", "TypeScript"))

    def test_policy_rejects_invalid_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text('{"severity_overrides": {"x": "urgent"}}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_policy(path)


if __name__ == "__main__":
    unittest.main()
