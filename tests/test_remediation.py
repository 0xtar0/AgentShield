import unittest

from agentshield.models import Finding
from agentshield.remediation import recipe_for


class RemediationTests(unittest.TestCase):
    def test_file_permission_recipe_shell_quotes_path(self):
        finding = Finding(
            id="ssh.private_key_permissions",
            title="Bad permissions",
            severity="critical",
            category="ssh",
            location="/tmp/path with spaces/id_rsa",
            evidence="Mode is 0o644.",
            remediation="Run chmod 600.",
        )

        recipe = recipe_for(finding)
        self.assertEqual(recipe.commands, ["chmod 600 '/tmp/path with spaces/id_rsa'"])

    def test_secret_exposure_recipe_has_manual_steps_not_commands(self):
        finding = Finding(
            id="shell.secret_in_history",
            title="Secret in history",
            severity="critical",
            category="shell-history",
            location="/tmp/.bash_history:1",
            evidence="TOKEN=[redacted]",
            remediation="Rotate it.",
        )

        recipe = recipe_for(finding)
        self.assertEqual(recipe.commands, [])
        self.assertTrue(any("Rotate" in step for step in recipe.manual_steps))


if __name__ == "__main__":
    unittest.main()
