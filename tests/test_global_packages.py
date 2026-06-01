import unittest
from pathlib import Path

from agentshield.checks.global_packages import scan_global_packages
from agentshield.models import AuditContext, Policy


class GlobalPackageTests(unittest.TestCase):
    def test_scans_additional_package_managers(self):
        def runner(command, timeout):
            outputs = {
                ("npm", "list", "-g", "--depth=0", "--json"): '{"dependencies": {}}',
                ("python", "-m", "pip", "list", "--user", "--format=json"): "[]",
                ("python3", "-m", "pip", "list", "--user", "--format=json"): "[]",
                ("pipx", "list", "--json"): '{"venvs": {}}',
                ("brew", "list", "--formula"): "git\nwallet-stealer\n",
                ("pnpm", "list", "-g", "--depth", "0", "--json"): '[{"dependencies": {"typescript": {"version": "1.0.0"}}}]',
                ("cargo", "install", "--list"): "ripgrep v14.0.0:\n    rg\n",
                ("gem", "list", "--local"): "bundler (2.5.0)\n",
            }
            value = outputs.get(tuple(command))
            return (0, value, "") if value is not None else (1, "", "")

        findings = scan_global_packages(AuditContext(home=Path("/tmp"), command_runner=runner))
        ids = {finding.id for finding in findings}
        self.assertIn("packages.homebrew.inventory", ids)
        self.assertIn("packages.homebrew.suspicious_name", ids)
        self.assertIn("packages.pnpm.inventory", ids)
        self.assertIn("packages.cargo.inventory", ids)
        self.assertIn("packages.gem.inventory", ids)

    def test_policy_trusted_packages_and_thresholds_affect_findings(self):
        def runner(command, timeout):
            if command == ["brew", "list", "--formula"]:
                return 0, "git\nopenssl\npython\n", ""
            return 1, "", ""

        policy = Policy(
            trusted_packages={"homebrew": frozenset({"git"})},
            max_global_packages={"homebrew": 2},
        )
        findings = scan_global_packages(AuditContext(home=Path("/tmp"), command_runner=runner, policy=policy))
        inventory = next(finding for finding in findings if finding.id == "packages.homebrew.inventory")
        self.assertEqual(inventory.metadata["packages"], ["openssl", "python"])
        self.assertIn("packages.homebrew.large_global_surface", {finding.id for finding in findings})

    def test_wrong_json_shapes_are_ignored(self):
        def runner(command, timeout):
            outputs = {
                ("npm", "list", "-g", "--depth=0", "--json"): "[]",
                ("python", "-m", "pip", "list", "--user", "--format=json"): "{}",
                ("python3", "-m", "pip", "list", "--user", "--format=json"): "{}",
                ("pipx", "list", "--json"): "[]",
            }
            value = outputs.get(tuple(command))
            return (0, value, "") if value is not None else (1, "", "")

        findings = scan_global_packages(AuditContext(home=Path("/tmp"), command_runner=runner))
        self.assertEqual([finding.id for finding in findings], ["packages.no_inventory"])


if __name__ == "__main__":
    unittest.main()
