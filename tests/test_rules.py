import unittest

from agentshield.rules import rules_for_category


class RuleCatalogTests(unittest.TestCase):
    def test_rules_are_sorted_and_filterable(self):
        project_rules = rules_for_category("project")
        self.assertGreater(len(project_rules), 0)
        self.assertEqual(project_rules, sorted(project_rules, key=lambda rule: rule.id))
        self.assertTrue(all(rule.category == "project" for rule in project_rules))


if __name__ == "__main__":
    unittest.main()
