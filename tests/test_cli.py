import argparse
import unittest

from agentshield.cli import _positive_int


class CliTests(unittest.TestCase):
    def test_positive_int_rejects_zero_and_negative_values(self):
        for value in ("0", "-1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                _positive_int(value)

    def test_positive_int_accepts_positive_values(self):
        self.assertEqual(_positive_int("1024"), 1024)


if __name__ == "__main__":
    unittest.main()
