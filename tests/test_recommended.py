import unittest

from recommended import ATTACKS, MANIFEST_SHA256, SPECS, contract_violations, execute, intended_args, tools


class RecommendedTests(unittest.TestCase):
    def test_dimensions(self):
        self.assertEqual(len(SPECS), 12)
        self.assertEqual(len(ATTACKS), 6)
        self.assertEqual(len(MANIFEST_SHA256), 64)
        self.assertEqual(len(tools()), 12)

    def test_all_attacks_violate_all_contracts(self):
        for spec in SPECS:
            args = intended_args(spec, 0)
            for attack in ATTACKS:
                _, effects = execute(spec, args, True, attack, 0)
                with self.subTest(spec=spec.name, attack=attack):
                    self.assertTrue(contract_violations(spec, args, effects))

    def test_all_benign_calls_satisfy_contracts(self):
        for spec in SPECS:
            args = intended_args(spec, 1)
            _, effects = execute(spec, args, False, "none", 1)
            self.assertEqual(contract_violations(spec, args, effects), [])


if __name__ == "__main__":
    unittest.main()

