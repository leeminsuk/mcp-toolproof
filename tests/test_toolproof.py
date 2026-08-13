import unittest

from toolproof import Observer, ToolServer, canonical_manifest, defense_decisions, expected_violation, manifest_sha256


class ToolProofTests(unittest.TestCase):
    def test_manifest_is_identical_for_server_modes(self):
        benign = canonical_manifest()
        malicious = canonical_manifest()
        self.assertEqual(benign, malicious)
        self.assertEqual(len(manifest_sha256()), 64)

    def test_payment_response_hides_effect_but_observer_detects(self):
        requested = {"recipient": "USER_00", "amount": 1_000_000}
        observer = Observer()
        response = ToolServer(observer, True, "conditional_substitution", True).call("payment_transfer", requested)
        self.assertEqual(response["recipient"], requested["recipient"])
        self.assertEqual(observer.ledger[-1]["recipient"], "ATTACKER_TEST_ACCOUNT")
        violations = expected_violation("payment_transfer", requested, observer.snapshot())
        decisions = defense_decisions(requested, response, violations)
        self.assertFalse(decisions["static_hash"])
        self.assertFalse(decisions["response_detector"])
        self.assertTrue(decisions["toolproof"])

    def test_readonly_scope_expansion(self):
        requested = {"path": "/sandbox/public.txt"}
        observer = Observer()
        ToolServer(observer, True, "scope_expansion", True).call("file_read", requested)
        self.assertEqual(expected_violation("file_read", requested, observer.snapshot()), ["readonly_scope_violation"])

    def test_benign_has_no_violation(self):
        requested = {"to": "user@local.test", "body": "hello"}
        observer = Observer()
        response = ToolServer(observer, False, "conditional_substitution", True).call("mail_send", requested)
        violations = expected_violation("mail_send", requested, observer.snapshot())
        self.assertEqual(violations, [])
        self.assertFalse(defense_decisions(requested, response, violations)["toolproof"])


if __name__ == "__main__":
    unittest.main()

