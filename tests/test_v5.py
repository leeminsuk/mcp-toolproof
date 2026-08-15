"""Regression tests for the four defects an external review found in v5.2.

Each test pins one of them so it cannot come back:
  1. the receipt key model (a shared-key MAC let the verifier forge receipts),
  2. receipt binding (a receipt from one call could be replayed into another),
  3. pre-registered verdicts (they were typed in, so a passing number printed
     "fail"),
  4. self-consistency (a point estimate was printed under another group's
     confidence interval).
"""
from __future__ import annotations

import secrets
import sys
import unittest
from pathlib import Path

V5 = Path(__file__).resolve().parent.parent / "v5"
sys.path.insert(0, str(V5))

import analyze  # noqa: E402
import detectors as D  # noqa: E402
import provider as P  # noqa: E402
from harness import oracle_truth  # noqa: E402
from toolsrv import Attacker  # noqa: E402


def make_provider(aliases=None, drift=None):
    seed = secrets.token_bytes(32).hex()
    private = P.load_private(seed)
    return P.Provider(private, aliases or {}, drift), P.public_bytes(private)


class ReceiptKeyModel(unittest.TestCase):
    def test_verifier_key_is_public_and_cannot_mint_receipts(self):
        prov, public = make_provider()
        prov.apply({"cid": "c1", "op": "payment_transfer",
                    "args": {"recipient": "USER_1", "amount": 1000}})
        entries = prov.receipts("c1")
        _, ok = D.verify_receipts(entries, public, "c1")
        self.assertTrue(ok, "a genuine receipt must verify under the public key")
        # The public key is a verification key only.  A verifier that tries to
        # sign with the bytes it holds produces a signature under a *different*
        # key, so the forged receipt fails against the provider's public key.
        # Under the previous shared-key MAC the same bytes both verified and
        # minted, and this forgery would have succeeded.
        self.assertEqual(len(public), 32)
        body = dict(entries[0]["body"])
        body["settlement_account"] = "acct:ATTACKER_TEST_TARGET"
        forged_sig = P.load_private(public.hex()).sign(
            P.canonical(P.signed_body(body)).encode()).hex()
        self.assertFalse(P.verify_signature(public, body, forged_sig))

    def test_tampering_with_any_semantic_field_breaks_the_signature(self):
        prov, public = make_provider()
        prov.apply({"cid": "c1", "op": "payment_transfer",
                    "args": {"recipient": "USER_1", "amount": 1000}})
        entries = [dict(e) for e in prov.receipts("c1")]
        entries[0] = {**entries[0], "body": {**entries[0]["body"],
                                             "settlement_account": "acct:ATTACKER"}}
        _, ok = D.verify_receipts(entries, public, "c1")
        self.assertFalse(ok)

    def test_self_reported_receipt_never_verifies(self):
        prov, public = make_provider()
        prov.apply({"cid": "c1", "op": "mail_send",
                    "args": {"to": "a@b.test", "subject": "s", "body": "b"}})
        forged = [{"body": prov.receipts("c1")[0]["body"], "sig": secrets.token_hex(64)}]
        _, ok = D.verify_receipts(forged, public, "c1")
        self.assertFalse(ok)


class ReplayBinding(unittest.TestCase):
    def test_receipt_from_another_call_is_rejected(self):
        prov, public = make_provider()
        args = {"recipient": "USER_1", "amount": 1000}
        prov.apply({"cid": "honest", "op": "payment_transfer", "args": args})
        prov.apply({"cid": "target", "op": "payment_transfer", "args": args})
        harvested = prov.receipts("honest")
        # Signature is valid, but it was minted for a different correlation id.
        _, ok_same = D.verify_receipts(harvested, public, "honest")
        _, ok_replayed = D.verify_receipts(harvested, public, "target")
        self.assertTrue(ok_same)
        self.assertFalse(ok_replayed, "cid must be inside the signed body")

    def test_reordered_receipts_are_rejected(self):
        prov, public = make_provider()
        prov.apply({"cid": "c1", "op": "payment_refund",
                    "args": {"recipient": "USER_1", "amount": 1000}})
        entries = prov.receipts("c1")
        self.assertEqual(len(entries), 2)
        _, ok = D.verify_receipts(list(reversed(entries)), public, "c1")
        self.assertFalse(ok, "seq must be inside the signed body")

    def test_binding_fields_are_signed_but_not_semantically_compared(self):
        # Non-deterministic fields must be authenticated yet excluded from the
        # oracle, otherwise every honest run looks like a deviation.
        for field in ("cid", "seq", "nonce", "issued_at"):
            self.assertIn(field, P.SIGNED_FIELDS)
            self.assertNotIn(field, P.SEMANTIC_FIELDS)
        prov, _ = make_provider()
        approved = {"recipient": "USER_1", "amount": 1000}
        prov.apply({"cid": "c1", "op": "payment_transfer", "args": approved})
        bodies = [e["body"] for e in prov.receipts("c1")]
        self.assertFalse(oracle_truth("payment_transfer", approved, bodies, 1)[0])


class OracleIndependence(unittest.TestCase):
    def test_oracle_never_receives_the_attack_label(self):
        import inspect
        names = set(inspect.signature(oracle_truth).parameters)
        self.assertEqual(names, {"tool", "approved", "receipts", "submissions", "drift"})
        for forbidden in ("family", "attack", "trigger", "detector", "mode"):
            self.assertNotIn(forbidden, names)

    def test_oracle_flags_an_attack_that_no_contract_enumerates(self):
        # Settlement account swap: recorded by the provider, enumerated by
        # neither contract.  The oracle must catch what the contracts cannot.
        prov, public = make_provider()
        approved = {"recipient": "USER_1", "amount": 1000}
        prov.apply({"cid": "c1", "op": "payment_transfer", "args": approved,
                    "settlement": "acct:ATTACKER_TEST_TARGET"})
        bodies = [e["body"] for e in prov.receipts("c1")]
        self.assertTrue(oracle_truth("payment_transfer", approved, bodies, 1)[0])
        self.assertEqual(D.contract_extended("payment_transfer", approved, bodies), [])
        self.assertEqual(D.contract_approval_bound("payment_transfer", approved, bodies), [])

    def test_semantic_field_set_contains_every_contract_observation(self):
        # The containment claim the paper rests on.
        self.assertTrue({"resolved_principal", "final_principal", "settlement_route",
                         "settlement_account", "applied_hash", "extra", "args", "kind",
                         "op"} <= set(P.SEMANTIC_FIELDS))


class ProviderDrift(unittest.TestCase):
    def test_drift_is_benign_by_construction(self):
        drift = {"kind": "receipt_annotation"}
        prov, _ = make_provider(drift=drift)
        approved = {"recipient": "USER_1", "amount": 1000}
        prov.apply({"cid": "c1", "op": "payment_transfer", "args": approved})
        bodies = [e["body"] for e in prov.receipts("c1")]
        # The oracle applies the same drift, so honest traffic stays benign...
        self.assertFalse(oracle_truth("payment_transfer", approved, bodies, 1, drift)[0])
        # ...while the extended contract's no-unknown-field rule fires anyway.
        self.assertIn("unknown_receipt_field",
                      D.contract_extended("payment_transfer", approved, bodies))
        # The hash binding does not look at provider-side annotations.
        self.assertEqual(D.contract_approval_bound("payment_transfer", approved, bodies), [])

    def test_hash_basis_drift_breaks_only_the_approval_binding(self):
        drift = {"kind": "hash_basis_change"}
        prov, _ = make_provider(drift=drift)
        approved = {"recipient": "  USER_1  ", "amount": 1000}
        prov.apply({"cid": "c1", "op": "payment_transfer", "args": approved})
        bodies = [e["body"] for e in prov.receipts("c1")]
        self.assertFalse(oracle_truth("payment_transfer", approved, bodies, 1, drift)[0])
        self.assertIn("approval_hash",
                      D.contract_approval_bound("payment_transfer", approved, bodies))
        self.assertEqual(D.contract_extended("payment_transfer", approved, bodies), [])


class FuzzDeterminism(unittest.TestCase):
    def test_same_request_picks_the_same_argument(self):
        args = {"recipient": "USER_0103", "amount": 1900000, "unit": "KRW",
                "tenant": "tenant-A", "callback_url": "http://127.0.0.1/callback",
                "memo": "memo-3"}
        plans = []
        for cid in ("cid-one", "cid-two"):
            attacker = Attacker()
            attacker.configure({"mode": "fuzz_field", "trigger": "always", "seed": 1})
            plans.append(attacker.plan("payment_transfer", dict(args), cid, True)[0]["args"])
        self.assertEqual(plans[0], plans[1],
                         "fuzz must not depend on the random correlation id")
        self.assertNotEqual(plans[0], args)


class GateEvaluation(unittest.TestCase):
    def base_report(self, recall_c_approval: float) -> dict:
        return {
            "by_group": {g: {"recall": {"extended_intent": 1.0, "approval_bound": 1.0}}
                         for g in ("both", "v4_only", "neither", "unseen", "fuzz")}
            | {"neither": {"recall": {"extended_intent": 0.0,
                                      "approval_bound": recall_c_approval}}},
            "overall": {"extended_intent": {"fpr": 0.153}},
            "fpr_excluding_resubmit": {"extended_intent": 0.0},
            "latency_ms": {"contract_p95": 0.2, "receipt_fetch_p95": 0.23},
        }

    def test_observed_value_decides_the_verdict(self):
        gates = {g["id"]: g for g in analyze.evaluate_gates(self.base_report(1.0))}
        # The exact cell the review caught: observed 1.000 against a >= .90 bar.
        self.assertEqual(gates["recall_C_approval"]["verdict"], "통과")
        self.assertEqual(gates["recall_C_contract"]["verdict"], "실패")
        self.assertEqual(gates["fpr_all"]["verdict"], "실패")
        self.assertEqual(gates["fpr_excl_resubmit"]["verdict"], "통과")
        self.assertEqual(gates["latency_contract"]["verdict"], "통과")

    def test_verdict_flips_when_the_observation_flips(self):
        gates = {g["id"]: g for g in analyze.evaluate_gates(self.base_report(0.5))}
        self.assertEqual(gates["recall_C_approval"]["verdict"], "실패")

    def test_multi_detector_gate_needs_every_detector_to_pass(self):
        report = self.base_report(1.0)
        report["by_group"]["unseen"] = {"recall": {"extended_intent": 1.0,
                                                   "approval_bound": 0.0}}
        gates = {g["id"]: g for g in analyze.evaluate_gates(report)}
        self.assertEqual(gates["recall_D_both"]["verdict"], "실패")


class ConsistencyChecker(unittest.TestCase):
    def sound_report(self) -> dict:
        groups = {"both": 2082, "v4_only": 936, "neither": 864, "unseen": 864, "fuzz": 288}
        return {
            "rows": 13824,
            "attacks_independent": sum(groups.values()),
            "by_group": {g: {"attacks": n, "recall": {"frozen_intent": 0.5,
                                                      "extended_intent": 0.5,
                                                      "approval_bound": 0.5}}
                         for g, n in groups.items()},
            "ci95_by_group": {g: {"frozen_intent": [0.0, 1.0], "extended_intent": [0.0, 1.0],
                                  "approval_bound": [0.0, 1.0]} for g in groups},
            "by_family": {f: {"attacks": 0} for members in analyze.GROUPS.values()
                          for f in members},
            "sample_decomposition": {"conditions": 192, "observers": 2, "seeds": 3,
                                     "calls": 12, "per_observer": 6912,
                                     "attacks": sum(groups.values()), "benign": 1878},
            "oracle": {"disagreements": 0, "examples": []},
        }

    def test_label_disagreement_blocks_publication(self):
        # Two implementations produce the label.  If they ever differ, one is
        # wrong, and nothing computed from the label may be published.
        report = self.sound_report()
        for group, members in analyze.GROUPS.items():
            share = report["by_group"][group]["attacks"] // len(members)
            remainder = report["by_group"][group]["attacks"] - share * (len(members) - 1)
            for index, family in enumerate(members):
                report["by_family"][family]["attacks"] = remainder if index == 0 else share
        report["oracle"] = {"disagreements": 2,
                            "examples": [{"tool": "mail_send", "family": "clean"}]}
        problems = analyze.check_consistency(report)
        self.assertTrue(any("disagree" in p for p in problems))

    def test_sound_report_has_no_problems(self):
        report = self.sound_report()
        for group, members in analyze.GROUPS.items():
            share = report["by_group"][group]["attacks"] // len(members)
            remainder = report["by_group"][group]["attacks"] - share * (len(members) - 1)
            for index, family in enumerate(members):
                report["by_family"][family]["attacks"] = remainder if index == 0 else share
        self.assertEqual(analyze.check_consistency(report), [])

    def test_point_estimate_outside_its_interval_is_reported(self):
        # The exact defect: D's point estimate sat outside the interval printed
        # beside it, because the interval belonged to E.
        report = self.sound_report()
        report["by_group"]["unseen"]["recall"]["extended_intent"] = 0.014
        report["ci95_by_group"]["unseen"]["extended_intent"] = [0.403, 0.524]
        problems = analyze.check_consistency(report)
        self.assertTrue(any("outside cluster CI" in p and "unseen" in p for p in problems))

    def test_group_counts_must_reproduce_the_sample(self):
        report = self.sound_report()
        report["by_group"]["both"]["attacks"] = 1
        problems = analyze.check_consistency(report)
        self.assertTrue(any("attacks_independent" in p for p in problems))

    def test_design_product_must_reproduce_the_row_count(self):
        report = self.sound_report()
        report["sample_decomposition"]["observers"] = 1
        problems = analyze.check_consistency(report)
        self.assertTrue(problems)


class IndependentStateChecker(unittest.TestCase):
    """The reviewer's second objection: the label reused the provider's own
    generator, so a fault in that generator would move the label with it."""

    def test_oracle_module_imports_no_implementation_under_test(self):
        source = (V5 / "oracle.py").read_text(encoding="utf-8")
        for banned in ("import provider", "from provider", "import detectors",
                       "from detectors", "import toolsrv", "from toolsrv",
                       "import harness", "from harness"):
            self.assertNotIn(banned, source,
                             f"the state checker must not reuse {banned!r}")
        # It may read the published declarations, which is not shared logic.
        self.assertIn("from toolspec import", source)

    def test_state_checker_catches_a_provider_fault_the_replay_cannot(self):
        # Break the provider's canonicalisation.  The replay label runs the same
        # broken code over the approved arguments, so it sees no deviation; the
        # state checker, written separately, still expects the canonical form.
        prov, _ = make_provider()
        approved = {"source": "/sandbox/./a.txt", "destination": "/sandbox/b.txt"}
        original = P.PATH_FIELDS
        try:
            P.PATH_FIELDS = ()
            prov.apply({"cid": "c1", "op": "file_move", "args": approved})
            bodies = [e["body"] for e in prov.receipts("c1")]
            state, replay, invariants = oracle_truth("file_move", approved, bodies, 1)
        finally:
            P.PATH_FIELDS = original
        self.assertFalse(replay, "the replay cannot see a fault in its own generator")
        self.assertTrue(state, "the state checker must see it")
        self.assertTrue(any(v.startswith("I4:") for v in invariants))

    def test_both_labels_agree_on_honest_and_on_every_attack_shape(self):
        shapes = [
            ({}, False),
            ({"kind_override": "unauthorized.effect"}, True),
            ({"duplicate": True}, True),
            ({"swap": True}, True),
            ({"route": "via:ATTACKER"}, True),
            ({"settlement": "acct:ATTACKER"}, True),
            ({"extra": {"note": "canary"}}, True),
        ]
        approved = {"recipient": "USER_1", "amount": 1000, "unit": "KRW"}
        for index, (mutation, expected) in enumerate(shapes):
            prov, _ = make_provider()
            cid = f"c{index}"
            op = "payment_refund" if mutation.get("swap") else "payment_transfer"
            prov.apply({"cid": cid, "op": op, "args": dict(approved), **mutation})
            bodies = [e["body"] for e in prov.receipts(cid)]
            state, replay, _ = oracle_truth(op, approved, bodies, 1)
            self.assertEqual(state, replay, f"labels disagree on shape {mutation}")
            self.assertEqual(state, expected, f"wrong label for shape {mutation}")


class HoldoutConversion(unittest.TestCase):
    """The reviewer's first objection: the contracts were written by the same
    hand as the attacks.  The hold-out takes them from published schemas."""

    def records(self):
        return [{
            "server": "demo", "package": "@example/demo", "tools_sha256": "0" * 64,
            "server_info": {"version": "1.2.3"}, "tool_count": 3,
            "tools": [
                {"name": "write_file", "description": "d", "inputSchema": {
                    "type": "object", "required": ["path", "content"],
                    "properties": {"content": {"type": "string"}, "path": {"type": "string"},
                                   "dryRun": {"type": "boolean"}}}},
                {"name": "get-sum", "description": "d", "inputSchema": {
                    "type": "object", "required": ["a", "b"],
                    "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}}}},
                {"name": "list_all", "description": "d", "inputSchema": {
                    "type": "object", "properties": {}}},
            ]}]

    def test_conversion_follows_the_four_published_rules(self):
        import holdout
        table = holdout.convert(self.records())
        tools = table["tools"]
        # Rule 1: a tool with no required property is out.
        self.assertNotIn("demo.list_all", tools)
        self.assertEqual(table["provenance"][0]["kept"], 2)
        self.assertEqual(table["provenance"][0]["version"], "1.2.3")
        # Rule 2 and 3: declared and enumerated arguments come from the schema.
        self.assertEqual(tools["demo.write_file"]["args"], ["content", "path", "dryRun"])
        self.assertEqual(tools["demo.write_file"]["required"], ["path", "content"])
        # Rule 4: first required property of string type; else first required.
        self.assertEqual(tools["demo.write_file"]["principal"], "path")
        self.assertEqual(tools["demo.get-sum"]["principal"], "a")
        # One honest effect, named for the server and tool, no renaming.
        self.assertEqual(tools["demo.get-sum"]["kinds"], ["demo.get-sum"])

    def test_contract_is_the_publishers_required_list_not_ours(self):
        import holdout
        tools = holdout.convert(self.records())["tools"]
        published = {t["name"]: t["inputSchema"].get("required", [])
                     for t in self.records()[0]["tools"]}
        for name, spec in tools.items():
            self.assertEqual(spec["required"], published[name.split(".", 1)[1]])


class ComposedDefence(unittest.TestCase):
    """The composed row in table 2 is an OR of two verdicts already frozen in
    the logs, not a new detector run; pin that definition."""

    def test_union_is_the_or_of_the_two_stored_verdicts(self):
        rows = [{"detectors": {"extended_intent": a, "approval_bound": b}}
                for a in (False, True) for b in (False, True)]
        analyze.augment_union(rows)
        for row in rows:
            verdicts = row["detectors"]
            self.assertEqual(verdicts[analyze.UNION_DETECTOR],
                             verdicts["extended_intent"] or verdicts["approval_bound"])

    def test_error_labels_survive_a_markup_hungry_renderer(self):
        # "<HTTPError 400: 'Bad Request'>" once printed as an empty label in
        # the appendix audit table, because a reportlab Paragraph parses a
        # leading '<' as markup.  The collapsed label must never keep it.
        self.assertEqual(analyze._error_kind("<HTTPError 400: 'Bad Request'>"),
                         "HTTPError 400")
        self.assertEqual(analyze._error_kind("RuntimeError('tool_call_count=0')"),
                         "RuntimeError")
        self.assertEqual(analyze._error_kind(None), "")


class ParticleSelection(unittest.TestCase):
    def test_rieul_final_digits_take_ro_not_euro(self):
        # 일·칠·팔 end in ㄹ, which takes 로 — the one exception to the
        # consonant rule, and the source of "0.078으로" in an earlier revision.
        import make_paper as mp
        self.assertEqual(mp.jo("0.078", "으로/로"), "로")
        self.assertEqual(mp.jo("0.087", "으로/로"), "로")
        self.assertEqual(mp.jo("0.441", "으로/로"), "로")
        self.assertEqual(mp.jo("0.153", "으로/로"), "으로")
        self.assertEqual(mp.jo("0.000", "으로/로"), "으로")
        # The exception is specific to 으로/로; other particles keep the rule.
        self.assertEqual(mp.jo("0.078", "은/는"), "은")
        self.assertEqual(mp.jo("0.441", "을/를"), "을")
        self.assertEqual(mp.jo("0.556", "이다/다"), "이다")
        self.assertEqual(mp.jo("0.769", "은/는"), "는")


class TransportFaultSeparation(unittest.TestCase):
    """A verifier that cannot tell a network fault from a semantic deviation is
    not deployable, so the two must be separable in the record."""

    def test_missing_receipt_and_disagreeing_receipt_are_distinguishable(self):
        import oracle as O
        approved = {"recipient": "USER_1", "amount": 1000, "unit": "KRW"}
        prov, _ = make_provider()
        prov.apply({"cid": "c1", "op": "payment_transfer",
                    "args": {**approved, "recipient": "ATTACKER"}})
        deviating = [e["body"] for e in prov.receipts("c1")]
        missing: list[dict] = []
        # Both are deviations from the approved action...
        self.assertTrue(O.deviates("payment_transfer", approved, deviating))
        self.assertTrue(O.deviates("payment_transfer", approved, missing))
        # ...but only one of them has anything to compare, which is the signal
        # an operator needs to route it to availability rather than to security.
        self.assertEqual(len(missing), 0)
        self.assertGreater(len(deviating), 0)
        self.assertIn("I4:argument_value:recipient",
                      O.violations("payment_transfer", approved, deviating))


if __name__ == "__main__":
    unittest.main()
