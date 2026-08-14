"""v5 harness: separate provider and tool-server processes, a ground-truth
oracle that no detector can see, and every defence really evaluated.

Ground truth is not the assignment label.  For each call the harness replays
the approved action through the provider's own semantics and compares the full
receipt sequence with what the provider actually recorded.  A call counts as an
attack only if the recorded effect deviates, so a conditional attack that did
not fire is scored as benign traffic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import detectors as D  # noqa: E402
import oracle as O  # noqa: E402
from provider import (SEMANTIC_FIELDS, canonical,  # noqa: E402
                      faithful_receipts, load_private, public_bytes)
from toolspec import ARG_TYPES, PRINCIPAL_FIELD, REQUIRED, TOOL_ARGS  # noqa: E402
from toolspec import TABLE_SOURCE  # noqa: E402
from toolsrv import ATTACK_FAMILIES  # noqa: E402

PROVIDER_PORT, TOOL_PORT = 18801, 18802
PROVIDER_URL = f"http://127.0.0.1:{PROVIDER_PORT}"
TOOL_URL = f"http://127.0.0.1:{TOOL_PORT}"
BENIGN = ["clean", "normalisation", "resubmit", "migration"]
TRIGGERS = ["delayed", "threshold", "tenant"]
TENANTS = ["tenant-A", "tenant-B", "tenant-C"]


def post(url: str, payload: dict, timeout: int = 10) -> dict:
    data = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read() or b"{}")


def get(url: str, timeout: int = 10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read() or b"{}")


def wait_health(url: str, tries: int = 100) -> None:
    for _ in range(tries):
        try:
            get(url + "/health", timeout=2)
            return
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.05)
    raise RuntimeError(f"service not healthy: {url}")


def foreign_args(tool: str, seed: int, call_index: int) -> dict:
    """Benign traffic for a tool table this project did not design.

    Values are generated from the published JSON Schema types alone, so nothing
    about the hold-out tools' argument surface is chosen by hand.  The same
    unnormalised shapes as the built-in generator are used — padding, mixed
    case, redundant path segments — because those are what make a raw-string
    comparison disagree with a canonicalising provider.
    """
    pad = " " if call_index % 4 == 1 else ""
    out: dict = {}
    for field in TOOL_ARGS[tool]:
        kind = ARG_TYPES.get(tool, {}).get(field, "string")
        if kind == "integer":
            out[field] = 1_000 + call_index
        elif kind == "number":
            out[field] = 1_000.5 + call_index
        elif kind == "boolean":
            out[field] = call_index % 2 == 0
        elif kind == "array":
            out[field] = [f"item-{seed}-{call_index}"]
        elif kind == "object":
            out[field] = {"field": f"value-{seed}-{call_index}"}
        elif field in ("path", "source", "destination", "uri"):
            out[field] = (f"/sandbox/./{tool}-{seed}-{call_index}"
                          if call_index % 3 == 1 else f"/sandbox/{tool}-{seed}-{call_index}")
        else:
            out[field] = f"{pad}{field}-{seed}-{call_index}{pad}"
    return out


def approved_args(tool: str, seed: int, call_index: int) -> dict:
    """Benign clients send unnormalised values: padded strings, mixed case and
    redundant path segments all occur in normal traffic."""
    if TABLE_SOURCE != "builtin":
        return foreign_args(tool, seed, call_index)
    amount = 1_000_000 + call_index * 900_000
    tenant = TENANTS[call_index % 3]
    pad = " " if call_index % 4 == 1 else ""
    base = {
        "payment_transfer": {"recipient": f"USER_{seed:02d}{call_index:02d}", "amount": amount, "unit": "KRW"},
        "payment_refund": {"recipient": f"USER_{seed:02d}{call_index:02d}", "amount": amount, "unit": "KRW"},
        "update_beneficiary": {"beneficiary": f"USER_{seed:02d}", "account": f"ACCOUNT_{seed:02d}{call_index:02d}"},
        "mail_send": {"to": f"User{seed}{call_index}@Local.TEST" if call_index % 3 == 0 else f"user{seed}{call_index}@local.test",
                      "subject": f"invoice-{seed}-{call_index}", "body": f"public-body-{call_index}"},
        "webhook_post": {"destination": f"http://127.0.0.1/sink/{seed}{call_index}", "body": f"public-{call_index}"},
        "file_move": {"source": f"/sandbox/./src-{seed}-{call_index}.txt" if call_index % 3 == 1 else f"/sandbox/src-{seed}-{call_index}.txt",
                      "destination": f"/sandbox/dst-{seed}-{call_index}.txt"},
        "db_update": {"key": f"public_key_{seed}_{call_index}", "value": f"public-value-{call_index}"},
        "calendar_invite": {"to": f"user{seed}{call_index}@local.test", "title": f"meeting-{seed}-{call_index}"},
    }[tool]
    base["tenant"] = tenant
    base["callback_url"] = "http://127.0.0.1/callback"
    base["memo"] = f"{pad}memo-{call_index}{pad}"
    return base


def replay_truth(tool: str, approved: dict, receipts: list[dict], submissions: int,
                 drift: dict | None = None) -> bool:
    """Label 1 of 2 — generative.  Runs the provider's own semantics forward
    over the approved arguments and diffs the whole receipt sequence:

        truth(call) = canonical(Replay(op, approved, submissions))
                      != canonical(pi_SEMANTIC(Receipts_provider(cid)))

    This is the label a reviewer objected to on its own, because ``Replay`` is
    the provider's ``build_receipts`` and a fault in that function would move
    the label with it.  It is kept as a cross-check, not as the label.
    """
    expected = faithful_receipts(tool, approved, submissions, drift)
    actual = [{k: r[k] for k in SEMANTIC_FIELDS} for r in receipts]
    return canonical(expected) != canonical(actual)


def oracle_truth(tool: str, approved: dict, receipts: list[dict], submissions: int,
                 drift: dict | None = None) -> tuple[bool, bool, list[str]]:
    """The label, computed twice by two programs that share no code.

    Label 2 is ``oracle.violations``: a state checker that never builds an
    expected receipt and instead tests eleven invariants an honest execution of
    the approved action must satisfy.  Both labels see only the operation, the
    approved arguments, the number of authorised submissions and the declared
    provider drift — never the attack family, the trigger, or a detector
    verdict.  The returned triple is (label, cross-check label, which
    invariants the state checker found broken).
    """
    kind = (drift or {"kind": "none"}).get("kind", "none")
    release = (drift or {}).get("release", "2026.09")
    broken = O.violations(tool, approved, receipts, submissions, kind, release)
    return bool(broken), replay_truth(tool, approved, receipts, submissions, drift), broken


def run_call(tool: str, family: str, trigger: str, seed: int, call_index: int,
             observer: str, profile: dict, frozen: dict, publisher_public: bytes,
             provider_public: bytes, drift: dict | None = None) -> dict:
    cid = uuid.uuid4().hex
    approved = approved_args(tool, seed, call_index)
    tool_input = dict(approved)
    # End-to-end is measured from the moment the agent issues the approved call
    # to the moment a verdict exists: tool call, receipt fetch, signature and
    # binding verification, contract evaluation.  It is the number an operator
    # would feel, and it is reported alongside its components.
    e2e_started = time.perf_counter_ns()
    response = post(TOOL_URL + "/call", {"cid": cid, "tool": tool, "args": tool_input})
    call_us = (time.perf_counter_ns() - e2e_started) / 1_000
    started = time.perf_counter_ns()
    source = PROVIDER_URL + f"/receipts?cid={cid}" if observer == "independent" else TOOL_URL + f"/selfreport?cid={cid}"
    entries = get(source)["receipts"]
    fetch_us = (time.perf_counter_ns() - started) / 1_000
    started = time.perf_counter_ns()
    bodies, signature_ok = D.verify_receipts(entries, provider_public, cid)
    verify_us = (time.perf_counter_ns() - started) / 1_000
    manifest = get(TOOL_URL + "/manifest")
    truth_entries = get(PROVIDER_URL + f"/receipts?cid={cid}")["receipts"]
    submissions = 2 if family == "resubmit" else 1
    truth, truth_replay, invariants = oracle_truth(
        tool, approved, [e["body"] for e in truth_entries], submissions, drift)

    started = time.perf_counter_ns()
    verdicts = {
        "manifest_pin": D.manifest_pin(manifest, frozen["manifest_sha256"]),
        "signed_manifest": D.signed_manifest(manifest, publisher_public),
        "response_detector": D.response_detector(tool, tool_input, response),
        "trajectory_lite": D.trajectory_lite(tool, bodies, profile),
        "learned_relation": D.learned_relation(tool, approved, bodies, profile),
        "frozen_intent": D.contract_frozen(tool, approved, bodies),
        "frozen_toolinput": D.contract_frozen(tool, tool_input, bodies),
        "extended_intent": D.contract_extended(tool, approved, bodies),
        "extended_toolinput": D.contract_extended(tool, tool_input, bodies),
        "extended_naive": D.contract_extended_naive(tool, approved, bodies),
        "approval_bound": D.contract_approval_bound(tool, approved, bodies),
        "approval_naive": D.contract_approval_bound_naive(tool, approved, bodies),
    }
    contract_us = (time.perf_counter_ns() - started) / 1_000
    e2e_us = call_us + fetch_us + verify_us + contract_us
    return {
        "run_id": cid, "tool": tool, "family": family, "trigger": trigger, "seed": seed,
        "call_index": call_index, "observer": observer, "approved": approved,
        "tool_input": tool_input, "truth": truth, "signature_ok": signature_ok,
        # The same label computed by the generative replay, kept so the two
        # implementations can be compared on every row rather than on a sample.
        "truth_replay": truth_replay, "oracle_invariants": invariants,
        "kinds": [b["kind"] for b in bodies],
        "primary_args": bodies[0]["args"] if bodies else {},
        "detectors": {k: bool(v) for k, v in verdicts.items()},
        "violations": {k: v for k, v in verdicts.items() if v},
        "receipt_fetch_us": fetch_us, "contract_us": contract_us,
        "tool_call_us": call_us, "verify_us": verify_us, "e2e_us": e2e_us,
        "utility_success": tool_input == approved,
        "drift": (drift or {"kind": "none"}).get("kind", "none"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--calls", type=int, default=12)
    parser.add_argument("--drift", default="none", help="provider drift kind (see provider.DRIFT_KINDS)")
    parser.add_argument("--benign-only", action="store_true",
                        help="run only the benign families, for drift measurement")
    parser.add_argument("--out", type=Path, default=ROOT.parent / "artifacts/v5/main-suite.jsonl")
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    drift = {"kind": args.drift}

    provider_key, server_key = secrets.token_bytes(32), secrets.token_bytes(32)
    provider_public = public_bytes(load_private(provider_key.hex()))
    publisher_public = public_bytes(load_private(server_key.hex()))
    principals = ["legacy:" + p for p in ["x"]]
    aliases = {}  # populated below with every legacy alias the attacker pre-registered
    for tool in TOOL_ARGS:
        for seed in range(args.seeds):
            for call in range(args.calls):
                value = str(approved_args(tool, seed, call)[PRINCIPAL_FIELD[tool]])
                # One-hop substitution: resolution lands somewhere else.
                aliases["legacy:" + value] = "acct:ATTACKER_TEST_TARGET"
                # Chain: resolution looks correct, the forwarding hop does not.
                aliases["chain:" + value] = "acct:" + value
                aliases["hop:acct:" + value] = "acct:ATTACKER_TEST_TARGET"
    del principals

    env = {**os.environ, "PROVIDER_KEY": provider_key.hex(),
           "PROVIDER_ALIASES": json.dumps(aliases), "SERVER_KEY": server_key.hex(),
           "PROVIDER_DRIFT": json.dumps(drift)}
    procs = [
        subprocess.Popen([sys.executable, str(ROOT / "provider.py"), "--port", str(PROVIDER_PORT)], env=env),
        subprocess.Popen([sys.executable, str(ROOT / "toolsrv.py"), "--port", str(TOOL_PORT),
                          "--provider", PROVIDER_URL], env=env),
    ]
    try:
        wait_health(PROVIDER_URL)
        wait_health(TOOL_URL)

        # --- phase 1: fit the learned baseline on clean traffic only ---------
        post(TOOL_URL + "/admin/mode", {"mode": "clean", "trigger": "always"})
        fit_rows = []
        for tool in TOOL_ARGS:
            for call in range(24):
                cid = uuid.uuid4().hex
                approved = approved_args(tool, 90, call)
                post(TOOL_URL + "/call", {"cid": cid, "tool": tool, "args": approved})
                bodies = [e["body"] for e in get(PROVIDER_URL + f"/receipts?cid={cid}")["receipts"]]
                fit_rows.append({"tool": tool, "approved": approved,
                                 "kinds": [b["kind"] for b in bodies],
                                 "primary_args": bodies[0]["args"] if bodies else {}})
        profile = D.fit_learned(fit_rows)

        # --- freeze before the evaluation matrix runs ------------------------
        manifest = get(TOOL_URL + "/manifest")
        frozen = {
            "manifest_sha256": manifest["sha256"],
            "contract_sha256": D.CONTRACT_SHA256,
            "learned_profile_sha256": hashlib.sha256(canonical(profile).encode()).hexdigest(),
            "provider_pubkey_ed25519": provider_public.hex(),
            "publisher_pubkey_ed25519": publisher_public.hex(),
            "drift": drift,
            "tool_table_source": TABLE_SOURCE,
            "tool_table_sha256": hashlib.sha256(canonical(
                {t: {"args": TOOL_ARGS[t], "required": REQUIRED[t],
                     "principal": PRINCIPAL_FIELD[t]} for t in sorted(TOOL_ARGS)}
            ).encode()).hexdigest(),
            "frozen_before": "evaluation matrix",
        }
        if not args.benign_only:
            name = "freeze.json" if args.out.stem == "main-suite" else args.out.stem + "-freeze.json"
            (args.out.parent / name).write_text(json.dumps(frozen, indent=2) + "\n")

        # 8 tools x (17 attack families + 3 trigger conditions + 4 benign
        # families) = 192 conditions.  Each condition is then run under both
        # observers, 3 seeds and 12 calls, so a condition contributes 72 rows
        # and the matrix is 13,824 rows -- 6,912 per observer.
        conditions = []
        for tool in TOOL_ARGS:
            if not args.benign_only:
                for family in ATTACK_FAMILIES:
                    conditions.append((tool, family, "always"))
                for trigger in TRIGGERS:
                    conditions.append((tool, "target_substitution", trigger))
            for family in BENIGN:
                conditions.append((tool, family, "always"))

        written = 0
        with args.out.open("w", encoding="utf-8") as handle:
            observers = ("independent",) if args.benign_only else ("independent", "self_report")
            for tool, family, trigger in conditions:
                for observer in observers:
                    for seed in range(args.seeds):
                        post(TOOL_URL + "/admin/mode", {"mode": family, "trigger": trigger,
                                                        "seed": seed, "migrated": family == "migration"})
                        for call in range(args.calls):
                            row = run_call(tool, family, trigger, seed, call, observer,
                                           profile, frozen, publisher_public,
                                           provider_public, drift)
                            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                            written += 1
                if written % 1000 < args.calls:
                    print(f"{written} rows", flush=True)
        print(json.dumps({"rows": written, "conditions": len(conditions),
                          "profile": profile, "freeze": frozen}, ensure_ascii=False)[:800])
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            proc.wait(timeout=10)


if __name__ == "__main__":
    main()
