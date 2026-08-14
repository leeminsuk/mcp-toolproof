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
from provider import (PRINCIPAL_FIELD, RECEIPT_FIELDS, canonical,  # noqa: E402
                      faithful_receipts)
from toolsrv import ATTACK_FAMILIES, TOOL_ARGS  # noqa: E402

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


def approved_args(tool: str, seed: int, call_index: int) -> dict:
    """Benign clients send unnormalised values: padded strings, mixed case and
    redundant path segments all occur in normal traffic."""
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


def oracle_truth(tool: str, approved: dict, receipts: list[dict], submissions: int) -> bool:
    """Detector-independent label: did the provider record something other than
    the faithful execution of the approved action?"""
    expected = faithful_receipts(tool, approved, submissions)
    actual = [{k: r[k] for k in RECEIPT_FIELDS} for r in receipts]
    return canonical(expected) != canonical(actual)


def run_call(tool: str, family: str, trigger: str, seed: int, call_index: int,
             observer: str, profile: dict, frozen: dict, server_key: bytes,
             verifier_key: bytes) -> dict:
    cid = uuid.uuid4().hex
    approved = approved_args(tool, seed, call_index)
    tool_input = dict(approved)
    response = post(TOOL_URL + "/call", {"cid": cid, "tool": tool, "args": tool_input})
    started = time.perf_counter_ns()
    source = PROVIDER_URL + f"/receipts?cid={cid}" if observer == "independent" else TOOL_URL + f"/selfreport?cid={cid}"
    entries = get(source)["receipts"]
    fetch_us = (time.perf_counter_ns() - started) / 1_000
    bodies, signature_ok = D.verify_receipts(entries, verifier_key)
    manifest = get(TOOL_URL + "/manifest")
    truth_entries = get(PROVIDER_URL + f"/receipts?cid={cid}")["receipts"]
    submissions = 2 if family == "resubmit" else 1
    truth = oracle_truth(tool, approved, [e["body"] for e in truth_entries], submissions)

    started = time.perf_counter_ns()
    verdicts = {
        "manifest_pin": D.manifest_pin(manifest, frozen["manifest_sha256"]),
        "signed_manifest": D.signed_manifest(manifest, server_key),
        "response_detector": D.response_detector(tool, tool_input, response),
        "trajectory_lite": D.trajectory_lite(tool, bodies, profile),
        "learned_relation": D.learned_relation(tool, approved, bodies, profile),
        "frozen_intent": D.contract_frozen(tool, approved, bodies),
        "frozen_toolinput": D.contract_frozen(tool, tool_input, bodies),
        "extended_intent": D.contract_extended(tool, approved, bodies),
        "extended_toolinput": D.contract_extended(tool, tool_input, bodies),
        "extended_naive": D.contract_extended_naive(tool, approved, bodies),
        "approval_bound": D.contract_approval_bound(tool, approved, bodies),
    }
    contract_us = (time.perf_counter_ns() - started) / 1_000
    return {
        "run_id": cid, "tool": tool, "family": family, "trigger": trigger, "seed": seed,
        "call_index": call_index, "observer": observer, "approved": approved,
        "tool_input": tool_input, "truth": truth, "signature_ok": signature_ok,
        "kinds": [b["kind"] for b in bodies],
        "primary_args": bodies[0]["args"] if bodies else {},
        "detectors": {k: bool(v) for k, v in verdicts.items()},
        "violations": {k: v for k, v in verdicts.items() if v},
        "receipt_fetch_us": fetch_us, "contract_us": contract_us,
        "utility_success": tool_input == approved,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--calls", type=int, default=12)
    parser.add_argument("--out", type=Path, default=ROOT.parent / "artifacts/v5/main-suite.jsonl")
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)

    provider_key, server_key = secrets.token_bytes(32), secrets.token_bytes(32)
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
           "PROVIDER_ALIASES": json.dumps(aliases), "SERVER_KEY": server_key.hex()}
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
            "frozen_before": "evaluation matrix",
        }
        (args.out.parent / "freeze.json").write_text(json.dumps(frozen, indent=2) + "\n")

        conditions = []
        for tool in TOOL_ARGS:
            for family in ATTACK_FAMILIES:
                conditions.append((tool, family, "always"))
            for trigger in TRIGGERS:
                conditions.append((tool, "target_substitution", trigger))
            for family in BENIGN:
                conditions.append((tool, family, "always"))

        written = 0
        with args.out.open("w", encoding="utf-8") as handle:
            for tool, family, trigger in conditions:
                for observer in ("independent", "self_report"):
                    for seed in range(args.seeds):
                        post(TOOL_URL + "/admin/mode", {"mode": family, "trigger": trigger,
                                                        "seed": seed, "migrated": family == "migration"})
                        for call in range(args.calls):
                            row = run_call(tool, family, trigger, seed, call, observer,
                                           profile, frozen, server_key, provider_key)
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
