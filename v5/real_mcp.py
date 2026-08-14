"""Carry the v5 threat model onto the official MCP SDK, with the v5 observer.

Everything load-bearing is shared with the main matrix: the attacker
(``toolsrv.Attacker``, all seventeen families), the provider (Ed25519-signed
receipts in a separate process), the independent oracle (``oracle.violations``)
and the contracts (``detectors``).  What is different is the wire between the
agent and the tool: the official MCP Python SDK over stdio instead of local
HTTP, with a real ``initialize`` / ``list_tools`` / ``call_tool`` handshake and
the server in its own OS process.

The point of the suite is therefore not to re-measure recall.  It is to check
three things a purpose-built HTTP testbed cannot check on its own:

  1. the served manifest is byte-identical whether the server is honest or not,
     so nothing at the protocol layer distinguishes them;
  2. the response the agent receives echoes the approved call in every family,
     so a response-only verifier is blind by construction, not by tuning;
  3. a verifier reading an independent receipt log can separate a *transport
     fault* (no receipt, or a receipt that has not arrived yet) from a
     *semantic deviation* (a receipt that disagrees) — because in operations
     the two arrive through the same symptom.

Fault modes are injected between the tool server and the provider: an aborted
TCP connection, a dead provider port, and an asynchronous write that lands
after the verifier first looks.  Under ``async_lag`` the verifier polls to a
deadline; a single-shot read is scored alongside it so the cost of not waiting
is measured rather than asserted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import anyio  # noqa: E402
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

import detectors as D  # noqa: E402
import oracle as O  # noqa: E402
from harness import approved_args  # noqa: E402
from provider import load_private, public_bytes  # noqa: E402
from toolspec import PRINCIPAL_FIELD, TOOL_ARGS  # noqa: E402
from toolsrv import ATTACK_FAMILIES  # noqa: E402

PORT = 18811
PROVIDER_URL = f"http://127.0.0.1:{PORT}"
BENIGN = ["clean", "normalisation", "resubmit"]
FAULTS = ["none", "async_lag", "tcp_reset", "provider_down"]
POLL_DEADLINE_MS = 400
LAG_MS = 120


def get(url: str, timeout: float = 5) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read() or b"{}")


def wait_health(url: str, tries: int = 200) -> None:
    for _ in range(tries):
        try:
            get(url + "/health", timeout=2)
            return
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.05)
    raise RuntimeError("provider did not come up")


def fetch_receipts(cid: str, deadline_ms: int) -> tuple[list[dict], int, list[dict]]:
    """Read the provider's log, waiting up to a deadline for a late write.

    Returns the receipts seen at the deadline, how long the wait took, and what
    a verifier that did not wait at all would have seen.
    """
    started = time.perf_counter_ns()
    first = get(PROVIDER_URL + f"/receipts?cid={cid}")["receipts"]
    entries = first
    while not entries and (time.perf_counter_ns() - started) / 1_000_000 < deadline_ms:
        time.sleep(0.02)
        entries = get(PROVIDER_URL + f"/receipts?cid={cid}")["receipts"]
    return entries, int((time.perf_counter_ns() - started) / 1_000), first


async def run_mode(family: str, trigger: str, fault: str, repeats: int, seed: int,
                   provider_public: bytes, interpreter: str, rows: list[dict],
                   hashes: list[str]) -> None:
    env = {**os.environ, "TOOLPROOF_PROVIDER_URL": PROVIDER_URL,
           "TOOLPROOF_ATTACK": family, "TOOLPROOF_TRIGGER": trigger,
           "TOOLPROOF_FAULT": fault, "TOOLPROOF_LAG_MS": str(LAG_MS),
           "PYTHONPATH": str(ROOT)}
    params = StdioServerParameters(command=interpreter,
                                   args=[str(ROOT / "mcp_server.py")], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listing = await session.list_tools()
            manifest = json.dumps([t.model_dump(mode="json") for t in listing.tools],
                                  sort_keys=True, separators=(",", ":"))
            hashes.append(hashlib.sha256(manifest.encode()).hexdigest())
            for call_index in range(repeats):
                for tool in TOOL_ARGS:
                    cid = uuid.uuid4().hex
                    approved = approved_args(tool, seed, call_index)
                    started = time.perf_counter_ns()
                    result = await session.call_tool(tool, {**approved, "cid": cid})
                    call_us = (time.perf_counter_ns() - started) / 1_000
                    entries, wait_us, single_shot = fetch_receipts(cid, POLL_DEADLINE_MS)
                    started = time.perf_counter_ns()
                    bodies, signature_ok = D.verify_receipts(entries, provider_public, cid)
                    submissions = 2 if family == "resubmit" else 1
                    broken = O.violations(tool, approved, bodies, submissions)
                    violations = D.contract_extended(tool, approved, bodies)
                    verdict_us = (time.perf_counter_ns() - started) / 1_000
                    others = {
                        "frozen_intent": D.contract_frozen(tool, approved, bodies),
                        "approval_bound": D.contract_approval_bound(tool, approved, bodies),
                    }
                    # What a verifier that never waits for a late write concludes.
                    shot_bodies, _ = D.verify_receipts(single_shot, provider_public, cid)
                    single_alarm = bool(D.contract_extended(tool, approved, shot_bodies))
                    payload = json.loads(result.content[0].text) if result.content else {}
                    rows.append({
                        "run_id": cid, "tool": tool, "family": family, "trigger": trigger,
                        "fault": fault, "call_index": call_index,
                        "fired": bool(payload.get("fired")),
                        "truth": bool(broken), "oracle_invariants": broken,
                        "toolproof": bool(violations), "violations": violations,
                        "detectors": {"extended_intent": bool(violations),
                                      **{k: bool(v) for k, v in others.items()}},
                        "signature_ok": signature_ok,
                        "receipts": len(bodies),
                        # A verifier that does not wait for a late write sees this.
                        "receipts_single_shot": len(single_shot),
                        "alarm_single_shot": single_alarm,
                        "receipt_missing": not bodies,
                        "response_matches_approved": all(
                            payload.get(k) == v for k, v in approved.items()),
                        "e2e_us": call_us + wait_us + verdict_us,
                        "call_us": call_us, "wait_us": wait_us, "verdict_us": verdict_us,
                    })


async def main(out: Path, repeats: int) -> None:
    interpreter = sys.executable
    key = secrets.token_bytes(32).hex()
    provider_public = public_bytes(load_private(key))
    aliases: dict = {}
    for tool in TOOL_ARGS:
        for call in range(repeats):
            value = str(approved_args(tool, 0, call)[PRINCIPAL_FIELD[tool]])
            aliases["legacy:" + value] = "acct:ATTACKER_TEST_TARGET"
            aliases["chain:" + value] = "acct:" + value
            aliases["hop:acct:" + value] = "acct:ATTACKER_TEST_TARGET"
    provider = subprocess.Popen(
        [interpreter, str(ROOT / "provider.py"), "--port", str(PORT)],
        env={**os.environ, "PROVIDER_KEY": key, "PROVIDER_ALIASES": json.dumps(aliases),
             "PYTHONPATH": str(ROOT)})
    rows: list[dict] = []
    hashes: list[str] = []
    try:
        wait_health(PROVIDER_URL)
        # Every attack family and a benign control, all over the real SDK.
        for family in ATTACK_FAMILIES + BENIGN:
            await run_mode(family, "always", "none", repeats, 0,
                           provider_public, interpreter, rows, hashes)
        # Conditional activation: a probe window that passes, then deviation.
        await run_mode("target_substitution", "delayed", "none", repeats, 1,
                       provider_public, interpreter, rows, hashes)
        # Transport faults, on benign traffic, so any alarm is a false alarm and
        # any missing receipt is availability rather than a deviation.
        for fault in FAULTS[1:]:
            await run_mode("clean", "always", fault, repeats, 2,
                           provider_public, interpreter, rows, hashes)
    finally:
        provider.terminate()
        provider.wait(timeout=10)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                   encoding="utf-8")
    e2e = sorted(r["e2e_us"] for r in rows if r["fault"] == "none")
    meta = {
        "rows": len(rows), "repeats": repeats, "tools": sorted(TOOL_ARGS),
        "families": ATTACK_FAMILIES + BENIGN, "faults": FAULTS,
        "probe_calls": 3, "poll_deadline_ms": POLL_DEADLINE_MS, "lag_ms": LAG_MS,
        "transport": "official MCP Python SDK 1.29, stdio, separate OS process",
        "observer": "independent provider process, Ed25519-signed receipt log",
        "oracle": "v5 independent state checker (oracle.violations)",
        "manifest_hashes": sorted(set(hashes)),
        "e2e_ms": {"p50": statistics.median(e2e) / 1000 if e2e else None,
                   "p95": e2e[int(0.95 * len(e2e))] / 1000 if e2e else None},
    }
    Path(str(out) + ".meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(meta, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=6)
    parser.add_argument("--out", type=Path,
                        default=ROOT.parent / "artifacts/v5/real-mcp-sdk-suite.jsonl")
    args = parser.parse_args()
    anyio.run(main, args.out, args.repeats)
