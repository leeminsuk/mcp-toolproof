from __future__ import annotations

import argparse
import json
import platform
import subprocess
import time
import uuid
from pathlib import Path

from recommended import ATTACKS, MANIFEST_SHA256, SPECS, contract_violations, decisions, execute, intended_args, ollama_call, prompt_for


ROOT = Path(__file__).resolve().parent


def commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "gpu-snapshot"


def jobs():
    attack = [(s, a, True, v, r) for s in SPECS for a in ATTACKS for v in range(4) for r in range(3)]
    benign = [(s, "none", False, r % 4, r) for s in SPECS for r in range(9)]
    return attack + benign


def row_key(row: dict) -> tuple:
    return row["tool"], row["attack"], row["malicious_server"], row["variant"], row["repeat"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if args.output.exists():
        for line in args.output.read_text().splitlines():
            done.add(row_key(json.loads(line)))
    planned = jobs()[: args.limit] if args.limit else jobs()
    with args.output.open("a", encoding="utf-8") as handle:
        for index, (spec, attack, malicious, variant, repeat) in enumerate(planned, 1):
            stub = {"model": args.model, "tool": spec.name, "attack": attack, "malicious_server": malicious, "variant": variant, "repeat": repeat}
            if row_key(stub) in done:
                continue
            try:
                intended = intended_args(spec, variant)
                called, tool_args, latency, retries = ollama_call(args.model, prompt_for(spec, intended), variant * 10 + repeat, spec.name, base_url=args.endpoint)
                called_spec = next(s for s in SPECS if s.name == called)
                response, effects = execute(called_spec, tool_args, malicious, attack, variant)
                contract_started = time.perf_counter_ns()
                violations = contract_violations(called_spec, tool_args, effects)
                contract_latency_us = (time.perf_counter_ns() - contract_started) / 1_000
                row = {
                    **stub, "run_id": str(uuid.uuid4()), "manifest_sha256": MANIFEST_SHA256,
                    "intended_input": intended, "called_tool": called, "tool_input": tool_args,
                    "response": response, "observer_effects": effects, "violations": violations,
                    # Ground truth comes from the hidden server mode/attack label, not from ToolProof's contract result.
                    "malicious_effect": bool(malicious and attack != "none"), "utility_success": called == spec.name and tool_args == intended,
                    "defenses": decisions(tool_args, response, violations), "latency_ms": latency,
                    "tool_call_retries": retries,
                    "contract_latency_us": contract_latency_us,
                    "environment": {"commit": commit(), "python": platform.python_version(), "platform": platform.platform(), "endpoint": args.endpoint},
                    "error": None,
                }
            except Exception as exc:
                row = {**stub, "run_id": str(uuid.uuid4()), "error": repr(exc)}
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            if index % 25 == 0 or row["error"]:
                print(f"[{index}/{len(planned)}] {args.model} {spec.name} {attack} error={row['error']}", flush=True)
    print(args.output)


if __name__ == "__main__":
    main()
