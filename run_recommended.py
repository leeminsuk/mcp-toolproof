from __future__ import annotations

import argparse
import json
import platform
import subprocess
import uuid
from pathlib import Path

from recommended import ATTACKS, MANIFEST_SHA256, SPECS, contract_violations, decisions, execute, intended_args, ollama_call, prompt_for


ROOT = Path(__file__).resolve().parent
MODELS = ("qwen3:4b", "qwen2.5:7b", "gemma4:12b")


def commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "uncommitted"


def key(row: dict) -> tuple:
    return row["model"], row["tool"], row["attack"], row["malicious_server"], row["variant"], row["repeat"]


def matrix(smoke: bool):
    if smoke:
        return [(m, s, "target_substitution", False, 0, 0) for m in MODELS for s in SPECS]
    attack = [(m, s, a, True, v, r) for m in MODELS for s in SPECS for a in ATTACKS for v in range(4) for r in range(3)]
    benign = [(m, s, "none", False, r % 4, r) for m in MODELS for s in SPECS for r in range(9)]
    return attack + benign


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/raw/recommended-2916.jsonl")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if args.output.exists():
        for line in args.output.read_text().splitlines():
            done.add(key(json.loads(line)))
    jobs = matrix(args.smoke)
    with args.output.open("a", encoding="utf-8") as handle:
        for index, (model, spec, attack, malicious, variant, repeat) in enumerate(jobs, 1):
            stub = {"model": model, "tool": spec.name, "attack": attack, "malicious_server": malicious, "variant": variant, "repeat": repeat}
            if key(stub) in done:
                continue
            try:
                intended = intended_args(spec, variant)
                called, tool_args, latency, retries = ollama_call(model, prompt_for(spec, intended), variant * 10 + repeat, spec.name)
                called_spec = next(s for s in SPECS if s.name == called)
                response, effects = execute(called_spec, tool_args, malicious, attack, variant)
                violations = contract_violations(called_spec, tool_args, effects)
                row = {
                    **stub, "run_id": str(uuid.uuid4()), "manifest_sha256": MANIFEST_SHA256,
                    "intended_input": intended, "called_tool": called, "tool_input": tool_args,
                    "response": response, "observer_effects": effects, "violations": violations,
                    "malicious_effect": bool(malicious and attack != "none"),
                    "utility_success": called == spec.name and tool_args == intended,
                    "defenses": decisions(tool_args, response, violations), "latency_ms": latency,
                    "tool_call_retries": retries,
                    "environment": {"commit": commit(), "python": platform.python_version(), "platform": platform.platform()},
                    "error": None,
                }
            except Exception as exc:
                row = {**stub, "run_id": str(uuid.uuid4()), "error": repr(exc)}
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            if index % 25 == 0 or row["error"]:
                print(f"[{index}/{len(jobs)}] {model} {spec.name} {attack} error={row['error']}", flush=True)
    print(args.output)


if __name__ == "__main__":
    main()
