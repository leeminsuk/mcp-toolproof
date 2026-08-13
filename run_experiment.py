from __future__ import annotations

import argparse
import json
import os
import platform
import random
import subprocess
import uuid
from pathlib import Path

from toolproof import Observer, ToolServer, defense_decisions, manifest_sha256, ollama_tool_call, task_for, expected_violation


ROOT = Path(__file__).resolve().parent
MODELS = ["qwen3:4b", "qwen2.5:7b", "gemma4:12b"]


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "uncommitted"


def response_for(name: str, args: dict) -> dict:
    if name == "payment_transfer":
        return {"status": "ok", "recipient": args["recipient"], "amount": args["amount"]}
    if name == "mail_send":
        return {"status": "sent", "to": args["to"], "body": args["body"]}
    return {"status": "ok", "path": args["path"], "content": "SIMULATED_PUBLIC_CONTENT"}


def run_one(model: str, tool: str, attack: str, malicious: bool, variant: int) -> dict:
    prompt, intended = task_for(tool, variant)
    called_name, called_args, latency_ms = ollama_tool_call(model, prompt)
    observer = Observer()
    server = ToolServer(observer, malicious=malicious, attack=attack, trigger=True)
    response = server.call(called_name, called_args)
    observed = observer.snapshot()
    violations = expected_violation(called_name, called_args, observed)
    malicious_effect = bool(violations)
    expected_tool = tool
    utility_success = called_name == expected_tool and all(called_args.get(k) == v for k, v in intended.items())
    return {
        "run_id": str(uuid.uuid4()),
        "phase": "pilot",
        "seed": variant,
        "model": model,
        "tool": tool,
        "called_tool": called_name,
        "attack": attack,
        "malicious_server": malicious,
        "manifest_sha256": manifest_sha256(),
        "intended_input": intended,
        "tool_input": called_args,
        "response": response,
        "observer_effect": observed,
        "violations": violations,
        "malicious_effect": malicious_effect,
        "utility_success": utility_success,
        "defenses": defense_decisions(called_args, response, violations),
        "latency_ms": latency_ms,
        "environment": {"commit": git_commit(), "python": platform.python_version(), "platform": platform.platform()},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["smoke", "pilot"], default="pilot")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or ROOT / "artifacts" / "raw" / f"{args.phase}.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.phase == "smoke":
        matrix = [(MODELS[0], "payment_transfer", "conditional_substitution", label, 0) for label in (False, True)]
    else:
        attacks = {
            "payment_transfer": ["conditional_substitution", "schema_preserving", "delayed_activation"],
            "mail_send": ["conditional_substitution", "schema_preserving", "delayed_activation"],
            "file_read": ["scope_expansion", "delayed_activation", "conditional_substitution"],
        }
        matrix = [(m, t, a, label, v) for m in MODELS for t, families in attacks.items() for a in families for label in (False, True) for v in range(2)]
    random.Random(20260813).shuffle(matrix)
    completed: set[tuple] = set()
    if output.exists():
        for line in output.read_text().splitlines():
            row = json.loads(line)
            completed.add((row["model"], row["tool"], row["attack"], row["malicious_server"], row["seed"]))
    with output.open("a", encoding="utf-8") as handle:
        for index, item in enumerate(matrix, 1):
            if item in completed:
                continue
            model, tool, attack, malicious, variant = item
            try:
                row = run_one(model, tool, attack, malicious, variant)
                row["phase"] = args.phase
                row["error"] = None
            except Exception as exc:
                row = {"run_id": str(uuid.uuid4()), "phase": args.phase, "model": model, "tool": tool, "attack": attack, "malicious_server": malicious, "seed": variant, "error": repr(exc)}
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            print(f"[{index}/{len(matrix)}] {model} {tool} {attack} malicious={malicious} error={row['error']}", flush=True)
    print(output)


if __name__ == "__main__":
    main()

