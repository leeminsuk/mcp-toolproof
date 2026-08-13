from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path


def wilson(success: int, total: int, z: float = 1.959963984540054) -> list[float]:
    if total == 0:
        return [0.0, 0.0]
    p = success / total
    den = 1 + z * z / total
    center = (p + z * z / (2 * total)) / den
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / den
    return [max(0.0, center - half), min(1.0, center + half)]


def percentile(values: list[float], p: float) -> float:
    values = sorted(values)
    if not values:
        return 0.0
    x = (len(values) - 1) * p
    lo, hi = math.floor(x), math.ceil(x)
    return values[lo] if lo == hi else values[lo] * (hi - x) + values[hi] * (x - lo)


def defense_metrics(rows: list[dict], name: str) -> dict:
    tp = fp = tn = fn = 0
    for row in rows:
        truth = bool(row["malicious_effect"])
        pred = bool(row["defenses"][name])
        tp += truth and pred
        fp += (not truth) and pred
        tn += (not truth) and (not pred)
        fn += truth and (not pred)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "precision_ci95": wilson(tp, tp + fp),
        "recall": recall, "recall_ci95": wilson(tp, tp + fn),
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0, "fpr_ci95": wilson(fp, fp + tn),
    }


def summarize(rows: list[dict]) -> dict:
    valid = [r for r in rows if not r.get("error")]
    attack = [r for r in valid if r["malicious_server"]]
    normal = [r for r in valid if not r["malicious_server"]]
    names = sorted(valid[0]["defenses"]) if valid else []
    actual = sum(r["malicious_effect"] for r in attack)
    utility = sum(r["utility_success"] for r in valid)
    return {
        "runs": len(rows), "valid": len(valid), "errors": len(rows) - len(valid),
        "attack_asr": actual / len(attack) if attack else 0.0, "attack_asr_ci95": wilson(actual, len(attack)),
        "utility": utility / len(valid) if valid else 0.0, "utility_ci95": wilson(utility, len(valid)),
        "retry_rate": sum(r.get("tool_call_retries", 0) > 0 for r in valid) / len(valid) if valid else 0.0,
        "inference_p50_ms": percentile([r["latency_ms"] for r in valid], .5),
        "inference_p95_ms": percentile([r["latency_ms"] for r in valid], .95),
        "contract_p50_us": percentile([r.get("contract_latency_us", 0) for r in valid], .5),
        "contract_p95_us": percentile([r.get("contract_latency_us", 0) for r in valid], .95),
        "defenses": {name: defense_metrics(valid, name) for name in names},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for path in args.inputs:
        rows.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
    by_model = defaultdict(list)
    by_attack = defaultdict(list)
    by_tool = defaultdict(list)
    for row in rows:
        by_model[row["model"]].append(row)
        by_attack[row["attack"]].append(row)
        by_tool[row["tool"]].append(row)
    report = {
        "overall": summarize(rows),
        "by_model": {k: summarize(v) for k, v in sorted(by_model.items())},
        "by_attack": {k: summarize(v) for k, v in sorted(by_attack.items())},
        "by_tool": {k: summarize(v) for k, v in sorted(by_tool.items())},
        "sources": [str(p) for p in args.inputs],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report["overall"], ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

