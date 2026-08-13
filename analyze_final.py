from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


DEFENSES = ["static_hash", "signed_manifest", "response_detector", "intent_trajectory", "toolproof", "toolproof_v2"]


def wilson(k: int, n: int, z: float = 1.959963984540054) -> list[float]:
    if not n:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def metric(rows: list[dict], defense: str, itt: bool) -> dict:
    tp = fp = tn = fn = 0
    for row in rows:
        truth = bool(row.get("malicious_server"))
        if row.get("error"):
            if not itt:
                continue
            pred = not truth  # conservative: attack error=miss, benign error=unavailable/false alarm
        else:
            pred = bool(row["defenses"][defense])
        tp += truth and pred
        fn += truth and not pred
        fp += (not truth) and pred
        tn += (not truth) and not pred
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": precision, "precision_ci95": wilson(tp, tp + fp),
        "recall": recall, "recall_ci95": wilson(tp, tp + fn),
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "fpr_ci95": wilson(fp, fp + tn),
    }


def summarize(rows: list[dict], itt: bool) -> dict:
    return {d: metric(rows, d, itt) for d in DEFENSES}


def load(paths: list[Path]) -> list[dict]:
    return [json.loads(line) for path in paths for line in path.read_text(encoding="utf-8").splitlines() if line]


def exact_mcnemar(b: int, c: int) -> float:
    n = b + c
    if not n:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def group(rows: list[dict], key: str, itt: bool) -> dict:
    buckets = defaultdict(list)
    for row in rows:
        buckets[str(row.get(key, "unknown"))].append(row)
    return {name: {"runs": len(part), "errors": sum(bool(r.get("error")) for r in part),
                   "metrics": summarize(part, itt)} for name, part in sorted(buckets.items())}


def suite_metrics(path: Path, names: list[str]) -> dict:
    rows = load([path])
    output = {"runs": len(rows)}
    for name in names:
        tp = fn = fp = tn = 0
        for row in rows:
            truth = bool(row.get("truth", row.get("malicious", row.get("malicious_server", row.get("attack") != "none"))))
            defenses = row.get("defenses", {})
            aliases = {"schema_only": "schema", "toolproof_v1": "v1", "toolproof_v2": "v2",
                       "static_hash": "static", "response_detector": "response"}
            pred = bool(defenses.get(name, row.get(name, row.get(aliases.get(name, ""), False))))
            tp += truth and pred; fn += truth and not pred
            fp += (not truth) and pred; tn += (not truth) and not pred
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        output[name] = {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "precision": p, "recall": r,
                        "f1": 2 * p * r / (p + r) if p + r else 0.0}
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--adversarial", type=Path)
    parser.add_argument("--network", type=Path)
    parser.add_argument("--mcp", type=Path)
    parser.add_argument("--exclusion-audit", type=Path)
    args = parser.parse_args()
    rows = load(args.inputs)
    valid = [r for r in rows if not r.get("error")]
    b = c = 0
    for r in valid:
        truth = bool(r.get("malicious_server"))
        v1_ok = bool(r["defenses"]["toolproof"]) == truth
        v2_ok = bool(r["defenses"]["toolproof_v2"]) == truth
        b += (not v1_ok) and v2_ok
        c += v1_ok and (not v2_ok)
    report = {
        "runs": len(rows), "valid": len(valid), "errors": len(rows) - len(valid),
        "error_types": Counter(r.get("error", "") for r in rows if r.get("error")),
        "pp": summarize(rows, False), "itt": summarize(rows, True),
        "mcnemar": {"v1_wrong_v2_right": b, "v1_right_v2_wrong": c, "p_two_sided_exact": exact_mcnemar(b, c)},
        "by_model_pp": group(rows, "model", False), "by_model_itt": group(rows, "model", True),
        "by_attack_pp": group(rows, "attack", False), "by_attack_itt": group(rows, "attack", True),
        "by_tool_pp": group(rows, "tool", False),
        "manifest_hashes": sorted({r.get("manifest_sha256") for r in valid}),
        "sources": [str(p) for p in args.inputs],
    }
    if args.adversarial:
        report["adversarial_contract"] = suite_metrics(args.adversarial, ["schema_only", "toolproof_v1", "toolproof_v2"])
    if args.network:
        report["network_boundary"] = suite_metrics(args.network, ["static_hash", "response_detector", "toolproof"])
    if args.mcp:
        report["real_mcp_sdk"] = suite_metrics(args.mcp, ["static_hash", "response_detector", "toolproof"])
    if args.exclusion_audit:
        report["exclusion_audit"] = json.loads(args.exclusion_audit.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=dict) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ["runs", "valid", "errors", "pp", "itt", "mcnemar"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
