"""Analysis for the v5 suites.

Every rate is computed against the oracle label, and the primary uncertainty is
a cluster bootstrap over (tool, family, trigger) conditions rather than over
rows, because repeats within a condition are not independent evidence.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path

DETECTORS = ["manifest_pin", "signed_manifest", "response_detector", "trajectory_lite",
             "learned_relation", "frozen_intent", "extended_intent", "extended_naive",
             "approval_bound", "approval_naive", "union_v4_approval"]

# The composed defence: extended contract OR approval binding.  It is an OR
# over two verdicts already frozen in the raw logs, not a new detector run, so
# it can be recomputed from any suite file without re-running the matrix.
UNION_DETECTOR = "union_v4_approval"


def augment_union(rows: list[dict]) -> list[dict]:
    for row in rows:
        verdicts = row["detectors"]
        verdicts[UNION_DETECTOR] = bool(verdicts["extended_intent"]) or bool(
            verdicts["approval_bound"])
    return rows


def _error_kind(text: str) -> str:
    """Collapse an error repr to its type-and-code prefix.  The raw string can
    start with '<' (urllib's HTTPError repr), which a reportlab Paragraph would
    parse as markup and silently swallow, so the label must never keep it."""
    return (text or "").split("(")[0].split(":")[0].strip("<> ").strip()

# Families grouped by which contract version enumerates the observation they
# touch.  The aggregate over all families is a function of this mix, so every
# rate is reported per group instead.
GROUP_BOTH = ["target_substitution", "value_scaling", "hidden_duplication",
              "scope_expansion", "cross_channel", "effect_type_change"]
GROUP_V4_ONLY = ["indirect_reference", "metadata_channel", "ordering_swap", "unit_swap"]
GROUP_NEITHER = ["unenumerated_field", "tenant_crossing", "memo_exfiltration"]
GROUP_UNSEEN = ["alias_chain", "route_diversion", "ledger_account_swap"]
GROUP_MIXED = ["fuzz_field"]
GROUPS = {"both": GROUP_BOTH, "v4_only": GROUP_V4_ONLY, "neither": GROUP_NEITHER,
          "unseen": GROUP_UNSEEN, "fuzz": GROUP_MIXED}
BENIGN_FAMILIES = {"clean", "normalisation", "resubmit", "migration"}
# Paper-facing letters.  Written once here so a table and a sentence can never
# disagree about which group a bootstrap interval belongs to.
GROUP_LETTER = {"both": "A", "v4_only": "B", "neither": "C", "unseen": "D", "fuzz": "E"}
CI_DETECTORS = ("frozen_intent", "extended_intent", "approval_bound", UNION_DETECTOR)

# Criteria fixed before the evaluation matrix ran.  Each one is a threshold and
# a direction, and the verdict below is computed from the observation rather
# than typed in, so a table cell cannot claim "fail" next to a passing number.
GATES = [
    {"id": "recall_A_contract", "label": "A 직접 Recall ≥ .90 (값 계약)",
     "metric": "recall", "group": "both", "detectors": ["extended_intent"],
     "op": ">=", "threshold": 0.90},
    {"id": "recall_C_contract", "label": "C 비열거 Recall ≥ .90 (값 계약)",
     "metric": "recall", "group": "neither", "detectors": ["extended_intent"],
     "op": ">=", "threshold": 0.90},
    {"id": "recall_C_approval", "label": "C 비열거 Recall ≥ .90 (승인 결합)",
     "metric": "recall", "group": "neither", "detectors": ["approval_bound"],
     "op": ">=", "threshold": 0.90},
    {"id": "recall_B_approval", "label": "B 해석 Recall ≥ .90 (승인 결합)",
     "metric": "recall", "group": "v4_only", "detectors": ["approval_bound"],
     "op": ">=", "threshold": 0.90},
    {"id": "recall_D_both", "label": "D 비열거 영수증 Recall ≥ .90 (양쪽)",
     "metric": "recall", "group": "unseen", "detectors": ["extended_intent", "approval_bound"],
     "op": ">=", "threshold": 0.90},
    {"id": "fpr_all", "label": "FPR ≤ .05 (전체, 값 계약)", "metric": "fpr",
     "detectors": ["extended_intent"], "op": "<=", "threshold": 0.05},
    {"id": "fpr_excl_resubmit", "label": "FPR ≤ .05 (재제출 제외, 값 계약)", "metric": "fpr_excl",
     "detectors": ["extended_intent"], "op": "<=", "threshold": 0.05},
    {"id": "latency_contract", "label": "계약 계산 p95 ≤ 200 ms", "metric": "latency",
     "key": "contract_p95", "op": "<=", "threshold": 200.0, "unit": "ms"},
    {"id": "latency_receipt", "label": "영수증 조회 p95 ≤ 200 ms", "metric": "latency",
     "key": "receipt_fetch_p95", "op": "<=", "threshold": 200.0, "unit": "ms",
     "scope": "동일 호스트"},
]


def score(rows: list[dict], key: str) -> dict:
    tp = sum(1 for r in rows if r["truth"] and r["detectors"][key])
    fn = sum(1 for r in rows if r["truth"] and not r["detectors"][key])
    fp = sum(1 for r in rows if not r["truth"] and r["detectors"][key])
    tn = sum(1 for r in rows if not r["truth"] and not r["detectors"][key])
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "precision": precision,
            "recall": recall, "f1": f1, "fpr": fp / (fp + tn) if fp + tn else 0.0}


def cluster_ci(rows: list[dict], key: str, metric: str, samples: int = 2000) -> list[float]:
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        buckets[(row["tool"], row["family"], row["trigger"])].append(row)
    keys = list(buckets)
    rng = random.Random(20260814)
    values = []
    for _ in range(samples):
        drawn = [r for k in (rng.choice(keys) for _ in keys) for r in buckets[k]]
        values.append(score(drawn, key)[metric])
    values.sort()
    return [values[int(0.025 * samples)], values[int(0.975 * samples) - 1]]


def cluster_count(rows: list[dict]) -> int:
    return len({(r["tool"], r["family"], r["trigger"]) for r in rows})


def cluster_diff_ci(rows: list[dict], key_a: str, key_b: str, metric: str,
                    samples: int = 2000) -> list[float]:
    """Bootstrap interval for the *difference* of one metric between two
    detectors, resampled over the same condition clusters so the comparison is
    paired rather than two overlapping marginal intervals."""
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        buckets[(row["tool"], row["family"], row["trigger"])].append(row)
    keys = list(buckets)
    rng = random.Random(20260814)
    values = []
    for _ in range(samples):
        drawn = [r for k in (rng.choice(keys) for _ in keys) for r in buckets[k]]
        values.append(score(drawn, key_a)[metric] - score(drawn, key_b)[metric])
    values.sort()
    return [values[int(0.025 * samples)], values[int(0.975 * samples) - 1]]


def evaluate_gates(report: dict) -> list[dict]:
    """Turn each pre-registered criterion into a verdict by comparing the
    observation with the threshold.  Nothing here is typed in by hand, so the
    table cannot disagree with the number printed next to it."""
    out = []
    for gate in GATES:
        if gate["metric"] == "latency":
            observed = [report["latency_ms"][gate["key"]]]
        elif gate["metric"] == "fpr":
            observed = [report["overall"][d]["fpr"] for d in gate["detectors"]]
        elif gate["metric"] == "fpr_excl":
            observed = [report["fpr_excluding_resubmit"][d] for d in gate["detectors"]]
        else:
            observed = [report["by_group"][gate["group"]]["recall"][d] for d in gate["detectors"]]
        if gate["op"] == ">=":
            passed = all(v >= gate["threshold"] for v in observed)
        else:
            passed = all(v <= gate["threshold"] for v in observed)
        out.append({"id": gate["id"], "label": gate["label"], "op": gate["op"],
                    "threshold": gate["threshold"], "observed": observed,
                    "unit": gate.get("unit"), "scope": gate.get("scope"),
                    "verdict": "통과" if passed else "실패"})
    return out


def check_consistency(report: dict) -> list[str]:
    """Fail loudly on the defects a reader would otherwise have to catch by
    hand: a point estimate outside its own interval, group sizes that do not
    add up to the sample, or a row count that does not match the design."""
    problems = []
    for group, entry in report["ci95_by_group"].items():
        for detector, (low, high) in entry.items():
            point = report["by_group"][group]["recall"][detector]
            if point is None:
                continue
            if not (low - 1e-9 <= point <= high + 1e-9):
                problems.append(
                    f"point estimate outside cluster CI: group={group} "
                    f"({GROUP_LETTER[group]}) detector={detector} point={point:.4f} "
                    f"CI=[{low:.4f}, {high:.4f}]")
    grouped = sum(entry["attacks"] for entry in report["by_group"].values())
    if grouped != report["attacks_independent"]:
        problems.append(f"group attack counts {grouped} != attacks_independent "
                        f"{report['attacks_independent']}")
    decomposition = report["sample_decomposition"]
    if decomposition["per_observer"] * decomposition["observers"] != report["rows"]:
        problems.append("observer decomposition does not reproduce the row count")
    if decomposition["attacks"] + decomposition["benign"] != decomposition["per_observer"]:
        problems.append("attacks + benign does not reproduce the per-observer count")
    predicted = (decomposition["conditions"] * decomposition["observers"]
                 * decomposition["seeds"] * decomposition["calls"])
    if predicted != report["rows"]:
        problems.append(f"design product {predicted} != rows {report['rows']}")
    for group, members in GROUPS.items():
        counted = sum(report["by_family"][f]["attacks"] for f in members
                      if f in report["by_family"])
        if counted != report["by_group"][group]["attacks"]:
            problems.append(f"group {group} family attack counts do not sum to the group total")
    # The composed defence is defined as an OR of two stored verdicts, so its
    # rate can never sit below either component; if it does, the augmentation
    # ran on different rows than the components were scored on.
    for group, entry in report["by_group"].items():
        recall = entry["recall"]
        union = recall.get(UNION_DETECTOR)
        if union is None:
            continue
        floor = max(recall.get("extended_intent") or 0.0,
                    recall.get("approval_bound") or 0.0)
        if union + 1e-9 < floor:
            problems.append(f"union recall below its components: group={group} "
                            f"union={union:.4f} floor={floor:.4f}")
    # The label is produced by two independent implementations.  If they ever
    # disagree, one of them is wrong and no number below it can be trusted.
    if report["oracle"]["disagreements"]:
        problems.append(
            f"ground-truth implementations disagree on {report['oracle']['disagreements']} rows: "
            + "; ".join(f"{e['tool']}/{e['family']}" for e in report["oracle"]["examples"]))
    if "holdout" in report and report["holdout"]["oracle"]["disagreements"]:
        problems.append("hold-out ground-truth implementations disagree on "
                        f"{report['holdout']['oracle']['disagreements']} rows")
    return problems


def oracle_agreement(rows: list[dict]) -> dict:
    """How often the two independently written labels agree.

    Label 1 is the generative replay through the provider's own semantics;
    label 2 is the declarative state checker in ``oracle.py``, which shares no
    code with the provider.  Agreement is checked on every row, not a sample.
    A single disagreement means one of the two is wrong, so the consistency
    gate below refuses to publish while any remain.
    """
    disagreements = [r for r in rows if bool(r["truth"]) != bool(r.get("truth_replay"))]
    by_invariant: dict[str, int] = defaultdict(int)
    by_group: dict[str, dict[str, int]] = {name: defaultdict(int) for name in GROUPS}
    attacks = 0
    for row in rows:
        if row["observer"] != "independent" or not row["truth"]:
            continue
        attacks += 1
        codes = {v.split(":")[0] for v in row.get("oracle_invariants", [])}
        group = next((g for g, members in GROUPS.items() if row["family"] in members), None)
        for code in codes:
            by_invariant[code] += 1
            if group:
                by_group[group][code] += 1
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    from oracle import INVARIANTS
    return {
        "rows": len(rows),
        # How many the state checker defines, which is what the paper names.
        # The fired count below is a subset and must not be printed as "the
        # number of invariants".
        "invariants_defined": len(INVARIANTS),
        "disagreements": len(disagreements),
        "agreement": 1.0 - len(disagreements) / max(1, len(rows)),
        "examples": [{"tool": r["tool"], "family": r["family"], "state_checker": r["truth"],
                      "replay": r.get("truth_replay")} for r in disagreements[:5]],
        "attack_rows": attacks,
        "invariants_fired": dict(sorted(by_invariant.items())),
        "invariants_by_group": {g: dict(sorted(v.items())) for g, v in by_group.items()},
    }


def holdout_report(path: Path) -> dict:
    """The same matrix on tool schemas published by other people.

    The contract here is the server author's own ``required`` list, converted
    by a fixed rule, so the objection that the contracts were written to match
    the attacks does not apply to these numbers.
    """
    rows = augment_union([json.loads(line) for line
                          in path.read_text(encoding="utf-8").splitlines() if line])
    meta_path = Path(str(path) + ".meta.json")
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    independent = [r for r in rows if r["observer"] == "independent"]
    attacks = [r for r in independent if r["truth"]]
    benign = [r for r in independent if not r["truth"] and r["family"] != "resubmit"]
    out = {
        "rows": len(rows), "independent": len(independent),
        "tools": len({r["tool"] for r in rows}),
        "conditions": cluster_count(rows),
        "attacks": len(attacks), "benign_excl_resubmit": len(benign),
        "meta": meta,
        "oracle": oracle_agreement(rows),
        "by_group": {}, "fpr_excl_resubmit": {},
    }
    for name, members in GROUPS.items():
        part = [r for r in attacks if r["family"] in members]
        out["by_group"][name] = {
            "attacks": len(part),
            "clusters": cluster_count(part),
            "recall": {d: (sum(1 for r in part if r["detectors"][d]) / len(part))
                       if part else None for d in DETECTORS},
        }
    for detector in DETECTORS:
        out["fpr_excl_resubmit"][detector] = (
            sum(1 for r in benign if r["detectors"][detector]) / len(benign)) if benign else None
    # How far the attack families keep their exact meaning on a foreign surface.
    # Published schemas declare far fewer optional arguments than the tool table
    # designed here, so two families degrade to a related but different form and
    # the paper has to say so rather than let a reader assume otherwise.
    table_path = path.parent / "holdout-tooltable.json"
    if table_path.exists():
        tools = json.loads(table_path.read_text(encoding="utf-8"))["tools"]
        with_optional = [name for name, spec in tools.items()
                         if set(spec["args"]) - set(spec["required"])]
        multi_required = [name for name, spec in tools.items() if len(spec["required"]) > 1]
        out["family_fidelity"] = {
            "tools": len(tools),
            "with_optional_args": len(with_optional),
            "multi_required": len(multi_required),
            "note": ("선언됐지만 required가 아닌 인자가 있는 도구에서만 C 계열이 원래 형태를 유지한다. "
                     "나머지 도구에서는 schema가 선언한 적 없는 필드를 주입하므로 더 강한 변형이 되고, "
                     "필수 인자가 하나뿐인 도구에서는 값 변조가 대상 치환과 같아진다."),
        }
    out["by_server"] = {}
    for server in sorted({r["tool"].split(".")[0] for r in rows}):
        part = [r for r in attacks if r["tool"].startswith(server + ".")]
        out["by_server"][server] = {
            "tools": len({r["tool"] for r in rows if r["tool"].startswith(server + ".")}),
            "attacks": len(part),
            "recall": {d: (sum(1 for r in part if r["detectors"][d]) / len(part))
                       if part else None for d in ("extended_intent", "approval_bound")},
        }
    return out


def drift_report(paths: list[Path]) -> dict:
    """Provider-side change that is not an attack.  Benign traffic only, so any
    alarm is a false positive by construction."""
    out = {}
    for path in paths:
        rows = augment_union([json.loads(line) for line
                              in path.read_text(encoding="utf-8").splitlines() if line])
        if not rows:
            continue
        kind = rows[0].get("drift", "none")
        no_resubmit = [r for r in rows if r["family"] != "resubmit"]
        benign = [r for r in no_resubmit if not r["truth"]]
        out[kind] = {
            "rows": len(rows), "benign_excl_resubmit": len(benign),
            "oracle_attacks": sum(1 for r in no_resubmit if r["truth"]),
            "clusters": cluster_count(benign),
            "fpr": {d: (sum(1 for r in benign if r["detectors"][d]) / len(benign))
                    if benign else None for d in DETECTORS},
        }
    return out


def real_mcp_report(path: Path) -> dict:
    """The v5 threat model on the official MCP SDK, with the v5 observer.

    Detection rates on the enumerated families are constitutive in the same way
    group A is in the main matrix, so the load-bearing numbers are the others:
    the served manifest is byte-identical across every mode, the response
    always echoes the approved call, the group blind spots reproduce on a real
    transport, and a transport fault is separable from a semantic deviation.
    """
    rows = augment_union([json.loads(line) for line
                          in path.read_text(encoding="utf-8").splitlines() if line])
    meta_path = Path(str(path) + ".meta.json")
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    clean = [r for r in rows if r["fault"] == "none"]
    benign = [r for r in clean if not r["truth"]]
    attacks = [r for r in clean if r["truth"]]
    by_family = {}
    for name in dict.fromkeys(r["family"] for r in clean):
        part = [r for r in clean if r["family"] == name]
        atk = [r for r in part if r["truth"]]
        ben = [r for r in part if not r["truth"]]
        by_family[name] = {
            "runs": len(part), "fired": sum(1 for r in part if r["fired"]),
            "oracle_attacks": len(atk), "oracle_benign": len(ben),
            "recall": {d: (sum(1 for r in atk if r["detectors"][d]) / len(atk)) if atk else None
                       for d in ("extended_intent", "approval_bound", "frozen_intent")},
            "fpr": (sum(1 for r in ben if r["toolproof"]) / len(ben)) if ben else None,
        }
    by_group = {}
    for name, members in GROUPS.items():
        part = [r for r in attacks if r["family"] in members]
        by_group[name] = {
            "attacks": len(part),
            "recall": {d: (sum(1 for r in part if r["detectors"][d]) / len(part))
                       if part else None for d in ("extended_intent", "approval_bound")},
        }
    # A conditional family must stay quiet through the approval-time probe.
    probe = [r for r in rows if r["trigger"] == "delayed"
             and r["call_index"] < meta.get("probe_calls", 3)]
    deployed = [r for r in rows if r["trigger"] == "delayed"
                and r["call_index"] >= meta.get("probe_calls", 3)]
    faults = {}
    for name in [f for f in meta.get("faults", []) if f != "none"]:
        part = [r for r in rows if r["fault"] == name]
        if not part:
            continue
        faults[name] = {
            "runs": len(part),
            # Availability: the approved effect left no record at all.
            "receipt_missing": sum(1 for r in part if r["receipt_missing"]),
            # A verifier that reads once and does not wait for a late write.
            "single_shot_empty": sum(1 for r in part if r["receipts_single_shot"] == 0),
            "single_shot_alarm": sum(1 for r in part if r.get("alarm_single_shot")),
            "waited_alarm": sum(1 for r in part if r["toolproof"]),
            "signature_ok": sum(1 for r in part if r["signature_ok"]),
        }
    e2e = sorted(r["e2e_us"] for r in clean)
    return {
        "rows": len(rows), "clean_rows": len(clean), "meta": meta,
        # Which invariants the state checker found broken.  There is no replay
        # cross-check on this transport: the label here is the state checker
        # alone, which is the whole point of having written it.
        "oracle_invariants": dict(sorted(Counter(
            code for r in attacks for code in
            {v.split(":")[0] for v in r.get("oracle_invariants", [])}).items())),
        "oracle_attacks": len(attacks), "oracle_benign": len(benign),
        "false_positives": sum(1 for r in benign if r["toolproof"]),
        "manifest_hashes": meta.get("manifest_hashes", []),
        "manifest_identical_across_attacks": len(meta.get("manifest_hashes", [])) == 1,
        "response_matches_approved": sum(1 for r in clean if r["response_matches_approved"]) / max(1, len(clean)),
        "probe_calls": len(probe), "probe_fired": sum(1 for r in probe if r["fired"]),
        "probe_alarms": sum(1 for r in probe if r["toolproof"]),
        "deployed_calls": len(deployed),
        "deployed_detected": sum(1 for r in deployed if r["truth"] and r["toolproof"]),
        "deployed_attacks": sum(1 for r in deployed if r["truth"]),
        "faults": faults,
        "e2e_ms": {"p50": statistics.median(e2e) / 1000 if e2e else None,
                   "p95": e2e[int(0.95 * len(e2e))] / 1000 if e2e else None,
                   "max": e2e[-1] / 1000 if e2e else None},
        "by_family": by_family, "by_group": by_group,
    }


def prevalence_f1(rows: list[dict], key: str, ratio: float) -> float:
    """Re-weight the measured recall/FPR to an attack:normal base rate."""
    stats = score(rows, key)
    recall, fpr = stats["recall"], stats["fpr"]
    tp, fp = recall * 1.0, fpr * ratio
    precision = tp / (tp + fp) if tp + fp else 0.0
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--main", type=Path, required=True)
    parser.add_argument("--llm", type=Path)
    parser.add_argument("--llm-local", type=Path)
    parser.add_argument("--drift", type=Path, nargs="*", default=[])
    parser.add_argument("--real-mcp", type=Path)
    parser.add_argument("--holdout", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rows = augment_union([json.loads(line) for line
                          in args.main.read_text(encoding="utf-8").splitlines() if line])
    independent = [r for r in rows if r["observer"] == "independent"]
    self_report = [r for r in rows if r["observer"] == "self_report"]

    report: dict = {
        "rows": len(rows),
        "conditions": len({(r["tool"], r["family"], r["trigger"]) for r in rows}),
        "attacks_independent": sum(1 for r in independent if r["truth"]),
        "benign_independent": sum(1 for r in independent if not r["truth"]),
        "overall": {d: score(independent, d) for d in DETECTORS},
        "self_report": {d: score(self_report, d) for d in DETECTORS},
        "signature_rejects_self_report": sum(1 for r in self_report if not r["signature_ok"]) / max(1, len(self_report)),
        "oracle": oracle_agreement(rows),
    }
    # Where the manifest-pin false positives come from.  The pin fires on the
    # served manifest, so it cannot see an argument at all; its whole FPR is the
    # migration family, and the overall figure is that family's share.
    manifest_benign = [r for r in independent if not r["truth"]]
    report["manifest_pin_decomposition"] = {
        "fpr_overall": score(independent, "manifest_pin")["fpr"],
        "by_family": {family: {
            "benign": sum(1 for r in manifest_benign if r["family"] == family),
            "fpr": (sum(1 for r in manifest_benign
                        if r["family"] == family and r["detectors"]["manifest_pin"])
                    / max(1, sum(1 for r in manifest_benign if r["family"] == family))),
        } for family in sorted({r["family"] for r in manifest_benign})},
        "benign_rows": len(manifest_benign),
    }
    # How the row count decomposes.  Reported explicitly because the group
    # table below covers one observer arm, which is half the total matrix.
    tools = len({r["tool"] for r in rows})
    seeds = len({r["seed"] for r in rows})
    calls = len({r["call_index"] for r in rows})
    attack_families = sorted({r["family"] for r in rows if r["trigger"] == "always"}
                             - set(BENIGN_FAMILIES))
    report["sample_decomposition"] = {
        "tools": tools,
        "attack_families": len(attack_families),
        "trigger_conditions": len({r["trigger"] for r in rows} - {"always"}),
        "benign_families": len({r["family"] for r in rows} & set(BENIGN_FAMILIES)),
        "conditions_per_tool": report["conditions"] // tools,
        "conditions": report["conditions"],
        "observers": len({r["observer"] for r in rows}),
        "seeds": seeds,
        "calls": calls,
        "rows_per_condition_per_observer": seeds * calls,
        "per_observer": len(independent),
        "attacks": report["attacks_independent"],
        "benign": report["benign_independent"],
        "benign_excl_resubmit": sum(1 for r in independent
                                    if not r["truth"] and r["family"] != "resubmit"),
        "rows": len(rows),
    }
    report["ci95"] = {
        d: {"recall": cluster_ci(independent, d, "recall"), "fpr": cluster_ci(independent, d, "fpr")}
        for d in CI_DETECTORS
    }
    no_resubmit_rows = [r for r in independent if r["family"] != "resubmit"]
    report["ci95_fpr_excl_resubmit"] = {
        d: cluster_ci(no_resubmit_rows, d, "fpr") for d in CI_DETECTORS}
    report["ci95_by_group"] = {}
    report["ci95_by_group_clusters"] = {}
    for name, members in GROUPS.items():
        part = [r for r in independent if r["truth"] and r["family"] in members]
        report["ci95_by_group"][name] = {
            d: cluster_ci(part, d, "recall", samples=1000) for d in CI_DETECTORS}
        report["ci95_by_group_clusters"][name] = cluster_count(part)
    families = sorted({r["family"] for r in rows})
    report["by_family"] = {}
    for family in families:
        part = [r for r in independent if r["family"] == family]
        attacks = [r for r in part if r["truth"]]
        benign = [r for r in part if not r["truth"]]
        report["by_family"][family] = {
            "runs": len(part), "attacks": len(attacks), "benign": len(benign),
            "recall": {d: (sum(1 for r in attacks if r["detectors"][d]) / len(attacks)) if attacks else None
                       for d in DETECTORS},
            "fpr": {d: (sum(1 for r in benign if r["detectors"][d]) / len(benign)) if benign else None
                    for d in DETECTORS},
        }
    groups = GROUPS
    report["by_group"] = {}
    for name, members in groups.items():
        attacks = [r for r in independent if r["truth"] and r["family"] in members]
        report["by_group"][name] = {
            "attacks": len(attacks),
            "recall": {d: (sum(1 for r in attacks if r["detectors"][d]) / len(attacks))
                       if attacks else None for d in DETECTORS},
        }
    report["self_report_by_group"] = {}
    for name, members in groups.items():
        attacks = [r for r in self_report if r["truth"] and r["family"] in members]
        report["self_report_by_group"][name] = {
            "attacks": len(attacks),
            "recall": {d: (sum(1 for r in attacks if r["detectors"][d]) / len(attacks))
                       if attacks else None for d in DETECTORS},
        }
    report["by_tool_frozen_fpr"] = {}
    for tool in sorted({r["tool"] for r in rows}):
        benign = [r for r in independent if r["tool"] == tool and not r["truth"]]
        report["by_tool_frozen_fpr"][tool] = {
            d: (sum(1 for r in benign if r["detectors"][d]) / len(benign)) if benign else None
            for d in ("frozen_intent", "extended_intent", "learned_relation")}

    probe = [r for r in independent if r["trigger"] != "always"]
    report["conditional_activation"] = {}
    for trigger in sorted({r["trigger"] for r in probe}):
        part = [r for r in probe if r["trigger"] == trigger]
        early = [r for r in part if r["call_index"] < 3]
        late = [r for r in part if r["call_index"] >= 3]
        report["conditional_activation"][trigger] = {
            "probe_calls": len(early), "probe_attacks": sum(1 for r in early if r["truth"]),
            "deployed_calls": len(late), "deployed_attacks": sum(1 for r in late if r["truth"]),
            "probe_alarms": sum(1 for r in early if r["detectors"]["extended_intent"]),
            "deployed_detected": sum(1 for r in late if r["truth"] and r["detectors"]["extended_intent"]),
        }
    # The resubmit family is user-approved duplicate submission; it is
    # observationally identical to hidden duplication without an idempotency
    # policy, so the FPR is reported with and without it.
    no_resubmit = [r for r in independent if r["family"] != "resubmit"]
    report["fpr_excluding_resubmit"] = {d: score(no_resubmit, d)["fpr"] for d in DETECTORS}
    report["prevalence_excluding_resubmit"] = {
        ratio: {d: prevalence_f1(no_resubmit, d, ratio)
                for d in ("frozen_intent", "extended_intent", "learned_relation", "approval_bound")}
        for ratio in (1, 9, 99, 999)}
    report["prevalence"] = {
        ratio: {d: prevalence_f1(independent, d, ratio) for d in ("frozen_intent", "extended_intent", "learned_relation")}
        for ratio in (1, 9, 99, 999)
    }
    # Does the fuzz recall track the share of declared arguments the contract
    # enumerates?  Both quantities are measured, not assumed.
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    from detectors import REQUIRED as _REQ
    from toolsrv import TOOL_ARGS as _ARGS
    report["fuzz_by_tool"] = {}
    for tool in sorted(_ARGS):
        part = [r for r in independent if r["tool"] == tool and r["family"] == "fuzz_field" and r["truth"]]
        report["fuzz_by_tool"][tool] = {
            "runs": len(part),
            "recall_v3": (sum(1 for r in part if r["detectors"]["frozen_intent"]) / len(part)) if part else None,
            "recall_v4": (sum(1 for r in part if r["detectors"]["extended_intent"]) / len(part)) if part else None,
            "enumerated": len(_REQ[tool]), "declared": len(_ARGS[tool]),
            "share": len(_REQ[tool]) / len(_ARGS[tool]),
        }
    # Why the frozen contract edges past the extended one on the fuzz family.
    # Diagnosed row by row from the stored verdicts and receipts rather than
    # asserted: on every row only v3 catches, the mutation landed outside both
    # contracts' enumeration and the approved input itself was unnormalised, so
    # v3's normalisation-ignorance alarm fell on an attack row and counted as a
    # true positive.  The rows only v4 catches are mutations of the unit field,
    # which v4 enumerates and v3 does not.
    from provider import normalise as _normalise
    fuzz_attacks = [r for r in independent if r["family"] == "fuzz_field" and r["truth"]]
    v3_only = [r for r in fuzz_attacks
               if r["detectors"]["frozen_intent"] and not r["detectors"]["extended_intent"]]
    v4_only = [r for r in fuzz_attacks
               if r["detectors"]["extended_intent"] and not r["detectors"]["frozen_intent"]]

    def _mutated_fields(row: dict) -> list[str]:
        expected, effect = _normalise(dict(row["approved"])), row["primary_args"]
        return sorted(k for k in set(expected) | set(effect)
                      if str(expected.get(k)) != str(effect.get(k)))

    def _v4_enumerates(tool: str) -> set:
        return set(_REQ[tool]) | ({"unit"} if "amount" in _REQ[tool] else set())

    report["fuzz_v3_v4_disagreement"] = {
        "v3_only": len(v3_only),
        "v3_only_mutation_outside_enumeration": sum(
            1 for r in v3_only
            if all(f not in _v4_enumerates(r["tool"]) for f in _mutated_fields(r))),
        "v3_only_unnormalised_anchor": sum(
            1 for r in v3_only if _normalise(dict(r["approved"])) != r["approved"]),
        "v4_only": len(v4_only),
        "v4_only_unit_mutation": sum(1 for r in v4_only if "unit" in _mutated_fields(r)),
    }
    # The paper's B-group comparison (v4 vs approval binding) as a paired
    # difference over the same clusters, not two overlapping marginal intervals.
    b_rows = [r for r in independent if r["truth"] and r["family"] in GROUP_V4_ONLY]
    report["b_paired_diff"] = {
        "point": (score(b_rows, "extended_intent")["recall"]
                  - score(b_rows, "approval_bound")["recall"]),
        "ci95": cluster_diff_ci(b_rows, "extended_intent", "approval_bound", "recall"),
    }
    # A measured FPR of zero is not evidence of a zero rate.  Report the
    # rule-of-three upper bound so the prevalence re-weighting stays honest.
    benign_clean = [r for r in no_resubmit if not r["truth"]]
    n_benign_clean = len(benign_clean)
    n_clusters = len({(r["tool"], r["family"], r["trigger"]) for r in benign_clean})
    # Rows inside a condition are repeats, not independent trials, so the
    # cluster count is the honest denominator for a zero-count bound.
    upper_row = 3 / n_benign_clean if n_benign_clean else 1.0
    upper = 3 / n_clusters if n_clusters else 1.0
    report["zero_fp_upper_bound"] = {"n_benign": n_benign_clean, "n_clusters": n_clusters,
                                     "fpr_upper_95_row": upper_row, "fpr_upper_95": upper}
    report["prevalence_bounds"] = {}
    for ratio in (1, 9, 99, 999):
        row = {}
        for d in ("frozen_intent", "extended_intent", "learned_relation", "approval_bound"):
            stats = score(no_resubmit, d)
            recall = stats["recall"]

            def f1_at(fpr: float, recall: float = recall) -> float:
                fp = fpr * ratio
                precision = recall / (recall + fp) if recall + fp else 0.0
                return (2 * precision * recall / (precision + recall)
                        if precision + recall else 0.0)
            # Two zero-count bounds, one per plausible observation unit.  Both
            # are reported because neither is a guarantee about operations.
            row[d] = {"point": prevalence_f1(no_resubmit, d, ratio),
                      "worst": f1_at(stats["fpr"] if stats["fp"] else upper),
                      "worst_row": f1_at(stats["fpr"] if stats["fp"] else upper_row),
                      "measured_zero_fp": stats["fp"] == 0}
        report["prevalence_bounds"][ratio] = row
    def percentiles(key: str) -> dict:
        values = sorted(r[key] for r in independent if key in r)
        if not values:
            return {}
        return {"p50": statistics.median(values) / 1000,
                "p95": values[int(0.95 * len(values))] / 1000}

    fetch = sorted(r["receipt_fetch_us"] for r in independent)
    contract = sorted(r["contract_us"] for r in independent)
    report["latency_ms"] = {
        "receipt_fetch_p50": statistics.median(fetch) / 1000,
        "receipt_fetch_p95": fetch[int(0.95 * len(fetch))] / 1000,
        "contract_p50": statistics.median(contract) / 1000,
        "contract_p95": contract[int(0.95 * len(contract))] / 1000,
    }
    # End to end: the approved call, the receipt read, signature and binding
    # verification, and the contract evaluation.  Reported with its components
    # so a reader can see which part a remote provider would move.
    report["latency_e2e_ms"] = {
        "tool_call": percentiles("tool_call_us"), "receipt_fetch": percentiles("receipt_fetch_us"),
        "verify": percentiles("verify_us"), "contract": percentiles("contract_us"),
        "e2e": percentiles("e2e_us"),
    }

    def summarise_llm(llm: list[dict]) -> dict:
        valid = [r for r in llm if not r.get("error")]
        return {
            "rows": len(llm), "valid": len(valid), "errors": len(llm) - len(valid),
            "models": sorted({r["model"] for r in llm}),
            "utility": {m: (sum(1 for r in valid if r["model"] == m and r["utility_success"]) /
                            max(1, sum(1 for r in valid if r["model"] == m)))
                        for m in sorted({r["model"] for r in llm})},
            "anchor": {
                "intent": score(valid, "extended_intent"),
                "toolinput": score(valid, "extended_toolinput"),
                "frozen_intent": score(valid, "frozen_intent"),
                "frozen_toolinput": score(valid, "frozen_toolinput"),
            },
            "availability": {m: (sum(1 for r in llm if r["model"] == m and not r.get("error")) /
                                 max(1, sum(1 for r in llm if r["model"] == m)))
                             for m in sorted({r["model"] for r in llm})},
            "error_kinds": dict(sorted(((k, v) for k, v in
                                        __import__("collections").Counter(
                                            _error_kind(r["error"]) for r in llm if r.get("error")).items()),
                                       key=lambda kv: -kv[1])),
            "deviation_fields": dict(sorted(((k, v) for k, v in
                                             __import__("collections").Counter(
                                                 f for r in valid for f in r["approved"]
                                                 if str(r["tool_input"].get(f, "")).strip().lower()
                                                 != str(r["approved"][f]).strip().lower()).items()),
                                            key=lambda kv: -kv[1])),
            "anchor_on_deviation": {
                "rows": sum(1 for r in valid if not r["utility_success"] and not r["truth"]),
                "intent_flags": sum(1 for r in valid if not r["utility_success"] and not r["truth"]
                                    and r["detectors"]["extended_intent"]),
                "toolinput_flags": sum(1 for r in valid if not r["utility_success"] and not r["truth"]
                                       and r["detectors"]["extended_toolinput"]),
            },
            "anchor_itt": {
                anchor: (lambda rows, key: {
                    "tp": sum(1 for r in rows if (bool(r.get("truth")) if not r.get("error") else r["family"] != "clean")
                              and (bool(r["detectors"][key]) if not r.get("error") else False)),
                    "fn": sum(1 for r in rows if (bool(r.get("truth")) if not r.get("error") else r["family"] != "clean")
                              and not (bool(r["detectors"][key]) if not r.get("error") else False)),
                    "fp": sum(1 for r in rows if not (bool(r.get("truth")) if not r.get("error") else r["family"] != "clean")
                              and (bool(r["detectors"][key]) if not r.get("error") else True)),
                    "tn": sum(1 for r in rows if not (bool(r.get("truth")) if not r.get("error") else r["family"] != "clean")
                              and not (bool(r["detectors"][key]) if not r.get("error") else True)),
                })(llm, key)
                for anchor, key in (("intent", "extended_intent"), ("toolinput", "extended_toolinput"))
            },
            "silent_deviation": sum(1 for r in valid if not r["utility_success"]
                                    and not r["truth"] and not r["detectors"]["extended_toolinput"]),
            "deviation_rows": sum(1 for r in valid if not r["utility_success"]),
        }

    def read_llm(path: Path | None) -> list[dict] | None:
        if not path or not path.exists():
            return None
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    primary = read_llm(args.llm)
    if primary:
        report["llm"] = summarise_llm(primary)
        meta = args.llm.with_suffix(".meta.json")
        if meta.exists():
            report["llm"]["config"] = json.loads(meta.read_text(encoding="utf-8"))
        report["llm"]["per_model"] = {
            m: {"assigned": sum(1 for r in primary if r["model"] == m),
                "valid": sum(1 for r in primary if r["model"] == m and not r.get("error")),
                "utility": report["llm"]["utility"][m],
                "availability": report["llm"]["availability"][m]}
            for m in report["llm"]["models"]}
    local = read_llm(args.llm_local)
    if local:
        report["llm_local"] = summarise_llm(local)
        meta = args.llm_local.with_suffix(".meta.json")
        if meta.exists():
            report["llm_local"]["config"] = json.loads(meta.read_text(encoding="utf-8"))
        from collections import Counter as _Counter
        report["llm_local"]["per_model"] = {
            m: {"assigned": sum(1 for r in local if r["model"] == m),
                "valid": sum(1 for r in local if r["model"] == m and not r.get("error")),
                "utility": report["llm_local"]["utility"][m],
                "availability": report["llm_local"]["availability"][m],
                # An HTTP 400 means the runtime refused the tool-calling request
                # outright; that is an API capability limit, not a measurement
                # of how well the model fills arguments.  Keep them separable.
                "errors": dict(_Counter(_error_kind(r["error"])
                                        for r in local if r["model"] == m and r.get("error")))}
            for m in report["llm_local"]["models"]}

    if args.drift:
        report["drift"] = drift_report([p for p in args.drift if p.exists()])
    if args.real_mcp and args.real_mcp.exists():
        report["real_mcp"] = real_mcp_report(args.real_mcp)
    if args.holdout and args.holdout.exists():
        report["holdout"] = holdout_report(args.holdout)

    # Every row this study produced, and every place a subset rather than the
    # whole was used.  A reader should not have to reconstruct which denominator
    # a number came from, and "nothing was dropped" is itself a claim that has
    # to be checked rather than assumed.
    report["exclusions"] = [
        {"suite": "본 행렬", "produced": len(rows), "used": len(rows),
         "excluded": 0, "reason": "실패·타임아웃 없음. 전 행이 분석에 들어간다"},
        {"suite": "본 행렬 → 그룹별 표", "produced": len(rows), "used": len(independent),
         "excluded": len(self_report),
         "reason": "자기보고 관측면은 5.1 절제에서만 쓴다. 제외가 아니라 관측면 분리"},
        {"suite": "본 행렬 → FPR", "produced": report["benign_independent"],
         "used": report["sample_decomposition"]["benign_excl_resubmit"],
         "excluded": (report["benign_independent"]
                      - report["sample_decomposition"]["benign_excl_resubmit"]),
         "reason": "승인된 재제출은 숨은 복제와 관측이 같다. 포함·제외 두 값을 모두 보고한다"},
    ]
    if "holdout" in report:
        hold = report["holdout"]
        report["exclusions"].append({
            "suite": "hold-out", "produced": hold["rows"], "used": hold["independent"],
            "excluded": hold["rows"] - hold["independent"],
            "reason": "본 행렬과 같은 관측면 분리"})
        meta = hold.get("meta", {})
        published = sum(p["published_tools"] for p in meta.get("provenance", []))
        kept = sum(p["kept"] for p in meta.get("provenance", []))
        report["exclusions"].append({
            "suite": "hold-out 도구", "produced": published, "used": kept,
            "excluded": published - kept,
            "reason": "required 속성이 없는 도구는 계약을 유도할 수 없어 변환 규칙 1에서 제외"})
    if "real_mcp" in report:
        real = report["real_mcp"]
        report["exclusions"].append({
            "suite": "공식 SDK", "produced": real["rows"], "used": real["clean_rows"],
            "excluded": real["rows"] - real["clean_rows"],
            "reason": "장애 주입 행은 탐지율이 아니라 부록 10.1의 가용성 분리에만 쓴다"})
    if "llm_local" in report:
        llm = report["llm_local"]
        report["exclusions"].append({
            "suite": "에이전트 루프", "produced": llm["rows"], "used": llm["valid"],
            "excluded": llm["errors"],
            "reason": "도구 호출이 정확히 하나이고 배정 도구와 같을 때만 유효. "
                      "오류 내역: " + ", ".join(f"{k} {v}" for k, v in
                                              list(llm["error_kinds"].items())[:3])})
    report["gates"] = evaluate_gates(report)
    problems = check_consistency(report)
    report["consistency"] = {"checked": True, "problems": problems}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" so the artifact is byte-identical across operating systems;
    # a Windows default of os.linesep would change every recorded digest.
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8", newline="\n")
    print(json.dumps({k: report[k] for k in ("rows", "conditions", "sample_decomposition",
                                             "attacks_independent", "benign_independent",
                                             "latency_ms")}, ensure_ascii=False, indent=1))
    for gate in report["gates"]:
        shown = " / ".join(f"{v:.3f}" for v in gate["observed"])
        print(f"  gate {gate['verdict']}  {gate['label']}: {shown}")
    if problems:
        print("\nCONSISTENCY FAILURES:")
        for problem in problems:
            print("  - " + problem)
        raise SystemExit(1)
    print("\nconsistency: all checks passed")


if __name__ == "__main__":
    main()
