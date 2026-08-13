from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def key(row: dict) -> tuple:
    return (row.get("model"), row.get("tool"), row.get("attack"), row.get("malicious_server"), row.get("variant"), row.get("repeat"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--expected-models", type=int, default=10)
    parser.add_argument("--expected-per-model", type=int, default=972)
    args = parser.parse_args()
    rows = [json.loads(line) for path in args.inputs for line in path.read_text().splitlines() if line.strip()]
    counts = Counter(key(row) for row in rows)
    by_model = defaultdict(list)
    for row in rows:
        by_model[row.get("model")].append(row)
    problems = []
    if len(by_model) != args.expected_models:
        problems.append(f"models={len(by_model)} expected={args.expected_models}")
    for model, model_rows in sorted(by_model.items()):
        if len(model_rows) != args.expected_per_model:
            problems.append(f"{model}: rows={len(model_rows)} expected={args.expected_per_model}")
    duplicates = [item for item, count in counts.items() if count != 1]
    if duplicates:
        problems.append(f"duplicate_keys={len(duplicates)}")
    hashes = {row.get("manifest_sha256") for row in rows if not row.get("error")}
    if len(hashes) != 1:
        problems.append(f"manifest_hashes={len(hashes)}")
    errors = sum(bool(row.get("error")) for row in rows)
    result = {"rows": len(rows), "models": len(by_model), "by_model": {k: len(v) for k, v in sorted(by_model.items())}, "duplicate_keys": len(duplicates), "manifest_hashes": sorted(hashes), "errors": errors, "problems": problems}
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    raise SystemExit(1 if problems else 0)


if __name__ == "__main__":
    main()
