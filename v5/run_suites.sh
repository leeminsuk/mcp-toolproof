#!/usr/bin/env bash
# Regenerate every deterministic v5 artifact on the local machine.
# The agent-loop layer is separate (run_local_llm.sh) because it needs a model
# runtime; everything here is pure local HTTP and needs no GPU.
set -euo pipefail
cd "$(dirname "$0")"
ART=../artifacts/v5

echo "=== main matrix (13,824 rows) ==="
python3 harness.py --seeds 3 --calls 12 --out "$ART/main-suite.jsonl"

# Provider-side drift: benign traffic only, so every alarm is a false positive.
# "none" is the same-code baseline, so the drift columns are read as a delta
# against it rather than against the main matrix.
for kind in none receipt_annotation normalisation_upgrade unicode_nfc hash_basis_change; do
  echo "=== drift: $kind ==="
  python3 harness.py --seeds 3 --calls 12 --benign-only --drift "$kind" \
    --out "$ART/drift-$kind.jsonl"
done

echo "=== done ==="
wc -l "$ART"/main-suite.jsonl "$ART"/drift-*.jsonl
