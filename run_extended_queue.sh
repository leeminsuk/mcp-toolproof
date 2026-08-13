#!/usr/bin/env bash
set -u
endpoint="$1"; shift
root="$(cd "$(dirname "$0")" && pwd)"; cd "$root"
mkdir -p artifacts/extended runtime/logs
safe_name() { printf '%s' "$1" | tr ':/' '--'; }
for model in "$@"; do
  safe="$(safe_name "$model")"; echo "EXTENDED_START $model"
  pids=(); failed=0
  for shard in $(seq 0 11); do
    python3 run_gpu.py --model "$model" --endpoint "$endpoint" --extended \
      --shard-count 12 --shard-index "$shard" \
      --output "artifacts/extended/gpu-${safe}-s${shard}.jsonl" \
      > "runtime/logs/extended-${safe}-s${shard}.log" 2>&1 &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
  if (( failed )); then echo "EXTENDED_FAIL $model"; else echo "EXTENDED_DONE $model"; fi
done
