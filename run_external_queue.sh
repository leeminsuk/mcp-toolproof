#!/usr/bin/env bash
set -u
endpoint="$1"; shift
mkdir -p artifacts/external-holdout runtime/logs
for model in "$@"; do
  safe="${model//:/-}"; pids=(); failed=0
  echo "EXTERNAL_START $model"
  for shard in $(seq 0 11); do
    python3 run_external_holdout_gpu.py --model "$model" --endpoint "$endpoint" \
      --schemas artifacts/external-holdout/official-tools.json --shard-count 12 --shard-index "$shard" \
      --output "artifacts/external-holdout/${safe}-s${shard}.jsonl" \
      > "runtime/logs/external-${safe}-s${shard}.log" 2>&1 &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
  if (( failed )); then echo "EXTERNAL_FAIL $model"; else echo "EXTERNAL_DONE $model"; fi
done
