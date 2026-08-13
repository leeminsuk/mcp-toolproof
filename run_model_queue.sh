#!/usr/bin/env bash
set -u

endpoint="$1"
models_dir="$2"
first_model="$3"
shift 3
root="$(cd "$(dirname "$0")" && pwd)"
cd "$root"
mkdir -p artifacts/raw artifacts/smoke runtime/logs

safe_name() { printf '%s' "$1" | tr ':/' '--'; }
installed() {
  OLLAMA_HOST="${endpoint#http://}" OLLAMA_MODELS="$models_dir" \
    ./runtime/bin/ollama list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Fxq "$1"
}
wait_for_model() {
  local model="$1" waited=0
  while ! installed "$model"; do
    if (( waited >= 7200 )); then
      echo "SKIP_NOT_INSTALLED $model"; return 1
    fi
    sleep 30; waited=$((waited + 30))
  done
}
wait_for_run() {
  local model="$1"
  while pgrep -f "python3 run_gpu.py --model ${model} --endpoint ${endpoint}" >/dev/null; do sleep 30; done
}

wait_for_run "$first_model"
for model in "$@"; do
  wait_for_model "$model" || continue
  safe="$(safe_name "$model")"
  smoke="artifacts/smoke/${safe}.jsonl"
  rm -f "$smoke"
  echo "SMOKE_START $model"
  python3 run_gpu.py --model "$model" --endpoint "$endpoint" --output "$smoke" --smoke
  if ! python3 - "$smoke" <<'PY'
import json, sys
rows=[json.loads(x) for x in open(sys.argv[1], encoding="utf-8")]
raise SystemExit(0 if len(rows)==12 and not any(r.get("error") for r in rows) else 1)
PY
  then
    echo "SMOKE_FAIL $model"; continue
  fi
  echo "RUN_START $model"
  python3 run_gpu.py --model "$model" --endpoint "$endpoint" \
    --output "artifacts/raw/gpu-${safe}.jsonl" > "runtime/logs/run-${safe}.log" 2>&1
  echo "RUN_DONE $model"
done
