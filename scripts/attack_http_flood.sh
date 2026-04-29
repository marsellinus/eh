#!/usr/bin/env bash
set -euo pipefail

TARGET_URL="${1:-http://127.0.0.1:8081/}"
REQUESTS="${2:-600}"
CONCURRENCY="${3:-30}"
OUT_FILE="${4:-results/attack_http.log}"

mkdir -p "$(dirname "$OUT_FILE")"

echo "target=$TARGET_URL requests=$REQUESTS concurrency=$CONCURRENCY" | tee -a "$OUT_FILE"

if command -v ab >/dev/null 2>&1; then
  # ApacheBench memberi statistik throughput yang konsisten untuk eksperimen.
  ab -n "$REQUESTS" -c "$CONCURRENCY" "$TARGET_URL" | tee -a "$OUT_FILE"
else
  echo "ab tidak tersedia, fallback ke curl loop" | tee -a "$OUT_FILE"
  for i in $(seq 1 "$REQUESTS"); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET_URL" || true)
    echo "request=$i status=$code" >> "$OUT_FILE"
  done
fi
