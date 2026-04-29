#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-baseline}"
OUT="results/resource_${MODE}.csv"
SAMPLES="${2:-10}"
INTERVAL="${3:-2}"

mkdir -p results

echo "timestamp,container,cpu_percent,mem_usage,mem_percent" > "$OUT"
for _ in $(seq 1 "$SAMPLES"); do
  ts=$(date -Iseconds)
  docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}}' \
    | sed "s/^/${ts},/" >> "$OUT"
  sleep "$INTERVAL"
done

echo "saved: $OUT"
