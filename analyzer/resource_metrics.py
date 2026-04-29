#!/usr/bin/env python3
"""
Resource metrics: parse resource_*.csv and collect live docker stats.

Refactored from scripts/collect_metrics.sh and parse_results.py.
"""

from __future__ import annotations

import csv
import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class ResourceStats:
    avg_cpu_percent: float = 0.0
    avg_mem_percent: float = 0.0
    samples: int = 0


def parse_resource_csv(path: Path) -> ResourceStats:
    """Parse a resource_*.csv file and return averaged CPU/memory stats."""
    if not path.exists():
        log.warning("[resource] CSV not found: %s", path)
        return ResourceStats()

    cpu_vals, mem_vals = [], []
    with path.open("r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                cpu_vals.append(float(row["cpu_percent"].replace("%", "")))
                mem_vals.append(float(row["mem_percent"].replace("%", "")))
            except (KeyError, ValueError):
                continue

    if not cpu_vals:
        return ResourceStats()

    stats = ResourceStats(
        avg_cpu_percent=round(sum(cpu_vals) / len(cpu_vals), 2),
        avg_mem_percent=round(sum(mem_vals) / len(mem_vals), 2),
        samples=len(cpu_vals),
    )
    log.debug("[resource] %s → cpu=%.2f%% mem=%.2f%%", path.name, stats.avg_cpu_percent, stats.avg_mem_percent)
    return stats


def collect_docker_stats(
    mode: str,
    output: Path,
    samples: int = 8,
    interval: float = 2.0,
) -> Path:
    """
    Collect docker stats snapshots and write to a CSV file.

    Args:
        mode:     Benchmark mode label (baseline/fail2ban/crowdsec).
        output:   Path to write the CSV.
        samples:  Number of snapshots to collect.
        interval: Seconds between snapshots.

    Returns:
        Path to the written CSV file.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []

    log.info("[resource] Collecting %d docker stats samples for mode=%s", samples, mode)

    for _ in range(samples):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        try:
            res = subprocess.run(
                ["docker", "stats", "--no-stream", "--format",
                 "{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}}"],
                capture_output=True, text=True, check=False,
            )
            for line in res.stdout.splitlines():
                parts = line.strip().split(",")
                if len(parts) >= 4:
                    rows.append({
                        "timestamp": ts,
                        "container": parts[0],
                        "cpu_percent": parts[1],
                        "mem_usage": parts[2],
                        "mem_percent": parts[3],
                    })
        except FileNotFoundError:
            log.warning("[resource] docker not found; skipping stats collection")
            break
        time.sleep(interval)

    with output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "container", "cpu_percent", "mem_usage", "mem_percent"])
        writer.writeheader()
        writer.writerows(rows)

    log.info("[resource] Saved %d rows to %s", len(rows), output)
    return output
