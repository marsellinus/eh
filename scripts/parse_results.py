#!/usr/bin/env python3
"""Parser sederhana untuk membandingkan hasil baseline vs Fail2Ban vs CrowdSec."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
MODES = ["baseline", "fail2ban", "crowdsec"]


def parse_http_log(path: Path) -> dict:
    if not path.exists():
        return {"http_2xx": 0, "http_403": 0, "http_other": 0}

    text = path.read_text(encoding="utf-8", errors="ignore")
    success = len(re.findall(r"\\b2\\d\\d\\b", text))
    forbidden = len(re.findall(r"\\b403\\b", text))
    other = len(re.findall(r"\\b[145]\\d\\d\\b", text)) - forbidden
    return {"http_2xx": success, "http_403": forbidden, "http_other": max(other, 0)}


def parse_ssh_log(path: Path) -> dict:
    if not path.exists():
        return {"ssh_fail": 0, "ssh_success": 0}

    text = path.read_text(encoding="utf-8", errors="ignore")
    fail = len(re.findall(r"status=FAIL", text))
    ok = len(re.findall(r"status=SUCCESS", text))
    return {"ssh_fail": fail, "ssh_success": ok}


def parse_resource_csv(path: Path) -> dict:
    if not path.exists():
        return {"avg_cpu_percent": 0.0, "avg_mem_percent": 0.0}

    cpu_vals = []
    mem_vals = []

    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                cpu_vals.append(float(row["cpu_percent"].replace("%", "")))
                mem_vals.append(float(row["mem_percent"].replace("%", "")))
            except Exception:
                continue

    avg_cpu = sum(cpu_vals) / len(cpu_vals) if cpu_vals else 0.0
    avg_mem = sum(mem_vals) / len(mem_vals) if mem_vals else 0.0
    return {"avg_cpu_percent": round(avg_cpu, 2), "avg_mem_percent": round(avg_mem, 2)}


def parse_security_snapshot(path: Path) -> dict:
    if not path.exists():
        return {
            "detected_events": 0,
            "blocked_ips": 0,
            "detect_http_s": 0.0,
            "detect_ssh_s": 0.0,
            "raw": "",
        }

    data = json.loads(path.read_text(encoding="utf-8"))
    raw = data.get("fail2ban_status") or data.get("crowdsec_metrics") or ""

    blocked = 0
    if "Banned IP list" in raw:
        # fail2ban output: parse banned ip count from line content.
        m = re.search(r"Currently banned:\s*(\\d+)", raw)
        if m:
            blocked = int(m.group(1))
    else:
        # crowdsec metrics fallback.
        m = re.search(r"total decisions.*?(\\d+)", raw, flags=re.IGNORECASE)
        if m:
            blocked = int(m.group(1))

    events = len(re.findall(r"(failed|ban|decision|alert)", raw, flags=re.IGNORECASE))
    detection = data.get("detection_seconds", {})
    return {
        "detected_events": events,
        "blocked_ips": blocked,
        "detect_http_s": float(detection.get("http") or 0.0),
        "detect_ssh_s": float(detection.get("ssh") or 0.0),
        "raw": raw[:8000],
    }


def main():
    rows = []

    for mode in MODES:
        http = parse_http_log(RESULTS / f"attack_http_{mode}.log")
        ssh = parse_ssh_log(RESULTS / f"attack_ssh_{mode}.log")
        resource = parse_resource_csv(RESULTS / f"resource_{mode}.csv")
        sec = parse_security_snapshot(RESULTS / f"security_snapshot_{mode}.json")

        rows.append(
            {
                "mode": mode,
                **http,
                **ssh,
                **resource,
                "detected_events": sec["detected_events"],
                "blocked_ips": sec["blocked_ips"],
                "detect_http_s": sec["detect_http_s"],
                "detect_ssh_s": sec["detect_ssh_s"],
            }
        )

    out_json = RESULTS / "comparison_summary.json"
    out_csv = RESULTS / "comparison_summary.csv"

    out_json.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    with out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print("=== Ringkasan Komparatif ===")
    for row in rows:
        print(row)
    print(f"Tersimpan: {out_json}")
    print(f"Tersimpan: {out_csv}")


if __name__ == "__main__":
    main()
