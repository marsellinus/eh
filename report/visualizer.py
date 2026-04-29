#!/usr/bin/env python3
"""
Chart visualizer: generates PNG charts for academic reports and slides.

Produces 4 charts:
  1. SSH brute-force attempts per mode (bar)
  2. HTTP success rate per mode (bar)
  3. CPU overhead comparison (bar)
  4. Risk score radar / composite bar

All charts saved to results/charts/.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Use non-interactive backend — safe for headless/server environments
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

_COLORS = {"baseline": "#e74c3c", "fail2ban": "#3498db", "crowdsec": "#2ecc71"}
_DEFAULT_COLOR = "#95a5a6"


def _color(mode: str) -> str:
    return _COLORS.get(mode, _DEFAULT_COLOR)


def _save(fig: plt.Figure, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("[viz] Saved: %s", path)
    return path


def chart_ssh_attempts(rows: list[dict[str, Any]], out_dir: Path) -> Path:
    """Bar chart: SSH fail vs success per mode."""
    modes  = [r["mode"] for r in rows]
    fails  = [r.get("ssh_fail", 0) for r in rows]
    succs  = [r.get("ssh_success", 0) for r in rows]
    x = np.arange(len(modes))
    w = 0.35

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(x - w/2, fails, w, label="Failed attempts", color=[_color(m) for m in modes], alpha=0.85)
    ax.bar(x + w/2, succs, w, label="Successful logins", color=[_color(m) for m in modes], alpha=0.45, hatch="//")
    ax.set_xticks(x); ax.set_xticklabels([m.upper() for m in modes])
    ax.set_ylabel("SSH Attempts"); ax.set_title("SSH Brute-Force: Attempts per Mode")
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    return _save(fig, out_dir / "chart_ssh_attempts.png")


def chart_http_responses(rows: list[dict[str, Any]], out_dir: Path) -> Path:
    """Stacked bar: HTTP 2xx / 403 / other per mode."""
    modes  = [r["mode"] for r in rows]
    ok     = [r.get("http_2xx",   0) for r in rows]
    forb   = [r.get("http_403",   0) for r in rows]
    other  = [r.get("http_other", 0) for r in rows]
    x = np.arange(len(modes))

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(x, ok,    label="2xx Success",  color="#e74c3c", alpha=0.85)
    ax.bar(x, forb,  label="403 Blocked",  color="#2ecc71", alpha=0.85, bottom=ok)
    bot2 = [a + b for a, b in zip(ok, forb)]
    ax.bar(x, other, label="Other (4xx/5xx)", color="#95a5a6", alpha=0.6, bottom=bot2)
    ax.set_xticks(x); ax.set_xticklabels([m.upper() for m in modes])
    ax.set_ylabel("HTTP Requests"); ax.set_title("HTTP Flood: Response Distribution per Mode")
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    return _save(fig, out_dir / "chart_http_responses.png")


def chart_cpu_overhead(rows: list[dict[str, Any]], out_dir: Path) -> Path:
    """Horizontal bar: avg CPU % per mode."""
    modes = [r["mode"] for r in rows]
    cpus  = [r.get("avg_cpu_percent", 0.0) for r in rows]

    fig, ax = plt.subplots(figsize=(7, 3))
    bars = ax.barh([m.upper() for m in modes], cpus,
                   color=[_color(m) for m in modes], alpha=0.85)
    ax.bar_label(bars, fmt="%.2f%%", padding=3)
    ax.set_xlabel("Average CPU (%)"); ax.set_title("Resource Overhead: Avg CPU per Mode")
    ax.grid(axis="x", linestyle="--", alpha=0.4)
    fig.tight_layout()
    return _save(fig, out_dir / "chart_cpu_overhead.png")


def chart_risk_scores(risk_rows: list[dict[str, Any]], out_dir: Path) -> Path:
    """
    Grouped bar: exposure / detection / response / overhead sub-scores per mode.
    Lower composite = safer.
    """
    modes      = [r["mode"] for r in risk_rows]
    exposure   = [r["exposure_score"]   for r in risk_rows]
    detection  = [r["detection_score"]  for r in risk_rows]
    response   = [r["response_score"]   for r in risk_rows]
    composite  = [r["composite"]        for r in risk_rows]

    x = np.arange(len(modes))
    w = 0.2

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(x - w*1.5, exposure,  w, label="Exposure",   color="#e74c3c", alpha=0.85)
    ax.bar(x - w*0.5, detection, w, label="Detection",  color="#2ecc71", alpha=0.85)
    ax.bar(x + w*0.5, response,  w, label="Response",   color="#3498db", alpha=0.85)
    ax.bar(x + w*1.5, composite, w, label="Composite ↓",color="#8e44ad", alpha=0.85)

    ax.set_xticks(x); ax.set_xticklabels([m.upper() for m in modes])
    ax.set_ylim(0, 11); ax.set_ylabel("Score (0–10)")
    ax.set_title("Risk Score Breakdown per Mode  (Composite: lower = safer)")
    ax.axhline(y=5, color="gray", linestyle="--", alpha=0.5, label="Threshold (5)")
    ax.legend(fontsize=8)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    return _save(fig, out_dir / "chart_risk_scores.png")


def generate_all_charts(
    rows: list[dict[str, Any]],
    risk_rows: list[dict[str, Any]],
    out_dir: Path,
) -> list[Path]:
    """Generate all 4 charts and return their paths."""
    paths = [
        chart_ssh_attempts(rows, out_dir),
        chart_http_responses(rows, out_dir),
        chart_cpu_overhead(rows, out_dir),
        chart_risk_scores(risk_rows, out_dir),
    ]
    log.info("[viz] %d charts saved to %s", len(paths), out_dir)
    return paths
