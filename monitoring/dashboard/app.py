#!/usr/bin/env python3
"""Security Lab Dashboard — full control panel."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory

app = Flask(__name__)

# ── Root resolution ───────────────────────────────────────────────────────────

def _find_root() -> Path:
    env = os.environ.get("DASHBOARD_ROOT")
    if env:
        p = Path(env).expanduser().resolve()
        if p.exists():
            return p
    for parent in Path(__file__).resolve().parents:
        if (parent / "docker-compose.yml").exists():
            return parent
    return Path.cwd().resolve()

ROOT    = _find_root()
RESULTS = ROOT / "results"
CHARTS  = RESULTS / "charts"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── Job state ─────────────────────────────────────────────────────────────────

_lock = threading.Lock()
_job: dict = {
    "running": False, "action": None, "log": "",
    "returncode": None, "started_at": None, "finished_at": None,
}

ACTIONS: dict[str, list[str] | None] = {
    "reset":          ["bash", "scripts/reset_environment.sh"],
    "start_baseline": None,
    "start_fail2ban": None,
    "start_crowdsec": None,
    "stop":           None,
    "run_benchmark":  ["python3", "main.py", "--modes", "baseline", "fail2ban", "crowdsec"],
    "run_baseline":   ["python3", "main.py", "--modes", "baseline"],
    "run_fail2ban":   ["python3", "main.py", "--modes", "fail2ban"],
    "run_crowdsec":   ["python3", "main.py", "--modes", "crowdsec"],
    "parse":          ["python3", "main.py", "--parse-only"],
    "report":         ["python3", "main.py", "--report-only"],
    "ml_nsl_kdd":     ["python3", "main.py", "--ml-only", "--dataset", "nsl_kdd"],
    "ml_cicids":      ["python3", "main.py", "--ml-only", "--dataset", "cicids"],
    "ml_custom":      ["python3", "main.py", "--ml-only", "--dataset", "custom"],
    "fetch_nsl_kdd":  ["python3", "scripts/fetch_external_datasets.py", "--dataset", "nsl_kdd"],
    "fetch_cicids":   ["python3", "scripts/fetch_external_datasets.py", "--dataset", "cicids"],
}

ACTION_LABELS = {
    "reset":          "Reset Environment",
    "start_baseline": "Start Baseline Stack",
    "start_fail2ban": "Start Fail2Ban Stack",
    "start_crowdsec": "Start CrowdSec Stack",
    "stop":           "Stop All Stacks",
    "run_benchmark":  "Run Full Benchmark",
    "run_baseline":   "Run Baseline Only",
    "run_fail2ban":   "Run Fail2Ban Only",
    "run_crowdsec":   "Run CrowdSec Only",
    "parse":          "Parse Results",
    "report":         "Build Academic Report",
    "ml_nsl_kdd":     "ML — NSL-KDD",
    "ml_cicids":      "ML — CICIDS2017",
    "ml_custom":      "ML — Custom Log",
    "fetch_nsl_kdd":  "Fetch NSL-KDD",
    "fetch_cicids":   "Fetch CICIDS2017",
}

# ── Docker helpers ────────────────────────────────────────────────────────────

def _compose() -> list[str]:
    if shutil.which("docker"):
        r = subprocess.run(["docker", "compose", "version"], capture_output=True, check=False)
        if r.returncode == 0:
            return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    raise RuntimeError("docker compose not found")

def _cmd_for(action: str) -> list[str]:
    cmd = ACTIONS.get(action)
    if cmd is not None:
        return cmd
    c = _compose()
    if action == "start_baseline":
        return [*c, "up", "-d", "--build"]
    if action == "start_fail2ban":
        return [*c, "-f", "docker-compose.yml", "-f", "docker-compose.fail2ban.yml", "up", "-d", "--build"]
    if action == "start_crowdsec":
        return [*c, "-f", "docker-compose.yml", "-f", "docker-compose.crowdsec.yml", "up", "-d", "--build"]
    if action == "stop":
        return [*c, "down", "-v", "--remove-orphans"]
    raise ValueError(f"No command for action: {action}")

def _run_bg(action: str) -> None:
    cmd = _cmd_for(action)
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    with _lock:
        _job.update(running=True, action=action, log=f"$ {' '.join(cmd)}\n",
                    returncode=None, started_at=datetime.now(timezone.utc).isoformat(),
                    finished_at=None)
    try:
        proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, env=env)
        assert proc.stdout
        for line in proc.stdout:
            with _lock:
                _job["log"] = (_job["log"] + line)[-20_000:]
        proc.wait()
        code = proc.returncode
    except Exception as e:
        code = 1
        with _lock:
            _job["log"] += f"\nERROR: {e}\n"
    with _lock:
        _job.update(running=False, returncode=code,
                    finished_at=datetime.now(timezone.utc).isoformat())

# ── Data helpers ──────────────────────────────────────────────────────────────

def _read_json(path: Path) -> dict | list:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}

def _docker_containers() -> list[dict]:
    try:
        c = _compose()
        r = subprocess.run([*c, "ps", "--format", "json"], cwd=ROOT,
                           capture_output=True, text=True, check=False)
        raw = r.stdout.strip()
        if not raw:
            return []
        data = json.loads(raw) if raw.startswith("[") else [json.loads(l) for l in raw.splitlines() if l.strip()]
        return [{"name": d.get("Name", d.get("Service", "?")),
                 "state": d.get("State", "?"),
                 "status": d.get("Status", "?")} for d in data]
    except Exception:
        return []

def _risk_scores(rows: list) -> list:
    try:
        from report.risk_scorer import score_all
        from dataclasses import asdict
        return [asdict(s) for s in score_all(rows)]
    except Exception:
        return []

def _deltas(rows: list) -> list:
    try:
        from report.comparator import compare, comparison_table
        return comparison_table(compare(rows))
    except Exception:
        return []

def _recs(rows: list, deltas: list, risks: list) -> list:
    try:
        from report.recommendations import generate, recommendations_to_dicts
        return recommendations_to_dicts(generate(rows, deltas, risks))
    except Exception:
        return []

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/favicon.ico")
def favicon():
    return "", 204

@app.get("/")
def index():
    return render_template("index.html", action_labels=ACTION_LABELS)

@app.get("/api/data")
def api_data():
    summary: list = _read_json(RESULTS / "comparison_summary.json") or []  # type: ignore[assignment]
    risks   = _risk_scores(summary)
    deltas  = _deltas(summary)
    recs    = _recs(summary, deltas, risks)
    charts  = [f.name for f in sorted(CHARTS.glob("*.png"))] if CHARTS.exists() else []
    with _lock:
        job = dict(_job)
    return jsonify({
        "summary":    summary,
        "risks":      risks,
        "deltas":     deltas,
        "recs":       recs,
        "charts":     charts,
        "containers": _docker_containers(),
        "job":        job,
        "server_time": datetime.now(timezone.utc).isoformat(),
    })

@app.get("/api/ml-datasets")
def api_ml_datasets():
    """Return ML metrics for all available datasets."""
    datasets = {
        "nsl_kdd": RESULTS / "ml_nslkdd_metrics.json",
        "cicids":  RESULTS / "ml_cicids_metrics.json",
        "custom":  RESULTS / "ml_custom_metrics.json",
    }
    result = {k: _read_json(v) for k, v in datasets.items()}
    cicids_dir = ROOT / "datasets" / "external" / "cicids2017"
    if not result["cicids"]:
        has_csv = cicids_dir.exists() and any(cicids_dir.glob("*.csv"))
        result["cicids_status"] = "has_csv" if has_csv else "missing"
    return jsonify(result)

@app.get("/api/justify")
def api_justify():
    """Return attack parameter justification analysis."""
    try:
        from analyzer.attack_param_justifier import justify_attack_parameters
        return jsonify(justify_attack_parameters())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/conclusion")
def api_conclusion():
    summary: list = _read_json(RESULTS / "comparison_summary.json") or []  # type: ignore[assignment]
    ml: dict = _read_json(RESULTS / "ml_nslkdd_metrics.json")              # type: ignore[assignment]

    if not summary:
        return jsonify({"available": False,
                        "text": "Belum ada data benchmark. Jalankan benchmark terlebih dahulu."})

    baseline = next((r for r in summary if r["mode"] == "baseline"), {})
    fail2ban = next((r for r in summary if r["mode"] == "fail2ban"), {})
    crowdsec = next((r for r in summary if r["mode"] == "crowdsec"), {})

    b_ssh = baseline.get("ssh_success", 0) or 1
    f_ssh = fail2ban.get("ssh_success", 0) or 0
    c_ssh = crowdsec.get("ssh_success", 0) or 0
    f_red = round((b_ssh - f_ssh) / b_ssh * 100, 1)
    c_red = round((b_ssh - c_ssh) / b_ssh * 100, 1)
    f_cpu = fail2ban.get("avg_cpu_percent", 0)
    c_cpu = crowdsec.get("avg_cpu_percent", 0)
    winner = "CrowdSec" if c_red >= f_red else "Fail2Ban"

    paragraphs = [
        f"Eksperimen membandingkan tiga kondisi pada home server Docker: tanpa proteksi (baseline), "
        f"dilindungi Fail2Ban, dan dilindungi CrowdSec. Serangan yang disimulasikan adalah HTTP flood "
        f"ke port 8081 dan SSH brute-force ke port 2222.",
        f"Pada baseline, tercatat {baseline.get('ssh_success', 0)} login SSH berhasil dari "
        f"{baseline.get('ssh_fail', 0) + baseline.get('ssh_success', 0)} percobaan.",
        f"Fail2Ban mereduksi login SSH berhasil sebesar {f_red}% dengan CPU rata-rata {f_cpu}%.",
        f"CrowdSec mencapai reduksi {c_red}% dengan overhead CPU hanya {c_cpu}%.",
        f"Berdasarkan efektivitas dan efisiensi resource, <strong>{winner}</strong> menjadi pilihan unggul.",
    ]

    if ml and ml.get("accuracy"):
        paragraphs.append(
            f"Model RandomForest (NSL-KDD, {ml.get('train_rows', 0):,} baris) mencapai "
            f"akurasi {ml['accuracy']:.4f} dan weighted F1 {ml.get('weighted_f1', 0):.4f}."
        )

    return jsonify({"available": True, "paragraphs": paragraphs, "winner": winner})

@app.post("/api/run/<action>")
def api_run(action: str):
    if action not in ACTIONS and action not in ("start_baseline", "start_fail2ban", "start_crowdsec", "stop"):
        return jsonify({"ok": False, "error": "Unknown action"}), 404
    with _lock:
        if _job["running"]:
            return jsonify({"ok": False, "error": "Job sedang berjalan"}), 409
    threading.Thread(target=_run_bg, args=(action,), daemon=True).start()
    return jsonify({"ok": True})

@app.get("/api/job")
def api_job():
    with _lock:
        return jsonify(dict(_job))

@app.get("/charts/<filename>")
def serve_chart(filename: str):
    return send_from_directory(CHARTS, filename)

@app.get("/health")
def health():
    return "ok\n", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5050)), debug=False)
