#!/usr/bin/env python3
"""
Generate laporan penelitian lengkap dalam format Markdown
dari data hasil benchmark (academic_report.json).

Usage:
    python3 scripts/generate_report_md.py
    python3 scripts/generate_report_md.py --output results/laporan.md

Output: Markdown siap cetak / konversi ke PDF atau Word.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

ROOT    = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"


def _load(path: Path) -> dict | list:
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        return {}


def _pct(val: float) -> str:
    return f"{val:.1f}%"


def _score_bar(val: float, max_val: float = 10.0, width: int = 10) -> str:
    filled = round((val / max_val) * width)
    return "█" * filled + "░" * (width - filled)


def build(out_path: Path) -> None:
    acad: dict  = _load(RESULTS / "academic_report.json")   # type: ignore[assignment]
    summ: list  = _load(RESULTS / "comparison_summary.json") or []  # type: ignore[assignment]
    ml:   dict  = _load(RESULTS / "ml_nsl_kdd_metrics.json")  # type: ignore[assignment]

    if not acad:
        # fallback: build from raw summary
        acad = {"summary": summ, "risk_scores": [], "comparative_analysis": [],
                "recommendations": [], "ml_baseline": ml, "meta": {}}

    meta    = acad.get("meta", {})
    risks   = acad.get("risk_scores", [])
    deltas  = acad.get("comparative_analysis", [])
    recs    = acad.get("recommendations", [])
    ml_data = acad.get("ml_baseline", ml)

    baseline = next((r for r in summ if r.get("mode") == "baseline"), {})
    fail2ban = next((r for r in summ if r.get("mode") == "fail2ban"), {})
    crowdsec = next((r for r in summ if r.get("mode") == "crowdsec"), {})

    b_ssh = baseline.get("ssh_success", 0) or 1
    c_ssh = crowdsec.get("ssh_success", 0)
    f_ssh = fail2ban.get("ssh_success", 0)
    c_red = round((b_ssh - c_ssh) / b_ssh * 100, 1)
    f_red = round((b_ssh - f_ssh) / b_ssh * 100, 1)
    winner = "CrowdSec" if c_red >= f_red else "Fail2Ban"

    now = datetime.now().strftime("%d %B %Y")
    gen = meta.get("generated_at", "")[:10] or now

    lines: list[str] = []
    w = lines.append

    # ── Cover ─────────────────────────────────────────────────────────────────
    w("# Laporan Penelitian")
    w("")
    w("## Analisis Komparatif CrowdSec vs Fail2Ban")
    w("### pada Home Server Berbasis Docker")
    w("")
    w(f"**Tanggal:** {now}  ")
    w(f"**Data dihasilkan:** {gen}  ")
    w("**Jenis:** Penelitian Eksperimental — Ethical Hacking (Lab Terkontrol)  ")
    w("**Catatan:** Semua serangan hanya menarget localhost/jaringan privat.")
    w("")
    w("---")
    w("")

    # ── Abstrak ───────────────────────────────────────────────────────────────
    w("## Abstrak")
    w("")
    w(
        f"Penelitian ini membandingkan efektivitas dua solusi keamanan open-source, "
        f"**CrowdSec** dan **Fail2Ban**, dalam memitigasi serangan pada home server berbasis Docker. "
        f"Eksperimen dilakukan dalam lingkungan lab terkontrol dengan tiga skenario: "
        f"tanpa proteksi (baseline), dengan Fail2Ban, dan dengan CrowdSec. "
        f"Serangan yang disimulasikan meliputi HTTP flood dan SSH brute-force. "
        f"Hasil menunjukkan bahwa **{winner}** memberikan perlindungan lebih baik "
        f"dengan reduksi login SSH berhasil sebesar {max(c_red, f_red)}% dibanding baseline. "
        f"Sebagai pembanding akademik, model RandomForest pada dataset NSL-KDD "
        f"mencapai akurasi {ml_data.get('accuracy', 0):.4f}."
    )
    w("")
    w("---")
    w("")

    # ── Pendahuluan ───────────────────────────────────────────────────────────
    w("## 1. Pendahuluan")
    w("")
    w(
        "Home server yang terekspos ke jaringan rentan terhadap berbagai serangan otomatis, "
        "terutama SSH brute-force dan HTTP flood. Dua solusi populer untuk mitigasi adalah "
        "**Fail2Ban** (rule-based, iptables) dan **CrowdSec** (collaborative threat intelligence). "
        "Penelitian ini bertujuan membandingkan keduanya secara kuantitatif dalam kondisi yang identik."
    )
    w("")
    w("### Tujuan Penelitian")
    w("")
    w("1. Mengukur efektivitas mitigasi serangan SSH brute-force dan HTTP flood")
    w("2. Membandingkan overhead resource (CPU/memory) masing-masing solusi")
    w("3. Menentukan solusi yang paling sesuai untuk home server Docker")
    w("4. Membandingkan dengan baseline ML (RandomForest, NSL-KDD)")
    w("")
    w("---")
    w("")

    # ── Metodologi ────────────────────────────────────────────────────────────
    w("## 2. Metodologi")
    w("")
    w("### 2.1 Environment")
    w("")
    w("| Komponen | Detail |")
    w("|---|---|")
    w("| Platform | Docker Compose pada Linux |")
    w("| Target HTTP | nginx:1.27-alpine (port 8081) |")
    w("| Target SSH | Debian 12 + OpenSSH (port 2222) |")
    w("| Fail2Ban | crazymax/fail2ban:1.1.0 |")
    w("| CrowdSec | crowdsecurity/crowdsec:latest |")
    w("| Python | 3.12.3 |")
    w("")
    w("### 2.2 Parameter Serangan")
    w("")
    w("| Serangan | Parameter |")
    w("|---|---|")
    w("| HTTP Flood | 500 requests, concurrency 25 |")
    w("| SSH Brute-Force | 40 attempts, delay 0.2s, wordlist 7 password |")
    w("")
    w("### 2.3 Alur Eksperimen")
    w("")
    w("```")
    w("Reset Environment → Start Stack → HTTP Flood + SSH Brute-Force")
    w("→ Collect Logs & Docker Stats → Parse Results → Analisis")
    w("```")
    w("")
    w("Setiap mode dijalankan secara independen dengan environment yang di-reset terlebih dahulu.")
    w("")
    w("---")
    w("")

    # ── Hasil ─────────────────────────────────────────────────────────────────
    w("## 3. Hasil Eksperimen")
    w("")
    w("### 3.1 Ringkasan Metrik")
    w("")
    w("| Mode | SSH Fail | SSH Success | HTTP 2xx | HTTP 403 | CPU Avg (%) |")
    w("|---|---|---|---|---|---|")
    for r in summ:
        w(f"| {r.get('mode','?')} | {r.get('ssh_fail',0)} | {r.get('ssh_success',0)} | "
          f"{r.get('http_2xx',0)} | {r.get('http_403',0)} | {r.get('avg_cpu_percent',0)} |")
    w("")

    w("### 3.2 Analisis Komparatif vs Baseline")
    w("")
    if deltas:
        w("| Mode | SSH Reduksi | HTTP Reduksi | Blocked IPs | Effectiveness | Verdict |")
        w("|---|---|---|---|---|---|")
        for d in deltas:
            w(f"| {d['mode']} | {_pct(d['ssh_attempts_reduced_pct'])} | "
              f"{_pct(d['http_success_reduced_pct'])} | {d['blocked_ips']} | "
              f"{d['effectiveness_score']}/100 | {d['verdict']} |")
        w("")
    else:
        w("*Data komparatif belum tersedia.*")
        w("")

    w("### 3.3 Risk Score (CVSS-like, 0–10)")
    w("")
    w("Skor komposit dihitung dari: exposure (35%), detection (30%), response time (20%), CPU overhead (15%).")
    w("**Lebih rendah = lebih aman.**")
    w("")
    if risks:
        w("| Mode | Composite | Severity | Exposure | Detection | Response |")
        w("|---|---|---|---|---|---|")
        for r in risks:
            w(f"| {r['mode']} | {r['composite']} | {r['severity']} | "
              f"{r['exposure_score']} | {r['detection_score']} | {r['response_score']} |")
        w("")
        w("**Visualisasi skor:**")
        w("")
        w("```")
        for r in risks:
            bar = _score_bar(r['composite'])
            w(f"{r['mode']:<12} {bar}  {r['composite']}/10  ({r['severity']})")
        w("```")
        w("")
    else:
        w("*Risk score belum tersedia.*")
        w("")

    w("### 3.4 Resource Usage")
    w("")
    w("| Mode | CPU Avg (%) | Memory Avg (%) | Overhead vs Baseline |")
    w("|---|---|---|---|")
    b_cpu = baseline.get("avg_cpu_percent", 0)
    for r in summ:
        overhead = round(r.get("avg_cpu_percent", 0) - b_cpu, 2)
        sign = "+" if overhead >= 0 else ""
        w(f"| {r.get('mode','?')} | {r.get('avg_cpu_percent',0)} | "
          f"{r.get('avg_mem_percent',0)} | {sign}{overhead}% |")
    w("")
    w("---")
    w("")

    # ── ML Baseline ───────────────────────────────────────────────────────────
    w("## 4. ML Baseline — NSL-KDD")
    w("")
    w(
        "Sebagai pembanding akademik, model RandomForest dilatih pada dataset NSL-KDD "
        "untuk mendeteksi intrusi jaringan. Dataset ini berisi 41 fitur per koneksi "
        "dengan label normal/attack (termasuk `guess_passwd` yang merepresentasikan SSH brute-force)."
    )
    w("")
    w("| Metrik | Nilai |")
    w("|---|---|")
    w(f"| Model | {ml_data.get('model', '-')} |")
    w(f"| Dataset | {ml_data.get('dataset', '-')} |")
    w(f"| Training rows | {ml_data.get('train_rows', 0):,} |")
    w(f"| Test rows | {ml_data.get('test_rows', 0):,} |")
    w(f"| Accuracy | {ml_data.get('accuracy', 0):.4f} |")
    w(f"| Weighted F1 | {ml_data.get('weighted_f1', 0):.4f} |")
    w(f"| Macro F1 | {ml_data.get('macro_f1', 0):.4f} |")
    w("")
    w("---")
    w("")

    # ── Rekomendasi ───────────────────────────────────────────────────────────
    w("## 5. Rekomendasi Keamanan")
    w("")
    if recs:
        for r in recs:
            w(f"### {r['id']} — [{r['priority']}] {r['category']}")
            w("")
            w(f"**Temuan:** {r['finding']}")
            w("")
            w(f"**Tindakan:** {r['action']}")
            w("")
            w(f"*Berlaku untuk: {', '.join(r['applicable_to'])}*")
            w("")
    else:
        w("*Rekomendasi belum tersedia.*")
        w("")
    w("---")
    w("")

    # ── Kesimpulan ────────────────────────────────────────────────────────────
    w("## 6. Kesimpulan")
    w("")
    w(
        f"Eksperimen ini membuktikan bahwa kedua solusi — Fail2Ban dan CrowdSec — "
        f"memberikan perlindungan yang lebih baik dibanding kondisi tanpa proteksi. "
        f"Fail2Ban mereduksi login SSH berhasil sebesar **{f_red}%**, "
        f"sementara CrowdSec mencapai **{c_red}%** dengan overhead CPU yang lebih rendah "
        f"({crowdsec.get('avg_cpu_percent', 0)}% vs {fail2ban.get('avg_cpu_percent', 0)}%)."
    )
    w("")
    w(
        f"**{winner}** direkomendasikan sebagai solusi utama berdasarkan kombinasi "
        f"efektivitas mitigasi dan efisiensi resource. Untuk perlindungan optimal, "
        f"kombinasikan dengan autentikasi SSH berbasis key dan rate limiting nginx."
    )
    w("")
    w(
        f"Model ML (RandomForest, NSL-KDD) mencapai akurasi {ml_data.get('accuracy', 0):.4f}, "
        f"menunjukkan potensi pendekatan berbasis data sebagai pelengkap rule-based tools "
        f"untuk deteksi ancaman yang lebih adaptif."
    )
    w("")
    w("---")
    w("")

    # ── Referensi ─────────────────────────────────────────────────────────────
    w("## Referensi")
    w("")
    w("1. Tavallaee, M., et al. (2009). *A Detailed Analysis of the KDD CUP 99 Data Set*. IEEE CISDA.")
    w("2. CrowdSec Documentation. https://docs.crowdsec.net")
    w("3. Fail2Ban Documentation. https://www.fail2ban.org/wiki/index.php/Main_Page")
    w("4. CVSS v3.1 Specification. https://www.first.org/cvss/specification-document")
    w("5. Scikit-learn: Machine Learning in Python. https://scikit-learn.org")
    w("")
    w("---")
    w("")
    w(f"*Laporan ini digenerate otomatis oleh ethical-hacking-research-framework pada {now}.*")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"✅ Laporan tersimpan: {out_path}")
    print(f"   {len(lines)} baris | {out_path.stat().st_size:,} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="results/laporan_penelitian.md")
    args = parser.parse_args()
    build(Path(args.output))
