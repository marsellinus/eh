# Analisis Komparatif CrowdSec vs Fail2Ban (Home Server Docker)

Proyek penelitian untuk membandingkan efektivitas **CrowdSec** dan **Fail2Ban** dalam memitigasi serangan pada layanan home server berbasis Docker.

> ⚠️ **Untuk keperluan akademik dan lab terkontrol saja. Semua serangan hanya menarget localhost/jaringan privat.**

---

## Fitur

- Simulasi serangan: HTTP flood dan SSH brute-force
- Tiga mode pengujian: baseline, Fail2Ban, CrowdSec
- Analisis komparatif otomatis (before vs after)
- Risk scoring berbasis CVSS-like (0–10)
- Visualisasi 4 chart PNG (matplotlib)
- Rekomendasi keamanan berbasis bukti
- ML baseline deteksi intrusi (RandomForest, NSL-KDD)
- 45 automated tests (pytest)

---

## Struktur Project

```
eh/
├── main.py                    # Controller utama (entry point)
├── scanner/                   # Port scan & service fingerprinting
├── exploit/                   # Simulasi serangan (HTTP flood, SSH brute)
├── analyzer/                  # Parser log, resource metrics, ML baseline
├── report/                    # Generator laporan, risk score, chart, rekomendasi
├── tests/                     # 45 automated tests
├── scripts/                   # Script legacy (benchmark, parse, reset)
├── docker-compose.yml         # Stack target (nginx:8081, ssh:2222)
├── docker-compose.fail2ban.yml
├── docker-compose.crowdsec.yml
├── datasets/external/         # NSL-KDD dataset
├── results/                   # Semua output (JSON, CSV, PNG)
├── .env                       # API keys (CROWDSEC_CTI_API_KEY, CROWDSEC_BOUNCER_API_KEY)
├── requirements.txt           # Dependensi core
└── requirements-ml.txt        # Dependensi ML (opsional)
```

---

## Prasyarat

- Python 3.10+
- Docker + Docker Compose v2
- `apache2-utils` (untuk `ab`, opsional — fallback ke curl)

---

## Setup

```bash
# 1. Masuk ke direktori project
cd eh

# 2. Buat virtualenv
python3 -m venv .venv && source .venv/bin/activate

# 3. Install dependensi core
pip install -r requirements.txt

# 4. (Opsional) Install dependensi ML
pip install -r requirements-ml.txt

# 5. Verifikasi — semua test harus pass
python3 -m pytest
# Expected: 45 passed
```

---

## Menjalankan Benchmark

### Tanpa Docker (analisis dari hasil yang sudah ada)

```bash
# Regenerasi laporan komparatif
python3 main.py --parse-only

# Buat laporan akademik lengkap (risk score + chart + rekomendasi)
python3 main.py --report-only

# ML baseline — NSL-KDD (default)
python3 scripts/fetch_external_datasets.py
python3 main.py --ml-only

# ML baseline — CICIDS2017 (lebih modern, HTTP flood & SSH brute-force)
python3 scripts/fetch_external_datasets.py --dataset cicids
python3 main.py --ml-only --dataset cicids

# ML baseline — Custom (dari log eksperimen sendiri, tanpa download)
python3 main.py --ml-only --dataset custom
```

### Dengan Docker — Baseline (~3 menit)

```bash
bash scripts/reset_environment.sh
python3 main.py --modes baseline --scan --report
```

### Dengan Docker — Fail2Ban (~5 menit)

```bash
bash scripts/reset_environment.sh
python3 main.py --modes fail2ban --report
```

### Dengan Docker — CrowdSec (~5 menit)

```bash
# 1. Jalankan stack CrowdSec
docker compose -f docker-compose.yml -f docker-compose.crowdsec.yml up -d --build

# 2. Generate bouncer key
docker exec sec-crowdsec cscli bouncers add docker-bouncer
# Salin key dari output, lalu:
export CROWDSEC_BOUNCER_API_KEY=<key>

# 3. Simpan ke .env agar persisten
echo "CROWDSEC_BOUNCER_API_KEY=<key>" >> .env

# 4. Restart stack agar key aktif
docker compose -f docker-compose.yml -f docker-compose.crowdsec.yml up -d

# 5. Jalankan
python3 main.py --modes crowdsec --report
```

### Benchmark Penuh — Semua Mode (~20 menit)

```bash
bash scripts/reset_environment.sh
python3 main.py --modes baseline fail2ban crowdsec --scan --report
```

---

## Semua Opsi CLI

```
python3 main.py [opsi]

--modes baseline fail2ban crowdsec   Mode yang dijalankan (default: semua)
--scan                               Port scan sebelum benchmark
--report                             Buat laporan akademik setelah benchmark
--scan-only                          Hanya port scan
--parse-only                         Hanya regenerasi comparison summary
--report-only                        Hanya buat laporan akademik
--ml-only                            Hanya jalankan ML baseline
--dataset nsl_kdd|cicids|custom      Dataset untuk ML baseline (default: nsl_kdd)
--debug                              Aktifkan debug logging
```

---

## Output

| File | Keterangan |
|---|---|
| `results/comparison_summary.json` | Ringkasan metrik semua mode |
| `results/comparison_summary.csv` | Versi CSV untuk spreadsheet |
| `results/academic_report.json` | Laporan lengkap (risk, delta, rekomendasi) |
| `results/ml_nsl_kdd_metrics.json` | Metrik model RandomForest (NSL-KDD) |
| `results/ml_cicids_metrics.json` | Metrik model RandomForest (CICIDS2017) |
| `results/ml_custom_metrics.json` | Metrik model RandomForest (log eksperimen) |
| `results/charts/chart_ssh_attempts.png` | SSH brute-force per mode |
| `results/charts/chart_http_responses.png` | HTTP response distribution |
| `results/charts/chart_cpu_overhead.png` | CPU overhead per mode |
| `results/charts/chart_risk_scores.png` | Risk score breakdown |
| `results/attack_http_*.log` | Log HTTP flood per mode |
| `results/attack_ssh_*.log` | Log SSH brute-force per mode |
| `results/resource_*.csv` | CPU/memory docker stats per mode |
| `results/security_snapshot_*.json` | Snapshot deteksi per mode |

---

## Web Dashboard

```bash
# Jalankan
docker compose --profile dashboard up -d --build dashboard

# Buka di browser
http://localhost:5050

# Matikan
docker compose --profile dashboard down
```

> ⚠️ Dashboard mount `/var/run/docker.sock`. Jangan expose ke internet publik.

---

## Environment Variables (`.env`)

| Variable | Keterangan |
|---|---|
| `CROWDSEC_CTI_API_KEY` | API key CrowdSec Threat Intelligence (opsional) |
| `CROWDSEC_BOUNCER_API_KEY` | Bouncer key untuk blocking IP (wajib untuk mode crowdsec) |

---

## Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Network (172.28.0.0/24)          │
│                                                             │
│  ┌──────────┐   HTTP flood    ┌─────────────────────────┐  │
│  │          │ ──────────────► │  nginx:8081             │  │
│  │ Attacker │                 │  (172.28.0.10)          │  │
│  │(localhost│   SSH brute     ├─────────────────────────┤  │
│  │          │ ──────────────► │  ssh-target:2222        │  │
│  └──────────┘                 │  (172.28.0.11)          │  │
│                               └────────────┬────────────┘  │
│                                            │ logs          │
│                               ┌────────────▼────────────┐  │
│                               │  Fail2Ban / CrowdSec    │  │
│                               │  (iptables / bouncer)   │  │
│                               └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Tiga mode pengujian:**

```
Mode 1 — Baseline  : nginx + ssh-target (tanpa proteksi)
Mode 2 — Fail2Ban  : nginx + ssh-target + fail2ban (rule-based, iptables)
Mode 3 — CrowdSec  : nginx + ssh-target + crowdsec + bouncer (threat intelligence)
```

## Metodologi

- **Detection time**: dihitung sejak serangan dimulai hingga IP pertama diblokir
- **Resource usage**: diambil dari `docker stats` selama serangan berlangsung
- **Effectiveness**: persentase reduksi serangan dibanding baseline

```
Effectiveness (%) = (baseline_attacks - mode_attacks) / baseline_attacks × 100
```

- **Risk score**: composite 0–10 berbasis CVSS-like

```
Risk Score = (0.35 × Exposure) + (0.30 × Detection) + (0.20 × Response) + (0.15 × CPU_Overhead)

  Exposure      = f(ssh_success, http_2xx)          → lebih banyak serangan lolos = lebih tinggi
  Detection     = f(detected_events)                → lebih banyak deteksi = lebih rendah (lebih aman)
  Response      = f(blocked_ips, detection_time)    → lebih cepat blokir = lebih rendah
  CPU_Overhead  = f(avg_cpu_percent)                → lebih tinggi CPU = lebih tinggi
```

- **ML baseline**: RandomForest tersedia dalam tiga mode dataset:
  - `nsl_kdd` — NSL-KDD klasik (125.973 train / 22.544 test rows)
  - `cicids` — CICIDS2017, mencakup HTTP flood & SSH brute-force (lebih relevan dengan eksperimen ini)
  - `custom` — Log eksperimen sendiri (`results/attack_*.log`), dilabeli otomatis berdasarkan mode dan respons

## Hasil Eksperimen (Ringkasan)

| Mode | SSH Success | HTTP 2xx | CPU Avg (%) | Risk Score |
|---|---|---|---|---|
| baseline | 28 | 4800 | 1.89 | 7.65 (HIGH) |
| fail2ban | 24 (−14.3%) | 3000 (−37.5%) | 6.70 | 7.69 (HIGH) |
| crowdsec | 18 (−35.7%) | 2402 (−50.0%) | 6.26 | 6.62 (HIGH) |

**Charts** (digenerate otomatis setelah benchmark):

| Chart | Path |
|---|---|
| SSH Attempts | `results/charts/chart_ssh_attempts.png` |
| HTTP Responses | `results/charts/chart_http_responses.png` |
| CPU Overhead | `results/charts/chart_cpu_overhead.png` |
| Risk Scores | `results/charts/chart_risk_scores.png` |

---

## Reproducibility

1. Gunakan environment yang sama untuk semua mode
2. Jalankan `bash scripts/reset_environment.sh` sebelum setiap mode
3. Parameter serangan konsisten: 500 HTTP requests, 40 SSH attempts
4. Semua hasil tersimpan di `results/` dengan nama file yang deterministik
