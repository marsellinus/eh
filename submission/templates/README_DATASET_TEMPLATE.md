# README Dataset / Experiment Evidence

## Ringkasan
Dokumen ini menjelaskan bukti eksperimen ethical hacking untuk studi komparatif CrowdSec vs Fail2Ban.

## Lingkungan Uji
- OS host:
- Docker version:
- Docker Compose version:
- Tanggal eksperimen:
- Konfigurasi hardware (CPU/RAM):

## Skenario Eksperimen
1. Baseline (tanpa proteksi)
2. Fail2Ban
3. CrowdSec

Serangan yang disimulasikan:
- HTTP flooding
- SSH brute force

## Struktur Evidence
- results/attack_http_baseline.log
- results/attack_http_fail2ban.log
- results/attack_http_crowdsec.log
- results/attack_ssh_baseline.log
- results/attack_ssh_fail2ban.log
- results/attack_ssh_crowdsec.log
- results/resource_baseline.csv
- results/resource_fail2ban.csv
- results/resource_crowdsec.csv
- results/security_snapshot_baseline.json
- results/security_snapshot_fail2ban.json
- results/security_snapshot_crowdsec.json
- results/comparison_summary.csv
- results/comparison_summary.json

## Cara Reproduksi
1. Install dependency Python: `pip install -r scripts/requirements.txt`
2. Reset environment: `bash scripts/reset_environment.sh`
3. Jalankan benchmark: `python3 scripts/benchmark.py`
4. Parsing hasil: `python3 scripts/parse_results.py`

## Integritas Data
- Data berasal dari eksperimen mandiri.
- Tidak ada modifikasi hasil di luar proses parsing otomatis.
- Timestamp dan log mentah disertakan sebagai bukti.

## Lisensi dan Etika
Eksperimen dilakukan dalam lingkungan terkontrol untuk tujuan akademik ethical hacking.
Tidak menargetkan sistem pihak ketiga tanpa izin.
