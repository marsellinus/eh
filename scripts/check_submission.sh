#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

missing=0

check_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    echo "[OK] $f"
  else
    echo "[MISSING] $f"
    missing=$((missing + 1))
  fi
}

echo "=== Validasi Output Wajib Ujian ==="

echo "1) Laporan PDF"
check_file "submission/01_laporan/Laporan_Ethical_Hacking_Nama_NIM.pdf"

echo "2) Dataset / Evidence"
check_file "submission/02_dataset_evidence/README_dataset.md"
check_file "submission/02_dataset_evidence/results/comparison_summary.csv"
check_file "submission/02_dataset_evidence/results/comparison_summary.json"

echo "3) Demo Teknis"
check_file "submission/03_demo/Demo_Teknis_Nama_NIM.mp4"
check_file "submission/03_demo/SCRIPT_DEMO.md"

echo "4) Slide"
check_file "submission/04_slide/Presentasi_Ethical_Hacking_Nama_NIM.pptx"

echo "5) Poster"
check_file "submission/05_poster/Poster_Ilmiah_Ethical_Hacking_Nama_NIM.pdf"

if [[ "$missing" -eq 0 ]]; then
  echo "\nSemua output wajib terdeteksi lengkap."
  exit 0
fi

echo "\nTotal file belum lengkap: $missing"
exit 1
