#!/usr/bin/env python3
"""Unduh dataset eksternal: NSL-KDD dan CICIDS2017."""

from __future__ import annotations

import argparse
import csv
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "datasets" / "external"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── NSL-KDD ───────────────────────────────────────────────────────────────────

NSL_SOURCES = {
    "KDDTrain+.txt": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt",
    "KDDTest+.txt": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt",
}

NSL_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

# ── CICIDS2017 ────────────────────────────────────────────────────────────────
# Dataset tersedia di UNB: https://www.unb.ca/cic/datasets/ids-2017.html
# File CSV tersedia via mirror GitHub (subset yang umum dipakai)
CICIDS_DIR = OUT_DIR / "cicids2017"

CICIDS_ZIP_URL = (
    "https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php"
    "?file=CIC-IDS-2017%2FCSVs%2FMachineLearningCSV.zip"
)


def download_file(url: str, output: Path) -> bool:
    print(f"[download] {url}")
    print(f"        -> {output}")
    try:
        urllib.request.urlretrieve(url, output)
        return True
    except Exception as e:
        print(f"[error] Gagal: {e}")
        return False


def txt_to_csv(src: Path, dst: Path) -> None:
    print(f"[convert] {src.name} -> {dst.name}")
    with src.open("r", encoding="utf-8", errors="ignore") as f_in, \
         dst.open("w", encoding="utf-8", newline="") as f_out:
        writer = csv.writer(f_out)
        writer.writerow(NSL_COLUMNS)
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            writer.writerow([part.strip() for part in line.split(",")])


def fetch_nsl_kdd() -> None:
    print("\n=== NSL-KDD ===")
    for filename, url in NSL_SOURCES.items():
        raw_path = OUT_DIR / filename
        download_file(url, raw_path)

    txt_to_csv(OUT_DIR / "KDDTrain+.txt", OUT_DIR / "KDDTrain+.csv")
    txt_to_csv(OUT_DIR / "KDDTest+.txt", OUT_DIR / "KDDTest+.csv")
    print("NSL-KDD selesai.")


def fetch_cicids() -> None:
    import zipfile

    print("\n=== CICIDS2017 ===")
    CICIDS_DIR.mkdir(parents=True, exist_ok=True)

    zip_path = CICIDS_DIR / "MachineLearningCSV.zip"
    if not download_file(CICIDS_ZIP_URL, zip_path):
        print(
            "\n[info] Download otomatis gagal. Unduh manual dari:\n"
            "  https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php"
            "?file=CIC-IDS-2017%2FCSVs%2FMachineLearningCSV.zip\n"
            f"Letakkan MachineLearningCSV.zip di: {CICIDS_DIR}\n"
            "Kemudian jalankan ulang: python3 scripts/fetch_external_datasets.py --dataset cicids"
        )
        return

    print(f"[extract] {zip_path}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            if member.endswith(".csv"):
                dest = CICIDS_DIR / Path(member).name
                with zf.open(member) as src, dest.open("wb") as dst:
                    dst.write(src.read())
                print(f"  -> {dest.name}")

    zip_path.unlink()
    print(f"CICIDS2017 selesai. File di: {CICIDS_DIR}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Download dataset eksternal")
    parser.add_argument(
        "--dataset",
        choices=["nsl_kdd", "cicids", "all"],
        default="nsl_kdd",
        help="Dataset yang diunduh (default: nsl_kdd)",
    )
    args = parser.parse_args()

    if args.dataset in ("nsl_kdd", "all"):
        fetch_nsl_kdd()
    if args.dataset in ("cicids", "all"):
        fetch_cicids()

    print("\nSelesai. File output:")
    for p in sorted(OUT_DIR.rglob("*")):
        if p.is_file():
            print(f"- {p.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
