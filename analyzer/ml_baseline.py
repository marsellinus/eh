#!/usr/bin/env python3
"""
ML baseline: RandomForest intrusion detection.

Supports three dataset modes:
  - nsl_kdd  : NSL-KDD (default, classic benchmark)
  - cicids   : CICIDS2017 (modern, HTTP/SSH attacks)
  - custom   : Log eksperimen sendiri (results/attack_*.log)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parents[1]

# NSL-KDD paths
DEFAULT_TRAIN = _ROOT / "datasets" / "external" / "KDDTrain+.csv"
DEFAULT_TEST = _ROOT / "datasets" / "external" / "KDDTest+.csv"
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

# CICIDS2017 paths
CICIDS_DIR = _ROOT / "datasets" / "external" / "cicids2017"

# Custom dataset (dari log eksperimen)
RESULTS_DIR = _ROOT / "results"


# ── Custom dataset builder ────────────────────────────────────────────────────

def _build_custom_dataset():
    """
    Bangun dataset dari log eksperimen (attack_http_*.log, attack_ssh_*.log).
    Setiap baris log diparse menjadi fitur numerik sederhana + label.
    """
    try:
        import pandas as pd
    except ImportError as e:
        raise ImportError(f"pandas missing: {e}") from e

    records = []

    # Parse HTTP flood logs
    for log_file in sorted(RESULTS_DIR.glob("attack_http_*.log")):
        mode = log_file.stem.replace("attack_http_", "")
        for line in log_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            # Ekstrak status code jika ada (format: "HTTP/1.1 200" atau "200")
            status_match = re.search(r"\b([2345]\d{2})\b", line)
            status = int(status_match.group(1)) if status_match else 0
            records.append({
                "attack_type": "http_flood",
                "mode": mode,
                "status_code": status,
                "is_error": 1 if status >= 400 else 0,
                "line_length": len(line),
                "label": "attack" if mode == "baseline" else "blocked",
            })

    # Parse SSH brute-force logs
    for log_file in sorted(RESULTS_DIR.glob("attack_ssh_*.log")):
        mode = log_file.stem.replace("attack_ssh_", "")
        for line in log_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            success = 1 if re.search(r"success|authenticated|accepted", line, re.I) else 0
            failed = 1 if re.search(r"fail|refused|denied|error", line, re.I) else 0
            records.append({
                "attack_type": "ssh_brute",
                "mode": mode,
                "status_code": 0,
                "is_error": failed,
                "line_length": len(line),
                "label": "success" if success else ("blocked" if mode != "baseline" else "attack"),
            })

    if not records:
        raise FileNotFoundError(
            "Tidak ada log eksperimen ditemukan di results/. "
            "Jalankan benchmark terlebih dahulu: python3 main.py --modes baseline"
        )

    df = pd.DataFrame(records)
    return df


def _run_custom(n_estimators: int) -> dict[str, Any]:
    """Train RandomForest pada log eksperimen sendiri."""
    try:
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, classification_report
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder
    except ImportError as e:
        raise ImportError(f"ML dependencies missing: {e}. pip install pandas scikit-learn") from e

    log.info("[ml_baseline] Building custom dataset from experiment logs...")
    df = _build_custom_dataset()

    le_attack = LabelEncoder()
    df["attack_type_enc"] = le_attack.fit_transform(df["attack_type"])

    feature_cols = ["attack_type_enc", "status_code", "is_error", "line_length"]
    X = df[feature_cols].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=n_estimators, random_state=42, n_jobs=-1)
    log.info("[ml_baseline] Training on custom dataset (%d rows)...", len(df))
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)

    acc = accuracy_score(y_test, preds)
    report: dict = classification_report(y_test, preds, output_dict=True, zero_division=0)  # type: ignore[assignment]

    return {
        "model": "RandomForestClassifier",
        "dataset": "custom_experiment_logs",
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "total_rows": int(len(df)),
        "classes": sorted(df["label"].unique().tolist()),
        "accuracy": float(acc),
        "weighted_f1": float(report.get("weighted avg", {}).get("f1-score", 0.0)),
        "macro_f1": float(report.get("macro avg", {}).get("f1-score", 0.0)),
        "per_class": {
            cls: {
                "precision": float(v.get("precision", 0)),
                "recall": float(v.get("recall", 0)),
                "f1": float(v.get("f1-score", 0)),
            }
            for cls, v in report.items()
            if isinstance(v, dict) and cls not in ("weighted avg", "macro avg", "accuracy")
        },
    }


# ── CICIDS2017 ────────────────────────────────────────────────────────────────

def _run_cicids(n_estimators: int) -> dict[str, Any]:
    """Train RandomForest pada CICIDS2017."""
    try:
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, classification_report
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import LabelEncoder
    except ImportError as e:
        raise ImportError(f"ML dependencies missing: {e}. pip install pandas scikit-learn") from e

    csv_files = sorted(CICIDS_DIR.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"CICIDS2017 dataset tidak ditemukan di {CICIDS_DIR}. "
            "Jalankan: python3 scripts/fetch_external_datasets.py --dataset cicids"
        )

    log.info("[ml_baseline] Loading CICIDS2017 (%d file(s))...", len(csv_files))
    dfs = []
    for f in csv_files:
        try:
            dfs.append(pd.read_csv(f, low_memory=False))
        except Exception as exc:
            log.warning("[ml_baseline] Skip %s: %s", f.name, exc)

    df = pd.concat(dfs, ignore_index=True)

    # Normalise column names (CICIDS2017 has spaces/mixed case)
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

    label_col = next((c for c in df.columns if "label" in c), None)
    if label_col is None:
        raise ValueError("Kolom 'label' tidak ditemukan di CICIDS2017 CSV.")

    df = df.dropna(subset=[label_col])
    df = df.replace([float("inf"), float("-inf")], 0).fillna(0)

    y = LabelEncoder().fit_transform(df[label_col].astype(str))
    X = df.drop(columns=[label_col]).select_dtypes(include="number")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=n_estimators, random_state=42, n_jobs=-1)
    log.info("[ml_baseline] Training on CICIDS2017 (%d rows, %d features)...", len(df), X.shape[1])
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)

    acc = accuracy_score(y_test, preds)
    report: dict = classification_report(y_test, preds, output_dict=True, zero_division=0)  # type: ignore[assignment]

    return {
        "model": "RandomForestClassifier",
        "dataset": "CICIDS2017",
        "source_files": [f.name for f in csv_files],
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "n_features": int(X.shape[1]),
        "accuracy": float(acc),
        "weighted_f1": float(report.get("weighted avg", {}).get("f1-score", 0.0)),
        "macro_f1": float(report.get("macro avg", {}).get("f1-score", 0.0)),
    }


# ── NSL-KDD (original) ────────────────────────────────────────────────────────

def _run_nsl_kdd(
    train_csv: Path | None,
    test_csv: Path | None,
    n_estimators: int,
) -> dict[str, Any]:
    """Train RandomForest pada NSL-KDD."""
    try:
        import pandas as pd
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, classification_report
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder
    except ImportError as e:
        raise ImportError(
            f"ML dependencies missing: {e}. pip install pandas scikit-learn"
        ) from e

    train_path = train_csv or DEFAULT_TRAIN
    test_path = test_csv or DEFAULT_TEST

    if not train_path.exists() or not test_path.exists():
        raise FileNotFoundError(
            "NSL-KDD dataset tidak ditemukan. "
            "Jalankan: python3 scripts/fetch_external_datasets.py"
        )

    log.info("[ml_baseline] Loading NSL-KDD...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    X_train = train_df.drop(columns=["label", "difficulty"])
    y_train = train_df["label"]
    X_test = test_df.drop(columns=["label", "difficulty"])
    y_test = test_df["label"]

    cat_cols = [c for c in CATEGORICAL_FEATURES if c in X_train.columns]
    num_cols = [c for c in X_train.columns if c not in cat_cols]

    for col in num_cols:
        X_train[col] = pd.to_numeric(X_train[col], errors="coerce").fillna(0)
        X_test[col] = pd.to_numeric(X_test[col], errors="coerce").fillna(0)

    preprocessor = ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols),
        ("num", "passthrough", num_cols),
    ])

    clf = Pipeline([
        ("prep", preprocessor),
        ("model", RandomForestClassifier(n_estimators=n_estimators, random_state=42, n_jobs=-1)),
    ])

    log.info("[ml_baseline] Training RandomForest (n_estimators=%d)...", n_estimators)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)

    acc = accuracy_score(y_test, preds)
    report: dict = classification_report(y_test, preds, output_dict=True, zero_division=0)  # type: ignore[assignment]

    return {
        "model": "RandomForestClassifier",
        "dataset": "NSL-KDD",
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "accuracy": float(acc),
        "weighted_f1": float(report.get("weighted avg", {}).get("f1-score", 0.0)),
        "macro_f1": float(report.get("macro avg", {}).get("f1-score", 0.0)),
    }


# ── Public API ────────────────────────────────────────────────────────────────

def run_ml_baseline(
    train_csv: Path | None = None,
    test_csv: Path | None = None,
    n_estimators: int = 200,
    dataset: str = "nsl_kdd",
) -> dict[str, Any]:
    """
    Train RandomForest dan kembalikan metrik evaluasi.

    Args:
        train_csv:     Path ke KDDTrain+.csv (hanya untuk dataset='nsl_kdd').
        test_csv:      Path ke KDDTest+.csv (hanya untuk dataset='nsl_kdd').
        n_estimators:  Jumlah pohon di forest.
        dataset:       'nsl_kdd' | 'cicids' | 'custom'

    Returns:
        Dict berisi nama model, dataset, jumlah baris, accuracy, dan F1 scores.

    Raises:
        FileNotFoundError: Dataset tidak ditemukan.
        ImportError:       pandas / scikit-learn belum diinstall.
        ValueError:        dataset tidak dikenal.
    """
    if dataset == "nsl_kdd":
        return _run_nsl_kdd(train_csv, test_csv, n_estimators)
    if dataset == "cicids":
        return _run_cicids(n_estimators)
    if dataset == "custom":
        return _run_custom(n_estimators)
    raise ValueError(f"Dataset tidak dikenal: '{dataset}'. Pilih: nsl_kdd, cicids, custom")
