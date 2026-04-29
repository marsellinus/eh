#!/usr/bin/env python3
"""Baseline machine learning untuk deteksi intrusi memakai NSL-KDD CSV."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "datasets" / "external"
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_CSV = DATA_DIR / "KDDTrain+.csv"
TEST_CSV = DATA_DIR / "KDDTest+.csv"
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]


def main() -> None:
    if not TRAIN_CSV.exists() or not TEST_CSV.exists():
        raise FileNotFoundError(
            "Dataset belum tersedia. Jalankan: python3 scripts/fetch_external_datasets.py"
        )

    train_df = pd.read_csv(TRAIN_CSV)
    test_df = pd.read_csv(TEST_CSV)

    X_train = train_df.drop(columns=["label", "difficulty"])
    y_train = train_df["label"]

    X_test = test_df.drop(columns=["label", "difficulty"])
    y_test = test_df["label"]

    categorical_cols = [c for c in CATEGORICAL_FEATURES if c in X_train.columns]
    numeric_cols = [c for c in X_train.columns if c not in categorical_cols]

    # Normalisasi fitur numerik dari data mentah NSL-KDD (fallback jika ada noise string).
    for col in numeric_cols:
        X_train[col] = pd.to_numeric(X_train[col], errors="coerce").fillna(0)
        X_test[col] = pd.to_numeric(X_test[col], errors="coerce").fillna(0)

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
            ("num", "passthrough", numeric_cols),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
    )

    clf = Pipeline(
        steps=[
            ("prep", preprocessor),
            ("model", model),
        ]
    )

    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)

    acc = accuracy_score(y_test, preds)
    report = classification_report(y_test, preds, output_dict=True, zero_division=0)
    report_dict: dict[str, Any] = report if isinstance(report, dict) else {}

    weighted = report_dict.get("weighted avg", {})
    macro = report_dict.get("macro avg", {})

    metrics = {
        "model": "RandomForestClassifier",
        "dataset": "NSL-KDD",
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "accuracy": float(acc),
        "weighted_f1": float(weighted.get("f1-score", 0.0)),
        "macro_f1": float(macro.get("f1-score", 0.0)),
    }

    out_json = RESULTS_DIR / "ml_nsl_kdd_metrics.json"
    out_json.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("=== ML Baseline NSL-KDD ===")
    print(json.dumps(metrics, indent=2))
    print(f"Saved: {out_json}")


if __name__ == "__main__":
    main()
