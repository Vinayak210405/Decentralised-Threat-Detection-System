"""Train detectors that only use features a network sensor (Zeek) can compute.

    python -m dtds.ingest.train_network_model

Writes models/nsl-kdd-network_<model>.joblib (loadable by CompanyNode) and
reports/ml/nsl-kdd-network/results.md, and prints the accuracy cost of losing
the 14 payload/packet features against the full-feature models.
"""
from __future__ import annotations

import argparse
import json

from dtds.ingest.zeek import NETWORK_FEATURES
from dtds.ml import datasets
from dtds.ml.datasets import Dataset
from dtds.ml.train import run
from dtds.paths import REPORTS_DIR


def network_only(ds: Dataset) -> Dataset:
    cols = [c for c in NETWORK_FEATURES if c in ds.X_train.columns]
    return Dataset(ds.name + "-network", ds.X_train[cols], ds.y_train, ds.X_test[cols], ds.y_test,
                   [c for c in ds.categorical if c in cols], [c for c in ds.numeric if c in cols],
                   ds.notes + [f"network-only: {len(cols)} features a Zeek conn.log can provide; "
                               "payload and packet-level features removed"],
                   ds.y_test_detail, ds.novel_test_labels)


def save_network_hybrid(anomaly: str = "autoencoder", seed: int = 42):
    """Hybrid (classifier + anomaly detector) on network-only features, saved for
    CompanyNode. Calibrate it to a network with HybridDetector.calibrate_to_baseline."""
    import joblib
    from dtds.ml.novelty import HybridDetector
    from dtds.paths import MODELS_DIR, ensure
    ds = network_only(datasets.load("nsl-kdd"))
    det = HybridDetector(ds.categorical, ds.numeric, anomaly=anomaly, seed=seed).fit(ds.X_train, ds.y_train)
    path = ensure(MODELS_DIR) / "nsl-kdd-network_hybrid.joblib"
    joblib.dump({"hybrid": det, "features": list(ds.X_train.columns), "dataset": ds.name}, path)
    return path


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="rf,hgb")
    ap.add_argument("--hybrid", action="store_true", help="also save the network-only hybrid detector")
    args = ap.parse_args(argv)
    if args.hybrid:
        print(f"Saved {save_network_hybrid()}")
    models = [m for m in args.models.split(",") if m]
    ds = network_only(datasets.load("nsl-kdd"))
    res = run(ds.name, models, dataset=ds)
    full_path = REPORTS_DIR / "ml" / "nsl-kdd" / "metrics.json"
    if full_path.exists():
        full = json.loads(full_path.read_text(encoding="utf-8"))["models"]
        print("\nCost of using network features only (vs all 40 features):")
        for m in models:
            if m in full:
                for k in ("accuracy", "macro_f1", "detection_rate", "false_alarm_rate",
                          "detection_rate_novel_attacks"):
                    print(f"  {m:4s} {k:28s} {100 * full[m][k]:5.1f}% -> {100 * res[m][k]:5.1f}%")


if __name__ == "__main__":
    main()
