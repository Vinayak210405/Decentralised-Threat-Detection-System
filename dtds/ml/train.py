"""Train and evaluate intrusion-detection models.

Examples::

    python -m dtds.ml.train --dataset nsl-kdd
    python -m dtds.ml.train --dataset unsw-nb15 --models rf,hgb
    python -m dtds.ml.train --dataset nsl-kdd --binary
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np

from dtds.ml import datasets
from dtds.ml.evaluate import compute_metrics, plot_confusion, write_report
from dtds.ml.models import MODEL_DESCRIPTIONS, make_pipeline
from dtds.paths import MODELS_DIR, REPORTS_DIR, ensure


def run(dataset_name: str, model_names, binary: bool = False, seed: int = 42,
        out_dir: Path = None, save_models: bool = True, dataset=None):
    ds = dataset or datasets.load(dataset_name)
    if binary:
        ds = ds.as_binary()
    classes = ds.classes
    out_dir = ensure(Path(out_dir or REPORTS_DIR / "ml" / ds.name))
    print(f"[{ds.name}] train={len(ds.X_train):,} test={len(ds.X_test):,} classes={classes}")

    results = {}
    for name in model_names:
        pipe = make_pipeline(name, ds.categorical, ds.numeric, seed)
        t0 = time.perf_counter()
        pipe.fit(ds.X_train, ds.y_train)
        train_s = time.perf_counter() - t0

        t0 = time.perf_counter()
        y_pred = pipe.predict(ds.X_test)
        infer_ms = 1000 * (time.perf_counter() - t0) / len(ds.X_test) * 1000

        m = compute_metrics(ds.y_test, y_pred, classes, ds.y_test_detail, ds.novel_test_labels)
        m.update(description=MODEL_DESCRIPTIONS[name], train_seconds=train_s,
                 inference_ms_per_1k=infer_ms)
        png = f"confusion_{name}.png"
        plot_confusion(m, f"{ds.name}: {MODEL_DESCRIPTIONS[name].split(',')[0]}", out_dir / png)
        m["confusion_png"] = png
        results[name] = m
        print(f"  {name:6s} acc={m['accuracy']:.4f} macroF1={m['macro_f1']:.4f} "
              f"detect={m['detection_rate']:.4f} FAR={m['false_alarm_rate']:.4f} "
              f"({train_s:.1f}s)")
        if save_models:
            path = ensure(MODELS_DIR) / f"{ds.name}_{name}.joblib"
            joblib.dump({"pipeline": pipe, "classes": classes, "dataset": ds.name,
                         "features": list(ds.X_train.columns)}, path)

    report = write_report(results, ds.summary(), out_dir)
    print(f"Report: {report}")
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="nsl-kdd", choices=sorted(datasets.LOADERS))
    ap.add_argument("--models", default="logreg,rf,hgb,mlp",
                    help=f"comma-separated subset of {','.join(MODEL_DESCRIPTIONS)}")
    ap.add_argument("--binary", action="store_true", help="Normal vs Attack instead of categories")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--no-save", action="store_true", help="don't write models/*.joblib")
    args = ap.parse_args(argv)
    np.random.seed(args.seed)
    run(args.dataset, [m.strip() for m in args.models.split(",") if m.strip()], args.binary,
        args.seed, args.out, not args.no_save)


if __name__ == "__main__":
    main()
