"""Repeat the federated experiments over several seeds and report mean +/- std.

Single-seed neural-network results on NSL-KDD move by several points between
runs, so headline numbers should come from this summary.

    python scripts/fl_multiseed.py --seeds 1 2 3 4 5
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dtds.ml import datasets  # noqa: E402
from dtds.ml.federated import run_experiment  # noqa: E402
from dtds.paths import REPORTS_DIR  # noqa: E402

CONFIGS = [
    ("by-attack", "samples"),
    ("by-attack", "uniform"),
    ("dirichlet", "samples"),
    ("iid", "samples"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="nsl-kdd")
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    ap.add_argument("--rounds", type=int, default=30)
    args = ap.parse_args()
    ds = datasets.load(args.dataset)
    rows = {}
    for partition, agg in CONFIGS:
        key = f"{partition} / {agg}"
        per_seed = []
        for seed in args.seeds:
            print(f"== {key} seed={seed}")
            r = run_experiment(ds, 3, partition, 0.3, args.rounds, 1, seed, None, eval_every=10**9,
                               aggregation=agg)
            res = r["results"]
            locals_ = [v for k, v in res.items() if k.startswith("local_")]
            gains = r["unseen_category_recall"]
            per_seed.append({
                "federated_macro_f1": res["federated"]["macro_f1"],
                "centralised_macro_f1": res["centralised"]["macro_f1"],
                "local_mean_macro_f1": float(np.mean([m["macro_f1"] for m in locals_])),
                "federated_detection": res["federated"]["detection_rate"],
                "local_mean_detection": float(np.mean([m["detection_rate"] for m in locals_])),
                "federated_far": res["federated"]["false_alarm_rate"],
                "unseen_local": float(np.mean([g["local_recall"] for g in gains.values()])) if gains else None,
                "unseen_federated": float(np.mean([g["federated_recall"] for g in gains.values()])) if gains else None,
            })
        rows[key] = per_seed

    def ms(key, field):
        vals = [s[field] for s in rows[key] if s[field] is not None]
        if not vals:
            return "n/a"
        return f"{100 * np.mean(vals):.1f} ± {100 * np.std(vals):.1f}"

    out = REPORTS_DIR / "ml" / ds.name
    out.mkdir(parents=True, exist_ok=True)
    (out / "federated_summary.json").write_text(json.dumps({"seeds": args.seeds, "runs": rows}, indent=2), encoding="utf-8")
    lines = [f"# Federated learning summary: {ds.name}", "",
             f"3 simulated companies, {args.rounds} rounds, class-balanced local loss, "
             f"mean ± std over seeds {args.seeds}. All numbers are % on the official test set.", "",
             "| Partition / aggregation | Centralised macro-F1 | Federated macro-F1 | Local-only macro-F1 (mean of companies) "
             "| Federated detection | Local-only detection | Federated false alarms | Recall on never-seen categories: local → federated |",
             "|---|---|---|---|---|---|---|---|"]
    for key in rows:
        lines.append(f"| {key} | {ms(key, 'centralised_macro_f1')} | {ms(key, 'federated_macro_f1')} | "
                     f"{ms(key, 'local_mean_macro_f1')} | {ms(key, 'federated_detection')} | "
                     f"{ms(key, 'local_mean_detection')} | {ms(key, 'federated_far')} | "
                     f"{ms(key, 'unseen_local')} → {ms(key, 'unseen_federated')} |")
    lines += ["", "Partitions: **by-attack** = each company sees Normal traffic plus only its own "
              "attack categories (A: DoS+Probe, B: R2L, C: U2R); **dirichlet** = label skew with "
              "alpha=0.3; **iid** = random equal split. Aggregation: **samples** = standard FedAvg, "
              "**uniform** = equal weight per company.", ""]
    (out / "federated_summary.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {out / 'federated_summary.md'}")


if __name__ == "__main__":
    main()
