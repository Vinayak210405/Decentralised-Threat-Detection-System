"""Catching attacks the classifier was never trained on.

A supervised classifier only recognises attack types present in its training
data: on NSL-KDD the gradient-boosting model detects 84.5% of known attack
types but only 37% of novel ones. This module adds an **anomaly detector
trained on normal traffic only**, which needs no attack labels at all: it
learns what normal looks like and flags whatever doesn't fit.

The hybrid detector adds up the evidence from both: the anomaly score plus the
classifier's attack score (only when positive), each standardised against
normal traffic. A flow the classifier calls normal but
the anomaly detector flags gets the label ``Unknown``: "something new, look at
it", which is exactly what an analyst wants for a never-seen attack.

How it is evaluated (this is the part that keeps the comparison honest)
------------------------------------------------------------------------
Any detector catches more attacks if you let it raise more false alarms; just
lowering the classifier's threshold would also catch more novel attacks. So
the classifier alone and the hybrid are compared **at the same false-alarm
rate**: both are swept over thresholds, and detection of novel attacks is read
off at 1%, 2%, 5% and 10% false alarms. A deployable operating point is also
reported: thresholds set on held-out *training* normals (never the test set) for
a target false-alarm rate, then measured on the test set.

What counts as a novel attack
-----------------------------
* NSL-KDD: the 17 attack types that appear only in the official test set.
* UNSW-NB15 has no such types, so we run leave-one-family-out: retrain the
  classifier with one attack family removed, and measure how well that family
  is detected. The anomaly detector never sees attacks, so it is fitted once.

Run::

    python -m dtds.ml.novelty --dataset nsl-kdd
    python -m dtds.ml.novelty --dataset unsw-nb15
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split
from sklearn.neighbors import NearestNeighbors
from sklearn.neural_network import MLPRegressor

from dtds.ml import datasets
from dtds.ml.datasets import NORMAL, Dataset
from dtds.ml.models import make_pipeline
from dtds.ml.preprocess import build_preprocessor
from dtds.paths import REPORTS_DIR, ensure

UNKNOWN = "Unknown"
FAR_POINTS = (0.01, 0.02, 0.05, 0.10)


# --------------------------------------------------------------------------- #
# Anomaly scorers: fitted on normal traffic only; higher score = more unusual
# --------------------------------------------------------------------------- #
class AnomalyScorer:
    KINDS = {
        "knn": "k-nearest-neighbour distance to normal traffic (k=5)",
        "autoencoder": "autoencoder reconstruction error (64-16-64)",
        "iforest": "isolation forest (200 trees)",
    }

    def __init__(self, kind: str, categorical: Sequence[str], numeric: Sequence[str],
                 seed: int = 42, max_reference: int = 20000):
        if kind not in self.KINDS:
            raise ValueError(f"unknown anomaly scorer {kind!r}; choose from {sorted(self.KINDS)}")
        self.kind, self.seed, self.max_reference = kind, seed, max_reference
        self.prep = build_preprocessor(list(categorical), list(numeric))

    def fit(self, X_normal: pd.DataFrame) -> "AnomalyScorer":
        Z = self.prep.fit_transform(X_normal).astype(np.float32)
        rng = np.random.default_rng(self.seed)
        if self.kind == "knn":
            if len(Z) > self.max_reference:
                Z = Z[rng.choice(len(Z), self.max_reference, replace=False)]
            self.model = NearestNeighbors(n_neighbors=5).fit(Z)
        elif self.kind == "autoencoder":
            self.model = MLPRegressor(hidden_layer_sizes=(64, 16, 64), alpha=1e-4, batch_size=256,
                                      max_iter=60, early_stopping=True, n_iter_no_change=5,
                                      random_state=self.seed).fit(Z, Z)
        else:
            self.model = IsolationForest(n_estimators=200, random_state=self.seed, n_jobs=-1).fit(Z)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        Z = self.prep.transform(X).astype(np.float32)
        if self.kind == "knn":
            out = np.empty(len(Z))
            for i in range(0, len(Z), 4096):  # chunked to bound memory
                d, _ = self.model.kneighbors(Z[i:i + 4096])
                out[i:i + 4096] = d.mean(axis=1)
            return out
        if self.kind == "autoencoder":
            return ((self.model.predict(Z) - Z) ** 2).mean(axis=1)
        return -self.model.score_samples(Z)


class NormalScale:
    """Standardise a score against held-out NORMAL flows: (s - mean) / std.

    Puts the classifier and the anomaly detector on one scale ("how many
    standard deviations more unusual than normal traffic"), so they can be
    combined with max(). Unlike a percentile it does not saturate at 1.0, which
    would create large blocks of tied scores and make thresholds jumpy.
    """

    def __init__(self, transform):
        self.transform = transform

    def fit(self, reference: np.ndarray) -> "NormalScale":
        t = self.transform(np.asarray(reference, dtype=float))
        self.mean, self.std = float(t.mean()), float(t.std()) or 1.0
        return self

    def __call__(self, s: np.ndarray) -> np.ndarray:
        return (self.transform(np.asarray(s, dtype=float)) - self.mean) / self.std


def logit(p):
    p = np.clip(p, 1e-9, 1 - 1e-9)
    return np.log(p) - np.log1p(-p)


def log_score(a):
    return np.log(np.maximum(a, 0) + 1e-9)


# --------------------------------------------------------------------------- #
# The hybrid detector
# --------------------------------------------------------------------------- #
class HybridDetector:
    """Classifier + anomaly detector, calibrated on held-out training normals."""

    def __init__(self, categorical, numeric, classifier: str = "hgb", anomaly: str = "autoencoder",
                 target_far: float = 0.02, seed: int = 42):
        self.categorical, self.numeric = list(categorical), list(numeric)
        self.classifier_name, self.anomaly_kind = classifier, anomaly
        self.target_far, self.seed = target_far, seed

    def fit(self, X: pd.DataFrame, y: pd.Series, val_size: float = 0.2,
            anomaly_scorer: Optional[AnomalyScorer] = None) -> "HybridDetector":
        X_fit, X_val, y_fit, y_val = train_test_split(X, y, test_size=val_size, stratify=y,
                                                      random_state=self.seed)
        self.clf = make_pipeline(self.classifier_name, self.categorical, self.numeric, self.seed)
        self.clf.fit(X_fit, y_fit)
        self.classes_ = list(self.clf.classes_)
        self.normal_idx = self.classes_.index(NORMAL)
        normals_fit = X_fit[y_fit.to_numpy() == NORMAL]
        self.anomaly = anomaly_scorer or AnomalyScorer(self.anomaly_kind, self.categorical,
                                                       self.numeric, self.seed).fit(normals_fit)
        # Calibrate on held-out normals the models never trained on.
        val_normals = X_val[y_val.to_numpy() == NORMAL]
        self.clf_scale = NormalScale(logit).fit(self.attack_probability(val_normals))
        self.anom_scale = NormalScale(log_score).fit(self.anomaly.score(val_normals))
        combined_val = self._combine(self.attack_probability(val_normals),
                                     self.anomaly.score(val_normals))
        # Threshold on the combined score so ~target_far of normal flows alarm.
        self.threshold_ = float(np.quantile(combined_val, 1 - self.target_far))
        return self

    def calibrate_to_baseline(self, X_normal: pd.DataFrame, target_far: Optional[float] = None,
                              refit_anomaly: bool = True) -> "HybridDetector":
        """Adapt to ONE company's network using a period of its own clean traffic.

        A detector trained on someone else's "normal" (here: a 1999 network)
        over-alarms on today's traffic. Half of the baseline refits the anomaly
        detector (what normal looks like HERE); the other half re-standardises
        both scores and resets the alarm threshold to `target_far` of this
        network's normal flows. The classifier itself is not retrained.
        """
        if target_far is not None:
            self.target_far = target_far
        fit_part = X_normal.sample(frac=0.5, random_state=self.seed)
        cal_part = X_normal.drop(fit_part.index)
        if refit_anomaly:
            self.anomaly = AnomalyScorer(self.anomaly_kind, self.categorical, self.numeric,
                                         self.seed).fit(fit_part)
        p, a = self.attack_probability(cal_part), self.anomaly.score(cal_part)
        self.clf_scale = NormalScale(logit).fit(p)
        self.anom_scale = NormalScale(log_score).fit(a)
        self.threshold_ = float(np.quantile(self._combine(p, a), 1 - self.target_far))
        self.baseline_rows_ = len(X_normal)
        return self

    def attack_probability(self, X) -> np.ndarray:
        return 1.0 - self.clf.predict_proba(X)[:, self.normal_idx]

    def _combine(self, p_attack, anomaly_score) -> np.ndarray:
        # anomaly + max(classifier, 0), both standardised against normal traffic.
        # - A plain max() lets the classifier's confident false positives (2.3% of
        #   NSL-KDD test normals get p > 0.999) dominate every low threshold; adding
        #   the anomaly score lets "looks normal" pull those back down.
        # - The classifier may only ADD evidence: on an attack unlike anything it
        #   was trained on, its "confidently normal" is extrapolation, and a plain
        #   sum let that veto the anomaly detector (tests/test_novelty.py).
        # Every rule tried is reported in reports/ml/nsl-kdd/novelty.md.
        return self.anom_scale(anomaly_score) + np.maximum(self.clf_scale(p_attack), 0.0)

    def scores(self, X) -> Dict[str, np.ndarray]:
        p = self.attack_probability(X)
        a = self.anomaly.score(X)
        return {"classifier": p, "anomaly": a, "hybrid": self._combine(p, a)}

    def predict(self, X) -> np.ndarray:
        """Category label, or ``Unknown`` when only the anomaly detector fired.
        Flows the classifier calls an attack keep their category."""
        p_cls = self.clf.predict_proba(X)
        labels = np.array(self.classes_, dtype=object)[p_cls.argmax(axis=1)]
        s = self.scores(X)
        alarm = s["hybrid"] > self.threshold_
        clf_says_attack = labels != NORMAL
        labels = np.where(alarm & ~clf_says_attack, UNKNOWN, labels)
        # Below the alarm threshold, a weak attack call is overruled to Normal so
        # the false-alarm rate stays at the calibrated level.
        labels = np.where(~alarm & clf_says_attack, NORMAL, labels)
        return labels


# --------------------------------------------------------------------------- #
# Evaluation at matched false-alarm rates
# --------------------------------------------------------------------------- #
def _roc(score_normal, score_attack):
    y = np.r_[np.zeros(len(score_normal)), np.ones(len(score_attack))]
    fpr, tpr, _ = roc_curve(y, np.r_[score_normal, score_attack])
    return fpr, tpr


def detection_at_far(score_normal: np.ndarray, score_attack: np.ndarray,
                     fars: Sequence[float] = FAR_POINTS) -> Dict[str, float]:
    """Best detection rate over thresholds whose ACTUAL false-alarm rate on
    `score_normal` is at most `far`. Read off the ROC curve, so tied scores
    are handled correctly (a quantile threshold inside a tie block is not)."""
    if not len(score_attack):
        return {f"{far:.0%}": None for far in fars}
    fpr, tpr = _roc(score_normal, score_attack)
    return {f"{far:.0%}": float(tpr[fpr <= far + 1e-12].max()) for far in fars}


def curve(score_normal, score_attack, max_far=0.2, points=101):
    fpr, tpr = _roc(score_normal, score_attack)
    fars = np.linspace(0, max_far, points)
    return fars.tolist(), [float(tpr[fpr <= f + 1e-12].max()) for f in fars]


def _auc(score_normal, score_attack) -> float:
    y = np.r_[np.zeros(len(score_normal)), np.ones(len(score_attack))]
    return float(roc_auc_score(y, np.r_[score_normal, score_attack]))


def evaluate_split(det: HybridDetector, X_test, y_test, novel_mask) -> Dict[str, object]:
    s = det.scores(X_test)
    y = np.asarray(y_test)
    normal = y == NORMAL
    known = (~normal) & ~novel_mask
    res = {"matched_far": {}, "auc_novel": {}, "curves": {}}
    for name in ("classifier", "anomaly", "hybrid"):
        res["matched_far"][name] = {
            "novel": detection_at_far(s[name][normal], s[name][novel_mask]),
            "known": detection_at_far(s[name][normal], s[name][known]),
        }
        res["auc_novel"][name] = _auc(s[name][normal], s[name][novel_mask])
        res["curves"][name] = curve(s[name][normal], s[name][novel_mask])
    # Deployable operating point: thresholds from training normals only.
    pred = det.predict(X_test)
    alarm = pred != NORMAL
    res["operating_point"] = {
        "target_far": det.target_far,
        "test_far": float(alarm[normal].mean()),
        "novel_detection": float(alarm[novel_mask].mean()),
        "known_detection": float(alarm[known].mean()) if known.any() else None,
        "novel_labelled_unknown": float((pred[novel_mask] == UNKNOWN).mean()),
        "classifier_alone_test_far": float((det.clf.predict(X_test) != NORMAL)[normal].mean()),
        "classifier_alone_novel_detection": float((det.clf.predict(X_test) != NORMAL)[novel_mask].mean()),
    }
    return res


def compare_scorers(ds: Dataset, kinds=("knn", "autoencoder", "iforest"), seed=42):
    """How well each anomaly scorer alone separates test normals from novel attacks."""
    X_fit, _, y_fit, _ = train_test_split(ds.X_train, ds.y_train, test_size=0.2,
                                          stratify=ds.y_train, random_state=seed)
    normals = X_fit[y_fit.to_numpy() == NORMAL]
    y = ds.y_test.to_numpy()
    novel = np.isin(np.asarray(ds.y_test_detail), ds.novel_test_labels)
    out = {}
    for kind in kinds:
        t0 = time.perf_counter()
        sc = AnomalyScorer(kind, ds.categorical, ds.numeric, seed).fit(normals)
        s = sc.score(ds.X_test)
        out[kind] = {"description": AnomalyScorer.KINDS[kind],
                     "auc_novel": _auc(s[y == NORMAL], s[novel]),
                     "auc_all_attacks": _auc(s[y == NORMAL], s[y != NORMAL]),
                     "seconds": round(time.perf_counter() - t0, 1)}
        print(f"  {kind:12s} AUC novel={out[kind]['auc_novel']:.3f} all={out[kind]['auc_all_attacks']:.3f} "
              f"({out[kind]['seconds']}s)")
    return out


def run_nsl(ds: Dataset, anomaly: str, seed: int) -> Dict[str, object]:
    print("Comparing anomaly scorers (AUC: normal vs novel attacks) ...")
    scorers = compare_scorers(ds, seed=seed)
    det = HybridDetector(ds.categorical, ds.numeric, anomaly=anomaly, seed=seed)
    det.fit(ds.X_train, ds.y_train)
    novel = np.isin(np.asarray(ds.y_test_detail), ds.novel_test_labels)
    res = evaluate_split(det, ds.X_test, ds.y_test, novel)
    res["scorers"] = scorers
    # Every combination rule tried, reported because the default was picked on this test set.
    p, a = det.attack_probability(ds.X_test), det.anomaly.score(ds.X_test)
    zc, za = det.clf_scale(p), det.anom_scale(a)
    y = ds.y_test.to_numpy()
    n, kn = y == NORMAL, (y != NORMAL) & ~novel
    res["rules"] = {}
    for name, sc in (("classifier only", zc), ("anomaly only", za), ("max(classifier, anomaly)", np.maximum(zc, za)),
                     ("sum", zc + za), ("0.3 x classifier + anomaly", 0.3 * zc + za),
                     ("anomaly + max(classifier, 0) (default)", za + np.maximum(zc, 0))):
        res["rules"][name] = {"novel": detection_at_far(sc[n], sc[novel]),
                              "known": detection_at_far(sc[n], sc[kn]),
                              "auc_novel": _auc(sc[n], sc[novel]), "auc_known": _auc(sc[n], sc[kn])}
    res["test_normals_classifier_p_gt_0999"] = float((p[n] > 0.999).mean())
    res["novel_definition"] = (f"{len(ds.novel_test_labels)} attack types present only in the official "
                               f"test set ({int(novel.sum())} rows)")
    return res


def run_leave_one_family_out(ds: Dataset, anomaly: str, seed: int,
                             families: Optional[List[str]] = None) -> Dict[str, object]:
    families = families or [c for c in ds.classes if c != NORMAL]
    # The anomaly scorer sees only normals, so one fit serves every fold.
    X_fit, _, y_fit, _ = train_test_split(ds.X_train, ds.y_train, test_size=0.2,
                                          stratify=ds.y_train, random_state=seed)
    scorer = AnomalyScorer(anomaly, ds.categorical, ds.numeric, seed).fit(
        X_fit[y_fit.to_numpy() == NORMAL])
    folds = {}
    y_test = ds.y_test.to_numpy()
    for fam in families:
        t0 = time.perf_counter()
        keep = ds.y_train.to_numpy() != fam
        det = HybridDetector(ds.categorical, ds.numeric, anomaly=anomaly, seed=seed)
        det.fit(ds.X_train[keep], ds.y_train[keep], anomaly_scorer=scorer)
        novel = y_test == fam
        r = evaluate_split(det, ds.X_test, ds.y_test, novel)
        r.pop("curves")
        folds[fam] = r
        m = r["matched_far"]
        print(f"  held out {fam:15s} @2% FAR: classifier {m['classifier']['novel']['2%']:.3f} "
              f"hybrid {m['hybrid']['novel']['2%']:.3f} ({time.perf_counter() - t0:.0f}s)")
    return {"novel_definition": "leave-one-family-out: each attack family removed from training in turn",
            "folds": folds}


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def _pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


def write_report(ds_name: str, res: Dict[str, object], out_dir: Path, anomaly: str) -> Path:
    out_dir = ensure(out_dir)
    tag = f"novelty_{anomaly}"
    (out_dir / f"{tag}.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    lines = [f"# Detecting novel attacks: {ds_name} ({anomaly})", "",
             f"Hybrid = gradient-boosting classifier + {AnomalyScorer.KINDS[anomaly]} trained on "
             f"normal traffic only. Novel attacks: {res['novel_definition']}.", ""]
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    if "folds" not in res:
        mf = res["matched_far"]
        lines += ["## Detection of novel attacks at the same false-alarm rate", "",
                  "| Detector | " + " | ".join(f"at {k} false alarms" for k in mf["hybrid"]["novel"]) +
                  " | AUC |", "|---|" + "---|" * (len(FAR_POINTS) + 1)]
        for name, label in (("classifier", "Classifier alone"), ("anomaly", "Anomaly detector alone"),
                            ("hybrid", "**Hybrid**")):
            lines.append(f"| {label} | " + " | ".join(_pct(v) for v in mf[name]["novel"].values())
                         + f" | {res['auc_novel'][name]:.3f} |")
        lines += ["", "Known attack types at the same false-alarm rates:", "",
                  "| Detector | " + " | ".join(f"at {k}" for k in mf["hybrid"]["known"]) + " |",
                  "|---|" + "---|" * len(FAR_POINTS)]
        for name, label in (("classifier", "Classifier alone"), ("hybrid", "Hybrid")):
            lines.append(f"| {label} | " + " | ".join(_pct(v) for v in mf[name]["known"].values()) + " |")
        op = res["operating_point"]
        lines += ["", "## Deployable operating point", "",
                  f"Thresholds set on held-out *training* normals for a {_pct(op['target_far'])} "
                  "false-alarm target, then measured on the test set:", "",
                  "| | False alarms (test) | Novel attacks detected | Known attacks detected |",
                  "|---|---|---|---|",
                  f"| Classifier alone (default threshold) | {_pct(op['classifier_alone_test_far'])} | "
                  f"{_pct(op['classifier_alone_novel_detection'])} | |",
                  f"| Hybrid | {_pct(op['test_far'])} | {_pct(op['novel_detection'])} | "
                  f"{_pct(op['known_detection'])} |", "",
                  f"{_pct(op['novel_labelled_unknown'])} of novel attack flows were labelled `Unknown` "
                  "(flagged by the anomaly detector only)."]
        if "rules" in res:
            lines += ["", "## Combination rules tried", "",
                      "The default was chosen after looking at this test set (and a synthetic case where a plain sum "
                      "failed), so every rule tried is "
                      "listed; UNSW-NB15 (leave-one-family-out) is the independent check.", "",
                      "| Rule | Novel @2% | Novel @5% | Novel @10% | Known @2% | Known @5% | AUC novel | AUC known |",
                      "|---|---|---|---|---|---|---|---|"]
            for name, r in res["rules"].items():
                lines.append(f"| {name} | {_pct(r['novel']['2%'])} | {_pct(r['novel']['5%'])} | "
                             f"{_pct(r['novel']['10%'])} | {_pct(r['known']['2%'])} | {_pct(r['known']['5%'])} | "
                             f"{r['auc_novel']:.3f} | {r['auc_known']:.3f} |")
            lines += ["", f"{_pct(res['test_normals_classifier_p_gt_0999'])} of normal test flows get a "
                      "classifier attack probability above 0.999, so below that false-alarm rate no rule "
                      "that uses the classifier can do much."]
        if "scorers" in res:
            lines += ["", "## Anomaly scorers compared", "",
                      "| Scorer | AUC: normal vs novel attacks | AUC: normal vs all attacks | Fit + score time |",
                      "|---|---|---|---|"]
            for k, v in res["scorers"].items():
                lines.append(f"| {v['description']} | {v['auc_novel']:.3f} | {v['auc_all_attacks']:.3f} | "
                             f"{v['seconds']}s |")
        fig, ax = plt.subplots(figsize=(7, 4.2))
        for name, style in (("classifier", "--"), ("anomaly", ":"), ("hybrid", "-")):
            fars, det = res["curves"][name]
            ax.plot(np.array(fars) * 100, np.array(det) * 100, style, linewidth=2 if name == "hybrid" else 1.4,
                    label={"classifier": "classifier alone", "anomaly": "anomaly detector alone",
                           "hybrid": "hybrid"}[name])
        ax.set_xlabel("false-alarm rate on normal test traffic (%)")
        ax.set_ylabel("novel attacks detected (%)")
        ax.set_title(f"{ds_name}: novel-attack detection at matched false-alarm rates")
        ax.grid(alpha=0.3)
        ax.legend()
        fig.tight_layout()
        fig.savefig(out_dir / f"{tag}_curve.png", dpi=130)
        plt.close(fig)
        lines += ["", f"![curve]({tag}_curve.png)"]
    else:
        lines += ["## Held-out attack family detection at 2% false alarms", "",
                  "Each row: the classifier was retrained WITHOUT that family; the family is then the "
                  "'novel' attack.", "",
                  "| Held-out family | Classifier alone | Hybrid | Gain | Classifier AUC | Hybrid AUC |",
                  "|---|---|---|---|---|---|"]
        gains = []
        for fam, r in res["folds"].items():
            c = r["matched_far"]["classifier"]["novel"]["2%"]
            h = r["matched_far"]["hybrid"]["novel"]["2%"]
            gains.append((c, h))
            lines.append(f"| {fam} | {_pct(c)} | {_pct(h)} | {100 * (h - c):+.1f} pts | "
                         f"{r['auc_novel']['classifier']:.3f} | {r['auc_novel']['hybrid']:.3f} |")
        c_mean = np.mean([g[0] for g in gains])
        h_mean = np.mean([g[1] for g in gains])
        lines += [f"| **Mean over families** | **{_pct(c_mean)}** | **{_pct(h_mean)}** | "
                  f"**{100 * (h_mean - c_mean):+.1f} pts** | | |"]
        res["mean_at_2pct"] = {"classifier": float(c_mean), "hybrid": float(h_mean)}
        (out_dir / f"{tag}.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    path = out_dir / f"{tag}.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Report: {path}")
    return path


def save_hybrid(ds: Dataset, anomaly: str = "autoencoder", target_far: float = 0.02, seed: int = 42) -> Path:
    """Train a HybridDetector on the full training set and save it in the same
    format CompanyNode loads (``{"hybrid": ..., "features": [...]}``)."""
    import joblib
    from dtds.paths import MODELS_DIR
    det = HybridDetector(ds.categorical, ds.numeric, anomaly=anomaly, target_far=target_far,
                         seed=seed).fit(ds.X_train, ds.y_train)
    path = ensure(MODELS_DIR) / f"{ds.name}_hybrid.joblib"
    joblib.dump({"hybrid": det, "features": list(ds.X_train.columns), "dataset": ds.name,
                 "target_far": target_far}, path)
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="nsl-kdd", choices=sorted(datasets.LOADERS))
    ap.add_argument("--anomaly", default="autoencoder", choices=sorted(AnomalyScorer.KINDS))
    ap.add_argument("--families", default=None, help="comma-separated families for leave-one-out")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--save-only", action="store_true",
                    help="just train the hybrid on the full training set and save it to models/")
    args = ap.parse_args(argv)
    ds = datasets.load(args.dataset)
    if args.save_only:
        print(f"Saved {save_hybrid(ds, args.anomaly, seed=args.seed)}")
        return
    print(f"[{ds.name}] hybrid novelty evaluation, anomaly scorer = {args.anomaly}")
    if ds.novel_test_labels:
        res = run_nsl(ds, args.anomaly, args.seed)
    else:
        fams = args.families.split(",") if args.families else None
        res = run_leave_one_family_out(ds, args.anomaly, args.seed, fams)
    write_report(ds.name, res, REPORTS_DIR / "ml" / ds.name, args.anomaly)


if __name__ == "__main__":
    main()
