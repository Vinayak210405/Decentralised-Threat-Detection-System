"""Metrics and report writing for intrusion-detection models.

Accuracy alone is misleading on intrusion data (rare classes like U2R are a
fraction of a percent), so every report includes per-class precision/recall/F1,
macro-F1, the binary view a SOC cares about (detection rate and false-alarm
rate), and - where the dataset tells us - recall on attack types the model
never saw during training.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support)

from dtds.ml.datasets import NORMAL


def compute_metrics(y_true, y_pred, classes: List[str], y_detail: Optional[pd.Series] = None,
                    novel_labels: Optional[List[str]] = None) -> Dict[str, object]:
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=classes, zero_division=0)
    per_class = {c: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]),
                     "support": int(s[i])} for i, c in enumerate(classes)}

    is_attack_true = y_true != NORMAL
    is_attack_pred = y_pred != NORMAL
    n_attack = int(is_attack_true.sum())
    n_normal = int((~is_attack_true).sum())
    metrics: Dict[str, object] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, labels=classes, average="weighted",
                                      zero_division=0)),
        # Binary SOC view: did we raise an alarm for an attack (any category)?
        "detection_rate": float((is_attack_pred & is_attack_true).sum() / n_attack) if n_attack else None,
        "false_alarm_rate": float((is_attack_pred & ~is_attack_true).sum() / n_normal) if n_normal else None,
        "per_class": per_class,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=classes).tolist(),
        "labels": classes,
    }

    if y_detail is not None and novel_labels:
        detail = np.asarray(y_detail)
        novel = np.isin(detail, novel_labels)
        known_attack = is_attack_true & ~novel
        metrics["novel_attack_rows"] = int(novel.sum())
        metrics["detection_rate_known_attacks"] = float(is_attack_pred[known_attack].mean())
        metrics["detection_rate_novel_attacks"] = float(is_attack_pred[novel].mean()) if novel.any() else None
    return metrics


def plot_confusion(metrics: Dict[str, object], title: str, path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cm = np.asarray(metrics["confusion_matrix"], dtype=float)
    labels = metrics["labels"]
    norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(1.1 * len(labels) + 2.5, 1.0 * len(labels) + 2))
    im = ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels)), labels, rotation=45, ha="right")
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title(title)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{norm[i, j]:.2f}\n({int(cm[i, j])})", ha="center", va="center",
                    fontsize=7, color="white" if norm[i, j] > 0.5 else "black")
    fig.colorbar(im, ax=ax, fraction=0.046, label="row-normalised (recall)")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def fmt(x, pct=True) -> str:
    if x is None:
        return "n/a"
    return f"{100 * x:.1f}%" if pct else f"{x:.3f}"


def write_report(results: Dict[str, Dict[str, object]], summary: Dict[str, object],
                 out_dir: Path) -> Path:
    """Write metrics.json and a human-readable results.md."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.json").write_text(json.dumps({"dataset": summary, "models": results},
                                                     indent=2), encoding="utf-8")
    lines = [f"# Results: {summary['dataset']}", "",
             f"Train rows: {summary['train_rows']:,}, test rows: {summary['test_rows']:,}, "
             f"features: {summary['features']}.", ""]
    for note in summary.get("notes", []):
        lines.append(f"- {note}")
    has_novel = any("detection_rate_novel_attacks" in m for m in results.values())
    header = "| Model | Accuracy | Macro-F1 | Detection rate | False-alarm rate |"
    sep = "|---|---|---|---|---|"
    if has_novel:
        header += " Detection (known attacks) | Detection (novel attacks) |"
        sep += "---|---|"
    header += " Train time | Inference per 1k flows |"
    sep += "---|---|"
    lines += ["", "## Summary", "", header, sep]
    for name, m in results.items():
        row = (f"| {m['description']} | {fmt(m['accuracy'])} | {fmt(m['macro_f1'])} | "
               f"{fmt(m['detection_rate'])} | {fmt(m['false_alarm_rate'])} |")
        if has_novel:
            row += f" {fmt(m.get('detection_rate_known_attacks'))} | {fmt(m.get('detection_rate_novel_attacks'))} |"
        row += f" {m['train_seconds']:.1f}s | {m['inference_ms_per_1k']:.1f} ms |"
        lines.append(row)
    for name, m in results.items():
        lines += ["", f"## {m['description']}", "", "| Class | Precision | Recall | F1 | Support |",
                  "|---|---|---|---|---|"]
        for c, pc in m["per_class"].items():
            lines.append(f"| {c} | {fmt(pc['precision'])} | {fmt(pc['recall'])} | {fmt(pc['f1'])} | "
                         f"{pc['support']:,} |")
        if m.get("confusion_png"):
            lines += ["", f"![Confusion matrix]({m['confusion_png']})"]
    path = out_dir / "results.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
