"""Federated learning (FedAvg) across simulated companies.

Each company ("client") trains the same neural network on its own traffic and
sends only model weights to an aggregator, never raw flows. The aggregator
averages the weights (weighted by how many samples each client has) and sends
the new global model back. Repeat for R rounds.

Why this matters for the project: in reality company A has seen DoS floods,
company B port scans, company C credential attacks. A model trained only on
its own data cannot recognise attack types that company has never seen. The
experiment below measures exactly that gap and how much FedAvg closes it.

Preprocessing is federated too: numeric scaling statistics are aggregated from
per-client (count, sum, sum of squares), so no client reveals raw values. The
union of categorical values (e.g. protocol names like "tcp", service names like
"http") is shared, which reveals only which protocols a company runs.

Run::

    python -m dtds.ml.federated --dataset nsl-kdd --partition by-attack
    python -m dtds.ml.federated --dataset nsl-kdd --partition dirichlet --alpha 0.3
"""
from __future__ import annotations

import argparse
import copy
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.neural_network import MLPClassifier

from dtds.ml import datasets
from dtds.ml.datasets import NORMAL, Dataset
from dtds.ml.evaluate import compute_metrics, fmt
from dtds.ml.preprocess import signed_log1p
from dtds.paths import REPORTS_DIR, ensure


# --------------------------------------------------------------------------- #
# Federated preprocessing
# --------------------------------------------------------------------------- #
@dataclass
class ClientStats:
    n: int
    sum: np.ndarray
    sumsq: np.ndarray
    categories: Dict[str, set]


class FederatedPreprocessor:
    """Signed-log + standard scaling + one-hot, fitted from aggregated client statistics."""

    def __init__(self, categorical: Sequence[str], numeric: Sequence[str]):
        self.categorical = list(categorical)
        self.numeric = list(numeric)
        self.mean_: Optional[np.ndarray] = None
        self.std_: Optional[np.ndarray] = None
        self.categories_: Dict[str, List[str]] = {}

    def client_stats(self, X: pd.DataFrame) -> ClientStats:
        """Computed locally by each client; only these aggregates leave the company."""
        v = signed_log1p(X[self.numeric].to_numpy())
        return ClientStats(len(v), v.sum(axis=0), (v ** 2).sum(axis=0),
                           {c: set(X[c].astype(str).unique()) for c in self.categorical})

    def fit_from_stats(self, stats: Sequence[ClientStats]) -> "FederatedPreprocessor":
        n = sum(s.n for s in stats)
        total = sum(s.sum for s in stats)
        total_sq = sum(s.sumsq for s in stats)
        self.mean_ = total / n
        var = np.maximum(total_sq / n - self.mean_ ** 2, 0.0)
        self.std_ = np.where(var > 1e-12, np.sqrt(var), 1.0)
        for c in self.categorical:
            self.categories_[c] = sorted(set().union(*(s.categories[c] for s in stats)))
        return self

    def fit(self, X: pd.DataFrame) -> "FederatedPreprocessor":
        return self.fit_from_stats([self.client_stats(X)])

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        num = (signed_log1p(X[self.numeric].to_numpy()) - self.mean_) / self.std_
        blocks = [num]
        for c in self.categorical:
            cats = self.categories_[c]
            idx = {v: i for i, v in enumerate(cats)}
            onehot = np.zeros((len(X), len(cats)))
            cols = X[c].astype(str).map(idx)
            rows = np.flatnonzero(cols.notna().to_numpy())
            onehot[rows, cols.dropna().astype(int).to_numpy()] = 1.0
            blocks.append(onehot)
        return np.hstack(blocks).astype(np.float32)


# --------------------------------------------------------------------------- #
# Partitioning the training set across companies
# --------------------------------------------------------------------------- #
def partition_by_attack(y: pd.Series, groups: List[List[str]], seed: int) -> List[np.ndarray]:
    """Each client gets an equal share of Normal traffic plus only its assigned
    attack categories (pathological non-IID: the realistic worst case)."""
    rng = np.random.default_rng(seed)
    y = np.asarray(y)
    normal_idx = rng.permutation(np.flatnonzero(y == NORMAL))
    normal_parts = np.array_split(normal_idx, len(groups))
    parts = []
    for k, cats in enumerate(groups):
        attack_idx = np.flatnonzero(np.isin(y, cats))
        parts.append(rng.permutation(np.concatenate([normal_parts[k], attack_idx])))
    return parts


def partition_dirichlet(y: pd.Series, n_clients: int, alpha: float, seed: int) -> List[np.ndarray]:
    """Label-skewed split: for each class, client shares are drawn from Dir(alpha).
    Small alpha (0.1) = highly skewed, large alpha (100) = close to IID."""
    rng = np.random.default_rng(seed)
    y = np.asarray(y)
    buckets: List[List[int]] = [[] for _ in range(n_clients)]
    for c in np.unique(y):
        idx = rng.permutation(np.flatnonzero(y == c))
        shares = rng.dirichlet([alpha] * n_clients)
        cuts = (np.cumsum(shares)[:-1] * len(idx)).astype(int)
        for k, chunk in enumerate(np.split(idx, cuts)):
            buckets[k].extend(chunk.tolist())
    return [rng.permutation(np.array(b, dtype=int)) for b in buckets]


def default_attack_groups(classes: List[str], n_clients: int) -> List[List[str]]:
    attacks = [c for c in classes if c != NORMAL]
    groups = [list(g) for g in np.array_split(np.array(attacks, dtype=object), n_clients)]
    return [[str(a) for a in g] for g in groups]


# --------------------------------------------------------------------------- #
# FedAvg
# --------------------------------------------------------------------------- #
def new_mlp(seed: int) -> MLPClassifier:
    return MLPClassifier(hidden_layer_sizes=(128, 64), alpha=1e-4, batch_size=256,
                         learning_rate_init=1e-3, random_state=seed)


def init_model(n_features: int, classes: List[str], seed: int) -> MLPClassifier:
    """Create weights for the right shapes. One partial_fit call on a single
    all-zero row per class initialises the layers; it reveals no client data."""
    import warnings
    model = new_mlp(seed)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # "batch_size larger than sample size" for the tiny init batch
        model.partial_fit(np.zeros((len(classes), n_features), dtype=np.float32), np.array(classes),
                          classes=np.array(classes))
    return model


def get_weights(m: MLPClassifier):
    return [w.copy() for w in m.coefs_], [b.copy() for b in m.intercepts_]


def set_weights(m: MLPClassifier, weights) -> None:
    coefs, intercepts = weights
    m.coefs_ = [w.copy() for w in coefs]
    m.intercepts_ = [b.copy() for b in intercepts]


def fedavg(updates: Sequence[tuple], aggregation: str = "samples") -> tuple:
    """updates: [((coefs, intercepts), n_samples), ...] -> weighted mean of weights.

    aggregation="samples" is standard FedAvg (weight = client's sample count).
    aggregation="uniform" gives every company an equal vote, so one large
    company cannot drown out the rare attacks only smaller companies have seen.
    """
    if aggregation == "uniform":
        updates = [(w, 1) for w, _ in updates]
    elif aggregation != "samples":
        raise ValueError(aggregation)
    total = sum(n for _, n in updates)
    coefs = [sum(w[0][i] * (n / total) for w, n in updates) for i in range(len(updates[0][0][0]))]
    intercepts = [sum(w[1][i] * (n / total) for w, n in updates) for i in range(len(updates[0][0][1]))]
    return coefs, intercepts


def balanced_weights(y: np.ndarray) -> np.ndarray:
    """Per-sample weights so every class present in y contributes equally to the
    local loss (mean weight 1). Without this, rare attacks (U2R: 52 rows next to
    22k Normal) are drowned out locally and then again by FedAvg's averaging."""
    classes, inv, counts = np.unique(y, return_inverse=True, return_counts=True)
    return (len(y) / (len(classes) * counts))[inv]


def local_train(model: MLPClassifier, X: np.ndarray, y: np.ndarray, epochs: int,
                rng: np.random.Generator, sample_weight: Optional[np.ndarray] = None) -> None:
    import warnings
    # partial_fit does one pass (in mini-batches) over the data it's given.
    for _ in range(epochs):
        order = rng.permutation(len(X))
        sw = None if sample_weight is None else sample_weight[order]
        with warnings.catch_warnings():
            # A company with fewer rows than one batch is fine; sklearn just clips the batch.
            warnings.filterwarnings("ignore", message=".*batch_size.*")
            model.partial_fit(X[order], y[order], sample_weight=sw)


def train_federated(client_data, classes, n_features, rounds, local_epochs, seed,
                    eval_fn=None, eval_every=1, balanced=True, aggregation="samples"):
    rng = np.random.default_rng(seed)
    global_model = init_model(n_features, classes, seed)
    # Each client keeps a persistent model object (and its Adam optimiser state);
    # at the start of every round its weights are overwritten with the global ones.
    clients = [copy.deepcopy(global_model) for _ in client_data]
    weights = [balanced_weights(y) if balanced else None for _, y in client_data]
    history = []
    for r in range(1, rounds + 1):
        g = get_weights(global_model)
        updates = []
        for model, (X, y), sw in zip(clients, client_data, weights):
            set_weights(model, g)
            local_train(model, X, y, local_epochs, rng, sw)
            updates.append((get_weights(model), len(X)))
        set_weights(global_model, fedavg(updates, aggregation))
        if eval_fn and (r % eval_every == 0 or r == rounds):
            history.append({"round": r, **eval_fn(global_model)})
    return global_model, history


def train_single(X, y, classes, n_features, epochs, seed, eval_fn=None, eval_every=1,
                 balanced=True):
    rng = np.random.default_rng(seed)
    model = init_model(n_features, classes, seed)
    sw = balanced_weights(y) if balanced else None
    history = []
    for e in range(1, epochs + 1):
        local_train(model, X, y, 1, rng, sw)
        if eval_fn and (e % eval_every == 0 or e == epochs):
            history.append({"round": e, **eval_fn(model)})
    return model, history


# --------------------------------------------------------------------------- #
# Experiment
# --------------------------------------------------------------------------- #
def run_experiment(ds: Dataset, n_clients: int = 3, partition: str = "by-attack",
                   alpha: float = 0.3, rounds: int = 30, local_epochs: int = 1, seed: int = 42,
                   out_dir: Optional[Path] = None, eval_every: int = 1,
                   balanced: bool = True, aggregation: str = "samples") -> Dict[str, object]:
    classes = ds.classes
    if partition == "by-attack":
        groups = default_attack_groups(classes, n_clients)
        parts = partition_by_attack(ds.y_train, groups, seed)
        part_desc = {f"company_{chr(65 + k)}": ["Normal"] + g for k, g in enumerate(groups)}
    elif partition == "dirichlet":
        parts = partition_dirichlet(ds.y_train, n_clients, alpha, seed)
        part_desc = {f"company_{chr(65 + k)}": f"Dirichlet(alpha={alpha}) label skew"
                     for k in range(n_clients)}
    elif partition == "iid":
        parts = np.array_split(np.random.default_rng(seed).permutation(len(ds.y_train)), n_clients)
        part_desc = {f"company_{chr(65 + k)}": "IID random split" for k in range(n_clients)}
    else:
        raise ValueError(partition)
    names = [f"company_{chr(65 + k)}" for k in range(n_clients)]

    raw_clients = [(ds.X_train.iloc[p], ds.y_train.iloc[p].to_numpy()) for p in parts]
    client_counts = {n: {k: int(v) for k, v in pd.Series(y).value_counts().items()}
                     for n, (_, y) in zip(names, raw_clients)}

    def evaluator(prep: FederatedPreprocessor):
        Xte = prep.transform(ds.X_test)

        def fn(model):
            pred = model.predict(Xte)
            m = compute_metrics(ds.y_test, pred, classes, ds.y_test_detail, ds.novel_test_labels)
            return {"accuracy": m["accuracy"], "macro_f1": m["macro_f1"],
                    "detection_rate": m["detection_rate"], "false_alarm_rate": m["false_alarm_rate"]}
        return fn, Xte

    def final_metrics(model, Xte, extra=None):
        m = compute_metrics(ds.y_test, model.predict(Xte), classes, ds.y_test_detail,
                            ds.novel_test_labels)
        m.pop("confusion_matrix")
        if extra:
            m.update(extra)
        return m

    results: Dict[str, object] = {}
    curves: Dict[str, list] = {}

    # 1) Federated: preprocessing from aggregated stats, then FedAvg.
    prep = FederatedPreprocessor(ds.categorical, ds.numeric)
    prep.fit_from_stats([prep.client_stats(X) for X, _ in raw_clients])
    client_data = [(prep.transform(X), y) for X, y in raw_clients]
    fn, Xte = evaluator(prep)
    t0 = time.perf_counter()
    fed_model, curves["federated"] = train_federated(client_data, classes, Xte.shape[1], rounds,
                                                     local_epochs, seed, fn, eval_every, balanced,
                                                     aggregation)
    results["federated"] = final_metrics(fed_model, Xte, {"train_seconds": time.perf_counter() - t0})
    print(f"  federated   macroF1={results['federated']['macro_f1']:.4f}")

    # 2) Centralised upper bound: all data pooled in one place (what privacy forbids).
    cprep = FederatedPreprocessor(ds.categorical, ds.numeric).fit(ds.X_train)
    fn_c, Xte_c = evaluator(cprep)
    t0 = time.perf_counter()
    c_model, curves["centralised"] = train_single(cprep.transform(ds.X_train), ds.y_train.to_numpy(),
                                                  classes, Xte_c.shape[1], rounds * local_epochs,
                                                  seed, fn_c, eval_every, balanced)
    results["centralised"] = final_metrics(c_model, Xte_c, {"train_seconds": time.perf_counter() - t0})
    print(f"  centralised macroF1={results['centralised']['macro_f1']:.4f}")

    # 3) Local-only: each company alone, same training budget.
    for name, (X, y) in zip(names, raw_clients):
        lprep = FederatedPreprocessor(ds.categorical, ds.numeric).fit(X)
        fn_l, Xte_l = evaluator(lprep)
        t0 = time.perf_counter()
        l_model, curves[name] = train_single(lprep.transform(X), y, classes, Xte_l.shape[1],
                                             rounds * local_epochs, seed, fn_l, eval_every, balanced)
        results[f"local_{name}"] = final_metrics(l_model, Xte_l,
                                                 {"train_seconds": time.perf_counter() - t0})
        print(f"  local {name} macroF1={results[f'local_{name}']['macro_f1']:.4f}")

    # Recall on attack categories each company never saw locally, local vs federated.
    unseen_gain = {}
    for name in names:
        seen = set(client_counts[name])
        unseen = [c for c in classes if c not in seen]
        if not unseen:
            continue
        loc = results[f"local_{name}"]["per_class"]
        fed = results["federated"]["per_class"]
        sup = {c: fed[c]["support"] for c in unseen}
        tot = sum(sup.values())
        unseen_gain[name] = {
            "unseen_categories": unseen,
            "local_recall": sum(loc[c]["recall"] * sup[c] for c in unseen) / tot if tot else None,
            "federated_recall": sum(fed[c]["recall"] * sup[c] for c in unseen) / tot if tot else None,
        }

    report = {
        "dataset": ds.name, "partition": partition, "alpha": alpha if partition == "dirichlet" else None,
        "n_clients": n_clients, "rounds": rounds, "local_epochs": local_epochs, "seed": seed,
        "model": "MLP 128-64 (sklearn MLPClassifier, Adam), FedAvg weighted by sample count",
        "class_balanced_loss": balanced, "aggregation": aggregation,
        "clients": part_desc, "client_class_counts": client_counts,
        "results": results, "unseen_category_recall": unseen_gain, "curves": curves,
    }
    if out_dir:
        write_fl_report(report, ensure(Path(out_dir)))
    return report


def write_fl_report(report: Dict[str, object], out_dir: Path) -> None:
    tag = report["partition"] + (f"-a{report['alpha']}" if report["alpha"] else "")
    if report.get("aggregation", "samples") != "samples":
        tag += "-" + report["aggregation"]
    if not report.get("class_balanced_loss", True):
        tag += "-unbalanced"
    (out_dir / f"federated_{tag}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 4))
    for name, hist in report["curves"].items():
        if not hist:
            continue
        style = "-" if name in ("federated", "centralised") else ":"
        ax.plot([h["round"] for h in hist], [h["macro_f1"] for h in hist], style,
                label=name.replace("_", " "), linewidth=2 if name == "federated" else 1.2)
    ax.set_xlabel("round (federated) / epoch (single-site)")
    ax.set_ylabel("macro-F1 on test set")
    ax.set_title(f"{report['dataset']}: FedAvg vs local-only vs centralised ({report['partition']})")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    png = f"federated_{tag}.png"
    fig.savefig(out_dir / png, dpi=130)
    plt.close(fig)

    R = report["results"]
    lines = [f"# Federated learning: {report['dataset']}, partition = {report['partition']}"
             + (f" (alpha={report['alpha']})" if report["alpha"] else ""), "",
             f"{report['n_clients']} simulated companies, {report['rounds']} rounds x "
             f"{report['local_epochs']} local epoch(s). Model: {report['model']}; "
             f"class-balanced local loss: {'yes' if report.get('class_balanced_loss') else 'no'}; "
             f"aggregation weights: {report.get('aggregation', 'samples')}. "
             f"Local-only and centralised models get the same number of epochs.", "",
             "## What each company saw", "", "| Company | Training data |", "|---|---|"]
    for name, desc in report["clients"].items():
        counts = report["client_class_counts"][name]
        lines.append(f"| {name} | " + ", ".join(f"{k}: {v:,}" for k, v in counts.items()) + " |")
    has_novel = "detection_rate_novel_attacks" in R["federated"]
    lines += ["", "## Results on the full test set", "",
              "| Setting | Accuracy | Macro-F1 | Detection rate | False-alarm rate |"
              + (" Detection (novel attacks) |" if has_novel else ""),
              "|---|---|---|---|---|" + ("---|" if has_novel else "")]
    order = ["centralised", "federated"] + [k for k in R if k.startswith("local_")]
    for k in order:
        m = R[k]
        row = (f"| {k.replace('_', ' ')} | {fmt(m['accuracy'])} | {fmt(m['macro_f1'])} | "
               f"{fmt(m['detection_rate'])} | {fmt(m['false_alarm_rate'])} |")
        if has_novel:
            row += f" {fmt(m.get('detection_rate_novel_attacks'))} |"
        lines.append(row)
    if report["unseen_category_recall"]:
        lines += ["", "## Recall on attack categories a company never saw locally", "",
                  "| Company | Never saw | Local-only recall | Federated recall |", "|---|---|---|---|"]
        for name, g in report["unseen_category_recall"].items():
            lines.append(f"| {name} | {', '.join(g['unseen_categories'])} | "
                         f"{fmt(g['local_recall'])} | {fmt(g['federated_recall'])} |")
    lines += ["", f"![macro-F1 per round]({png})", ""]
    (out_dir / f"federated_{tag}.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Report: {out_dir / f'federated_{tag}.md'}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="nsl-kdd", choices=sorted(datasets.LOADERS))
    ap.add_argument("--partition", default="by-attack", choices=["by-attack", "dirichlet", "iid"])
    ap.add_argument("--alpha", type=float, default=0.3, help="Dirichlet concentration")
    ap.add_argument("--clients", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--local-epochs", type=int, default=1)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--unbalanced", action="store_true", help="plain loss, no class weighting")
    ap.add_argument("--aggregation", default="samples", choices=["samples", "uniform"],
                    help="FedAvg weights: by client sample count (standard) or equal per client")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    ds = datasets.load(args.dataset)
    out = args.out or REPORTS_DIR / "ml" / ds.name
    print(f"[{ds.name}] FedAvg, {args.clients} clients, partition={args.partition}")
    run_experiment(ds, args.clients, args.partition, args.alpha, args.rounds, args.local_epochs,
                   args.seed, out, balanced=not args.unbalanced,
                   aggregation=args.aggregation)


if __name__ == "__main__":
    main()
