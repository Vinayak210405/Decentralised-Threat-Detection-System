"""Privacy for federated learning: secure aggregation + differential privacy.

Plain FedAvg shares each company's model update with the aggregator. Updates
are not raw data, but research has shown they can leak it (e.g. reconstructing
training examples from gradients). Two standard protections, combined:

1. SECURE AGGREGATION (the aggregator learns only the SUM of updates)
   Every pair of companies agrees on a secret with an X25519 key exchange (the
   aggregator only relays public keys). From that secret both derive the same
   pseudo-random mask with ChaCha20. Company i ADDS the mask it shares with j,
   company j SUBTRACTS it; summed, every mask cancels exactly. Arithmetic is done
   on fixed-point integers modulo 2^32 so the cancellation is exact, not
   approximate. Each masked update on its own is indistinguishable from random.
   Simplification: no dropout recovery (the full protocol, Bonawitz et al. 2017,
   secret-shares the keys so the sum survives a company going offline).

2. DIFFERENTIAL PRIVACY (the trained model reveals little about any one company)
   Each update is clipped to norm C, so no company can move the model by more
   than C. Each company adds Gaussian noise with variance (sigma*C)^2 / K, so the
   SUM carries noise of standard deviation sigma*C: "distributed" DP, where no
   one, not even the aggregator, ever sees an un-noised update. The guarantee is
   client-level: an outsider looking at the final model cannot tell (beyond
   epsilon) whether any given company took part at all.
   The privacy budget epsilon is computed with a Renyi-DP accountant for the
   Gaussian mechanism (Mironov 2017), composed over all rounds.

The catch, measured by ``python -m dtds.ml.private_fl``: the noise on the
average shrinks with the number of companies (sigma*C/K), so strong privacy is
only affordable with many participants.
"""
from __future__ import annotations

import argparse
import copy
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from dtds.ml import datasets
from dtds.ml.datasets import Dataset
from dtds.ml.evaluate import compute_metrics
from dtds.ml.federated import (FederatedPreprocessor, balanced_weights, get_weights, init_model,
                               local_train, partition_dirichlet, set_weights)
from dtds.paths import REPORTS_DIR, ensure

MOD = 1 << 32
SCALE = 1 << 16          # fixed point: 16 fractional bits
HALF = 1 << 31


# --------------------------------------------------------------------------- #
# Weight vectors
# --------------------------------------------------------------------------- #
def flatten(weights) -> np.ndarray:
    coefs, intercepts = weights
    return np.concatenate([w.ravel() for w in coefs] + [b.ravel() for b in intercepts]).astype(np.float64)


def unflatten(vec: np.ndarray, like) -> tuple:
    coefs, intercepts = like
    out_c, out_i, k = [], [], 0
    for w in coefs:
        out_c.append(vec[k:k + w.size].reshape(w.shape)); k += w.size
    for b in intercepts:
        out_i.append(vec[k:k + b.size].reshape(b.shape)); k += b.size
    return out_c, out_i


# --------------------------------------------------------------------------- #
# Secure aggregation
# --------------------------------------------------------------------------- #
def encode(x: np.ndarray) -> np.ndarray:
    """Real numbers -> fixed-point integers mod 2^32 (two's complement)."""
    q = np.round(x * SCALE).astype(np.int64)
    if np.abs(q).max(initial=0) >= HALF:
        raise OverflowError("value too large for fixed-point encoding")
    return (q % MOD).astype(np.uint64)


def decode(q: np.ndarray) -> np.ndarray:
    q = q.astype(np.int64)
    return np.where(q >= HALF, q - MOD, q).astype(np.float64) / SCALE


class SecAggClient:
    def __init__(self, index: int):
        self.index = index
        self._key = X25519PrivateKey.generate()
        self.public_key = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def _mask(self, peer_public: bytes, round_no: int, size: int) -> np.ndarray:
        shared = self._key.exchange(X25519PublicKey.from_public_bytes(peer_public))
        seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=f"dtds-secagg-round-{round_no}".encode()).derive(shared)
        stream = Cipher(algorithms.ChaCha20(seed, b"\x00" * 16), mode=None).encryptor()
        raw = stream.update(b"\x00" * (4 * size))
        return np.frombuffer(raw, dtype="<u4").astype(np.uint64)

    def mask(self, vec: np.ndarray, public_keys: Dict[int, bytes], round_no: int) -> np.ndarray:
        """encode(vec) + sum of pairwise masks (added for higher-index peers,
        subtracted for lower-index peers), all mod 2^32."""
        out = encode(vec)
        for j, pk in public_keys.items():
            if j == self.index:
                continue
            m = self._mask(pk, round_no, vec.size)
            out = (out + m) % MOD if self.index < j else (out + MOD - m) % MOD
        return out


def secure_sum(masked: Sequence[np.ndarray]) -> np.ndarray:
    """What the aggregator computes: masks cancel, only the sum is revealed."""
    total = np.zeros_like(masked[0])
    for m in masked:
        total = (total + m) % MOD
    return decode(total)


# --------------------------------------------------------------------------- #
# Differential privacy
# --------------------------------------------------------------------------- #
def clip(update: np.ndarray, c: float) -> Tuple[np.ndarray, bool]:
    norm = float(np.linalg.norm(update))
    return (update * (c / norm), True) if norm > c else (update, False)


def gaussian_epsilon(sigma: float, rounds: int, delta: float = 1e-5) -> float:
    """(epsilon, delta)-DP of `rounds` Gaussian mechanisms with noise multiplier
    sigma (noise std / sensitivity), via Renyi DP: RDP(a) = rounds * a / (2 sigma^2),
    epsilon = min_a RDP(a) + log(1/delta) / (a - 1). No subsampling (every company
    takes part every round)."""
    if sigma <= 0:
        return math.inf
    alphas = np.concatenate([np.linspace(1.01, 10, 900), np.linspace(10, 512, 2000)])
    eps = rounds * alphas / (2 * sigma ** 2) + math.log(1 / delta) / (alphas - 1)
    return float(eps.min())


@dataclass
class PrivacyConfig:
    clip_norm: float = 1.0
    noise_multiplier: float = 0.0   # sigma; 0 = no DP noise (secure aggregation only)
    secure_aggregation: bool = True
    delta: float = 1e-5


def train_private(client_data, classes, n_features, rounds, cfg: PrivacyConfig, seed: int = 42,
                  local_epochs: int = 1, eval_fn=None):
    """FedAvg where each round's update goes: local training -> clip -> add noise
    share -> mask -> aggregator sums -> average applied to the global model.
    Aggregation is uniform over companies (a sample-count weight would let one
    company's influence exceed the clip bound)."""
    rng = np.random.default_rng(seed)
    noise_rng = np.random.default_rng(seed + 1)
    k = len(client_data)
    global_model = init_model(n_features, classes, seed)
    clients = [copy.deepcopy(global_model) for _ in client_data]
    weights = [balanced_weights(y) for _, y in client_data]
    sec = [SecAggClient(i) for i in range(k)] if cfg.secure_aggregation else None
    pubs = {c.index: c.public_key for c in sec} if sec else None
    history, clipped, norms = [], 0, []
    for r in range(1, rounds + 1):
        g = get_weights(global_model)
        g_vec = flatten(g)
        contributions = []
        for i, (model, (X, y), sw) in enumerate(zip(clients, client_data, weights)):
            set_weights(model, g)
            local_train(model, X, y, local_epochs, rng, sw)
            update = flatten(get_weights(model)) - g_vec
            norms.append(float(np.linalg.norm(update)))
            update, was_clipped = clip(update, cfg.clip_norm)
            clipped += was_clipped
            if cfg.noise_multiplier > 0:
                update = update + noise_rng.normal(0, cfg.noise_multiplier * cfg.clip_norm / math.sqrt(k),
                                                   update.size)
            contributions.append(sec[i].mask(update, pubs, r) if sec else update)
        total = secure_sum(contributions) if sec else np.sum(contributions, axis=0)
        set_weights(global_model, unflatten(g_vec + total / k, g))
        if eval_fn:
            history.append({"round": r, **eval_fn(global_model)})
    stats = {"updates_clipped": clipped / (rounds * k), "update_norm_median": float(np.median(norms)),
             "epsilon": gaussian_epsilon(cfg.noise_multiplier, rounds, cfg.delta), "delta": cfg.delta}
    return global_model, history, stats


# --------------------------------------------------------------------------- #
# Experiment: privacy vs accuracy vs number of companies
# --------------------------------------------------------------------------- #
def run_grid(ds: Dataset, client_counts=(3, 10, 30), sigmas=(0.0, 1.0, 3.0, 6.0), rounds: int = 30,
             clip_norm: float = 1.0, alpha: float = 0.5, seed: int = 42) -> Dict[str, object]:
    classes = ds.classes
    results = []
    for k in client_counts:
        parts = partition_dirichlet(ds.y_train, k, alpha, seed)
        raw = [(ds.X_train.iloc[p], ds.y_train.iloc[p].to_numpy()) for p in parts]
        prep = FederatedPreprocessor(ds.categorical, ds.numeric)
        prep.fit_from_stats([prep.client_stats(X) for X, _ in raw])
        data = [(prep.transform(X), y) for X, y in raw if len(X)]
        Xte = prep.transform(ds.X_test)
        for sigma in sigmas:
            cfg = PrivacyConfig(clip_norm=clip_norm, noise_multiplier=sigma)
            model, _, stats = train_private(data, classes, Xte.shape[1], rounds, cfg, seed)
            m = compute_metrics(ds.y_test, model.predict(Xte), classes)
            row = {"companies": k, "sigma": sigma, "epsilon": stats["epsilon"],
                   "macro_f1": m["macro_f1"], "accuracy": m["accuracy"],
                   "detection_rate": m["detection_rate"], "false_alarm_rate": m["false_alarm_rate"],
                   "noise_std_on_average": sigma * clip_norm / k, **stats}
            results.append(row)
            print(f"  K={k:3d} sigma={sigma:4.1f} eps={stats['epsilon']:8.2f} macroF1={m['macro_f1']:.3f} "
                  f"detect={m['detection_rate']:.3f} FAR={m['false_alarm_rate']:.3f} "
                  f"clipped={stats['updates_clipped']:.0%}")
    return {"dataset": ds.name, "rounds": rounds, "clip_norm": clip_norm, "dirichlet_alpha": alpha,
            "delta": 1e-5, "seed": seed, "results": results}


def write_report(res: Dict[str, object], out_dir: Path) -> Path:
    out_dir = ensure(out_dir)
    (out_dir / "private_fl.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    rows = res["results"]
    ks = sorted({r["companies"] for r in rows})
    sigmas = sorted({r["sigma"] for r in rows})

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for k in ks:
        pts = [r for r in rows if r["companies"] == k]
        ax.plot([r["sigma"] for r in pts], [100 * r["macro_f1"] for r in pts], "-o", label=f"{k} companies")
    ax.set_xlabel("noise multiplier sigma (more noise = stronger privacy)")
    ax.set_ylabel("macro-F1 on test set (%)")
    ax.set_title(f"{res['dataset']}: accuracy cost of differential privacy")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "private_fl.png", dpi=130)
    plt.close(fig)

    def eps(s):
        e = next(r["epsilon"] for r in rows if r["sigma"] == s)
        return "none (no noise)" if math.isinf(e) else f"{e:.1f}"
    lines = [f"# Private federated learning: {res['dataset']}", "",
             f"Secure aggregation (X25519 + ChaCha20 pairwise masks) in every run; differential privacy "
             f"by clipping each company's update to norm {res['clip_norm']} and adding distributed Gaussian "
             f"noise. {res['rounds']} rounds, companies split by Dirichlet(alpha={res['dirichlet_alpha']}) "
             f"label skew, epsilon at delta = {res['delta']} (client-level, Renyi-DP accountant).", "",
             "## Macro-F1 by number of companies and privacy level", "",
             "| Noise multiplier | Epsilon | " + " | ".join(f"{k} companies" for k in ks) + " |",
             "|---|---|" + "---|" * len(ks)]
    for s in sigmas:
        cells = []
        for k in ks:
            r = next(r for r in rows if r["companies"] == k and r["sigma"] == s)
            cells.append(f"{100 * r['macro_f1']:.1f}%")
        lines.append(f"| {s:g} | {eps(s)} | " + " | ".join(cells) + " |")
    lines += ["", "## Attack detection rate / false-alarm rate", "",
              "| Noise multiplier | " + " | ".join(f"{k} companies" for k in ks) + " |",
              "|---|" + "---|" * len(ks)]
    for s in sigmas:
        cells = []
        for k in ks:
            r = next(r for r in rows if r["companies"] == k and r["sigma"] == s)
            cells.append(f"{100 * r['detection_rate']:.1f}% / {100 * r['false_alarm_rate']:.1f}%")
        lines.append(f"| {s:g} | " + " | ".join(cells) + " |")
    clipped = np.mean([r["updates_clipped"] for r in rows])
    lines += ["", f"Updates clipped: {clipped:.0%} on average (median update norm before clipping "
              f"{np.median([r['update_norm_median'] for r in rows]):.2f}).", "",
              "![macro-F1 vs noise](private_fl.png)", ""]
    path = out_dir / "private_fl.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Report: {path}")
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="nsl-kdd", choices=sorted(datasets.LOADERS))
    ap.add_argument("--companies", default="3,10,30")
    ap.add_argument("--sigmas", default="0,1,3,6")
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--clip", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)
    ds = datasets.load(args.dataset)
    print(f"[{ds.name}] private FedAvg grid")
    res = run_grid(ds, [int(x) for x in args.companies.split(",")],
                   [float(x) for x in args.sigmas.split(",")], args.rounds, args.clip, seed=args.seed)
    write_report(res, REPORTS_DIR / "ml" / ds.name)


if __name__ == "__main__":
    main()
