"""Loaders for public network-intrusion datasets.

Every loader returns a :class:`Dataset` with a train/test split, the feature
columns split into categorical and numeric, and a *category* label (e.g. DoS,
Probe) rather than the dozens of fine-grained attack names, because the sharing
layer reports threats by category.

Supported datasets
------------------
* ``nsl-kdd``     - downloaded automatically (~20 MB). Uses the official
                    KDDTrain+/KDDTest+ split; the test set deliberately contains
                    attack types that never appear in training.
* ``unsw-nb15``   - download the "training-set" and "testing-set" CSVs from
                    https://research.unsw.edu.au/projects/unsw-nb15-dataset and
                    put them in ``data/raw/unsw-nb15/``.
* ``cic-ids2017`` - download "MachineLearningCSV.zip" from
                    https://www.unb.ca/cic/datasets/ids-2017.html and extract
                    the CSVs into ``data/raw/cic-ids2017/``.
"""
from __future__ import annotations

import hashlib
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from dtds.paths import RAW_DIR, ensure

NORMAL = "Normal"


@dataclass
class Dataset:
    name: str
    X_train: pd.DataFrame
    y_train: pd.Series
    X_test: pd.DataFrame
    y_test: pd.Series
    categorical: List[str]
    numeric: List[str]
    notes: List[str] = field(default_factory=list)
    # Optional fine-grained test labels, e.g. the original attack name, and the
    # set of those names absent from training ("novel" attacks).
    y_test_detail: Optional[pd.Series] = None
    novel_test_labels: List[str] = field(default_factory=list)

    @property
    def classes(self) -> List[str]:
        labels = set(self.y_train) | set(self.y_test)
        # Normal first, then attacks alphabetically: stable ordering for reports.
        return [NORMAL] + sorted(labels - {NORMAL}) if NORMAL in labels else sorted(labels)

    def as_binary(self) -> "Dataset":
        """Collapse every attack category into a single ``Attack`` label."""
        to_bin = lambda s: s.where(s == NORMAL, "Attack")  # noqa: E731
        return Dataset(self.name + "-binary", self.X_train, to_bin(self.y_train),
                       self.X_test, to_bin(self.y_test), self.categorical,
                       self.numeric, self.notes + ["labels collapsed to Normal/Attack"],
                       self.y_test_detail, self.novel_test_labels)

    def summary(self) -> Dict[str, object]:
        return {
            "dataset": self.name,
            "train_rows": int(len(self.X_train)),
            "test_rows": int(len(self.X_test)),
            "features": len(self.categorical) + len(self.numeric),
            "categorical_features": self.categorical,
            "train_class_counts": {k: int(v) for k, v in self.y_train.value_counts().items()},
            "test_class_counts": {k: int(v) for k, v in self.y_test.value_counts().items()},
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
# NSL-KDD
# --------------------------------------------------------------------------- #
NSL_KDD_URLS = {
    "KDDTrain+.txt": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt",
    "KDDTest+.txt": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt",
}
# SHA-256 of the files the results in reports/ were produced with.
NSL_KDD_SHA256 = {
    "KDDTrain+.txt": "1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95",
    "KDDTest+.txt": "fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84",
}

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack", "difficulty",
]

# Standard grouping of the 39 NSL-KDD attack names into 4 categories.
NSL_KDD_CATEGORIES = {
    "DoS": ["apache2", "back", "land", "mailbomb", "neptune", "pod", "processtable",
            "smurf", "teardrop", "udpstorm", "worm"],
    "Probe": ["ipsweep", "mscan", "nmap", "portsweep", "saint", "satan"],
    "R2L": ["ftp_write", "guess_passwd", "httptunnel", "imap", "multihop", "named", "phf",
            "sendmail", "snmpgetattack", "snmpguess", "spy", "warezclient", "warezmaster",
            "xlock", "xsnoop"],
    "U2R": ["buffer_overflow", "loadmodule", "perl", "ps", "rootkit", "sqlattack", "xterm"],
}
_NSL_LOOKUP = {name: cat for cat, names in NSL_KDD_CATEGORIES.items() for name in names}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download_nsl_kdd(dest: Optional[Path] = None) -> Path:
    dest = ensure(dest or RAW_DIR / "nsl-kdd")
    for fname, url in NSL_KDD_URLS.items():
        target = dest / fname
        if not target.exists():
            print(f"Downloading {fname} ...")
            urllib.request.urlretrieve(url, target)
        digest = _sha256(target)
        if digest != NSL_KDD_SHA256[fname]:
            raise ValueError(f"{target} has SHA-256 {digest}, expected {NSL_KDD_SHA256[fname]}. "
                             "Delete it and download again.")
    return dest


def _nsl_category(attack: str) -> str:
    if attack == "normal":
        return NORMAL
    try:
        return _NSL_LOOKUP[attack]
    except KeyError as e:
        raise ValueError(f"Unknown NSL-KDD attack name: {attack!r}") from e


def load_nsl_kdd(root: Optional[Path] = None) -> Dataset:
    root = download_nsl_kdd(root)
    frames = {}
    for split, fname in (("train", "KDDTrain+.txt"), ("test", "KDDTest+.txt")):
        df = pd.read_csv(root / fname, header=None, names=NSL_KDD_COLUMNS)
        frames[split] = df
    train, test = frames["train"], frames["test"]
    unseen = sorted(set(test["attack"]) - set(train["attack"]))

    def split(df):
        y = df["attack"].map(_nsl_category).rename("label")
        # 'difficulty' is an annotation, not a traffic feature; num_outbound_cmds is constant 0.
        X = df.drop(columns=["attack", "difficulty", "num_outbound_cmds"])
        return X, y

    X_tr, y_tr = split(train)
    X_te, y_te = split(test)
    cat = ["protocol_type", "service", "flag"]
    num = [c for c in X_tr.columns if c not in cat]
    n_unseen = int(test["attack"].isin(unseen).sum())
    notes = [f"official KDDTest+ split; {n_unseen} test rows ({n_unseen / len(test):.1%}) are "
             f"{len(unseen)} attack types never seen in training: {', '.join(unseen)}"]
    return Dataset("nsl-kdd", X_tr, y_tr, X_te, y_te, cat, num, notes,
                   y_test_detail=test["attack"].rename("attack"), novel_test_labels=unseen)


# --------------------------------------------------------------------------- #
# UNSW-NB15
# --------------------------------------------------------------------------- #
def load_unsw_nb15(root: Optional[Path] = None) -> Dataset:
    root = Path(root or RAW_DIR / "unsw-nb15")
    files = {s: next(iter(sorted(root.glob(f"*{s}*set*.csv"))), None) for s in ("training", "testing")}
    if not all(files.values()):
        raise FileNotFoundError(
            f"Put UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv in {root}. "
            "Download: https://research.unsw.edu.au/projects/unsw-nb15-dataset")

    def split(path):
        df = pd.read_csv(path)
        df.columns = [c.strip() for c in df.columns]
        y = df["attack_cat"].fillna("Normal").astype(str).str.strip()
        y = y.replace({"Backdoors": "Backdoor"}).rename("label")
        X = df.drop(columns=[c for c in ("id", "label", "attack_cat") if c in df.columns])
        return X, y

    X_tr, y_tr = split(files["training"])
    X_te, y_te = split(files["testing"])
    cat = [c for c in ("proto", "service", "state") if c in X_tr.columns]
    num = [c for c in X_tr.columns if c not in cat]
    return Dataset("unsw-nb15", X_tr, y_tr, X_te, y_te, cat, num,
                   ["official UNSW-NB15 training/testing split"])


# --------------------------------------------------------------------------- #
# CIC-IDS2017
# --------------------------------------------------------------------------- #
def _cic_category(label: str) -> str:
    l = label.lower()
    if l == "benign":
        return NORMAL
    if l.startswith("dos") or l == "ddos" or l == "heartbleed":
        return "DoS"
    if l == "portscan":
        return "Probe"
    if "patator" in l:
        return "BruteForce"
    if l.startswith("web attack"):
        return "WebAttack"
    if l == "bot":
        return "Botnet"
    if l == "infiltration":
        return "Infiltration"
    raise ValueError(f"Unknown CIC-IDS2017 label: {label!r}")


# Identifiers that would let a model memorise hosts instead of learning behaviour.
_CIC_ID_COLUMNS = ["Flow ID", "Source IP", "Src IP", "Destination IP", "Dst IP",
                   "Source Port", "Src Port", "Timestamp"]


def load_cic_ids2017(root: Optional[Path] = None, max_rows: Optional[int] = 600_000,
                     seed: int = 42) -> Dataset:
    root = Path(root or RAW_DIR / "cic-ids2017")
    csvs = sorted(root.glob("*.csv"))
    if not csvs:
        raise FileNotFoundError(
            f"No CSVs in {root}. Download MachineLearningCSV.zip from "
            "https://www.unb.ca/cic/datasets/ids-2017.html and extract it there.")
    parts = []
    for path in csvs:
        df = pd.read_csv(path, encoding="latin-1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        parts.append(df)
    df = pd.concat(parts, ignore_index=True)
    df = df.drop(columns=[c for c in _CIC_ID_COLUMNS if c in df.columns])
    # The dataset's en-dash in "Web Attack – XSS" is often mangled by encodings.
    df["Label"] = df["Label"].astype(str).str.replace(r"[^\x20-\x7e]+", "-", regex=True).str.strip()
    y = df.pop("Label").map(_cic_category).rename("label")
    X = df.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    keep = X.notna().all(axis=1)
    X, y = X[keep], y[keep]
    constant = [c for c in X.columns if X[c].nunique() <= 1]
    X = X.drop(columns=constant)
    notes = [f"{len(csvs)} CSV files, {int((~keep).sum())} rows with NaN/inf dropped, "
             f"{len(constant)} constant columns dropped",
             "no official split: stratified 80/20 split"]
    if max_rows and len(X) > max_rows:
        X, _, y, _ = train_test_split(X, y, train_size=max_rows, stratify=y, random_state=seed)
        notes.append(f"stratified sample of {max_rows} rows (pass max_rows=None for all)")
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=seed)
    return Dataset("cic-ids2017", X_tr, y_tr, X_te, y_te, [], list(X.columns), notes)


LOADERS: Dict[str, Callable[..., Dataset]] = {
    "nsl-kdd": load_nsl_kdd,
    "unsw-nb15": load_unsw_nb15,
    "cic-ids2017": load_cic_ids2017,
}


def load(name: str, **kwargs) -> Dataset:
    try:
        return LOADERS[name](**kwargs)
    except KeyError:
        raise ValueError(f"Unknown dataset {name!r}; choose from {sorted(LOADERS)}") from None
