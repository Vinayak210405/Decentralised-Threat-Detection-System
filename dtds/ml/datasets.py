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
* ``unsw-nb15``   - downloaded automatically (~47 MB, checksum-verified), or put
                    the official "training-set" and "testing-set" CSVs from
                    https://research.unsw.edu.au/projects/unsw-nb15-dataset in
                    ``data/raw/unsw-nb15/``.
* ``cic-ids2017`` - downloaded automatically (~880 MB, checksum-verified), or
                    put the official MachineLearningCVE CSVs from
                    https://www.unb.ca/cic/datasets/ids-2017.html in
                    ``data/raw/cic-ids2017/``.
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
# SHA-256 of the official CSVs the committed results were produced with.
UNSW_NB15_SHA256 = {
    "UNSW_NB15_training-set.csv": "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
    "UNSW_NB15_testing-set.csv": "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
}


# The official site serves the CSVs through a SharePoint folder that scripts
# can't fetch, so the automatic download uses a GitHub mirror and accepts the
# files ONLY if their SHA-256 matches the hashes above (whose class counts match
# the paper's published counts exactly).
UNSW_NB15_MIRROR = ("https://media.githubusercontent.com/media/jamshaid120/"
                    "UNSW_NB15-Complete-dataset/HEAD/{name}")


def download_unsw_nb15(dest: Optional[Path] = None) -> Path:
    dest = ensure(dest or RAW_DIR / "unsw-nb15")
    for name, digest in UNSW_NB15_SHA256.items():
        target = dest / name
        if not target.exists():
            print(f"Downloading {name} (mirror, checksum-verified) ...")
            urllib.request.urlretrieve(UNSW_NB15_MIRROR.format(name=name), target)
        if _sha256(target) != digest:
            target.unlink()
            raise ValueError(f"{name} failed its SHA-256 check and was deleted. Download the official "
                             "files from https://research.unsw.edu.au/projects/unsw-nb15-dataset instead.")
    return dest


def load_unsw_nb15(root: Optional[Path] = None) -> Dataset:
    """UNSW-NB15 partitioned sets (Moustafa & Slay, 2015).

    Two quirks of the official release are handled here:
    * the files are named the wrong way round: "training-set" has 82,332 rows
      and "testing-set" 175,341, while the paper defines the TRAINING set as
      175,341 records. We follow the paper: train on the larger file.
    * the CSVs start with a UTF-8 byte-order mark, which would otherwise turn
      the first column name into "\\ufeffid".
    """
    root = Path(root or RAW_DIR / "unsw-nb15")
    files = sorted(root.glob("*set*.csv"))
    if not files:
        download_unsw_nb15(root)
        files = sorted(root.glob("*set*.csv"))
    if len(files) != 2:
        raise FileNotFoundError(
            f"Put UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv in {root}. "
            "Download: https://research.unsw.edu.au/projects/unsw-nb15-dataset")
    notes = []
    for f in files:
        expected = UNSW_NB15_SHA256.get(f.name)
        if expected and _sha256(f) != expected:
            notes.append(f"{f.name} differs from the file the committed results used")

    def read(path):
        df = pd.read_csv(path, encoding="utf-8-sig")
        df.columns = [c.strip() for c in df.columns]
        return df

    a, b = (read(f) for f in files)
    train, test = (a, b) if len(a) >= len(b) else (b, a)

    def split(df):
        y = df["attack_cat"].fillna("Normal").astype(str).str.strip()
        y = y.replace({"Backdoors": "Backdoor"}).rename("label")
        X = df.drop(columns=[c for c in ("id", "label", "attack_cat") if c in df.columns])
        return X, y

    X_tr, y_tr = split(train)
    X_te, y_te = split(test)
    cat = [c for c in ("proto", "service", "state") if c in X_tr.columns]
    num = [c for c in X_tr.columns if c not in cat]
    notes.insert(0, "official partitioned sets, following the paper: the 175,341-row file is used "
                    "for training (the release names the files the other way round)")
    return Dataset("unsw-nb15", X_tr, y_tr, X_te, y_te, cat, num, notes,
                   y_test_detail=y_te.rename("attack"))


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

# SHA-256 of the 8 MachineLearningCVE CSVs the committed results were produced
# with. Their label counts match the published totals exactly (2,830,743 rows).
CIC_IDS2017_SHA256 = {
    "Monday-WorkingHours.pcap_ISCX.csv": "852c4beb34eda186f32561fa79df7a0747e92e1a6535b01270820dd9ffe17f34",
    "Tuesday-WorkingHours.pcap_ISCX.csv": "52b8692ae8c7d2ed04671fe2b98335693c0a92c7ab157d8c8b534d6523080851",
    "Wednesday-workingHours.pcap_ISCX.csv": "893c27dc968bf7a8adef1689f90be55ca4a4dc3088fb63d6ff247ac56856df2a",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": "d67066211fb1689c78406f1506f4c44704ecb92088353d5c96d96d6474eb819d",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": "6bcda3857c2504676034e3ea57762d38393cc734cb377a726bd5cb153961b1b5",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": "53a41c24d570ea83b7ac55b2e94df94e7a8216aeb80a2af0246b6bc8bb543000",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": "ca1824c51bfbb7b3c72290a11be04366ba8815878c6a1cc5c44cb1cee269e99b",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": "6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee",
}
# The official site needs a form; scripts use a GitHub mirror and accept files
# ONLY if their SHA-256 matches the hashes above.
CIC_IDS2017_MIRROR = ("https://media.githubusercontent.com/media/2000pawan/"
                      "Cyber-Attack-Threat-Classification/HEAD/MachineLearningCVE/{name}")


def download_cic_ids2017(dest: Optional[Path] = None) -> Path:
    dest = ensure(dest or RAW_DIR / "cic-ids2017")
    for name, digest in CIC_IDS2017_SHA256.items():
        target = dest / name
        if not target.exists():
            print(f"Downloading {name} (mirror, checksum-verified) ...")
            urllib.request.urlretrieve(CIC_IDS2017_MIRROR.format(name=name), target)
        if _sha256(target) != digest:
            target.unlink()
            raise ValueError(f"{name} failed its SHA-256 check and was deleted. Download the official "
                             "files from https://www.unb.ca/cic/datasets/ids-2017.html instead.")
    return dest


def _sample_keep_rare(X: pd.DataFrame, y: pd.Series, max_rows: int, keep_below: int, seed: int):
    """Stratified sample to about max_rows, but classes smaller than keep_below are
    kept whole (a plain stratified sample would leave ~2 Heartbleed rows)."""
    counts = y.value_counts()
    rare = counts[counts < keep_below].index
    n_rare = int(counts[rare].sum())
    frac = min(1.0, (max_rows - n_rare) / max(1, len(y) - n_rare))
    rng = np.random.default_rng(seed)
    keep = y.isin(rare).to_numpy() | (rng.random(len(y)) < frac)
    return X[keep], y[keep]


def load_cic_ids2017(root: Optional[Path] = None, max_rows: Optional[int] = 600_000,
                     seed: int = 42, download: bool = True) -> Dataset:
    """CIC-IDS2017 "MachineLearningCVE" flows (CICFlowMeter features, 5 days).

    Cleaning, each step reported in the notes: identifier columns and the
    duplicated "Fwd Header Length" column are dropped, rows with NaN/inf are
    dropped, and EXACT DUPLICATE rows are removed before splitting. Duplicates
    are a known flaw of this dataset; left in, the same flow lands in both
    train and test and inflates scores. There is no official split, so a
    stratified 80/20 split is used (comparable with the literature, and known
    to be optimistic); the leave-one-family-out test in dtds.ml.novelty is the
    harder one.
    """
    root = Path(root or RAW_DIR / "cic-ids2017")
    csvs = sorted(root.glob("*.csv"))
    if not csvs and download:
        download_cic_ids2017(root)
        csvs = sorted(root.glob("*.csv"))
    if not csvs:
        raise FileNotFoundError(
            f"No CSVs in {root}. Download MachineLearningCSV.zip from "
            "https://www.unb.ca/cic/datasets/ids-2017.html and extract it there.")
    parts = []
    for path in csvs:
        head = pd.read_csv(path, nrows=0, encoding="latin-1")
        dtypes = {c: np.float32 for c in head.columns if c.strip() != "Label"}
        df = pd.read_csv(path, encoding="latin-1", dtype=dtypes)
        df.columns = [c.strip() for c in df.columns]
        parts.append(df)
    df = pd.concat(parts, ignore_index=True)
    n_raw = len(df)
    dup_cols = [c for c in df.columns if c.endswith(".1")]   # pandas' name for the repeated column
    df = df.drop(columns=[c for c in _CIC_ID_COLUMNS + dup_cols if c in df.columns])
    # The dataset's en-dash in "Web Attack – XSS" is mangled by its own encoding.
    df["Label"] = df["Label"].astype(str).str.replace(r"[^\x20-\x7e]+", "-", regex=True).str.strip()
    num = df.columns.drop("Label")
    df[num] = df[num].replace([np.inf, -np.inf], np.nan)
    bad = df[num].isna().any(axis=1)
    df = df[~bad]
    n_before = len(df)
    df = df.drop_duplicates()
    n_dupes = n_before - len(df)
    detail = df.pop("Label")
    y = detail.map(_cic_category).rename("label")
    X = df
    constant = [c for c in X.columns if X[c].nunique() <= 1]
    X = X.drop(columns=constant)
    notes = [f"{len(csvs)} CSV files, {n_raw:,} rows; {int(bad.sum()):,} rows with NaN/inf dropped, "
             f"{n_dupes:,} exact duplicate rows removed, {len(constant)} constant and "
             f"{len(dup_cols)} duplicated columns dropped",
             "no official split: stratified 80/20 split after de-duplication"]
    if max_rows and len(X) > max_rows:
        X, y = _sample_keep_rare(X, y, max_rows, 5000, seed)
        notes.append(f"sample of {len(X):,} rows: classes under 5,000 rows kept whole, the rest sampled "
                     "uniformly (pass max_rows=None for all)")
    detail = detail.loc[X.index].rename("attack")
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=seed)
    return Dataset("cic-ids2017", X_tr, y_tr, X_te, y_te, [], list(X.columns), notes,
                   y_test_detail=detail.loc[X_te.index])


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
