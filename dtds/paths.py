"""Filesystem locations used across the project (all relative to the repo root)."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Downloaded datasets live outside version control.
DATA_DIR = Path(os.environ.get("DTDS_DATA_DIR", ROOT / "data"))
RAW_DIR = DATA_DIR / "raw"

# Trained models and per-node state (keys, watchlists) are never committed.
MODELS_DIR = Path(os.environ.get("DTDS_MODELS_DIR", ROOT / "models"))
NODES_DIR = Path(os.environ.get("DTDS_NODES_DIR", ROOT / ".nodes"))

# Evaluation reports ARE committed so results are reviewable.
REPORTS_DIR = ROOT / "reports"

# ZK artifacts (compiled circuit, proving/verification keys).
CIRCUIT_BUILD_DIR = ROOT / "circuits" / "build"


def ensure(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
