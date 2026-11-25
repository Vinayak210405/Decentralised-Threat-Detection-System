"""Feature preprocessing: one-hot encoding, a signed log transform and scaling.

Network-flow features (byte counts, durations, packet counts) are extremely
heavy-tailed: a handful of flows carry millions of bytes while most carry a few
hundred. A signed ``log1p`` compresses that range before standard scaling so a
few huge flows do not dominate distance- and gradient-based models (MLP,
logistic regression). Tree models do not need it but are not hurt by it.
"""
from __future__ import annotations

from typing import List

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler


def signed_log1p(x):
    x = np.asarray(x, dtype=np.float64)
    return np.sign(x) * np.log1p(np.abs(x))


def build_preprocessor(categorical: List[str], numeric: List[str], log_transform: bool = True,
                       scale: bool = True) -> ColumnTransformer:
    numeric_steps = []
    if log_transform:
        numeric_steps.append(("log", FunctionTransformer(signed_log1p, feature_names_out="one-to-one")))
    if scale:
        numeric_steps.append(("scale", StandardScaler()))
    if not numeric_steps:
        numeric_steps.append(("identity", "passthrough"))
    transformers = [("num", Pipeline(numeric_steps), numeric)]
    if categorical:
        # Unknown categories at test time (e.g. a service never seen in training)
        # become an all-zero vector instead of crashing.
        transformers.append(("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                             categorical))
    return ColumnTransformer(transformers, verbose_feature_names_out=False)
