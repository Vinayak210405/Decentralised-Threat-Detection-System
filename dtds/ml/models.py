"""Classifier definitions. Each is wrapped with the preprocessor in one Pipeline
so the saved model takes raw flow records and nothing can drift between
training and inference."""
from __future__ import annotations

from typing import Dict

from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline

from dtds.ml.preprocess import build_preprocessor

MODEL_DESCRIPTIONS: Dict[str, str] = {
    "logreg": "Logistic regression, class-balanced (linear baseline)",
    "rf": "Random forest, 200 trees, balanced class weights per bootstrap",
    "hgb": "Histogram gradient boosting, balanced class weights",
    "mlp": "Multi-layer perceptron (128-64), Adam, early stopping",
}


def make_estimator(name: str, seed: int = 42):
    if name == "logreg":
        return LogisticRegression(max_iter=3000, class_weight="balanced", random_state=seed)
    if name == "rf":
        return RandomForestClassifier(n_estimators=200, class_weight="balanced_subsample",
                                      n_jobs=-1, random_state=seed)
    if name == "hgb":
        return HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1,
                                              class_weight="balanced", early_stopping=True,
                                              random_state=seed)
    if name == "mlp":
        # MLPClassifier has no class_weight; rare classes are handled by the
        # evaluation reporting per-class recall rather than hidden in accuracy.
        return MLPClassifier(hidden_layer_sizes=(128, 64), alpha=1e-4, batch_size=256,
                             max_iter=200, early_stopping=True, n_iter_no_change=8,
                             random_state=seed)
    raise ValueError(f"Unknown model {name!r}; choose from {sorted(MODEL_DESCRIPTIONS)}")


def make_pipeline(name: str, categorical, numeric, seed: int = 42) -> Pipeline:
    # Trees split on raw thresholds, so scaling is unnecessary for them, but the
    # log transform is harmless and keeps all models on the same features.
    return Pipeline([
        ("preprocess", build_preprocessor(categorical, numeric)),
        ("model", make_estimator(name, seed)),
    ])
