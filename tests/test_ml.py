import numpy as np
import pandas as pd
import pytest

from dtds.ml import federated as F
from dtds.ml.datasets import NSL_KDD_CATEGORIES, Dataset, _nsl_category
from dtds.ml.evaluate import compute_metrics
from dtds.ml.models import make_pipeline
from dtds.ml.train import run


def synthetic(n=600, seed=0):
    """Small separable dataset shaped like a flow table."""
    rng = np.random.default_rng(seed)
    labels = rng.choice(["Normal", "DoS", "Probe"], size=n, p=[0.6, 0.3, 0.1])
    X = pd.DataFrame({
        "src_bytes": np.where(labels == "DoS", 0, rng.integers(100, 5000, n)) + rng.integers(0, 5, n),
        "count": np.where(labels == "DoS", rng.integers(200, 500, n), rng.integers(1, 20, n)),
        "diff_srv_rate": np.where(labels == "Probe", rng.uniform(0.7, 1, n), rng.uniform(0, 0.2, n)),
        "protocol_type": rng.choice(["tcp", "udp", "icmp"], n),
    })
    y = pd.Series(labels, name="label")
    half = n // 2
    return Dataset("synthetic", X[:half], y[:half], X[half:].reset_index(drop=True),
                   y[half:].reset_index(drop=True), ["protocol_type"],
                   ["src_bytes", "count", "diff_srv_rate"])


def test_every_nsl_attack_maps_to_one_category():
    names = [n for ns in NSL_KDD_CATEGORIES.values() for n in ns]
    assert len(names) == len(set(names)) == 39
    assert _nsl_category("normal") == "Normal"
    with pytest.raises(ValueError):
        _nsl_category("not_an_attack")


def test_metrics_binary_view():
    y = ["Normal", "Normal", "DoS", "Probe"]
    p = ["Normal", "DoS", "Probe", "Normal"]
    m = compute_metrics(y, p, ["Normal", "DoS", "Probe"])
    # Attack flagged as the wrong attack category still counts as detected.
    assert m["detection_rate"] == 0.5
    assert m["false_alarm_rate"] == 0.5
    assert m["accuracy"] == 0.25


def test_metrics_novel_attack_split():
    y = pd.Series(["DoS", "DoS", "Normal"])
    detail = pd.Series(["neptune", "mailbomb", "normal"])
    m = compute_metrics(y, ["DoS", "Normal", "Normal"], ["Normal", "DoS"], detail, ["mailbomb"])
    assert m["detection_rate_known_attacks"] == 1.0
    assert m["detection_rate_novel_attacks"] == 0.0


def test_pipeline_handles_unseen_category():
    ds = synthetic()
    pipe = make_pipeline("rf", ds.categorical, ds.numeric).fit(ds.X_train, ds.y_train)
    X = ds.X_test.copy()
    X.loc[0, "protocol_type"] = "sctp"  # never seen in training
    assert len(pipe.predict(X)) == len(X)


def test_train_run_writes_report(tmp_path):
    res = run("synthetic", ["logreg", "hgb"], out_dir=tmp_path, save_models=False, dataset=synthetic())
    assert res["hgb"]["accuracy"] > 0.9
    assert (tmp_path / "results.md").exists() and (tmp_path / "metrics.json").exists()


def test_federated_scaler_equals_centralised_fit():
    """Aggregating per-client sums must give exactly the pooled statistics."""
    ds = synthetic()
    parts = np.array_split(np.arange(len(ds.X_train)), 3)
    prep = F.FederatedPreprocessor(ds.categorical, ds.numeric)
    prep.fit_from_stats([prep.client_stats(ds.X_train.iloc[p]) for p in parts])
    central = F.FederatedPreprocessor(ds.categorical, ds.numeric).fit(ds.X_train)
    np.testing.assert_allclose(prep.mean_, central.mean_)
    np.testing.assert_allclose(prep.std_, central.std_)
    np.testing.assert_allclose(prep.transform(ds.X_test), central.transform(ds.X_test), atol=1e-5)


def test_fedavg_is_sample_weighted_mean():
    w1 = ([np.ones((2, 2))], [np.zeros(2)])
    w2 = ([np.full((2, 2), 4.0)], [np.ones(2)])
    coefs, ints = F.fedavg([(w1, 1), (w2, 3)])
    np.testing.assert_allclose(coefs[0], 3.25)
    np.testing.assert_allclose(ints[0], 0.75)
    coefs_u, _ = F.fedavg([(w1, 1), (w2, 3)], aggregation="uniform")
    np.testing.assert_allclose(coefs_u[0], 2.5)


def test_partition_by_attack_keeps_categories_separate():
    y = pd.Series(["Normal"] * 9 + ["DoS"] * 4 + ["Probe"] * 3)
    parts = F.partition_by_attack(y, [["DoS"], ["Probe"]], seed=0)
    assert set(y.iloc[parts[0]]) == {"Normal", "DoS"}
    assert set(y.iloc[parts[1]]) == {"Normal", "Probe"}
    assert sorted(np.concatenate(parts)) == list(range(len(y)))


def test_balanced_weights_equalise_classes():
    y = np.array(["a"] * 90 + ["b"] * 10)
    w = F.balanced_weights(y)
    assert w[y == "a"].sum() == pytest.approx(w[y == "b"].sum())
    assert w.mean() == pytest.approx(1.0)


def test_federated_experiment_runs(tmp_path):
    ds = synthetic(900)
    r = F.run_experiment(ds, n_clients=2, partition="by-attack", rounds=3, out_dir=tmp_path)
    assert set(r["results"]) == {"federated", "centralised", "local_company_A", "local_company_B"}
    assert list(tmp_path.glob("federated_*.md"))
