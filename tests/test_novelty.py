import numpy as np
import pandas as pd
import pytest

from dtds.ml.datasets import Dataset
from dtds.ml.novelty import (UNKNOWN, AnomalyScorer, HybridDetector, NormalScale,
                             detection_at_far, evaluate_split, logit)


def synthetic_with_novel(n=3000, seed=0):
    """Normal traffic + two known attack types; a third type ('Novel') sits far
    from normal and appears ONLY in the test set."""
    rng = np.random.default_rng(seed)

    def block(label, k, centre):
        X = pd.DataFrame(rng.normal(centre, 1.0, size=(k, 4)), columns=["a", "b", "c", "d"])
        X["proto"] = rng.choice(["tcp", "udp"], k)
        return X, pd.Series([label] * k, name="label")

    parts_tr = [block("Normal", n, 0), block("DoS", n // 3, (6, 0, 0, 0)), block("Probe", n // 3, (0, 6, 0, 0))]
    parts_te = [block("Normal", n // 2, 0), block("DoS", n // 6, (6, 0, 0, 0)),
                block("Probe", n // 6, (0, 6, 0, 0)), block("Novel", n // 6, (0, 0, -6, 6))]
    Xtr = pd.concat([p[0] for p in parts_tr], ignore_index=True)
    ytr = pd.concat([p[1] for p in parts_tr], ignore_index=True)
    Xte = pd.concat([p[0] for p in parts_te], ignore_index=True)
    yte = pd.concat([p[1] for p in parts_te], ignore_index=True)
    # The Novel rows count as attacks in the binary view; their category is unknowable.
    return Dataset("synthetic-novel", Xtr, ytr, Xte, yte, ["proto"], ["a", "b", "c", "d"],
                   y_test_detail=yte, novel_test_labels=["Novel"])


def test_detection_at_far_handles_ties():
    normal = np.r_[np.zeros(95), np.ones(5)]          # 5% of normals tied at the top score
    attack = np.r_[np.ones(50), np.full(50, 0.5)]
    d = detection_at_far(normal, attack, fars=(0.01, 0.05))
    # Any threshold at or below 1.0 lets the whole tie block through (5% FAR), so
    # at <=1% nothing can be flagged; a naive quantile threshold would claim 50%.
    assert d["1%"] == pytest.approx(0.0)
    assert d["5%"] == pytest.approx(1.0)


def test_normal_scale_standardises_reference():
    ref = np.random.default_rng(0).uniform(0.01, 0.2, 1000)
    sc = NormalScale(logit).fit(ref)
    z = sc(ref)
    assert abs(z.mean()) < 1e-9 and abs(z.std() - 1) < 1e-9
    assert sc(np.array([0.999]))[0] > z.max()  # no saturation like a percentile would have


@pytest.mark.parametrize("kind", sorted(AnomalyScorer.KINDS))
def test_anomaly_scorers_rank_novel_above_normal(kind):
    ds = synthetic_with_novel(1500)
    normals = ds.X_train[ds.y_train == "Normal"]
    sc = AnomalyScorer(kind, ds.categorical, ds.numeric, max_reference=2000).fit(normals)
    s = sc.score(ds.X_test)
    assert s[(ds.y_test == "Novel").to_numpy()].mean() > s[(ds.y_test == "Normal").to_numpy()].mean()


def test_hybrid_catches_novel_attack_the_classifier_misses():
    ds = synthetic_with_novel()
    det = HybridDetector(ds.categorical, ds.numeric, anomaly="iforest", target_far=0.05).fit(
        ds.X_train, ds.y_train)
    novel = (ds.y_test == "Novel").to_numpy()
    res = evaluate_split(det, ds.X_test, ds.y_test, novel)
    mf = res["matched_far"]
    assert mf["hybrid"]["novel"]["5%"] > mf["classifier"]["novel"]["5%"] + 0.5
    assert mf["hybrid"]["known"]["5%"] > 0.9            # known attacks still caught
    op = res["operating_point"]
    assert op["test_far"] < 0.10                          # calibrated near the 5% target
    pred = det.predict(ds.X_test)
    assert (pred[novel] == UNKNOWN).mean() > 0.5          # new attack surfaces as Unknown


def test_node_uses_hybrid_model(tmp_path, monkeypatch):
    import joblib
    from dtds.node import CompanyNode
    ds = synthetic_with_novel()
    det = HybridDetector(ds.categorical, ds.numeric, target_far=0.05).fit(ds.X_train, ds.y_train)
    path = tmp_path / "hybrid.joblib"
    joblib.dump({"hybrid": det, "features": list(ds.X_train.columns)}, path)
    monkeypatch.setattr("dtds.sharing.zkprover.new_identity", lambda: {"secret": 1, "commitment": 2})
    node = CompanyNode("T", tmp_path / "n", bytes(32), None, path, alerter=None, use_ipfs=False)
    flows = ds.X_test.copy()
    flows["src_ip"] = np.where(ds.y_test == "Novel", "203.0.113.50", "198.51.100.7")
    r = node.process_traffic(flows)
    assert "ipv4:203.0.113.50" in {f.ioc for f in r.findings}
