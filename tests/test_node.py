"""CompanyNode logic that doesn't need a blockchain."""
import joblib
import numpy as np
import pytest

from dtds.ml.models import make_pipeline
from dtds.node import CompanyNode, is_internal
from dtds.sharing.ioc_hash import ioc_hash
from dtds.sharing.taxonomy import Category, Severity, severity_for
from tests.test_ml import synthetic

KEY = bytes(32)


@pytest.fixture
def node(tmp_path, monkeypatch):
    ds = synthetic(1200)
    pipe = make_pipeline("hgb", ds.categorical, ds.numeric).fit(ds.X_train, ds.y_train)
    model = tmp_path / "m.joblib"
    joblib.dump({"pipeline": pipe, "features": list(ds.X_train.columns), "classes": ds.classes}, model)
    # No Node.js needed for these tests: stub out identity creation.
    monkeypatch.setattr("dtds.sharing.zkprover.new_identity", lambda: {"secret": 1, "commitment": 2})
    n = CompanyNode("Test", tmp_path / "node", KEY, None, model, alerter=None, use_ipfs=False)
    return n, ds


def flows(ds, ip_for_attacks="203.0.113.9"):
    X = ds.X_test.copy()
    X["src_ip"] = np.where(ds.y_test == "Normal", "198.51.100.50", ip_for_attacks)
    return X


def test_internal_ip_detection():
    assert is_internal("10.1.2.3") and is_internal("192.168.0.1") and is_internal("::1")
    assert not is_internal("203.0.113.9") and not is_internal("8.8.4.4")


def test_detector_turns_attacking_source_into_finding(node):
    n, ds = node
    r = n.process_traffic(flows(ds))
    assert [f.ioc for f in r.findings] == ["ipv4:203.0.113.9"]
    assert r.findings[0].category in (Category.DOS, Category.RECON)
    assert r.blocked_by_consortium == 0


def test_internal_attackers_are_not_shared(node):
    n, ds = node
    r = n.process_traffic(flows(ds, "10.0.0.5"))
    assert r.findings == []


def test_watchlist_blocks_before_the_model(node):
    n, ds = node
    n.watchlist[ioc_hash(KEY, "ipv4:203.0.113.9")] = {"reports": 2}
    f = flows(ds)
    r = n.process_traffic(f)
    assert r.blocked_by_consortium == int((f["src_ip"] == "203.0.113.9").sum())
    assert r.findings == []
    assert n.is_blocked("ipv4:203.0.113.9") and not n.is_blocked("ipv4:198.51.100.50")


def test_ingest_report(node):
    n, _ = node
    from dtds.paths import ROOT
    found = n.ingest_report(ROOT / "samples" / "reports" / "similar.docx")
    assert "ipv4:182.54.217.2" in {f.ioc for f in found}
    assert all(f.category == Category.INTEL_REPORT for f in found)


def test_severity_rules():
    assert severity_for(Category.DOS, flows=100, confidence=0.99) == Severity.CRITICAL
    assert severity_for(Category.RECON, flows=3, confidence=0.5) == Severity.INFO
