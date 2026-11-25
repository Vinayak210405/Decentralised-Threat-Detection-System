import json
from pathlib import Path

import numpy as np
import pytest

from dtds.ingest.zeek import (NETWORK_FEATURES, _service, conn_to_flows, load_flows,
                              read_conn_log)
from dtds.paths import ROOT

SAMPLES = ROOT / "samples" / "zeek"
HEADER = ("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\t"
          "service\tduration\torig_bytes\tresp_bytes\tconn_state\n")


def tsv(rows):
    return HEADER + "".join("\t".join(map(str, r)) + "\n" for r in rows)


def test_service_mapping():
    assert _service("tcp", 50000, 80) == "http"
    assert _service("tcp", 50000, 443) == "http_443"
    assert _service("udp", 50000, 53) == "domain_u"
    assert _service("tcp", 50000, 6001) == "X11"
    assert _service("tcp", 50000, 31337) == "private"
    assert _service("tcp", 50000, 999) == "other"
    assert _service("icmp", 8, 0) == "eco_i"   # echo request (ping sweeps)
    assert _service("icmp", 0, 0) == "ecr_i"   # echo reply (smurf floods)


def test_tsv_and_json_logs_give_identical_flows(tmp_path):
    rows = [[100.0, "C1", "203.0.113.5", 40000, "10.0.0.5", 80, "tcp", "http", 0.5, 300, 5000, "SF"],
            [100.5, "C2", "203.0.113.5", 40001, "10.0.0.5", 80, "tcp", "-", "-", "-", "-", "S0"]]
    (tmp_path / "conn.log").write_text(tsv(rows), encoding="utf-8")
    keys = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
            "duration", "orig_bytes", "resp_bytes", "conn_state"]
    (tmp_path / "conn.json").write_text("\n".join(json.dumps(dict(zip(keys, r))) for r in rows),
                                        encoding="utf-8")
    a, b = load_flows(tmp_path / "conn.log"), load_flows(tmp_path / "conn.json")
    assert a[NETWORK_FEATURES].equals(b[NETWORK_FEATURES])
    assert a.loc[1, "src_bytes"] == 0 and a.loc[1, "flag"] == "S0"   # "-" means unset -> 0


def test_window_features_count_correctly():
    # 4 connections to 10.0.0.5 within 2 s (3 half-open on port 80, 1 REJ on 22),
    # then one 5 s later to the same host: its 2-second window holds only itself.
    rows = [[0.0, "a", "1.2.3.4", 1, "10.0.0.5", 80, "tcp", "-", 0, 0, 0, "S0"],
            [0.5, "b", "1.2.3.4", 2, "10.0.0.5", 80, "tcp", "-", 0, 0, 0, "S0"],
            [1.0, "c", "1.2.3.4", 3, "10.0.0.5", 80, "tcp", "-", 0, 0, 0, "S0"],
            [1.5, "d", "1.2.3.4", 4, "10.0.0.5", 22, "tcp", "-", 0, 0, 0, "REJ"],
            [6.5, "e", "1.2.3.4", 5, "10.0.0.5", 80, "tcp", "-", 0, 0, 0, "SF"]]
    import pandas as pd
    conn = pd.DataFrame(rows, columns=["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                                       "proto", "service", "duration", "orig_bytes", "resp_bytes",
                                       "conn_state"]).astype(str)
    f = conn_to_flows(conn)
    d = f.iloc[3]          # the REJ at t=1.5
    assert d["count"] == 4 and d["srv_count"] == 1
    assert d["serror_rate"] == 0.75 and d["rerror_rate"] == 0.25
    assert d["same_srv_rate"] == 0.25 and d["diff_srv_rate"] == 0.75
    e = f.iloc[4]          # t=6.5: alone in its 2 s window, but 5 in the host window
    assert e["count"] == 1 and e["serror_rate"] == 0.0
    assert e["dst_host_count"] == 5 and e["dst_host_serror_rate"] == 0.6
    assert e["dst_host_same_srv_rate"] == 0.8


def test_sample_logs_parse():
    for name in ("baseline", "normal", "syn_flood", "port_scan"):
        f = load_flows(SAMPLES / f"{name}.log")
        assert set(NETWORK_FEATURES) <= set(f.columns)
        assert f[NETWORK_FEATURES].select_dtypes("number").notna().all().all()
    flood = load_flows(SAMPLES / "syn_flood.log")
    att = flood[flood.src_ip == "203.0.113.66"]
    assert len(att) == 600 and (att.flag == "S0").all() and att["count"].max() > 300


@pytest.mark.slow
def test_calibrated_hybrid_on_sample_logs(tmp_path, monkeypatch):
    """End to end on the sample logs: trains the network-only hybrid on NSL-KDD
    (downloads it if needed, ~40 s), calibrates on baseline.log, then checks the
    flood and the scan are reported and normal traffic is not."""
    monkeypatch.setattr("dtds.paths.MODELS_DIR", tmp_path)
    monkeypatch.setattr("dtds.sharing.zkprover.new_identity", lambda: {"secret": 1, "commitment": 2})
    from dtds.ingest.train_network_model import save_network_hybrid
    from dtds.node import CompanyNode
    path = save_network_hybrid()
    node = CompanyNode("t", tmp_path / "n", bytes(32), None, path, alerter=None, use_ipfs=False)
    feats = node.detector["features"]
    node.detector["hybrid"].calibrate_to_baseline(load_flows(SAMPLES / "baseline.log")[feats])
    found = {}
    for name in ("normal", "syn_flood", "port_scan"):
        r = node.process_traffic(load_flows(SAMPLES / f"{name}.log"))
        found[name] = {f.ioc for f in r.findings}
    assert found["normal"] == set()
    assert found["syn_flood"] == {"ipv4:203.0.113.66"}
    assert found["port_scan"] == {"ipv4:203.0.113.99"}
