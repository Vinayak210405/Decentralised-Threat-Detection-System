import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from dtds.dashboard.__main__ import export_html, make_handler
from dtds.dashboard.collect import build_state, chain_state, company_states

SECRET = "987654321987654321"
EVIL = "url:http://x/</script><script>alert(1)</script>"


def make_node(root, folder, name, known=None, alerts=()):
    d = root / folder
    d.mkdir(parents=True)
    (d / "identity.json").write_text(json.dumps({"secret": SECRET, "commitment": "12345"}))
    (d / "state.json").write_text(json.dumps({
        "company": name, "known": {hex(h): v for h, v in (known or {}).items()},
        "reported": [hex(h) for h in (known or {})], "watchlist": {hex(7): {"reports": 2}},
        "traffic": []}))
    with open(d / "alerts.jsonl", "w") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")


def test_company_state_reads_private_index_but_never_the_secret(tmp_path):
    make_node(tmp_path, "A", "Company A", known={7: "ipv4:203.0.113.66"},
              alerts=[{"company": "Company A", "title": "t", "severity": 4, "category": 1,
                       "ioc_hash": hex(7), "reports": 2, "known_locally": "ipv4:203.0.113.66",
                       "action": "blocked", "timestamp": 1.0}])
    make_node(tmp_path, "C", "Company C")
    st = company_states(tmp_path)
    assert set(st) == {"Company A", "Company C"}
    a = st["Company A"]
    assert a["known"] == {"0x" + "0" * 63 + "7": "ipv4:203.0.113.66"}
    assert a["alerts"][0]["severity_name"] == "Critical" and a["alerts"][0]["category_name"] == "DoS"
    assert st["Company C"]["known"] == {}
    assert SECRET not in json.dumps(st)


class FakeCall:
    def __init__(self, v):
        self.v = v

    def call(self):
        return self.v


def fake_registry():
    fns = SimpleNamespace(threshold=lambda: FakeCall(2), totalReports=lambda: FakeCall(3),
                          proposalCount=lambda: FakeCall(1))
    reports = [
        {"iocHash": 7, "category": 1, "severity": 3, "reports": 1, "nullifier": 11, "evidenceCid": "", "block": 5, "tx": "0x1"},
        {"iocHash": 7, "category": 1, "severity": 4, "reports": 2, "nullifier": 12, "evidenceCid": "", "block": 6, "tx": "0x2"},
        {"iocHash": 9, "category": 11, "severity": 2, "reports": 1, "nullifier": 13, "evidenceCid": "", "block": 7, "tx": "0x3"},
    ]
    return SimpleNamespace(
        contract=SimpleNamespace(functions=fns, address="0xabc"),
        members=lambda: [1, 2, 3], reports=lambda: reports,
        common_threats=lambda: [{"ioc_hash": 7, "reports": 2, "max_severity": 4, "block": 6}],
        block_number=lambda: 9,
        proposal=lambda pid: {"kind": 0, "value": 99, "snapshot_root": 0, "snapshot_members": 3,
                              "yes": 2, "no": 0, "deadline": 0, "executed": True})


def test_chain_state_groups_reports_into_indicators():
    c = chain_state(fake_registry())
    assert c["threshold"] == 2 and c["total_reports"] == 3 and len(c["members"]) == 3
    first, second = c["indicators"]
    assert first["common"] and first["reports"] == 2 and first["max_severity"] == "Critical"
    assert not second["common"] and second["categories"] == ["Threat intel"]
    assert c["proposals"][0]["kind"] == "Add member" and c["proposals"][0]["executed"]
    # Nothing but hashes, categories and counts: no plaintext field exists.
    assert "known" not in json.dumps(c)


def test_export_cannot_be_broken_out_of_by_a_malicious_indicator(tmp_path):
    make_node(tmp_path / "nodes", "A", "Company A", known={7: EVIL})
    state = build_state(fake_registry(), tmp_path / "nodes")
    out = export_html(state, tmp_path / "d.html")
    html = out.read_text()
    from dtds.dashboard.__main__ import STATIC
    assert html.count("</script>") == STATIC.read_text().count("</script>")
    assert "<\\/script><script>alert(1)<\\/script>" in html


@pytest.fixture
def server(tmp_path):
    state = {"generated_at": 0, "source": "snapshot", "chain": None, "companies": {}}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(lambda: state))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_server_routes_and_headers(server):
    with urllib.request.urlopen(server + "/") as r:
        assert r.status == 200 and b"Threat Consortium Dashboard" in r.read()
        assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    with urllib.request.urlopen(server + "/api/state") as r:
        assert json.loads(r.read())["source"] == "snapshot"
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(server + "/../etc/passwd")
    assert e.value.code == 404
