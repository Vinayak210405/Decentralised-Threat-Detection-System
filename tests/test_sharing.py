import json
import shutil
import subprocess

import pytest

from dtds.paths import ROOT
from dtds.sharing.chain import report_signal_hash, vote_scope
from dtds.sharing.evidence import EvidenceStore
from dtds.sharing.ioc_hash import FIELD, hash_indicator, ioc_hash

KEY = bytes(range(32))

needs_node = pytest.mark.skipif(
    not shutil.which("node") or not (ROOT / "node_modules" / "snarkjs").exists(),
    reason="Node.js and `npm install` needed")


def test_ioc_hash_deterministic_keyed_and_in_field():
    h = ioc_hash(KEY, "ipv4:203.0.113.7")
    assert h == ioc_hash(KEY, "ipv4:203.0.113.7")
    assert h != ioc_hash(bytes(32), "ipv4:203.0.113.7")
    assert 0 <= h < FIELD
    assert h.bit_length() <= 248


def test_equivalent_notations_hash_identically():
    assert hash_indicator(KEY, "ipv6", "2001:0DB8::0001") == hash_indicator(KEY, "ipv6", "2001:db8::1")
    assert hash_indicator(KEY, "url", "HTTP://Evil.COM") == hash_indicator(KEY, "url", "http://evil.com/")


def test_ioc_hash_requires_canonical_form():
    with pytest.raises(ValueError):
        ioc_hash(KEY, "203.0.113.7")


def test_evidence_roundtrip_and_isolation(tmp_path):
    a = EvidenceStore(tmp_path / "a", use_ipfs=False)
    b = EvidenceStore(tmp_path / "b", use_ipfs=False)
    cid, digest = a.put({"ioc": "ipv4:203.0.113.7", "n": 3})
    assert cid == f"local:sha256:{digest}"
    assert a.get(cid) == {"ioc": "ipv4:203.0.113.7", "n": 3}
    # b cannot read a's bundle even with the ciphertext in hand
    (tmp_path / "b" / "evidence").mkdir(exist_ok=True)
    shutil.copy(tmp_path / "a" / "evidence" / digest, tmp_path / "b" / "evidence" / digest)
    with pytest.raises(Exception):
        b.get(cid)


@needs_node
def test_signal_hashes_match_solidity_encoding():
    """Python must compute exactly what ThreatRegistry computes on-chain."""
    js = """
    const { ethers } = require('ethers');
    const c = ethers.AbiCoder.defaultAbiCoder();
    const sig = BigInt(ethers.keccak256(c.encode(['uint8','uint8','string'], [3, 4, 'local:sha256:abc']))) >> 8n;
    const vote = BigInt(ethers.keccak256(c.encode(['string','uint256'], ['DTDS_VOTE', 5]))) >> 8n;
    console.log(JSON.stringify([sig.toString(), vote.toString()]));
    """
    out = subprocess.run(["node", "-e", js], cwd=ROOT, capture_output=True, text=True, check=True)
    sig, vote = map(int, json.loads(out.stdout))
    assert report_signal_hash(3, 4, "local:sha256:abc") == sig
    assert vote_scope(5) == vote


@needs_node
def test_python_prover_bridge():
    from dtds.sharing import zkprover
    a, b = zkprover.new_identity(), zkprover.new_identity()
    assert zkprover.commitment_of(a["secret"]) == a["commitment"]
    members = [a["commitment"], b["commitment"]]
    p1 = zkprover.prove(a["secret"], members, scope=1234, signal_hash=99)
    p2 = zkprover.prove(a["secret"], members, scope=1234, signal_hash=7)
    p3 = zkprover.prove(b["secret"], members, scope=1234, signal_hash=99)
    assert len(p1["proof"]) == 8
    assert p1["nullifier"] == p2["nullifier"] != p3["nullifier"]
    assert p1["root"] == p3["root"]
    with pytest.raises(zkprover.ProverError):
        zkprover.prove(12345, members, scope=1, signal_hash=1)
