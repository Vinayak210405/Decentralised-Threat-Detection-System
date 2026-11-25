"""Keyed hashing of indicators.

Why not a plain SHA-256 of the IP? Because indicators have very little entropy:
there are only ~4.3 billion IPv4 addresses, and a laptop hashes all of them in
minutes. Anyone reading the public chain could reverse a plain hash and learn
exactly which IPs attacked the consortium's members.

So members hash with HMAC-SHA256 under a **consortium key** that only members
hold. Members can still match indicators across companies (same key, same
input -> same hash), outsiders reading the chain cannot invert or test them.

The digest is shifted right by 8 bits so it fits in the BN254 scalar field used
by the zk-SNARK (the hash is the proof's `scope`).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from dtds.extraction.iocs import canonical

FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def new_consortium_key() -> bytes:
    return secrets.token_bytes(32)


def load_or_create_key(path: Path) -> bytes:
    path = Path(path)
    if path.exists():
        return bytes.fromhex(path.read_text(encoding="utf-8").strip())
    path.parent.mkdir(parents=True, exist_ok=True)
    key = new_consortium_key()
    path.write_text(key.hex(), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def ioc_hash(key: bytes, canonical_ioc: str) -> int:
    """HMAC-SHA256(key, "type:value") >> 8, always < the SNARK field."""
    if ":" not in canonical_ioc:
        raise ValueError("expected canonical 'type:value' form, e.g. 'ipv4:203.0.113.7'")
    digest = hmac.new(key, canonical_ioc.encode("utf-8"), hashlib.sha256).digest()
    h = int.from_bytes(digest, "big") >> 8
    assert h < FIELD
    return h


def hash_indicator(key: bytes, ioc_type: str, value: str) -> int:
    return ioc_hash(key, canonical(ioc_type, value))
