"""Encrypted evidence bundles.

When a company reports an indicator it can attach a pointer (CID) to an
evidence bundle: the extracted IOCs, detection statistics, the report file's
hash. The bundle is encrypted with the **company's own** key (Fernet: AES-128-
CBC + HMAC), so no other member can read it. The CID is bound into the ZK
proof's signal, which makes the bundle tamper-evident: later, in an audit or a
dispute, the company can reveal its key for that one bundle and prove what it
knew and when, without ever having exposed it to competitors.

Storage: IPFS if a local IPFS daemon (Kubo) is running at DTDS_IPFS_API
(default http://127.0.0.1:5001), otherwise a local content-addressed folder.
The returned identifier says which: ``ipfs://<cid>`` or ``local:sha256:<hex>``.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional, Tuple

from cryptography.fernet import Fernet

IPFS_API = os.environ.get("DTDS_IPFS_API", "http://127.0.0.1:5001")


class EvidenceStore:
    def __init__(self, node_dir: Path, use_ipfs: Optional[bool] = None):
        self.dir = Path(node_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        key_path = self.dir / "evidence.key"
        if key_path.exists():
            self.key = key_path.read_bytes()
        else:
            self.key = Fernet.generate_key()
            key_path.write_bytes(self.key)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
        self.fernet = Fernet(self.key)
        self.local_dir = self.dir / "evidence"
        self.use_ipfs = self._ipfs_available() if use_ipfs is None else use_ipfs

    @staticmethod
    def _ipfs_available() -> bool:
        try:
            import requests
            return requests.post(f"{IPFS_API}/api/v0/id", timeout=1).ok
        except Exception:
            return False

    def put(self, bundle: dict) -> Tuple[str, str]:
        """Encrypt and store; returns (identifier, sha256 of the ciphertext)."""
        plaintext = json.dumps(bundle, sort_keys=True, default=str).encode()
        ciphertext = self.fernet.encrypt(plaintext)
        digest = hashlib.sha256(ciphertext).hexdigest()
        if self.use_ipfs:
            import requests
            r = requests.post(f"{IPFS_API}/api/v0/add", files={"file": ciphertext}, timeout=30)
            r.raise_for_status()
            return f"ipfs://{r.json()['Hash']}", digest
        self.local_dir.mkdir(exist_ok=True)
        (self.local_dir / digest).write_bytes(ciphertext)
        return f"local:sha256:{digest}", digest

    def get(self, identifier: str) -> dict:
        if identifier.startswith("ipfs://"):
            import requests
            r = requests.post(f"{IPFS_API}/api/v0/cat", params={"arg": identifier[7:]}, timeout=30)
            r.raise_for_status()
            ciphertext = r.content
        elif identifier.startswith("local:sha256:"):
            ciphertext = (self.local_dir / identifier.split(":")[-1]).read_bytes()
        else:
            raise ValueError(identifier)
        return json.loads(self.fernet.decrypt(ciphertext))
