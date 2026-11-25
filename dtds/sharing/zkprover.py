"""Python wrapper around scripts/zk/cli.js (snarkjs runs in Node.js)."""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Dict, List

from dtds.paths import ROOT

CLI = ROOT / "scripts" / "zk" / "cli.js"


class ProverError(RuntimeError):
    pass


def _node() -> str:
    node = shutil.which("node")
    if not node:
        raise ProverError("Node.js not found on PATH (needed for proof generation)")
    return node


def _call(request: Dict) -> Dict:
    proc = subprocess.run([_node(), str(CLI)], input=json.dumps(request), capture_output=True,
                          text=True, cwd=str(ROOT), timeout=300)
    try:
        out = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        raise ProverError(f"prover output not JSON: {proc.stdout[:200]} {proc.stderr[:500]}")
    if proc.returncode != 0 or "error" in out:
        raise ProverError(out.get("error") or proc.stderr[:500])
    return out


def new_identity() -> Dict[str, int]:
    out = _call({"cmd": "identity"})
    return {"secret": int(out["secret"]), "commitment": int(out["commitment"])}


def commitment_of(secret: int) -> int:
    return int(_call({"cmd": "commitment", "secret": str(secret)})["commitment"])


def prove(secret: int, members: List[int], scope: int, signal_hash: int) -> Dict:
    out = _call({"cmd": "prove", "secret": str(secret), "members": [str(m) for m in members],
                 "scope": str(scope), "signalHash": str(signal_hash)})
    return {"proof": [int(x) for x in out["proof"]], "nullifier": int(out["nullifier"]),
            "root": int(out["root"])}
