"""Thin web3.py client for ThreatRegistry."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from eth_abi import encode as abi_encode
from eth_utils import keccak
from web3 import Web3

from dtds.paths import ROOT

DEFAULT_RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")


def report_signal_hash(category: int, severity: int, evidence_cid: str) -> int:
    """Must equal ThreatRegistry.reportSignalHash()."""
    return int.from_bytes(keccak(abi_encode(["uint8", "uint8", "string"],
                                            [category, severity, evidence_cid])), "big") >> 8


def vote_scope(proposal_id: int) -> int:
    """Must equal ThreatRegistry.voteScope()."""
    return int.from_bytes(keccak(abi_encode(["string", "uint256"], ["DTDS_VOTE", proposal_id])),
                          "big") >> 8


class Registry:
    def __init__(self, deployment: Optional[Path] = None, rpc_url: str = DEFAULT_RPC,
                 account_index: int = 0, private_key: Optional[str] = None):
        deployment = Path(deployment or ROOT / "deployments" / "localhost.json")
        info = json.loads(deployment.read_text(encoding="utf-8"))
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError(f"No Ethereum node at {rpc_url}. Start one: npx hardhat node")
        self.contract = self.w3.eth.contract(address=info["address"], abi=info["abi"])
        self.start_block = info.get("startBlock", 0)
        self.private_key = private_key or os.environ.get("DTDS_PRIVATE_KEY")
        if self.private_key:
            self.account = self.w3.eth.account.from_key(self.private_key).address
        else:
            # Dev chain: use an unlocked account. Each company should use a
            # different (ideally fresh) address so transactions don't link reports.
            self.account = self.w3.eth.accounts[account_index]

    # ---- reads ----
    def members(self) -> List[int]:
        logs = self.contract.events.MemberAdded().get_logs(from_block=self.start_block)
        return [e["args"]["commitment"] for e in sorted(logs, key=lambda e: e["args"]["index"])]

    def threshold(self) -> int:
        return self.contract.functions.threshold().call()

    def indicator(self, ioc_hash: int) -> Dict:
        r = self.contract.functions.indicators(ioc_hash).call()
        return {"reports": r[0], "first_seen": r[1], "last_seen": r[2], "max_severity": r[3],
                "common": r[4]}

    def common_threats(self, from_block: Optional[int] = None) -> List[Dict]:
        logs = self.contract.events.CommonThreat().get_logs(
            from_block=self.start_block if from_block is None else from_block)
        return [{"ioc_hash": e["args"]["iocHash"], "reports": e["args"]["reports"],
                 "max_severity": e["args"]["maxSeverity"], "block": e["blockNumber"]} for e in logs]

    def reports(self, from_block: Optional[int] = None) -> List[Dict]:
        logs = self.contract.events.ThreatReported().get_logs(
            from_block=self.start_block if from_block is None else from_block)
        return [dict(e["args"], block=e["blockNumber"], tx=e["transactionHash"].hex()) for e in logs]

    def block_number(self) -> int:
        return self.w3.eth.block_number

    # ---- writes ----
    def _send(self, fn):
        if self.private_key:
            tx = fn.build_transaction({"from": self.account,
                                       "nonce": self.w3.eth.get_transaction_count(self.account)})
            signed = self.w3.eth.account.sign_transaction(tx, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        else:
            tx_hash = fn.transact({"from": self.account})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise RuntimeError(f"transaction reverted: {tx_hash.hex()}")
        return receipt

    def submit_report(self, ioc_hash: int, category: int, severity: int, evidence_cid: str,
                      root: int, nullifier: int, proof: List[int]):
        return self._send(self.contract.functions.submitReport(
            ioc_hash, category, severity, evidence_cid, root, nullifier, proof))

    def nullifier_used(self, nullifier: int) -> bool:
        return self.contract.functions.nullifierUsed(nullifier).call()

    def propose(self, kind: int, value: int):
        receipt = self._send(self.contract.functions.propose(kind, value))
        ev = self.contract.events.ProposalCreated().process_receipt(receipt)[0]
        return ev["args"]["id"]

    def proposal(self, pid: int) -> Dict:
        p = self.contract.functions.proposals(pid).call()
        keys = ["kind", "value", "snapshot_root", "snapshot_members", "yes", "no", "deadline", "executed"]
        return dict(zip(keys, p))

    def vote(self, pid: int, support: bool, nullifier: int, proof: List[int]):
        return self._send(self.contract.functions.vote(pid, support, nullifier, proof))

    def execute(self, pid: int):
        return self._send(self.contract.functions.execute(pid))
