"""A company's node: detect locally, share anonymously, receive early warnings.

Data that never leaves the company: raw traffic, threat reports, the plaintext
indicators, the identity secret, the evidence key, the ML model's inputs.

Data that leaves: per indicator, a keyed hash + category + severity + an
encrypted-evidence pointer + a zk-SNARK proving membership, submitted through a
shared relayer so the transaction sender does not identify the company.
"""
from __future__ import annotations

import ipaddress
import json
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

import numpy as np
import pandas as pd

from dtds.alerts import Alert, Alerter
from dtds.extraction import extract_file
from dtds.extraction.iocs import canonical
from dtds.sharing import zkprover
from dtds.sharing.chain import Registry, report_signal_hash
from dtds.sharing.evidence import EvidenceStore
from dtds.sharing.ioc_hash import ioc_hash
from dtds.sharing.taxonomy import ML_LABEL_TO_CATEGORY, Category, Severity, severity_for

INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                  "::1/128", "fc00::/7", "fe80::/10")]


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in net for net in INTERNAL_NETS)


@dataclass
class Finding:
    ioc: str                 # canonical "type:value"
    category: Category
    severity: Severity
    source: str              # "ml-detector" or the report file name
    details: Dict = field(default_factory=dict)


@dataclass
class TrafficResult:
    total_flows: int
    blocked_by_consortium: int
    flagged_by_model: int
    findings: List[Finding]
    per_source: Dict[str, Dict]


class CompanyNode:
    def __init__(self, name: str, node_dir: Path, consortium_key: bytes,
                 registry: Optional[Registry] = None, detector_path: Optional[Path] = None,
                 alerter: Optional[Alerter] = None, use_ipfs: Optional[bool] = None):
        self.name = name
        self.dir = Path(node_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.key = consortium_key
        self.registry = registry
        self.alerter = alerter or Alerter.from_env(self.dir / "alerts.jsonl")
        self.evidence = EvidenceStore(self.dir, use_ipfs)
        self.identity = self._load_identity()
        self.detector = None
        if detector_path:
            import joblib
            self.detector = joblib.load(detector_path)
        self.local_index: Dict[int, str] = {}   # hash -> plaintext IOC this company has seen
        self.watchlist: Dict[int, Dict] = {}    # hash -> on-chain common-threat info
        self.reported: Set[int] = set()
        self.synced_to_block: Optional[int] = None
        self.traffic_log: List[Dict] = []       # per-batch detection counts (for the dashboard)
        self._load_state()

    # ------------------------------------------------------------------ #
    # Local state (never leaves the company's machine)
    # ------------------------------------------------------------------ #
    @property
    def state_path(self) -> Path:
        return self.dir / "state.json"

    def _load_state(self) -> None:
        if not self.state_path.exists():
            return
        d = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.local_index = {int(h, 16): v for h, v in d.get("known", {}).items()}
        self.reported = {int(h, 16) for h in d.get("reported", [])}
        self.watchlist = {int(h, 16): v for h, v in d.get("watchlist", {}).items()}
        self.synced_to_block = d.get("synced_to_block")
        self.traffic_log = d.get("traffic", [])

    def save_state(self) -> None:
        """Persist what this company knows locally: which plaintext indicator each
        hash stands for, what it reported, its watchlist. This is private: it is
        exactly what the chain does NOT contain."""
        d = {"company": self.name,
             "known": {hex(h): v for h, v in self.local_index.items()},
             "reported": [hex(h) for h in sorted(self.reported)],
             "watchlist": {hex(h): v for h, v in self.watchlist.items()},
             "synced_to_block": self.synced_to_block,
             "traffic": self.traffic_log[-200:]}
        self.state_path.write_text(json.dumps(d, indent=1), encoding="utf-8")

    # ------------------------------------------------------------------ #
    # Identity
    # ------------------------------------------------------------------ #
    def _load_identity(self) -> Dict[str, int]:
        path = self.dir / "identity.json"
        if path.exists():
            d = json.loads(path.read_text(encoding="utf-8"))
            return {"secret": int(d["secret"]), "commitment": int(d["commitment"])}
        ident = zkprover.new_identity()
        path.write_text(json.dumps({k: str(v) for k, v in ident.items()}), encoding="utf-8")
        return ident

    @property
    def commitment(self) -> int:
        return self.identity["commitment"]

    def hash_ioc(self, canonical_ioc: str) -> int:
        h = ioc_hash(self.key, canonical_ioc)
        self.local_index[h] = canonical_ioc
        return h

    # ------------------------------------------------------------------ #
    # Local detection
    # ------------------------------------------------------------------ #
    def is_blocked(self, canonical_ioc: str) -> bool:
        return ioc_hash(self.key, canonical_ioc) in self.watchlist

    def process_traffic(self, flows: pd.DataFrame, src_col: str = "src_ip", min_flows: int = 5,
                        min_confidence: float = 0.8, use_consortium: bool = True,
                        min_share: float = 0.2) -> TrafficResult:
        """Firewall check against consortium intel, then ML classification of
        whatever got through. A source becomes a finding to share when at least
        `min_flows` of its connections AND at least `min_share` of them are
        confidently flagged. The share rule matters for busy machines: on real
        traffic (reports/zeek-wrccdc) a benign server with 160,000 connections
        and a 2% false-alarm rate would otherwise be reported."""
        if self.detector is None:
            raise RuntimeError("no detector model loaded")
        src = flows[src_col].astype(str)
        blocked = np.zeros(len(flows), dtype=bool)
        if use_consortium and self.watchlist:
            hashes = {ip: ioc_hash(self.key, canonical("ipv4" if ":" not in ip else "ipv6", ip))
                      for ip in src.unique() if not is_internal(ip)}
            blocked = src.map(lambda ip: hashes.get(ip) in self.watchlist).to_numpy()

        passed = flows.loc[~blocked]
        feats = passed[self.detector["features"]]
        if "hybrid" in self.detector:
            # Classifier + anomaly detector (dtds.ml.novelty). Its alarm threshold is
            # already calibrated to a false-alarm budget, so every alarm counts as
            # confident; flows only the anomaly detector flags are labelled Unknown.
            pred = self.detector["hybrid"].predict(feats)
            conf = np.where(pred != "Normal", 1.0, 0.0)
        else:
            pipe = self.detector["pipeline"]
            proba = pipe.predict_proba(feats)
            pred = np.array(list(pipe.classes_))[proba.argmax(axis=1)]
            conf = proba.max(axis=1)
        is_attack = pred != "Normal"

        per_source: Dict[str, Dict] = {}
        findings: List[Finding] = []
        df = pd.DataFrame({"src": passed[src_col].astype(str).to_numpy(), "pred": pred, "conf": conf,
                           "attack": is_attack})
        for ip, g in df.groupby("src"):
            att = g[g["attack"] & (g["conf"] >= min_confidence)]
            per_source[ip] = {"flows": int(len(g)), "attack_flows": int(len(att))}
            if len(att) < min_flows or len(att) < min_share * len(g) or is_internal(ip):
                continue
            label = Counter(att["pred"]).most_common(1)[0][0]
            cat = ML_LABEL_TO_CATEGORY.get(label, Category.UNKNOWN)
            c = float(att["conf"].mean())
            ioc = canonical("ipv6" if ":" in ip else "ipv4", ip)
            findings.append(Finding(ioc, cat, severity_for(cat, len(att), c), "ml-detector",
                                    {"attack_flows": int(len(att)), "flows": int(len(g)),
                                     "predicted": label, "mean_confidence": round(c, 3)}))
        for ip in src[blocked].unique():
            per_source.setdefault(ip, {"flows": 0, "attack_flows": 0})["blocked"] = int((src[blocked] == ip).sum())
        self.traffic_log.append({"time": time.time(), "flows": int(len(flows)), "blocked": int(blocked.sum()),
                                 "flagged": int(is_attack.sum()), "findings": len(findings),
                                 "consortium": bool(use_consortium)})
        self.save_state()
        return TrafficResult(len(flows), int(blocked.sum()), int(is_attack.sum()), findings, per_source)

    def ingest_report(self, path) -> List[Finding]:
        res = extract_file(path)
        name = Path(path).name
        return [Finding(ioc, Category.INTEL_REPORT, Severity.MEDIUM, name,
                        {"attack_techniques": res.attack_techniques, "cves": res.cves})
                for ioc in res.canonical()]

    # ------------------------------------------------------------------ #
    # Sharing
    # ------------------------------------------------------------------ #
    def share(self, findings: Iterable[Finding]) -> List[Dict]:
        if self.registry is None:
            raise RuntimeError("no registry configured")
        members = self.registry.members()
        if self.commitment not in members:
            raise RuntimeError(f"{self.name} is not a consortium member yet")
        out = []
        for f in findings:
            h = self.hash_ioc(f.ioc)
            if h in self.reported:
                continue
            bundle = {"company": self.name, "ioc": f.ioc, "category": int(f.category),
                      "severity": int(f.severity), "source": f.source, "details": f.details,
                      "reported_at": time.time()}
            cid, _ = self.evidence.put(bundle)
            sig = report_signal_hash(int(f.category), int(f.severity), cid)
            t0 = time.perf_counter()
            p = zkprover.prove(self.identity["secret"], members, h, sig)
            prove_s = time.perf_counter() - t0
            if self.registry.nullifier_used(p["nullifier"]):
                self.reported.add(h)  # reported in an earlier session
                continue
            receipt = self.registry.submit_report(h, int(f.category), int(f.severity), cid,
                                                  p["root"], p["nullifier"], p["proof"])
            self.reported.add(h)
            out.append({"ioc": f.ioc, "ioc_hash": h, "evidence": cid, "gas": receipt.gasUsed,
                        "prove_seconds": round(prove_s, 2), "tx": receipt.transactionHash.hex()})
        self.save_state()
        return out

    def sync(self) -> List[Alert]:
        """Pull new CommonThreat events into the watchlist and raise alerts."""
        if self.registry is None:
            return []
        start = None if self.synced_to_block is None else self.synced_to_block + 1
        head = self.registry.block_number()
        alerts = []
        for ev in self.registry.common_threats(start):
            h = ev["ioc_hash"]
            if h in self.watchlist:
                continue
            info = self.registry.indicator(h)
            self.watchlist[h] = {**info, "block": ev["block"]}
            seen = self.local_index.get(h)
            reports = self.registry.reports(ev["block"])
            cat = next((r["category"] for r in reports if r["iocHash"] == h), 0)
            alert = Alert(self.name,
                          "Common threat confirmed (we have seen it too)" if seen else
                          "Early warning: common threat not yet seen here",
                          info["max_severity"], cat, h, info["reports"], seen,
                          "added to blocklist")
            self.alerter.send(alert)
            alerts.append(alert)
        self.synced_to_block = head
        self.save_state()
        return alerts

    # ------------------------------------------------------------------ #
    # Governance
    # ------------------------------------------------------------------ #
    def vote(self, proposal_id: int, support: bool) -> None:
        from dtds.sharing.chain import vote_scope
        p = self.registry.proposal(proposal_id)
        members = self.registry.members()[: p["snapshot_members"]]
        proof = zkprover.prove(self.identity["secret"], members, vote_scope(proposal_id),
                               1 if support else 0)
        self.registry.vote(proposal_id, support, proof["nullifier"], proof["proof"])
