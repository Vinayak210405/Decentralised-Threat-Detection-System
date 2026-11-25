"""Assemble everything the dashboard shows into one JSON-ready dict.

Two kinds of data, kept visibly apart because that separation IS the privacy
design:

* ``chain``: what anyone reading the blockchain sees: member commitments,
  anonymous reports (keyed hashes, category, severity, nullifier), common
  threats, governance proposals. No IP, domain or company name appears here.
* ``companies``: each company node's PRIVATE local state, read from its own
  folder: which plaintext indicator each hash stands for (only those it saw
  itself), what it reported, its watchlist and alerts. In a real deployment
  each company's dashboard would only ever load its own folder.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Optional

from dtds.sharing.taxonomy import Category, Severity

KINDS = {0: "Add member", 1: "Set threshold"}


def _hx(v: int) -> str:
    return "0x%064x" % int(v)


CATEGORY_NAMES = {
    Category.UNKNOWN: "Unknown", Category.DOS: "DoS", Category.RECON: "Reconnaissance",
    Category.REMOTE_ACCESS: "Remote access", Category.PRIVILEGE_ESC: "Privilege escalation",
    Category.MALWARE: "Malware", Category.PHISHING: "Phishing", Category.C2: "Command and control",
    Category.WEB_ATTACK: "Web attack", Category.BOTNET: "Botnet", Category.BRUTE_FORCE: "Brute force",
    Category.INTEL_REPORT: "Threat intel",
}


def _category(c: int) -> str:
    try:
        return CATEGORY_NAMES[Category(int(c))]
    except (ValueError, KeyError):
        return str(c)


def _severity(s: int) -> str:
    try:
        return Severity(int(s)).name.title()
    except ValueError:
        return str(s)


def chain_state(registry) -> Dict[str, object]:
    c = registry.contract.functions
    threshold = c.threshold().call()
    members = [{"index": i, "commitment": _hx(m)} for i, m in enumerate(registry.members())]
    reports, indicators = [], {}
    for r in sorted(registry.reports(), key=lambda r: r["block"]):
        h = _hx(r["iocHash"])
        reports.append({"block": r["block"], "ioc_hash": h, "category": _category(r["category"]),
                        "severity": _severity(r["severity"]), "severity_level": int(r["severity"]),
                        "count_after": int(r["reports"]), "nullifier": _hx(r["nullifier"]),
                        "evidence": r["evidenceCid"], "tx": r["tx"]})
        ind = indicators.setdefault(h, {"ioc_hash": h, "reports": 0, "first_block": r["block"],
                                        "categories": [], "max_severity_level": 0})
        ind["reports"] = int(r["reports"])
        ind["last_block"] = r["block"]
        if reports[-1]["category"] not in ind["categories"]:
            ind["categories"].append(reports[-1]["category"])
        ind["max_severity_level"] = max(ind["max_severity_level"], int(r["severity"]))
    for ev in registry.common_threats():
        h = _hx(ev["ioc_hash"])
        if h in indicators:
            indicators[h]["common"] = True
            indicators[h]["common_block"] = ev["block"]
    for ind in indicators.values():
        ind.setdefault("common", False)
        ind["max_severity"] = _severity(ind["max_severity_level"])
    proposals = []
    for pid in range(c.proposalCount().call()):
        p = registry.proposal(pid)
        proposals.append({"id": pid, "kind": KINDS.get(int(p["kind"]), str(p["kind"])),
                          "value": _hx(p["value"]) if int(p["kind"]) == 0 else int(p["value"]),
                          "yes": int(p["yes"]), "no": int(p["no"]),
                          "members_at_creation": int(p["snapshot_members"]),
                          "executed": bool(p["executed"])})
    return {"address": registry.contract.address, "block": registry.block_number(),
            "threshold": int(threshold), "members": members,
            "total_reports": int(c.totalReports().call()), "reports": reports,
            "indicators": sorted(indicators.values(), key=lambda i: (-i["common"], -i["reports"],
                                                                     i["first_block"])),
            "proposals": proposals}


def company_states(nodes_dir: Path) -> Dict[str, Dict[str, object]]:
    out = {}
    for d in sorted(Path(nodes_dir).iterdir()) if Path(nodes_dir).exists() else []:
        if not (d / "identity.json").exists():
            continue
        state = json.loads((d / "state.json").read_text(encoding="utf-8")) if (d / "state.json").exists() else {}
        alerts: List[Dict] = []
        if (d / "alerts.jsonl").exists():
            for line in (d / "alerts.jsonl").read_text(encoding="utf-8").splitlines():
                if line.strip():
                    a = json.loads(line)
                    a["ioc_hash"] = _hx(int(a["ioc_hash"], 16))
                    a["severity_name"] = _severity(a["severity"])
                    a["category_name"] = _category(a["category"])
                    alerts.append(a)
        name = state.get("company") or (alerts[0]["company"] if alerts else f"Company {d.name}")
        commitment = int(json.loads((d / "identity.json").read_text(encoding="utf-8"))["commitment"])
        out[name] = {
            "folder": d.name,
            "commitment": _hx(commitment),   # public anyway; the SECRET is never read here
            "known": {_hx(int(h, 16)): v for h, v in state.get("known", {}).items()},
            "reported": [_hx(int(h, 16)) for h in state.get("reported", [])],
            "watchlist": [_hx(int(h, 16)) for h in state.get("watchlist", {})],
            "alerts": alerts,
            "traffic": state.get("traffic", []),
        }
    return out


def build_state(registry=None, nodes_dir: Optional[Path] = None,
                snapshot: Optional[Dict] = None) -> Dict[str, object]:
    """Live state from a registry + node folders, or a saved snapshot."""
    if registry is None and snapshot is not None:
        return {**snapshot, "source": "snapshot"}
    return {"generated_at": time.time(), "source": "live" if registry is not None else "nodes only",
            "chain": chain_state(registry) if registry is not None else None,
            "companies": company_states(nodes_dir) if nodes_dir else {}}


def save_snapshot(state: Dict[str, object], path: Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps({**state, "source": "snapshot"}, indent=1), encoding="utf-8")
    return path
