"""End-to-end demo: three companies, one shared attacker, an early warning.

    python -m dtds.demo

What happens
------------
1. A local Ethereum dev chain starts (Hardhat) unless one is already running,
   and the ThreatRegistry is deployed with companies A, B and C as founding
   members (only their public identity commitments go on-chain).
2. Company A is hit by a SYN flood from 203.0.113.66. Its ML detector (trained
   on NSL-KDD) flags the source; A reports the IP's keyed hash anonymously.
3. Company B is hit by the same attacker plus a port scan from another IP. B
   reports both. The flood IP now has 2 independent reports = the threshold,
   so the contract emits CommonThreat. The scanner (1 report) does not.
4. A and B also ingest two different threat-intel reports (from samples/). The
   indicators that appear in both become common threats as well.
5. Company C syncs and receives early warnings for indicators it has never
   seen. Then the attacker hits C with a *different* DoS variant that the ML
   model has never been trained on. We compare C's own detector against C with
   consortium intel.
6. Privacy check: what an outsider reading the chain learns.
7. Governance: company D applies; members vote anonymously; D is admitted.

All IPs used for simulated attackers are from the RFC 5737 documentation
ranges (203.0.113.0/24, 198.51.100.0/24), which are never routed on the
internet, so the demo cannot implicate a real host.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

from dtds.alerts import Alerter
from dtds.ml import datasets
from dtds.node import CompanyNode
from dtds.paths import MODELS_DIR, NODES_DIR, REPORTS_DIR, ROOT
from dtds.sharing.chain import Registry
from dtds.sharing.ioc_hash import load_or_create_key

ATTACKER = "203.0.113.66"     # shared campaign
SCANNER = "198.51.100.23"     # only seen by company B
RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")


def banner(text):
    print("\n" + "=" * 78 + f"\n{text}\n" + "=" * 78)


def npx():
    exe = shutil.which("npx") or shutil.which("npx.cmd")
    if not exe:
        sys.exit("npx (Node.js) not found. Install Node.js 18+ and run `npm install`.")
    return exe


def chain_up() -> bool:
    from web3 import Web3
    try:
        return Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 2})).is_connected()
    except Exception:
        return False


def start_chain():
    if chain_up():
        print(f"Using the Ethereum node already running at {RPC}")
        return None
    print("Starting a local Hardhat chain ...")
    log = open(NODES_DIR / "hardhat-node.log", "w", encoding="utf-8")
    kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    proc = subprocess.Popen([npx(), "hardhat", "node"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, **kwargs)
    for _ in range(120):
        if chain_up():
            return proc
        time.sleep(1)
    proc.kill()
    sys.exit(f"Hardhat node did not start; see {NODES_DIR / 'hardhat-node.log'}")


def stop_chain(proc):
    if proc is None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        proc.kill()


def deploy(members, threshold, demo_dir: Path) -> Path:
    members_file = demo_dir / "members.json"
    members_file.write_text(json.dumps([str(m) for m in members]), encoding="utf-8")
    env = {**os.environ, "DTDS_MEMBERS": str(members_file), "DTDS_THRESHOLD": str(threshold),
           "DTDS_VOTING_PERIOD": "3600"}
    r = subprocess.run([npx(), "hardhat", "run", "scripts/deploy.js", "--network", "localhost"],
                       cwd=ROOT, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("deploy failed:\n" + r.stdout + r.stderr)
    print("  " + r.stdout.strip().splitlines()[-1])
    return ROOT / "deployments" / "localhost.json"


def ensure_model() -> Path:
    path = MODELS_DIR / "nsl-kdd_hgb.joblib"
    if not path.exists():
        print("No trained detector found; training gradient boosting on NSL-KDD (~10 s) ...")
        from dtds.ml.train import run
        run("nsl-kdd", ["hgb"], out_dir=REPORTS_DIR / "ml" / "nsl-kdd-demo")
    return path


def make_traffic(ds, rng, normal_n, attacks):
    """Flows from the NSL-KDD *test* set (unseen by the model) with source IPs attached.
    attacks: list of (src_ip, attack_name, n)."""
    X, detail = ds.X_test, ds.y_test_detail.to_numpy()
    parts = []
    idx = rng.choice(np.flatnonzero(detail == "normal"), normal_n, replace=False)
    benign_ips = [f"198.51.100.{i}" for i in range(100, 140)]
    parts.append(X.iloc[idx].assign(src_ip=rng.choice(benign_ips, normal_n), truth="normal"))
    for ip, name, n in attacks:
        pool = np.flatnonzero(detail == name)
        idx = rng.choice(pool, n, replace=len(pool) < n)
        parts.append(X.iloc[idx].assign(src_ip=ip, truth=name))
    return pd.concat(parts).sample(frac=1, random_state=int(rng.integers(1 << 31))).reset_index(drop=True)


def print_shares(name, shares):
    for s in shares:
        print(f"  {name} reported {s['ioc']:<62} proof {s['prove_seconds']:.1f}s, gas {s['gas']:,}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--keep-chain", action="store_true", help="leave the Hardhat node running")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero unless the expected outcomes happen (used by CI)")
    args = ap.parse_args(argv)
    rng = np.random.default_rng(args.seed)
    t_start = time.time()

    demo_dir = NODES_DIR / "demo"
    shutil.rmtree(demo_dir, ignore_errors=True)
    demo_dir.mkdir(parents=True)
    model_path = ensure_model()
    ds = datasets.load("nsl-kdd")
    chain = start_chain()
    summary = {}
    try:
        banner("1. Consortium setup")
        # The consortium key is shared among members out-of-band (e.g. at onboarding).
        key = load_or_create_key(demo_dir / "consortium.key")
        nodes = {}
        for name in ("A", "B", "C"):
            nodes[name] = CompanyNode(f"Company {name}", demo_dir / name, key, None, model_path,
                                      Alerter.from_env(demo_dir / name / "alerts.jsonl"))
            print(f"  Company {name}: identity commitment {hex(nodes[name].commitment)[:20]}... "
                  "(secret stays on its own machine)")
        deployment = deploy([n.commitment for n in nodes.values()], 2, demo_dir)
        # All companies submit through one shared relayer account, so the
        # transaction sender reveals nothing about which company reported.
        for n in nodes.values():
            n.registry = Registry(deployment, RPC, account_index=0)
        reg = nodes["A"].registry
        print(f"  Threshold: an indicator becomes a common threat after {reg.threshold()} independent reports")

        banner("2. Company A is attacked; its ML detector flags the source and A reports it")
        traffic_a = make_traffic(ds, rng, 400, [(ATTACKER, "neptune", 120)])
        ra = nodes["A"].process_traffic(traffic_a)
        print(f"  {ra.total_flows} flows, {ra.flagged_by_model} classified as attacks")
        for f in ra.findings:
            print(f"  finding: {f.ioc} {f.category.name} severity {f.severity.name} {f.details}")
        print_shares("A", nodes["A"].share(ra.findings))

        banner("3. Company B is hit by the same attacker, plus a port scan only B sees")
        traffic_b = make_traffic(ds, rng, 400, [(ATTACKER, "neptune", 80), (SCANNER, "satan", 60)])
        rb = nodes["B"].process_traffic(traffic_b)
        for f in rb.findings:
            print(f"  finding: {f.ioc} {f.category.name} severity {f.severity.name} {f.details}")
        print_shares("B", nodes["B"].share(rb.findings))

        banner("4. A and B each ingest a different threat-intel report")
        fa = nodes["A"].ingest_report(ROOT / "samples" / "reports" / "threat_report.docx")
        fb = nodes["B"].ingest_report(ROOT / "samples" / "reports" / "similar.docx")
        print(f"  A extracted {len(fa)} indicators from threat_report.docx, B extracted {len(fb)} from similar.docx")
        print_shares("A", nodes["A"].share(fa))
        print_shares("B", nodes["B"].share(fb))

        banner("5. Everyone syncs with the chain")
        for name, n in nodes.items():
            print(f"-- Company {name}")
            n.sync()
        common = reg.common_threats()
        print(f"  Common threats on-chain: {len(common)}; total reports: "
              f"{reg.contract.functions.totalReports().call()}")
        scanner_hash = nodes["B"].hash_ioc(f"ipv4:{SCANNER}")
        print(f"  Scanner {SCANNER}: {reg.indicator(scanner_hash)['reports']} report(s), "
              "below threshold, so no alert (one company's sighting is not yet trusted)")

        banner("6. The attacker moves to Company C with a DoS variant the model was never trained on")
        traffic_c = make_traffic(ds, rng, 400, [(ATTACKER, "processtable", 150)])
        attack_rows = (traffic_c["src_ip"] == ATTACKER).sum()
        alone = nodes["C"].process_traffic(traffic_c, use_consortium=False)
        caught_alone = alone.per_source.get(ATTACKER, {}).get("attack_flows", 0)
        with_c = nodes["C"].process_traffic(traffic_c, use_consortium=True)
        normal_blocked = int(((traffic_c["src_ip"] != ATTACKER) &
                              traffic_c["src_ip"].map(lambda ip: nodes["C"].is_blocked(f"ipv4:{ip}"))).sum())
        print(f"  Attack flows from {ATTACKER}: {attack_rows}")
        print(f"  C's own model alone flags:      {caught_alone} ({caught_alone / attack_rows:.0%})")
        print(f"  C with consortium early warning: {with_c.blocked_by_consortium} blocked before reaching "
              f"the model ({with_c.blocked_by_consortium / attack_rows:.0%}); legitimate flows blocked: {normal_blocked}")
        summary["company_c"] = {"attack_flows": int(attack_rows), "model_alone_flagged": int(caught_alone),
                                "blocked_with_consortium": with_c.blocked_by_consortium,
                                "legitimate_blocked": normal_blocked}

        banner("7. Privacy check: what does an outsider reading the chain see?")
        rep = reg.reports()[0]
        print(f"  A report on-chain: iocHash={hex(rep['iocHash'])[:22]}... category={rep['category']} "
              f"severity={rep['severity']} evidence={rep['evidenceCid'][:30]}... nullifier={hex(rep['nullifier'])[:18]}...")
        from dtds.sharing.ioc_hash import ioc_hash
        guess_wrong_key = ioc_hash(b"\x00" * 32, f"ipv4:{ATTACKER}")
        on_chain = {r["iocHash"] for r in reg.reports()}
        print(f"  Outsider guesses '{ATTACKER}' without the consortium key -> hash found on-chain? "
              f"{guess_wrong_key in on_chain}")
        senders = {reg.w3.eth.get_transaction(r['tx'])['from'] for r in reg.reports()}
        print(f"  Distinct transaction senders across {len(reg.reports())} reports: {len(senders)} (the relayer)")
        print("  Nullifiers differ for every (company, indicator) pair, so reports cannot be grouped by company.")
        try:
            evidence = nodes["B"].evidence.get(rep["evidenceCid"])
            print(f"  Company B decrypting Company A's evidence: succeeded?! {evidence}")
        except Exception:
            print("  Company B trying to decrypt Company A's evidence bundle: fails (A's key only)")

        banner("8. Governance: Company D applies to join; members vote anonymously")
        d = CompanyNode("Company D", demo_dir / "D", key, nodes["A"].registry, model_path,
                        Alerter.from_env(demo_dir / "D" / "alerts.jsonl"))
        pid = reg.propose(0, d.commitment)
        nodes["A"].vote(pid, True)
        nodes["B"].vote(pid, True)
        p = reg.proposal(pid)
        print(f"  Proposal {pid}: yes={p['yes']} no={p['no']} of {p['snapshot_members']} members")
        reg.execute(pid)
        print(f"  Executed. Members now: {len(reg.members())}. D is a member: "
              f"{d.commitment in reg.members()}")
        d.sync()
        print(f"  D's watchlist after first sync: {len(d.watchlist)} common threats")

        summary.update({
            "common_threats": len(common),
            "total_reports": reg.contract.functions.totalReports().call(),
            "members": len(reg.members()),
            "seconds": round(time.time() - t_start, 1),
        })
        summary["early_warnings_company_c"] = len([a for a in nodes["C"].alerter.sent
                                                   if a.known_locally is None])
        (demo_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        if args.check:
            c = summary["company_c"]
            checks = {
                "3 common threats (shared attacker + 2 report overlaps)": summary["common_threats"] == 3,
                "scanner seen by one company stays below threshold": reg.indicator(scanner_hash)["reports"] == 1,
                "Company C got 3 early warnings": summary["early_warnings_company_c"] == 3,
                "every attack flow at C blocked": c["blocked_with_consortium"] == c["attack_flows"],
                "no legitimate flow blocked": c["legitimate_blocked"] == 0,
                "C's model alone misses most of the novel variant": c["model_alone_flagged"] < c["attack_flows"] / 2,
                "Company D admitted": summary["members"] == 4,
            }
            for name, ok in checks.items():
                print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
            if not all(checks.values()):
                sys.exit(1)
        banner(f"Done in {summary['seconds']}s. Summary: {demo_dir / 'summary.json'}")
    finally:
        if not args.keep_chain:
            stop_chain(chain)


if __name__ == "__main__":
    main()
