"""Run a Zeek conn.log through a company's detector.

    python -m dtds.ingest samples/zeek/syn_flood.log --baseline samples/zeek/baseline.log
    python -m dtds.ingest conn.log                  # classifier only, no baseline

With --baseline (a conn.log of known-clean traffic from the SAME network), the
hybrid detector (classifier + autoencoder) is calibrated to this network's own
normal behaviour, which is how it catches attacks the classifier was never
trained on without flooding you with false alarms.

Prints, per external source address, how many connections it made and how many
the detector flagged, and lists the findings the node would share with the
consortium. Nothing is sent anywhere: sharing is a separate, explicit step.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dtds.ingest.zeek import load_flows
from dtds.node import CompanyNode, is_internal
from dtds.paths import MODELS_DIR, NODES_DIR


def ensure_network_model(path: Path) -> Path:
    if not path.exists():
        print(f"{path.name} not found; training the network-only classifier on NSL-KDD (~20 s) ...")
        from dtds.ingest.train_network_model import main as train
        train(["--models", path.stem.split("_")[-1]])
    return path


def ensure_network_hybrid(path: Path) -> Path:
    if not path.exists():
        print(f"{path.name} not found; training the network-only hybrid on NSL-KDD (~40 s) ...")
        from dtds.ingest.train_network_model import save_network_hybrid
        save_network_hybrid()
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("conn_log", type=Path)
    ap.add_argument("--baseline", type=Path, default=None,
                    help="conn.log of clean traffic from this network: enables the calibrated hybrid")
    ap.add_argument("--target-far", type=float, default=0.02, help="false-alarm budget for --baseline")
    ap.add_argument("--model", type=Path, default=None, help="override the model file")
    ap.add_argument("--min-flows", type=int, default=5, help="attack flows needed to report a source")
    ap.add_argument("--min-share", type=float, default=0.2,
                    help="share of a source's connections that must be flagged to report it")
    ap.add_argument("--node-dir", type=Path, default=NODES_DIR / "ingest")
    args = ap.parse_args(argv)

    flows = load_flows(args.conn_log)
    print(f"{args.conn_log}: {len(flows):,} connections, "
          f"{flows['src_ip'].nunique()} source addresses")
    if args.baseline:
        path = args.model or ensure_network_hybrid(MODELS_DIR / "nsl-kdd-network_hybrid.joblib")
    else:
        path = args.model or ensure_network_model(MODELS_DIR / "nsl-kdd-network_hgb.joblib")
    node = CompanyNode("local", args.node_dir, consortium_key=bytes(32), registry=None,
                       detector_path=path)
    if args.baseline:
        base = load_flows(args.baseline)
        node.detector["hybrid"].calibrate_to_baseline(base[node.detector["features"]], args.target_far)
        print(f"Hybrid calibrated on {len(base):,} baseline connections "
              f"({args.target_far:.0%} false-alarm budget)")
    else:
        print("Classifier only (pass --baseline to enable the calibrated hybrid detector)")
    result = node.process_traffic(flows, min_flows=args.min_flows, min_share=args.min_share)
    print(f"Flagged as attacks: {result.flagged_by_model:,} of {result.total_flows:,} connections\n")
    external = {ip: v for ip, v in result.per_source.items() if not is_internal(ip)}
    print(f"{'source':<18}{'connections':>12}{'flagged':>10}")
    for ip, v in sorted(external.items(), key=lambda kv: -kv[1]["attack_flows"])[:15]:
        print(f"{ip:<18}{v['flows']:>12,}{v['attack_flows']:>10,}")
    print(f"\nFindings to share ({len(result.findings)}):")
    for f in result.findings:
        print(f"  {f.ioc:<24} {f.category.name:<14} {f.severity.name:<9} {f.details}")
    if not result.findings:
        print("  none")


if __name__ == "__main__":
    main()
