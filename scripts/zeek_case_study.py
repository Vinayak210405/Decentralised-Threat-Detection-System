"""Case study: the network-only detectors on REAL Zeek logs (WRCCDC 2018).

Data: the Brim/Zed sample Zeek logs, generated from packet captures of the 2018
Western Regional Collegiate Cyber Defense Competition, where a professional red
team attacks networks defended by student teams. Real traffic, real attacks,
but NO labels. Licence: CC BY-SA 4.0 (WRCCDC; Brim Data). The data is not
redistributed here; download it with:

    curl -LO https://raw.githubusercontent.com/brimdata/zed-sample-data/main/zeek-default/conn.log.gz
    gunzip conn.log.gz
    python scripts/zeek_case_study.py conn.log

Because there are no labels, sources are compared with a transparent
behavioural rule, the same idea as Zeek's own scan detection:
  * "likely scanner": contacted >= 100 distinct (host, port) pairs and at least
    half of its connections failed (no handshake, or rejected).
  * "likely benign": contacted <= 10 distinct (host, port) pairs and at least
    90% of its connections completed normally (state SF).
Everything else is "unclear". This rule is a proxy, not ground truth.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dtds.ingest.zeek import conn_to_flows, read_conn_log  # noqa: E402
from dtds.paths import MODELS_DIR, REPORTS_DIR, ensure  # noqa: E402

FAILED = {"S0", "REJ", "RSTOS0", "RSTR", "SH", "OTH"}


def behaviour(conn: pd.DataFrame) -> pd.DataFrame:
    c = conn.assign(pair=conn["id.resp_h"] + ":" + conn["id.resp_p"])
    g = c.groupby("id.orig_h")
    out = pd.DataFrame({
        "connections": g.size(),
        "distinct_targets": g["pair"].nunique(),
        "distinct_hosts": g["id.resp_h"].nunique(),
        "failed_share": g["conn_state"].agg(lambda s: s.isin(FAILED).mean()),
        "completed_share": g["conn_state"].agg(lambda s: (s == "SF").mean()),
    })
    out["proxy"] = np.where((out.distinct_targets >= 100) & (out.failed_share >= 0.5), "likely scanner",
                            np.where((out.distinct_targets <= 10) & (out.completed_share >= 0.9),
                                     "likely benign", "unclear"))
    return out


def classify(flows: pd.DataFrame, model_path, calibrate_on=None):
    m = joblib.load(model_path) if isinstance(model_path, (str, Path)) else model_path
    X = flows[m["features"]]
    if "hybrid" in m:
        if calibrate_on is not None:
            m["hybrid"].calibrate_to_baseline(X[calibrate_on])
        pred = m["hybrid"].predict(X)
        conf = np.where(pred != "Normal", 1.0, 0.0)
    else:
        p = m["pipeline"].predict_proba(X)
        pred = np.array(list(m["pipeline"].classes_))[p.argmax(1)]
        conf = p.max(1)
    return pred, conf


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("conn_log", type=Path)
    ap.add_argument("--out", type=Path, default=REPORTS_DIR / "zeek-wrccdc")
    ap.add_argument("--min-flows", type=int, default=5)
    args = ap.parse_args()
    t0 = time.time()
    conn = read_conn_log(args.conn_log)
    flows = conn_to_flows(conn)
    print(f"{len(flows):,} connections, features in {time.time() - t0:.0f}s")
    beh = behaviour(conn)

    # No clean baseline period exists in a competition capture, so the closest
    # substitute: calibrate on the flows of HALF the likely-benign sources (split
    # alternately by size) and evaluate on everything else. Those calibration
    # sources are then excluded from the benign figures.
    benign = beh.index[beh.proxy == "likely benign"]
    by_size = beh.loc[benign].sort_values("connections", ascending=False).index
    calib_sources = set(by_size[::2])
    calib_mask = flows.src_ip.isin(calib_sources).to_numpy()
    models = {"classifier": (MODELS_DIR / "nsl-kdd-network_hgb.joblib", None),
              "hybrid (uncalibrated)": (MODELS_DIR / "nsl-kdd-network_hybrid.joblib", None),
              "hybrid (calibrated on half the benign sources)": (MODELS_DIR / "nsl-kdd-network_hybrid.joblib",
                                                                 calib_mask)}
    for name, (path, _) in models.items():
        if not path.exists():
            sys.exit(f"{path} missing: run `python -m dtds.ingest.train_network_model --hybrid` first")
    res = {"connections": int(len(flows)), "sources": int(beh.shape[0]),
           "hours": float((flows.ts.max() - flows.ts.min()) / 3600),
           "conn_state": conn["conn_state"].value_counts().head(8).to_dict(),
           "proxy_counts": beh.proxy.value_counts().to_dict(), "detectors": {}}
    per_source = beh.copy()
    proxy_of_flow = flows.src_ip.map(beh.proxy).to_numpy()
    held_out = ~flows.src_ip.isin(calib_sources).to_numpy()
    res["calibration_sources"] = len(calib_sources)
    for name, (path, calib) in models.items():
        pred, conf = classify(flows, path, calib)
        attack = (pred != "Normal") & (conf >= 0.8)
        d = pd.DataFrame({"src": flows.src_ip.to_numpy(), "attack": attack, "pred": pred})
        g = d.groupby("src")
        flagged = g["attack"].sum()
        top = d[d.attack].groupby("src")["pred"].agg(lambda s: s.value_counts().index[0])
        share = flagged / g.size()
        reported = flagged >= args.min_flows
        reported_share = reported & (share >= 0.2)
        per_source[f"{name}: flagged"] = flagged
        per_source[f"{name}: reported"] = reported
        per_source[f"{name}: category"] = top
        tab = {}
        for proxy in ("likely scanner", "likely benign", "unclear"):
            srcs = [s for s in beh.index[beh.proxy == proxy] if s not in calib_sources]
            flows_in = (proxy_of_flow == proxy) & held_out
            tab[proxy] = {"sources": int(len(srcs)), "reported": int(reported.reindex(srcs).fillna(False).sum()),
                          "reported_share_rule": int(reported_share.reindex(srcs).fillna(False).sum()),
                          "flows_flagged_share": float(attack[flows_in].mean()) if flows_in.any() else None}
        res["detectors"][name] = {
            "flows_flagged_share": float(attack.mean()),
            "by_proxy": tab,
            "categories_of_flagged_flows": pd.Series(pred[attack]).value_counts().to_dict(),
        }
        print(f"{name}: {attack.mean():.1%} of flows flagged; {tab}")
    out = ensure(args.out)
    (out / "case_study.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    top = per_source.sort_values("connections", ascending=False).head(15)
    lines = ["# Case study: real Zeek logs (WRCCDC 2018)", "",
             f"{res['connections']:,} real connections from {res['sources']:,} sources over "
             f"{60 * res['hours']:.0f} minutes of the 2018 Western Regional Collegiate Cyber Defense "
             "Competition, where a red team attacks student-defended networks. Data: Brim/Zed sample "
             "Zeek logs (CC BY-SA 4.0), not redistributed here. **No labels exist**, so sources are "
             "compared with a behavioural proxy (see `scripts/zeek_case_study.py`), not ground truth.", "",
             "Connection states: " + ", ".join(f"{k} {v:,}" for k, v in res["conn_state"].items()) +
             " (S0 = no handshake, REJ = rejected: the footprint of mass scanning).", "",
             "## Results", "",
             f"Benign figures exclude the {res['calibration_sources']} likely-benign sources used to "
             "calibrate the third detector, so all three are measured on the same held-out sources.", "",
             "| Detector | Scanner connections flagged | Benign connections flagged | Scanners reported | "
             "Benign sources reported | Unclear sources reported |",
             "|---|---|---|---|---|---|"]
    for name, d in res["detectors"].items():
        b = d["by_proxy"]
        for rule, key in (("5 flagged", "reported"), ("5 flagged and at least 20%", "reported_share_rule")):
            lines.append(f"| {name}, report if {rule} | {100 * b['likely scanner']['flows_flagged_share']:.1f}% | "
                         f"{100 * b['likely benign']['flows_flagged_share']:.1f}% | "
                         f"{b['likely scanner'][key]} of {b['likely scanner']['sources']} | "
                         f"{b['likely benign'][key]} of {b['likely benign']['sources']} | "
                         f"{b['unclear'][key]} of {b['unclear']['sources']} |")
    lines += ["", "A source is *reported* when 5 or more of its connections are flagged; scanners need "
              "only that for the consortium to learn about them, so source-level detection can be "
              "complete even when many individual scan connections look normal."]
    lines += ["", "## The 15 busiest sources", "",
              "| Source | Connections | Distinct targets | Failed | Proxy | Classifier flagged | Calibrated hybrid flagged |",
              "|---|---|---|---|---|---|---|"]
    for ip, r in top.iterrows():
        lines.append(f"| {ip} | {int(r.connections):,} | {int(r.distinct_targets):,} | "
                     f"{100 * r.failed_share:.0f}% | {r.proxy} | {int(r['classifier: flagged']):,} | "
                     f"{int(r['hybrid (calibrated on half the benign sources): flagged']):,} |")
    (out / "case_study.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Per-source detail is derived from CC BY-SA data: written for local analysis, not committed.
    per_source.to_csv(out / "per_source.local.csv")
    print(f"Report: {out / 'case_study.md'}")


if __name__ == "__main__":
    main()
