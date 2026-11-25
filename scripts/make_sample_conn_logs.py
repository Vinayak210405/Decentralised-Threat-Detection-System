"""Generate SYNTHETIC Zeek conn.log files for testing the ingest pipeline.

These are not captures of real traffic: they are generated from simple,
documented patterns so the expected answer is known. All external addresses are
from the RFC 5737 documentation ranges (never routed on the internet).

    python scripts/make_sample_conn_logs.py      # writes samples/zeek/*.log

* baseline.log   an earlier, independent 10 minutes of clean traffic (different
                 random seed) for learning this network's normal behaviour
* normal.log     ~10 minutes of web, DNS and SSH traffic from 20 internal clients
* syn_flood.log  normal traffic + 203.0.113.66 sending 600 half-open TCP SYNs
                 to 10.0.0.5:80 within 3 seconds (conn_state S0: no handshake)
* port_scan.log  normal traffic + 203.0.113.99 probing ports 1-1024 on 10.0.0.7
                 in 10 seconds (mostly REJ: closed ports reset the connection)
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "samples" / "zeek"
FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
          "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp",
          "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
          "tunnel_parents"]
TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count",
         "count", "string", "bool", "bool", "count", "string", "count", "count", "count", "count",
         "set[string]"]
T0 = 1764000000.0  # fixed start time so files are reproducible


def row(rng, ts, src, sport, dst, dport, proto, service, dur, ob, rb, state, history):
    pkts_o = max(1, int(ob // 500) + 2) if state != "S0" else 1
    pkts_r = max(0, int(rb // 1000) + 1) if state in ("SF", "S1") else (1 if state == "REJ" else 0)
    dur_s = "-" if dur is None else f"{dur:.6f}"
    ob_s = "-" if ob is None else str(int(ob))
    rb_s = "-" if rb is None else str(int(rb))
    uid = "C" + "".join(rng.choice(list("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"), 17))
    return [f"{ts:.6f}", uid, src, str(sport), dst, str(dport), proto, service, dur_s, ob_s, rb_s,
            state, "F", "T", "0", history, str(pkts_o), str(pkts_o * 40 + int(ob or 0)), str(pkts_r),
            str(pkts_r * 40 + int(rb or 0)), "-"]


def normal_traffic(rng, minutes=10, start=T0):
    rows = []
    clients = [f"10.0.0.{i}" for i in range(10, 30)]
    web = [f"198.51.100.{i}" for i in range(10, 25)]
    t = start
    end = start + minutes * 60
    while t < end:
        t += rng.exponential(0.25)
        c = rng.choice(clients)
        kind = rng.random()
        if kind < 0.7:
            port = 443 if rng.random() < 0.7 else 80
            rows.append(row(rng, t, c, int(rng.integers(40000, 60000)), rng.choice(web), port, "tcp",
                            "ssl" if port == 443 else "http", rng.uniform(0.05, 4), rng.integers(200, 2000),
                            rng.integers(1000, 60000), "SF", "ShADadFf"))
        elif kind < 0.95:
            rows.append(row(rng, t, c, int(rng.integers(40000, 60000)), "10.0.0.2", 53, "udp", "dns",
                            rng.uniform(0.001, 0.05), rng.integers(30, 80), rng.integers(60, 300), "SF", "Dd"))
        else:
            rows.append(row(rng, t, c, int(rng.integers(40000, 60000)), "10.0.0.3", 22, "tcp", "ssh",
                            rng.uniform(5, 300), rng.integers(2000, 20000), rng.integers(2000, 40000),
                            "SF", "ShADadFf"))
    return rows


def syn_flood(rng, attacker="203.0.113.66", victim="10.0.0.5", n=600, start=T0 + 200, seconds=3):
    ts = np.sort(rng.uniform(start, start + seconds, n))
    return [row(rng, t, attacker, int(rng.integers(1024, 65535)), victim, 80, "tcp", "-", None, None, None,
                "S0", "S") for t in ts]


def port_scan(rng, attacker="203.0.113.99", victim="10.0.0.7", start=T0 + 300, seconds=10):
    rows = []
    open_ports = {22, 80, 443}
    sport = int(rng.integers(40000, 60000))
    for i, port in enumerate(range(1, 1025)):
        t = start + seconds * i / 1024
        if port in open_ports:
            rows.append(row(rng, t, attacker, sport, victim, port, "tcp", "-", 0.0005, 0, 0, "RSTO", "ShR"))
        else:
            rows.append(row(rng, t, attacker, sport, victim, port, "tcp", "-", 0.0003, 0, 0, "REJ", "Sr"))
    return rows


def write(path: Path, rows):
    rows = sorted(rows, key=lambda r: float(r[0]))
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n")
        f.write("#path\tconn\n#open\t2025-11-24-16-00-00\n")
        f.write("#fields\t" + "\t".join(FIELDS) + "\n#types\t" + "\t".join(TYPES) + "\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
        f.write("#close\t2025-11-24-16-10-00\n")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(2025)
    base = normal_traffic(rng)
    write(OUT / "normal.log", base)
    write(OUT / "syn_flood.log", base + syn_flood(rng))
    write(OUT / "port_scan.log", base + port_scan(rng))
    write(OUT / "baseline.log", normal_traffic(np.random.default_rng(7), start=T0 - 3600))
    for p in sorted(OUT.glob("*.log")):
        print(f"{p.relative_to(ROOT)}: {sum(1 for l in open(p, encoding='utf-8') if not l.startswith('#'))} connections")


if __name__ == "__main__":
    sys.exit(main())
