"""Turn a Zeek ``conn.log`` into the flow features the detectors use.

Zeek (formerly Bro) is the most widely deployed open-source network sensor:
it watches traffic and writes one summary line per connection to ``conn.log``.
NSL-KDD's features were originally computed from Bro connection records, so
most of them can be rebuilt from a modern Zeek log:

* **Basic features** (8 of them) come straight from the record: duration,
  protocol, service (from the destination port), connection state, bytes.
* **2-second window features** (9): for each connection, look at the
  connections in the previous 2 seconds to the same destination host / the
  same service, and count them or measure how many failed (SYN errors such as
  half-open floods, REJ errors such as closed-port scans).
* **Host window features** (10): the same idea over the last 255 connections,
  which catches slow scans that 2 seconds would miss.

What Zeek's conn.log can NOT give: the 13 *content* features (failed logins,
root shells, file creations...), which in 1999 came from inspecting packet
payloads, plus two packet-level counters (wrong fragments, urgent packets).
Models used on Zeek data are therefore trained without them: see
``NETWORK_FEATURES`` and ``python -m dtds.ingest.train_network_model``.

Exact window definitions for KDD's derived features vary between papers; the
ones here follow the published feature descriptions and match the dataset's
value ranges (counts include the current connection; capped at 511 and 255).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Union

import numpy as np
import pandas as pd

# Features rebuildable from conn.log (the NSL-KDD names, so models trained on
# NSL-KDD restricted to these columns accept Zeek-derived flows unchanged).
BASIC = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land"]
TIME_WINDOW = ["count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
               "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate"]
HOST_WINDOW = ["dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
               "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
               "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
               "dst_host_srv_rerror_rate"]
NETWORK_FEATURES = BASIC + TIME_WINDOW + HOST_WINDOW

# Payload- and packet-level features a conn.log cannot provide.
CONTENT_FEATURES = ["wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
                    "num_compromised", "root_shell", "su_attempted", "num_root",
                    "num_file_creations", "num_shells", "num_access_files", "is_host_login",
                    "is_guest_login"]

NEEDED_COLUMNS = {"ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration",
                  "orig_bytes", "resp_bytes", "conn_state"}

TIME_WINDOW_SECONDS = 2.0
HOST_WINDOW_CONNECTIONS = 255

# Destination port -> NSL-KDD service name (well-known assignments).
TCP_SERVICES = {
    7: "echo", 9: "discard", 11: "systat", 13: "daytime", 15: "netstat", 20: "ftp_data",
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time", 42: "name", 43: "whois",
    53: "domain", 57: "mtp", 70: "gopher", 71: "remote_job", 77: "rje", 79: "finger",
    80: "http", 87: "link", 95: "supdup", 101: "hostnames", 102: "iso_tsap", 105: "csnet_ns",
    109: "pop_2", 110: "pop_3", 111: "sunrpc", 113: "auth", 117: "uucp_path", 119: "nntp",
    137: "netbios_ns", 138: "netbios_dgm", 139: "netbios_ssn", 143: "imap4", 150: "sql_net",
    175: "vmnet", 179: "bgp", 194: "IRC", 210: "Z39_50", 389: "ldap", 443: "http_443",
    512: "exec", 513: "login", 514: "shell", 515: "printer", 520: "efs", 530: "courier",
    540: "uucp", 543: "klogin", 544: "kshell", 2784: "http_2784", 8001: "http_8001",
}
UDP_SERVICES = {53: "domain_u", 69: "tftp_u", 123: "ntp_u", 137: "netbios_ns", 138: "netbios_dgm"}
# Zeek puts the ICMP type in the originator "port" field.
ICMP_SERVICES = {8: "eco_i", 0: "ecr_i", 3: "urp_i", 5: "red_i", 13: "tim_i", 14: "tim_i"}

# Zeek conn_state -> NSL-KDD flag (identical codes, two Zeek-only states folded in).
FLAG_MAP = {"SF": "SF", "S0": "S0", "S1": "S1", "S2": "S2", "S3": "S3", "REJ": "REJ",
            "RSTO": "RSTO", "RSTR": "RSTR", "RSTOS0": "RSTOS0", "RSTRH": "RSTR", "SH": "SH",
            "SHR": "SH", "OTH": "OTH"}
SYN_ERROR_FLAGS = {"S0", "S1", "S2", "S3"}


def read_conn_log(path: Union[str, Path]) -> pd.DataFrame:
    """Read a conn.log in Zeek's default TSV format or its JSON-lines format."""
    path = Path(path)
    with open(path, encoding="utf-8") as f:
        first = f.readline()
    if first.lstrip().startswith("{"):
        rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
        return pd.DataFrame(rows)
    fields, header_lines = None, 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.startswith("#"):
                break
            header_lines += 1
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
    if fields is None:
        raise ValueError(f"{path}: no '#fields' header; is this a Zeek conn.log?")
    # Only the columns the features need, parsed by pandas' C reader: a million-
    # connection log then fits comfortably in memory.
    use = [c for c in fields if c in NEEDED_COLUMNS]
    df = pd.read_csv(path, sep="\t", skiprows=header_lines, names=fields, usecols=use, dtype=str,
                     na_filter=False, quoting=3, engine="c")
    return df[~df["ts"].str.startswith("#")].reset_index(drop=True)   # drop the trailing "#close" line


def _num(series: pd.Series) -> pd.Series:
    # Zeek writes "-" for unset values.
    return pd.to_numeric(series.replace({"-": np.nan, "(empty)": np.nan}), errors="coerce").fillna(0)


def _service(proto: str, orig_p: int, resp_p: int) -> str:
    if proto == "icmp":
        return ICMP_SERVICES.get(orig_p, "eco_i")
    if proto == "tcp":
        if 6000 <= resp_p <= 6063:
            return "X11"
        return TCP_SERVICES.get(resp_p, "other" if resp_p < 1024 else "private")
    return UDP_SERVICES.get(resp_p, "other" if resp_p < 1024 else "private")


def conn_to_flows(conn: pd.DataFrame) -> pd.DataFrame:
    """One row per connection with NETWORK_FEATURES + src_ip/dst_ip/ts columns."""
    c = conn.copy()
    ts = _num(c["ts"]).to_numpy(dtype=float)
    order = np.argsort(ts, kind="stable")
    c = c.iloc[order].reset_index(drop=True)
    ts = ts[order]
    proto = c["proto"].astype(str).str.lower().to_numpy()
    orig_p = _num(c["id.orig_p"]).astype(int).to_numpy()
    resp_p = _num(c["id.resp_p"]).astype(int).to_numpy()
    src = c["id.orig_h"].astype(str).to_numpy()
    dst = c["id.resp_h"].astype(str).to_numpy()
    flag = c["conn_state"].astype(str).map(FLAG_MAP).fillna("OTH").to_numpy()
    service = np.array([_service(p, o, r) for p, o, r in zip(proto, orig_p, resp_p)], dtype=object)

    out = pd.DataFrame({
        "duration": _num(c["duration"]).to_numpy(),
        "protocol_type": np.where(np.isin(proto, ["tcp", "udp", "icmp"]), proto, "tcp"),
        "service": service,
        "flag": flag,
        "src_bytes": _num(c["orig_bytes"]).to_numpy(),
        "dst_bytes": _num(c["resp_bytes"]).to_numpy(),
        "land": ((src == dst) & (orig_p == resp_p)).astype(int),
    })

    syn_err = np.isin(flag, list(SYN_ERROR_FLAGS))
    rej_err = flag == "REJ"
    n = len(out)
    feats = {k: np.zeros(n) for k in TIME_WINDOW + HOST_WINDOW}
    start = 0
    for i in range(n):
        # ---- 2-second window: connections in (ts_i - 2s, ts_i], including i ----
        while ts[start] <= ts[i] - TIME_WINDOW_SECONDS:
            start += 1
        w = slice(start, i + 1)
        same_host = dst[w] == dst[i]
        same_srv = service[w] == service[i]
        nh, ns = int(same_host.sum()), int(same_srv.sum())
        feats["count"][i] = min(nh, 511)
        feats["srv_count"][i] = min(ns, 511)
        feats["serror_rate"][i] = syn_err[w][same_host].mean()
        feats["rerror_rate"][i] = rej_err[w][same_host].mean()
        feats["same_srv_rate"][i] = same_srv[same_host].mean()
        feats["diff_srv_rate"][i] = 1 - feats["same_srv_rate"][i]
        feats["srv_serror_rate"][i] = syn_err[w][same_srv].mean()
        feats["srv_rerror_rate"][i] = rej_err[w][same_srv].mean()
        feats["srv_diff_host_rate"][i] = (~same_host[same_srv]).mean()

        # ---- host window: the last 255 connections, including i ----
        hw = slice(max(0, i + 1 - HOST_WINDOW_CONNECTIONS), i + 1)
        h_host = dst[hw] == dst[i]
        h_srv = service[hw] == service[i]
        feats["dst_host_count"][i] = min(int(h_host.sum()), 255)
        feats["dst_host_srv_count"][i] = min(int(h_srv.sum()), 255)
        feats["dst_host_same_srv_rate"][i] = h_srv[h_host].mean()
        feats["dst_host_diff_srv_rate"][i] = 1 - feats["dst_host_same_srv_rate"][i]
        feats["dst_host_same_src_port_rate"][i] = (orig_p[hw][h_host] == orig_p[i]).mean()
        feats["dst_host_srv_diff_host_rate"][i] = (~h_host[h_srv]).mean()
        feats["dst_host_serror_rate"][i] = syn_err[hw][h_host].mean()
        feats["dst_host_srv_serror_rate"][i] = syn_err[hw][h_srv].mean()
        feats["dst_host_rerror_rate"][i] = rej_err[hw][h_host].mean()
        feats["dst_host_srv_rerror_rate"][i] = rej_err[hw][h_srv].mean()
    for k, v in feats.items():
        out[k] = np.round(v, 2) if k.endswith("rate") else v
    out["src_ip"] = src
    out["dst_ip"] = dst
    out["ts"] = ts
    return out


def load_flows(path: Union[str, Path]) -> pd.DataFrame:
    return conn_to_flows(read_conn_log(path))
