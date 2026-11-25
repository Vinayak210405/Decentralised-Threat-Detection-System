"""Indicator-of-compromise (IOC) extraction from threat-report text.

Improvements over the v1 extractor:

* **Refanging**: threat reports "defang" indicators so nobody clicks them:
  ``hxxp://evil[.]com``, ``1.2.3[.]4``, ``evil(.)com``, ``user[@]mail``. These
  are converted back before matching.
* **Spaced-out IDs**: ``T 1 5 6 6 . 0 0 2`` is normalised to ``T1566.002``.
* **No false positives from private space**: 192.168.x.x, 10.x, loopback,
  documentation ranges (RFC 5737 / 3849) are internal or placeholder addresses
  and must never be shared as threats.
* **No double counting**: an MD5 is not also reported as part of a SHA-256,
  hashes are lower-cased, IPv6 is put in canonical compressed form.
* **Canonical form**: every IOC becomes ``type:value`` so two companies that see
  the same indicator produce byte-identical strings, and therefore the same
  keyed hash on-chain.

ATT&CK technique IDs and CVEs are extracted as *context* (they describe how an
attack works, and thousands of unrelated attacks share them) but are not
treated as shareable indicators.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Set
from urllib.parse import urlsplit, urlunsplit

SHAREABLE_TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email")

# Common file extensions that look like TLDs in "payload.exe"-style matches.
_NOT_TLDS = {"exe", "dll", "bin", "php", "html", "htm", "js", "zip", "rar", "doc", "docx", "xls",
             "xlsx", "pdf", "txt", "jpg", "png", "gif", "ps1", "bat", "sh", "py", "jar", "msi",
             "iso", "img", "lnk", "vbs", "hta", "tmp", "log", "dat", "cfg", "ini", "json", "xml",
             "stix", "text", "sys", "conf", "config", "dmp", "evtx", "pcap", "pcapng", "yml", "yaml",
             "csv", "tar", "gz", "apk", "elf", "dylib", "scr", "cpl", "ocx", "drv", "vhd", "vmdk",
             "pst", "eml", "cpp", "java", "class", "svg", "css", "aspx", "jsp", "cgi", "bak", "old",
             "key", "pem", "crt", "cer", "sql", "sqlite", "db", "rtf", "xlsm", "docm", "pptx", "ppt"}

# Well-known benign infrastructure that reports mention (e.g. attackers "ping
# 8.8.8.8" to test connectivity). Sharing these would make every member block
# Google DNS. Extend for your environment.
BENIGN = {
    "ipv4": {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
             "208.67.222.222", "208.67.220.220"},
    "ipv6": {"2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111"},
    "domain": {"google.com", "www.google.com", "microsoft.com", "www.microsoft.com", "github.com",
               "cisa.gov", "www.cisa.gov", "us-cert.cisa.gov", "attack.mitre.org", "mitre.org",
               "nist.gov", "nvd.nist.gov", "virustotal.com", "www.virustotal.com", "fbi.gov",
               "www.fbi.gov", "ic3.gov", "www.ic3.gov"},
}
# Report-contact addresses at these domains (and any .gov/.mil) are not indicators.


@dataclass
class ExtractionResult:
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    attack_techniques: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    dropped_non_public_ips: List[str] = field(default_factory=list)
    dropped_benign: List[str] = field(default_factory=list)

    def canonical(self) -> List[str]:
        """Sorted ``type:value`` strings for every shareable IOC."""
        return sorted(f"{t}:{v}" for t, vals in self.iocs.items() for v in vals)

    def count(self) -> int:
        return sum(len(v) for v in self.iocs.values())

    def to_dict(self) -> Dict[str, object]:
        return {"iocs": self.iocs, "attack_techniques": self.attack_techniques, "cves": self.cves,
                "dropped_non_public_ips": self.dropped_non_public_ips,
                "dropped_benign": self.dropped_benign}


def refang(text: str) -> str:
    t = text
    t = re.sub(r"\bhxxp(s?)\b", r"http\1", t, flags=re.I)
    t = re.sub(r"\bfxp\b", "ftp", t, flags=re.I)
    t = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", ".", t, flags=re.I)
    t = re.sub(r"\[\s*:\s*\]", ":", t)
    t = re.sub(r"\[\s*@\s*\]|\[at\]|\(at\)", "@", t, flags=re.I)
    t = re.sub(r"\[\s*/\s*\]", "/", t)
    return t


def _despace_ids(text: str) -> str:
    # "T 1 5 6 6 . 0 0 2" -> "T1566.002"; "C V E - 2 0 2 1 - ..." handled by CVE regex flexibility.
    def join(m):
        return re.sub(r"\s+", "", m.group(0))
    return re.sub(r"\bT(?:\s?\d){4}(?:\s?\.(?:\s?\d){3})?\b", join, text)


_RE = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>()\[\]{}`]+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"),
    "ipv4": re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"),
    "ipv6": re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%\w+)?(?![0-9A-Fa-f:])"),
    "sha256": re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])"),
    "sha1": re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])"),
    "md5": re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])"),
    "domain": re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"),
    "attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
}


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def normalise_url(url: str) -> str:
    url = url.rstrip(".,;:!?'\")]}")
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    netloc = host + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def normalise(ioc_type: str, value: str) -> str:
    """Canonical form so the same indicator always hashes identically."""
    v = value.strip()
    if ioc_type in ("md5", "sha1", "sha256", "domain", "email"):
        return v.lower().rstrip(".")
    if ioc_type in ("ipv4", "ipv6"):
        return str(ipaddress.ip_address(v.split("%")[0]))
    if ioc_type == "url":
        return normalise_url(v)
    raise ValueError(f"unknown IOC type {ioc_type!r}")


def canonical(ioc_type: str, value: str) -> str:
    return f"{ioc_type}:{normalise(ioc_type, value)}"


def extract_iocs(text: str, include_non_public_ips: bool = False) -> ExtractionResult:
    text = _despace_ids(refang(text))
    res = ExtractionResult()
    found: Dict[str, Set[str]] = {t: set() for t in SHAREABLE_TYPES}

    urls = [normalise_url(u) for u in _RE["url"].findall(text)]
    found["url"].update(urls)
    url_hosts = {urlsplit(u).hostname for u in urls}
    emails = {e.lower() for e in _RE["email"].findall(text)}
    found["email"].update(emails)
    email_domains = {e.split("@", 1)[1] for e in emails}

    for ip in _RE["ipv4"].findall(text):
        (found["ipv4"].add(ip) if include_non_public_ips or _public_ip(ip)
         else res.dropped_non_public_ips.append(ip))
    for cand in _RE["ipv6"].findall(text):
        try:
            ip = normalise("ipv6", cand)
        except ValueError:
            continue  # e.g. a timestamp like 10:51:02
        if ipaddress.ip_address(ip).version != 6:
            continue
        (found["ipv6"].add(ip) if include_non_public_ips or _public_ip(ip)
         else res.dropped_non_public_ips.append(ip))

    # Longest hashes first; the lookarounds already stop an MD5 matching inside a SHA-256.
    for t in ("sha256", "sha1", "md5"):
        found[t].update(h.lower() for h in _RE[t].findall(text))

    for d in _RE["domain"].findall(text):
        d = d.lower().rstrip(".")
        tld = d.rsplit(".", 1)[-1]
        if tld in _NOT_TLDS or _RE["ipv4"].fullmatch(d):
            continue
        if d in url_hosts or d in email_domains:
            continue  # already covered by the URL / email indicator
        found["domain"].add(d)
    # A domain also seen with a "www." prefix is the same indicator.
    for d in list(found["domain"]):
        if d.startswith("www.") and d[4:] in found["domain"]:
            found["domain"].discard(d)

    iocs: Dict[str, List[str]] = {}
    for t, vals in found.items():
        keep = []
        for v in sorted({normalise(t, x) for x in vals}):
            host = (urlsplit(v).hostname if t == "url" else v.split("@", 1)[1] if t == "email" else v)
            if (v in BENIGN.get(t, ()) or (t in ("url", "email") and host in BENIGN["domain"])
                    or (t == "email" and host.endswith((".gov", ".mil")))):
                res.dropped_benign.append(f"{t}:{v}")
            else:
                keep.append(v)
        if keep:
            iocs[t] = keep
    res.iocs = iocs
    res.attack_techniques = sorted(set(_RE["attack"].findall(text)))
    res.cves = sorted({c.upper() for c in _RE["cve"].findall(text)})
    res.dropped_non_public_ips = sorted(set(res.dropped_non_public_ips))
    return res


def iter_canonical(results: Iterable[ExtractionResult]) -> List[str]:
    out: Set[str] = set()
    for r in results:
        out.update(r.canonical())
    return sorted(out)
