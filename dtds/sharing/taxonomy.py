"""Threat categories and severity levels as stored on-chain (uint8)."""
from __future__ import annotations

from enum import IntEnum


class Category(IntEnum):
    UNKNOWN = 0
    DOS = 1               # denial of service / flooding
    RECON = 2             # probing, port scans
    REMOTE_ACCESS = 3     # remote-to-local: password guessing, exploited services (R2L)
    PRIVILEGE_ESC = 4     # user-to-root (U2R)
    MALWARE = 5
    PHISHING = 6
    C2 = 7                # command and control
    WEB_ATTACK = 8
    BOTNET = 9
    BRUTE_FORCE = 10
    INTEL_REPORT = 11     # indicator taken from a threat-intelligence report


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ML label (from any supported dataset) -> category.
ML_LABEL_TO_CATEGORY = {
    "DoS": Category.DOS, "Probe": Category.RECON, "R2L": Category.REMOTE_ACCESS,
    "U2R": Category.PRIVILEGE_ESC, "Botnet": Category.BOTNET, "BruteForce": Category.BRUTE_FORCE,
    "WebAttack": Category.WEB_ATTACK, "Infiltration": Category.REMOTE_ACCESS,
    "Exploits": Category.REMOTE_ACCESS, "Reconnaissance": Category.RECON,
    "Backdoor": Category.C2, "Shellcode": Category.MALWARE, "Worms": Category.MALWARE,
    "Generic": Category.UNKNOWN, "Fuzzers": Category.RECON, "Analysis": Category.RECON,
}

BASE_SEVERITY = {
    Category.DOS: Severity.HIGH, Category.RECON: Severity.LOW,
    Category.REMOTE_ACCESS: Severity.HIGH, Category.PRIVILEGE_ESC: Severity.CRITICAL,
    Category.MALWARE: Severity.HIGH, Category.PHISHING: Severity.MEDIUM, Category.C2: Severity.CRITICAL,
    Category.WEB_ATTACK: Severity.MEDIUM, Category.BOTNET: Severity.HIGH,
    Category.BRUTE_FORCE: Severity.MEDIUM, Category.INTEL_REPORT: Severity.MEDIUM,
    Category.UNKNOWN: Severity.LOW,
}


def severity_for(category: Category, flows: int = 1, confidence: float = 1.0) -> Severity:
    """Category baseline, raised one level for sustained, confident detections."""
    sev = int(BASE_SEVERITY[category])
    if flows >= 50 and confidence >= 0.9:
        sev += 1
    if confidence < 0.6:
        sev -= 1
    return Severity(max(0, min(4, sev)))
