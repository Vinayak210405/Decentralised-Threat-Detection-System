"""Threat-report ingestion: file -> text -> indicators of compromise.

    python -m dtds.extraction samples/reports/threat_report.txt
"""
from dtds.extraction.documents import extract_text
from dtds.extraction.iocs import ExtractionResult, canonical, extract_iocs, refang


def extract_file(path, include_non_public_ips: bool = False) -> ExtractionResult:
    return extract_iocs(extract_text(path), include_non_public_ips)


__all__ = ["extract_text", "extract_iocs", "extract_file", "canonical", "refang", "ExtractionResult"]
