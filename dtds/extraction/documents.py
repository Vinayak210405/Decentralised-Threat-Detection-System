"""Turn threat-report files into plain text.

Supported: .txt .md .log .csv .json .stix .stix2 .xml .ioc (OpenIOC) .html .htm
.pdf .docx .xlsx .eml. Parsers for binary formats are imported lazily so the
rest of the project works without them installed.
"""
from __future__ import annotations

import json
from email import message_from_binary_file, policy
from pathlib import Path

TEXT_TYPES = {".txt", ".md", ".log", ".csv", ".ioc", ".xml"}


def _html_to_text(html: str) -> str:
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    # Keep link targets: they are often the indicators.
    links = [a.get("href", "") for a in soup.find_all("a")]
    return soup.get_text("\n") + "\n" + "\n".join(links)


def _json_strings(obj) -> str:
    """All string values of a JSON document (works for STIX bundles and MISP events)."""
    out = []

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str):
            out.append(o)
    walk(obj)
    return "\n".join(out)


def extract_text(path) -> str:
    path = Path(path)
    ext = path.suffix.lower()
    if ext in TEXT_TYPES:
        return path.read_text(encoding="utf-8", errors="replace")
    if ext in (".json", ".stix", ".stix2"):
        return _json_strings(json.loads(path.read_text(encoding="utf-8", errors="replace")))
    if ext in (".html", ".htm"):
        return _html_to_text(path.read_text(encoding="utf-8", errors="replace"))
    if ext == ".pdf":
        from pdfminer.high_level import extract_text as pdf_text
        return pdf_text(str(path))
    if ext == ".docx":
        from docx import Document
        doc = Document(str(path))
        parts = [p.text for p in doc.paragraphs]
        for table in doc.tables:
            for row in table.rows:
                parts.append("\t".join(c.text for c in row.cells))
        return "\n".join(parts)
    if ext == ".xlsx":
        import pandas as pd
        sheets = pd.read_excel(path, sheet_name=None, dtype=str)
        return "\n".join(df.to_csv(index=False) for df in sheets.values())
    if ext == ".eml":
        with open(path, "rb") as f:
            msg = message_from_binary_file(f, policy=policy.default)
        parts = [f"{k}: {v}" for k, v in msg.items()]
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            if ctype == "text/plain":
                parts.append(part.get_content())
            elif ctype == "text/html":
                parts.append(_html_to_text(part.get_content()))
        return "\n".join(parts)
    raise ValueError(f"Unsupported file type: {ext}")
