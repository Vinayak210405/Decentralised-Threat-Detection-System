from pathlib import Path

import pytest

from dtds.extraction import extract_file, extract_iocs, refang
from dtds.extraction.iocs import canonical

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "reports"


def test_refang_variants():
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang("1.2.3(.)4") == "1.2.3.4"
    assert refang("bad[@]mail[.]ru") == "bad@mail.ru"
    assert refang("evil[dot]com") == "evil.com"


def test_defanged_and_plain_give_same_canonical_ioc():
    a = extract_iocs("C2 at hxxp://download[.]malwar3[.]xyz/index.php").canonical()
    b = extract_iocs("C2 at http://download.malwar3.xyz/index.php").canonical()
    assert a == b == ["url:http://download.malwar3.xyz/index.php"]


def test_private_and_documentation_ips_are_dropped():
    r = extract_iocs("internal 192.168.1.1 and 10.0.0.1, doc 2001:db8::1, real 185.100.87.202")
    assert r.iocs["ipv4"] == ["185.100.87.202"]
    assert "192.168.1.1" in r.dropped_non_public_ips
    assert "ipv6" not in r.iocs


def test_benign_infrastructure_is_dropped():
    r = extract_iocs("they pinged 8.8.8.8 then beaconed to 51.89.181.64; email report@cisa.gov")
    assert r.iocs["ipv4"] == ["51.89.181.64"]
    assert "ipv4:8.8.8.8" in r.dropped_benign
    assert "email" not in r.iocs


def test_hashes_not_double_counted_and_lowercased():
    sha256 = "9C56CC51B374F3D4E4517A1E15B0431D5071D81B492A13475E8A2C46542E5DE9"
    r = extract_iocs(f"sample {sha256}")
    assert r.iocs == {"sha256": [sha256.lower()]}


def test_spaced_attack_ids_and_cves():
    r = extract_iocs("Technique T 1 5 6 6 . 0 0 2 exploiting cve-2021-44228")
    assert r.attack_techniques == ["T1566.002"]
    assert r.cves == ["CVE-2021-44228"]
    assert r.count() == 0  # context, not shareable indicators


def test_filenames_are_not_domains():
    r = extract_iocs("dropped winring0x64.sys and payload.exe, read aa22-320a.stix; C2 lennut.com")
    assert r.iocs["domain"] == ["lennut.com"]


def test_ipv6_canonical_form():
    assert canonical("ipv6", "2001:0DB8:0000:0000:0000:0000:0000:0001") == "ipv6:2001:db8::1"


def test_sample_threat_report_txt():
    r = extract_file(SAMPLES / "threat_report.txt")
    assert r.iocs["ipv4"] == ["182.54.217.2"]  # from the defanged 182.54.217[.]2
    assert r.iocs["md5"] == ["44d88612fea8a8f36de82e1278abb02f"]
    assert r.iocs["url"] == ["https://malicious-domain.com/payload.exe"]
    assert "192.168.1.1" in r.dropped_non_public_ips


def test_obfuscated_sample_report():
    r = extract_file(SAMPLES / "test_report.txt")
    assert set(r.iocs["ipv4"]) == {"185.100.87.202", "51.91.12.55"}
    assert r.iocs["sha1"] == ["2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"]
    assert r.attack_techniques == ["T1566.002"]


def test_docx_reports_overlap():
    a = set(extract_file(SAMPLES / "threat_report.docx").canonical())
    b = set(extract_file(SAMPLES / "similar.docx").canonical())
    assert a & b == {"ipv4:182.54.217.2", "sha1:2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"}


def test_real_cisa_pdf():
    pytest.importorskip("pdfminer")
    r = extract_file(SAMPLES / "cisa_aa22-320a_iranian_apt.pdf")
    assert "182.54.217.2" in r.iocs["ipv4"]
    assert "8.8.8.8" not in r.iocs["ipv4"]
    assert "T1003.001" in r.attack_techniques
