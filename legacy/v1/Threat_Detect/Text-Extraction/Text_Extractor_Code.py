import os as o
import re
import spacy as sp
import json as js
import csv
import pandas as pd
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup as bs
from pdfminer.high_level import extract_text
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from docx import Document
from email import message_from_file
from stix2 import parse as parse_stix
from datetime import datetime, timezone # <--- CHANGED THIS LINE
# import requests # <--- REMOVE OR COMMENT OUT THIS LINE, NO LONGER NEEDED FOR FILE-BASED COMMUNICATION

nlp = sp.load("en_core_web_sm")

filepath = input('Enter the file path: ')
ext = o.path.splitext(filepath)[1].lower()

# --- NEW CONSTANT FOR FILE-BASED COMMUNICATION ---
# This path must match MONITORED_DIR in simple_threat_processor.py
# It's recommended to make this a relative path if both scripts are run
# from the same parent directory, or an absolute path if they are elsewhere.
SHARED_INBOX_DIR = "threat_inbox"
# --- END NEW CONSTANT ---

# ========== TEXT EXTRACTION (unchanged) ==========
def extract_text_from_file(filepath):
    try:
        if ext == '.pdf':
            return extract_text(filepath)

        elif ext in ['.html', '.htm']:
            with open(filepath, 'r', encoding='utf-8') as f:
                global soup
                soup = bs(f, 'lxml')
                return soup.get_text(separator='\n')

        elif ext == '.txt':
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()

        elif ext == '.docx':
            doc = Document(filepath)
            return '\n'.join([para.text for para in doc.paragraphs])

        elif ext == '.csv':
            with open(filepath, newline='', encoding='utf-8') as f:
                return '\n'.join(f.read().splitlines())

        elif ext == '.xlsx':
            df = pd.read_excel(filepath)
            return df.to_string(index=False)

        elif ext == '.json':
            with open(filepath, 'r', encoding='utf-8') as f:
                data = js.load(f)
                return js.dumps(data, indent=2)

        elif ext == '.xml':
            tree = ET.parse(filepath)
            root = tree.getroot()
            return ET.tostring(root, encoding='unicode')

        elif ext == '.ioc':  # OpenIOC file
            tree = ET.parse(filepath)
            root = tree.getroot()
            return ET.tostring(root, encoding='unicode')

        elif ext in ['.stix', '.stix2']:  # STIX 2.x JSON format
            with open(filepath, 'r', encoding='utf-8') as f:
                stix_obj = parse_stix(f.read())
                return js.dumps(stix_obj.serialize(), indent=2)

        elif ext == '.eml':
            with open(filepath, 'r', encoding='utf-8') as fp_eml:
                msg = message_from_file(fp_eml)
                email_body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        cdispo = str(part.get('Content-Disposition'))

                        if ctype == 'text/plain' and 'attachment' not in cdispo:
                            email_body += part.get_payload(decode=True).decode('utf-8', errors='ignore') + "\n"
                        elif ctype == 'text/html' and 'attachment' not in cdispo:
                            html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            email_body += bs(html_content, 'html.parser').get_text() + "\n"
                else:
                    email_body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

                email_headers = "\n".join([f"{k}: {v}" for k, v in msg.items()])
                return email_body.strip() + '\n\n' + email_headers.strip()

        else:
            print(f"[!] Unsupported File Type: {ext}")
            return ''

    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
        return ''

# ========== GET RAW TEXT (unchanged) ==========
fp_text_content = extract_text_from_file(filepath) # Renamed 'fp' to 'fp_text_content' for clarity
if not fp_text_content:
    print("[!] No data extracted. Exiting...")
    exit()

# ========== TEXT CLEANUP (Safe Version) (unchanged) ==========
fp_text_content = re.sub(r'\n+', ' ', fp_text_content)
fp_text_content = re.sub(r'\s{2,}', ' ', fp_text_content)
fp_text_content = re.sub(r'(?<=\b\w)\s(?=\w\b)', '', fp_text_content) # This line usually removes spaces between single letters, be careful if that's not intended.

# ========== REGEX IOCs (unchanged) ==========
try:
    raw_ips = re.findall(r'\b\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}\b', fp_text_content)
except Exception as e:
    print("[!] Error extracting IPv4 addresses:", e)
    raw_ips = []

extract1 = {
    'ipv4': list(set(ip.replace('[.]', '.') for ip in raw_ips)),
    'ipv6': re.findall(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', fp_text_content),
    'url': re.findall(r'https?://[^\s"\']+', fp_text_content) + re.findall(r'\b(?:www\.)[a-zA-Z0-9-]+\.[a-zA-Z]{2,6}\b', fp_text_content),
    'md5': re.findall(r'\b[a-fA-F0-9]{32}\b', fp_text_content),
    'sha1': re.findall(r'\b[a-fA-F0-9]{40}\b', fp_text_content),
    'sha256': re.findall(r'\b[a-fA-F0-9]{64}\b', fp_text_content),
    'attack_id': re.findall(r'T\d{4}(?:\.\d{3})?', fp_text_content)
}

# ========== NLP Named Entities (unchanged) ==========
doc = nlp(fp_text_content)
seen_entities = set()
extract2 = []
for ent in doc.ents:
    key = (ent.text, ent.label_)
    if key not in seen_entities:
        seen_entities.add(key)
        extract2.append({"text": ent.text, "label": ent.label_, "start": ent.start_char, "end": ent.end_char})

from collections import OrderedDict
threat_actors = list(OrderedDict.fromkeys(
    ent.text for ent in doc.ents if ent.label_ in ["ORG", "PERSON", "PRODUCT"]
))

# ========== HTML Metadata (unchanged) ==========
extract3 = {}
if ext in ['.html', '.htm']:
    try:
        extract3 = {
            'title': soup.title.text if soup.title else None,
            'urls': [a['href'] for a in soup.find_all('a', href=True)],
            'images': [img['src'] for img in soup.find_all('img', src=True)],
            'author': soup.find('meta', attrs={'name': 'author'})['content'] if soup.find('meta', attrs={'name': 'author'}) else None,
            'report_date': soup.find('meta', attrs={'name': 'date'})['content'] if soup.find('meta', attrs={'name': 'date'}) else None,
            'source': soup.find('meta', attrs={'name': 'source'})['content'] if soup.find('meta', attrs={'name': 'source'}) else None
        }
    except Exception as e:
        print("[!] Error extracting HTML metadata:", e)

# ========== PDF Metadata (unchanged) ==========
extract4 = {}
if ext == '.pdf':
    try:
        with open(filepath, 'rb') as file:
            parser = PDFParser(file)
            document = PDFDocument(parser)
            if hasattr(document, 'info') and document.info:
                metadata = document.info[0]
                for key, value in metadata.items():
                    try:
                        extract4[key.decode('utf-8')] = value.decode('utf-8')
                    except:
                        extract4[key.decode('utf-8')] = str(value)
    except Exception as e:
        print("[!] PDF metadata extraction failed:", e)

# ========== NORMALIZED STRUCTURE (unchanged) ==========
def normalize_output(extract1, extract2):
    # Use timezone.utc for current timestamp, compatible with older Python versions
    normalized = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z", # <--- CHANGED THIS LINE
        "hashes": extract1["md5"] + extract1["sha1"] + extract1["sha256"],
        "ips": extract1["ipv4"] + extract1["ipv6"],
        "domains": [u for u in extract1["url"] if not u.startswith("http")],
        "ttp_ids": extract1["attack_id"],
        "confidence": 90
    }
    return normalized

normalized_output = normalize_output(extract1, extract2)

# ========== FINAL OUTPUT (unchanged) ==========
final_output = {
    'regex_iocs': extract1,
    'nlp_entities': extract2,
    'threat_actors': threat_actors,
    'html_metadata': extract3,
    'pdf_metadata': extract4,
    'normalized_vector': normalized_output
}

# --- LOCAL FILE SAVING (Keep if you still want local output) ---
out_name = o.path.splitext(o.path.basename(filepath))[0] + '_output.json'
try:
    with open(out_name, 'w', encoding='utf-8') as f:
        js.dump(final_output, f, indent=4)
    print(f"[✓] Local output saved to {out_name}")
except Exception as e:
    print(f"[!] Failed to save local JSON: {e}")
# ---------------------------------------------------------------

# ========== NEW FUNCTION TO SEND DATA TO THREAT PROCESSOR (FILE-BASED) ==========
def send_to_threat_processor(data_payload: dict, original_filepath: str):
    """
    Writes the processed threat data to a JSON file in the shared inbox directory.
    This file will then be picked up by the SimpleThreatProcessor.
    """
    try:
        # Ensure the inbox directory exists
        o.makedirs(SHARED_INBOX_DIR, exist_ok=True)
        
        # Create a unique filename for the output JSON, including timestamp
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        original_filename_base = o.path.basename(original_filepath).split('.')[0]
        output_filename = f"threat_data_{original_filename_base}_{timestamp_str}.json"
        output_filepath = o.path.join(SHARED_INBOX_DIR, output_filename)

        # Structure the payload as expected by the SimpleThreatProcessor
        # (threat_detection, zk_proof, source)
        payload = {
            "threat_detection": data_payload,
            "zk_proof": {}, # Placeholder: If you generate ZK proofs, insert them here
            "source": f"text_extractor_for_{o.path.basename(original_filepath)}"
        }

        # Write the payload to the file
        with open(output_filepath, 'w', encoding='utf-8') as f:
            js.dump(payload, f, indent=2)

        print(f"\n[INFO] Wrote threat data to file: '{output_filepath}'")
        print("[✓] Data sent successfully to threat processor (via file).")

        return {"status": "file_written", "filepath": output_filepath}

    except Exception as e:
        print(f"[ERROR] An unexpected error occurred while writing data to file: {e}")
        return None

# ========== Execute Sending to Threat Processor (File-Based) ==========
send_to_threat_processor(final_output, filepath)