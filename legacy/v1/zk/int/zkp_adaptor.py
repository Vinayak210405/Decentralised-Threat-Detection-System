#!/usr/bin/env python3
"""
Adapter to send ZKP proofs to the threat processor
Combines your proof.json and public.json with threat detection data
"""

import json
import requests
from pathlib import Path
import sys
import os

# Fix Windows encoding issues
if sys.platform == "win32":
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# Safe print function that works on Windows
def safe_print(text):
    """Print function that handles Unicode characters safely on Windows"""
    try:
        print(text)
    except UnicodeEncodeError:
        # Fall back to ASCII-safe version
        ascii_text = text.encode('ascii', 'replace').decode('ascii')
        print(ascii_text)

class ZKPThreatAdapter:
    def __init__(self, processor_url="http://localhost:8080"):
        self.processor_url = processor_url
    
    def load_zkp_files(self, proof_path="proof.json", public_path="public.json"):
        """Load your ZKP proof and public signal files"""
        try:
            with open(proof_path, 'r') as f:
                proof_data = json.load(f)
            
            with open(public_path, 'r') as f:
                public_data = json.load(f)
            
            safe_print(f"[OK] Loaded ZKP files: {proof_path}, {public_path}")
            return proof_data, public_data
        
        except FileNotFoundError as e:
            safe_print(f"[ERROR] File not found: {e}")
            return None, None
        except json.JSONDecodeError as e:
            safe_print(f"[ERROR] Invalid JSON: {e}")
            return None, None
    
    def create_threat_payload(self, proof_data, public_data, threat_info=None):
        """
        Combine ZKP proof with threat detection data
        """
        # Default threat detection data if none provided
        if threat_info is None:
            threat_info = {
                "regex_iocs": {
                    "ipv4": [],
                    "ipv6": [],
                    "url": [],
                    "md5": [],
                    "sha1": [],
                    "sha256": [],
                    "attack_id": []
                },
                "normalized_vector": {
                    "confidence": 50  # Default confidence
                },
                "nlp_entities": []
            }
        
        # Format ZKP proof for the threat processor
        # Handle both formats: {"public_signals": [...]} or just [...]
        if isinstance(public_data, list):
            public_signals = public_data
        else:
            public_signals = public_data.get("public_signals", [])
        
        zk_proof = {
            "pi_a": proof_data.get("pi_a", []),
            "pi_b": proof_data.get("pi_b", []),
            "pi_c": proof_data.get("pi_c", []),
            "protocol": proof_data.get("protocol", "groth16"),
            "curve": proof_data.get("curve", "bn128"),
            "public_signals": public_signals
        }
        
        # Create the complete payload
        payload = {
            "threat_detection": threat_info,
            "zk_proof": zk_proof,
            "source": "zkp_threat_detector"
        }
        
        return payload
    
    def send_to_processor(self, payload):
        """Send the combined payload to the threat processor"""
        try:
            safe_print(f"[SENDING] Sending data to {self.processor_url}...")
            
            response = requests.post(
                self.processor_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                safe_print("[SUCCESS] Successfully sent to threat processor!")
                return result
            else:
                safe_print(f"[ERROR] Error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            safe_print(f"[ERROR] Connection error: {e}")
            return None
    
    def process_zkp_threat(self, proof_path="proof.json", public_path="public.json", threat_info=None):
        """
        Complete workflow: load ZKP files and send to threat processor
        """
        safe_print("[START] Starting ZKP threat processing...")
        
        # Load ZKP files
        proof_data, public_data = self.load_zkp_files(proof_path, public_path)
        if not proof_data or not public_data:
            return None
        
        # Create payload
        payload = self.create_threat_payload(proof_data, public_data, threat_info)
        
        # Send to processor
        result = self.send_to_processor(payload)
        
        if result:
            safe_print("\n[RESULT] PROCESSING RESULT:")
            safe_print(f"Status: {result.get('status')}")
            safe_print(f"Threat Level: {result.get('threat_level')}")
            safe_print(f"Confidence: {result.get('confidence')}%")
            safe_print(f"Encrypted CID: {result.get('encrypted_data_cid')}")
            safe_print(f"Metadata CID: {result.get('public_metadata_cid')}")
        
        return result

# Example usage functions
def example_with_actual_threats():
    """Example with real threat detection data"""
    adapter = ZKPThreatAdapter()
    
    # Example threat data - replace with your actual threat detection
    threat_info = {
        "regex_iocs": {
            "ipv4": ["192.168.1.100", "10.0.0.50"],
            "url": ["http://malicious-site.com", "https://bad-domain.org"],
            "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
            "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "attack_id": ["T1059.001", "T1055.012"]
        },
        "normalized_vector": {
            "confidence": 85
        },
        "nlp_entities": ["malware", "ransomware", "command injection"]
    }
    
    return adapter.process_zkp_threat(threat_info=threat_info)

def example_zkp_only():
    """Example with just ZKP proof, minimal threat data"""
    adapter = ZKPThreatAdapter()
    return adapter.process_zkp_threat()

def test_connection():
    """Test if the threat processor is running"""
    try:
        response = requests.get("http://localhost:8080/status", timeout=5)
        if response.status_code == 200:
            safe_print("[OK] Threat processor is running!")
            safe_print(f"Response: {response.json()}")
            return True
        else:
            safe_print(f"[ERROR] Threat processor returned: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        safe_print(f"[ERROR] Cannot connect to threat processor: {e}")
        safe_print("[INFO] Make sure the threat processor is running on localhost:8080")
        return False

if __name__ == "__main__":
    safe_print("ZKP Threat Processor Adapter")
    safe_print("=" * 50)
    
    # Test connection first
    if not test_connection():
        safe_print("\n[STOP] Cannot proceed without threat processor running")
        exit(1)
    
    # Check if ZKP files exist
    if not Path("proof.json").exists() or not Path("public.json").exists():
        safe_print("\n[ERROR] Missing proof.json or public.json files")
        safe_print("[INFO] Make sure your ZKP files are in the current directory")
        
        # List files in current directory to help debug
        safe_print("\n[DEBUG] Files in current directory:")
        for file in Path(".").glob("*.json"):
            safe_print(f"  - {file.name}")
        exit(1)
    
    safe_print("\n[MENU] Choose an option:")
    safe_print("1. Send ZKP proof with actual threat data")
    safe_print("2. Send ZKP proof with minimal threat data")
    
    choice = input("\nEnter choice (1 or 2): ").strip()
    
    if choice == "1":
        result = example_with_actual_threats()
    elif choice == "2":
        result = example_zkp_only()
    else:
        safe_print("[ERROR] Invalid choice")
        exit(1)
    
    if result:
        safe_print(f"\n[SUCCESS] Your ZKP proof has been processed and stored on IPFS!")
    else:
        safe_print("\n[FAILED] Processing failed")