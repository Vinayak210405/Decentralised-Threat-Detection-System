# simple_threat_processor.py - File System Monitoring Version

import os
import json
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict
import sys
import codecs

# --- Watchdog Imports ---
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Windows encoding fix ---
if sys.platform == "win32":
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    try:
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    except Exception as e:
        pass

def safe_print(text, file=sys.stdout):
    """Print function that handles Unicode characters safely, with optional file output."""
    try:
        print(text, file=file, flush=True) # Added flush=True for immediate output
    except UnicodeEncodeError:
        ascii_text = text.encode('ascii', 'replace').decode('ascii')
        print(ascii_text, file=file, flush=True) # Added flush=True

# --- Package Imports ---
try:
    import ipfshttpclient
    from cryptography.fernet import Fernet
    safe_print("✅ All packages imported successfully!")
except ImportError as e:
    safe_print(f"❌ Missing package: {e}", file=sys.stderr)
    safe_print("💡 Run: pip install ipfshttpclient cryptography watchdog", file=sys.stderr) # Updated install message
    exit(1)

# --- Constants ---
ENCRYPTION_KEY_FILE = "encryption_key.key"
MONITORED_DIR = "threat_inbox"
PROCESSED_DIR = os.path.join(MONITORED_DIR, "processed")

# --- Custom Event Handler for Watchdog ---
class ThreatFileHandler(FileSystemEventHandler):
    def __init__(self, processor):
        super().__init__()
        self.processor = processor

    def on_created(self, event):
        # Only process files, not directories
        if not event.is_directory and event.src_path.endswith(".json") and not os.path.basename(event.src_path).startswith("."):
            safe_print(f"\n📨 Detected new file (via watchdog): '{os.path.basename(event.src_path)}'")
            # Add a small delay to ensure the file is fully written
            time.sleep(0.5) # Increased sleep slightly for more robustness
            self.processor.process_file(event.src_path)
            
    # You might also want to handle on_modified if files are modified after creation,
    # but for simple "new file" processing, on_created is usually sufficient.
    # def on_modified(self, event):
    #     if not event.is_directory and event.src_path.endswith(".json") and not os.path.basename(event.src_path).startswith("."):
    #         safe_print(f"📝 File modified: '{os.path.basename(event.src_path)}'")
    #         # Only re-process if the file is not already in the processed directory
    #         if not os.path.dirname(event.src_path) == PROCESSED_DIR:
    #             time.sleep(0.5)
    #             self.processor.process_file(event.src_path)


class SimpleThreatProcessor:
    def __init__(self):
        safe_print("🚀 Initializing Simple Threat Processor (File System Monitor)")
        
        os.makedirs(MONITORED_DIR, exist_ok=True)
        os.makedirs(PROCESSED_DIR, exist_ok=True)
        safe_print(f"📁 Monitoring directory: '{MONITORED_DIR}'")
        safe_print(f"📁 Processed files moved to: '{PROCESSED_DIR}'")

        try:
            self.client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
            
            if os.path.exists(ENCRYPTION_KEY_FILE):
                with open(ENCRYPTION_KEY_FILE, "rb") as key_file:
                    self.encryption_key = key_file.read()
                safe_print(f"🔑 Loaded encryption key from '{ENCRYPTION_KEY_FILE}'")
            else:
                self.encryption_key = Fernet.generate_key()
                with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
                    key_file.write(self.encryption_key)
                safe_print(f"🔐 Generated and saved new encryption key to '{ENCRYPTION_KEY_FILE}'")
            self.cipher_suite = Fernet(self.encryption_key)
            
            node_info = self.client.id()
            safe_print(f"✅ Connected to IPFS node: {node_info['ID'][:16]}...")
            
        except Exception as e:
            safe_print(f"❌ Initialization failed: {str(e)}", file=sys.stderr)
            safe_print("💡 Make sure IPFS daemon is running: 'ipfs daemon'", file=sys.stderr)
            raise

    def start_file_monitor(self): # No need for interval_seconds here, watchdog is event-driven
        """
        Starts monitoring the specified directory for new threat data files.
        Processes existing files first, then continuously monitors using watchdog.
        """
        safe_print(f"\n⏳ Processing any existing files in '{MONITORED_DIR}' before starting real-time monitor...")
        
        initial_files = sorted([f for f in os.listdir(MONITORED_DIR) 
                                if f.endswith(".json") and not f.startswith(".")])
        
        if initial_files:
            safe_print(f"Found {len(initial_files)} existing files to process.")
            for filename in initial_files:
                file_path = os.path.join(MONITORED_DIR, filename)
                if os.path.isfile(file_path): 
                    safe_print(f"📨 Processing existing file: '{filename}'")
                    self.process_file(file_path)
                else:
                    safe_print(f"⚠️ Warning: File '{filename}' disappeared before processing.", file=sys.stderr)
            safe_print("✅ Finished processing existing files.")
        else:
            safe_print("No existing files found to process on startup.")

        # --- NEW: Watchdog setup ---
        event_handler = ThreatFileHandler(self)
        observer = Observer()
        observer.schedule(event_handler, MONITORED_DIR, recursive=False) # recursive=False for only top-level files
        
        safe_print(f"\n⚡ Now actively monitoring '{MONITORED_DIR}' for new threat files using watchdog... (Press Ctrl+C to stop)")
        observer.start()
        
        try:
            while True:
                time.sleep(1) # Keep the main thread alive, watchdog runs in its own thread
        except KeyboardInterrupt:
            safe_print("\n🛑 File monitor stopped by user")
        finally:
            observer.stop()
            observer.join() # Wait for the observer thread to finish
        # --- END NEW ---

    def process_file(self, file_path: str):
        """Reads and processes a threat data file."""
        try:
            # Check if the file already exists in the PROCESSED_DIR
            # This is an important check for watchdog, as 'on_created' might fire
            # for files being moved into the directory (which are "new" to the directory)
            # or if the processor is restarted and finds already processed files that weren't moved properly.
            if os.path.basename(file_path) in os.listdir(PROCESSED_DIR):
                safe_print(f"Skipping '{os.path.basename(file_path)}': already processed.")
                # Optionally, delete the duplicate file if it's not supposed to be there
                # os.remove(file_path) 
                return

            with open(file_path, 'r', encoding='utf-8') as f:
                data_payload = json.load(f)
            
            safe_print(f"📊 Processing data from '{os.path.basename(file_path)}'...")
            
            threat_data = data_payload.get("threat_detection", {})
            zk_proof = data_payload.get("zk_proof", {})
            source_info = data_payload.get("source", f"file_processor_{os.path.basename(file_path)}")

            if not threat_data:
                safe_print(f"⚠️ Warning: File '{file_path}' has missing 'threat_detection' data. Skipping and moving to processed.", file=sys.stderr)
                os.rename(file_path, os.path.join(PROCESSED_DIR, os.path.basename(file_path) + "_invalid"))
                return

            result = self.process_threat_data(threat_data, zk_proof, source_info)
            
            processed_file_path = os.path.join(PROCESSED_DIR, os.path.basename(file_path))
            # Ensure the file exists before attempting to rename it.
            # This handles cases where another process might delete the file quickly.
            if os.path.exists(file_path):
                os.rename(file_path, processed_file_path)
                safe_print(f"✅ File processed and moved to '{processed_file_path}'")
            else:
                safe_print(f"⚠️ Warning: Original file '{file_path}' not found for moving after processing.", file=sys.stderr)
            
            safe_print(f"Processed result: {json.dumps(result, indent=2)}")

        except json.JSONDecodeError:
            safe_print(f"❌ Error: File '{file_path}' contains malformed JSON. Skipping and moving to processed.", file=sys.stderr)
            if os.path.exists(file_path):
                os.rename(file_path, os.path.join(PROCESSED_DIR, os.path.basename(file_path) + "_malformed"))
        except FileNotFoundError:
            safe_print(f"❌ Error: File '{file_path}' not found. It might have been processed by another instance or deleted.", file=sys.stderr)
        except Exception as e:
            safe_print(f"❌ Error processing file '{file_path}': {str(e)}", file=sys.stderr)
            if os.path.exists(file_path):
                os.rename(file_path, os.path.join(PROCESSED_DIR, os.path.basename(file_path) + "_failed"))


    def process_threat_data(self, threat_data: Dict, zk_proof: Dict, source_info: str) -> Dict:
        """Process the threat data from the file"""
        try:
            threat_analysis = self._analyze_threat_severity(threat_data)
            metadata = self._create_metadata(threat_data, zk_proof, threat_analysis, source_info)
            
            complete_package = {
                "source": source_info,
                "threat_detection": threat_data,
                "zk_proof": zk_proof,
                "analysis": metadata,
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "processor_version": "file_monitor_1.1" # Updated processor version for watchdog
            }
            
            encrypted_cid = self._store_encrypted(complete_package)
            metadata_cid = self._store_public(metadata)
            verification_hash = hashlib.sha256(f"{encrypted_cid}{metadata_cid}".encode()).hexdigest()
            
            result = {
                "status": "success",
                "message": "Threat data processed and stored on IPFS",
                "threat_level": threat_analysis["threat_level"],
                "confidence": threat_analysis["confidence_score"],
                "encrypted_data_cid": encrypted_cid,
                "public_metadata_cid": metadata_cid,
                "verification_hash": verification_hash,
                "processing_time": datetime.now(timezone.utc).isoformat()
            }
            
            self._print_summary(result, threat_analysis)
            
            return result
            
        except Exception as e:
            safe_print(f"❌ Processing failed: {str(e)}", file=sys.stderr)
            return {
                "status": "error", 
                "message": f"Processing failed: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

    def _analyze_threat_severity(self, threat_data: Dict) -> Dict:
        safe_print("🔍 Analyzing threat severity...")
        
        regex_iocs = threat_data.get("regex_iocs", {})
        normalized_vector = threat_data.get("normalized_vector", {})

        ioc_counts = {
            "ips": len(regex_iocs.get("ipv4", [])) + len(regex_iocs.get("ipv6", [])),
            "urls": len(regex_iocs.get("url", [])),
            "hashes": len(regex_iocs.get("md5", [])) + len(regex_iocs.get("sha1", [])) + len(regex_iocs.get("sha256", [])),
            "attack_ids": len(regex_iocs.get("attack_id", []))
        }

        confidence = normalized_vector.get("confidence", 0)
        total_iocs = sum(ioc_counts.values())

        if confidence >= 90 and total_iocs >= 5:
            threat_level, severity_score = "CRITICAL", 5
        elif confidence >= 80 and total_iocs >= 3:
            threat_level, severity_score = "HIGH", 4
        elif confidence >= 70 and total_iocs >= 2:
            threat_level, severity_score = "MEDIUM", 3
        elif confidence >= 60 and total_iocs >= 1:
            threat_level, severity_score = "LOW", 2
        else:
            threat_level, severity_score = "INFO", 1

        return {
            "threat_level": threat_level,
            "severity_score": severity_score,
            "confidence_score": confidence,
            "ioc_breakdown": ioc_counts,
            "total_iocs": total_iocs
        }

    def _create_metadata(self, threat_data: Dict, zk_proof: Dict, analysis: Dict, source: str) -> Dict:
        return {
            "report_id": hashlib.sha256(f"{source}{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "threat_level": analysis["threat_level"],
            "confidence": analysis["confidence_score"],
            "total_threats_found": analysis["total_iocs"],
            "threat_breakdown": analysis["ioc_breakdown"],
            "has_zk_proof": bool(zk_proof),
            "processor": "SimpleThreatProcessor"
        }

    def _store_encrypted(self, data: Dict) -> str:
        safe_print("🔐 Encrypting and storing threat data...")
        json_data = json.dumps(data, indent=2)
        encrypted_data = self.cipher_suite.encrypt(json_data.encode())
        result = self.client.add_bytes(encrypted_data)
        cid = result['Hash'] if isinstance(result, dict) else result
        safe_print(f"📦 Encrypted data stored: {cid}")
        return cid

    def _store_public(self, metadata: Dict) -> str:
        safe_print("📄 Storing public metadata...")
        metadata_json = json.dumps(metadata, indent=2)
        result = self.client.add_str(metadata_json)
        cid = result['Hash'] if isinstance(result, dict) else result
        safe_print(f"📋 Metadata stored: {cid}")
        return cid

    def _print_summary(self, result: Dict, analysis: Dict):
        safe_print("\n" + "="*50)
        safe_print("📊 THREAT PROCESSING SUMMARY")
        safe_print("="*50)
        safe_print(f"🎯 Threat Level: {analysis['threat_level']}")
        safe_print(f"📈 Confidence: {analysis['confidence_score']}%")
        safe_print(f"🔍 Threats Found: {analysis['total_iocs']}")
        safe_print(f"📦 Encrypted Data: {result['encrypted_data_cid'][:20]}...")
        safe_print(f"📄 Public Data: {result['public_metadata_cid'][:20]}...")
        safe_print("="*50)

if __name__ == "__main__":
    safe_print("🚀 Simple Threat Processor - File System Monitor Version")
    safe_print("="*60)
    
    try:
        processor = SimpleThreatProcessor()
        safe_print(f"\n💡 Your text extractor should write JSON files to: '{MONITORED_DIR}'")
        safe_print(f"    Each file should contain the threat data payload.")
        
        processor.start_file_monitor()
        
    except Exception as e:
        safe_print(f"❌ Failed to start processor: {str(e)}", file=sys.stderr)
        safe_print("\n🔧 Troubleshooting:", file=sys.stderr)
        safe_print("1. Make sure IPFS daemon is running: 'ipfs daemon'", file=sys.stderr)
        safe_print("2. Check permissions for directory: 'threat_inbox'", file=sys.stderr)
        safe_print("3. Install required packages: 'pip install ipfshttpclient cryptography watchdog'", file=sys.stderr)