import os
import hashlib
import json
import re
import argparse
import shutil
import time
import requests
import pefile
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ==========================================
# METADATA & RIGHTS
# ==========================================
# Author: Saeed Elfiky
# License: MIT
# Copyright (c) 2026 Saeed Elfiky
# ==========================================

# ==========================================
# CONFIGURATION
# ==========================================
LOG_FILE = "nyx_scan_history.log"

class Colors:
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

BANNER = f"""
{Colors.BLUE}{Colors.BOLD}
  _   ___   ____  __
 | \\ | \\ \\ / /\\ \\/ /
 |  \\| |\\ V /  \\  / 
 |_|\\__| |_|   /_/\\_\\
                       
        [ NYX THREAT SCANNER - V1.1 ]
        [ Created by: Saeed Elfiky  ]
{Colors.END}
"""

# ==========================================
# CORE ANTIVIRUS ENGINE
# ==========================================
class NyxEngine:
    def __init__(self, db_path="signatures.json", quarantine_dir="quarantine"):
        self.db_path = db_path
        self.quarantine_dir = quarantine_dir
        self.signatures = {"hashes": {}, "heuristics": []}
        self.stats = {
            "scanned": 0,
            "infected": 0,
            "quarantined": 0,
            "errors": 0
        }
        
        self._load_signatures()
        self._setup_quarantine()

    def _load_signatures(self):
        if not os.path.exists(self.db_path):
            print(f"{Colors.RED}[!] Signature database '{self.db_path}' not found!{Colors.END}")
            self.signatures = {"hashes": {}, "heuristics": []}
            return

        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            self.signatures["hashes"] = {k.lower(): v for k, v in raw_data.get("hashes", {}).items()}
            self.signatures["heuristics"] = raw_data.get("heuristics", [])
            for rule in self.signatures.get("heuristics", []):
                rule["regex"] = re.compile(rule["pattern"], re.IGNORECASE)
            print(f"{Colors.GREEN}[+] Loaded {len(self.signatures['hashes'])} hashes & {len(self.signatures['heuristics'])} rules.{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error loading signatures: {str(e)}{Colors.END}")

    def _setup_quarantine(self):
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def log_event(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")

    def calculate_hashes(self, file_path):
        md5_h, sha1_h, sha256_h = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_h.update(chunk)
                    sha1_h.update(chunk)
                    sha256_h.update(chunk)
            return {"md5": md5_h.hexdigest(), "sha1": sha1_h.hexdigest(), "sha256": sha256_h.hexdigest()}
        except: return None

    def pe_deep_inspect(self, file_path):
        """Advanced PE Analysis for suspicious imports/entropy."""
        try:
            pe = pefile.PE(file_path)
            # High Entropy check (packed/encrypted)
            entropy = sum(s.get_entropy() for s in pe.sections) / len(pe.sections)
            if entropy > 7.1:
                return {"name": "Possible_Packed_Malware", "type": "packer", "method": f"Deep PE (Entropy: {entropy:.2f})"}
            
            # Suspicious Import Check
            suspicious_dlls = ["ws2_32.dll", "wininet.dll", "advapi32.dll"]
            found_dll_count = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode().lower()
                    if dll_name in suspicious_dlls:
                        found_dll_count += 1
            
            if found_dll_count >= 2:
                return {"name": "Suspicious_Imports", "type": "dropper", "method": f"PE Import Analysis"}
        except: pass
        return None

    def scan_file(self, file_path, silent=False):
        self.stats["scanned"] += 1
        threat_found, threat_info = False, None
        hashes = self.calculate_hashes(file_path)
        if not hashes: 
            self.stats["errors"] += 1
            return False, None

        # 1. Local Hash Check
        db_hashes = self.signatures.get("hashes", {})
        for algo, hval in hashes.items():
            if hval in db_hashes:
                threat_found, threat_info = True, db_hashes[hval]
                threat_info["method"] = f"Local Hash ({algo.upper()})"
                break

        # 2. Deep PE Analysis (for .exe/.dll)
        if not threat_found and file_path.lower().endswith(('.exe', '.dll')):
            pe_result = self.pe_deep_inspect(file_path)
            if pe_result: threat_found, threat_info = True, pe_result

        # 3. Local Heuristic Content Scan
        if not threat_found:
            try:
                if os.path.getsize(file_path) < 10*1024*1024:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    for rule in self.signatures.get("heuristics", []):
                        if rule["regex"].search(content):
                            threat_found, threat_info = True, {"name": rule["name"], "type": rule["type"], "method": "Heuristic Rule"}
                            break
            except: pass

        if threat_found and not silent:
            msg = f"THREAT: {file_path} | {threat_info['name']} ({threat_info['method']})"
            print(f"\n{Colors.RED}{Colors.BOLD}[!] {msg}{Colors.END}")
            self.log_event(msg)
        return threat_found, threat_info

    def quarantine_file(self, file_path):
        try:
            filename = os.path.basename(file_path)
            q_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}.quarantined"
            q_path = os.path.join(self.quarantine_dir, q_name)
            shutil.move(file_path, q_path)
            self.stats["quarantined"] += 1
            self.log_event(f"QUARANTINED: {file_path} moved to {q_path}")
            return q_path
        except Exception as e:
            print(f"{Colors.RED}[!] Quarantine failed: {str(e)}{Colors.END}")
            return None

    def scan_directory(self, target_dir, auto_quarantine=False):
        print(f"\n{Colors.BLUE}[*] Scanning: {target_dir}{Colors.END}")
        start = time.time()
        for root, _, files in os.walk(target_dir):
            if os.path.abspath(root).startswith(os.path.abspath(self.quarantine_dir)): continue
            for file in files:
                file_path = os.path.join(root, file)
                print(f"[>] Scanning: {file_path[:60]:<60}...", end='\r')
                infected, info = self.scan_file(file_path)
                if infected and auto_quarantine: self.quarantine_file(file_path)
        print(" " * 80, end='\r')
        self.print_report(time.time() - start)

    def print_report(self, elapsed):
        print(f"\n{Colors.BLUE}{Colors.BOLD}--- NYX SCAN REPORT ---{Colors.END}")
        print(f"Time: {elapsed:.2f}s | Scanned: {self.stats['scanned']} | Infected: {Colors.RED}{self.stats['infected']}{Colors.END}")
        print(f"Quarantined: {self.stats['quarantined']} | Errors: {self.stats['errors']}")
        print("-" * 30)

# ==========================================
# REAL-TIME PROTECTION HANDLER
# ==========================================
class NyxGuardian(FileSystemEventHandler):
    def __init__(self, scanner, auto_quarantine):
        self.scanner = scanner
        self.auto_quarantine = auto_quarantine

    def on_created(self, event):
        if not event.is_directory:
            print(f"\n{Colors.YELLOW}[*] Nyx Guardian detected new file: {event.src_path}{Colors.END}")
            infected, info = self.scanner.scan_file(event.src_path)
            if infected and self.auto_quarantine:
                self.scanner.quarantine_file(event.src_path)
                print(f"{Colors.GREEN}[+] Threat isolated successfully.{Colors.END}")

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    print(BANNER)
    parser = argparse.ArgumentParser(description="Nyx Threat Scanner (Advanced Version)")
    parser.add_argument("target", nargs='?', default=".", help="Target directory/file")
    parser.add_argument("-q", "--quarantine", action="store_true", help="Auto-quarantine")
    parser.add_argument("-w", "--watch", action="store_true", help="Enable Real-Time Protection (Guardian Mode)")
    args = parser.parse_args()

    scanner = NyxEngine()
    
    if args.watch:
        print(f"{Colors.GREEN}{Colors.BOLD}[🛡️] Nyx Guardian (Active Protection) Started! Monitoring: {args.target}{Colors.END}")
        event_handler = NyxGuardian(scanner, args.quarantine)
        observer = Observer()
        observer.schedule(event_handler, args.target, recursive=True)
        observer.start()
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        target = os.path.abspath(args.target)
        if os.path.isdir(target): scanner.scan_directory(target, args.quarantine)
        elif os.path.isfile(target): 
            inf, _ = scanner.scan_file(target)
            if inf and args.quarantine: scanner.quarantine_file(target)
