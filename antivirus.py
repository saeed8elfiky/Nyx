import os
import hashlib
import json
import re
import argparse
import shutil
import time
from datetime import datetime

# ==========================================
# TERMINAL THEME / COLORS
# ==========================================
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
                       
        [ NYX THREAT SCANNER - V1.0 ]
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
        """Loads hash and heuristic signatures from the database file."""
        if not os.path.exists(self.db_path):
            print(f"{Colors.RED}[!] Signature database '{self.db_path}' not found!{Colors.END}")
            # Create an empty one if not exists
            self.signatures = {"hashes": {}, "heuristics": []}
            return

        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            
            # Normalize database hashes to lowercase for consistent matching
            self.signatures["hashes"] = {k.lower(): v for k, v in raw_data.get("hashes", {}).items()}
            self.signatures["heuristics"] = raw_data.get("heuristics", [])
            
            # Pre-compile regex for faster heuristic scanning
            for rule in self.signatures.get("heuristics", []):
                rule["regex"] = re.compile(rule["pattern"], re.IGNORECASE)
                
            hash_count = len(self.signatures.get("hashes", {}))
            rule_count = len(self.signatures.get("heuristics", []))
            print(f"{Colors.GREEN}[+] Loaded {hash_count} hash signatures and {rule_count} heuristic rules.{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error loading signatures: {str(e)}{Colors.END}")

    def _setup_quarantine(self):
        """Ensures the quarantine directory exists."""
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def calculate_hashes(self, file_path):
        """Calculates MD5, SHA1, and SHA256 of a file."""
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
                    
            return {
                "md5": md5_hash.hexdigest(),
                "sha1": sha1_hash.hexdigest(),
                "sha256": sha256_hash.hexdigest()
            }
        except Exception as e:
             return None

    def heuristic_scan(self, file_path):
        """Scans the file content for suspicious heuristic patterns."""
        # Only scan smallish files to avoid huge memory usage (e.g., < 10MB)
        try:
            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                return None
                
            # Quick text-based scan (many scripts/droppers are text)
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                
            for rule in self.signatures.get("heuristics", []):
                if rule["regex"].search(content):
                    return {
                        "name": rule["name"],
                        "type": rule["type"],
                        "severity": rule["severity"],
                        "method": "Heuristic"
                    }
        except Exception as e:
            pass
            
        return None

    def scan_file(self, file_path):
        """Scans a single file using hashing and heuristics."""
        self.stats["scanned"] += 1
        threat_found = False
        threat_info = None

        # 1. Hashing Check
        hashes = self.calculate_hashes(file_path)
        if not hashes:
            self.stats["errors"] += 1
            return False, None

        db_hashes = self.signatures.get("hashes", {})
        
        # Check if any calculated hash exists in our DB
        for algo, hval in hashes.items():
            if hval in db_hashes:
                threat_found = True
                threat_info = db_hashes[hval]
                threat_info["method"] = f"Hash Match ({algo.upper()})"
                break

        # 2. Heuristic Check (if hash is clean)
        if not threat_found:
            heuristic_result = self.heuristic_scan(file_path)
            if heuristic_result:
                threat_found = True
                threat_info = heuristic_result

        return threat_found, threat_info

    def quarantine_file(self, file_path):
        """Moves an infected file to the quarantine directory."""
        try:
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_path = os.path.join(self.quarantine_dir, f"{timestamp}_{filename}.quarantined")
            
            shutil.move(file_path, quarantine_path)
            self.stats["quarantined"] += 1
            return quarantine_path
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to quarantine {file_path}: {str(e)}{Colors.END}")
            return None

    def scan_directory(self, target_dir, auto_quarantine=False):
        """Recursively scans a directory."""
        print(f"\n{Colors.BLUE}[*] Starting scan on directory: {target_dir}{Colors.END}")
        start_time = time.time()

        for root, dirs, files in os.walk(target_dir):
            # Skip the quarantine directory itself
            if os.path.abspath(root).startswith(os.path.abspath(self.quarantine_dir)):
                continue

            for file in files:
                file_path = os.path.join(root, file)
                
                # Simple progress indicator mapping
                print(f"[>] Scanning: {file_path[:60]:<60}...", end='\r')
                
                infected, info = self.scan_file(file_path)
                
                if infected:
                    self.stats["infected"] += 1
                    print(f"\n{Colors.RED}{Colors.BOLD}[!] THREAT DETECTED: {file_path}{Colors.END}")
                    print(f"    └── Name: {info.get('name', 'Unknown')}")
                    print(f"    └── Type: {info.get('type', 'Unknown')}")
                    print(f"    └── Method: {info.get('method', 'Unknown')}")
                    
                    if auto_quarantine:
                        q_path = self.quarantine_file(file_path)
                        if q_path:
                            print(f"{Colors.YELLOW}    └── Action: Quarantined to {q_path}{Colors.END}")
                    else:
                        print(f"{Colors.YELLOW}    └── Action: Requires Manual Review{Colors.END}")

        # Clear the scanning line
        print(" " * 80, end='\r')
        
        elapsed_time = time.time() - start_time
        self.print_report(elapsed_time)

    def print_report(self, elapsed_time):
        """Prints a summary report of the scan."""
        print(f"\n{Colors.BLUE}{Colors.BOLD}--- SCANNED FINISHED ---{Colors.END}")
        print(f"Time Elapsed: {Colors.BOLD}{elapsed_time:.2f} seconds{Colors.END}")
        print(f"Files Scanned: {Colors.BOLD}{self.stats['scanned']}{Colors.END}")
        
        if self.stats["infected"] > 0:
            print(f"Threats Found: {Colors.RED}{Colors.BOLD}{self.stats['infected']}{Colors.END}")
            print(f"Quarantined: {Colors.YELLOW}{Colors.BOLD}{self.stats['quarantined']}{Colors.END}")
        else:
            print(f"Threats Found: {Colors.GREEN}{Colors.BOLD}0 (System is Clean){Colors.END}")
            
        if self.stats["errors"] > 0:
            print(f"Errors (File locked/unreadable): {Colors.YELLOW}{self.stats['errors']}{Colors.END}")
        print("-" * 25)

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="Nyx Anti-Virus Scanner")
    parser.add_argument("target", nargs='?', default=".", help="Directory or file to scan (default is current directory)")
    parser.add_argument("-q", "--quarantine", action="store_true", help="Automatically quarantine infected files")
    parser.add_argument("-d", "--database", default="signatures.json", help="Path to signature database")
    
    args = parser.parse_args()

    scanner = NyxEngine(db_path=args.database)
    
    target_path = os.path.abspath(args.target)
    
    if os.path.isdir(target_path):
        scanner.scan_directory(target_path, auto_quarantine=args.quarantine)
    elif os.path.isfile(target_path):
        infected, info = scanner.scan_file(target_path)
        if infected:
            print(f"\n{Colors.RED}{Colors.BOLD}[!] THREAT DETECTED in single file: {target_path}{Colors.END}")
            print(f"    └── Name: {info.get('name', 'Unknown')}")
            print(f"    └── Type: {info.get('type', 'Unknown')}")
            if args.quarantine:
                scanner.quarantine_file(target_path)
                print(f"{Colors.YELLOW}    └── Action: Quarantined{Colors.END}")
        else:
            print(f"\n{Colors.GREEN}[+] File is clean: {target_path}{Colors.END}")
    else:
        print(f"{Colors.RED}[!] Target path not found: {target_path}{Colors.END}")
