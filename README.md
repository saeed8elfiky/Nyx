# 🌑 Nyx Threat Scanner

Nyx is a lightweight, command-line Anti-Virus and Threat Scanner built entirely from scratch in Python. It is designed to quickly identify malicious files, web shells, and scripts via both precise hash-matching and dynamic heuristic analysis.

![Nyx Scanner Demo](https://img.shields.io/badge/Status-Active-blue.svg)
![Python Version](https://img.shields.io/badge/Python-3.x-blue.svg)

---

## ⚡ Features

*   **Hash-Based Signatures (MD5, SHA1, SHA256):** Instantly identifies known malware payloads based on precise cryptographic hashes.
*   **Heuristic Analysis Engine:** Scans the content of unknown files for suspicious and common malicious patterns (e.g., encoded PowerShell execution, obfuscated PHP `eval()` expressions, malicious VBS runners) using regular expressions.
*   **Automated Quarantine:** Automatically safely isolates infected files into a segregated quarantine folder to prevent accidental execution.
*   **Recursive Directory Scanning:** Rapidly traverses deep folder structures and selectively ignores giant files to maintain optimum scanning speed.
*   **Rich Terminal Interface:** A slick, fast, color-coded CLI dashboard to easily monitor scanning progress and threat reports.

---

## 🚀 Installation & Setup

Nyx requires **zero external dependencies** outside of the standard Python library.

1. **Clone the Repository**
   ```bash
   git clone https://github.com/YourUsername/Nyx-Antivirus.git
   cd Nyx-Antivirus
   ```

2. **Ensure Python 3 is installed**
   Verify you are running Python 3.x by typing `python --version` in your terminal.

---

## 🛠️ Usage

By default, Nyx looks for `signatures.json` in the same directory and scans the current path.

**Basic Directory Scan:** (Scans the current directory recursively)
```bash
python antivirus.py .
```

**Scan a Specific File:**
```bash
python antivirus.py /path/to/suspicious_file.exe
```

**Auto-Quarantine Threats:** (Moves detected threats into a `/quarantine` folder automatically)
```bash
python antivirus.py /var/www/html -q
```

**Use a Custom Signature Database:**
```bash
python antivirus.py . -d /path/to/custom_signatures.json
```

---

## 📁 Database Structure (`signatures.json`)

Nyx uses a highly accessible JSON format for its signature database. It allows you to rapidly add new Threat Intel on the fly. 

```json
{
    "hashes": {
        "44d88612fea8a8f36de82e1278abb02f": {
            "name": "EICAR-Standard-Antivirus-Test-File",
            "type": "test_virus"
        }
    },
    "heuristics": [
        {
            "name": "Suspicious_PHP_Eval",
            "pattern": "eval\\s*\\(\\s*base64_decode\\s*\\(",
            "type": "webshell",
            "severity": "high"
        }
    ]
}
```
*   **Hashes:** Accepts MD5, SHA1, or SHA256 hashes as keys.
*   **Heuristics:** Employs standard Python Regular Expressions in the `pattern` field.

---

## ⚠️ Disclaimer

**Nyx is intended for educational purposes and internal tooling.** While highly effective at static analysis and heuristic matching, it does not employ real-time advanced memory scanning or ring-0 rootkit detection found in commercial enterprise EDR solutions. Use responsibly.
