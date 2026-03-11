# 🛡️ NetVulnScanner

**Network Vulnerability Scanner** built with Python, Scapy, Nmap, and Tkinter.

## Features

- **Host Discovery** — ARP scan (Scapy) with ICMP ping fallback
- **Port Scanning** — 5 scan profiles via python-nmap (quick, standard, full, vuln, stealth)
- **OWASP Mapping** — Every open port mapped against OWASP Top 10 (2021)
- **Risk Scoring** — Automated severity scoring (CRITICAL → INFO) with A–F grade
- **GUI Dashboard** — Real-time Tkinter dashboard with live log, findings table, risk chart
- **Report Export** — Styled HTML + CSV reports with CVE references and remediation steps

## Installation

```bash
pip install -r requirements.txt

# Also install nmap binary:
# Linux:   sudo apt install nmap
# macOS:   brew install nmap
# Windows: https://nmap.org/download.html
```

## Usage

```bash
# Requires sudo/root for ARP scan (Scapy)
sudo python main.py

# Without root — falls back to ping sweep + TCP scan
python main.py
```

## Scan Profiles

| Profile   | Description                        |
|-----------|------------------------------------|
| quick     | Fast scan, common ports only        |
| standard  | Top 1024 ports + service detection  |
| full      | All 65535 ports                     |
| vuln      | Full scan + NSE vuln scripts        |
| stealth   | SYN scan, slower, less noisy        |

## OWASP Top 10 (2021) Coverage

The scanner maps findings to:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures

## ⚠️ Legal Disclaimer

This tool is for **authorized testing and educational use only**.  
Only scan networks you own or have explicit written permission to test.  
Unauthorized network scanning is illegal.

## Tech Stack

- **Python 3.10+**
- **Scapy** — ARP host discovery
- **python-nmap** — Port scanning via Nmap
- **Tkinter** — GUI dashboard
- **OWASP Top 10** — Vulnerability framework
