"""
main.py — NetVulnScanner entry point
Usage: python main.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.dashboard import run

if __name__ == "__main__":
    print("=" * 55)
    print("  🛡️  NetVulnScanner — Network Vulnerability Scanner")
    print("  Built with Python, Scapy, Nmap, Tkinter")
    print("  ⚠  For authorized/educational use only")
    print("=" * 55)
    print()

    # Check dependencies
    missing = []
    try:
        import scapy
    except ImportError:
        missing.append("scapy")
    try:
        import nmap
    except ImportError:
        missing.append("python-nmap")

    if missing:
        print(f"[!] Optional dependencies missing: {', '.join(missing)}")
        print(f"    Install with: pip install {' '.join(missing)}")
        print(f"    Scanner will use fallback methods.\n")

    run()
