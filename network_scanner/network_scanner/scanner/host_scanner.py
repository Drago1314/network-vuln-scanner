"""
host_scanner.py — ARP-based host discovery + Nmap port scanning
"""

import socket
import subprocess
import threading
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except Exception:
    # Scapy may fail to load on some systems (e.g., IPv6 routing issues in containers)
    SCAPY_AVAILABLE = False
    ARP = Ether = srp = conf = None

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class HostScanner:
    """Discovers live hosts on a network using ARP (Scapy) or ping fallback."""

    def __init__(self, log_callback=None):
        self.log_callback = log_callback or print
        self.active_hosts = []

    def _log(self, msg):
        self.log_callback(f"[HostScanner] {msg}")

    def arp_scan(self, network: str) -> list[dict]:
        """
        Performs ARP scan using Scapy.
        Returns list of {ip, mac, hostname}
        """
        if not SCAPY_AVAILABLE:
            self._log("Scapy not available — falling back to ping scan.")
            return self.ping_scan(network)

        self._log(f"Starting ARP scan on {network} ...")
        conf.verb = 0
        arp_req = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_req

        try:
            answered, _ = srp(packet, timeout=3, retry=1)
        except PermissionError:
            self._log("PermissionError: Run as root/sudo for ARP scan. Falling back to ping.")
            return self.ping_scan(network)
        except Exception as e:
            self._log(f"ARP scan error: {e}. Falling back to ping.")
            return self.ping_scan(network)

        hosts = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            hostname = self._resolve_hostname(ip)
            hosts.append({"ip": ip, "mac": mac, "hostname": hostname, "discovered_at": datetime.now().isoformat()})
            self._log(f"  Host found → {ip} ({hostname}) [{mac}]")

        self.active_hosts = hosts
        self._log(f"ARP scan complete. {len(hosts)} host(s) found.")
        return hosts

    def ping_scan(self, network: str) -> list[dict]:
        """
        Fallback: ICMP ping sweep using subprocess.
        Works without root but slower.
        """
        self._log(f"Ping scan on {network} ...")
        base = ".".join(network.split(".")[:3])
        hosts = []
        threads = []

        lock = threading.Lock()

        def ping_host(ip):
            import platform
            if platform.system() == "Windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                hostname = self._resolve_hostname(ip)
                with lock:
                    hosts.append({"ip": ip, "mac": "N/A", "hostname": hostname, "discovered_at": datetime.now().isoformat()})
                    self._log(f"  Host found → {ip} ({hostname})")

        for i in range(1, 255):
            ip = f"{base}.{i}"
            t = threading.Thread(target=ping_host, args=(ip,))
            threads.append(t)
            t.start()
            if len(threads) % 50 == 0:
                for t in threads:
                    t.join()
                threads = []

        for t in threads:
            t.join()

        self.active_hosts = hosts
        self._log(f"Ping scan complete. {len(hosts)} host(s) found.")
        return hosts

    @staticmethod
    def _resolve_hostname(ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"


class PortScanner:
    """Port scanner using python-nmap with service/version detection."""

    SCAN_PROFILES = {
        "quick":       "-T4 -F --open",
        "standard":    "-T4 -sV -sC --open -p 1-1024",
        "full":        "-T4 -sV -sC --open -p 1-65535",
        "vuln":        "-T4 -sV --script=vuln --open -p 1-65535",
        "stealth":     "-sS -T2 -sV --open -p 1-1024",
    }

    CRITICAL_PORTS = {
        21:    {"service": "FTP",        "risk": "HIGH",     "note": "Unencrypted file transfer"},
        22:    {"service": "SSH",        "risk": "MEDIUM",   "note": "Brute-force target"},
        23:    {"service": "Telnet",     "risk": "CRITICAL", "note": "Plaintext protocol — replace with SSH"},
        25:    {"service": "SMTP",       "risk": "MEDIUM",   "note": "Mail relay abuse possible"},
        53:    {"service": "DNS",        "risk": "MEDIUM",   "note": "DNS amplification / zone transfer"},
        80:    {"service": "HTTP",       "risk": "MEDIUM",   "note": "Unencrypted web traffic"},
        110:   {"service": "POP3",       "risk": "MEDIUM",   "note": "Unencrypted mail"},
        135:   {"service": "RPC",        "risk": "HIGH",     "note": "Windows RPC exploit surface"},
        139:   {"service": "NetBIOS",    "risk": "HIGH",     "note": "SMB enumeration possible"},
        143:   {"service": "IMAP",       "risk": "MEDIUM",   "note": "Unencrypted mail"},
        443:   {"service": "HTTPS",      "risk": "LOW",      "note": "Check TLS config & cert"},
        445:   {"service": "SMB",        "risk": "CRITICAL", "note": "EternalBlue / ransomware vector"},
        1433:  {"service": "MSSQL",      "risk": "HIGH",     "note": "DB exposed to network"},
        3306:  {"service": "MySQL",      "risk": "HIGH",     "note": "DB exposed to network"},
        3389:  {"service": "RDP",        "risk": "CRITICAL", "note": "BlueKeep / brute-force target"},
        4444:  {"service": "Metasploit", "risk": "CRITICAL", "note": "Default Metasploit listener"},
        5432:  {"service": "PostgreSQL", "risk": "HIGH",     "note": "DB exposed to network"},
        5900:  {"service": "VNC",        "risk": "HIGH",     "note": "Remote desktop — often no auth"},
        6379:  {"service": "Redis",      "risk": "CRITICAL", "note": "Auth-less Redis — full RCE"},
        8080:  {"service": "HTTP-Alt",   "risk": "MEDIUM",   "note": "Dev/proxy server exposure"},
        8443:  {"service": "HTTPS-Alt",  "risk": "MEDIUM",   "note": "Alt HTTPS port"},
        27017: {"service": "MongoDB",    "risk": "CRITICAL", "note": "Unauth MongoDB — data exposure"},
        9200:  {"service": "Elasticsearch","risk":"CRITICAL","note": "Unauth ES — data exposure"},
    }

    def __init__(self, log_callback=None):
        self.log_callback = log_callback or print
        self.nm = nmap.PortScanner() if NMAP_AVAILABLE else None

    def _log(self, msg):
        self.log_callback(f"[PortScanner] {msg}")

    def scan_host(self, ip: str, profile: str = "standard") -> dict:
        """
        Scan a single host. Returns structured result dict.
        """
        if not NMAP_AVAILABLE:
            self._log("python-nmap not available. Install with: pip install python-nmap")
            return self._mock_scan(ip)

        args = self.SCAN_PROFILES.get(profile, self.SCAN_PROFILES["standard"])
        self._log(f"Scanning {ip} with profile '{profile}' → nmap {args}")

        try:
            self.nm.scan(hosts=ip, arguments=args)
        except nmap.nmap.PortScannerError as e:
            self._log(f"Nmap error (install nmap binary): {e}")
            return self._mock_scan(ip)
        except Exception as e:
            self._log(f"Scan error: {e}")
            return {"ip": ip, "status": "error", "ports": [], "os_guess": "N/A", "error": str(e)}

        return self._parse_nmap_result(ip)

    def _parse_nmap_result(self, ip: str) -> dict:
        try:
            host_data = self.nm[ip]
        except KeyError:
            return {"ip": ip, "status": "down", "ports": [], "os_guess": "N/A"}

        status = host_data.state() if hasattr(host_data, "state") else "unknown"
        os_guess = "N/A"
        try:
            if "osmatch" in host_data and host_data["osmatch"]:
                os_guess = host_data["osmatch"][0]["name"]
        except Exception:
            pass

        ports = []
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                pinfo = host_data[proto][port]
                state = pinfo.get("state", "unknown")
                if state != "open":
                    continue
                service = pinfo.get("name", "unknown")
                version = f"{pinfo.get('product', '')} {pinfo.get('version', '')}".strip()
                script_output = pinfo.get("script", {})

                risk_data = self.CRITICAL_PORTS.get(port, {"risk": "INFO", "note": "No specific vulnerability mapped"})

                ports.append({
                    "port":     port,
                    "protocol": proto,
                    "state":    state,
                    "service":  service,
                    "version":  version or "N/A",
                    "risk":     risk_data["risk"],
                    "note":     risk_data["note"],
                    "scripts":  script_output,
                })

        return {
            "ip":       ip,
            "status":   status,
            "ports":    ports,
            "os_guess": os_guess,
            "scanned_at": datetime.now().isoformat(),
        }

    def _mock_scan(self, ip: str) -> dict:
        """Demo data when nmap binary not available."""
        self._log(f"Using MOCK scan data for {ip} (nmap binary missing)")
        return {
            "ip": ip,
            "status": "up (mock)",
            "ports": [
                {"port": 22,   "protocol": "tcp", "state": "open", "service": "SSH",   "version": "OpenSSH 8.9", "risk": "MEDIUM",   "note": "Brute-force target",                  "scripts": {}},
                {"port": 80,   "protocol": "tcp", "state": "open", "service": "HTTP",  "version": "Apache 2.4",  "risk": "MEDIUM",   "note": "Unencrypted web traffic",             "scripts": {}},
                {"port": 443,  "protocol": "tcp", "state": "open", "service": "HTTPS", "version": "nginx 1.22",  "risk": "LOW",      "note": "Check TLS config & cert",             "scripts": {}},
                {"port": 3306, "protocol": "tcp", "state": "open", "service": "MySQL", "version": "MySQL 8.0",   "risk": "HIGH",     "note": "DB exposed to network",               "scripts": {}},
                {"port": 6379, "protocol": "tcp", "state": "open", "service": "Redis", "version": "Redis 7.0",   "risk": "CRITICAL", "note": "Auth-less Redis — full RCE possible", "scripts": {}},
            ],
            "os_guess": "Linux 5.x (mock)",
            "scanned_at": datetime.now().isoformat(),
        }
