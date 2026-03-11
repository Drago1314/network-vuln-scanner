"""
vuln_mapper.py — Maps open ports/services to OWASP Top 10 (2021) categories
and assigns CVE-like findings with remediation guidance.
"""

OWASP_TOP_10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# Port → [OWASP categories, CVE references, remediation]
PORT_OWASP_MAP = {
    21: {
        "owasp": ["A02", "A07"],
        "title": "FTP Service Exposed",
        "description": "FTP transmits credentials and data in plaintext. Susceptible to credential theft via MITM.",
        "cve_refs": ["CVE-1999-0612", "CVE-2010-4221"],
        "remediation": "Disable FTP. Use SFTP or SCP over SSH instead. If required, enforce TLS (FTPS).",
        "severity": "HIGH",
    },
    22: {
        "owasp": ["A07"],
        "title": "SSH Service Exposed",
        "description": "SSH exposed to network. If misconfigured, susceptible to brute-force and weak key attacks.",
        "cve_refs": ["CVE-2023-38408"],
        "remediation": "Disable root login, enforce key-based auth, use fail2ban, change default port.",
        "severity": "MEDIUM",
    },
    23: {
        "owasp": ["A02", "A05", "A07"],
        "title": "Telnet Service — Plaintext Protocol",
        "description": "Telnet sends all data including credentials in cleartext. Critical misconfiguration.",
        "cve_refs": ["CVE-1999-0619"],
        "remediation": "Immediately disable Telnet. Replace with SSH. No exceptions.",
        "severity": "CRITICAL",
    },
    25: {
        "owasp": ["A05"],
        "title": "SMTP Open Relay Risk",
        "description": "SMTP port exposed. Misconfigured SMTP can be abused as an open relay for spam.",
        "cve_refs": [],
        "remediation": "Restrict SMTP to authorized senders. Enable SPF, DKIM, DMARC.",
        "severity": "MEDIUM",
    },
    53: {
        "owasp": ["A05"],
        "title": "DNS Zone Transfer / Amplification Risk",
        "description": "DNS service exposed. May allow zone transfers or DNS amplification DDoS.",
        "cve_refs": ["CVE-2020-8617"],
        "remediation": "Restrict zone transfers to authorised IPs. Rate-limit DNS queries.",
        "severity": "MEDIUM",
    },
    80: {
        "owasp": ["A02", "A03"],
        "title": "HTTP (Unencrypted Web Service)",
        "description": "Web service running on HTTP without TLS. Data in transit is unencrypted.",
        "cve_refs": [],
        "remediation": "Enforce HTTPS. Redirect all HTTP → HTTPS. Use HSTS header.",
        "severity": "MEDIUM",
    },
    135: {
        "owasp": ["A05", "A01"],
        "title": "Windows RPC Endpoint Mapper",
        "description": "RPC endpoint exposed. Historically exploited for remote code execution on Windows.",
        "cve_refs": ["CVE-2003-0352", "CVE-2022-26809"],
        "remediation": "Block port 135 at perimeter firewall. Patch Windows regularly.",
        "severity": "HIGH",
    },
    139: {
        "owasp": ["A05", "A01"],
        "title": "NetBIOS Session Service",
        "description": "NetBIOS exposed. Enables SMB enumeration, pass-the-hash attacks.",
        "cve_refs": ["CVE-2017-0144"],
        "remediation": "Disable NetBIOS over TCP/IP. Block at firewall.",
        "severity": "HIGH",
    },
    443: {
        "owasp": ["A02"],
        "title": "HTTPS — Verify TLS Configuration",
        "description": "HTTPS present. Check for weak ciphers, expired certs, or TLS 1.0/1.1.",
        "cve_refs": ["CVE-2014-3566"],  # POODLE
        "remediation": "Enforce TLS 1.2+. Disable weak ciphers. Use valid, non-expired certs.",
        "severity": "LOW",
    },
    445: {
        "owasp": ["A05", "A06"],
        "title": "SMB — EternalBlue Attack Surface",
        "description": "SMB exposed. Critical vector for ransomware (WannaCry, NotPetya) via EternalBlue.",
        "cve_refs": ["CVE-2017-0144", "CVE-2020-0796"],
        "remediation": "Block SMB (445) at perimeter. Patch KB4012212. Disable SMBv1.",
        "severity": "CRITICAL",
    },
    1433: {
        "owasp": ["A03", "A05"],
        "title": "MSSQL Exposed to Network",
        "description": "MSSQL database reachable from network. Brute-force and SQL injection risk.",
        "cve_refs": ["CVE-2020-0618"],
        "remediation": "Bind DB to localhost only. Use firewall rules. Enforce strong auth.",
        "severity": "HIGH",
    },
    3306: {
        "owasp": ["A03", "A05"],
        "title": "MySQL Exposed to Network",
        "description": "MySQL database directly reachable. Risk of credential brute-force and SQL injection.",
        "cve_refs": ["CVE-2012-2122", "CVE-2021-27928"],
        "remediation": "Bind MySQL to 127.0.0.1. Use SSH tunnels for remote access.",
        "severity": "HIGH",
    },
    3389: {
        "owasp": ["A07", "A06"],
        "title": "RDP Exposed — BlueKeep / DejaBlue Risk",
        "description": "RDP exposed publicly. High-value brute-force target. BlueKeep allows pre-auth RCE.",
        "cve_refs": ["CVE-2019-0708", "CVE-2019-1181", "CVE-2022-21990"],
        "remediation": "Restrict RDP behind VPN. Enable NLA. Patch Windows. Enable MFA.",
        "severity": "CRITICAL",
    },
    4444: {
        "owasp": ["A05"],
        "title": "Default Metasploit/Backdoor Port",
        "description": "Port 4444 is the default Metasploit listener and common backdoor port. Immediate concern.",
        "cve_refs": [],
        "remediation": "Investigate immediately. Kill any process using this port. Check for malware.",
        "severity": "CRITICAL",
    },
    5432: {
        "owasp": ["A03", "A05"],
        "title": "PostgreSQL Exposed to Network",
        "description": "PostgreSQL reachable over network. Risk of brute-force and unauthorised data access.",
        "cve_refs": ["CVE-2019-10164"],
        "remediation": "Restrict to localhost. Use pg_hba.conf to whitelist IPs.",
        "severity": "HIGH",
    },
    5900: {
        "owasp": ["A07", "A05"],
        "title": "VNC Remote Desktop Exposed",
        "description": "VNC often runs without auth or with weak passwords. Full desktop control possible.",
        "cve_refs": ["CVE-2019-15681"],
        "remediation": "Disable VNC if unused. Enforce strong password. Use VPN + SSH tunnel.",
        "severity": "HIGH",
    },
    6379: {
        "owasp": ["A05", "A01"],
        "title": "Redis — Unauthenticated Access (RCE Risk)",
        "description": "Redis by default has no auth. Attackers can write SSH keys or cron jobs → full RCE.",
        "cve_refs": ["CVE-2022-0543"],
        "remediation": "Bind Redis to 127.0.0.1. Set requirepass. Never expose Redis publicly.",
        "severity": "CRITICAL",
    },
    8080: {
        "owasp": ["A02", "A03"],
        "title": "HTTP Alternate Port",
        "description": "Dev/proxy server exposed on 8080. Often runs without TLS or auth.",
        "cve_refs": [],
        "remediation": "Restrict to internal network. Add authentication. Enforce HTTPS.",
        "severity": "MEDIUM",
    },
    9200: {
        "owasp": ["A05", "A01"],
        "title": "Elasticsearch — Unauthenticated Data Exposure",
        "description": "Elasticsearch has no auth by default. Any user can read/delete all indexed data.",
        "cve_refs": ["CVE-2021-22145"],
        "remediation": "Enable X-Pack security. Never expose ES port publicly.",
        "severity": "CRITICAL",
    },
    27017: {
        "owasp": ["A05", "A01"],
        "title": "MongoDB — Unauthenticated Access",
        "description": "MongoDB exposed without auth. Billion+ records have been leaked this way.",
        "cve_refs": ["CVE-2017-15535"],
        "remediation": "Enable --auth. Bind to localhost. Never expose 27017 publicly.",
        "severity": "CRITICAL",
    },
}


def map_port_to_owasp(port: int, service: str = "") -> dict:
    """
    Returns OWASP mapping for a port. Fallback for unmapped ports.
    """
    if port in PORT_OWASP_MAP:
        entry = PORT_OWASP_MAP[port].copy()
        entry["owasp_names"] = [f"{k}: {OWASP_TOP_10[k]}" for k in entry["owasp"]]
        return entry

    # Generic fallback
    return {
        "owasp": ["A05"],
        "owasp_names": [f"A05: {OWASP_TOP_10['A05']}"],
        "title": f"Open Port {port} ({service or 'Unknown Service'})",
        "description": f"Port {port} is open and reachable. Service: {service or 'unknown'}.",
        "cve_refs": [],
        "remediation": "Close port if not required. Restrict access via firewall.",
        "severity": "INFO",
    }


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#FF3B30",
    "HIGH":     "#FF9500",
    "MEDIUM":   "#FFCC00",
    "LOW":      "#34C759",
    "INFO":     "#5AC8FA",
}


def calculate_risk_score(findings: list[dict]) -> dict:
    """Calculates overall risk score from findings list."""
    if not findings:
        return {"score": 0, "grade": "A", "label": "Clean"}

    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    total = sum(weights.get(f.get("severity", "INFO"), 0) for f in findings)
    max_score = len(findings) * 10

    score = min(100, int((total / max(max_score, 1)) * 100))

    if score >= 75:    grade, label = "F", "Critical Risk"
    elif score >= 50:  grade, label = "D", "High Risk"
    elif score >= 30:  grade, label = "C", "Medium Risk"
    elif score >= 10:  grade, label = "B", "Low Risk"
    else:              grade, label = "A", "Minimal Risk"

    return {"score": score, "grade": grade, "label": label}
