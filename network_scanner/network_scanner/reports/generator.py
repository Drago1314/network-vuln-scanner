"""
generator.py — Generates HTML and CSV vulnerability reports
"""

import csv
import os
from datetime import datetime
from scanner.vuln_mapper import OWASP_TOP_10, SEVERITY_COLOR, calculate_risk_score


def generate_html_report(scan_results: list[dict], output_dir: str = "output_reports") -> str:
    """
    Generates a styled HTML report from scan results.
    Returns path to generated file.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"vuln_report_{timestamp}.html")

    all_findings = []
    for host in scan_results:
        for finding in host.get("findings", []):
            finding["host_ip"] = host["ip"]
            all_findings.append(finding)

    risk = calculate_risk_score(all_findings)

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev_counts[f.get("severity", "INFO")] += 1

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetVulnScanner — Vulnerability Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; }}
        .header {{ background: linear-gradient(135deg, #161b22, #21262d); padding: 40px; border-bottom: 1px solid #30363d; }}
        .header h1 {{ font-size: 2rem; color: #58a6ff; margin-bottom: 8px; }}
        .header .meta {{ color: #8b949e; font-size: 0.9rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 30px; }}
        .risk-banner {{ display: flex; align-items: center; gap: 20px; background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; margin-bottom: 30px; }}
        .risk-grade {{ font-size: 4rem; font-weight: 900; width: 80px; text-align: center; }}
        .risk-label {{ font-size: 1.4rem; font-weight: 600; }}
        .risk-sub {{ color: #8b949e; font-size: 0.9rem; margin-top: 4px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 30px; }}
        .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }}
        .stat-num {{ font-size: 2rem; font-weight: 700; }}
        .stat-label {{ font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }}
        .section-title {{ font-size: 1.2rem; font-weight: 600; color: #58a6ff; margin: 30px 0 16px; padding-bottom: 8px; border-bottom: 1px solid #30363d; }}
        table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #30363d; margin-bottom: 30px; }}
        th {{ background: #21262d; padding: 12px 16px; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; color: #8b949e; }}
        td {{ padding: 12px 16px; border-top: 1px solid #21262d; font-size: 0.9rem; vertical-align: top; }}
        tr:hover td {{ background: #1c2128; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; }}
        .owasp-tag {{ display: inline-block; background: #21262d; border: 1px solid #30363d; border-radius: 4px; padding: 2px 8px; font-size: 0.72rem; color: #8b949e; margin: 2px; }}
        .finding-title {{ font-weight: 600; color: #e6edf3; }}
        .finding-desc {{ color: #8b949e; font-size: 0.85rem; margin-top: 4px; }}
        .remediation {{ color: #3fb950; font-size: 0.82rem; margin-top: 6px; }}
        .cve {{ font-family: monospace; color: #79c0ff; font-size: 0.8rem; }}
        .footer {{ text-align: center; padding: 30px; color: #8b949e; font-size: 0.8rem; border-top: 1px solid #30363d; }}
    </style>
</head>
<body>
<div class="header">
    <h1>🛡️ NetVulnScanner — Vulnerability Report</h1>
    <div class="meta">
        Generated: {datetime.now().strftime("%B %d, %Y at %H:%M:%S")} &nbsp;|&nbsp;
        Hosts scanned: {len(scan_results)} &nbsp;|&nbsp;
        Total findings: {len(all_findings)}
    </div>
</div>
<div class="container">
"""

    # Risk Banner
    grade_colors = {"A": "#3fb950", "B": "#58a6ff", "C": "#e3b341", "D": "#f0883e", "F": "#FF3B30"}
    gc = grade_colors.get(risk["grade"], "#8b949e")
    html += f"""
    <div class="risk-banner">
        <div class="risk-grade" style="color:{gc}">{risk["grade"]}</div>
        <div>
            <div class="risk-label" style="color:{gc}">{risk["label"]}</div>
            <div class="risk-sub">Risk Score: {risk["score"]}/100</div>
        </div>
    </div>
"""

    # Stats
    html += '<div class="stats-grid">'
    for sev, color in SEVERITY_COLOR.items():
        html += f'''
        <div class="stat-card">
            <div class="stat-num" style="color:{color}">{sev_counts[sev]}</div>
            <div class="stat-label">{sev}</div>
        </div>'''
    html += '</div>'

    # Findings per host
    for host in scan_results:
        findings = host.get("findings", [])
        ip = host["ip"]
        os_guess = host.get("os_guess", "N/A")
        html += f'<div class="section-title">📡 Host: {ip} — {os_guess} ({len(findings)} findings)</div>'

        if not findings:
            html += '<p style="color:#8b949e; margin-bottom:20px;">No open ports found.</p>'
            continue

        html += """<table>
        <thead><tr>
            <th>Port</th><th>Service</th><th>Severity</th><th>Finding</th><th>OWASP</th><th>CVEs</th>
        </tr></thead><tbody>"""

        for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.get("severity","INFO"))):
            sev = f.get("severity", "INFO")
            color = SEVERITY_COLOR[sev]
            owasp_tags = "".join(f'<span class="owasp-tag">{o}</span>' for o in f.get("owasp", []))
            cves = " ".join(f'<span class="cve">{c}</span>' for c in f.get("cve_refs", [])) or "—"

            html += f"""<tr>
            <td><strong>{f['port']}</strong><br><small style="color:#8b949e">{f.get('protocol','tcp')}</small></td>
            <td>{f.get('service','—')}<br><small style="color:#8b949e">{f.get('version','N/A')}</small></td>
            <td><span class="badge" style="background:{color}22;color:{color};border:1px solid {color}44">{sev}</span></td>
            <td>
                <div class="finding-title">{f.get('title','')}</div>
                <div class="finding-desc">{f.get('description','')}</div>
                <div class="remediation">✅ {f.get('remediation','')}</div>
            </td>
            <td>{owasp_tags}</td>
            <td>{cves}</td>
        </tr>"""

        html += "</tbody></table>"

    # OWASP Reference
    html += '<div class="section-title">📋 OWASP Top 10 (2021) Reference</div>'
    html += '<table><thead><tr><th>ID</th><th>Category</th></tr></thead><tbody>'
    for k, v in OWASP_TOP_10.items():
        html += f'<tr><td><strong>{k}</strong></td><td>{v}</td></tr>'
    html += '</tbody></table>'

    html += f'''
</div>
<div class="footer">Generated by NetVulnScanner &nbsp;|&nbsp; EHDF / Ethical Hacking Project &nbsp;|&nbsp; For authorized use only</div>
</body></html>'''

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename


def generate_csv_report(scan_results: list[dict], output_dir: str = "output_reports") -> str:
    """Generates CSV report of all findings."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"vuln_report_{timestamp}.csv")

    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Host IP", "Port", "Protocol", "Service", "Version",
                          "Severity", "Title", "OWASP Categories", "CVEs", "Remediation"])
        for host in scan_results:
            for f in host.get("findings", []):
                writer.writerow([
                    host["ip"], f["port"], f.get("protocol", "tcp"),
                    f.get("service", ""), f.get("version", ""),
                    f.get("severity", ""), f.get("title", ""),
                    " | ".join(f.get("owasp", [])),
                    " | ".join(f.get("cve_refs", [])),
                    f.get("remediation", ""),
                ])
    return filename
