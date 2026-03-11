try:
    from .host_scanner import HostScanner, PortScanner
except Exception:
    pass
try:
    from .vuln_mapper import map_port_to_owasp, calculate_risk_score
except Exception:
    pass
