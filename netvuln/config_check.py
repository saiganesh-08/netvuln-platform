import http.client
import ssl

from .findings import Finding

RISKY_SERVICES = {
    21: ("FTP", "high", "Sends credentials in plain text."),
    23: ("Telnet", "critical", "Unencrypted remote shell."),
    69: ("TFTP", "medium", "No authentication."),
    135: ("MS RPC", "medium", "Commonly abused for lateral movement."),
    139: ("NetBIOS", "medium", "Legacy file sharing exposure."),
    445: ("SMB", "high", "Exposed SMB is a frequent attack target."),
    1433: ("MSSQL", "medium", "Database exposed to the network."),
    3306: ("MySQL", "medium", "Database exposed to the network."),
    3389: ("RDP", "high", "Remote desktop exposed to the network."),
    5432: ("PostgreSQL", "medium", "Database exposed to the network."),
    5900: ("VNC", "high", "Remote desktop, often weakly protected."),
    6379: ("Redis", "high", "Often runs without authentication."),
    9200: ("Elasticsearch", "high", "Frequently exposed without authentication."),
    27017: ("MongoDB", "high", "Often runs without authentication."),
}

WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443}

EXPECTED_HEADERS = {
    "X-Content-Type-Options": ("low", "Add 'X-Content-Type-Options: nosniff'."),
    "X-Frame-Options": ("low", "Add X-Frame-Options or a CSP frame-ancestors rule."),
    "Content-Security-Policy": ("medium", "Define a Content-Security-Policy."),
}


def check_risky_service(host, result):
    entry = RISKY_SERVICES.get(result.port)
    if not entry:
        return []
    name, severity, why = entry
    return [Finding(
        title=f"{name} reachable on port {result.port}", severity=severity,
        host=host, port=result.port, category="exposure", detail=why,
        recommendation="Restrict access with a firewall or place it behind a VPN.",
    )]


def check_http(host, port, use_tls, timeout=3.0):
    findings = []
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
    except (OSError, http.client.HTTPException):
        return findings

    if not use_tls:
        findings.append(Finding(
            title="HTTP served without TLS", severity="medium", host=host, port=port,
            category="config", recommendation="Redirect to HTTPS.",
        ))
    elif "strict-transport-security" not in headers:
        findings.append(Finding(
            title="Missing Strict-Transport-Security header", severity="medium",
            host=host, port=port, category="config",
            recommendation="Add an HSTS header with a long max-age.",
        ))

    for name, (severity, fix) in EXPECTED_HEADERS.items():
        if name.lower() not in headers:
            findings.append(Finding(
                title=f"Missing {name} header", severity=severity, host=host,
                port=port, category="config", recommendation=fix,
            ))

    server = headers.get("server", "")
    if any(ch.isdigit() for ch in server):
        findings.append(Finding(
            title="Server header discloses version", severity="low", host=host,
            port=port, category="config", detail=server,
            recommendation="Hide version details from the Server header.",
        ))
    return findings
