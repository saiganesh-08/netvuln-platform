import socket
import ssl
import time

from .findings import Finding

WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5")
TLS_PORTS = {443, 465, 636, 993, 995, 8443}


def looks_like_tls(host, port, timeout=2.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except (OSError, ssl.SSLError):
        return False


def inspect_tls(host, port, timeout=3.0):
    findings = []
    verified = True
    cert = None

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version, cipher = tls.version(), tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        verified = False
        findings.append(Finding(
            title="Certificate failed validation",
            severity="high",
            host=host, port=port, category="tls",
            detail=exc.verify_message or str(exc),
            recommendation="Use a certificate from a trusted CA that matches the hostname.",
        ))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    version, cipher = tls.version(), tls.cipher()
        except (OSError, ssl.SSLError):
            return findings
    except (OSError, ssl.SSLError) as exc:
        findings.append(Finding(
            title="TLS handshake failed",
            severity="info", host=host, port=port, category="tls", detail=str(exc),
        ))
        return findings

    if cert:
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        days_left = int((expires - time.time()) // 86400)
        if days_left < 0:
            findings.append(Finding(
                title="Certificate expired", severity="critical", host=host, port=port,
                category="tls", detail=f"Expired {-days_left} days ago",
                recommendation="Renew the certificate immediately.",
            ))
        elif days_left < 30:
            findings.append(Finding(
                title="Certificate expires soon", severity="medium", host=host, port=port,
                category="tls", detail=f"{days_left} days remaining",
                recommendation="Renew the certificate before it expires.",
            ))

    if version in ("SSLv3", "TLSv1", "TLSv1.1"):
        findings.append(Finding(
            title=f"Deprecated protocol negotiated ({version})", severity="high",
            host=host, port=port, category="tls",
            recommendation="Disable anything below TLS 1.2.",
        ))

    if cipher and any(m in cipher[0] for m in WEAK_CIPHER_MARKERS):
        findings.append(Finding(
            title=f"Weak cipher negotiated ({cipher[0]})", severity="high",
            host=host, port=port, category="tls",
            recommendation="Restrict the server to modern AEAD cipher suites.",
        ))

    if verified and not findings:
        findings.append(Finding(
            title="TLS configuration looks healthy", severity="info", host=host,
            port=port, category="tls", detail=f"{version}, {cipher[0] if cipher else 'n/a'}",
        ))
    return findings
