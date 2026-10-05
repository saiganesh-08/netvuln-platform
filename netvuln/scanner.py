import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
}


@dataclass
class PortResult:
    port: int
    service: str
    latency_ms: float
    banner: Optional[str] = None

    def to_dict(self):
        return {
            "port": self.port,
            "service": self.service,
            "latency_ms": round(self.latency_ms, 2),
            "banner": self.banner,
        }


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"port out of range: {bad[0]}")
    return sorted(ports)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock, port):
    try:
        sock.settimeout(1.0)
        probe = PROBES.get(port)
        if probe:
            sock.sendall(probe)
        data = sock.recv(256)
        text = data.decode("utf-8", errors="replace").strip()
        return text.splitlines()[0][:120] if text else None
    except OSError:
        return None


def probe_port(host, port, timeout):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            latency = (time.perf_counter() - start) * 1000
            banner = grab_banner(sock, port)
            return PortResult(port, service_name(port), latency, banner)
    except OSError:
        return None


def scan_host(host, ports, timeout=1.0, workers=100):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: probe_port(host, p, timeout), ports)
    return sorted((r for r in results if r), key=lambda r: r.port)
