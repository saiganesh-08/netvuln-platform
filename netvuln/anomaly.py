import json
import statistics

from .findings import Finding


def latency_outliers(host, results, threshold=2.0):
    if len(results) < 4:
        return []
    values = [r.latency_ms for r in results]
    mean = statistics.mean(values)
    stdev = statistics.pstdev(values)
    if stdev == 0:
        return []
    findings = []
    for r in results:
        z = (r.latency_ms - mean) / stdev
        if abs(z) >= threshold:
            findings.append(Finding(
                title=f"Unusual response time on port {r.port}", severity="low",
                host=host, port=r.port, category="anomaly",
                detail=f"{r.latency_ms:.1f} ms (z-score {z:.2f}, mean {mean:.1f} ms)",
                recommendation="Check what is running on this port.",
            ))
    return findings


def compare_with_baseline(host, results, baseline_path):
    try:
        with open(baseline_path) as fh:
            baseline = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    known = {
        p["port"] for h in baseline.get("hosts", []) if h["host"] == host
        for p in h["open_ports"]
    }
    current = {r.port for r in results}
    findings = []
    for port in sorted(current - known):
        findings.append(Finding(
            title=f"New open port since baseline ({port})", severity="medium",
            host=host, port=port, category="anomaly",
            recommendation="Confirm this service is expected.",
        ))
    for port in sorted(known - current):
        findings.append(Finding(
            title=f"Port from baseline no longer open ({port})", severity="info",
            host=host, port=port, category="anomaly",
        ))
    return findings
