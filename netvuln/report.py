import json
from datetime import datetime, timezone

from .findings import sort_findings, summarize


def build_report(target, hosts, findings):
    ordered = sort_findings(findings)
    return {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summarize(ordered),
        "hosts": [
            {"host": h, "open_ports": [r.to_dict() for r in results]}
            for h, results in hosts.items()
        ],
        "findings": [f.to_dict() for f in ordered],
    }


def write_json(report, path):
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)


def write_markdown(report, path):
    lines = [f"# Security Assessment: {report['target']}", "",
             f"Generated: {report['generated_at']}", "", "## Summary", ""]
    for sev, count in report["summary"].items():
        lines.append(f"- {sev.capitalize()}: {count}")
    lines += ["", "## Open ports", ""]
    for h in report["hosts"]:
        lines.append(f"**{h['host']}**")
        for p in h["open_ports"]:
            lines.append(f"- {p['port']}/tcp {p['service']}")
        lines.append("")
    lines += ["## Findings", ""]
    for f in report["findings"]:
        port = f":{f['port']}" if f["port"] else ""
        lines.append(f"### [{f['severity'].upper()}] {f['title']} ({f['host']}{port})")
        if f["detail"]:
            lines.append(f"- Detail: {f['detail']}")
        if f["recommendation"]:
            lines.append(f"- Fix: {f['recommendation']}")
        lines.append("")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))
