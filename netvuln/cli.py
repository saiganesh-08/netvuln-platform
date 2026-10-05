import argparse
import ipaddress
import socket
import sys

from . import anomaly, config_check, tls_check
from .report import build_report, write_json, write_markdown
from .scanner import parse_ports, scan_host

DEFAULT_PORTS = "21-25,53,80,110,143,443,445,993,995,1433,3000,3306,3389,5000,5432,5900,6379,8000,8080,8443,9200,27017"


def expand_target(target):
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = list(net.hosts()) or [net.network_address]
        if len(hosts) > 256:
            raise SystemExit("refusing to scan more than 256 hosts at once")
        return [str(h) for h in hosts]
    except ValueError:
        return [target]


def assess_host(host, args):
    ports = parse_ports(args.ports)
    results = scan_host(host, ports, timeout=args.timeout)
    findings = []
    for r in results:
        findings += config_check.check_risky_service(host, r)
        tls = r.port in tls_check.TLS_PORTS or tls_check.looks_like_tls(host, r.port)
        if tls:
            findings += tls_check.inspect_tls(host, r.port)
        if r.port in config_check.WEB_PORTS or (r.banner or "").startswith("HTTP/"):
            findings += config_check.check_http(host, r.port, use_tls=tls)
    findings += anomaly.latency_outliers(host, results)
    if args.baseline:
        findings += anomaly.compare_with_baseline(host, results, args.baseline)
    return results, findings


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="netvuln",
        description="Network vulnerability assessment for systems you are authorized to test.",
    )
    parser.add_argument("target", help="hostname, IP, or CIDR range (max 256 hosts)")
    parser.add_argument("--ports", default=DEFAULT_PORTS)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--baseline", help="previous JSON report to compare against")
    parser.add_argument("--out", default="reports/report", help="output path without extension")
    parser.add_argument("--i-have-permission", action="store_true",
                        help="confirm you are authorized to scan this target")
    args = parser.parse_args(argv)

    if not args.i_have_permission:
        print("Scanning requires --i-have-permission. Only scan systems you own or are authorized to test.")
        return 2

    hosts, all_findings = {}, []
    for host in expand_target(args.target):
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            print(f"could not resolve {host}", file=sys.stderr)
            continue
        print(f"scanning {host} ...")
        results, findings = assess_host(host, args)
        hosts[host] = results
        all_findings += findings

    report = build_report(args.target, hosts, all_findings)
    write_json(report, args.out + ".json")
    write_markdown(report, args.out + ".md")
    print(f"done: {report['summary']}")
    print(f"reports written to {args.out}.json and {args.out}.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
