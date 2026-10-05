# netvuln

A Python tool for assessing the security of networks and hosts you are authorized to test. It discovers open services, checks TLS and web configuration, rates findings by severity, writes reports, and flags unusual behavior.

Standard library only, no dependencies.

## What it does

- **Service discovery:** threaded TCP connect scan with banner grabbing
- **SSL/TLS checks:** certificate validation, expiry, deprecated protocol versions, weak ciphers
- **Configuration checks:** risky exposed services (Telnet, RDP, Redis, etc.), missing HTTP security headers, version disclosure
- **Severity ratings:** critical, high, medium, low, info
- **Reporting:** JSON and Markdown reports
- **Anomaly detection:** z-score outliers on response times, plus new or missing ports compared to a previous scan

## Usage

```
python -m netvuln 192.168.1.10 --i-have-permission
python -m netvuln 192.168.1.0/24 --ports 1-1024 --out reports/lan
python -m netvuln 192.168.1.10 --baseline reports/lan.json --i-have-permission
```

The `--i-have-permission` flag is required. Only scan systems you own or have written permission to test.

## Tests

```
python -m unittest discover -s tests
```

## Layout

```
netvuln/
  scanner.py       port scan and banner grab
  tls_check.py     certificate and protocol checks
  config_check.py  exposed services and HTTP headers
  anomaly.py       z-score and baseline comparison
  findings.py      Finding model, sorting, summary
  report.py        JSON and Markdown output
  cli.py           command line entry point
tests/
reports/
```

## Limits

- TCP connect scan only, no UDP or raw packets
- Finds misconfigurations, does not exploit anything
- Certificate expiry is only read when the certificate validates
