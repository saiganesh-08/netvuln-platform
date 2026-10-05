from dataclasses import dataclass, asdict
from typing import Optional

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    title: str
    severity: str
    host: str
    port: Optional[int] = None
    detail: str = ""
    recommendation: str = ""
    category: str = "general"

    def __post_init__(self):
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {self.severity}")

    def to_dict(self):
        return asdict(self)


def sort_findings(findings):
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.port or 0, f.title))


def summarize(findings):
    counts = {name: 0 for name in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return counts
