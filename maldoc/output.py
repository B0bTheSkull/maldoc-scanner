"""Output formatting for MalDoc Scanner."""

from __future__ import annotations

import json
from dataclasses import asdict

from maldoc.analyzer import Report

SEVERITY_COLOR = {
    "high": "\033[1;91m",
    "medium": "\033[93m",
    "low": "\033[94m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _badge(severity: str, color: bool) -> str:
    label = f"[{severity.upper():>6}]"
    if not color:
        return label
    return f"{SEVERITY_COLOR.get(severity, '')}{label}{RESET}"


def print_text(report: Report, color: bool = True) -> None:
    print(f"\n{BOLD if color else ''}MalDoc Scanner{RESET if color else ''}")
    print(
        f"{DIM if color else ''}Source: {report.source}  |  Type: {report.doc_type}  |  "
        f"Score: {report.score}/100  |  Severity: {report.severity.upper()}{RESET if color else ''}\n"
    )
    if report.notes:
        for n in report.notes:
            print(f"  note: {n}")
        print()

    if not report.hits:
        print("No suspicious indicators matched.")
    else:
        sep = "─" * 72
        print(sep)
        for h in sorted(report.hits, key=lambda x: -x.weight):
            print(f"{_badge(report.severity, color)} +{h.weight:>3}  {BOLD if color else ''}{h.name}{RESET if color else ''}")
            print(f"        {h.detail}")
        print(sep)

    if report.iocs.urls:
        print(f"\nURLs ({len(report.iocs.urls)}):")
        for u in report.iocs.urls[:20]:
            print(f"  {u}")
    if report.iocs.ips:
        print(f"\nIPs ({len(report.iocs.ips)}):")
        for ip in report.iocs.ips:
            print(f"  {ip}")


def print_json(report: Report) -> None:
    print(json.dumps(asdict(report), indent=2, default=str))
