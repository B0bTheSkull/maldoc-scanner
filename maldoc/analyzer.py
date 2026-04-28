"""Score extracted document content against the indicator catalog."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from maldoc.indicators import PDF_INDICATORS, VBA_INDICATORS

URL_RE = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Hit:
    name: str
    weight: int
    detail: str


@dataclass
class IOCs:
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)


@dataclass
class Report:
    source: str
    doc_type: str  # "office" | "pdf" | "unknown"
    score: int
    severity: str  # low | medium | high
    hits: list[Hit] = field(default_factory=list)
    iocs: IOCs = field(default_factory=IOCs)
    notes: list[str] = field(default_factory=list)


def _severity(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _scan(text: str, catalog) -> list[Hit]:
    hits: list[Hit] = []
    for name, pattern, weight, explain in catalog:
        if pattern.search(text):
            hits.append(Hit(name=name, weight=weight, detail=explain))
    return hits


def _extract_iocs(text: str) -> IOCs:
    urls = sorted({u.rstrip(".,);'\"") for u in URL_RE.findall(text)})
    ips = sorted({ip for ip in IPV4_RE.findall(text) if not ip.startswith(("0.", "127.", "255."))})
    return IOCs(urls=urls, ips=ips)


def analyze_office(content: str, source: str = "(stdin)", notes: Optional[list[str]] = None) -> Report:
    """Score extracted Office macro / OLE content."""
    hits = _scan(content, VBA_INDICATORS)
    score = min(100, sum(h.weight for h in hits))
    return Report(
        source=source,
        doc_type="office",
        score=score,
        severity=_severity(score),
        hits=hits,
        iocs=_extract_iocs(content),
        notes=notes or [],
    )


def analyze_pdf(content: str, source: str = "(stdin)", notes: Optional[list[str]] = None) -> Report:
    """Score extracted PDF body / catalog content."""
    hits = _scan(content, PDF_INDICATORS)
    score = min(100, sum(h.weight for h in hits))
    return Report(
        source=source,
        doc_type="pdf",
        score=score,
        severity=_severity(score),
        hits=hits,
        iocs=_extract_iocs(content),
        notes=notes or [],
    )
