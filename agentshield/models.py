from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    category: str
    location: str
    evidence: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "location": self.location,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class AuditContext:
    home: Path
    scan_shell_history: bool = True
    scan_global_packages: bool = True
    max_history_bytes: int = 1_000_000
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    command_runner: Callable[[list[str], int], tuple[int, str, str]] | None = None


@dataclass(frozen=True)
class AuditReport:
    generated_at: datetime
    home: Path
    findings: list[Finding]

    @property
    def counts(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def risk_score(self) -> int:
        weights = {"info": 0, "low": 3, "medium": 9, "high": 18, "critical": 30}
        score = sum(weights.get(finding.severity, 0) for finding in self.findings)
        return min(score, 100)

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda item: SEVERITY_ORDER[item.severity]).severity

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "home": str(self.home),
            "risk_score": self.risk_score,
            "counts": self.counts,
            "findings": [finding.as_dict() for finding in self.findings],
        }

