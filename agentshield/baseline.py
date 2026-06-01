from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentshield.models import AuditReport, Finding

BASELINE_VERSION = 1


@dataclass(frozen=True)
class BaselineApplyResult:
    report: AuditReport
    suppressed: list[Finding]
    unknown_fingerprints: set[str]


def write_baseline(report: AuditReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": BASELINE_VERSION,
        "generated_at": report.generated_at.isoformat(),
        "home": str(report.home),
        "findings": [
            {
                "fingerprint": finding.fingerprint,
                "id": finding.id,
                "severity": finding.severity,
                "category": finding.category,
                "location": finding.location,
                "title": finding.title,
            }
            for finding in report.findings
            if finding.severity != "info"
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> set[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{path} must contain a findings list")

    fingerprints: set[str] = set()
    for item in findings:
        fingerprint = _fingerprint_from_item(item)
        if fingerprint:
            fingerprints.add(fingerprint)
    return fingerprints


def apply_baseline(report: AuditReport, fingerprints: set[str]) -> BaselineApplyResult:
    active: list[Finding] = []
    suppressed: list[Finding] = []
    matched: set[str] = set()
    for finding in report.findings:
        if finding.fingerprint in fingerprints and finding.severity != "info":
            suppressed.append(finding)
            matched.add(finding.fingerprint)
        else:
            active.append(finding)
    return BaselineApplyResult(
        report=AuditReport(generated_at=report.generated_at, home=report.home, findings=active),
        suppressed=suppressed,
        unknown_fingerprints=fingerprints - matched,
    )


def _fingerprint_from_item(item: Any) -> str | None:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        value = item.get("fingerprint")
        return value if isinstance(value, str) and value else None
    return None
