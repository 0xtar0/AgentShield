from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentshield.models import Finding, Policy, SEVERITY_ORDER

DEFAULT_POLICY = {
    "ignored_ids": [],
    "severity_overrides": {},
    "trusted_packages": {
        "npm": [],
        "pip-user": [],
        "pipx": [],
        "homebrew": [],
        "pnpm": [],
        "cargo": [],
        "gem": [],
    },
    "max_global_packages": {
        "npm": 25,
        "pip-user": 25,
        "pipx": 25,
        "homebrew": 40,
        "pnpm": 25,
        "cargo": 25,
        "gem": 25,
    },
}


def write_default_policy(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(DEFAULT_POLICY, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_policy(path: Path) -> Policy:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")

    ignored_ids = _string_set(payload.get("ignored_ids", []), "ignored_ids")
    severity_overrides = _severity_overrides(payload.get("severity_overrides", {}))
    trusted_packages = _trusted_packages(payload.get("trusted_packages", {}))
    max_global_packages = _max_global_packages(payload.get("max_global_packages", {}))
    return Policy(
        ignored_ids=frozenset(ignored_ids),
        severity_overrides=severity_overrides,
        trusted_packages=trusted_packages,
        max_global_packages=max_global_packages,
    )


def apply_policy(findings: list[Finding], policy: Policy) -> list[Finding]:
    filtered: list[Finding] = []
    for finding in findings:
        if finding.id in policy.ignored_ids:
            continue
        severity = policy.severity_overrides.get(finding.id)
        if severity:
            filtered.append(finding.with_severity(severity))
        else:
            filtered.append(finding)
    return filtered


def _string_set(value: Any, field_name: str) -> set[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    result: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item:
            raise ValueError(f"{field_name} must contain non-empty strings")
        result.add(item)
    return result


def _severity_overrides(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("severity_overrides must be an object")
    result: dict[str, str] = {}
    for finding_id, severity in value.items():
        if not isinstance(finding_id, str) or not isinstance(severity, str):
            raise ValueError("severity_overrides keys and values must be strings")
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"invalid severity override for {finding_id}: {severity}")
        result[finding_id] = severity
    return result


def _trusted_packages(value: Any) -> dict[str, frozenset[str]]:
    if not isinstance(value, dict):
        raise ValueError("trusted_packages must be an object")
    result: dict[str, frozenset[str]] = {}
    for manager, packages in value.items():
        if not isinstance(manager, str):
            raise ValueError("trusted_packages manager names must be strings")
        result[manager] = frozenset(package.lower() for package in _string_set(packages, f"trusted_packages.{manager}"))
    return result


def _max_global_packages(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ValueError("max_global_packages must be an object")
    result: dict[str, int] = {}
    for manager, limit in value.items():
        if not isinstance(manager, str) or not isinstance(limit, int) or limit < 0:
            raise ValueError("max_global_packages must map manager names to non-negative integers")
        result[manager] = limit
    return result
