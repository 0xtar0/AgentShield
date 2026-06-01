from __future__ import annotations

import argparse
from pathlib import Path

from agentshield import __version__
from agentshield.audit import run_audit
from agentshield.baseline import apply_baseline, load_baseline, write_baseline
from agentshield.models import AuditContext, SEVERITY_ORDER
from agentshield.policy import load_policy, write_default_policy
from agentshield.report import write_html, write_json, write_markdown, write_sarif


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "init-policy":
        return _init_policy(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentshield", description="Audit a developer laptop for agentic-coding security risks.")
    parser.add_argument("--version", action="version", version=f"AgentShield {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Run a local read-only workstation audit.")
    scan.add_argument("--home", type=Path, default=Path.home(), help="Home directory to audit.")
    scan.add_argument("--output", type=Path, default=Path("reports/agentshield.html"), help="HTML report path.")
    scan.add_argument("--json-output", type=Path, help="JSON report path.")
    scan.add_argument("--markdown-output", type=Path, help="Markdown report path.")
    scan.add_argument("--sarif-output", type=Path, help="SARIF report path.")
    scan.add_argument("--format", choices=["html", "json", "md", "sarif", "all"], default="html", help="Report format convenience switch.")
    scan.add_argument("--skip-shell-history", action="store_true", help="Skip shell history scanning.")
    scan.add_argument("--skip-global-packages", action="store_true", help="Skip npm/pip/pipx inventory.")
    scan.add_argument("--max-history-bytes", type=_positive_int, default=1_000_000, help="Bytes to read from the end of each history file.")
    scan.add_argument("--baseline", type=Path, help="Suppress findings listed in an AgentShield baseline JSON file.")
    scan.add_argument("--write-baseline", type=Path, help="Write a baseline JSON file from the full unsuppressed audit.")
    scan.add_argument("--policy", type=Path, help="Apply an AgentShield policy JSON file.")
    scan.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none", help="Exit non-zero when this severity or higher is present.")

    init_policy = subparsers.add_parser("init-policy", help="Write a starter AgentShield policy JSON file.")
    init_policy.add_argument("--output", type=Path, default=Path(".agentshield-policy.json"), help="Policy output path.")
    init_policy.add_argument("--force", action="store_true", help="Overwrite an existing policy file.")
    return parser


def _scan(args: argparse.Namespace) -> int:
    home = args.home.expanduser().resolve()
    try:
        policy = load_policy(args.policy) if args.policy else None
    except ValueError as exc:
        print(f"Policy error: {exc}")
        return 2
    ctx = AuditContext(
        home=home,
        scan_shell_history=not args.skip_shell_history,
        scan_global_packages=not args.skip_global_packages,
        max_history_bytes=args.max_history_bytes,
        **({"policy": policy} if policy else {}),
    )
    report = run_audit(ctx)
    unsuppressed_report = report
    suppressed_count = 0
    if args.write_baseline:
        write_baseline(unsuppressed_report, args.write_baseline)
    if args.baseline:
        try:
            baseline_fingerprints = load_baseline(args.baseline)
        except ValueError as exc:
            print(f"Baseline error: {exc}")
            return 2
        baseline_result = apply_baseline(report, baseline_fingerprints)
        report = baseline_result.report
        suppressed_count = len(baseline_result.suppressed)

    html_path: Path | None = args.output
    json_path: Path | None = args.json_output
    markdown_path: Path | None = args.markdown_output
    sarif_path: Path | None = args.sarif_output
    if args.format in ("json", "all") and json_path is None:
        json_path = args.output.with_suffix(".json")
    if args.format in ("md", "all") and markdown_path is None:
        markdown_path = args.output.with_suffix(".md")
    if args.format in ("sarif", "all") and sarif_path is None:
        sarif_path = args.output.with_suffix(".sarif")

    if args.format in ("html", "all"):
        write_html(report, html_path)
    if json_path:
        write_json(report, json_path)
    if markdown_path:
        write_markdown(report, markdown_path)
    if sarif_path:
        write_sarif(report, sarif_path)

    print("AgentShield audit complete")
    print(f"Risk score: {report.risk_score}/100")
    print("Findings: " + _counts_text(report))
    if args.write_baseline:
        print(f"Baseline written: {args.write_baseline}")
    if args.baseline:
        print(f"Baseline suppressed: {suppressed_count} findings")
    if args.policy:
        print(f"Policy applied: {args.policy}")
    if args.format in ("html", "all"):
        print(f"HTML report: {html_path}")
    if json_path:
        print(f"JSON report: {json_path}")
    if markdown_path:
        print(f"Markdown report: {markdown_path}")
    if sarif_path:
        print(f"SARIF report: {sarif_path}")

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[finding.severity] >= threshold for finding in report.findings):
            return 1
    return 0


def _init_policy(args: argparse.Namespace) -> int:
    if args.output.exists() and not args.force:
        print(f"Policy already exists: {args.output}. Use --force to overwrite.")
        return 2
    write_default_policy(args.output)
    print(f"Policy written: {args.output}")
    return 0


def _counts_text(report) -> str:
    counts = report.counts
    return ", ".join(f"{counts[severity]} {severity}" for severity in ["critical", "high", "medium", "low", "info"])


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed
