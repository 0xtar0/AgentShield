from __future__ import annotations

import html
import json
from pathlib import Path

from agentshield.models import AuditReport


def write_json(report: AuditReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(report: AuditReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# AgentShield Audit Report",
        "",
        f"- Generated: `{report.generated_at.isoformat()}`",
        f"- Home: `{report.home}`",
        f"- Risk score: `{report.risk_score}/100`",
        f"- Findings: `{_counts_text(report)}`",
        "",
        "## Findings",
        "",
    ]
    for finding in report.findings:
        lines.extend(
            [
                f"### [{finding.severity.upper()}] {finding.title}",
                "",
                f"- ID: `{finding.id}`",
                f"- Category: `{finding.category}`",
                f"- Location: `{finding.location}`",
                f"- Evidence: `{finding.evidence}`",
                f"- Remediation: {finding.remediation}",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_html(report: AuditReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")


def render_html(report: AuditReport) -> str:
    cards = "\n".join(
        f"""
        <article class="finding severity-{html.escape(finding.severity)}">
          <div class="finding-head">
            <span class="badge">{html.escape(finding.severity.upper())}</span>
            <span class="category">{html.escape(finding.category)}</span>
          </div>
          <h2>{html.escape(finding.title)}</h2>
          <dl>
            <dt>ID</dt><dd><code>{html.escape(finding.id)}</code></dd>
            <dt>Location</dt><dd><code>{html.escape(finding.location)}</code></dd>
            <dt>Evidence</dt><dd><code>{html.escape(finding.evidence)}</code></dd>
            <dt>Remediation</dt><dd>{html.escape(finding.remediation)}</dd>
          </dl>
        </article>
        """
        for finding in report.findings
    )
    counts = report.counts
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentShield Audit Report</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0b1115;
      --panel: #121b21;
      --panel-2: #17232b;
      --text: #edf7f6;
      --muted: #9fb4b0;
      --line: #273942;
      --teal: #26d7b8;
      --amber: #f6b84b;
      --red: #ff5d66;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    header {{
      padding: 40px min(6vw, 72px) 28px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(135deg, #0b1115 0%, #102026 58%, #241d10 100%);
    }}
    .eyebrow {{ color: var(--teal); font-weight: 700; text-transform: uppercase; letter-spacing: .08em; font-size: 12px; }}
    h1 {{ margin: 8px 0 8px; font-size: clamp(32px, 5vw, 64px); line-height: 1; letter-spacing: 0; }}
    .summary {{ color: var(--muted); max-width: 920px; margin: 0; }}
    main {{ padding: 28px min(6vw, 72px) 64px; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }}
    .stat {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }}
    .stat strong {{ display: block; font-size: 28px; }}
    .stat span {{ color: var(--muted); font-size: 13px; }}
    .finding {{ background: var(--panel); border: 1px solid var(--line); border-left: 5px solid var(--teal); border-radius: 8px; padding: 18px; margin: 12px 0; }}
    .severity-critical, .severity-high {{ border-left-color: var(--red); }}
    .severity-medium {{ border-left-color: var(--amber); }}
    .finding-head {{ display: flex; gap: 10px; align-items: center; margin-bottom: 8px; }}
    .badge {{ font-size: 12px; font-weight: 800; color: #05110f; background: var(--teal); border-radius: 999px; padding: 3px 8px; }}
    .severity-critical .badge, .severity-high .badge {{ background: var(--red); }}
    .severity-medium .badge {{ background: var(--amber); }}
    .category {{ color: var(--muted); font-size: 13px; }}
    h2 {{ margin: 0 0 12px; font-size: 20px; letter-spacing: 0; }}
    dl {{ display: grid; grid-template-columns: 120px 1fr; gap: 8px 14px; margin: 0; }}
    dt {{ color: var(--muted); }}
    dd {{ margin: 0; min-width: 0; }}
    code {{ color: #d6fffa; background: var(--panel-2); border: 1px solid var(--line); border-radius: 5px; padding: 2px 5px; word-break: break-word; }}
    @media (max-width: 640px) {{ dl {{ grid-template-columns: 1fr; }} dt {{ margin-top: 8px; }} }}
  </style>
</head>
<body>
  <header>
    <div class="eyebrow">AgentShield audit</div>
    <h1>Risk score {report.risk_score}/100</h1>
    <p class="summary">Generated {html.escape(report.generated_at.isoformat())} for <code>{html.escape(str(report.home))}</code>. Evidence is redacted and the audit is read-only.</p>
  </header>
  <main>
    <section class="stats" aria-label="Finding counts">
      <div class="stat"><strong>{counts.get("critical", 0)}</strong><span>Critical</span></div>
      <div class="stat"><strong>{counts.get("high", 0)}</strong><span>High</span></div>
      <div class="stat"><strong>{counts.get("medium", 0)}</strong><span>Medium</span></div>
      <div class="stat"><strong>{counts.get("low", 0)}</strong><span>Low</span></div>
      <div class="stat"><strong>{counts.get("info", 0)}</strong><span>Info</span></div>
    </section>
    {cards}
  </main>
</body>
</html>
"""


def _counts_text(report: AuditReport) -> str:
    counts = report.counts
    return ", ".join(f"{counts[severity]} {severity}" for severity in ["critical", "high", "medium", "low", "info"])

