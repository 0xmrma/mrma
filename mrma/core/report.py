from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_md_report(data: dict[str, Any]) -> str:
    """
    Render a compact Markdown report from report.json structure.
    """
    lines: list[str] = []
    tgt = data.get("target", {})
    lines.append("# mrma report")
    lines.append("")
    lines.append(f"- URL: `{tgt.get('url','')}`")
    lines.append(f"- Generated: `{data.get('generated_at','')}`")
    lines.append("")

    # Trust boundary score
    tb = data.get("trust_boundary", {})
    if tb:
        lines.append("## Trust boundary score")
        lines.append("")
        lines.append(f"- Score: `{tb.get('score')}` / 100")

        score_val = int(tb.get("score", 0) or 0)
        severity = "LOW" if score_val <= 20 else "MED" if score_val <= 50 else "HIGH"
        lines.append(f"- Severity: `{severity}`")

        lines.append(f"- Summary: {md_escape(str(tb.get('summary','')))}")
        lines.append("")

    # Baseline
    base = data.get("baseline", {})
    if base:
        lines.append("## Baseline")
        lines.append("")
        lines.append(f"- Status: `{base.get('status')}`")
        lines.append(f"- Length: `{base.get('body_length')}`")
        lines.append(f"- SHA256: `{base.get('body_sha256')}`")
        lines.append("")

    # Impact
    impact = data.get("impact", {})
    rows = impact.get("rows", []) if isinstance(impact, dict) else []
    if rows:
        lines.append("## Top deltas (impact)")
        lines.append("")
        lines.append("| Mutation | Verdict | Similarity | Status | Len |")
        lines.append("|---|---:|---:|---:|---:|")
        for r in rows[:20]:
            lines.append(
                f"| {md_escape(str(r.get('mutation','')))} "
                f"| {md_escape(str(r.get('verdict','')))} "
                f"| {r.get('similarity','')} "
                f"| {r.get('status_base','')}→{r.get('status_mut','')} "
                f"| {r.get('len_base','')}→{r.get('len_mut','')} |"
            )
        lines.append("")

    # Security headers
    sec = data.get("security_headers", {})
    findings = sec.get("findings", []) if isinstance(sec, dict) else []
    if findings:
        lines.append("## Security headers")
        lines.append("")
        summ = sec.get("summary", {})
        if summ:
            lines.append(f"- Score: `{summ.get('score')}` (0 best)")
            lines.append(f"- OK/WEAK/MISSING: `{summ.get('ok')}/{summ.get('weak')}/{summ.get('missing')}`")
            lines.append("")
        lines.append("| Header | Status | Note |")
        lines.append("|---|---:|---|")
        for f in findings:
            lines.append(
                f"| {md_escape(str(f.get('header','')))} "
                f"| {md_escape(str(f.get('status','')))} "
                f"| {md_escape(str(f.get('note','')))} |"
            )
        lines.append("")

    # Proxy trust / Host routing
    for key, title in [("proxy_trust", "Proxy-trust"), ("host_routing", "Host-routing")]:
        block = data.get(key, {})
        results = block.get("results", []) if isinstance(block, dict) else []
        if results:
            lines.append(f"## {title}")
            lines.append("")
            lines.append("| Case | Verdict | Similarity | Status | Location change |")
            lines.append("|---|---:|---:|---:|---:|")
            for r in results:
                loc_change = "yes" if (r.get("location_base") != r.get("location_case")) else "no"
                lines.append(
                    f"| {md_escape(str(r.get('case','')))} "
                    f"| {md_escape(str(r.get('verdict','')))} "
                    f"| {r.get('similarity','')} "
                    f"| {r.get('status_base','')}→{r.get('status_case','')} "
                    f"| {loc_change} |"
                )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"
