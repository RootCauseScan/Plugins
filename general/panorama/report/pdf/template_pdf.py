"""Template-based PDF report from canonical report (Markdown + CSS -> WeasyPrint)."""
from __future__ import annotations

import copy
import os
from datetime import datetime
from typing import Any, Dict, List

from .template_engine import process_template

try:
    import markdown
    from weasyprint import HTML, CSS

    TEMPLATE_AVAILABLE = True
except ImportError:
    TEMPLATE_AVAILABLE = False


def _escape_html(s: str) -> str:
    if not s:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _truncate_text(s: str, max_chars: int = 2500, max_lines: int = 50) -> tuple[str, bool]:
    if not s:
        return "", False
    raw = s.replace("\r\n", "\n").replace("\r", "\n")
    lines = raw.split("\n")
    truncated = False
    if len(lines) > max_lines:
        raw = "\n".join(lines[:max_lines])
        truncated = True
    if len(raw) > max_chars:
        raw = raw[:max_chars]
        truncated = True
    return raw, truncated


def _format_locations(occurrences: List[Dict[str, Any]], per_line: int = 10) -> str:
    if not occurrences:
        return "N/A"
    locs = [f"{o.get('line', 'N/A')}:{o.get('column', 'N/A')}" for o in occurrences]
    parts = []
    for i in range(0, len(locs), per_line):
        parts.append(", ".join(locs[i : i + per_line]))
    return "\n".join(parts)


def build_panorama_template_context(report: Dict[str, Any], opts: Dict[str, Any]) -> Dict[str, Any]:
    """Build template context from canonical report. Enriches sast.findings for HTML output."""
    ctx = copy.deepcopy(report)
    metadata = ctx.get("metadata", {})
    summary = metadata.get("summary", {})
    workspace_root = metadata.get("workspace_root") or opts.get("workspace_root") or ""

    # Convenience fields
    generated_at = metadata.get("generated_at", "")
    if generated_at:
        try:
            dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            ctx["report_date"] = dt.strftime("%B %d, %Y")
        except Exception:
            ctx["report_date"] = generated_at
    else:
        ctx["report_date"] = datetime.now().strftime("%B %d, %Y")

    ctx["title"] = metadata.get("report_title") or opts.get("report_title") or "RootCause Panorama Report"
    ctx["workspace_root"] = _escape_html(workspace_root)
    if workspace_root and workspace_root not in ("", "N/A"):
        ctx["workspace_name"] = _escape_html(os.path.basename(workspace_root.rstrip(os.sep)) or "this project")
    else:
        ctx["workspace_name"] = "this project"

    # Convenience flags still used by template (no OR in template language: has_infra = images or findings)
    infra_images = ctx.get("infrastructure", {}).get("images", [])
    infra_findings = ctx.get("infrastructure", {}).get("findings", [])
    ctx["has_infra"] = bool(
        opts.get("infra") is not False and (infra_images or infra_findings)
    )
    sast_findings = ctx.get("sast", {}).get("findings", [])
    ctx["no_sast_findings"] = len(sast_findings) == 0

    # SAST severity breakdown for charts (same format as dependency severity_breakdown)
    _sast_sev: Dict[str, int] = {}
    for f in sast_findings:
        sev = (f.get("severity") or "unknown").upper()
        _sast_sev[sev] = _sast_sev.get(sev, 0) + 1
    _sev_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
    sast_severity_breakdown: List[Dict[str, Any]] = []
    for sev in _sev_order:
        if sev in _sast_sev:
            cnt = _sast_sev[sev]
            total_s = len(sast_findings)
            pct = f"{(cnt / total_s * 100.0):.1f}" if total_s else "0.0"
            sast_severity_breakdown.append({"severity": sev.title(), "count": cnt, "percent": pct, "severity_class": sev.lower()})
    for sev in sorted(_sast_sev.keys()):
        if sev not in _sev_order:
            cnt = _sast_sev[sev]
            total_s = len(sast_findings)
            pct = f"{(cnt / total_s * 100.0):.1f}" if total_s else "0.0"
            sast_severity_breakdown.append({"severity": sev.title(), "count": cnt, "percent": pct, "severity_class": sev.lower()})
    ctx["sast_severity_breakdown"] = sast_severity_breakdown

    # Add severity_class to dependency breakdown for chart CSS
    for row in ctx.get("dependency_vulnerabilities", {}).get("severity_breakdown", []):
        row["severity_class"] = (row.get("severity") or "unknown").lower()

    # Enrich sast.findings for template (file_display, locations_txt, title, *_md)
    enriched = []
    for i, f in enumerate(sast_findings, 1):
        row = dict(f)
        occ_count = int(f.get("occurrence_count", 1))
        row["occ_count"] = str(occ_count)
        file_path = f.get("file", "Unknown Path") or "Unknown Path"
        if workspace_root and file_path != "Unknown Path" and str(file_path).startswith(workspace_root):
            row["file_display"] = _escape_html(os.path.relpath(file_path, workspace_root))
        elif file_path != "Unknown Path":
            row["file_display"] = _escape_html(os.path.basename(file_path))
        else:
            row["file_display"] = _escape_html(str(file_path))

        occs = f.get("occurrences", [])
        row["locations_txt"] = _escape_html(_format_locations(occs))

        rule_id = f.get("rule_id", "Unknown Rule") or "Unknown Rule"
        row["title"] = _escape_html(
            f"Finding #{i}: {rule_id} ({occ_count} occurrence{'s' if occ_count != 1 else ''})"
        )
        row["rule_id"] = _escape_html(rule_id)
        row["severity"] = (f.get("severity") or "unknown").title()
        row["message"] = _escape_html(f.get("message", "No message provided") or "No message provided")

        excerpt = f.get("excerpt", "") or ""
        excerpt_trunc, excerpt_was = _truncate_text(excerpt, 2500, 50)
        if excerpt_was:
            excerpt_trunc += "\n… (truncated)"
        row["excerpt_md"] = "<pre>" + _escape_html(excerpt_trunc) + "</pre>" if excerpt_trunc else ""

        remediation = f.get("remediation", "") or ""
        row["remediation_md"] = "**Remediation:** " + _escape_html(remediation) if remediation else ""

        context_val = f.get("context", "") or ""
        context_trunc, context_was = _truncate_text(context_val, 2500, 50)
        if context_was:
            context_trunc += "\n… (truncated)"
        row["context_md"] = "<pre>" + _escape_html(context_trunc) + "</pre>" if context_trunc else ""

        enriched.append(row)

    if "sast" not in ctx:
        ctx["sast"] = {}
    ctx["sast"]["findings"] = enriched

    # Truncate vuln descriptions for table
    for v in ctx.get("dependency_vulnerabilities", {}).get("vulnerabilities", []):
        desc = v.get("description", "") or ""
        if len(desc) > 100:
            v["description_short"] = desc[:97] + "..."
        else:
            v["description_short"] = desc

    # Split infrastructure findings into config vs image-vulnerability
    infra = ctx.get("infrastructure", {})
    all_infra_findings = infra.get("findings", [])
    config_findings = [
        f for f in all_infra_findings
        if (f.get("rule_id") or "") != "infra.image-vulnerability"
    ]
    image_vuln_findings = [
        f for f in all_infra_findings
        if (f.get("rule_id") or "") == "infra.image-vulnerability"
    ]
    ctx["infrastructure"]["config_findings"] = config_findings
    ctx["infrastructure"]["image_vulnerability_findings"] = image_vuln_findings
    ctx["has_image_vulnerability_findings"] = bool(image_vuln_findings)
    # Limit displayed vulns per image to avoid huge PDFs; expose first 30 + remaining count
    MAX_IMAGE_VULNS_DISPLAY = 30
    for f in image_vuln_findings:
        vulns = f.get("vulnerabilities") or []
        total = len(vulns)
        f["vulnerabilities"] = vulns[:MAX_IMAGE_VULNS_DISPLAY]
        f["remaining_vulns_count"] = max(0, total - MAX_IMAGE_VULNS_DISPLAY)

    return ctx


def write_pdf(
    report_dir: str,
    report: Dict[str, Any],
    opts: Dict[str, Any],
    plugin_dir: str,
    allow_commands: bool = False,
) -> List[tuple[str, int]]:
    """Render PDF from template + canonical report. Returns [(path, size)]."""
    if not TEMPLATE_AVAILABLE:
        return []

    template_path = opts.get("pdf_template") or os.path.join(plugin_dir, "templates", "panorama-report.md")
    css_path = opts.get("pdf_template_css") or os.path.join(plugin_dir, "templates", "panorama-report.css")

    if not os.path.isfile(template_path):
        return []
    if not os.path.isfile(css_path):
        css_path = os.path.join(plugin_dir, "templates", "panorama-report.css")

    context = build_panorama_template_context(report, opts)

    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()

    processed = process_template(template_content, context, allow_commands=allow_commands)
    html_body = markdown.markdown(processed, extensions=["tables", "nl2br"])

    css_abs = os.path.abspath(css_path)
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>{_escape_html(context.get("title", "Panorama Report"))}</title>
  <link rel="stylesheet" href="file://{css_abs}" />
</head>
<body>
{html_body}
</body>
</html>"""

    output_path = os.path.join(report_dir, "panorama-report.pdf")
    base_url = os.path.abspath(plugin_dir)
    html = HTML(string=html_doc, base_url=base_url)
    html.write_pdf(output_path, stylesheets=[CSS(filename=css_abs)])

    return [(output_path, os.path.getsize(output_path))]
