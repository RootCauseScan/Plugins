"""Template-based PDF report (Markdown + CSS → WeasyPrint)."""
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from .findings import format_locations, group_findings, safe_str, truncate_text
from .template_engine import process_template

try:
    import markdown
    from weasyprint import HTML, CSS

    TEMPLATE_AVAILABLE = True
except ImportError:
    TEMPLATE_AVAILABLE = False


def _escape_html(s: str) -> str:
    """Escape for safe inclusion in HTML/MD."""
    if not s:
        return ""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def build_template_context(
    findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    workspace_root: str,
) -> Dict[str, Any]:
    """Build context dict for the MD template (variables, findings, severity_breakdown)."""
    total_occurrences = len(findings or [])
    grouped = group_findings(findings or [])
    total_unique = len(grouped)

    severity_unique: Dict[str, int] = {}
    severity_occ: Dict[str, int] = {}
    for g in grouped:
        sev = safe_str(g.get("severity", "unknown"))
        severity_unique[sev] = severity_unique.get(sev, 0) + 1
        severity_occ[sev] = severity_occ.get(sev, 0) + int(g.get("_occurrence_count", 1))

    severity_breakdown: List[Dict[str, Any]] = []
    for sev in sorted(severity_unique.keys()):
        uniq = severity_unique[sev]
        occ = severity_occ.get(sev, 0)
        pct = (occ / total_occurrences * 100.0) if total_occurrences else 0.0
        severity_breakdown.append(
            {
                "severity": sev.title(),
                "unique": str(uniq),
                "occurrences": str(occ),
                "percent": f"{pct:.1f}",
            }
        )

    template_findings: List[Dict[str, Any]] = []
    for i, finding in enumerate(grouped, 1):
        rule_id = safe_str(finding.get("rule_id", "Unknown Rule"))
        severity = safe_str(finding.get("severity", "unknown"))
        file_path = safe_str(finding.get("file", "Unknown Path"))
        if workspace_root and workspace_root != "N/A" and file_path.startswith(workspace_root):
            file_display = os.path.relpath(file_path, workspace_root)
        elif file_path != "Unknown Path":
            file_display = os.path.basename(file_path)
        else:
            file_display = file_path
        occ_count = int(finding.get("_occurrence_count", 1))
        locations_txt = format_locations(finding.get("_locations", []), per_line=10)
        message = safe_str(finding.get("message", "No message provided"))
        remediation = safe_str(finding.get("remediation", ""))
        occs = finding.get("_occurrences", [])
        first_excerpt = safe_str(occs[0].get("excerpt", "")) if occs else safe_str(finding.get("excerpt", ""))
        first_context = safe_str(occs[0].get("context", "")) if occs else safe_str(finding.get("context", ""))
        excerpt_trunc, excerpt_was_trunc = truncate_text(first_excerpt, max_chars=2500, max_lines=50)
        if excerpt_was_trunc:
            excerpt_trunc += "\n… (truncated)"
        context_trunc, context_was_trunc = truncate_text(first_context, max_chars=2500, max_lines=50)
        if context_was_trunc:
            context_trunc += "\n… (truncated)"

        title = f"Finding #{i}: {rule_id} ({occ_count} occurrence{'s' if occ_count != 1 else ''})"
        excerpt_md = ""
        if excerpt_trunc:
            excerpt_md = "**Code Excerpt (first)**\n\n" + "<pre>" + _escape_html(excerpt_trunc) + "</pre>"
        remediation_md = ""
        if remediation:
            remediation_md = "**Remediation:** " + _escape_html(remediation)
        context_md = ""
        if context_trunc:
            context_md = "**Context (first)**\n\n" + "<pre>" + _escape_html(context_trunc) + "</pre>"

        template_findings.append(
            {
                "title": _escape_html(title),
                "rule_id": _escape_html(rule_id),
                "severity": severity.title(),
                "file_display": _escape_html(file_display),
                "occ_count": str(occ_count),
                "locations_txt": _escape_html(locations_txt),
                "message": _escape_html(message),
                "excerpt_md": excerpt_md,
                "remediation_md": remediation_md,
                "context_md": context_md,
            }
        )

    report_date = datetime.now().strftime("%B %d, %Y")
    if workspace_root and workspace_root not in ("", "N/A"):
        workspace_name = os.path.basename(workspace_root.rstrip(os.sep)) or "this project"
    else:
        workspace_name = "this project"
    return {
        "report_date": report_date,
        "workspace_root": _escape_html(workspace_root),
        "workspace_name": _escape_html(workspace_name),
        "total_unique": str(total_unique),
        "total_occurrences": str(total_occurrences),
        "findings": template_findings,
        "severity_breakdown": severity_breakdown,
        "metrics": {
            "ms": safe_str(metrics.get("ms", 0)),
            "files": safe_str(metrics.get("files", "N/A")),
        },
        "no_findings": total_unique == 0,
    }


def create_pdf_from_template(
    template_path: str,
    css_path: Optional[str],
    context: Dict[str, Any],
    output_path: str,
    plugin_dir: str,
    allow_commands: bool = False,
) -> str:
    """Render MD template + CSS to PDF via WeasyPrint."""
    if not TEMPLATE_AVAILABLE:
        raise RuntimeError("markdown and weasyprint are required for template reports")

    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()
    processed = process_template(template_content, context, allow_commands=allow_commands)
    html_body = markdown.markdown(processed, extensions=["tables", "nl2br"])
    css_resolved = css_path or os.path.join(plugin_dir, "templates", "report.css")
    css_abs = os.path.abspath(css_resolved)
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>RootCause SAST Report</title>
  <link rel="stylesheet" href="file://{css_abs}" />
</head>
<body>
{html_body}
</body>
</html>"""
    base_url = os.path.abspath(plugin_dir)
    html = HTML(string=html_doc, base_url=base_url)
    styles = [CSS(filename=css_abs)]
    html.write_pdf(output_path, stylesheets=styles)
    return output_path
