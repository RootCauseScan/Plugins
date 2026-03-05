#!/usr/bin/env python3
"""Generate professional PDF reports from SAST findings.

This plugin implements the report capability for RootCause.
"""
import base64
import json
import os
import signal
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Tuple
from xml.sax.saxutils import escape

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def send(msg_id, result=None, error=None):
    """Send a JSON-RPC message to stdout."""
    payload = {"jsonrpc": "2.0", "id": msg_id}
    if error is None:
        payload["result"] = result
    else:
        payload["error"] = error
    try:
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        sys.exit(0)


def log(level, message):
    """Send a log message to RootCause."""
    payload = {
        "jsonrpc": "2.0",
        "method": "plugin.log",
        "params": {"level": level, "message": message},
    }
    try:
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        sys.exit(0)


def handle_init(params):
    """Handle plugin initialization."""
    opts.update(params.get("options") or {})
    opts["workspace_root"] = params.get("workspace_root", "")
    return {"ok": True, "capabilities": ["report"], "plugin_version": "1.0.0"}


def _safe_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v)


def _para(text: Any, style: ParagraphStyle, preserve_newlines: bool = False) -> Paragraph:
    """Create a wrapping Paragraph (prevents table overflow)."""
    s = _safe_str(text)
    s = escape(s)
    if preserve_newlines:
        s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br/>")
    return Paragraph(s, style)


def _truncate_text(s: str, max_chars: int = 2500, max_lines: int = 50) -> Tuple[str, bool]:
    """Avoid giant cells that can blow up layout; keep report readable."""
    if not s:
        return s, False
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


def group_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group findings when the same file has the same vulnerability in different lines.

    Group key: (rule_id, severity, file, message)
    This avoids merging different messages under the same rule/file.
    """
    grouped: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    for f in findings or []:
        rule_id = _safe_str(f.get("rule_id", "Unknown Rule"))
        severity = _safe_str(f.get("severity", "unknown"))
        file_path = _safe_str(f.get("file", "Unknown Path"))
        message = _safe_str(f.get("message", ""))

        key = (rule_id, severity, file_path, message)

        occ = {
            "line": f.get("line", "N/A"),
            "column": f.get("column", "N/A"),
            "excerpt": f.get("excerpt", ""),
            "context": f.get("context", ""),
        }

        if key not in grouped:
            base = dict(f)
            base["rule_id"] = rule_id
            base["severity"] = severity
            base["file"] = file_path
            base["message"] = message
            base["_occurrences"] = [occ]
            grouped[key] = base
        else:
            grouped[key]["_occurrences"].append(occ)

    # Normalize: unique+sorted locations
    out: List[Dict[str, Any]] = []
    for g in grouped.values():
        occs = g.get("_occurrences", [])

        def _num(x):
            try:
                return int(x)
            except Exception:
                return 10**9

        occs_sorted = sorted(occs, key=lambda o: (_num(o.get("line")), _num(o.get("column"))))
        g["_occurrences"] = occs_sorted

        locs = [f"{o.get('line','N/A')}:{o.get('column','N/A')}" for o in occs_sorted]

        seen = set()
        uniq_locs = []
        for x in locs:
            if x not in seen:
                seen.add(x)
                uniq_locs.append(x)

        g["_locations"] = uniq_locs
        g["_occurrence_count"] = len(occs_sorted)

        out.append(g)

    # Stable output: by severity then rule_id then file
    out.sort(
        key=lambda x: (
            _safe_str(x.get("severity", "")),
            _safe_str(x.get("rule_id", "")),
            _safe_str(x.get("file", "")),
        )
    )
    return out


def _format_locations(locations: List[str], per_line: int = 10) -> str:
    if not locations:
        return "N/A"
    parts = []
    for i in range(0, len(locations), per_line):
        parts.append(", ".join(locations[i : i + per_line]))
    return "\n".join(parts)


def create_pdf_report(findings: List[Dict[str, Any]], metrics: Dict[str, Any], output_path: str) -> str:
    """Create a professional PDF report from SAST findings."""
    styles = getSampleStyleSheet()

    # Brand colors
    brand_gold = HexColor("#FFD700")
    brand_text = HexColor("#151517")
    brand_text_secondary = HexColor("#53535A")
    brand_surface = HexColor("#F6F7F9")
    brand_border = HexColor("#E5E7EB")

    # Title style
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=28,
        spaceAfter=26,
        alignment=TA_CENTER,
        textColor=brand_text,
    )

    # Subtitle styles
    section_title_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=18,
        spaceAfter=14,
        textColor=brand_text_secondary,
        keepWithNext=True,  # keep headers with the next block
    )

    # Body style
    body_style = ParagraphStyle(
        "CustomBody",
        parent=styles["Normal"],
        fontSize=10,
        spaceAfter=10,
        textColor=brand_text,
    )

    # Brand accent style
    brand_style = ParagraphStyle(
        "BrandStyle",
        parent=styles["Normal"],
        fontSize=12,
        spaceAfter=10,
        textColor=brand_gold,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )

    # Finding title (kept with next)
    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=section_title_style,
        fontSize=16,
        spaceAfter=10,
        textColor=brand_text_secondary,
        keepWithNext=True,
    )

    # Table paragraph styles (fix overflow by forcing wrapping)
    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        textColor=brand_text,
        alignment=TA_LEFT,
        leading=12,
        wordWrap="CJK",
        splitLongWords=True,
    )
    table_key_style = ParagraphStyle(
        "TableKey",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=brand_text,
        alignment=TA_LEFT,
        leading=11,
        wordWrap="CJK",
        splitLongWords=True,
    )
    table_val_style = ParagraphStyle(
        "TableVal",
        parent=styles["Normal"],
        fontSize=9,
        textColor=brand_text,
        alignment=TA_LEFT,
        leading=11,
        wordWrap="CJK",
        splitLongWords=True,
    )
    table_code_style = ParagraphStyle(
        "TableCode",
        parent=styles["Code"],
        fontSize=8.5,
        textColor=brand_text,
        backColor=brand_surface,
        leading=10,
        wordWrap="CJK",
        splitLongWords=True,
    )

    report_date = datetime.now().strftime("%B %d, %Y")
    workspace_root = _safe_str(opts.get("workspace_root", "N/A"))

    # Group findings (same file + same vuln across lines)
    total_occurrences = len(findings or [])
    grouped = group_findings(findings or [])
    total_unique = len(grouped)

    # Document configuration
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=52,
    )

    def _draw_cover_footer(canvas, doc_):
        """Cover page footer (minimal or none)."""
        # Intentionally left minimal to keep the cover clean.
        canvas.saveState()
        canvas.restoreState()

    def _draw_page_chrome(canvas, doc_):
        """Header + footer for all non-cover pages."""
        canvas.saveState()

        # Header
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(brand_text_secondary)
        canvas.drawString(doc_.leftMargin, A4[1] - 50, "RootCause SAST Report")

        # Footer separator line
        y = 40
        canvas.setStrokeColor(brand_border)
        canvas.setLineWidth(1)
        canvas.line(doc_.leftMargin, y + 12, A4[0] - doc_.rightMargin, y + 12)

        # Footer text
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(brand_text_secondary)
        canvas.drawString(doc_.leftMargin, y, f"Generated on {report_date}")
        canvas.drawRightString(
            A4[0] - doc_.rightMargin,
            y,
            f"Page {canvas.getPageNumber()}",
        )

        canvas.restoreState()

    story: List[Any] = []

    # -------------------------
    # Cover page (single page)
    # -------------------------
    logo_path = os.path.join(os.path.dirname(__file__), "assets/logo.png")
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=120, height=120)
        logo.hAlign = "CENTER"
        story.append(logo)
        story.append(Spacer(1, 22))

    story.append(Paragraph("RootCause SAST Report", title_style))
    story.append(Paragraph("Static Application Security Testing", brand_style))
    story.append(Spacer(1, 28))

    story.append(Paragraph(f"<b>Generated on:</b> {escape(report_date)}", body_style))
    story.append(Paragraph(f"<b>Workspace:</b> {escape(workspace_root)}", body_style))
    story.append(Spacer(1, 16))

    # Small cover summary (kept short to ensure cover remains a single page)
    story.append(
        Paragraph(
            f"<b>Unique issues:</b> {total_unique} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Total occurrences:</b> {total_occurrences}",
            body_style,
        )
    )

    story.append(PageBreak())

    # -------------------------
    # Executive Summary (single page)
    # -------------------------
    story.append(Paragraph("Executive Summary", section_title_style))

    story.append(
        Paragraph(
            (
                f"This security analysis identified <b>{total_unique}</b> unique security issue(s), "
                f"representing <b>{total_occurrences}</b> total occurrence(s) across the codebase."
            ),
            body_style,
        )
    )

    # Severity breakdown (unique + occurrences)
    severity_unique: Dict[str, int] = {}
    severity_occ: Dict[str, int] = {}
    for g in grouped:
        sev = _safe_str(g.get("severity", "unknown"))
        severity_unique[sev] = severity_unique.get(sev, 0) + 1
        severity_occ[sev] = severity_occ.get(sev, 0) + int(g.get("_occurrence_count", 1))

    if severity_unique:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Severity Breakdown", section_title_style))

        severity_data = [
            [
                _para("Severity", table_header_style),
                _para("Unique Issues", table_header_style),
                _para("Occurrences", table_header_style),
                _para("% of Occurrences", table_header_style),
            ]
        ]
        for sev in sorted(severity_unique.keys()):
            uniq = severity_unique[sev]
            occ = severity_occ.get(sev, 0)
            pct = (occ / total_occurrences * 100.0) if total_occurrences else 0.0
            severity_data.append(
                [
                    _para(sev.title(), table_val_style),
                    _para(str(uniq), table_val_style),
                    _para(str(occ), table_val_style),
                    _para(f"{pct:.1f}%", table_val_style),
                ]
            )

        severity_table = Table(
            severity_data,
            colWidths=[1.2 * inch, 1.2 * inch, 1.2 * inch, 1.6 * inch],
            repeatRows=1,
        )
        severity_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), brand_gold),
                    ("TEXTCOLOR", (0, 0), (-1, 0), brand_text),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                    ("BACKGROUND", (0, 1), (-1, -1), brand_surface),
                    ("GRID", (0, 0), (-1, -1), 1, brand_border),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                ]
            )
        )
        story.append(severity_table)

    # Metrics on summary page
    if metrics:
        story.append(Spacer(1, 14))
        story.append(Paragraph("Analysis Metrics", section_title_style))
        metrics_text = (
            f"<b>Analysis Time:</b> {escape(_safe_str(metrics.get('ms', 0)))}ms<br/>"
            f"<b>Files Analyzed:</b> {escape(_safe_str(metrics.get('files', 'N/A')))}<br/>"
        )
        story.append(Paragraph(metrics_text, body_style))

    story.append(PageBreak())

    # -------------------------
    # Detailed Findings (new page)
    # -------------------------
    story.append(Paragraph("Detailed Findings", section_title_style))
    story.append(
        Paragraph(
            "Findings are grouped when the same file contains the same vulnerability across multiple line locations.",
            body_style,
        )
    )
    story.append(Spacer(1, 6))

    if not grouped:
        story.append(Paragraph("No security issues were found during the analysis.", body_style))
    else:
        for i, finding in enumerate(grouped, 1):
            rule_id = _safe_str(finding.get("rule_id", "Unknown Rule"))
            severity = _safe_str(finding.get("severity", "unknown"))
            file_path = _safe_str(finding.get("file", "Unknown Path"))

            # Make path relative to workspace root if possible
            if workspace_root and workspace_root != "N/A" and file_path.startswith(workspace_root):
                file_path_display = os.path.relpath(file_path, workspace_root)
            elif file_path != "Unknown Path":
                file_path_display = os.path.basename(file_path)
            else:
                file_path_display = file_path

            occ_count = int(finding.get("_occurrence_count", 1))
            locations = finding.get("_locations", [])
            locations_txt = _format_locations(locations, per_line=10)

            message = _safe_str(finding.get("message", "No message provided"))
            remediation = _safe_str(finding.get("remediation", ""))

            occs = finding.get("_occurrences", [])
            first_excerpt = _safe_str(occs[0].get("excerpt", "")) if occs else _safe_str(finding.get("excerpt", ""))
            first_context = _safe_str(occs[0].get("context", "")) if occs else _safe_str(finding.get("context", ""))

            excerpt_trunc, excerpt_was_trunc = _truncate_text(first_excerpt, max_chars=2500, max_lines=50)
            if excerpt_was_trunc:
                excerpt_trunc += "\n… (truncated)"

            context_trunc, context_was_trunc = _truncate_text(first_context, max_chars=2500, max_lines=50)
            if context_was_trunc:
                context_trunc += "\n… (truncated)"

            finding_title = f"Finding #{i}: {rule_id} ({occ_count} occurrence{'s' if occ_count != 1 else ''})"

            details_data = [
                [_para("Property", table_header_style), _para("Value", table_header_style)],
                [_para("Rule ID", table_key_style), _para(rule_id, table_val_style)],
                [_para("Severity", table_key_style), _para(severity.title(), table_val_style)],
                [_para("File Path", table_key_style), _para(file_path_display, table_val_style)],
                [_para("Occurrences", table_key_style), _para(str(occ_count), table_val_style)],
                [
                    _para("Locations (line:col)", table_key_style),
                    _para(locations_txt, table_val_style, preserve_newlines=True),
                ],
                [_para("Message", table_key_style), _para(message, table_val_style)],
            ]

            if excerpt_trunc:
                details_data.append(
                    [
                        _para("Code Excerpt (first)", table_key_style),
                        _para(excerpt_trunc, table_code_style, preserve_newlines=True),
                    ]
                )
            if remediation:
                details_data.append([_para("Remediation", table_key_style), _para(remediation, table_val_style)])
            if context_trunc:
                details_data.append(
                    [
                        _para("Context (first)", table_key_style),
                        _para(context_trunc, table_code_style, preserve_newlines=True),
                    ]
                )

            details_table = Table(details_data, colWidths=[1.7 * inch, 3.8 * inch], repeatRows=1)
            details_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), brand_gold),
                        ("TEXTCOLOR", (0, 0), (-1, 0), brand_text),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                        ("BACKGROUND", (0, 1), (-1, -1), brand_surface),
                        ("GRID", (0, 0), (-1, -1), 1, brand_border),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )

            # Keep the title + table together when possible.
            # If the table is too large, ReportLab will still split it across pages.
            block = KeepTogether(
                [
                    Paragraph(escape(finding_title), finding_title_style),
                    Spacer(1, 6),
                    details_table,
                    Spacer(1, 10),
                ]
            )
            story.append(block)

            # Professional pagination:
            # Each finding starts on a fresh page (except the last one).
            if i < len(grouped):
                story.append(PageBreak())

    # Build PDF with different chrome for cover vs later pages
    doc.build(story, onFirstPage=_draw_cover_footer, onLaterPages=_draw_page_chrome)
    return output_path


def handle_report(params):
    """Handle report generation request."""
    t0 = time.time()
    try:
        findings = params.get("findings", []) or []
        metrics = params.get("metrics", {}) or {}

        log("info", f"Generating PDF report for {len(findings)} finding occurrence(s)")

        output_filename = opts.get("output", "report.pdf")

        # Prefer host-provided CWD as base directory; fallback to current process CWD
        base_dir = opts.get("cwd") or os.getcwd()
        if not os.path.exists(base_dir):
            base_dir = os.getcwd()
        output_path = os.path.join(base_dir, output_filename)
        log("info", f"Output path: {output_path}")

        pdf_path = create_pdf_report(findings, metrics, output_path)

        with open(pdf_path, "rb") as f:
            pdf_content = f.read()

        pdf_b64 = base64.b64encode(pdf_content).decode("utf-8")
        elapsed_ms = int((time.time() - t0) * 1000)

        log("info", f"PDF report generated: {pdf_path}")

        return {
            "report_path": pdf_path,
            "report_content_b64": pdf_b64,
            "report_type": "application/pdf",
            "metrics": {
                "findings_processed": len(findings),
                "unique_findings": len(group_findings(findings)),
                "pdf_size_bytes": len(pdf_content),
                "ms": elapsed_ms,
            },
        }
    except Exception as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        log("error", f"Failed to generate PDF report: {str(e)}")
        return {"error": f"Failed to generate PDF report: {str(e)}", "metrics": {"ms": elapsed_ms}}


def signal_handler(signum, frame):
    """Handle signals for graceful termination."""
    sys.exit(0)


# Configure signal handlers
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

opts = {"workspace_root": "", "output": "report.pdf"}

try:
    for line in sys.stdin:
        msg = json.loads(line)
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})

        if method == "plugin.init":
            send(mid, handle_init(params))
        elif method == "scan.report":
            send(mid, handle_report(params))
        elif method == "plugin.ping":
            send(mid, {"pong": True})
        elif method == "plugin.shutdown":
            send(mid, {"ok": True})
            break
        else:
            send(mid, None, {"code": -32601, "message": "Method not found"})
except (BrokenPipeError, KeyboardInterrupt, OSError):
    sys.exit(0)
