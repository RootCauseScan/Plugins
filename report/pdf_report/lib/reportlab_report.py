"""ReportLab-based PDF report (fallback when template/WeasyPrint not used)."""
import os
from datetime import datetime
from typing import Any, Dict, List

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT
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
from xml.sax.saxutils import escape

from .findings import format_locations, group_findings, safe_str, truncate_text


def _para(text: Any, style: ParagraphStyle, preserve_newlines: bool = False) -> Paragraph:
    """Create a wrapping Paragraph (prevents table overflow)."""
    s = safe_str(text)
    s = escape(s)
    if preserve_newlines:
        s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br/>")
    return Paragraph(s, style)


def create_pdf_report(
    findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    output_path: str,
    workspace_root: str = "",
    plugin_dir: str = "",
) -> str:
    """Create a professional PDF report from SAST findings (ReportLab)."""
    styles = getSampleStyleSheet()
    brand_gold = HexColor("#FFD700")
    brand_text = HexColor("#151517")
    brand_text_secondary = HexColor("#53535A")
    brand_surface = HexColor("#F6F7F9")
    brand_border = HexColor("#E5E7EB")

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=28,
        spaceAfter=26,
        alignment=TA_CENTER,
        textColor=brand_text,
    )
    section_title_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=18,
        spaceAfter=14,
        textColor=brand_text_secondary,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "CustomBody",
        parent=styles["Normal"],
        fontSize=10,
        spaceAfter=10,
        textColor=brand_text,
    )
    brand_style = ParagraphStyle(
        "BrandStyle",
        parent=styles["Normal"],
        fontSize=12,
        spaceAfter=10,
        textColor=brand_gold,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=section_title_style,
        fontSize=16,
        spaceAfter=10,
        textColor=brand_text_secondary,
        keepWithNext=True,
    )
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
    workspace_root = safe_str(workspace_root or "N/A")
    total_occurrences = len(findings or [])
    grouped = group_findings(findings or [])
    total_unique = len(grouped)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=52,
    )

    def _draw_cover_footer(canvas, doc_):
        canvas.saveState()
        canvas.restoreState()

    def _draw_page_chrome(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(brand_text_secondary)
        canvas.drawString(doc_.leftMargin, A4[1] - 50, "RootCause SAST Report")
        y = 40
        canvas.setStrokeColor(brand_border)
        canvas.setLineWidth(1)
        canvas.line(doc_.leftMargin, y + 12, A4[0] - doc_.rightMargin, y + 12)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(brand_text_secondary)
        canvas.drawString(doc_.leftMargin, y, f"Generated on {report_date}")
        canvas.drawRightString(A4[0] - doc_.rightMargin, y, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    story: List[Any] = []
    logo_path = os.path.join(plugin_dir, "assets", "logo.png") if plugin_dir else ""
    if plugin_dir and os.path.exists(logo_path):
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
    story.append(
        Paragraph(
            f"<b>Unique issues:</b> {total_unique} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Total occurrences:</b> {total_occurrences}",
            body_style,
        )
    )
    story.append(PageBreak())

    story.append(Paragraph("Executive Summary", section_title_style))
    story.append(
        Paragraph(
            f"This security analysis identified <b>{total_unique}</b> unique security issue(s), "
            f"representing <b>{total_occurrences}</b> total occurrence(s) across the codebase.",
            body_style,
        )
    )

    severity_unique: Dict[str, int] = {}
    severity_occ: Dict[str, int] = {}
    for g in grouped:
        sev = safe_str(g.get("severity", "unknown"))
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

    if metrics:
        story.append(Spacer(1, 14))
        story.append(Paragraph("Analysis Metrics", section_title_style))
        metrics_text = (
            f"<b>Analysis Time:</b> {escape(safe_str(metrics.get('ms', 0)))}ms<br/>"
            f"<b>Files Analyzed:</b> {escape(safe_str(metrics.get('files', 'N/A')))}<br/>"
        )
        story.append(Paragraph(metrics_text, body_style))

    story.append(PageBreak())
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
            rule_id = safe_str(finding.get("rule_id", "Unknown Rule"))
            severity = safe_str(finding.get("severity", "unknown"))
            file_path = safe_str(finding.get("file", "Unknown Path"))
            if workspace_root and workspace_root != "N/A" and file_path.startswith(workspace_root):
                file_path_display = os.path.relpath(file_path, workspace_root)
            elif file_path != "Unknown Path":
                file_path_display = os.path.basename(file_path)
            else:
                file_path_display = file_path
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
            block = KeepTogether(
                [
                    Paragraph(escape(finding_title), finding_title_style),
                    Spacer(1, 6),
                    details_table,
                    Spacer(1, 10),
                ]
            )
            story.append(block)
            if i < len(grouped):
                story.append(PageBreak())

    doc.build(story, onFirstPage=_draw_cover_footer, onLaterPages=_draw_page_chrome)
    return output_path
