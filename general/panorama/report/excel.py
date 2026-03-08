"""Excel (.xlsx) report with 4 sheets: FRONTPAGE, SAST, SCA, LICENSES."""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from analyze.filters import severity_for_vuln


def _safe(v: Any) -> str:
    return "" if v is None else str(v)


def _sca_severity_display(sev: str) -> str:
    """Show only severity level (e.g. HIGH), stripping any leading numeric prefix like '0 '."""
    if not sev or not isinstance(sev, str):
        return _safe(sev)
    s = str(sev).strip()
    parts = s.split(None, 1)
    if len(parts) == 2 and parts[0].isdigit():
        return parts[1]
    return s


def _severity_sast(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        rid = f.get("rule_id") or ""
        if rid.startswith("deps.") or rid.startswith("infra."):
            continue
        sev = _safe(f.get("severity", "unknown")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _severity_sca(vulns: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in vulns:
        raw = v.get("severity") or severity_for_vuln(_safe(v.get("vuln_id", "")))
        sev = _sca_severity_display(raw)
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _purl(eco: str, name: str, version: str) -> str:
    eco_lower = (eco or "").lower().replace(" ", "")
    return f"pkg:{eco_lower}/{name}@{version}"


def _style_cell(cell, font: Font | None = None, fill: PatternFill | None = None, border: Border | None = None, alignment: Alignment | None = None) -> None:
    if font:
        cell.font = font
    if fill:
        cell.fill = fill
    if border:
        cell.border = border
    if alignment:
        cell.alignment = alignment


def write_excel(
    report_dir: str,
    sbom: list[dict],
    vulns: list[dict],
    opts: dict[str, Any],
    findings: list[dict] | None = None,
    images: list[dict] | None = None,
    findings_infra: list[dict] | None = None,
) -> list[tuple[str, int]]:
    """Write panorama-report.xlsx with sheets FRONTPAGE, SAST, SCA, INFRA, LICENSES. Returns [(path, size), ...]."""
    wb = Workbook()
    title = opts.get("report_title") or "RootCause Panorama Report"
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M")
    workspace_root = opts.get("workspace_root") or ""
    all_findings = findings or []
    code_findings = [f for f in all_findings if not (f.get("rule_id") or "").startswith("deps.") and not (f.get("rule_id") or "").startswith("infra.")]

    thin_border = Border(
        left=Side(style="thin"), right=Side(style="thin"),
        top=Side(style="thin"), bottom=Side(style="thin"),
    )
    header_font = Font(bold=True)
    header_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")  # blue
    header_font_white = Font(bold=True, color="FFFFFF")
    section_fill = PatternFill(start_color="D6DCE4", end_color="D6DCE4", fill_type="solid")  # light gray
    title_fill = PatternFill(start_color="2F5496", end_color="2F5496", fill_type="solid")  # dark blue
    title_font = Font(bold=True, size=16, color="FFFFFF")
    wrap_align = Alignment(wrap_text=True, vertical="top")

    # ---- FRONTPAGE (styled) ----
    ws_front = wb.active
    ws_front.title = "FRONTPAGE"
    ws_front.merge_cells("A1:B1")
    ws_front["A1"] = title
    _style_cell(ws_front["A1"], font=title_font, fill=title_fill, alignment=Alignment(horizontal="center", vertical="center", wrap_text=True))
    ws_front.row_dimensions[1].height = 36
    ws_front["A2"] = "Generated"
    ws_front["B2"] = report_date
    ws_front["A2"].font = header_font
    ws_front["A3"] = "Workspace"
    ws_front["B3"] = workspace_root
    ws_front["A3"].font = header_font
    ws_front.column_dimensions["A"].width = 28
    ws_front.column_dimensions["B"].width = 52

    # Summary section
    r = 5
    ws_front.merge_cells(start_row=r, start_column=1, end_row=r, end_column=2)
    ws_front.cell(row=r, column=1, value="Summary").font = header_font
    ws_front.cell(row=r, column=1).fill = section_fill
    ws_front.cell(row=r, column=1).border = thin_border
    ws_front.cell(row=r, column=2).fill = section_fill
    ws_front.cell(row=r, column=2).border = thin_border
    r += 1
    summary_rows = [("SAST findings (code)", len(code_findings))]
    if opts.get("dependencies") is not False:
        summary_rows.append(("SCA vulnerabilities (dependencies)", len(vulns)))
        summary_rows.append(("SBOM components", len(sbom)))
    for label, value in summary_rows:
        ws_front.cell(row=r, column=1, value=label).border = thin_border
        ws_front.cell(row=r, column=2, value=value).border = thin_border
        r += 1
    r += 1

    # SAST by severity
    ws_front.merge_cells(start_row=r, start_column=1, end_row=r, end_column=2)
    ws_front.cell(row=r, column=1, value="SAST by severity").font = header_font
    ws_front.cell(row=r, column=1).fill = section_fill
    ws_front.cell(row=r, column=1).border = thin_border
    ws_front.cell(row=r, column=2).fill = section_fill
    ws_front.cell(row=r, column=2).border = thin_border
    r += 1
    ws_front.cell(row=r, column=1, value="Severity").font = header_font_white
    ws_front.cell(row=r, column=1).fill = header_fill
    ws_front.cell(row=r, column=1).border = thin_border
    ws_front.cell(row=r, column=2, value="Count").font = header_font_white
    ws_front.cell(row=r, column=2).fill = header_fill
    ws_front.cell(row=r, column=2).border = thin_border
    r += 1
    sast_sev = _severity_sast(all_findings)
    for sev, count in sorted(sast_sev.items()):
        ws_front.cell(row=r, column=1, value=sev).border = thin_border
        ws_front.cell(row=r, column=2, value=count).border = thin_border
        r += 1
    r += 1

    if opts.get("dependencies") is not False:
        # SCA by severity
        ws_front.merge_cells(start_row=r, start_column=1, end_row=r, end_column=2)
        ws_front.cell(row=r, column=1, value="SCA by severity").font = header_font
        ws_front.cell(row=r, column=1).fill = section_fill
        ws_front.cell(row=r, column=1).border = thin_border
        ws_front.cell(row=r, column=2).fill = section_fill
        ws_front.cell(row=r, column=2).border = thin_border
        r += 1
        ws_front.cell(row=r, column=1, value="Severity").font = header_font_white
        ws_front.cell(row=r, column=1).fill = header_fill
        ws_front.cell(row=r, column=1).border = thin_border
        ws_front.cell(row=r, column=2, value="Count").font = header_font_white
        ws_front.cell(row=r, column=2).fill = header_fill
        ws_front.cell(row=r, column=2).border = thin_border
        r += 1
        sca_sev = _severity_sca(vulns)
        for sev, count in sorted(sca_sev.items()):
            ws_front.cell(row=r, column=1, value=sev).border = thin_border
            ws_front.cell(row=r, column=2, value=count).border = thin_border
            r += 1
        r += 1

    # ---- SAST: IDs | File/Location | Severity | Description | Extra ----
    ws_sast = wb.create_sheet("SAST", 1)
    sast_headers = [
        "Finding ID", "Rule ID", "File", "Line", "Column", "Severity", "Message", "Excerpt", "Remediation", "Context",
    ]
    for col, h in enumerate(sast_headers, start=1):
        cell = ws_sast.cell(row=1, column=col, value=h)
        cell.font = header_font_white
        cell.fill = header_fill
        cell.border = thin_border
        cell.alignment = wrap_align
    ws_sast.column_dimensions["A"].width = 12
    ws_sast.column_dimensions["B"].width = 22
    ws_sast.column_dimensions["C"].width = 38
    ws_sast.column_dimensions["D"].width = 8
    ws_sast.column_dimensions["E"].width = 8
    ws_sast.column_dimensions["F"].width = 10
    ws_sast.column_dimensions["G"].width = 42
    ws_sast.column_dimensions["H"].width = 32
    ws_sast.column_dimensions["I"].width = 32
    ws_sast.column_dimensions["J"].width = 28

    for row, f in enumerate(code_findings, start=2):
        ws_sast.cell(row=row, column=1, value=_safe(f.get("id")))
        ws_sast.cell(row=row, column=2, value=_safe(f.get("rule_id")))
        ws_sast.cell(row=row, column=3, value=_safe(f.get("file") or f.get("path")))
        ws_sast.cell(row=row, column=4, value=f.get("line"))
        ws_sast.cell(row=row, column=5, value=f.get("column"))
        ws_sast.cell(row=row, column=6, value=_safe(f.get("severity")))
        ws_sast.cell(row=row, column=7, value=_safe(f.get("message")))
        ws_sast.cell(row=row, column=8, value=_safe(f.get("excerpt")))
        ws_sast.cell(row=row, column=9, value=_safe(f.get("remediation")))
        ws_sast.cell(row=row, column=10, value=_safe(f.get("context")))
        for c in range(1, 11):
            ws_sast.cell(row=row, column=c).alignment = wrap_align

    sheet_idx = 2
    if opts.get("dependencies") is not False:
        # ---- SCA: IDs | Package/Location | Severity | Description | Extra ----
        ws_sca = wb.create_sheet("SCA", sheet_idx)
        sheet_idx += 1
        sca_headers = [
            "Vuln ID", "Package", "Version", "Ecosystem", "File", "Line", "Severity", "Description", "Fixed In", "Published", "Modified", "References",
        ]
        for col, h in enumerate(sca_headers, start=1):
            cell = ws_sca.cell(row=1, column=col, value=h)
            cell.font = header_font_white
            cell.fill = header_fill
            cell.border = thin_border
            cell.alignment = wrap_align
        for row, v in enumerate(vulns, start=2):
            sev = _sca_severity_display(
                v.get("severity") or severity_for_vuln(_safe(v.get("vuln_id", "")))
            )
            ws_sca.cell(row=row, column=1, value=_safe(v.get("vuln_id")))
            ws_sca.cell(row=row, column=2, value=_safe(v.get("name")))
            ws_sca.cell(row=row, column=3, value=_safe(v.get("version")))
            ws_sca.cell(row=row, column=4, value=_safe(v.get("ecosystem")))
            ws_sca.cell(row=row, column=5, value=_safe(v.get("file")))
            ws_sca.cell(row=row, column=6, value=v.get("line"))
            ws_sca.cell(row=row, column=7, value=sev)
            ws_sca.cell(row=row, column=8, value=_safe(v.get("description")))
            ws_sca.cell(row=row, column=9, value=_safe(v.get("fixed_in")))
            ws_sca.cell(row=row, column=10, value=_safe(v.get("published")))
            ws_sca.cell(row=row, column=11, value=_safe(v.get("modified")))
            ws_sca.cell(row=row, column=12, value=_safe(v.get("references")))
            for c in range(1, 13):
                ws_sca.cell(row=row, column=c).alignment = wrap_align
        ws_sca.column_dimensions["A"].width = 22
        ws_sca.column_dimensions["B"].width = 10
        ws_sca.column_dimensions["C"].width = 24
        ws_sca.column_dimensions["D"].width = 14
        ws_sca.column_dimensions["E"].width = 12
        ws_sca.column_dimensions["F"].width = 32
        ws_sca.column_dimensions["G"].width = 8
        ws_sca.column_dimensions["H"].width = 48
        ws_sca.column_dimensions["I"].width = 14
        ws_sca.column_dimensions["J"].width = 12
        ws_sca.column_dimensions["K"].width = 12
        ws_sca.column_dimensions["L"].width = 28

    if opts.get("infra") is not False:
        # ---- INFRA: images + findings ----
        images = images or []
        findings_infra = findings_infra or []
        ws_infra = wb.create_sheet("INFRA", sheet_idx)
        sheet_idx += 1
        inf_headers_img = ["File", "Line", "Image", "Source"]
        for col, h in enumerate(inf_headers_img, start=1):
            cell = ws_infra.cell(row=1, column=col, value=h)
            cell.font = header_font_white
            cell.fill = header_fill
            cell.border = thin_border
            cell.alignment = wrap_align
        if images:
            for row, im in enumerate(images, start=2):
                ws_infra.cell(row=row, column=1, value=_safe(im.get("file")))
                ws_infra.cell(row=row, column=2, value=im.get("line"))
                ws_infra.cell(row=row, column=3, value=_safe(im.get("image_ref") or im.get("image")))
                ws_infra.cell(row=row, column=4, value=_safe(im.get("source")))
                for c in range(1, 5):
                    ws_infra.cell(row=row, column=c).alignment = wrap_align
        else:
            ws_infra.cell(row=2, column=1, value="No images")
            ws_infra.cell(row=2, column=1).alignment = wrap_align
        r_infra = 2 + max(len(images), 1)
        inf_headers_fin = ["Rule ID", "Severity", "File", "Line", "Message"]
        for col, h in enumerate(inf_headers_fin, start=1):
            cell = ws_infra.cell(row=r_infra, column=col, value=h)
            cell.font = header_font_white
            cell.fill = header_fill
            cell.border = thin_border
            cell.alignment = wrap_align
        r_infra += 1
        if findings_infra:
            for f in findings_infra:
                ws_infra.cell(row=r_infra, column=1, value=_safe(f.get("rule_id")))
                ws_infra.cell(row=r_infra, column=2, value=_safe(f.get("severity")))
                ws_infra.cell(row=r_infra, column=3, value=_safe(f.get("file")))
                ws_infra.cell(row=r_infra, column=4, value=f.get("line"))
                ws_infra.cell(row=r_infra, column=5, value=_safe(f.get("message")))
                for c in range(1, 6):
                    ws_infra.cell(row=r_infra, column=c).alignment = wrap_align
                r_infra += 1
        else:
            ws_infra.cell(row=r_infra, column=1, value="No findings")
            ws_infra.cell(row=r_infra, column=1).alignment = wrap_align
        ws_infra.column_dimensions["A"].width = 32
        ws_infra.column_dimensions["B"].width = 10
        ws_infra.column_dimensions["C"].width = 24
        ws_infra.column_dimensions["D"].width = 38
        ws_infra.column_dimensions["E"].width = 48

    if opts.get("licenses") is not False:
        # ---- LICENSES: PURL | Component | Version | Ecosystem | Line | Type | License (no File/Notes) ----
        ws_lic = wb.create_sheet("LICENSES", sheet_idx)
        lic_headers = [
            "PURL", "Component Name", "Version", "Ecosystem", "Line", "Type", "License",
        ]
        for col, h in enumerate(lic_headers, start=1):
            cell = ws_lic.cell(row=1, column=col, value=h)
            cell.font = header_font_white
            cell.fill = header_fill
            cell.border = thin_border
            cell.alignment = wrap_align
        for row, c in enumerate(sbom, start=2):
            name = _safe(c.get("name"))
            version = _safe(c.get("version"))
            eco = _safe(c.get("ecosystem"))
            ws_lic.cell(row=row, column=1, value=_purl(eco, name, version))
            ws_lic.cell(row=row, column=2, value=name)
            ws_lic.cell(row=row, column=3, value=version)
            ws_lic.cell(row=row, column=4, value=eco)
            ws_lic.cell(row=row, column=5, value=c.get("line"))
            ws_lic.cell(row=row, column=6, value=_safe(c.get("type")) or "library")
            ws_lic.cell(row=row, column=7, value=_safe(c.get("license")) or "N/A")
            for col in range(1, 8):
                ws_lic.cell(row=row, column=col).alignment = wrap_align
        ws_lic.column_dimensions["A"].width = 48
        ws_lic.column_dimensions["B"].width = 28
        ws_lic.column_dimensions["C"].width = 14
        ws_lic.column_dimensions["D"].width = 12
        ws_lic.column_dimensions["E"].width = 8
        ws_lic.column_dimensions["F"].width = 10
        ws_lic.column_dimensions["G"].width = 14

    path = os.path.join(report_dir, "panorama-report.xlsx")
    wb.save(path)
    return [(path, os.path.getsize(path))]
