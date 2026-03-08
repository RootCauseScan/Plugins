"""Build PDF report from sections. All pages numbered."""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate

from . import sections
from .styles import build_styles


def create_pdf(
    output_path: str,
    sbom: list[dict[str, Any]],
    vulns: list[dict[str, Any]],
    opts: dict[str, Any],
    findings: list[dict[str, Any]] | None = None,
    images: list[dict[str, Any]] | None = None,
    findings_infra: list[dict[str, Any]] | None = None,
) -> str:
    all_findings = findings or []
    code_findings = [f for f in all_findings if not (f.get("rule_id") or "").startswith("deps.") and not (f.get("rule_id") or "").startswith("infra.")]
    severity_counts = {}
    for v in vulns:
        from .styles import severity_for_vuln_id
        sev = v.get("severity") or severity_for_vuln_id(v.get("vuln_id", ""))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    ecosystem_sbom = {}
    for c in sbom:
        eco = (c.get("ecosystem") or "Other") if c.get("ecosystem") is not None else "Other"
        ecosystem_sbom[eco] = ecosystem_sbom.get(eco, 0) + 1
    report_date = datetime.now().strftime("%B %d, %Y")
    title = opts.get("report_title") or "RootCause Dependencies Report"
    styles = build_styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=52,
    )

    def draw_page_chrome(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(styles["text_secondary"])
        canvas.drawString(doc_.leftMargin, A4[1] - 50, title)
        y = 40
        canvas.setStrokeColor(styles["border"])
        canvas.setLineWidth(1)
        canvas.line(doc_.leftMargin, y + 12, A4[0] - doc_.rightMargin, y + 12)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(styles["text_secondary"])
        canvas.drawString(doc_.leftMargin, y, f"Generated on {report_date}")
        canvas.drawRightString(A4[0] - doc_.rightMargin, y, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    ctx = {
        "opts": opts,
        "code_findings": code_findings,
        "vulns": vulns,
        "sbom": sbom,
        "severity_counts": severity_counts,
        "ecosystem_sbom": ecosystem_sbom,
        "report_date": report_date,
        "title": title,
        "workspace_root": opts.get("workspace_root") or "",
        "styles": styles,
        "images": images or [],
        "findings_infra": findings_infra or [],
    }
    story = []
    sections.add_cover(story, ctx)
    sections.add_intro(story, ctx)
    sections.add_code_vulns(story, ctx)
    if opts.get("dependencies") is not False:
        sections.add_dependency_vulns(story, ctx)
    if opts.get("infra") is not False:
        sections.add_infra(story, ctx)
    if opts.get("licenses") is not False:
        sections.add_licenses(story, ctx)
    doc.build(story, onFirstPage=draw_page_chrome, onLaterPages=draw_page_chrome)
    return output_path


def write_pdf(
    report_dir: str,
    sbom: list[dict],
    vulns: list[dict],
    opts: dict[str, Any],
    findings: list[dict] | None = None,
    images: list[dict] | None = None,
    findings_infra: list[dict] | None = None,
) -> list[tuple[str, int]]:
    path = os.path.join(report_dir, "panorama-report.pdf")
    create_pdf(path, sbom, vulns, opts, findings=findings or [], images=images or [], findings_infra=findings_infra or [])
    return [(path, os.path.getsize(path))]
