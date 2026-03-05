"""PDF sections: cover, intro, code vulns, dependency vulns, SBOM."""
from __future__ import annotations

import os
from xml.sax.saxutils import escape

from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from reportlab.lib.colors import HexColor
from reportlab.lib.units import inch
from reportlab.platypus import Image, KeepTogether, PageBreak, Paragraph, Spacer, Table, TableStyle

from . import styles as S


def add_cover(story, ctx):
    opts, code_findings, vulns, sbom = ctx["opts"], ctx["code_findings"], ctx["vulns"], ctx["sbom"]
    sty = ctx["styles"]
    title = ctx["title"]
    report_date = ctx["report_date"]
    plugin_root = S.plugin_root()
    plugins_root = os.path.dirname(os.path.dirname(plugin_root))
    logo_path = os.path.join(plugin_root, "assets", "logo.png")
    if not os.path.exists(logo_path):
        logo_path = os.path.join(plugins_root, "report", "pdf_report", "assets", "logo.png")
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=120, height=120)
        logo.hAlign = "CENTER"
        story.append(logo)
        story.append(Spacer(1, 22))
    story.append(Paragraph(title, sty["title"]))
    story.append(Paragraph("SBOM · Vulnerabilities · Licenses", sty["brand"]))
    story.append(Spacer(1, 24))
    story.append(Paragraph(f"<b>Generated on:</b> {escape(report_date)}", sty["body"]))
    story.append(Paragraph(f"<b>Code findings (SAST):</b> {len(code_findings)}", sty["body"]))
    story.append(Paragraph(f"<b>Vulnerabilities in dependencies (OSV):</b> {len(vulns)}", sty["body"]))
    story.append(Paragraph(f"<b>Components (SBOM):</b> {len(sbom)}", sty["body"]))
    story.append(PageBreak())


def add_intro(story, ctx):
    sty = ctx["styles"]
    story.append(Paragraph("Introduction", sty["section"]))
    story.append(
        Paragraph(
            "This report presents the results of a combined security and dependency analysis. "
            "It is structured in three parts: first, vulnerabilities identified in the application code by static analysis; "
            "second, known vulnerabilities in third-party dependencies; and third, the full list of dependencies and their metadata. "
            "Use this document to prioritise remediation and to maintain an accurate software bill of materials (SBOM).",
            sty["body"],
        )
    )
    story.append(Spacer(1, 16))
    story.append(PageBreak())


def add_code_vulns(story, ctx):
    code_findings = ctx["code_findings"]
    workspace_root = ctx.get("workspace_root") or ""
    sty = ctx["styles"]
    grouped = S.group_findings(code_findings) if code_findings else []
    story.append(Paragraph("1. Code Vulnerabilities", sty["section"]))
    story.append(
        Paragraph(
            "This section lists issues found in the application source code by static analysis (SAST). "
            "Each finding includes the rule that triggered it, severity, file and line, and remediation guidance. "
            "Findings are grouped when the same issue appears in multiple locations within the same file.",
            sty["body"],
        )
    )
    story.append(Spacer(1, 8))
    if grouped:
        for i, finding in enumerate(grouped, 1):
            rule_id = S.safe(finding.get("rule_id", "Unknown Rule"))
            file_path = S.safe(finding.get("file", "Unknown Path"))
            if workspace_root and file_path.startswith(workspace_root):
                file_path_display = os.path.relpath(file_path, workspace_root)
            elif file_path != "Unknown Path":
                file_path_display = os.path.basename(file_path)
            else:
                file_path_display = file_path
            occ_count = int(finding.get("_occurrence_count", 1))
            locations_txt = S.format_locations(finding.get("_locations", []), 10)
            message = S.safe(finding.get("message", "No message provided"))
            remediation = S.safe(finding.get("remediation", ""))
            occs = finding.get("_occurrences", [])
            first_excerpt = S.safe(occs[0].get("excerpt", "")) if occs else S.safe(finding.get("excerpt", ""))
            first_context = S.safe(occs[0].get("context", "")) if occs else S.safe(finding.get("context", ""))
            excerpt_trunc, excerpt_was_trunc = S.truncate_text(first_excerpt, 2500, 50)
            if excerpt_was_trunc:
                excerpt_trunc += "\n… (truncated)"
            context_trunc, context_was_trunc = S.truncate_text(first_context, 2500, 50)
            if context_was_trunc:
                context_trunc += "\n… (truncated)"
            finding_title = f"Finding #{i}: {rule_id} ({occ_count} occurrence{'s' if occ_count != 1 else ''})"
            details_data = [
                [S.para("Property", sty["table_header"]), S.para("Value", sty["table_header"])],
                [S.para("Rule ID", sty["table_key"]), S.para(rule_id, sty["table_val"])],
                [S.para("Severity", sty["table_key"]), S.para(S.safe(finding.get("severity", "")).title(), sty["table_val"])],
                [S.para("File Path", sty["table_key"]), S.para(file_path_display, sty["table_val"])],
                [S.para("Occurrences", sty["table_key"]), S.para(str(occ_count), sty["table_val"])],
                [S.para("Locations (line:col)", sty["table_key"]), S.para(locations_txt, sty["table_val"], preserve_newlines=True)],
                [S.para("Message", sty["table_key"]), S.para(message, sty["table_val"])],
            ]
            if excerpt_trunc:
                details_data.append([S.para("Code Excerpt (first)", sty["table_key"]), S.para(excerpt_trunc, sty["table_code"], preserve_newlines=True)])
            if remediation:
                details_data.append([S.para("Remediation", sty["table_key"]), S.para(remediation, sty["table_val"])])
            if context_trunc:
                details_data.append([S.para("Context (first)", sty["table_key"]), S.para(context_trunc, sty["table_code"], preserve_newlines=True)])
            t = Table(details_data, colWidths=[1.7 * inch, 3.8 * inch], repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), sty["gold"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), sty["text"]),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                ("BACKGROUND", (0, 1), (-1, -1), sty["surface"]),
                ("GRID", (0, 0), (-1, -1), 1, sty["border"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(KeepTogether([
                Paragraph(escape(finding_title), sty["finding_title"]),
                Spacer(1, 6),
                t,
                Spacer(1, 10),
            ]))
            if i < len(grouped):
                story.append(PageBreak())
    else:
        story.append(Paragraph("No code vulnerabilities were reported.", sty["body"]))
    story.append(PageBreak())


def add_dependency_vulns(story, ctx):
    vulns = ctx["vulns"]
    severity_counts = ctx["severity_counts"]
    sty = ctx["styles"]
    story.append(Paragraph("2. Vulnerabilities in Dependencies", sty["section"]))
    story.append(
        Paragraph(
            "This section covers known vulnerabilities in third-party packages, as reported by the OSV database. "
            "Each row includes the vulnerability identifier, affected package and version, ecosystem, severity, and a short description. "
            "Remediation typically involves upgrading to a patched version or applying the vendor advisory.",
            sty["body"],
        )
    )
    story.append(Spacer(1, 12))
    if severity_counts:
        story.append(Paragraph("Vulnerabilities by severity", sty["section"]))
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sev_data = [severity_counts.get(s, 0) for s in sev_order if severity_counts.get(s, 0)]
        sev_labels = [s for s in sev_order if severity_counts.get(s, 0)]
        if sev_data:
            drawing = Drawing(400, 220)
            pie = Pie()
            pie.data = sev_data
            pie.labels = [f"{l} ({c})" for l, c in zip(sev_labels, sev_data)]
            pie.x, pie.y, pie.width, pie.height = 100, 20, 200, 180
            pie.sideLabels = True
            colors = [HexColor("#c0392b"), HexColor("#e74c3c"), HexColor("#f39c12"), HexColor("#3498db"), HexColor("#95a5a6")]
            for i in range(len(sev_data)):
                if i < len(colors):
                    pie.slices[i].fillColor = colors[i]
            drawing.add(pie)
            story.append(drawing)
            story.append(Spacer(1, 12))
        sev_table_data = [[S.para("Severity", sty["table_header"]), S.para("Count", sty["table_header"])]]
        for sev in sev_order:
            if sev in severity_counts:
                sev_table_data.append([S.para(sev, sty["table_val"]), S.para(str(severity_counts[sev]), sty["table_val"])])
        t1 = Table(sev_table_data, colWidths=[2 * inch, 1.5 * inch])
        t1.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), sty["gold"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), sty["text"]),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("BACKGROUND", (0, 1), (-1, -1), sty["surface"]),
            ("GRID", (0, 0), (-1, -1), 1, sty["border"]),
        ]))
        story.append(t1)
        story.append(Spacer(1, 14))
    if vulns:
        vuln_table_data = [[S.para("Vuln ID", sty["table_header"]), S.para("Package", sty["table_header"]), S.para("Version", sty["table_header"]), S.para("Ecosystem", sty["table_header"]), S.para("Severity", sty["table_header"]), S.para("Description", sty["table_header"])]]
        for v in vulns[:300]:
            sev = S.severity_for_vuln_id(v.get("vuln_id", ""))
            desc = S.truncate(v.get("description", ""), 100)
            vuln_table_data.append([
                S.para(v.get("vuln_id", ""), sty["table_val"]),
                S.para(v.get("name", ""), sty["table_val"]),
                S.para(v.get("version", ""), sty["table_val"]),
                S.para(v.get("ecosystem", ""), sty["table_val"]),
                S.para(sev, sty["table_val"]),
                S.para(desc, sty["table_val"]),
            ])
        if len(vulns) > 300:
            vuln_table_data.append([S.para("…", sty["table_val"]), S.para(f"+ {len(vulns) - 300} more", sty["table_val"]), S.para("", sty["table_val"]), S.para("", sty["table_val"]), S.para("", sty["table_val"]), S.para("", sty["table_val"])])
        t3 = Table(vuln_table_data, colWidths=[1.2 * inch, 1.0 * inch, 0.7 * inch, 0.7 * inch, 0.6 * inch, 1.8 * inch], repeatRows=1)
        t3.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), sty["gold"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), sty["text"]),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 1), (-1, -1), sty["surface"]),
            ("GRID", (0, 0), (-1, -1), 1, sty["border"]),
        ]))
        story.append(t3)
    else:
        story.append(Paragraph("No vulnerabilities in dependencies were reported.", sty["body"]))
    story.append(PageBreak())


def add_sbom(story, ctx):
    sbom = ctx["sbom"]
    ecosystem_sbom = ctx["ecosystem_sbom"]
    sty = ctx["styles"]
    story.append(Paragraph("3. Dependencies and Licenses", sty["section"]))
    story.append(
        Paragraph(
            "This section lists the software components (SBOM) identified in the project. "
            "It includes the package name, version, and ecosystem. "
            "Use this inventory for license compliance, dependency audits, and supply-chain visibility.",
            sty["body"],
        )
    )
    story.append(Spacer(1, 8))
    if sbom:
        if ecosystem_sbom:
            story.append(Paragraph("Components by ecosystem", sty["section"]))
            eco_names = list(ecosystem_sbom.keys())
            eco_values = [ecosystem_sbom[k] for k in eco_names]
            drawing2 = Drawing(400, 220)
            pie2 = Pie()
            pie2.data = eco_values
            pie2.labels = [f"{n} ({v})" for n, v in zip(eco_names, eco_values)]
            pie2.x, pie2.y, pie2.width, pie2.height = 100, 20, 200, 180
            pie2.sideLabels = True
            colors_eco = [HexColor("#3498db"), HexColor("#2ecc71"), HexColor("#9b59b6"), HexColor("#e67e22"), HexColor("#1abc9c"), HexColor("#FFD700")]
            for i in range(len(eco_values)):
                pie2.slices[i].fillColor = colors_eco[i % len(colors_eco)]
            drawing2.add(pie2)
            story.append(drawing2)
            story.append(Spacer(1, 12))
        sbom_table_data = [[S.para("Name", sty["table_header"]), S.para("Version", sty["table_header"]), S.para("Ecosystem", sty["table_header"])]]
        for c in sbom[:200]:
            sbom_table_data.append([S.para(c.get("name", ""), sty["table_val"]), S.para(c.get("version", ""), sty["table_val"]), S.para(c.get("ecosystem", ""), sty["table_val"])])
        if len(sbom) > 200:
            sbom_table_data.append([S.para("…", sty["table_val"]), S.para(f"+ {len(sbom) - 200} more", sty["table_val"]), S.para("", sty["table_val"])])
        t4 = Table(sbom_table_data, colWidths=[2.2 * inch, 1.2 * inch, 1.2 * inch], repeatRows=1)
        t4.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), sty["gold"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), sty["text"]),
            ("BACKGROUND", (0, 1), (-1, -1), sty["surface"]),
            ("GRID", (0, 0), (-1, -1), 1, sty["border"]),
        ]))
        story.append(t4)
    else:
        story.append(Paragraph("No components in the SBOM.", sty["body"]))
