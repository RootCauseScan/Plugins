"""PDF styles and text helpers."""
from __future__ import annotations

from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph


def safe(v: Any) -> str:
    return "" if v is None else str(v)


def para(text: str, style: ParagraphStyle, preserve_newlines: bool = False) -> Paragraph:
    s = escape(safe(text))
    if preserve_newlines:
        s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br/>")
    return Paragraph(s, style)


def truncate(s: str, max_len: int = 120) -> str:
    s = safe(s).strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def truncate_text(s: str, max_chars: int = 2500, max_lines: int = 50) -> tuple[str, bool]:
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


def format_locations(locations: list[str], per_line: int = 10) -> str:
    if not locations:
        return "N/A"
    parts = []
    for i in range(0, len(locations), per_line):
        parts.append(", ".join(locations[i : i + per_line]))
    return "\n".join(parts)


def group_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for f in findings or []:
        rule_id = safe(f.get("rule_id", "Unknown Rule"))
        severity = safe(f.get("severity", "unknown"))
        file_path = safe(f.get("file", "Unknown Path"))
        message = safe(f.get("message", ""))
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
    out = []
    for g in grouped.values():
        occs = g.get("_occurrences", [])

        def _num(x):
            try:
                return int(x) if x != "N/A" else 10**9
            except Exception:
                return 10**9

        occs_sorted = sorted(occs, key=lambda o: (_num(o.get("line")), _num(o.get("column"))))
        g["_occurrences"] = occs_sorted
        locs = [f"{o.get('line','N/A')}:{o.get('column','N/A')}" for o in occs_sorted]
        seen = set()
        uniq_locs = [x for x in locs if x not in seen and not seen.add(x)]
        g["_locations"] = uniq_locs
        g["_occurrence_count"] = len(occs_sorted)
        out.append(g)
    out.sort(key=lambda x: (safe(x.get("severity", "")), safe(x.get("rule_id", "")), safe(x.get("file", ""))))
    return out


def severity_for_vuln_id(vuln_id: str) -> str:
    if vuln_id.startswith("CVE-") or vuln_id.startswith("GHSA-"):
        return "HIGH"
    if vuln_id.startswith("PYSEC-") or vuln_id.startswith("RUSTSEC-"):
        return "MEDIUM"
    return "LOW"


def plugin_root() -> str:
    """Plugin root directory (panorama folder)."""
    import os
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def build_styles():
    """Return dict of ParagraphStyles and colors for the PDF."""
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
    section_style = ParagraphStyle(
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
    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        textColor=brand_text,
        alignment=TA_LEFT,
    )
    table_val_style = ParagraphStyle(
        "TableVal",
        parent=styles["Normal"],
        fontSize=9,
        textColor=brand_text,
        alignment=TA_LEFT,
        leading=11,
        wordWrap="CJK",
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
    )
    table_code_style = ParagraphStyle(
        "TableCode",
        parent=styles["Normal"],
        fontSize=8.5,
        textColor=brand_text,
        backColor=brand_surface,
        leading=10,
        wordWrap="CJK",
    )
    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=section_style,
        fontSize=16,
        spaceAfter=10,
        textColor=brand_text_secondary,
        keepWithNext=True,
    )
    return {
        "title": title_style,
        "section": section_style,
        "body": body_style,
        "brand": brand_style,
        "table_header": table_header_style,
        "table_val": table_val_style,
        "table_key": table_key_style,
        "table_code": table_code_style,
        "finding_title": finding_title_style,
        "gold": brand_gold,
        "text": brand_text,
        "text_secondary": brand_text_secondary,
        "surface": brand_surface,
        "border": brand_border,
    }
