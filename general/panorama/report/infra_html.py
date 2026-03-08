"""HTML report: panorama-infra.html with images and findings only (rule_id starting with prefix)."""
from __future__ import annotations

import html
import io
import os
from typing import Any

RULE_PREFIX = "infra."


def _infra_findings_only(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in findings if (f.get("rule_id") or "").startswith(RULE_PREFIX)]


def write_infra_html(
    report_dir: str,
    images: list[dict[str, Any]],
    findings_infra: list[dict[str, Any]],
    opts: dict[str, Any],
) -> list[tuple[str, int]]:
    findings = _infra_findings_only(findings_infra)
    title = opts.get("report_title") or "RootCause Panorama Report (Infra)"
    buf = io.StringIO()
    buf.write("<!DOCTYPE html><html><head><meta charset='utf-8'><title>")
    buf.write(html.escape(title))
    buf.write("</title><style>table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:6px}th{background:#eee}.severity-HIGH{color:#c00}.severity-MEDIUM{color:#f80}.severity-LOW{color:#666}</style></head><body><h1>")
    buf.write(html.escape(title))
    buf.write("</h1>")
    buf.write("<h2>Images</h2>")
    if images:
        buf.write("<table><tr><th>File</th><th>Line</th><th>Image</th><th>Source</th></tr>")
        for im in images:
            buf.write("<tr><td>")
            buf.write(html.escape(im.get("file") or ""))
            buf.write("</td><td>")
            buf.write(str(im.get("line") or ""))
            buf.write("</td><td>")
            buf.write(html.escape(im.get("image_ref") or ""))
            buf.write("</td><td>")
            buf.write(html.escape(im.get("source") or ""))
            buf.write("</td></tr>")
        buf.write("</table>")
    else:
        buf.write("<p>No container images found.</p>")
    buf.write("<h2>Findings (misconfig &amp; image vulnerabilities)</h2>")
    if findings:
        buf.write("<table><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Message</th></tr>")
        for f in findings:
            sev = f.get("severity") or ""
            buf.write(f"<tr><td class='severity-{sev}'>{html.escape(sev)}</td><td>")
            buf.write(html.escape(f.get("rule_id") or ""))
            buf.write("</td><td>")
            buf.write(html.escape(f.get("file") or ""))
            buf.write("</td><td>")
            buf.write(str(f.get("line") or ""))
            buf.write("</td><td>")
            msg = html.escape(f.get("message") or "").replace("\n", "<br>\n")
            buf.write(msg)
            buf.write("</td></tr>")
        buf.write("</table>")
    else:
        buf.write("<p>No infra findings.</p>")
    buf.write("</body></html>")
    path = os.path.join(report_dir, "panorama-infra.html")
    content = buf.getvalue()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return [(path, len(content.encode("utf-8")))]
