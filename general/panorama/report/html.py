"""HTML report: panorama-report.html."""
from __future__ import annotations

import io
import os
from typing import Any


def write_html(
    report_dir: str,
    sbom: list[dict],
    vulns: list[dict],
    opts: dict[str, Any],
) -> list[tuple[str, int]]:
    title = opts.get("report_title") or "RootCause Dependencies Report"
    buf = io.StringIO()
    buf.write("<!DOCTYPE html><html><head><meta charset='utf-8'><title>")
    buf.write(title)
    buf.write("</title><style>table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:6px}th{background:#eee}</style></head><body><h1>")
    buf.write(title)
    buf.write("</h1>")
    if opts.get("include_sbom") and sbom:
        buf.write("<h2>SBOM</h2><table><tr><th>Name</th><th>Version</th><th>Ecosystem</th><th>File</th></tr>")
        for c in sbom:
            buf.write(f"<tr><td>{c.get('name','')}</td><td>{c.get('version','')}</td><td>{c.get('ecosystem','')}</td><td>{c.get('file','')}</td></tr>")
        buf.write("</table>")
    if opts.get("include_vulns") and vulns:
        buf.write("<h2>Vulnerabilities</h2><table><tr><th>ID</th><th>Package</th><th>Version</th><th>Ecosystem</th><th>File</th></tr>")
        for v in vulns:
            buf.write(f"<tr><td>{v.get('vuln_id','')}</td><td>{v.get('name','')}</td><td>{v.get('version','')}</td><td>{v.get('ecosystem','')}</td><td>{v.get('file','')}</td></tr>")
        buf.write("</table>")
    buf.write("</body></html>")
    path = os.path.join(report_dir, "panorama-report.html")
    content = buf.getvalue()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return [(path, len(content.encode("utf-8")))]
