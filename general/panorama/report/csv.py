"""CSV report: panorama-sbom.csv and panorama-vulns.csv. Reads from canonical report."""
from __future__ import annotations

import csv
import os
from typing import Any


def write_csv(
    report_dir: str,
    report: dict[str, Any],
    opts: dict[str, Any],
) -> list[tuple[str, int]]:
    """Write CSV files from canonical report. Returns [(path, size), ...]."""
    out: list[tuple[str, int]] = []
    sep = opts.get("csv_separator") or ","
    sbom = report.get("sbom", {}).get("components", [])
    vulns = report.get("dependency_vulnerabilities", {}).get("vulnerabilities", [])
    if opts.get("include_sbom", True) and sbom:
        path = os.path.join(report_dir, "panorama-sbom.csv")
        headers = ["purl", "name", "version", "ecosystem", "file", "line", "type", "license", "notes"]
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, delimiter=sep)
            w.writerow(headers)
            for c in sbom:
                name = c.get("name") or ""
                version = c.get("version") or ""
                eco = c.get("ecosystem") or ""
                w.writerow([
                    c.get("purl", f"pkg:{eco.lower()}/{name}@{version}"),
                    name,
                    version,
                    eco,
                    c.get("file"),
                    c.get("line"),
                    c.get("type") or "library",
                    c.get("license") or "N/A",
                    "",
                ])
        out.append((path, os.path.getsize(path)))
    if opts.get("include_vulns", True) and vulns:
        path = os.path.join(report_dir, "panorama-vulns.csv")
        headers = ["vuln_id", "name", "version", "ecosystem", "file", "line", "severity", "description", "fixed_in", "published", "modified", "references"]
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, delimiter=sep)
            w.writerow(headers)
            for v in vulns:
                refs = v.get("references")
                ref_str = refs if isinstance(refs, str) else ("; ".join(refs) if isinstance(refs, list) else "")
                w.writerow([
                    v.get("vuln_id"),
                    v.get("name"),
                    v.get("version"),
                    v.get("ecosystem"),
                    v.get("file"),
                    v.get("line"),
                    v.get("severity"),
                    v.get("description") or "",
                    v.get("fixed_in") or "",
                    v.get("published") or "",
                    v.get("modified") or "",
                    ref_str,
                ])
        out.append((path, os.path.getsize(path)))
    return out
