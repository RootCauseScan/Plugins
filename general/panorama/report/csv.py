"""CSV report: panorama-sbom.csv and panorama-vulns.csv. Column order: IDs | file/dependency | location | severity | description | extra."""
from __future__ import annotations

import csv
import os
from typing import Any


def _severity_for_vuln(vuln_id: str) -> str:
    if (vuln_id or "").startswith("CVE-") or (vuln_id or "").startswith("GHSA-"):
        return "HIGH"
    return "MEDIUM"


def _purl(eco: str, name: str, version: str) -> str:
    eco_lower = (eco or "").lower().replace(" ", "")
    return f"pkg:{eco_lower}/{name}@{version}"


def write_csv(
    report_dir: str,
    sbom: list[dict],
    vulns: list[dict],
    opts: dict[str, Any],
) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    sep = opts.get("csv_separator") or ","
    if opts.get("include_sbom") and sbom:
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
                    _purl(eco, name, version),
                    name,
                    version,
                    eco,
                    c.get("file"),
                    c.get("line"),
                    c.get("type") or "library",
                    c.get("license") or "N/A",
                    c.get("notes") or "",
                ])
        out.append((path, os.path.getsize(path)))
    if opts.get("include_vulns") and vulns:
        path = os.path.join(report_dir, "panorama-vulns.csv")
        headers = ["vuln_id", "name", "version", "ecosystem", "file", "line", "severity", "description", "fixed_in", "published", "modified", "references"]
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, delimiter=sep)
            w.writerow(headers)
            for v in vulns:
                vid = v.get("vuln_id") or ""
                w.writerow([
                    vid,
                    v.get("name"),
                    v.get("version"),
                    v.get("ecosystem"),
                    v.get("file"),
                    v.get("line"),
                    v.get("severity") or _severity_for_vuln(vid),
                    v.get("description") or "",
                    v.get("fixed_in") or "",
                    v.get("published") or "",
                    v.get("modified") or "",
                    v.get("references") or "",
                ])
        out.append((path, os.path.getsize(path)))
    return out
