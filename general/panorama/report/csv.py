"""CSV report: sbom.csv and deps-vulns.csv."""
from __future__ import annotations

import csv
import os
from typing import Any


def write_csv(
    report_dir: str,
    sbom: list[dict],
    vulns: list[dict],
    opts: dict[str, Any],
) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    sep = opts.get("csv_separator") or ","
    if opts.get("include_sbom") and sbom:
        path = os.path.join(report_dir, "sbom.csv")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, delimiter=sep)
            w.writerow(["name", "version", "ecosystem", "file", "line"])
            for c in sbom:
                w.writerow([c.get("name"), c.get("version"), c.get("ecosystem"), c.get("file"), c.get("line")])
        out.append((path, os.path.getsize(path)))
    if opts.get("include_vulns") and vulns:
        path = os.path.join(report_dir, "deps-vulns.csv")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, delimiter=sep)
            w.writerow(["vuln_id", "name", "version", "ecosystem", "file", "line"])
            for v in vulns:
                w.writerow([v.get("vuln_id"), v.get("name"), v.get("version"), v.get("ecosystem"), v.get("file"), v.get("line")])
        out.append((path, os.path.getsize(path)))
    return out
