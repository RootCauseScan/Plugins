"""JSON report: panorama-sbom.json (CycloneDX) and panorama-vulns.json."""
from __future__ import annotations

import json
import os
from typing import Any


def write_json(
    report_dir: str,
    sbom: list[dict],
    vulns: list[dict],
    opts: dict[str, Any],
) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    if opts.get("include_sbom"):
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": c["name"],
                    "version": c["version"],
                    "purl": f"pkg:{str(c.get('ecosystem','')).lower()}/{c['name']}@{c['version']}",
                }
                for c in sbom
            ],
        }
        path = os.path.join(report_dir, "panorama-sbom.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sbom_data, fh, indent=2)
        out.append((path, os.path.getsize(path)))
    if opts.get("include_vulns"):
        path = os.path.join(report_dir, "panorama-vulns.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(vulns, fh, indent=2)
        out.append((path, os.path.getsize(path)))
    return out
