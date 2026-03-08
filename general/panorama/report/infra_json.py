"""JSON report: panorama-infra.json with images and infra findings. Reads from canonical report."""
from __future__ import annotations

import json
import os
from typing import Any


def write_infra_json(
    report_dir: str,
    report: dict[str, Any],
    opts: dict[str, Any],
) -> list[tuple[str, int]]:
    """Write panorama-infra.json from report["infrastructure"]. Returns [(path, size)]."""
    infra = report.get("infrastructure", {})
    images = infra.get("images", [])
    findings = infra.get("findings", [])
    data = {
        "report": "infra",
        "images": images,
        "findings": findings,
        "summary": {
            "images_count": len(images),
            "findings_count": len(findings),
        },
    }
    path = os.path.join(report_dir, "panorama-infra.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return [(path, os.path.getsize(path))]
