"""JSON report: infra-report.json with images and infra findings only (rule_id starting with prefix)."""
from __future__ import annotations

import json
import os
from typing import Any

# Only include findings from this plugin's rules (e.g. infra.image-vulnerability, infra.runs-as-root)
RULE_PREFIX = "infra."


def _infra_findings_only(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in findings if (f.get("rule_id") or "").startswith(RULE_PREFIX)]


def write_json(
    report_dir: str,
    images: list[dict[str, Any]],
    findings_infra: list[dict[str, Any]],
    opts: dict[str, Any],
) -> list[tuple[str, int]]:
    findings = _infra_findings_only(findings_infra)
    data = {
        "report": "infra",
        "images": images,
        "findings": findings,
        "summary": {
            "images_count": len(images),
            "findings_count": len(findings),
        },
    }
    path = os.path.join(report_dir, "infra-report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return [(path, os.path.getsize(path))]
