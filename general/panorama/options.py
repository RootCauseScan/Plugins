"""Option parsing for panorama plugin (CLI sends strings)."""
from __future__ import annotations

import json
from typing import Any


def default_options() -> dict[str, Any]:
    return {
        "output_dir": "reports",
        "output_formats": ["pdf"],
        "include_sbom": True,
        "include_vulns": True,
        "min_severity": "INFO",
        "ecosystems": [],
        "exclude_ecosystems": [],
        "denied_licenses": [],
        "report_title": "RootCause Panorama Report",
        "csv_separator": ",",
    }


def parse_opt_value(key: str, raw: Any) -> Any:
    if raw is None:
        return default_options().get(key)
    if key == "output_formats":
        if isinstance(raw, list):
            return raw
        s = str(raw).strip()
        if s.startswith("["):
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                pass
        return [x.strip() for x in s.split(",") if x.strip()]
    if key in ("include_sbom", "include_vulns"):
        if isinstance(raw, bool):
            return raw
        return str(raw).lower() in ("1", "true", "yes", "on")
    if key in ("ecosystems", "exclude_ecosystems", "denied_licenses"):
        if isinstance(raw, list):
            return raw
        s = str(raw).strip()
        if s.startswith("["):
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                pass
        return [x.strip() for x in s.split(",") if x.strip()]
    if key == "min_severity":
        return str(raw).upper() if raw else "INFO"
    return raw if isinstance(raw, str) else str(raw)
