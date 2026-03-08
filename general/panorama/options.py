"""Option parsing for panorama plugin (CLI sends strings)."""
from __future__ import annotations

import json
from typing import Any


def default_options() -> dict[str, Any]:
    return {
        "output_dir": "reports",
        "output_formats": ["json", "csv", "html", "pdf", "xlsx"],
        "dependencies": True,
        "infra": True,
        "licenses": True,
        "include_sbom": True,
        "include_vulns": True,
        "min_severity": "INFO",
        "ecosystems": [],
        "exclude_ecosystems": [],
        "denied_licenses": [],
        "report_title": "RootCause Panorama Report",
        "csv_separator": ",",
        # Deps: Syft (SBOM) + Grype (vulns); empty = use plugin-local bin/
        "syft_path": "",
        "grype_path": "",
        "grype_timeout_sec": 300,
        # Infra (Dockerfile, compose, K8s); empty = plugin-local bin/trivy
        "scan_images": True,
        "trivy_path": "",
        "trivy_timeout_sec": 10,
        "check_healthcheck": True,
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
    if key in ("dependencies", "infra", "licenses", "include_sbom", "include_vulns", "scan_images", "check_healthcheck"):
        if isinstance(raw, bool):
            return raw
        return str(raw).lower() in ("1", "true", "yes", "on")
    if key in ("trivy_timeout_sec", "grype_timeout_sec"):
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default_options().get(key, 300)
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
