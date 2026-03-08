"""Option parsing for infra plugin (CLI sends strings)."""
from __future__ import annotations

import json
from typing import Any


def default_options() -> dict[str, Any]:
    return {
        "output_dir": "reports",
        "output_formats": ["json", "html"],
        "scan_images": False,
        "trivy_path": "trivy",
        "trivy_timeout_sec": 300,
        "report_title": "RootCause Infra Report",
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
    if key in ("scan_images", "check_healthcheck"):
        if isinstance(raw, bool):
            return raw
        return str(raw).lower() in ("1", "true", "yes", "on")
    if key == "trivy_timeout_sec":
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 300
    return raw if isinstance(raw, str) else str(raw)
