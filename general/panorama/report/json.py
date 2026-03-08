"""JSON report: writes canonical panorama-report.json."""
from __future__ import annotations

from typing import Any

from . import canonical as _canonical


def write_json(
    report_dir: str,
    report: dict[str, Any],
    opts: dict[str, Any],
) -> list[tuple[str, int]]:
    """Write the canonical report to report_dir/panorama-report.json. Returns [(path, size)]."""
    return _canonical.write_canonical_json(report_dir, report, opts)
