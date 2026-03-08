"""Finding grouping and text helpers for PDF reports."""
import os
from typing import Any, Dict, List, Tuple


def safe_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v)


def truncate_text(s: str, max_chars: int = 2500, max_lines: int = 50) -> Tuple[str, bool]:
    """Avoid giant cells that can blow up layout; keep report readable."""
    if not s:
        return s, False
    raw = s.replace("\r\n", "\n").replace("\r", "\n")
    lines = raw.split("\n")
    truncated = False
    if len(lines) > max_lines:
        raw = "\n".join(lines[:max_lines])
        truncated = True
    if len(raw) > max_chars:
        raw = raw[:max_chars]
        truncated = True
    return raw, truncated


def group_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group findings when the same file has the same vulnerability in different lines.
    Group key: (rule_id, severity, file, message).
    """
    grouped: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    for f in findings or []:
        rule_id = safe_str(f.get("rule_id", "Unknown Rule"))
        severity = safe_str(f.get("severity", "unknown"))
        file_path = safe_str(f.get("file", "Unknown Path"))
        message = safe_str(f.get("message", ""))

        key = (rule_id, severity, file_path, message)
        occ = {
            "line": f.get("line", "N/A"),
            "column": f.get("column", "N/A"),
            "excerpt": f.get("excerpt", ""),
            "context": f.get("context", ""),
        }

        if key not in grouped:
            base = dict(f)
            base["rule_id"] = rule_id
            base["severity"] = severity
            base["file"] = file_path
            base["message"] = message
            base["_occurrences"] = [occ]
            grouped[key] = base
        else:
            grouped[key]["_occurrences"].append(occ)

    out: List[Dict[str, Any]] = []
    for g in grouped.values():
        occs = g.get("_occurrences", [])

        def _num(x):
            try:
                return int(x)
            except Exception:
                return 10**9

        occs_sorted = sorted(occs, key=lambda o: (_num(o.get("line")), _num(o.get("column"))))
        g["_occurrences"] = occs_sorted
        locs = [f"{o.get('line','N/A')}:{o.get('column','N/A')}" for o in occs_sorted]
        seen = set()
        uniq_locs = []
        for x in locs:
            if x not in seen:
                seen.add(x)
                uniq_locs.append(x)
        g["_locations"] = uniq_locs
        g["_occurrence_count"] = len(occs_sorted)
        out.append(g)

    out.sort(
        key=lambda x: (
            safe_str(x.get("severity", "")),
            safe_str(x.get("rule_id", "")),
            safe_str(x.get("file", "")),
        )
    )
    return out


def format_locations(locations: List[str], per_line: int = 10) -> str:
    if not locations:
        return "N/A"
    parts = []
    for i in range(0, len(locations), per_line):
        parts.append(", ".join(locations[i : i + per_line]))
    return "\n".join(parts)
