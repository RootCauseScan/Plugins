"""Canonical report: build single JSON (metadata, sast, dependency_vulnerabilities, infrastructure, sbom)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import os as _os
import sys

# Plugin root is parent of report/
_plugin_dir = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))  # noqa: E402
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from analyze.filters import filter_sbom, filter_vulns, severity_for_vuln


def _safe(v: Any) -> str:
    return "" if v is None else str(v)


def _group_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings by (rule_id, severity, file, message); add _occurrences and _occurrence_count."""
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for f in findings or []:
        rule_id = _safe(f.get("rule_id", "Unknown Rule"))
        severity = _safe(f.get("severity", "unknown"))
        file_path = _safe(f.get("file", "Unknown Path"))
        message = _safe(f.get("message", ""))
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
    out = []
    for g in grouped.values():
        occs = g.get("_occurrences", [])

        def _num(x: Any) -> int:
            try:
                return int(x) if x != "N/A" else 10**9
            except Exception:
                return 10**9

        occs_sorted = sorted(occs, key=lambda o: (_num(o.get("line")), _num(o.get("column"))))
        g["_occurrences"] = occs_sorted
        locs = [f"{o.get('line', 'N/A')}:{o.get('column', 'N/A')}" for o in occs_sorted]
        seen: set[str] = set()
        uniq_locs = [x for x in locs if x not in seen and not seen.add(x)]
        g["_locations"] = uniq_locs
        g["_occurrence_count"] = len(occs_sorted)
        out.append(g)
    out.sort(key=lambda x: (_safe(x.get("severity", "")), _safe(x.get("rule_id", "")), _safe(x.get("file", ""))))
    return out


def _normalize_sast_finding(f: dict[str, Any]) -> dict[str, Any]:
    """One finding entry for canonical sast.findings: flat fields + occurrences."""
    occs = f.get("_occurrences", [])
    first = occs[0] if occs else {}
    return {
        "rule_id": _safe(f.get("rule_id")),
        "severity": _safe(f.get("severity")),
        "file": _safe(f.get("file")),
        "line": first.get("line", f.get("line", "N/A")),
        "column": first.get("column", f.get("column", "N/A")),
        "message": _safe(f.get("message")),
        "excerpt": _safe(first.get("excerpt") or f.get("excerpt")),
        "remediation": _safe(f.get("remediation")),
        "context": _safe(first.get("context") or f.get("context")),
        "occurrences": [
            {"line": o.get("line", "N/A"), "column": o.get("column", "N/A"), "excerpt": _safe(o.get("excerpt")), "context": _safe(o.get("context"))}
            for o in occs
        ],
        "occurrence_count": int(f.get("_occurrence_count", 1)),
    }


def _purl(eco: str, name: str, version: str) -> str:
    eco_lower = (eco or "").lower().replace(" ", "")
    return f"pkg:{eco_lower}/{name}@{version}"


def build_canonical_report(
    state: dict[str, Any],
    findings_sast: list[dict[str, Any]],
    opts: dict[str, Any],
) -> dict[str, Any]:
    """Build the canonical report dict: metadata, sast, dependency_vulnerabilities, infrastructure, sbom."""
    sbom_raw = state.get("sbom") or []
    vulns_raw = state.get("vulns") or []
    images = state.get("images") or []
    findings_infra = state.get("findings_infra") or []
    denied_licenses = set(opts.get("denied_licenses") or [])

    ecosystems = opts.get("ecosystems") or []
    exclude_eco = opts.get("exclude_ecosystems") or []
    min_sev = opts.get("min_severity") or "INFO"

    sbom_f = filter_sbom(sbom_raw, ecosystems, exclude_eco)
    vulns_f = filter_vulns(vulns_raw, min_sev, ecosystems, exclude_eco)

    # SAST: findings that are not deps. or infra. (code only)
    code_findings = [
        f for f in (findings_sast or [])
        if not _safe(f.get("rule_id", "")).startswith("deps.")
        and not _safe(f.get("rule_id", "")).startswith("infra.")
    ]
    grouped_code = _group_findings(code_findings)
    sast_findings = [_normalize_sast_finding(g) for g in grouped_code]

    # dependency_vulnerabilities: severity_breakdown
    severity_counts: dict[str, int] = {}
    for v in vulns_f:
        sev = _safe(v.get("severity") or severity_for_vuln(_safe(v.get("vuln_id", "")))).upper()
        if sev not in severity_counts:
            severity_counts[sev] = 0
        severity_counts[sev] += 1
    total_v = len(vulns_f)
    severity_breakdown = [
        {"severity": sev, "count": cnt, "percent": f"{(cnt / total_v * 100.0):.1f}" if total_v else "0.0"}
        for sev, cnt in sorted(severity_counts.items())
    ]

    # dependency_vulnerabilities.vulnerabilities: normalize vuln entries
    vuln_list = []
    for v in vulns_f:
        vuln_list.append({
            "vuln_id": _safe(v.get("vuln_id")),
            "name": _safe(v.get("name")),
            "version": _safe(v.get("version")),
            "ecosystem": _safe(v.get("ecosystem")),
            "severity": _safe(v.get("severity") or severity_for_vuln(_safe(v.get("vuln_id", "")))),
            "description": _safe(v.get("description")),
            "fixed_in": _safe(v.get("fixed_in")),
            "file": _safe(v.get("file")),
            "line": v.get("line"),
            "published": _safe(v.get("published")),
            "modified": _safe(v.get("modified")),
            "references": v.get("references"),
        })

    # infrastructure: only findings with rule_id starting with "infra."
    infra_findings = [f for f in findings_infra if _safe(f.get("rule_id", "")).startswith("infra.")]
    infra_findings_normalized = []
    for f in infra_findings:
        entry = {
            "rule_id": _safe(f.get("rule_id")),
            "severity": _safe(f.get("severity")),
            "file": _safe(f.get("file")),
            "line": f.get("line"),
            "message": _safe(f.get("message")),
            "image_ref": _safe(f.get("image_ref") or f.get("image")),
        }
        if f.get("vulnerabilities"):
            entry["vulnerabilities"] = f["vulnerabilities"]
        infra_findings_normalized.append(entry)

    images_normalized = [
        {
            "file": _safe(im.get("file")),
            "line": im.get("line"),
            "image_ref": _safe(im.get("image_ref") or im.get("image")),
            "source": _safe(im.get("source")),
        }
        for im in images
    ]

    # sbom.components with denied flag
    components = []
    for c in sbom_f:
        name = _safe(c.get("name", ""))
        version = _safe(c.get("version", ""))
        eco = _safe(c.get("ecosystem", ""))
        lic = _safe(c.get("license", ""))
        denied = bool(denied_licenses and lic and any(d in lic for d in denied_licenses))
        components.append({
            "name": name,
            "version": version,
            "ecosystem": eco,
            "license": lic or "N/A",
            "purl": _purl(eco, name, version),
            "file": _safe(c.get("file")),
            "line": c.get("line"),
            "type": _safe(c.get("type")) or "library",
            "denied": denied,
        })

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    workspace_root = opts.get("workspace_root") or state.get("workspace_root") or ""
    report_title = opts.get("report_title") or "RootCause Panorama Report"

    report = {
        "metadata": {
            "report_version": "1.0",
            "generated_at": generated_at,
            "workspace_root": workspace_root,
            "report_title": report_title,
            "options": {
                "output_dir": opts.get("output_dir"),
                "min_severity": opts.get("min_severity"),
                "dependencies": opts.get("dependencies"),
                "infra": opts.get("infra"),
                "licenses": opts.get("licenses"),
            },
            "summary": {
                "sast_findings_count": len(sast_findings),
                "dependency_vulnerabilities_count": len(vuln_list),
                "infrastructure_images_count": len(images_normalized),
                "infrastructure_findings_count": len(infra_findings_normalized),
                "sbom_components_count": len(components),
            },
        },
        "sast": {
            "findings": sast_findings,
        },
        "dependency_vulnerabilities": {
            "vulnerabilities": vuln_list,
            "severity_breakdown": severity_breakdown,
        },
        "infrastructure": {
            "images": images_normalized,
            "findings": infra_findings_normalized,
        },
        "sbom": {
            "components": components,
        },
    }
    return report


def write_canonical_json(report_dir: str, report: dict[str, Any], opts: dict[str, Any]) -> list[tuple[str, int]]:
    """Write the canonical report to report_dir/panorama-report.json. Returns [(path, size)]."""
    import json
    path = _os.path.join(report_dir, "panorama-report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return [(path, _os.path.getsize(path))]
