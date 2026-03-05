"""Analyze phase: parse files, update state (SBOM + vulns), return findings."""
from __future__ import annotations

import base64
import os
from typing import Any

from . import osv, parsers
from .filters import severity_for_vuln


def _next_id(state: dict[str, Any]) -> str:
    state["finding_id"] = state.get("finding_id", 0) + 1
    return f"deps-{state['finding_id']}"


def analyze_files(files: list[dict[str, Any]], state: dict[str, Any]) -> list[dict[str, Any]]:
    """Process manifest files: parse deps, query OSV, append to state['sbom'] and state['vulns'], return findings."""
    workspace_root = state.get("workspace_root", ".")
    all_findings: list[dict[str, Any]] = []
    for f in files:
        path = f.get("path", "")
        if not path:
            continue
        content_b64 = f.get("content_b64")
        if not content_b64:
            continue
        try:
            data = base64.standard_b64decode(content_b64)
        except Exception:
            continue
        base = os.path.basename(path).split("-")[0] if "/virtual/" in path else os.path.basename(path)
        ecosystem = "npm"
        deps: list[tuple[str, str, int, str]] = []
        if base == "package.json":
            deps = parsers.parse_package_json(data)
            ecosystem = "npm"
        elif base == "requirements.txt":
            deps = parsers.parse_requirements_txt(data)
            ecosystem = "PyPI"
        elif base in ("go.mod", "go.sum"):
            deps = parsers.parse_go_mod(data)
            ecosystem = "Go"
        elif base == "Cargo.toml":
            deps = parsers.parse_cargo_toml(data)
            ecosystem = "crates.io"
        elif base == "Cargo.lock":
            deps = parsers.parse_cargo_lock(data)
            ecosystem = "crates.io"
        else:
            continue
        if not deps:
            continue
        dep_keys = [(ecosystem, name, version) for name, version, line, excerpt in deps]
        vuln_id_lists = osv.query_osv_batch(dep_keys)
        for (name, version, line, excerpt), vuln_ids in zip(deps, vuln_id_lists):
            state["sbom"].append({
                "name": name, "version": version, "ecosystem": ecosystem,
                "file": path, "line": line,
            })
            for vid in vuln_ids:
                state["vulns"].append({
                    "vuln_id": vid, "name": name, "version": version,
                    "ecosystem": ecosystem, "file": path, "line": line,
                })
                all_findings.append({
                    "id": _next_id(state),
                    "rule_id": "deps.vulnerability",
                    "rule_file": None,
                    "severity": severity_for_vuln(vid),
                    "file": path,
                    "line": line,
                    "column": 1,
                    "excerpt": excerpt,
                    "message": f"Known vulnerability {vid} in {name}@{version}",
                    "remediation": "Update to a patched version or apply vendor advisory.",
                    "fix": None,
                })
    return all_findings
