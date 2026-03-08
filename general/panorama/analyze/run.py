"""Analyze phase: dependencies via Syft (SBOM) + Grype (vulns); infra via analyze.infra."""
from __future__ import annotations

from typing import Any

from . import cyclonedx_grype as cg
from .infra import analyze_infra_files

# Re-export for plugin
from .cyclonedx_grype import (  # noqa: F401
    resolve_tool_path,
    run_syft,
    run_grype,
    sbom_from_cyclonedx,
    vulns_from_grype,
)


def analyze_files(files: list[dict[str, Any]], state: dict[str, Any]) -> list[dict[str, Any]]:
    """Process manifest files: run Syft (SBOM) and Grype (vulns) once per workspace; append to state, return findings."""
    if not files:
        return []
    opts = state.get("options") or {}
    if opts.get("dependencies") is False:
        return []
    # Run deps pipeline only once per workspace (engine may call file.analyze multiple times in batches)
    if state.get("deps_analyzed"):
        return []
    workspace_root = state.get("workspace_root", ".")
    plugin_dir = state.get("plugin_dir") or "."
    opts = state.get("options") or {}
    log_fn = state.get("log")

    syft_path = cg.resolve_tool_path(
        (opts.get("syft_path") or "").strip(),
        plugin_dir,
        "bin/syft",
    )
    grype_path = cg.resolve_tool_path(
        (opts.get("grype_path") or "").strip(),
        plugin_dir,
        "bin/grype",
    )
    grype_timeout = int(opts.get("grype_timeout_sec") or 300)

    sbom_path = cg.run_syft(workspace_root, syft_path, log_fn, timeout_sec=300)
    if not sbom_path:
        if files and log_fn:
            log_fn("info", "Dependency analysis skipped (Syft unavailable).")
        state["deps_analyzed"] = True  # avoid retrying on every batch
        return []

    try:
        grype_data = cg.run_grype(sbom_path, grype_path, log_fn, timeout_sec=grype_timeout)
        sbom_list = cg.sbom_from_cyclonedx(sbom_path)
        if not sbom_list and log_fn:
            log_fn("warn", "Syft produced 0 components. For npm: run 'npm install' to generate package-lock.json and node_modules. For other ecosystems ensure lock files exist (e.g. yarn.lock, Pipfile.lock).")
        state["sbom"].extend(sbom_list)

        if grype_data:
            vulns_list, findings_list = cg.vulns_from_grype(grype_data, state)
            state["vulns"].extend(vulns_list)
            if log_fn:
                log_fn("info", f"Dependencies: {len(sbom_list)} components, {len(vulns_list)} vulnerabilities (Grype).")
            return findings_list
        else:
            if log_fn:
                log_fn("info", f"Dependencies: {len(sbom_list)} components (Grype skipped or no vulns).")
            return []
    finally:
        state["deps_analyzed"] = True
        try:
            import os
            if os.path.isfile(sbom_path):
                os.unlink(sbom_path)
        except OSError:
            pass
