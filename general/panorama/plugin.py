#!/usr/bin/env python3
"""All-in-One plugin: dependencies (SBOM, vulns) + infra (Dockerfile, compose, K8s). Discover, analyze, report."""
from __future__ import annotations

import json
import os
import sys
from typing import Any

import discover
import report
from analyze import analyze_files
from analyze.infra import analyze_infra_files
from analyze.filters import filter_sbom, filter_vulns
from options import default_options, parse_opt_value

write_infra_json = report.write_infra_json
write_infra_html = report.write_infra_html

try:
    from report import write_pdf
    _HAS_PDF = write_pdf is not None
except ImportError:
    write_pdf = None
    _HAS_PDF = False

try:
    from report import write_excel
    _HAS_EXCEL = write_excel is not None
except ImportError:
    write_excel = None
    _HAS_EXCEL = False

_plugin_dir = os.path.dirname(os.path.abspath(__file__))
_state: dict[str, Any] = {}


def send(mid: Any, result: Any = None, error: dict[str, Any] | None = None) -> None:
    msg = {"jsonrpc": "2.0", "id": mid}
    if error is None:
        msg["result"] = result
    else:
        msg["error"] = error
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def log(level: str, message: str) -> None:
    sys.stdout.write(json.dumps({
        "jsonrpc": "2.0", "method": "plugin.log",
        "params": {"level": level, "message": message},
    }) + "\n")
    sys.stdout.flush()


def _ensure_state() -> None:
    if not _state:
        _state["workspace_root"] = "."
        _state["plugin_dir"] = _plugin_dir
        _state["sbom"] = []
        _state["licenses"] = []
        _state["vulns"] = []
        _state["denied_licenses"] = []
        _state["finding_id"] = 0
        _state["options"] = default_options()
        _state["images"] = []
        _state["findings_infra"] = []
        _state["scanned_image_refs"] = set()


def main() -> None:
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        if method == "plugin.init":
            _ensure_state()
            _state["workspace_root"] = params.get("workspace_root", ".")
            raw = params.get("options") or {}
            opts = default_options()
            for key in opts:
                if key in raw:
                    opts[key] = parse_opt_value(key, raw[key])
            _state["options"] = opts
            _state["denied_licenses"] = opts.get("denied_licenses") or []
            _state["findings_infra"] = []
            _state["images"] = []
            _state["scanned_image_refs"] = set()
            _state["sbom"] = []
            _state["vulns"] = []
            _state["deps_analyzed"] = False
            send(mid, {
                "ok": True,
                "capabilities": ["discover", "analyze", "report"],
                "plugin_version": "0.4.0",
            })

        elif method == "plugin.ping":
            send(mid, {"pong": True})

        elif method == "repo.discover":
            _ensure_state()
            root = _state["workspace_root"]
            base = params.get("path", ".")
            max_depth = params.get("max_depth")
            opts = _state.get("options") or default_options()
            manifest_files = discover.discover_manifests(root, base, max_depth)
            infra_files = discover.discover_infra_files(root, base, max_depth) if opts.get("infra") else []
            files = manifest_files + infra_files
            log("info", f"Discovered {len(manifest_files)} manifest(s), {len(infra_files)} infra file(s) (Dockerfile, compose, K8s)")
            send(mid, {
                "files": files,
                "external": [],
                "metrics": {"files_found": len(files), "scan_time_ms": 0},
            })

        elif method == "file.analyze":
            _ensure_state()
            _state["log"] = log
            opts = _state.get("options") or default_options()
            files = params.get("files") or []
            manifest_files = [f for f in files if discover.is_manifest(f.get("path", ""))]
            infra_files = [f for f in files if discover.is_infra_file(f.get("path", ""))]
            deps_findings = analyze_files(manifest_files, _state) if opts.get("dependencies") else []
            infra_findings = analyze_infra_files(infra_files, _state) if opts.get("infra") else []
            all_findings = deps_findings + infra_findings
            send(mid, {
                "findings": all_findings,
                "metrics": {
                    "files_analyzed": len(manifest_files) + len(infra_files),
                    "findings": len(all_findings),
                    "sbom_entries": len(_state["sbom"]),
                    "images_found": len(_state.get("images") or []),
                },
            })

        elif method == "scan.report":
            _ensure_state()
            root = _state["workspace_root"]
            findings_param = params.get("findings") or []
            opts = _state.get("options") or default_options()
            pdf_opts = {**opts, "workspace_root": root}
            output_dir = opts.get("output_dir") or "reports"
            report_dir = os.path.join(root, output_dir)
            os.makedirs(report_dir, exist_ok=True)
            formats = opts.get("output_formats") or default_options().get("output_formats") or ["json", "csv", "pdf", "xlsx"]
            if isinstance(formats, str):
                formats = [formats]
            canonical_report = report.build_canonical_report(_state, findings_param, pdf_opts)
            output_files: list[dict[str, Any]] = []
            deps_enabled = opts.get("dependencies") is not False
            infra_enabled = opts.get("infra") is not False
            licenses_enabled = opts.get("licenses") is not False
            sbom_f = filter_sbom(_state["sbom"], opts.get("ecosystems") or [], opts.get("exclude_ecosystems") or [])
            vulns_f = filter_vulns(_state["vulns"], opts.get("min_severity") or "INFO", opts.get("ecosystems") or [], opts.get("exclude_ecosystems") or [])
            for fmt in formats:
                fmt = str(fmt).lower().strip()
                if fmt == "json":
                    for path, size in report.write_canonical_json(report_dir, canonical_report, pdf_opts):
                        output_files.append({"path": os.path.relpath(path, root).replace(os.sep, "/"), "type": "application/json", "size": size})
                elif fmt == "csv":
                    if deps_enabled:
                        for path, size in report.write_csv(report_dir, canonical_report, pdf_opts):
                            output_files.append({"path": os.path.relpath(path, root).replace(os.sep, "/"), "type": "text/csv", "size": size})
                elif fmt == "pdf":
                    if _HAS_PDF and write_pdf:
                        pdf_result = write_pdf(report_dir, canonical_report, pdf_opts, _plugin_dir)
                        for path, size in pdf_result:
                            output_files.append({"path": os.path.relpath(path, root).replace(os.sep, "/"), "type": "application/pdf", "size": size})
                        if not pdf_result:
                            log("warn", "PDF not generated: install markdown and weasyprint in the plugin environment (pip install markdown weasyprint)")
                    else:
                        log("warn", "PDF requested but markdown/weasyprint not installed; run pip install markdown weasyprint or ./install.sh")
                elif fmt == "xlsx":
                    if _HAS_EXCEL and write_excel:
                        for path, size in write_excel(report_dir, canonical_report, pdf_opts):
                            output_files.append({"path": os.path.relpath(path, root).replace(os.sep, "/"), "type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "size": size})
                    else:
                        log("warn", "Excel requested but openpyxl not installed; run pip install openpyxl or ./install.sh")
            infra_data = canonical_report.get("infrastructure", {})
            images = infra_data.get("images", [])
            findings_infra = infra_data.get("findings", [])
            if infra_enabled and (images or findings_infra) and write_infra_json and write_infra_html:
                for path, size in write_infra_json(report_dir, canonical_report, pdf_opts):
                    output_files.append({"path": os.path.relpath(path, root).replace(os.sep, "/"), "type": "application/json", "size": size})
                for path, size in write_infra_html(report_dir, canonical_report, pdf_opts):
                    output_files.append({"path": os.path.relpath(path, root).replace(os.sep, "/"), "type": "text/html", "size": size})
            log("info", f"Writing {len(output_files)} report file(s) to {output_dir}/ (formats: {', '.join(formats)})")
            summary = {
                "sbom_components": len(sbom_f),
                "vulnerabilities": len(vulns_f),
                "total_findings": len(findings_param),
            }
            if images or findings_infra:
                summary["images"] = len(images)
                summary["infra_findings"] = len(findings_infra)
            send(mid, {
                "output_files": output_files,
                "summary": summary,
                "generation_time_ms": 0,
            })

        elif method == "plugin.shutdown":
            send(mid, {"ok": True})
            break

        else:
            send(mid, None, {"code": -32601, "message": f"Method not found: {method}"})


if __name__ == "__main__":
    main()
