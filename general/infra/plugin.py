#!/usr/bin/env python3
"""Infra plugin: discover + analyze + report for Dockerfile, Containerfile, compose, K8s/OpenShift."""
from __future__ import annotations

import json
import os
import sys
from typing import Any

import discover
import report
from analyze import analyze_files
from options import default_options, parse_opt_value

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
        _state["images"] = []
        _state["findings_infra"] = []
        _state["finding_id"] = 0
        _state["options"] = default_options()


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
            _state["findings_infra"] = []
            _state["images"] = []
            _state["scanned_image_refs"] = set()
            send(mid, {
                "ok": True,
                "capabilities": ["discover", "analyze", "report"],
                "plugin_version": "0.1.0",
            })

        elif method == "plugin.ping":
            send(mid, {"pong": True})

        elif method == "repo.discover":
            _ensure_state()
            root = _state["workspace_root"]
            base = params.get("path", ".")
            max_depth = params.get("max_depth")
            files = discover.discover_infra_files(root, base, max_depth)
            log("info", f"Discovered {len(files)} infra files (Dockerfile, compose, K8s)")
            send(mid, {
                "files": files,
                "external": [],
                "metrics": {"files_found": len(files), "scan_time_ms": 0},
            })

        elif method == "file.analyze":
            _ensure_state()
            _state["log"] = log
            files = params.get("files") or []
            infra_files = [f for f in files if discover.is_infra_file(f.get("path", ""))]
            all_findings = analyze_files(infra_files, _state)
            send(mid, {
                "findings": all_findings,
                "metrics": {
                    "files_analyzed": len(infra_files),
                    "findings": len(all_findings),
                    "images_found": len(_state.get("images") or []),
                },
            })

        elif method == "scan.report":
            _ensure_state()
            root = _state["workspace_root"]
            findings_param = params.get("findings") or []
            opts = _state.get("options") or default_options()
            output_dir = opts.get("output_dir") or "reports"
            report_dir = os.path.join(root, output_dir)
            os.makedirs(report_dir, exist_ok=True)
            formats = opts.get("output_formats") or ["json", "html"]
            if isinstance(formats, str):
                formats = [formats]
            images = _state.get("images") or []
            findings_infra = _state.get("findings_infra") or []
            output_files: list[dict[str, Any]] = []
            for fmt in formats:
                fmt = str(fmt).lower().strip()
                if fmt == "json":
                    for path, size in report.write_json(report_dir, images, findings_infra, opts):
                        output_files.append({
                            "path": os.path.relpath(path, root).replace(os.sep, "/"),
                            "type": "application/json",
                            "size": size,
                        })
                elif fmt == "html":
                    for path, size in report.write_html(report_dir, images, findings_infra, opts):
                        output_files.append({
                            "path": os.path.relpath(path, root).replace(os.sep, "/"),
                            "type": "text/html",
                            "size": size,
                        })
                elif fmt == "pdf":
                    log("warn", "PDF format not implemented; run with output_formats=json,html or add install.sh and reportlab")
            log("info", f"Wrote {len(output_files)} report file(s)")
            send(mid, {
                "output_files": output_files,
                "summary": {
                    "images": len(images),
                    "infra_findings": len(findings_infra),
                    "total_findings": len(findings_param),
                },
                "generation_time_ms": 0,
            })

        elif method == "plugin.shutdown":
            send(mid, {"ok": True})
            break

        else:
            send(mid, None, {"code": -32601, "message": f"Method not found: {method}"})


if __name__ == "__main__":
    main()
