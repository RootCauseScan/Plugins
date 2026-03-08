#!/usr/bin/env python3
"""Generate professional PDF reports from SAST findings.

This plugin implements the report capability for RootCause.
Supports an editable Markdown template with CSS (templates/report.md + report.css).
"""
import base64
import json
import os
import signal
import sys
import time

# Ensure plugin directory is on path for lib imports
_plugin_dir = os.path.dirname(os.path.abspath(__file__))
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from lib.findings import group_findings
from lib.reportlab_report import create_pdf_report
from lib.template_report import (
    TEMPLATE_AVAILABLE,
    build_template_context,
    create_pdf_from_template,
)


def send(msg_id, result=None, error=None):
    """Send a JSON-RPC message to stdout."""
    payload = {"jsonrpc": "2.0", "id": msg_id}
    if error is None:
        payload["result"] = result
    else:
        payload["error"] = error
    try:
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        sys.exit(0)


def log(level, message):
    """Send a log message to RootCause."""
    payload = {
        "jsonrpc": "2.0",
        "method": "plugin.log",
        "params": {"level": level, "message": message},
    }
    try:
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        sys.exit(0)


def handle_init(params):
    """Handle plugin initialization."""
    opts.update(params.get("options") or {})
    opts["workspace_root"] = params.get("workspace_root", "")
    return {"ok": True, "capabilities": ["report"], "plugin_version": "1.0.0"}


def handle_report(params):
    """Handle report generation request."""
    t0 = time.time()
    try:
        findings = params.get("findings", []) or []
        metrics = params.get("metrics", {}) or {}

        log("info", f"Generating PDF report for {len(findings)} finding occurrence(s)")

        output_filename = opts.get("output", "reports/report.pdf")
        base_dir = opts.get("workspace_root") or opts.get("cwd") or os.getcwd()
        if not os.path.exists(base_dir):
            base_dir = os.getcwd()
        output_path = os.path.join(base_dir, output_filename)
        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        log("info", f"Output path: {output_path}")

        plugin_dir = _plugin_dir
        template_path = opts.get("template") or os.path.join(plugin_dir, "templates", "report.md")
        css_path = opts.get("template_css")
        if css_path and not os.path.isabs(css_path):
            css_path = os.path.join(plugin_dir, css_path)
        allow_commands = bool(opts.get("allow_commands", False))

        use_template = TEMPLATE_AVAILABLE and os.path.isfile(template_path)
        if use_template:
            try:
                context = build_template_context(findings, metrics, opts.get("workspace_root", ""))
                pdf_path = create_pdf_from_template(
                    template_path,
                    css_path or os.path.join(plugin_dir, "templates", "report.css"),
                    context,
                    output_path,
                    plugin_dir,
                    allow_commands=allow_commands,
                )
            except Exception as e:
                log("warning", f"Template PDF failed ({e}), falling back to built-in report")
                pdf_path = create_pdf_report(
                    findings,
                    metrics,
                    output_path,
                    workspace_root=opts.get("workspace_root", ""),
                    plugin_dir=plugin_dir,
                )
        else:
            if not TEMPLATE_AVAILABLE:
                log("info", "Template engine unavailable (install markdown, weasyprint); using built-in report")
            pdf_path = create_pdf_report(
                findings,
                metrics,
                output_path,
                workspace_root=opts.get("workspace_root", ""),
                plugin_dir=plugin_dir,
            )

        with open(pdf_path, "rb") as f:
            pdf_content = f.read()

        pdf_b64 = base64.b64encode(pdf_content).decode("utf-8")
        elapsed_ms = int((time.time() - t0) * 1000)
        log("info", f"PDF report generated: {pdf_path}")

        return {
            "report_path": pdf_path,
            "report_content_b64": pdf_b64,
            "report_type": "application/pdf",
            "metrics": {
                "findings_processed": len(findings),
                "unique_findings": len(group_findings(findings)),
                "pdf_size_bytes": len(pdf_content),
                "ms": elapsed_ms,
            },
        }
    except Exception as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        log("error", f"Failed to generate PDF report: {str(e)}")
        return {"error": f"Failed to generate PDF report: {str(e)}", "metrics": {"ms": elapsed_ms}}


def signal_handler(signum, frame):
    sys.exit(0)


signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

opts = {"workspace_root": "", "output": "reports/report.pdf"}

try:
    for line in sys.stdin:
        msg = json.loads(line)
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})

        if method == "plugin.init":
            send(mid, handle_init(params))
        elif method == "scan.report":
            send(mid, handle_report(params))
        elif method == "plugin.ping":
            send(mid, {"pong": True})
        elif method == "plugin.shutdown":
            send(mid, {"ok": True})
            break
        else:
            send(mid, None, {"code": -32601, "message": "Method not found"})
except (BrokenPipeError, KeyboardInterrupt, OSError):
    sys.exit(0)
