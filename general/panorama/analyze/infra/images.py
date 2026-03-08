"""Optional Trivy integration: scan images for CVEs."""
from __future__ import annotations

import json
import os
import signal
import subprocess
from typing import Any, Callable

# Severity mapping Trivy -> RootCause (INFO, LOW, MEDIUM, HIGH, CRITICAL, ERROR)
TRIVY_TO_SEVERITY = {
    "UNKNOWN": "INFO",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}


def _parse_trivy_json(json_str: str) -> list[dict[str, Any]]:
    """Parse Trivy JSON and return list of vuln dicts."""
    vulns: list[dict[str, Any]] = []
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        return vulns
    # Trivy JSON: { "Results": [ { "Vulnerabilities": [ {...} ] } ] }
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or v.get("ID") or ""
            pkg = v.get("PkgName") or ""
            sev = (v.get("Severity") or "UNKNOWN").upper()
            vulns.append({
                "vulnerability_id": vid,
                "pkg_name": pkg,
                "severity": TRIVY_TO_SEVERITY.get(sev, "INFO"),
                "title": v.get("Title") or "",
                "description": v.get("Description") or "",
            })
    return vulns


def scan_image_trivy(
    image_ref: str,
    trivy_path: str,
    timeout_sec: int,
    log_fn: Callable[[str, str], None] | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """
    Run trivy image --format json --scanners vuln. Returns (vulns, timed_out).
    Timeout is enforced by this code (supervisor); we kill the process (and its group) after timeout_sec.
    """
    timeout_sec = max(1, timeout_sec)
    cmd = [
        trivy_path,
        "image",
        "--format", "json",
        "--scanners", "vuln",
        "--quiet",
        "--exit-code", "0",
        image_ref,
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=(os.name != "nt"),
        )
    except FileNotFoundError:
        return ([], False)
    try:
        stdout, stderr = proc.communicate(timeout=timeout_sec)
        out = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        if log_fn:
            log_fn("warn", f"[infra] Trivy reached timeout ({timeout_sec}s) for {image_ref}. Scan skipped.")
        try:
            if os.name != "nt":
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, OSError):
            pass
        proc.wait()
        return ([], True)
    except Exception as e:
        if log_fn:
            log_fn("warn", f"[infra] Trivy error for {image_ref}: {e}")
        try:
            proc.kill()
            proc.wait()
        except (ProcessLookupError, OSError):
            pass
        return ([], False)
    # Trivy may write JSON to stdout (or in some setups to stderr); parse both
    vulns = _parse_trivy_json(out.stdout or "")
    if not vulns and (out.stderr or "").strip():
        vulns = _parse_trivy_json(out.stderr.strip())
    # When 0 vulns, check if Trivy failed (e.g. OOM)
    if not vulns and log_fn and out.returncode != 0:
        stderr = (out.stderr or "").strip()
        if "failed to reserve page summary memory" in stderr or "fatal error" in stderr:
            log_fn(
                "warn",
                f"[infra] Trivy crashed for {image_ref} (e.g. out-of-memory when run as subprocess). "
                "Run Trivy manually for this image or increase memory for the scan process.",
            )
        elif stderr and len(stderr) <= 400:
            log_fn("info", f"[infra] Trivy stderr for {image_ref}: {stderr}")
        elif stderr:
            log_fn("info", f"[infra] Trivy stderr for {image_ref} (first 300 chars): {stderr[:300]}")
    return (vulns, False)
