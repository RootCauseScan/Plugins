"""Optional Trivy integration: scan images for CVEs."""
from __future__ import annotations

import json
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
) -> list[dict[str, Any]]:
    """
    Run trivy image --format json --scanners vuln. Returns list of vuln dicts:
    {vulnerability_id, pkg_name, severity, ...}.
    Uses --exit-code 0 so Trivy always returns 0 and full JSON is on stdout.
    """
    try:
        out = subprocess.run(
            [
                trivy_path,
                "image",
                "--format", "json",
                "--scanners", "vuln",
                "--quiet",
                "--exit-code", "0",
                image_ref,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        if log_fn:
            log_fn("warn", f"[infra] Trivy timed out for {image_ref}")
        return []
    except FileNotFoundError:
        return []
    except Exception as e:
        if log_fn:
            log_fn("warn", f"[infra] Trivy error for {image_ref}: {e}")
        return []
    # Trivy may write JSON to stdout (or in some setups to stderr); parse both
    vulns = _parse_trivy_json(out.stdout or "")
    if not vulns and (out.stderr or "").strip():
        vulns = _parse_trivy_json(out.stderr.strip())
    # When 0 vulns, check if Trivy failed (e.g. OOM when run as subprocess)
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
    return vulns
