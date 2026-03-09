"""Dependency analysis via Syft (SBOM, CycloneDX) and Grype (vulns). No Node.js."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Callable

from .filters import severity_for_vuln

# Map Grype severity to our levels (INFO, LOW, MEDIUM, HIGH, CRITICAL)
GRYPE_SEVERITY = {
    "Unknown": "INFO",
    "Negligible": "LOW",
    "Low": "LOW",
    "Medium": "MEDIUM",
    "High": "HIGH",
    "Critical": "CRITICAL",
}


def _license_from_component(component: dict[str, Any]) -> str:
    """Extract license string from CycloneDX component (licenses array: id or name)."""
    licenses = component.get("licenses") or []
    parts = []
    for lic_entry in licenses:
        lic = lic_entry.get("license") if isinstance(lic_entry, dict) else None
        if not lic:
            continue
        if isinstance(lic, dict):
            lid = lic.get("id") or lic.get("name") or ""
            if lid:
                parts.append(lid.strip())
        elif isinstance(lic, str):
            parts.append(lic.strip())
    return "; ".join(parts) if parts else ""


def _ecosystem_from_purl(purl: str) -> str:
    """Extract ecosystem from purl (pkg:type/name@version)."""
    if not purl or not purl.startswith("pkg:"):
        return ""
    try:
        rest = purl[4:]
        typ = rest.split("/")[0].split("@")[0].lower()
        if typ in ("npm", "nodejs"):
            return "npm"
        if typ in ("pypi", "python"):
            return "PyPI"
        if typ in ("golang", "go"):
            return "Go"
        if typ in ("cargo", "crates.io", "rust"):
            return "crates.io"
        if typ in ("maven", "composer", "gem", "nuget"):
            return typ
        return typ
    except Exception:
        return ""


def run_syft(
    workspace_root: str,
    syft_path: str,
    log_fn: Callable[[str, str], None] | None,
    timeout_sec: int = 300,
) -> str | None:
    """Run Syft to generate CycloneDX SBOM from directory. Returns path to SBOM JSON or None (binary, no Node)."""
    if not syft_path or not os.path.isfile(syft_path):
        if log_fn:
            log_fn("warn", "Syft not found. Dependency SBOM/vuln analysis skipped. Run ./install.sh or set panorama.syft_path.")
        return None
    workspace_abs = os.path.abspath(workspace_root)
    if not os.path.isdir(workspace_abs):
        if log_fn:
            log_fn("warn", f"Workspace not a directory: {workspace_abs}")
        return None
    fd, out_path = tempfile.mkstemp(suffix=".cyclonedx.json")
    os.close(fd)
    try:
        if log_fn:
            log_fn("info", "Generating SBOM with Syft...")
        # syft dir:<path> -o cyclonedx-json=<file>
        cmd = [syft_path, f"dir:{workspace_abs}", "-o", f"cyclonedx-json={out_path}"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        if result.returncode != 0:
            if log_fn:
                stderr = (result.stderr or "").strip()[:500]
                log_fn("warn", f"Syft failed: {stderr}")
            os.unlink(out_path)
            return None
        if not os.path.isfile(out_path) or os.path.getsize(out_path) == 0:
            if log_fn:
                log_fn("warn", "Syft produced no SBOM file")
            if os.path.isfile(out_path):
                os.unlink(out_path)
            return None
        return out_path
    except subprocess.TimeoutExpired:
        if log_fn:
            log_fn("warn", f"Syft timed out after {timeout_sec}s")
        if os.path.isfile(out_path):
            os.unlink(out_path)
        return None
    except Exception as e:
        if log_fn:
            log_fn("warn", f"Syft error: {e}")
        if os.path.isfile(out_path):
            os.unlink(out_path)
        return None


def run_grype(
    sbom_path: str,
    grype_path: str,
    log_fn: Callable[[str, str], None] | None,
    timeout_sec: int = 300,
) -> dict[str, Any] | None:
    """Run Grype on SBOM file. Returns Grype JSON dict or None."""
    if not grype_path or not os.path.isfile(grype_path):
        if log_fn:
            log_fn("warn", "Grype not found. Vulnerability scan skipped. Run ./install.sh or set panorama.grype_path.")
        return None
    if not os.path.isfile(sbom_path):
        return None
    try:
        if log_fn:
            log_fn("info", "Running Grype on SBOM...")
        # sbom:path format for Grype
        cmd = [grype_path, f"sbom:{sbom_path}", "-o", "json", "--by-cve"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        if result.returncode != 0:
            if log_fn:
                stderr = (result.stderr or "").strip()[:500]
                log_fn("warn", f"Grype failed: {stderr}")
            return None
        data = json.loads(result.stdout or "{}")
        return data
    except subprocess.TimeoutExpired:
        if log_fn:
            log_fn("warn", f"Grype timed out after {timeout_sec}s")
        return None
    except json.JSONDecodeError as e:
        if log_fn:
            log_fn("warn", f"Grype output not valid JSON: {e}")
        return None
    except Exception as e:
        if log_fn:
            log_fn("warn", f"Grype error: {e}")
        return None


def sbom_from_cyclonedx(bom_path: str) -> list[dict[str, Any]]:
    """Parse CycloneDX BOM and return list of components in our internal format."""
    out: list[dict[str, Any]] = []
    try:
        with open(bom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return out
    components = data.get("components") or []
    for c in components:
        name = c.get("name") or ""
        version = c.get("version") or ""
        purl = c.get("purl") or ""
        ecosystem = _ecosystem_from_purl(purl) or "unknown"
        license_str = _license_from_component(c)
        out.append({
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "file": "",
            "line": 0,
            "license": license_str,
        })
    return out


def vulns_from_grype(
    grype_data: dict[str, Any],
    state: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Convert Grype matches to our vulns list and findings. Returns (vulns, findings)."""
    vulns: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    matches = grype_data.get("matches") or []
    finding_id = state.get("finding_id", 0)

    for m in matches:
        vuln = m.get("vulnerability") or {}
        artifact = m.get("artifact") or {}
        vid = vuln.get("id") or vuln.get("vulnerabilityID") or vuln.get("VulnerabilityID") or ""
        name = artifact.get("name") or ""
        version = artifact.get("version") or ""
        purl = artifact.get("purl") or artifact.get("PURL") or ""
        ecosystem = _ecosystem_from_purl(purl) or "unknown"
        grype_sev = (vuln.get("severity") or vuln.get("Severity") or "Unknown")
        grype_sev = grype_sev.capitalize() if isinstance(grype_sev, str) else "Unknown"
        severity = GRYPE_SEVERITY.get(grype_sev, severity_for_vuln(vid))
        description = (vuln.get("description") or vuln.get("summary") or "").strip()
        if len(description) > 4000:
            description = description[:3997] + "..."

        fix_obj = vuln.get("fix") or {}
        fix_versions = fix_obj.get("versions") or fix_obj.get("Versions") or []
        fixed_in = ", ".join(str(v) for v in fix_versions[:5]) if isinstance(fix_versions, list) else ""
        if not fixed_in and fix_obj.get("state") == "wont-fix":
            fixed_in = "(won't fix)"

        urls = vuln.get("urls") or vuln.get("relatedUrls") or vuln.get("URLs") or []
        if isinstance(urls, list) and urls:
            ref_url = urls[0] if isinstance(urls[0], str) else urls[0].get("url") or urls[0].get("URL") or ""
        else:
            ref_url = ""
        if not ref_url and vid.startswith("GHSA-"):
            ref_url = f"https://github.com/advisories/{vid}"
        elif not ref_url and vid.startswith("CVE-"):
            ref_url = f"https://nvd.nist.gov/vuln/detail/{vid}"

        published = vuln.get("published") or vuln.get("publishedDate") or vuln.get("PublishedDate") or ""
        modified = vuln.get("updated") or vuln.get("updatedDate") or vuln.get("ModifiedDate") or ""

        vulns.append({
            "vuln_id": vid,
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "file": "",
            "line": 0,
            "severity": severity,
            "description": description,
            "fixed_in": fixed_in,
            "published": str(published)[:20] if published else "",
            "modified": str(modified)[:20] if modified else "",
            "references": ref_url,
        })
        finding_id += 1
        findings.append({
            "id": f"deps-{finding_id}",
            "rule_id": "deps.vulnerability",
            "rule_file": None,
            "severity": severity,
            "file": "",
            "line": 0,
            "column": 1,
            "excerpt": vid,
            "message": f"Known vulnerability {vid} in {name}@{version}",
            "remediation": "Update to a patched version or apply vendor advisory.",
            "fix": None,
        })

    state["finding_id"] = finding_id
    return vulns, findings


def resolve_tool_path(opt_path: str, plugin_dir: str, default_relative: str) -> str:
    """Resolve tool path, preferring user PATH over plugin-local ./bin.

    Rules:
      - If opt_path is set:
          * Absolute path -> use as-is.
          * If contains a path separator -> treat as relative to plugin_dir.
          * Otherwise: first try PATH (shutil.which), else plugin_dir/opt_path.
      - If opt_path is empty:
          * Try to find the executable name (basename of default_relative) on PATH.
          * Fallback to plugin_dir/default_relative.
    """
    p = (opt_path or "").strip()
    if p:
        if os.path.isabs(p):
            return p
        # If user passed something that looks like a path, resolve against plugin_dir
        if os.sep in p or (os.path.altsep and os.path.altsep in p):
            return os.path.abspath(os.path.join(plugin_dir, p))
        # Bare command name: prefer PATH
        found = shutil.which(p)
        if found:
            return found
        return os.path.abspath(os.path.join(plugin_dir, p))

    # No explicit path: prefer PATH for the tool name, then plugin ./bin
    tool_name = os.path.basename(default_relative)
    found = shutil.which(tool_name)
    if found:
        return found
    return os.path.abspath(os.path.join(plugin_dir, default_relative))
