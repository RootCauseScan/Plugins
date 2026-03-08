"""Analyze phase: dispatch by file type, collect images, run misconfig + optional Trivy."""
from __future__ import annotations

import base64
import os
import subprocess
from typing import Any

from . import dockerfile as df
from . import compose as comp
from . import kubernetes as k8s
from . import misconfig
from . import images as img_module


def _next_id(state: dict[str, Any]) -> str:
    state["finding_id"] = state.get("finding_id", 0) + 1
    return f"infra-{state['finding_id']}"


def _file_type(path: str, content: str) -> str:
    base = os.path.basename(path).lower()
    if "dockerfile" in base or base == "containerfile":
        return "dockerfile"
    if "compose" in base or "docker-compose" in base:
        return "compose"
    return "kubernetes"


def analyze_files(files: list[dict[str, Any]], state: dict[str, Any]) -> list[dict[str, Any]]:
    """Process infra files: parse, extract images, misconfig, optional Trivy; return findings."""
    all_findings: list[dict[str, Any]] = []
    opts = state.get("options") or {}
    scan_images = opts.get("scan_images") is True
    trivy_path = opts.get("trivy_path") or "trivy"
    trivy_timeout = int(opts.get("trivy_timeout_sec") or 300)
    check_healthcheck = opts.get("check_healthcheck", True)
    # Accumulate across multiple file.analyze calls (CLI sends one file per call)
    images_registry: list[dict[str, Any]] = state.setdefault("images", [])

    def next_id() -> str:
        return _next_id(state)

    for f in files:
        path = f.get("path") or ""
        if not path:
            continue
        content_b64 = f.get("content_b64")
        if not content_b64:
            continue
        try:
            content = base64.standard_b64decode(content_b64).decode("utf-8", errors="replace")
        except Exception:
            continue
        ftype = _file_type(path, content)
        if ftype == "dockerfile":
            parsed = df.parse_dockerfile(content, path)
            for im in parsed.get("images") or []:
                images_registry.append({
                    "file": path,
                    "line": im.get("line"),
                    "image_ref": im.get("image_ref"),
                    "source": "from",
                })
            all_findings.extend(misconfig.check_dockerfile_misconfig(
                path, parsed, next_id, check_healthcheck
            ))
        elif ftype == "compose":
            parsed = comp.parse_compose(content, path)
            for im in parsed.get("images") or []:
                images_registry.append({
                    "file": path,
                    "line": im.get("line"),
                    "image_ref": im.get("image_ref"),
                    "source": "compose",
                    "service": im.get("service_name"),
                })
            all_findings.extend(misconfig.check_compose_misconfig(path, parsed, next_id))
        else:
            parsed = k8s.parse_kubernetes(content, path)
            for im in parsed.get("images") or []:
                images_registry.append({
                    "file": path,
                    "line": im.get("line"),
                    "image_ref": im.get("image_ref"),
                    "source": "k8s",
                    "container": im.get("container_name"),
                })
            all_findings.extend(misconfig.check_kubernetes_misconfig(path, parsed, next_id))

    if scan_images:
        log_fn = state.get("log")
        # Check Trivy is available
        try:
            subprocess.run(
                [trivy_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except FileNotFoundError:
            if log_fn:
                log_fn("warn", f"Trivy not found (infra.trivy_path={trivy_path}). Image vulnerability scan skipped. Install Trivy or set infra.trivy_path.")
        except subprocess.TimeoutExpired:
            if log_fn:
                log_fn("warn", "Trivy --version timed out; image scan skipped.")
        else:
            seen_refs: set[str] = set()
            unique_refs = []
            for ent in images_registry:
                ref = (ent.get("image_ref") or "").strip()
                if not ref or ref in seen_refs:
                    continue
                seen_refs.add(ref)
                unique_refs.append((ref, ent))
            scanned_refs = state.setdefault("scanned_image_refs", set())
            to_scan = [(ref, ent) for ref, ent in unique_refs if ref not in scanned_refs]
            if log_fn and to_scan:
                log_fn("info", f"Scanning {len(to_scan)} image(s) with Trivy for vulnerabilities...")
            for ref, ent in to_scan:
                if log_fn:
                    log_fn(
                        "info",
                        f"  Scanning image: {ref} (may take 1–5 min for large images, timeout={trivy_timeout}s)",
                    )
                vulns = img_module.scan_image_trivy(ref, trivy_path, trivy_timeout, log_fn=log_fn)
                scanned_refs.add(ref)
                if log_fn:
                    log_fn("info", f"    {ref}: {len(vulns)} vulnerability(ies) found")
                if vulns:
                    fid = next_id()
                    finding = misconfig.finding_for_image_cves_aggregated(
                        fid,
                        ent.get("file") or path,
                        ent.get("line") or 0,
                        ref,
                        vulns,
                    )
                    all_findings.append(finding)

    # Extend state; avoid duplicate image-vulnerability findings for the same image_ref
    existing = state.setdefault("findings_infra", [])
    seen_image_refs = {f.get("image_ref") for f in existing if f.get("rule_id") == "infra.image-vulnerability"}
    for f in all_findings:
        if f.get("rule_id") == "infra.image-vulnerability" and f.get("image_ref") in seen_image_refs:
            continue
        if f.get("rule_id") == "infra.image-vulnerability":
            seen_image_refs.add(f.get("image_ref"))
        existing.append(f)
    return all_findings
