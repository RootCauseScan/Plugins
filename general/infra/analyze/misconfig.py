"""Emit finding dicts for misconfigurations (unpinned image, run as root, etc.)."""
from __future__ import annotations

from typing import Any, Callable


def _finding(
    finding_id: str,
    rule_id: str,
    severity: str,
    file_path: str,
    line: int,
    message: str,
    excerpt: str = "",
    remediation: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out = {
        "id": finding_id,
        "rule_id": rule_id,
        "rule_file": None,
        "severity": severity,
        "file": file_path,
        "line": max(1, line),
        "column": 1,
        "excerpt": excerpt or message,
        "message": message,
        "remediation": remediation,
        "fix": None,
    }
    if extra:
        out.update(extra)
    return out


def check_dockerfile_misconfig(
    file_path: str,
    parsed: dict[str, Any],
    finding_id_fn: Callable[[], str],
    check_healthcheck: bool,
) -> list[dict[str, Any]]:
    findings = []
    for img in parsed.get("images") or []:
        ref = img.get("image_ref") or ""
        line = img.get("line") or 0
        if not ref or ":" not in ref and "@" not in ref:
            findings.append(_finding(
                finding_id_fn(),
                "infra.image-unpinned",
                "MEDIUM",
                file_path,
                line,
                "Image has no tag or digest; use a pinned reference (e.g. image:1.2.3 or image@sha256:...)",
                ref,
                "Pin to a specific tag or digest.",
            ))
        elif ":latest" in ref.split("@")[0].rstrip(":"):
            findings.append(_finding(
                finding_id_fn(),
                "infra.image-unpinned",
                "MEDIUM",
                file_path,
                line,
                "Avoid using the 'latest' tag; use a specific version.",
                ref,
                "Use a specific tag (e.g. alpine:3.18).",
            ))
    if parsed.get("user_root"):
        line = 0
        for ln in parsed.get("lines") or []:
            if ln.get("instruction") == "USER":
                line = ln.get("line_num") or 0
                break
        findings.append(_finding(
            finding_id_fn(),
            "infra.runs-as-root",
            "HIGH",
            file_path,
            line or 1,
            "Container runs as root user; use a non-root USER for security.",
            "USER root",
            "Add a non-root user and use USER <name>.",
        ))
    if check_healthcheck and not parsed.get("has_healthcheck") and parsed.get("images"):
        findings.append(_finding(
            finding_id_fn(),
            "infra.no-healthcheck",
            "LOW",
            file_path,
            1,
            "Dockerfile has no HEALTHCHECK instruction.",
            "",
            "Add HEALTHCHECK to improve orchestration and monitoring.",
        ))
    if parsed.get("has_add"):
        line = 0
        for ln in parsed.get("lines") or []:
            if ln.get("instruction") == "ADD":
                line = ln.get("line_num") or 0
                break
        findings.append(_finding(
            finding_id_fn(),
            "infra.dockerfile-use-add",
            "MEDIUM",
            file_path,
            line or 1,
            "Use COPY instead of ADD for local files (ADD has unexpected extraction behavior).",
            "ADD ",
            "Replace ADD with COPY for local context files.",
        ))
    return findings


def check_compose_misconfig(
    file_path: str,
    parsed: dict[str, Any],
    finding_id_fn: Callable[[], str],
) -> list[dict[str, Any]]:
    findings = []
    for img in parsed.get("images") or []:
        ref = img.get("image_ref") or ""
        line = img.get("line") or 0
        if not ref or ("." not in ref and "/" not in ref):
            continue
        if ":" not in ref and "@" not in ref:
            findings.append(_finding(
                finding_id_fn(),
                "infra.image-unpinned",
                "MEDIUM",
                file_path,
                line,
                "Service image has no tag or digest; pin to a specific version.",
                ref,
                "Use image:tag or image@digest.",
            ))
        elif ":latest" in ref.split("@")[0].rstrip(":"):
            findings.append(_finding(
                finding_id_fn(),
                "infra.image-unpinned",
                "MEDIUM",
                file_path,
                line,
                "Avoid 'latest' tag; use a specific version.",
                ref,
                "Use a specific tag.",
            ))
    return findings


def check_kubernetes_misconfig(
    file_path: str,
    parsed: dict[str, Any],
    finding_id_fn: Callable[[], str],
) -> list[dict[str, Any]]:
    findings = []
    for img in parsed.get("images") or []:
        ref = img.get("image_ref") or ""
        line = img.get("line") or 0
        if ":" not in ref and "@" not in ref and ref:
            findings.append(_finding(
                finding_id_fn(),
                "infra.image-unpinned",
                "MEDIUM",
                file_path,
                line,
                "Container image has no tag or digest; pin to a specific version.",
                ref,
                "Use image:tag or image@digest.",
            ))
        elif ":latest" in (ref.split("@")[0].rstrip(":") if ref else ""):
            findings.append(_finding(
                finding_id_fn(),
                "infra.image-unpinned",
                "MEDIUM",
                file_path,
                line,
                "Avoid 'latest' tag; use a specific version.",
                ref,
                "Use a specific tag.",
            ))
    for r in parsed.get("run_as_root") or []:
        findings.append(_finding(
            finding_id_fn(),
            "infra.runs-as-root",
            "HIGH",
            file_path,
            r.get("line") or 0,
            f"Container '{r.get('container_name', '')}' runs as root (runAsNonRoot: false or runAsUser: 0).",
            "securityContext",
            "Set runAsNonRoot: true or runAsUser to a non-zero UID.",
        ))
    for p in parsed.get("privileged") or []:
        findings.append(_finding(
            finding_id_fn(),
            "infra.privileged-container",
            "HIGH",
            file_path,
            p.get("line") or 0,
            f"Container '{p.get('container_name', '')}' is privileged.",
            "privileged: true",
            "Avoid privileged containers unless strictly required.",
        ))
    return findings


_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _max_severity(severities: list[str]) -> str:
    if not severities:
        return "MEDIUM"
    return max(severities, key=lambda s: _SEVERITY_ORDER.get(s.upper(), -1))


def finding_for_image_cves_aggregated(
    finding_id: str,
    file_path: str,
    line: int,
    image_ref: str,
    vulns: list[dict[str, Any]],
    max_bullets: int = 50,
) -> dict[str, Any]:
    """One finding per image with a bullet list of CVEs in the message (avoids flooding text output)."""
    n = len(vulns)
    if n == 0:
        return _finding(
            finding_id,
            "infra.image-vulnerability",
            "INFO",
            file_path,
            line,
            f"Image {image_ref}: no vulnerabilities reported.",
            "",
            None,
        )
    severity = _max_severity([v.get("severity") or "MEDIUM" for v in vulns])
    bullets = []
    for v in vulns[:max_bullets]:
        vid = v.get("vulnerability_id") or "CVE-???"
        pkg = v.get("pkg_name") or ""
        sev = (v.get("severity") or "MEDIUM").upper()
        bullets.append(f"  • {vid}" + (f" ({pkg})" if pkg else "") + f" {sev}")
    msg_lines = [f"Image {image_ref}: {n} vulnerability(ies):", ""] + bullets
    if n > max_bullets:
        msg_lines.append(f"  … and {n - max_bullets} more (see JSON report for full list).")
    message = "\n".join(msg_lines)
    excerpt = vulns[0].get("vulnerability_id") or "CVE"  # first CVE as excerpt
    return _finding(
        finding_id,
        "infra.image-vulnerability",
        severity,
        file_path,
        line,
        message,
        excerpt,
        "Update base image or rebuild with patched packages.",
        extra={"vulnerabilities": vulns, "image_ref": image_ref},
    )
