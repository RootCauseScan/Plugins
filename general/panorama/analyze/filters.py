"""Filter SBOM and vulns by ecosystem and severity."""
from __future__ import annotations

_SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "ERROR")


def severity_for_vuln(vuln_id: str) -> str:
    if vuln_id.startswith("CVE-") or vuln_id.startswith("GHSA-"):
        return "HIGH"
    return "MEDIUM"


def severity_at_least(sev: str, min_sev: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(sev) >= _SEVERITY_ORDER.index(min_sev)
    except ValueError:
        return True


def filter_sbom(sbom: list[dict], ecosystems: list[str], exclude: list[str]) -> list[dict]:
    out = sbom
    if ecosystems:
        out = [c for c in out if c.get("ecosystem") in ecosystems]
    if exclude:
        out = [c for c in out if c.get("ecosystem") not in exclude]
    return out


def filter_vulns(
    vulns: list[dict],
    min_severity: str,
    ecosystems: list[str],
    exclude: list[str],
) -> list[dict]:
    out = vulns
    if ecosystems:
        out = [v for v in out if v.get("ecosystem") in ecosystems]
    if exclude:
        out = [v for v in out if v.get("ecosystem") not in exclude]
    if min_severity and min_severity != "INFO":
        out = [
            v for v in out
            if severity_at_least(
                v.get("severity") or severity_for_vuln(v.get("vuln_id", "")),
                min_severity,
            )
        ]
    return out
