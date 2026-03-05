"""OSV API: batch query for vuln IDs and fetch description per vuln."""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any

_osv_cache: dict[tuple[str, str, str], list[str]] = {}
_osv_details_cache: dict[str, str] = {}
_OSV_BATCH_CHUNK = 100


def query_osv_batch(deps: list[tuple[str, str, str]]) -> list[list[str]]:
    """Query OSV for many (ecosystem, name, version). Returns list of vuln id lists (same order as deps)."""
    results: list[list[str]] = []
    to_fetch: list[tuple[int, tuple[str, str, str]]] = []
    for i, key in enumerate(deps):
        if key in _osv_cache:
            results.append(_osv_cache[key])
        else:
            results.append([])
            to_fetch.append((i, key))
    if not to_fetch:
        return results
    for chunk_start in range(0, len(to_fetch), _OSV_BATCH_CHUNK):
        chunk = to_fetch[chunk_start : chunk_start + _OSV_BATCH_CHUNK]
        queries = [
            {"package": {"name": name, "ecosystem": eco}, "version": ver}
            for _, (eco, name, ver) in chunk
        ]
        body = json.dumps({"queries": queries}).encode("utf-8")
        try:
            req = urllib.request.Request(
                "https://api.osv.dev/v1/querybatch",
                data=body,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode())
                batch_results = data.get("results", [])
                for (idx, key), res in zip(chunk, batch_results):
                    ids = [v["id"] for v in res.get("vulns", [])]
                    _osv_cache[key] = ids
                    results[idx] = ids
        except Exception:
            for idx, key in chunk:
                _osv_cache[key] = []
    return results


def fetch_vuln_description(vuln_id: str) -> str:
    if vuln_id in _osv_details_cache:
        return _osv_details_cache[vuln_id]
    try:
        req = urllib.request.Request(
            f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vuln_id, safe='')}",
            method="GET",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
        summary = (data.get("summary") or "").strip()
        details = (data.get("details") or "").strip()
        desc = summary or details
        if len(desc) > 4000:
            desc = desc[:3997] + "..."
        _osv_details_cache[vuln_id] = desc
        return desc
    except Exception:
        _osv_details_cache[vuln_id] = ""
        return ""


def enrich_vulns_descriptions(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    for v in vulns:
        vid = v.get("vuln_id", "")
        if vid and vid not in seen:
            seen.add(vid)
            fetch_vuln_description(vid)
    for v in vulns:
        vid = v.get("vuln_id", "")
        v["description"] = _osv_details_cache.get(vid, "") if vid else ""
    return vulns
