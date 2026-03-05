"""Parse dependency manifest/lock files. Returns list of (name, version, line, excerpt)."""
from __future__ import annotations

import json
import re
from typing import Any


def parse_package_json(data: bytes) -> list[tuple[str, str, int, str]]:
    out: list[tuple[str, str, int, str]] = []
    try:
        obj = json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return out
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps = obj.get(key, {})
        if not isinstance(deps, dict):
            continue
        for name, ver in deps.items():
            if isinstance(ver, str):
                ver = re.sub(r"^[\^~>=<]", "", ver.strip())
                out.append((name, ver, 1, f"{name}: {ver}"))
    return out


def parse_requirements_txt(data: bytes) -> list[tuple[str, str, int, str]]:
    out: list[tuple[str, str, int, str]] = []
    for i, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, ver = line.split("==", 1)
            out.append((name.strip(), ver.strip(), i, line))
    return out


def parse_go_mod(data: bytes) -> list[tuple[str, str, int, str]]:
    out: list[tuple[str, str, int, str]] = []
    for i, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
        line = line.strip()
        if line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                out.append((parts[1], parts[2].lstrip("v"), i, line))
        elif line and not line.startswith("//") and " " in line:
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("("):
                out.append((parts[0], parts[1].lstrip("v"), i, line))
    return out


def parse_cargo_toml(data: bytes) -> list[tuple[str, str, int, str]]:
    out: list[tuple[str, str, int, str]] = []
    text = data.decode("utf-8", errors="replace")
    deps_section = False
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("[dependencies") or stripped == "[dependencies]":
            deps_section = True
            continue
        if stripped.startswith("[") and deps_section:
            break
        if not deps_section or "=" not in stripped:
            continue
        m = re.match(r'^(\w+)\s*=\s*"([^"]+)"', stripped)
        if m:
            name, ver = m.group(1), m.group(2)
            if not ver.startswith("{"):
                out.append((name, ver, i, f'{name} = "{ver}"'))
            continue
        m = re.match(r'^(\w+)\s*=\s*\{', stripped)
        if m:
            name = m.group(1)
            ver_match = re.search(r'version\s*=\s*"([^"]+)"', stripped)
            if ver_match:
                ver = ver_match.group(1)
                out.append((name, ver, i, stripped[:80]))
    return out


def parse_cargo_lock(data: bytes) -> list[tuple[str, str, int, str]]:
    out: list[tuple[str, str, int, str]] = []
    in_pkg = False
    name = ""
    for i, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
        s = line.strip()
        if s == "[[package]]":
            in_pkg = True
            name = ""
            continue
        if in_pkg and s.startswith("name = "):
            name = s.split("=", 1)[1].strip().strip('"')
        elif in_pkg and s.startswith("version = ") and name:
            ver = s.split("=", 1)[1].strip().strip('"')
            out.append((name, ver, i, f"{name} = {ver}"))
            name = ""
        if s.startswith("[") and s != "[[package]]":
            in_pkg = False
    return out
