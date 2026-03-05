"""Manifest/lock file discovery for the discover phase."""
from __future__ import annotations

import os
from typing import Any

MANIFEST_NAMES = frozenset({
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml",
    "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
})


def is_manifest(path: str) -> bool:
    base = os.path.basename(path)
    if "/virtual/" in path:
        base = base.split("-")[0] if "-" in base else base
    return base in MANIFEST_NAMES


def discover_manifests(root: str, base_path: str, max_depth: int | None) -> list[dict[str, Any]]:
    start = os.path.join(root, base_path) if not os.path.isabs(base_path) else base_path
    start = os.path.abspath(start)
    root_abs = os.path.abspath(root)
    if not os.path.isdir(start):
        return []
    start_depth = len(start.split(os.sep))
    files: list[dict[str, Any]] = []
    for dirpath, _, filenames in os.walk(start):
        if max_depth is not None:
            depth = len(os.path.abspath(dirpath).split(os.sep)) - start_depth
            if depth > max_depth:
                continue
        for name in filenames:
            if name not in MANIFEST_NAMES:
                continue
            full = os.path.abspath(os.path.join(dirpath, name))
            try:
                common = os.path.commonpath([root_abs, full])
            except ValueError:
                common = None
            if common == root_abs:
                rel = os.path.relpath(full, root_abs)
            else:
                rel = full
            lang = "json" if name.endswith(".json") else "toml" if name.endswith(".toml") else "text"
            files.append({"path": rel.replace(os.sep, "/"), "language": lang})
    return files
