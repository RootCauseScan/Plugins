"""Discover container and orchestration files: Dockerfile, Containerfile, compose, K8s."""
from __future__ import annotations

import os
import fnmatch
from typing import Any

# Exact filenames (case-sensitive as typically used)
DOCKERFILE_NAMES = frozenset({
    "Dockerfile",
    "Containerfile",
})
# Suffix patterns: Dockerfile.*, Containerfile.*, *.dockerfile
DOCKERFILE_PATTERNS = ("Dockerfile.*", "Containerfile.*", "*.dockerfile")

COMPOSE_NAMES = frozenset({
    "docker-compose.yml", "docker-compose.yaml",
    "compose.yml", "compose.yaml",
})
COMPOSE_PATTERNS = ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml")

# Directories that often contain K8s/OpenShift manifests
K8S_DIR_NAMES = frozenset({"k8s", "openshift", "manifests", "deploy", "base", "kubernetes"})
# Filenames that often indicate K8s manifests
K8S_FILE_NAMES = frozenset({
    "deployment.yaml", "deployment.yml", "deploy.yaml", "deploy.yml",
    "pod.yaml", "pod.yml", "service.yaml", "service.yml",
    "daemonset.yaml", "statefulset.yaml", "configmap.yaml",
    "route.yaml", "buildconfig.yaml", "template.yaml",
})


def _matches_patterns(name: str, patterns: tuple[str, ...]) -> bool:
    for p in patterns:
        if fnmatch.fnmatch(name, p):
            return True
    return False


def is_infra_file(path: str) -> bool:
    """Return True if path is a container/orchestration file we handle."""
    base = os.path.basename(path)
    dirs = path.replace("\\", "/").split("/")
    if base in DOCKERFILE_NAMES or base in COMPOSE_NAMES or base in K8S_FILE_NAMES:
        return True
    if _matches_patterns(base, DOCKERFILE_PATTERNS) or _matches_patterns(base, COMPOSE_PATTERNS):
        return True
    if base.endswith(".yaml") or base.endswith(".yml"):
        if any(d in K8S_DIR_NAMES for d in dirs):
            return True
    return False


def _language_for_path(path: str) -> str:
    base = os.path.basename(path).lower()
    if "dockerfile" in base or base == "containerfile":
        return "dockerfile"
    return "yaml"


def discover_infra_files(root: str, base_path: str, max_depth: int | None) -> list[dict[str, Any]]:
    """Walk tree under base_path and return FileSpec list for infra files."""
    start = os.path.join(root, base_path) if not os.path.isabs(base_path) else base_path
    start = os.path.abspath(start)
    root_abs = os.path.abspath(root)
    if not os.path.isdir(start):
        return []
    start_depth = len(os.path.normpath(start).split(os.sep))
    files: list[dict[str, Any]] = []
    for dirpath, _, filenames in os.walk(start):
        if max_depth is not None:
            depth = len(os.path.normpath(os.path.abspath(dirpath)).split(os.sep)) - start_depth
            if depth > max_depth:
                continue
        rel_dir = os.path.relpath(dirpath, root_abs) if dirpath.startswith(root_abs) else dirpath
        dirs_in_path = rel_dir.replace(os.sep, "/").split("/")
        for name in filenames:
            full = os.path.abspath(os.path.join(dirpath, name))
            try:
                common = os.path.commonpath([root_abs, full])
            except ValueError:
                common = None
            if common != root_abs:
                rel = full
            else:
                rel = os.path.relpath(full, root_abs)
            rel = rel.replace(os.sep, "/")
            if not is_infra_file(rel):
                continue
            files.append({"path": rel, "language": _language_for_path(rel)})
    return files
