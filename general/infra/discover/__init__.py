"""Discover phase: find Dockerfile, Containerfile, docker-compose, K8s/OpenShift files."""
from .files import discover_infra_files, is_infra_file

__all__ = ["discover_infra_files", "is_infra_file"]
