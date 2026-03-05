"""Analyze phase: parse manifests, build SBOM, query OSV for vulnerabilities."""
from .run import analyze_files

__all__ = ["analyze_files"]
