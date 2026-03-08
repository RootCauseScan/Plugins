"""Analyze phase: SBOM via Syft, vulns via Grype; infra via analyze.infra."""
from .run import analyze_files

__all__ = ["analyze_files"]
