"""Infra analysis: Dockerfile, compose, K8s — images, misconfig, optional Trivy."""
from .run import analyze_files as analyze_infra_files

__all__ = ["analyze_infra_files"]
