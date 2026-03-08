"""Analyze phase: parse Dockerfile/compose/K8s, extract images, misconfig, optional Trivy."""
from .run import analyze_files

__all__ = ["analyze_files"]
