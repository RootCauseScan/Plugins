"""Parse K8s/OpenShift YAML: extract container images and securityContext."""
from __future__ import annotations

import yaml
from typing import Any


def parse_kubernetes(content: str, file_path: str) -> dict[str, Any]:
    """
    Parse K8s/OpenShift manifest. Handles single-doc or multi-doc YAML.
    Returns:
      - images: list of {line, image_ref, container_name, source: "k8s"}
      - run_as_root: list of {line, container_name} where runAsNonRoot is false or runAsUser is 0
      - privileged: list of {line, container_name}
      - parse_error: optional
    """
    result: dict[str, Any] = {
        "images": [],
        "run_as_root": [],
        "privileged": [],
        "parse_error": None,
    }
    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        result["parse_error"] = str(e)
        return result
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        _process_k8s_doc(doc, file_path, content, result)
    return result


def _process_k8s_doc(doc: dict, file_path: str, content: str, result: dict[str, Any]) -> None:
    kind = doc.get("kind") or ""
    spec = doc.get("spec") or {}
    if not spec:
        return
    templates = []
    if "containers" in spec:
        templates.append(("containers", spec["containers"]))
    if "initContainers" in spec:
        templates.append(("initContainers", spec["initContainers"]))
    for group, containers in templates:
        if not isinstance(containers, list):
            continue
        for c in containers:
            if not isinstance(c, dict):
                continue
            name = c.get("name") or "unknown"
            image = c.get("image")
            if isinstance(image, str) and image.strip():
                result["images"].append({
                    "line": _find_line(content, image),
                    "image_ref": image.strip(),
                    "container_name": name,
                    "source": "k8s",
                })
            sec = c.get("securityContext") or {}
            if isinstance(sec, dict):
                if sec.get("runAsNonRoot") is False:
                    result["run_as_root"].append({"line": _find_line(content, "runAsNonRoot"), "container_name": name})
                elif sec.get("runAsUser") == 0:
                    result["run_as_root"].append({"line": _find_line(content, "runAsUser"), "container_name": name})
                if sec.get("privileged") is True:
                    result["privileged"].append({"line": _find_line(content, "privileged"), "container_name": name})
    if kind == "Pod":
        return
    # Workload types with template.spec (K8s + OpenShift DeploymentConfig)
    if kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "DeploymentConfig"}:
        template = spec.get("template") or {}
        pod_spec = template.get("spec") or {}
        if isinstance(pod_spec, dict):
            _process_k8s_doc({"kind": "Pod", "spec": pod_spec}, file_path, content, result)
    # CronJob: spec.jobTemplate.spec.template.spec
    if kind == "CronJob":
        job_tmpl = spec.get("jobTemplate") or {}
        job_spec = job_tmpl.get("spec") or {}
        if isinstance(job_spec, dict):
            template = job_spec.get("template") or {}
            pod_spec = template.get("spec") or {}
            if isinstance(pod_spec, dict):
                _process_k8s_doc({"kind": "Pod", "spec": pod_spec}, file_path, content, result)


def _find_line(content: str, needle: str) -> int:
    for i, line in enumerate(content.splitlines(), 1):
        if needle in line:
            return i
    return 0
