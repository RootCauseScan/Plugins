"""Parse docker-compose YAML: extract service images."""
from __future__ import annotations

import re
import yaml
from typing import Any


def parse_compose(content: str, file_path: str) -> dict[str, Any]:
    """
    Parse docker-compose content. Returns:
      - images: list of {line, image_ref, service_name}
      - parse_error: optional error message
    """
    result: dict[str, Any] = {"images": [], "parse_error": None}
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        result["parse_error"] = str(e)
        return result
    if not isinstance(data, dict):
        return result
    services = data.get("services") or data.get("Services")
    if not isinstance(services, dict):
        return result
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        image = svc.get("image") or svc.get("Image")
        if isinstance(image, str) and image.strip():
            result["images"].append({
                "line": _line_of_key(content, "image") or 0,
                "image_ref": image.strip(),
                "service_name": name,
                "source": "compose",
            })
    return result


def _line_of_key(content: str, key: str) -> int | None:
    for i, line in enumerate(content.splitlines(), 1):
        if re.match(rf"^\s*{key}\s*:", line):
            return i
    return None
