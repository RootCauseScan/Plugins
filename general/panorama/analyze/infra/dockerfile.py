"""Parse Dockerfile/Containerfile: extract FROM, USER, HEALTHCHECK, ADD, etc."""
from __future__ import annotations

import re
from typing import Any


def parse_dockerfile(content: str, file_path: str) -> dict[str, Any]:
    """
    Parse Dockerfile content. Returns:
      - images: list of {line, image_ref, raw}
      - has_user: bool (any USER instruction)
      - user_root: bool (USER root or 0)
      - has_healthcheck: bool
      - has_add: bool
      - lines: list of {line_num, instruction, value} for debugging
    """
    result: dict[str, Any] = {
        "images": [],
        "has_user": False,
        "user_root": False,
        "has_healthcheck": False,
        "has_add": False,
        "lines": [],
    }
    for idx, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(maxsplit=1)
        instr = (parts[0].upper() if parts else "").rstrip(":")
        value = parts[1].strip() if len(parts) > 1 else ""
        result["lines"].append({"line_num": idx, "instruction": instr, "value": value})
        if instr == "FROM":
            # FROM [--platform=...] image[:tag][@digest] [AS name]
            ref = value
            for prefix in ("--platform=", "--from="):
                if ref.startswith(prefix):
                    ref = ref.split(maxsplit=1)[-1] if " " in ref else ""
                    break
            if ref:
                as_part = " AS "
                if as_part in ref.upper():
                    ref = ref.split(as_part, 1)[0].strip()
                result["images"].append({"line": idx, "image_ref": ref.strip(), "raw": value, "source": "from"})
        elif instr == "USER":
            result["has_user"] = True
            u = value.split()[0] if value else ""
            if u in ("root", "0"):
                result["user_root"] = True
        elif instr == "HEALTHCHECK":
            result["has_healthcheck"] = True
        elif instr == "ADD":
            result["has_add"] = True
    return result
