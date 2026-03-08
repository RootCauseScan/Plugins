"""Simple template engine for Markdown report templates.

Supports:
- {variable} and {object.key} substitution
- {for item in list} ... {end} loops
- {if variable} ... {endif} conditionals
- {cmd:shell command} to run a command and insert stdout (when allow_commands=True)
"""
import re
import subprocess
from typing import Any, Dict, List


def _get_path(ctx: Dict[str, Any], path: str) -> Any:
    """Get value from context by dot path (e.g. 'finding.rule_id')."""
    parts = path.strip().split(".")
    obj = ctx
    for p in parts:
        if isinstance(obj, dict) and p in obj:
            obj = obj[p]
        else:
            return ""
    return obj if obj is not None else ""


def _replace_vars(text: str, ctx: Dict[str, Any]) -> str:
    """Replace {path} and {path.subkey} with values from ctx."""
    def repl(match: re.Match) -> str:
        key = match.group(1).strip()
        val = _get_path(ctx, key)
        return str(val) if val is not None else ""

    return re.sub(r"\{([^}\s{]+(?:\.[^}\s{]+)*)\}", repl, text)


def _run_cmd(cmd: str, timeout: int = 5) -> str:
    """Run shell command and return stdout (stripped)."""
    try:
        r = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return (r.stdout or "").strip()
    except Exception:
        return ""


def process_template(
    content: str,
    context: Dict[str, Any],
    allow_commands: bool = False,
    cmd_timeout: int = 5,
) -> str:
    """Process template: variables, for loops, optional cmd.

    - Variables: {report_date}, {finding.rule_id}, etc.
    - Loop: {for finding in findings} ... {end}
    - Command (if allow_commands): {cmd:python -c "..."}
    """
    out: List[str] = []
    lines = content.split("\n")
    i = 0

    for_re = re.compile(r"^\s*\{\s*for\s+(\w+)\s+in\s+(\w+)\s*\}\s*$", re.IGNORECASE)
    end_re = re.compile(r"^\s*\{\s*end\s*\}\s*$", re.IGNORECASE)
    if_re = re.compile(r"^\s*\{\s*if\s+(.+?)\s*\}\s*$", re.IGNORECASE)
    endif_re = re.compile(r"^\s*\{\s*endif\s*\}\s*$", re.IGNORECASE)
    cmd_re = re.compile(r"\{\s*cmd:\s*(.+?)\s*\}", re.DOTALL)

    while i < len(lines):
        line = lines[i]

        m_for = for_re.match(line)
        if m_for:
            item_name = m_for.group(1)
            list_name = m_for.group(2)
            list_val = _get_path(context, list_name)
            if not isinstance(list_val, list):
                list_val = []
            block_lines: List[str] = []
            i += 1
            depth = 1
            while i < len(lines):
                if for_re.match(lines[i]):
                    depth += 1
                elif end_re.match(lines[i]):
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                block_lines.append(lines[i])
                i += 1
            block = "\n".join(block_lines)
            for item in list_val:
                child_ctx = dict(context)
                child_ctx[item_name] = item
                out.append(process_template(block, child_ctx, allow_commands, cmd_timeout))
            continue

        m_if = if_re.match(line)
        if m_if:
            expr = m_if.group(1).strip()
            val = _get_path(context, expr)
            truthy = bool(val) if val != "" else False
            block_lines = []
            i += 1
            depth = 1
            while i < len(lines):
                if if_re.match(lines[i]):
                    depth += 1
                elif endif_re.match(lines[i]):
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                block_lines.append(lines[i])
                i += 1
            if truthy:
                block = "\n".join(block_lines)
                out.append(process_template(block, context, allow_commands, cmd_timeout))
            continue

        if end_re.match(line) or endif_re.match(line):
            i += 1
            continue

        line = _replace_vars(line, context)
        if allow_commands:
            line = cmd_re.sub(lambda m: _run_cmd(m.group(1).strip(), cmd_timeout), line)
        out.append(line)
        i += 1

    return "\n".join(out)
