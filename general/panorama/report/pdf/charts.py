"""Chart rendering for PDF templates (pie, bar). Uses pygal for SVG output."""
from __future__ import annotations

import re
from typing import Any, Dict, List

try:
    import pygal
    from pygal import Config
    from pygal.style import Style
    _HAS_PYGAL = True
    _WHITE_STYLE = Style(background="white", plot_background="white")
except ImportError:
    _HAS_PYGAL = False
    _WHITE_STYLE = None

# Severity colors aligned with panorama-report.css
_SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#65a30d",
    "info": "#0ea5e9",
    "unknown": "#6b7280",
}


def _strip_script_from_svg(svg: str) -> str:
    """Remove <script> blocks from pygal SVG so WeasyPrint doesn't choke."""
    if not svg or "<script>" not in svg:
        return svg or ""
    return re.sub(r"<script[^>]*>.*?</script>", "", svg, flags=re.DOTALL | re.IGNORECASE)


def render_pie_chart(rows: List[Dict[str, Any]], title: str = "", size: tuple = (400, 300)) -> str:
    """Render a pie chart from severity-style rows (severity, count, percent, severity_class). Returns SVG string or empty."""
    if not _HAS_PYGAL or not rows:
        return ""
    try:
        config = Config(style=_WHITE_STYLE)
        config.show_legend = True
        config.truncate_legend = -1
        config.legend_at_bottom = True
        config.disable_xml_declaration = True
        config.explicit_size = True
        config.width = size[0]
        config.height = size[1]
        chart = pygal.Pie(config, inner_radius=0.6, print_values=True)
        chart.title = ""
        for r in rows:
            label = str(r.get("severity") or r.get("label", ""))
            count = int(r.get("count", 0))
            if count <= 0:
                continue
            severity_class = (r.get("severity_class") or "").lower() or "unknown"
            color = _SEVERITY_COLORS.get(severity_class) or _SEVERITY_COLORS["unknown"]
            chart.add(label, count, color=color)
        svg = chart.render(is_unicode=True)
        return _strip_script_from_svg(svg) if isinstance(svg, str) else _strip_script_from_svg(svg.decode("utf-8"))
    except Exception:
        return ""
