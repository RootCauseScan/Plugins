"""Report phase: JSON, HTML, optional PDF."""
from . import json as _json
from . import html as _html

write_json = _json.write_json
write_html = _html.write_html

__all__ = ["write_json", "write_html"]
