"""Report phase: JSON, CSV, HTML, PDF, Excel output."""
from . import json as _json
from . import csv as _csv
from . import html as _html

write_json = _json.write_json
write_csv = _csv.write_csv
write_html = _html.write_html

__all__ = ["write_json", "write_csv", "write_html"]

try:
    from . import pdf as _pdf
    write_pdf = _pdf.write_pdf
    __all__ = ["write_json", "write_csv", "write_html", "write_pdf"]
    HAS_PDF = True
except ImportError:
    write_pdf = None
    HAS_PDF = False

try:
    from . import excel as _excel
    write_excel = _excel.write_excel
    __all__ = list(__all__) + ["write_excel"]
    HAS_EXCEL = True
except ImportError:
    write_excel = None
    HAS_EXCEL = False
