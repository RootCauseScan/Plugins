"""Report phase: JSON, CSV, PDF, Excel output; infra JSON/HTML."""
from . import canonical as _canonical
from . import csv as _csv
from . import infra_json as _infra_json
from . import infra_html as _infra_html
from . import json as _json

build_canonical_report = _canonical.build_canonical_report
write_canonical_json = _canonical.write_canonical_json
write_json = _json.write_json
write_csv = _csv.write_csv
write_infra_json = _infra_json.write_infra_json
write_infra_html = _infra_html.write_infra_html

__all__ = [
    "build_canonical_report",
    "write_canonical_json",
    "write_json",
    "write_csv",
    "write_infra_json",
    "write_infra_html",
]

try:
    from . import pdf as _pdf
    write_pdf = _pdf.write_pdf
    __all__ = list(__all__) + ["write_pdf"]
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
