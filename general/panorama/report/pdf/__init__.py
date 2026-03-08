"""PDF report: template-based (Markdown + CSS -> WeasyPrint)."""
try:
    from .template_pdf import write_pdf
except ImportError:
    write_pdf = None

__all__ = ["write_pdf"]
