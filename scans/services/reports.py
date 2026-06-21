from io import BytesIO

from django.template.loader import render_to_string
from xhtml2pdf import pisa

from scans.models import Scan
from scans.services.pipeline import scan_to_context


def build_report_context(scan: Scan) -> dict:
    ctx = scan_to_context(scan)
    ctx["scan"] = scan
    return ctx


def render_html_report(scan: Scan) -> str:
    return render_to_string("reports/scan_report.html", build_report_context(scan))


def render_pdf_report(scan: Scan) -> bytes:
    html = render_html_report(scan)
    buffer = BytesIO()
    pisa.CreatePDF(html, dest=buffer)
    return buffer.getvalue()
