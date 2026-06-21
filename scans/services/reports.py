import base64
import json
from io import BytesIO
from pathlib import Path

from django.conf import settings
from django.template.loader import render_to_string
from xhtml2pdf import pisa

from scans.models import Scan
from scans.services.formatters import nuclei_severity_counts
from scans.services.output_paths import scan_output_dir
from scans.services.pipeline import scan_to_context

_pdf_font_registered = False


def _font_path() -> Path:
    return Path(settings.BASE_DIR) / "static" / "fonts" / "DejaVuSans.ttf"


def _ensure_pdf_font() -> None:
    global _pdf_font_registered
    if _pdf_font_registered:
        return
    path = _font_path()
    if not path.is_file():
        return
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from xhtml2pdf import default as pisa_default

    font_path = str(path.resolve())
    pdfmetrics.registerFont(TTFont("DejaVuSans", font_path))
    pisa_default.DEFAULT_FONT["dejavusans"] = "DejaVuSans"
    pisa_default.DEFAULT_FONT["dejavu"] = "DejaVuSans"
    _pdf_font_registered = True


def _pdf_link_callback(uri: str, _rel) -> str:
    if uri.startswith("/static/"):
        return str(Path(settings.BASE_DIR) / uri.lstrip("/"))
    if uri.startswith("static/"):
        return str(Path(settings.BASE_DIR) / uri)
    return uri


def _collect_nuclei_json(scan: Scan) -> list:
    scan_dir = scan_output_dir(scan.pk)
    combined = []
    for path in sorted(scan_dir.glob("*_nuclei.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                combined.extend(data)
        except (json.JSONDecodeError, OSError):
            continue
    root = scan_dir / f"{scan.domain}_nuclei.json"
    if root.is_file():
        try:
            data = json.loads(root.read_text(encoding="utf-8"))
            if isinstance(data, list):
                combined.extend(data)
        except (json.JSONDecodeError, OSError):
            pass
    return combined


def _severity_chart_base64(counts: dict[str, int]) -> str:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        plt.rcParams["font.family"] = "DejaVu Sans"
        labels = []
        values = []
        colors = {
            "critical": "#fd5d93",
            "high": "#fb6340",
            "medium": "#ffd600",
            "low": "#00f2c3",
            "info": "#1d8cf8",
        }
        for key in ("critical", "high", "medium", "low", "info"):
            if counts.get(key, 0) > 0:
                labels.append(key.upper())
                values.append(counts[key])

        if not values:
            return ""

        fig, ax = plt.subplots(figsize=(6, 3.2))
        bar_colors = [colors.get(k.lower(), "#888") for k in labels]
        ax.bar(labels, values, color=bar_colors)
        ax.set_title("Nuclei Önem Dağılımı")
        ax.set_ylabel("Bulgu Sayısı")
        fig.tight_layout()
        buf = BytesIO()
        fig.savefig(buf, format="png", dpi=120)
        plt.close(fig)
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        return ""


def _report_sections(scan: Scan, context: dict) -> list[dict]:
    sections = [
        ("2", "Subdomain Keşfi", "subdomain_output"),
        ("6", "DNS Kayıtları", "dnsx_output"),
        ("3", "Wayback URL (alt alan bazlı)", "wayback_output"),
        ("4", "HTTPX", "httpx_output"),
        ("7", "Katana Crawl", "katana_output"),
        ("1", "Port Tarama (Naabu)", "naabu_output"),
        ("8", "Servis Tarama (Nmap)", "nmap_output"),
        ("5", "Nuclei Zafiyet", "nuclei_output"),
    ]
    modules = set(scan.modules or [])
    result = []
    for choice, title, key in sections:
        if choice not in modules and not (choice == "8" and "1" in modules):
            continue
        body = context.get(key, "") or ""
        result.append({
            "title": title,
            "body": body,
            "is_empty": not str(body).strip(),
        })
    return result


def build_report_context(scan: Scan) -> dict:
    ctx = scan_to_context(scan)
    ctx["scan"] = scan
    nuclei_items = _collect_nuclei_json(scan)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in nuclei_items:
        sev = (item.get("info") or {}).get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    ctx["nuclei_counts"] = counts
    ctx["nuclei_total"] = sum(counts.values())
    ctx["severity_chart_b64"] = _severity_chart_base64(counts)
    ctx["exploit_suggestions"] = (scan.config or {}).get("nmap_exploit_suggestions", [])
    ctx["font_path"] = str(_font_path().resolve())
    ctx["report_sections"] = _report_sections(scan, ctx)
    ctx["subdomain_list"] = [
        line.strip()
        for line in (ctx.get("subdomain_output") or "").splitlines()
        if line.strip()
    ]
    return ctx


def render_html_report(scan: Scan) -> str:
    return render_to_string("reports/scan_report.html", build_report_context(scan))


def render_pdf_report(scan: Scan) -> bytes:
    _ensure_pdf_font()
    html = render_html_report(scan)
    buffer = BytesIO()
    pisa.CreatePDF(
        html,
        dest=buffer,
        encoding="utf-8",
        link_callback=_pdf_link_callback,
    )
    return buffer.getvalue()
