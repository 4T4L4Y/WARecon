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


def _font_path() -> Path:
    path = Path(settings.BASE_DIR) / "static" / "fonts" / "DejaVuSans.ttf"
    return path


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
    return ctx


def render_html_report(scan: Scan) -> str:
    return render_to_string("reports/scan_report.html", build_report_context(scan))


def render_pdf_report(scan: Scan) -> bytes:
    html = render_html_report(scan)
    buffer = BytesIO()
    pisa.CreatePDF(
        html,
        dest=buffer,
        encoding="utf-8",
        link_callback=_pdf_link_callback,
    )
    return buffer.getvalue()
