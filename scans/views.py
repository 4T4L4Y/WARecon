import base64
import json
import time
from functools import wraps

from django.conf import settings
from django.contrib.auth.views import redirect_to_login
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.http import FileResponse, Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_http_methods

from .forms import ScanForm
from .models import Scan
from .services.pipeline import create_scan, scan_to_context
from .services.reports import render_html_report, render_pdf_report
from .tasks import enqueue_scan


def _resolve_user(request):
    if request.user.is_authenticated:
        return request.user
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode()
            username, password = decoded.split(":", 1)
            return authenticate(request, username=username, password=password)
        except (ValueError, UnicodeDecodeError):
            return None
    return None


def login_required_basic(view):
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        user = _resolve_user(request)
        if not user:
            return redirect_to_login(request.get_full_path())
        request.user = user
        return view(request, *args, **kwargs)
    return wrapper


def _user_scans(user):
    return Scan.objects.filter(user=user)


@login_required_basic
@require_http_methods(["GET", "POST"])
def index(request):
    context = {
        "domain": "",
        "naabu_output": "",
        "subdomain_output": "",
        "wayback_output": "",
        "httpx_output": "",
        "nuclei_output": "",
        "dnsx_output": "",
        "katana_output": "",
    }

    if request.method == "POST":
        form = ScanForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Form doğrulaması başarısız.")
            return render(request, "scans/index.html", context)

        try:
            scan = create_scan(request.user, form.cleaned_data)
            enqueue_scan(scan.pk)
            return redirect("scans:progress", pk=scan.pk)
        except ValidationError as exc:
            msg = exc.messages[0] if getattr(exc, "messages", None) else str(exc)
            messages.error(request, msg)
        except ValueError as exc:
            messages.error(request, str(exc))
        except Exception:
            messages.error(request, "Tarama başlatılamadı.")

    return render(request, "scans/index.html", context)


@login_required_basic
@require_GET
def progress(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user), pk=pk)
    return render(request, "scans/progress.html", {"scan": scan})


@login_required_basic
@require_GET
def scan_events(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user), pk=pk)

    def event_stream():
        last_percent = -1
        while True:
            scan.refresh_from_db()
            payload = {
                "status": scan.status,
                "message": scan.progress_message,
                "percent": scan.progress_percent,
                "module": scan.current_module,
                "error": scan.error_message,
            }
            if scan.progress_percent != last_percent or scan.status in (
                Scan.Status.COMPLETED,
                Scan.Status.FAILED,
            ):
                yield f"data: {json.dumps(payload)}\n\n"
                last_percent = scan.progress_percent
            if scan.status in (Scan.Status.COMPLETED, Scan.Status.FAILED):
                break
            time.sleep(1)

    response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    return response


@login_required_basic
@require_GET
def history(request):
    scans = _user_scans(request.user)[:50]
    return render(request, "scans/history.html", {"scans": scans})


@login_required_basic
@require_GET
def scan_detail(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user).prefetch_related("results"), pk=pk)
    context = scan_to_context(scan)
    return render(request, "scans/index.html", context)


@login_required_basic
@require_GET
def report_html(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user).prefetch_related("results"), pk=pk)
    return HttpResponse(render_html_report(scan))


@login_required_basic
@require_GET
def report_pdf(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user).prefetch_related("results"), pk=pk)
    pdf = render_pdf_report(scan)
    response = HttpResponse(pdf, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="warecon_{scan.domain}_{scan.pk}.pdf"'
    return response


@login_required_basic
@require_GET
def download_output(request, filename: str):
    if ".." in filename or "/" in filename:
        raise Http404
    path = settings.OUTPUTS_DIR / filename
    if not path.is_file():
        raise Http404
    domain = filename.split("_")[0]
    if not _user_scans(request.user).filter(domain=domain).exists():
        raise Http404
    return FileResponse(path.open("rb"), as_attachment=True, filename=filename)


@require_GET
def nuclei_json(request, filename: str):
    if not filename.endswith("_nuclei.json") or ".." in filename:
        raise Http404
    path = settings.OUTPUTS_DIR / filename
    if not path.is_file():
        return JsonResponse({"error": "File not found"}, status=404)
    return JsonResponse(json.loads(path.read_text(encoding="utf-8")), safe=False)
