import base64
import json
import time
from functools import wraps

from django.conf import settings
from django.contrib.auth.views import redirect_to_login
from django.contrib import messages
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.http import FileResponse, Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_http_methods

from .forms import ScanForm
from .services.scan_control import request_cancel, request_skip_module, skip_available
from .services.subdomain_detail import host_results_context, subdomain_breakdown
from .services.notifications import get_or_create_profile
from .tasks import cancel_rq_job
from .models import Scan, ScanLog, ScanNotification, UserProfile
from .services.live_log import module_status_for_scan
from .services.output_paths import cleanup_scan_outputs, scan_output_dir
from .services.pipeline import apply_subdomain_selection, create_scan, scan_to_context
from .services.reports import render_html_report, render_pdf_report
from scans.services import tools
from .tasks import enqueue_continue_scan, enqueue_scan


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
        "nmap_output": "",
    }

    if request.method == "POST":
        form = ScanForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Form doğrulaması başarısız.")
            return render(request, "scans/index.html", context)

        try:
            cleaned = form.cleaned_data
            cleaned["nucleiTemplateIds"] = request.POST.getlist("nucleiTemplateIds")
            scan = create_scan(request.user, cleaned)
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
    initial_logs = list(ScanLog.objects.filter(scan=scan).order_by("id")[:200])
    initial_logs_data = [
        {
            "id": entry.id,
            "level": entry.level,
            "message": entry.message,
            "module": entry.module,
            "time": entry.created_at.strftime("%H:%M:%S"),
        }
        for entry in initial_logs
    ]
    return render(request, "scans/progress.html", {
        "scan": scan,
        "initial_logs_data": initial_logs_data,
        "module_status": module_status_for_scan(scan),
    })


@login_required_basic
@require_GET
def scan_events(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user), pk=pk)

    def event_stream():
        last_percent = -1
        last_log_id = 0
        last_status = ""
        last_module = ""
        while True:
            scan.refresh_from_db()
            new_logs = list(
                ScanLog.objects.filter(scan=scan, id__gt=last_log_id).order_by("id")[:100]
            )
            if new_logs:
                last_log_id = new_logs[-1].id

            payload = {
                "status": scan.status,
                "message": scan.progress_message,
                "percent": scan.progress_percent,
                "module": scan.current_module,
                "error": scan.error_message,
                "modules": module_status_for_scan(scan),
                "skip_available": skip_available(scan),
                "logs": [
                    {
                        "id": entry.id,
                        "level": entry.level,
                        "message": entry.message,
                        "module": entry.module,
                        "time": entry.created_at.strftime("%H:%M:%S"),
                    }
                    for entry in new_logs
                ],
            }
            changed = (
                scan.progress_percent != last_percent
                or scan.status != last_status
                or scan.current_module != last_module
                or bool(new_logs)
            )
            if changed:
                yield f"data: {json.dumps(payload)}\n\n"
                last_percent = scan.progress_percent
                last_status = scan.status
                last_module = scan.current_module
            if scan.status in (
                Scan.Status.COMPLETED,
                Scan.Status.FAILED,
                Scan.Status.CANCELLED,
            ):
                break
            time.sleep(0.5)

    response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    return response


@login_required_basic
@require_http_methods(["GET", "POST"])
def select_subdomains(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user), pk=pk)
    if scan.status != Scan.Status.AWAITING_SUBDOMAIN_SELECTION:
        return redirect("scans:progress", pk=pk)

    config = scan.config or {}
    hosts = config.get("discovered_subdomains") or []
    modules = set(scan.modules or [])
    web_flags = {
        "wayback": "3" in modules,
        "httpx": "4" in modules,
        "nuclei": "5" in modules,
        "katana": "7" in modules,
    }

    if request.method == "POST":
        selected = request.POST.getlist("subdomains")
        if not selected:
            messages.error(request, "En az bir alt alan seçmelisiniz.")
        else:
            run_wayback = web_flags["wayback"] and "run_wayback" in request.POST
            run_httpx = web_flags["httpx"] and "run_httpx" in request.POST
            run_nuclei = web_flags["nuclei"] and "run_nuclei" in request.POST
            run_katana = web_flags["katana"] and "run_katana" in request.POST
            if not any((run_wayback, run_httpx, run_nuclei, run_katana)):
                messages.error(request, "En az bir web modülü seçmelisiniz.")
            else:
                apply_subdomain_selection(
                    scan,
                    selected,
                    run_wayback=run_wayback,
                    run_httpx=run_httpx,
                    run_nuclei=run_nuclei,
                    run_katana=run_katana,
                )
                enqueue_continue_scan(scan.pk)
                messages.success(
                    request,
                    f"{len(selected)} alt alan için tarama devam ediyor.",
                )
                return redirect("scans:progress", pk=pk)

    return render(request, "scans/select_subdomains.html", {
        "scan": scan,
        "hosts": hosts,
        "web_flags": web_flags,
    })


@login_required_basic
@require_GET
def history(request):
    show_archived = request.GET.get("archived") == "1"
    scans = _user_scans(request.user).filter(is_archived=show_archived)[:50]
    return render(request, "scans/history.html", {
        "scans": scans,
        "show_archived": show_archived,
    })


@login_required_basic
@require_http_methods(["POST"])
def scan_archive(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user), pk=pk)
    scan.is_archived = not scan.is_archived
    scan.save(update_fields=["is_archived"])
    label = "arşivlendi" if scan.is_archived else "arşivden çıkarıldı"
    messages.success(request, f"Tarama {label}.")
    return redirect(request.POST.get("next") or "scans:history")


@login_required_basic
@require_http_methods(["POST"])
def scan_delete(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user), pk=pk)
    cleanup_scan_outputs(scan.pk)
    scan.delete()
    messages.success(request, "Tarama silindi.")
    return redirect("scans:history")


@login_required_basic
@require_http_methods(["POST"])
def run_exploit_check(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user).prefetch_related("results"), pk=pk)
    suggestions = (scan.config or {}).get("nmap_exploit_suggestions", [])
    if not suggestions:
        messages.warning(request, "Doğrulanacak exploit önerisi bulunamadı.")
        return redirect("scans:detail", pk=pk)

    hosts = list({item.get("host", scan.domain) for item in suggestions})
    log_token = None
    try:
        from scans.services.live_log import bind_scan_log, reset_scan_log

        log_token = bind_scan_log(scan.pk, "5")
        output = tools.run_nuclei_exploit_verification(scan.pk, scan.domain, hosts)
    finally:
        if log_token is not None:
            reset_scan_log(log_token)

    from scans.models import ScanModuleResult

    nuclei_result = scan.results.filter(module=ScanModuleResult.Module.NUCLEI).first()
    merged = (nuclei_result.output + "\n\n=== Exploit Doğrulama ===\n" + output) if nuclei_result else output
    if nuclei_result:
        nuclei_result.output = merged
        nuclei_result.save(update_fields=["output"])
    else:
        ScanModuleResult.objects.create(
            scan=scan,
            module=ScanModuleResult.Module.NUCLEI,
            output=merged,
            output_file=f"scan_{scan.pk}/{scan.domain}_nuclei_exploit.txt",
        )
    messages.success(request, "Exploit doğrulama taraması tamamlandı.")
    return redirect("scans:detail", pk=pk)


@login_required_basic
@require_GET
def scan_detail(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user).prefetch_related("results"), pk=pk)
    host = request.GET.get("host", "").strip()
    subs = subdomain_breakdown(scan)
    if not host:
        selected = [s["host"] for s in subs if s["scanned"]]
        host = selected[0] if selected else scan.domain
    context = scan_to_context(scan)
    context.update({
        "scan": scan,
        "subdomain_breakdown": subs,
        "active_host": host,
        "host_results": host_results_context(scan, host),
    })
    return render(request, "scans/scan_detail.html", context)


@login_required_basic
@require_http_methods(["POST"])
def scan_cancel(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user), pk=pk)
    if scan.status in (Scan.Status.COMPLETED, Scan.Status.FAILED, Scan.Status.CANCELLED):
        return redirect("scans:progress", pk=pk)
    cancel_rq_job(scan)
    request_cancel(scan)
    from scans.services.notifications import notify_scan_finished

    notify_scan_finished(scan)
    messages.warning(request, "Tarama durduruldu.")
    return redirect(request.POST.get("next") or "scans:progress", pk=scan.pk)


@login_required_basic
@require_http_methods(["POST"])
def scan_skip_module(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user), pk=pk)
    module = scan.current_module or request.POST.get("module", "")
    if module:
        from scans.services.pipeline import MODULE_LABELS

        request_skip_module(scan, module)
        label = MODULE_LABELS.get(module, module)
        messages.info(request, f"{label} atlanıyor…")
    return redirect("scans:progress", pk=pk)


@login_required_basic
@require_GET
def nuclei_templates_api(request):
    from scans.services.nuclei_templates import search_nuclei_templates

    q = request.GET.get("q", "")
    items = search_nuclei_templates(q, limit=300)
    return JsonResponse({"templates": items})


@login_required_basic
@require_GET
def notifications_api(request):
    items = ScanNotification.objects.filter(
        user=request.user, is_read=False,
    )[:30]
    return JsonResponse({
        "count": ScanNotification.objects.filter(user=request.user, is_read=False).count(),
        "items": [
            {
                "id": n.id,
                "title": n.title,
                "message": n.message,
                "level": n.level,
                "scan_id": n.scan_id,
                "time": n.created_at.strftime("%d.%m %H:%M"),
            }
            for n in items
        ],
    })


@login_required_basic
@require_http_methods(["POST"])
def notifications_mark_read(request):
    ScanNotification.objects.filter(user=request.user, is_read=False).update(is_read=True)
    return JsonResponse({"ok": True})


@login_required_basic
@require_http_methods(["GET", "POST"])
def notification_settings(request):
    profile = get_or_create_profile(request.user)
    if request.method == "POST":
        profile.notify_in_app = "notify_in_app" in request.POST
        profile.notify_email = "notify_email" in request.POST
        profile.notify_email_critical_high = "notify_email_critical_high" in request.POST
        profile.phone_critical_high = "phone_critical_high" in request.POST
        profile.notify_phone = request.POST.get("notify_phone", "").strip()
        profile.save()
        messages.success(request, "Bildirim tercihleri kaydedildi.")
        return redirect("scans:notification_settings")
    return render(request, "scans/notification_settings.html", {"profile": profile})


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
def download_output(request, pk: int, filename: str):
    scan = get_object_or_404(_user_scans(request.user), pk=pk)
    if ".." in filename:
        raise Http404
    path = scan_output_dir(pk) / filename
    if not path.is_file():
        path = settings.OUTPUTS_DIR / f"scan_{pk}" / filename
    if not path.is_file():
        raise Http404
    return FileResponse(path.open("rb"), as_attachment=True, filename=path.name)


@login_required_basic
@require_GET
def nuclei_json_for_scan(request, pk: int):
    scan = get_object_or_404(_user_scans(request.user), pk=pk)
    from scans.services.reports import _collect_nuclei_json

    data = _collect_nuclei_json(scan)
    return JsonResponse(data, safe=False)
