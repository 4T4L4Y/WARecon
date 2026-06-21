import json
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import FileResponse, Http404, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_GET, require_http_methods

from .forms import ScanForm
from .models import Scan
from .services.pipeline import ScanOutputs, run_pipeline


def _empty_context(domain: str = "") -> dict:
    return {
        "domain": domain,
        "naabu_output": "",
        "subdomain_output": "",
        "wayback_output": "",
        "httpx_output": "",
        "nuclei_output": "",
    }


def _context_from_outputs(outputs: ScanOutputs) -> dict:
    return {
        "domain": outputs.domain,
        "naabu_output": outputs.naabu_output,
        "subdomain_output": outputs.subdomain_output,
        "wayback_output": outputs.wayback_output,
        "httpx_output": outputs.httpx_output,
        "nuclei_output": outputs.nuclei_output,
    }


@require_http_methods(["GET", "POST"])
def index(request):
    context = _empty_context()

    if request.method == "POST":
        form = ScanForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Form doğrulaması başarısız.")
            context["form_errors"] = form.errors
            return render(request, "scans/index.html", context)

        try:
            _, outputs = run_pipeline(form.cleaned_data)
            context.update(_context_from_outputs(outputs))
            messages.success(request, f"{outputs.domain} taraması tamamlandı.")
        except ValidationError as exc:
            msg = exc.messages[0] if getattr(exc, "messages", None) else str(exc)
            messages.error(request, msg)
        except ValueError as exc:
            messages.error(request, str(exc))
        except Exception:
            messages.error(request, "Tarama sırasında bir hata oluştu.")

    return render(request, "scans/index.html", context)


@require_GET
def history(request):
    scans = Scan.objects.all()[:50]
    return render(request, "scans/history.html", {"scans": scans})


@require_GET
def scan_detail(request, pk: int):
    scan = get_object_or_404(Scan.objects.prefetch_related("results"), pk=pk)
    context = _empty_context(scan.domain)
    for result in scan.results.all():
        if result.module == "naabu":
            context["naabu_output"] = result.output
        elif result.module == "subdomain":
            context["subdomain_output"] = result.output
        elif result.module == "wayback":
            context["wayback_output"] = result.output
        elif result.module == "httpx":
            context["httpx_output"] = result.output
        elif result.module == "nuclei":
            context["nuclei_output"] = result.output
    context["scan"] = scan
    return render(request, "scans/index.html", context)


@require_GET
def download_output(request, filename: str):
    if ".." in filename or "/" in filename:
        raise Http404
    path = Path(settings.OUTPUTS_DIR) / filename
    if not path.is_file():
        raise Http404
    return FileResponse(path.open("rb"), as_attachment=True, filename=filename)


@require_GET
def nuclei_json(request, filename: str):
    if not filename.endswith("_nuclei.json") or ".." in filename:
        raise Http404
    path = Path(settings.OUTPUTS_DIR) / filename
    if not path.is_file():
        return JsonResponse({"error": "File not found"}, status=404)
    return JsonResponse(json.loads(path.read_text(encoding="utf-8")), safe=False)
