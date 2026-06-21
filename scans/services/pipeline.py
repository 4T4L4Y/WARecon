from django.utils import timezone

from scans.models import Scan, ScanModuleResult
from scans.services.live_log import bind_scan_log, log_activity, reset_scan_log
from scans.services.output_paths import scan_output_dir

from . import tools
from .validators import (
    validate_domain,
    validate_ports,
    validate_status_codes,
    validate_template_ids,
)

WEB_MODULE_IDS = {"3", "4", "5", "7"}

# Keşif → DNS → alt alan web zinciri → port → nmap → (kök nuclei yok, nuclei alt alanda)
MODULE_ORDER = ["2", "6", "3", "4", "7", "1", "5"]

MODULE_MAP = {
    "1": ScanModuleResult.Module.NAABU,
    "2": ScanModuleResult.Module.SUBDOMAIN,
    "3": ScanModuleResult.Module.WAYBACK,
    "4": ScanModuleResult.Module.HTTPX,
    "5": ScanModuleResult.Module.NUCLEI,
    "6": ScanModuleResult.Module.DNSX,
    "7": ScanModuleResult.Module.KATANA,
    "8": ScanModuleResult.Module.NMAP,
}

MODULE_LABELS = {
    "1": "Port Tarama (Naabu)",
    "2": "Subdomain Keşfi (Subfinder)",
    "3": "Wayback URL",
    "4": "Canlı URL (HTTPX)",
    "5": "Zafiyet Tarama (Nuclei)",
    "6": "DNS Kayıtları (dnsx)",
    "7": "Web Crawl (Katana)",
    "8": "Servis Tarama (Nmap)",
    "web": "Alt Alan Web Analizi",
}

OUTPUT_SUFFIX = {
    ScanModuleResult.Module.NAABU: "_naabu.txt",
    ScanModuleResult.Module.SUBDOMAIN: "_subdomains.txt",
    ScanModuleResult.Module.WAYBACK: "_wayback.txt",
    ScanModuleResult.Module.HTTPX: "_httpx.txt",
    ScanModuleResult.Module.NUCLEI: "_nuclei.txt",
    ScanModuleResult.Module.DNSX: "_dnsx.txt",
    ScanModuleResult.Module.KATANA: "_katana.txt",
    ScanModuleResult.Module.NMAP: "_nmap.txt",
}


def ordered_choices(choices: list[str]) -> list[str]:
    return [c for c in MODULE_ORDER if c in choices]


def build_execution_plan(choices: list[str]) -> list[str]:
    """Collapse 3/4/5/7 into single 'web' phase; drop standalone 5 if only per-subdomain."""
    plan: list[str] = []
    web_added = False
    for choice in ordered_choices(choices):
        if choice in WEB_MODULE_IDS:
            if not web_added:
                plan.append("web")
                web_added = True
        else:
            plan.append(choice)
    return plan


def validate_pipeline(choices: list[str]) -> None:
    ordered = ordered_choices(choices)
    if "3" in ordered and "2" not in ordered:
        raise ValueError("Wayback modülü için önce Subdomain keşfi gereklidir.")
    if WEB_MODULE_IDS.intersection(ordered) and "2" not in ordered:
        raise ValueError("HTTPX/Nuclei/Katana/Wayback için önce Subdomain keşfi gereklidir.")


def _output_relpath(scan_id: int, filename: str) -> str:
    return f"scan_{scan_id}/{filename}"


def _save_module_result(scan: Scan, module: str, output_text: str, filename: str) -> None:
    ScanModuleResult.objects.create(
        scan=scan,
        module=module,
        output=output_text,
        output_file=_output_relpath(scan.pk, filename),
    )


def create_scan(user, form_data: dict) -> Scan:
    raw_input = form_data.get("domain", "")
    domain = validate_domain(raw_input)
    choices = ordered_choices(form_data.get("choices", []))
    validate_pipeline(choices)

    config = {
        "naabuPorts": form_data.get("naabuPorts", ""),
        "subdomainParams": form_data.get("subdomainParams", []),
        "waybackKnownUrls": form_data.get("waybackKnownUrls", False),
        "includeSubdomains": form_data.get("includeSubdomains", False),
        "httpxFollowRedirects": form_data.get("httpxFollowRedirects", False),
        "httpxStatusCode": form_data.get("httpxStatusCode", False),
        "httpxMatchCodes": form_data.get("httpxMatchCodes", ""),
        "nucleiTemplates": form_data.get("nucleiTemplates", ""),
        "nucleiSeverity": form_data.get("nucleiSeverity", []),
        "katanaDepth": form_data.get("katanaDepth", "2"),
        "nmap_exploit_suggestions": [],
    }

    scan = Scan.objects.create(
        user=user,
        domain=domain,
        raw_input=raw_input,
        modules=choices,
        config=config,
        status=Scan.Status.PENDING,
        progress_message="Kuyruğa alındı…",
    )
    scan_output_dir(scan.pk)
    token = bind_scan_log(scan.pk)
    log_activity("Tarama kuyruğa alındı.", level="info")
    reset_scan_log(token)
    return scan


def execute_scan(scan_id: int) -> None:
    scan = Scan.objects.get(pk=scan_id)
    scan.status = Scan.Status.RUNNING
    scan.progress_percent = 0
    scan.save(update_fields=["status", "progress_percent"])

    log_token = bind_scan_log(scan_id)
    log_activity("Tarama worker tarafından başlatıldı.", level="info")

    config = dict(scan.config or {})
    domain = scan.domain
    ordered = scan.modules
    plan = build_execution_plan(ordered)
    total = len(plan) + (1 if "1" in ordered else 0)  # +1 for auto nmap after naabu
    step_index = 0

    try:
        for step in plan:
            module_token = bind_scan_log(scan_id, step)
            label = MODULE_LABELS.get(step, step)
            percent = int((step_index / max(total, 1)) * 100)
            scan.update_progress(step, f"{label} çalışıyor…", percent)
            log_activity(f"▶ {label} başlatılıyor…", level="info", module=step)

            if step == "web":
                _run_web_phase(scan, config, ordered)
            elif step == "1":
                _run_naabu_nmap_phase(scan, config)
                step_index += 1  # nmap counts as extra progress bump
            else:
                output_text = _run_simple_module(scan_id, step, domain, scan.raw_input, config)
                module_key = MODULE_MAP[step]
                filename = f"{domain}{OUTPUT_SUFFIX[module_key]}"
                _save_module_result(scan, module_key, output_text, filename)
                line_count = len([ln for ln in output_text.splitlines() if ln.strip()])
                log_activity(f"✓ {label} bitti — {line_count} satır.", level="success", module=step)

            reset_scan_log(module_token)
            step_index += 1
            scan.update_progress(step, f"{label} tamamlandı", int((step_index / max(total, 1)) * 100))

        scan.status = Scan.Status.COMPLETED
        scan.progress_percent = 100
        scan.progress_message = "Tarama tamamlandı."
        scan.current_module = ""
        scan.completed_at = timezone.now()
        scan.save(update_fields=[
            "status", "progress_percent", "progress_message",
            "current_module", "completed_at", "config",
        ])
        log_activity("Tüm modüller tamamlandı.", level="success")
    except Exception as exc:
        scan.status = Scan.Status.FAILED
        scan.error_message = str(exc)
        scan.progress_message = f"Hata: {exc}"
        scan.completed_at = timezone.now()
        scan.save(update_fields=[
            "status", "error_message", "progress_message", "completed_at",
        ])
        log_activity(f"Hata: {exc}", level="error")
        raise
    finally:
        reset_scan_log(log_token)


def _run_web_phase(scan: Scan, config: dict, ordered: list[str]) -> None:
    outputs = tools.run_per_subdomain_web_pipeline(
        scan.pk,
        scan.domain,
        config,
        run_wayback="3" in ordered,
        run_httpx="4" in ordered,
        run_nuclei="5" in ordered,
        run_katana="7" in ordered,
    )
    mapping = {
        "wayback": (ScanModuleResult.Module.WAYBACK, "3"),
        "httpx": (ScanModuleResult.Module.HTTPX, "4"),
        "nuclei": (ScanModuleResult.Module.NUCLEI, "5"),
        "katana": (ScanModuleResult.Module.KATANA, "7"),
    }
    for key, (module, choice_id) in mapping.items():
        if choice_id not in ordered:
            continue
        text = outputs.get(key, "")
        filename = f"{scan.domain}{OUTPUT_SUFFIX[module]}"
        _save_module_result(scan, module, text, filename)


def _run_naabu_nmap_phase(scan: Scan, config: dict) -> None:
    ports = validate_ports(config.get("naabuPorts", ""))
    naabu_out = tools.run_naabu(scan.pk, scan.domain, ports)
    _save_module_result(
        scan,
        ScanModuleResult.Module.NAABU,
        naabu_out,
        f"{scan.domain}_naabu.txt",
    )

    scan.update_progress("8", "Nmap servis taraması…", scan.progress_percent)
    log_activity("▶ Nmap: açık portlar taranıyor…", level="info", module="8")
    nmap_out, exploits = tools.run_nmap_on_naabu(scan.pk, scan.domain, naabu_out)
    config["nmap_exploit_suggestions"] = exploits
    scan.config = config
    scan.save(update_fields=["config"])

    if nmap_out.strip():
        _save_module_result(
            scan,
            ScanModuleResult.Module.NMAP,
            nmap_out,
            f"{scan.domain}_nmap.txt",
        )
    if exploits:
        log_activity(
            f"⚠ {len(exploits)} olası exploit/zafiyet bulgusu — sonuç sayfasından doğrulama isteyebilirsiniz.",
            level="warning",
        )


def _run_simple_module(scan_id: int, choice: str, domain: str, raw_input: str, config: dict) -> str:
    if choice == "2":
        return tools.run_subfinder(scan_id, domain, config.get("subdomainParams", []))
    if choice == "6":
        return tools.run_dnsx(scan_id, domain)
    return ""


def scan_to_context(scan: Scan) -> dict:
    context = {
        "domain": scan.domain,
        "scan": scan,
        "naabu_output": "",
        "nmap_output": "",
        "subdomain_output": "",
        "wayback_output": "",
        "httpx_output": "",
        "nuclei_output": "",
        "dnsx_output": "",
        "katana_output": "",
        "exploit_suggestions": (scan.config or {}).get("nmap_exploit_suggestions", []),
    }
    key_map = {
        "naabu": "naabu_output",
        "nmap": "nmap_output",
        "subdomain": "subdomain_output",
        "wayback": "wayback_output",
        "httpx": "httpx_output",
        "nuclei": "nuclei_output",
        "dnsx": "dnsx_output",
        "katana": "katana_output",
    }
    for result in scan.results.all():
        key = key_map.get(result.module)
        if key:
            context[key] = result.output
    return context
