from django.utils import timezone

from scans.models import Scan, ScanModuleResult
from scans.services.live_log import bind_scan_log, log_activity, reset_scan_log

from . import tools
from .validators import (
    validate_domain,
    validate_ports,
    validate_status_codes,
    validate_template_ids,
)

# Keşif → DNS → arşiv → doğrulama → crawl → port → zafiyet
MODULE_ORDER = ["2", "6", "3", "4", "7", "1", "5"]

MODULE_MAP = {
    "1": ScanModuleResult.Module.NAABU,
    "2": ScanModuleResult.Module.SUBDOMAIN,
    "3": ScanModuleResult.Module.WAYBACK,
    "4": ScanModuleResult.Module.HTTPX,
    "5": ScanModuleResult.Module.NUCLEI,
    "6": ScanModuleResult.Module.DNSX,
    "7": ScanModuleResult.Module.KATANA,
}

MODULE_LABELS = {
    "1": "Port Tarama (Naabu)",
    "2": "Subdomain Keşfi (Subfinder)",
    "3": "Wayback URL",
    "4": "Canlı URL (HTTPX)",
    "5": "Zafiyet Tarama (Nuclei)",
    "6": "DNS Kayıtları (dnsx)",
    "7": "Web Crawl (Katana)",
}

OUTPUT_SUFFIX = {
    ScanModuleResult.Module.NAABU: "_naabu.txt",
    ScanModuleResult.Module.SUBDOMAIN: "_subdomains.txt",
    ScanModuleResult.Module.WAYBACK: "_wayback.txt",
    ScanModuleResult.Module.HTTPX: "_httpx.txt",
    ScanModuleResult.Module.NUCLEI: "_nuclei.txt",
    ScanModuleResult.Module.DNSX: "_dnsx.txt",
    ScanModuleResult.Module.KATANA: "_katana.txt",
}


def ordered_choices(choices: list[str]) -> list[str]:
    return [c for c in MODULE_ORDER if c in choices]


def validate_pipeline(choices: list[str]) -> None:
    ordered = ordered_choices(choices)
    if "3" in ordered and "2" not in ordered:
        raise ValueError("Wayback modülü için önce Subdomain keşfi gereklidir.")


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

    config = scan.config or {}
    domain = scan.domain
    raw_input = scan.raw_input
    ordered = scan.modules
    total = len(ordered) or 1

    try:
        for index, choice in enumerate(ordered):
            module_token = bind_scan_log(scan_id, choice)
            label = MODULE_LABELS.get(choice, choice)
            percent = int((index / total) * 100)
            scan.update_progress(choice, f"{label} çalışıyor…", percent)
            log_activity(f"▶ {label} başlatılıyor…", level="info", module=choice)

            module_key = MODULE_MAP[choice]
            output_text = _run_module(choice, domain, raw_input, config)

            line_count = len([ln for ln in output_text.splitlines() if ln.strip()])
            log_activity(f"✓ {label} bitti — {line_count} satır sonuç.", level="success", module=choice)
            reset_scan_log(module_token)

            ScanModuleResult.objects.create(
                scan=scan,
                module=module_key,
                output=output_text,
                output_file=f"{domain}{OUTPUT_SUFFIX[module_key]}",
            )

        scan.status = Scan.Status.COMPLETED
        scan.progress_percent = 100
        scan.progress_message = "Tarama tamamlandı."
        scan.current_module = ""
        scan.completed_at = timezone.now()
        scan.save(update_fields=[
            "status", "progress_percent", "progress_message",
            "current_module", "completed_at",
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


def _run_module(choice: str, domain: str, raw_input: str, config: dict) -> str:
    if choice == "1":
        ports = validate_ports(config.get("naabuPorts", ""))
        return tools.run_naabu(domain, ports)
    if choice == "2":
        return tools.run_subfinder(domain, config.get("subdomainParams", []))
    if choice == "3":
        return tools.run_wayback(
            domain,
            known_urls=config.get("waybackKnownUrls", False),
            include_subdomains=config.get("includeSubdomains", False),
        )
    if choice == "4":
        match_codes = validate_status_codes(config.get("httpxMatchCodes", ""))
        return tools.run_httpx(
            domain,
            follow_redirects=config.get("httpxFollowRedirects", False),
            show_status=config.get("httpxStatusCode", False),
            match_codes=match_codes,
        )
    if choice == "5":
        templates = validate_template_ids(config.get("nucleiTemplates", ""))
        return tools.run_nuclei(
            domain,
            raw_input,
            templates,
            config.get("nucleiSeverity", []),
        )
    if choice == "6":
        return tools.run_dnsx(domain)
    if choice == "7":
        depth = str(config.get("katanaDepth", "2"))
        return tools.run_katana(domain, depth)
    return ""


def scan_to_context(scan: Scan) -> dict:
    context = {
        "domain": scan.domain,
        "scan": scan,
        "naabu_output": "",
        "subdomain_output": "",
        "wayback_output": "",
        "httpx_output": "",
        "nuclei_output": "",
        "dnsx_output": "",
        "katana_output": "",
    }
    key_map = {
        "naabu": "naabu_output",
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
