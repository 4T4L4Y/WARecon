from django.utils import timezone
from django.utils.safestring import mark_safe

from scans.models import Scan, ScanModuleResult
from scans.services.formatters import format_module_output, strip_html_output
from scans.services.output_utils import normalize_tool_output
from scans.services.scan_control import (
    consume_skip,
    is_cancelled,
    mark_module_started,
    skip_steps_match,
)
from scans.services.live_log import bind_scan_log, log_activity, reset_scan_log
from scans.services.output_paths import list_subdomains, read_file, safe_name, scan_output_dir

from . import tools
from .validators import (
    validate_domain,
    validate_ports,
    validate_status_codes,
    validate_template_ids,
)

WEB_MODULE_IDS = {"3", "4", "5", "7"}

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

RESULT_KEY_TO_MODULE = {
    "subdomain_output": "subdomain",
    "dnsx_output": "dnsx",
    "wayback_output": "wayback",
    "httpx_output": "httpx",
    "katana_output": "katana",
    "naabu_output": "naabu",
    "nmap_output": "nmap",
    "nuclei_output": "nuclei",
}

CHOICE_TO_OUTPUT_KEY = {
    "2": "subdomain_output",
    "6": "dnsx_output",
    "3": "wayback_output",
    "4": "httpx_output",
    "7": "katana_output",
    "1": "naabu_output",
    "5": "nuclei_output",
}


def ordered_choices(choices: list[str]) -> list[str]:
    return [c for c in MODULE_ORDER if c in choices]


def build_execution_plan(choices: list[str]) -> list[str]:
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
    plain = strip_html_output(normalize_tool_output(output_text))
    ScanModuleResult.objects.update_or_create(
        scan=scan,
        module=module,
        defaults={
            "output": plain,
            "output_file": _output_relpath(scan.pk, filename),
        },
    )


def _needs_subdomain_selection(scan: Scan, hosts: list[str], config: dict) -> bool:
    if config.get("selected_subdomains"):
        return False
    if not WEB_MODULE_IDS.intersection(scan.modules):
        return False
    return len(hosts) > 1


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
        "nucleiTemplateIds": form_data.get("nucleiTemplateIds") or [],
        "nucleiSeverity": form_data.get("nucleiSeverity", []),
        "katanaDepth": form_data.get("katanaDepth", "2"),
        "nmap_exploit_suggestions": [],
        "completed_steps": [],
        "discovered_subdomains": [],
        "selected_subdomains": [],
    }
    template_ids = config.get("nucleiTemplateIds") or []
    if template_ids:
        config["nucleiTemplates"] = ",".join(template_ids)

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
    if scan.status not in (
        Scan.Status.PENDING,
        Scan.Status.RUNNING,
        Scan.Status.AWAITING_SUBDOMAIN_SELECTION,
    ):
        return
    if scan.cancel_requested:
        return

    config = dict(scan.config or {})
    completed = set(config.get("completed_steps", []))
    was_awaiting = scan.status == Scan.Status.AWAITING_SUBDOMAIN_SELECTION

    if not was_awaiting:
        scan.status = Scan.Status.RUNNING
        scan.progress_percent = max(scan.progress_percent, 0)
        scan.save(update_fields=["status", "progress_percent"])

    log_token = bind_scan_log(scan_id)
    if was_awaiting:
        log_activity("Alt alan seçimi alındı — tarama devam ediyor.", level="info")
    else:
        log_activity("Tarama worker tarafından başlatıldı.", level="info")

    domain = scan.domain
    ordered = scan.modules
    plan = build_execution_plan(ordered)
    total = len(plan) + (1 if "1" in ordered else 0)
    step_index = len(completed)

    try:
        for step in plan:
            if step in completed:
                continue

            scan.refresh_from_db()
            if is_cancelled(scan_id):
                log_activity("Tarama iptal edildi.", level="warning")
                return

            if skip_steps_match(scan.skip_module_requested, step):
                consume_skip(scan, step)
                label = MODULE_LABELS.get(step, step)
                log_activity(f"⏭ {label} atlandı — mevcut çıktılarla devam.", level="warning", module=step)
                completed.add(step)
                config["completed_steps"] = list(completed)
                scan.config = config
                scan.save(update_fields=["config"])
                step_index += 1
                continue

            module_token = bind_scan_log(scan_id, step)
            label = MODULE_LABELS.get(step, step)
            mark_module_started(scan, step)
            percent = int((step_index / max(total, 1)) * 100)
            scan.update_progress(step, f"{label} çalışıyor…", percent)
            log_activity(f"▶ {label} başlatılıyor…", level="info", module=step)

            if step == "2":
                output_text = tools.run_subfinder(
                    scan_id, domain, config.get("subdomainParams", [])
                )
                _save_module_result(
                    scan,
                    ScanModuleResult.Module.SUBDOMAIN,
                    output_text,
                    f"{domain}_subdomains.txt",
                )
                completed.add("2")
                config["completed_steps"] = list(completed)
                scan.config = config
                scan.save(update_fields=["config"])

                hosts = list_subdomains(scan_output_dir(scan_id), domain)
                if _needs_subdomain_selection(scan, hosts, config):
                    config["discovered_subdomains"] = hosts
                    scan.config = config
                    scan.status = Scan.Status.AWAITING_SUBDOMAIN_SELECTION
                    scan.progress_message = (
                        f"{len(hosts)} alt alan bulundu — seçim bekleniyor."
                    )
                    scan.save(update_fields=[
                        "config", "status", "progress_message",
                    ])
                    log_activity(
                        f"{len(hosts)} alt alan bulundu. Lütfen hangilerinin taranacağını seçin.",
                        level="warning",
                    )
                    reset_scan_log(module_token)
                    reset_scan_log(log_token)
                    return

            elif step == "web":
                web_flags = _web_flags(scan, config)
                outputs = tools.run_per_subdomain_web_pipeline(
                    scan_id,
                    domain,
                    config,
                    hosts=_selected_hosts(scan_id, domain, config),
                    **web_flags,
                )
                _persist_web_outputs(scan, ordered, outputs)
            elif step == "1":
                _run_naabu_nmap_phase(scan, config)
                step_index += 1
            else:
                output_text = _run_simple_module(scan_id, step, domain, config)
                module_key = MODULE_MAP[step]
                filename = f"{domain}{OUTPUT_SUFFIX[module_key]}"
                _save_module_result(scan, module_key, output_text, filename)
                line_count = len([ln for ln in output_text.splitlines() if ln.strip()])
                log_activity(f"✓ {label} bitti — {line_count} satır.", level="success", module=step)

            scan.refresh_from_db()
            if skip_steps_match(scan.skip_module_requested, step):
                consume_skip(scan, step)
                log_activity(
                    f"⏭ {label} atlandı — mevcut çıktılarla devam.",
                    level="warning",
                    module=step,
                )

            completed.add(step)
            config["completed_steps"] = list(completed)
            scan.config = config
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
        from scans.services.notifications import (
            collect_nuclei_items_for_scan,
            notify_critical_findings,
            notify_scan_finished,
        )

        notify_scan_finished(scan)
        notify_critical_findings(scan, collect_nuclei_items_for_scan(scan))
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


def _web_flags(scan: Scan, config: dict) -> dict:
    overrides = config.get("web_modules_selected") or {}
    modules = set(scan.modules)
    return {
        "run_wayback": overrides.get("wayback", "3" in modules),
        "run_httpx": overrides.get("httpx", "4" in modules),
        "run_nuclei": overrides.get("nuclei", "5" in modules),
        "run_katana": overrides.get("katana", "7" in modules),
    }


def _selected_hosts(scan_id: int, domain: str, config: dict) -> list[str]:
    selected = config.get("selected_subdomains") or []
    if selected:
        return selected
    return list_subdomains(scan_output_dir(scan_id), domain)


def _persist_web_outputs(scan: Scan, ordered: list[str], outputs: dict[str, str]) -> None:
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
        lines = len([ln for ln in text.splitlines() if ln.strip()])
        log_activity(
            f"✓ {MODULE_LABELS[choice_id]} — {lines} satır toplandı.",
            level="success" if lines else "warning",
            module=choice_id,
        )


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

    _save_module_result(
        scan,
        ScanModuleResult.Module.NMAP,
        nmap_out,
        f"{scan.domain}_nmap.txt",
    )
    if exploits:
        log_activity(
            f"⚠ {len(exploits)} olası exploit/zafiyet bulgusu.",
            level="warning",
        )


def _run_simple_module(scan_id: int, choice: str, domain: str, config: dict) -> str:
    if choice == "6":
        return tools.run_dnsx(scan_id, domain)
    return ""


def apply_subdomain_selection(
    scan: Scan,
    selected_hosts: list[str],
    *,
    run_wayback: bool,
    run_httpx: bool,
    run_nuclei: bool,
    run_katana: bool,
) -> None:
    config = dict(scan.config or {})
    config["selected_subdomains"] = selected_hosts
    config["web_modules_selected"] = {
        "wayback": run_wayback,
        "httpx": run_httpx,
        "nuclei": run_nuclei,
        "katana": run_katana,
    }
    scan.config = config
    scan.status = Scan.Status.RUNNING
    scan.progress_message = "Seçilen alt alanlar taranıyor…"
    scan.save(update_fields=["config", "status", "progress_message"])


def refresh_scan_outputs(
    scan: Scan,
    *,
    rerun_wayback: bool = False,
    rerun_httpx: bool = False,
    rerun_nuclei: bool = False,
    rerun_katana: bool = False,
    rerun_nmap: bool = False,
) -> None:
    """Diskteki araç çıktılarını DB ile senkronize et; isteğe bağlı modülleri yeniden çalıştır."""
    scan_dir = scan_output_dir(scan.pk)
    config = dict(scan.config or {})
    hosts = config.get("selected_subdomains") or list_subdomains(scan_dir, scan.domain)
    web_flags = config.get("web_modules_selected") or {}

    if "6" in (scan.modules or []):
        dnsx_path = scan_dir / f"{scan.domain}_dnsx.txt"
        if dnsx_path.is_file():
            _save_module_result(
                scan,
                ScanModuleResult.Module.DNSX,
                read_file(dnsx_path),
                f"{scan.domain}_dnsx.txt",
            )

    if rerun_wayback or rerun_httpx or rerun_nuclei or rerun_katana:
        outputs = tools.run_per_subdomain_web_pipeline(
            scan.pk,
            scan.domain,
            config,
            hosts=hosts,
            run_wayback=rerun_wayback and web_flags.get("wayback", "3" in scan.modules),
            run_httpx=rerun_httpx and web_flags.get("httpx", "4" in scan.modules),
            run_nuclei=rerun_nuclei and web_flags.get("nuclei", "5" in scan.modules),
            run_katana=rerun_katana and web_flags.get("katana", "7" in scan.modules),
        )
        _persist_web_outputs(scan, scan.modules, outputs)
    else:
        outputs = _collect_web_outputs_from_disk(scan, hosts)
        _persist_web_outputs(scan, scan.modules, outputs)

    if rerun_nmap and "1" in (scan.modules or []):
        _run_naabu_nmap_phase(scan, config)


def _collect_web_outputs_from_disk(scan: Scan, hosts: list[str]) -> dict[str, str]:
    scan_dir = scan_output_dir(scan.pk)
    buckets = {"wayback": [], "httpx": [], "nuclei": [], "katana": []}
    suffix_map = {
        "wayback": "_wayback.txt",
        "httpx": "_httpx.txt",
        "nuclei": "_nuclei.txt",
        "katana": "_katana.txt",
    }
    for host in hosts:
        safe = safe_name(host)
        for key, suffix in suffix_map.items():
            path = scan_dir / f"{safe}{suffix}"
            if not path.is_file():
                continue
            text = normalize_tool_output(read_file(path))
            if text.strip():
                buckets[key].append(f"=== {host} ===\n{text}")
    return {key: "\n\n".join(parts) for key, parts in buckets.items()}


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
        "enabled_modules": set(scan.modules or []),
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
            context[key] = strip_html_output(result.output)

    for output_key, module_name in RESULT_KEY_TO_MODULE.items():
        raw = context.get(output_key, "")
        context[f"{output_key}_html"] = mark_safe(
            format_module_output(raw, module_name)
        )
        context[f"{output_key}_empty"] = not (raw and str(raw).strip())

    context["result_tabs"] = _result_tabs(scan, context)
    return context


def _result_tabs(scan: Scan, context: dict) -> list[dict]:
    tabs = [
        ("2", "subdomain_output", "Subdomain", "subdomain", "icon-world"),
        ("6", "dnsx_output", "DNS", "dnsx", "icon-cloud-download-93"),
        ("3", "wayback_output", "Wayback", "wayback", "icon-book-bookmark"),
        ("4", "httpx_output", "HTTPX", "httpx", "icon-link-72"),
        ("7", "katana_output", "Katana", "katana", "icon-map-big"),
        ("1", "naabu_output", "Port", "naabu", "icon-spaceship"),
        ("8", "nmap_output", "Nmap", "nmap", "icon-zoom-split"),
        ("5", "nuclei_output", "Nuclei", "nuclei", "icon-lock-circle"),
    ]
    result = []
    modules = set(scan.modules or [])
    for choice, key, label, fmt, icon in tabs:
        if choice not in modules and not (choice == "8" and "1" in modules):
            continue
        raw = context.get(key, "")
        result.append({
            "choice": choice,
            "key": key,
            "label": label,
            "icon": icon,
            "fmt": fmt,
            "html": context.get(f"{key}_html", ""),
            "is_empty": not (raw and str(raw).strip()),
        })
    return result
