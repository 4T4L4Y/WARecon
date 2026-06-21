from dataclasses import dataclass, field

from django.utils import timezone

from scans.models import Scan, ScanModuleResult

from . import tools
from .validators import (
    validate_domain,
    validate_ports,
    validate_status_codes,
    validate_template_ids,
)

# Mantıksal pipeline sırası: keşif → arşiv → doğrulama → port → zafiyet
MODULE_ORDER = ["2", "3", "4", "1", "5"]

MODULE_MAP = {
    "1": ScanModuleResult.Module.NAABU,
    "2": ScanModuleResult.Module.SUBDOMAIN,
    "3": ScanModuleResult.Module.WAYBACK,
    "4": ScanModuleResult.Module.HTTPX,
    "5": ScanModuleResult.Module.NUCLEI,
}


@dataclass
class ScanOutputs:
    domain: str = ""
    naabu_output: str = ""
    subdomain_output: str = ""
    wayback_output: str = ""
    httpx_output: str = ""
    nuclei_output: str = ""
    errors: list[str] = field(default_factory=list)


def _ordered_choices(choices: list[str]) -> list[str]:
    return [c for c in MODULE_ORDER if c in choices]


def run_pipeline(form_data: dict) -> tuple[Scan, ScanOutputs]:
    raw_input = form_data.get("domain", "")
    domain = validate_domain(raw_input)
    choices = form_data.get("choices", [])
    ordered = _ordered_choices(choices)

    if "3" in ordered and "2" not in ordered:
        raise ValueError("Wayback modülü için önce Subdomain keşfi gereklidir.")

    scan = Scan.objects.create(
        domain=domain,
        raw_input=raw_input,
        modules=ordered,
        status=Scan.Status.RUNNING,
    )

    outputs = ScanOutputs(domain=domain)

    try:
        for choice in ordered:
            module_key = MODULE_MAP[choice]
            output_text = ""

            if choice == "1":
                ports = validate_ports(form_data.get("naabuPorts", ""))
                output_text = tools.run_naabu(domain, ports)
                outputs.naabu_output = output_text

            elif choice == "2":
                params = form_data.get("subdomainParams", [])
                output_text = tools.run_subfinder(domain, params)
                outputs.subdomain_output = output_text

            elif choice == "3":
                output_text = tools.run_wayback(
                    domain,
                    known_urls=form_data.get("waybackKnownUrls", False),
                    include_subdomains=form_data.get("includeSubdomains", False),
                )
                outputs.wayback_output = output_text

            elif choice == "4":
                match_codes = validate_status_codes(form_data.get("httpxMatchCodes", ""))
                output_text = tools.run_httpx(
                    domain,
                    follow_redirects=form_data.get("httpxFollowRedirects", False),
                    show_status=form_data.get("httpxStatusCode", False),
                    match_codes=match_codes,
                )
                outputs.httpx_output = output_text

            elif choice == "5":
                templates = validate_template_ids(form_data.get("nucleiTemplates", ""))
                output_text = tools.run_nuclei(
                    domain,
                    raw_input,
                    templates,
                    form_data.get("nucleiSeverity", []),
                )
                outputs.nuclei_output = output_text

            ScanModuleResult.objects.create(
                scan=scan,
                module=module_key,
                output=output_text,
                output_file=_output_file_for(module_key, domain),
            )

        scan.status = Scan.Status.COMPLETED
        scan.completed_at = timezone.now()
        scan.save(update_fields=["status", "completed_at"])
        return scan, outputs

    except Exception as exc:
        scan.status = Scan.Status.FAILED
        scan.error_message = str(exc)
        scan.completed_at = timezone.now()
        scan.save(update_fields=["status", "error_message", "completed_at"])
        raise


def _output_file_for(module: str, domain: str) -> str:
    suffix_map = {
        ScanModuleResult.Module.NAABU: f"{domain}_naabu.txt",
        ScanModuleResult.Module.SUBDOMAIN: f"{domain}_subdomains.txt",
        ScanModuleResult.Module.WAYBACK: f"{domain}_wayback.txt",
        ScanModuleResult.Module.HTTPX: f"{domain}_httpx.txt",
        ScanModuleResult.Module.NUCLEI: f"{domain}_nuclei.txt",
    }
    return suffix_map.get(module, "")
