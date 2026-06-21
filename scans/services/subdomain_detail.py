import json
import re
from pathlib import Path

from django.utils.safestring import mark_safe

from scans.models import Scan
from scans.services.formatters import format_module_output, strip_html_output
from scans.services.output_paths import read_file, safe_name, scan_output_dir
from scans.services.output_utils import normalize_tool_output

HOST_SUFFIXES = {
    "wayback": "_wayback.txt",
    "httpx": "_httpx.txt",
    "nuclei": "_nuclei.txt",
    "katana": "_katana.txt",
    "whatweb": "_whatweb.txt",
}

MODULE_FMT = {
    "wayback": "wayback",
    "httpx": "httpx",
    "nuclei": "nuclei",
    "katana": "katana",
    "whatweb": "whatweb",
}


def subdomain_breakdown(scan: Scan) -> list[dict]:
    config = scan.config or {}
    discovered = list(config.get("discovered_subdomains") or [])
    if not discovered:
        from scans.models import ScanModuleResult

        sub = scan.results.filter(module=ScanModuleResult.Module.SUBDOMAIN).first()
        if sub and sub.output:
            discovered = [ln.strip() for ln in sub.output.splitlines() if ln.strip()]
    if scan.domain and scan.domain not in discovered:
        discovered.insert(0, scan.domain)
    selected = set(config.get("selected_subdomains") or [])

    items = []
    for host in discovered:
        is_root = host == scan.domain
        scanned = host in selected or (is_root and not selected)
        items.append({
            "host": host,
            "scanned": scanned,
            "is_root": is_root,
        })
    return items


def read_host_module_output(scan_id: int, host: str, module_key: str) -> str:
    scan_dir = scan_output_dir(scan_id)
    suffix = HOST_SUFFIXES.get(module_key)
    if not suffix:
        return ""
    path = scan_dir / f"{safe_name(host)}{suffix}"
    if not path.is_file():
        return ""
    return normalize_tool_output(read_file(path))


def host_results_context(scan: Scan, host: str | None) -> dict:
    """Per-subdomain module outputs for detail view."""
    config = scan.config or {}
    modules = set(scan.modules or [])
    web_flags = config.get("web_modules_selected") or {}
    host = host or scan.domain

    keys = []
    if "3" in modules and web_flags.get("wayback", True):
        keys.append("wayback")
    if "4" in modules and web_flags.get("httpx", True):
        keys.append("httpx")
    if "5" in modules and web_flags.get("nuclei", True):
        keys.append("nuclei")
    if "7" in modules and web_flags.get("katana", True):
        keys.append("katana")
    if "5" in modules:
        keys.append("whatweb")

    panels = []
    for key in keys:
        raw = read_host_module_output(scan.pk, host, key)
        fmt = MODULE_FMT[key]
        panels.append({
            "key": key,
            "label": key.upper() if key != "whatweb" else "WhatWeb",
            "raw": raw,
            "html": mark_safe(format_module_output(raw, fmt)),
            "is_empty": not raw.strip(),
        })

    return {
        "host": host,
        "panels": panels,
    }
