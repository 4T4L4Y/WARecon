"""Canlı (HTTP/80/443) doğrulanmış alt alanları tespit eder."""

from __future__ import annotations

from urllib.parse import urlparse

from scans.models import Scan, ScanModuleResult
from scans.services.output_paths import list_subdomains, read_file, safe_name, scan_output_dir
from scans.services.output_utils import extract_urls_from_text, normalize_tool_output
from scans.services import tools

LIVE_PORTS = {"80", "443"}


def _all_candidate_hosts(scan: Scan) -> list[str]:
    config = scan.config or {}
    hosts = list(config.get("discovered_subdomains") or [])
    if not hosts:
        hosts = list_subdomains(scan_output_dir(scan.pk), scan.domain)
    if not hosts:
        sub = scan.results.filter(module=ScanModuleResult.Module.SUBDOMAIN).first()
        if sub and sub.output:
            hosts = [ln.strip() for ln in sub.output.splitlines() if ln.strip()]
    selected = config.get("selected_subdomains") or []
    if selected:
        hosts = [h for h in hosts if h in selected]
    if scan.domain and scan.domain not in hosts:
        hosts.insert(0, scan.domain)
    seen: set[str] = set()
    ordered: list[str] = []
    for host in hosts:
        h = host.strip().lower()
        if h and h not in seen:
            seen.add(h)
            ordered.append(host.strip())
    return ordered


def _hosts_from_httpx_files(scan_id: int, hosts: list[str]) -> set[str]:
    scan_dir = scan_output_dir(scan_id)
    live: set[str] = set()
    for host in hosts:
        path = scan_dir / f"{safe_name(host)}_httpx.txt"
        if path.is_file() and normalize_tool_output(read_file(path)):
            live.add(host)
    return live


def _hosts_from_aggregated_httpx(scan: Scan) -> set[str]:
    result = scan.results.filter(module=ScanModuleResult.Module.HTTPX).first()
    if not result or not result.output:
        return set()
    live: set[str] = set()
    for url in extract_urls_from_text(result.output):
        host = urlparse(url).hostname
        if host:
            live.add(host)
    return live


def _hosts_from_naabu(scan: Scan) -> dict[str, set[str]]:
    """host -> {'port80', 'port443'}"""
    result = scan.results.filter(module=ScanModuleResult.Module.NAABU).first()
    text = ""
    if result and result.output:
        text = normalize_tool_output(result.output)
    if not text:
        path = scan_output_dir(scan.pk) / f"{scan.domain}_naabu.txt"
        if path.is_file():
            text = normalize_tool_output(read_file(path))
    ports_map = tools.parse_naabu_ports(text)
    reasons: dict[str, set[str]] = {}
    for host, ports in ports_map.items():
        tags: set[str] = set()
        if "80" in ports:
            tags.add("port80")
        if "443" in ports:
            tags.add("port443")
        if tags:
            reasons[host] = tags
    return reasons


def collect_live_subdomains(scan: Scan) -> list[dict]:
    """
    Sadece canlı doğrulanmış alt alanları döndürür.

    Kriter (en az biri):
    - HTTPX yanıtı (dosya veya birleşik çıktı)
    - Naabu'da 80 veya 443 açık
    """
    candidates = _all_candidate_hosts(scan)
    if not candidates:
        return []

    httpx_live = _hosts_from_httpx_files(scan.pk, candidates)
    httpx_live |= _hosts_from_aggregated_httpx(scan)
    naabu_reasons = _hosts_from_naabu(scan)

    results: list[dict] = []
    for host in candidates:
        reasons: list[str] = []
        if host in httpx_live:
            reasons.append("httpx")
        if host in naabu_reasons:
            reasons.extend(sorted(naabu_reasons[host]))
        if not reasons:
            continue
        results.append({
            "host": host,
            "reasons": reasons,
        })
    return results
