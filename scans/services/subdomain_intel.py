"""Asenkron OSINT / Threat Intelligence — AlienVault OTX (+ opsiyonel VirusTotal)."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp
from django.conf import settings
from django.utils import timezone

from scans.models import Scan, SubdomainIntelResult
from scans.services.live_log import log_activity
from scans.services.live_subdomains import collect_live_subdomains

logger = logging.getLogger("scans")

OTX_GENERAL_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{host}/general"
OTX_MALWARE_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{host}/malware"
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{host}"


class AsyncRateLimiter:
    """Saniyede belirli sayıda istek (varsayılan: 2/s)."""

    def __init__(self, rate_per_second: float = 2.0):
        self._interval = 1.0 / max(rate_per_second, 0.1)
        self._lock = asyncio.Lock()
        self._last_at = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._last_at + self._interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_at = time.monotonic()


@dataclass
class IntelSignals:
    pulse_count: int = 0
    malware_count: int = 0
    malicious_votes: int = 0
    suspicious_votes: int = 0
    sources: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def threat_level_from_score(score: int) -> str:
    if score >= 75:
        return SubdomainIntelResult.ThreatLevel.CRITICAL
    if score >= 50:
        return SubdomainIntelResult.ThreatLevel.HIGH
    if score >= 25:
        return SubdomainIntelResult.ThreatLevel.MEDIUM
    return SubdomainIntelResult.ThreatLevel.LOW


def calculate_risk_score(signals: IntelSignals) -> int:
    """0–100 risk skoru — pulse, malware ve AV oylarına göre."""
    score = 0

    pulse = min(signals.pulse_count, 20)
    score += min(pulse * 4, 40)

    if signals.malware_count > 0:
        score += min(15 + signals.malware_count * 3, 35)

    if signals.malicious_votes > 0:
        score += min(signals.malicious_votes * 8, 40)

    if signals.suspicious_votes > 0:
        score += min(signals.suspicious_votes * 3, 15)

    if signals.pulse_count >= 10:
        score += 10
    elif signals.pulse_count >= 5:
        score += 5

    return min(100, max(0, score))


def build_summary(signals: IntelSignals, score: int) -> str:
    parts = [f"Risk skoru: {score}/100"]
    if signals.pulse_count:
        parts.append(f"OTX pulse: {signals.pulse_count}")
    if signals.malware_count:
        parts.append(f"Malware kaydı: {signals.malware_count}")
    if signals.malicious_votes:
        parts.append(f"VT malicious: {signals.malicious_votes}")
    if signals.notes:
        parts.append("; ".join(signals.notes[:3]))
    return " · ".join(parts)


async def _fetch_json(
    session: aiohttp.ClientSession,
    limiter: AsyncRateLimiter,
    url: str,
    headers: dict[str, str],
) -> dict[str, Any] | None:
    await limiter.acquire()
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=25)) as resp:
            if resp.status == 404:
                return {}
            if resp.status == 429:
                logger.warning("Rate limit 429: %s", url)
                await asyncio.sleep(2)
                return None
            if resp.status >= 400:
                logger.warning("Intel API %s: %s", resp.status, url)
                return None
            return await resp.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        logger.warning("Intel fetch failed %s: %s", url, exc)
        return None


def _merge_otx_general(signals: IntelSignals, data: dict[str, Any]) -> None:
    if not data:
        return
    signals.sources.append("otx")
    pulse_info = data.get("pulse_info") or {}
    signals.pulse_count = int(pulse_info.get("count") or 0)
    validation = data.get("validation") or []
    for item in validation:
        if not isinstance(item, dict):
            continue
        name = (item.get("name") or "").lower()
        if "malware" in name or "phish" in name:
            signals.notes.append(item.get("message") or name)
    signals.raw["otx_general"] = {
        "pulse_count": signals.pulse_count,
        "validation": validation[:5],
    }


def _merge_otx_malware(signals: IntelSignals, data: dict[str, Any]) -> None:
    if not data:
        return
    count = int(data.get("count") or 0)
    if not count and isinstance(data.get("data"), list):
        count = len(data["data"])
    signals.malware_count = max(signals.malware_count, count)
    signals.raw["otx_malware"] = {"count": count}


def _merge_virustotal(signals: IntelSignals, data: dict[str, Any]) -> None:
    if not data:
        return
    signals.sources.append("virustotal")
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    signals.malicious_votes = int(stats.get("malicious") or 0)
    signals.suspicious_votes = int(stats.get("suspicious") or 0)
    rep = attrs.get("reputation")
    if rep is not None and int(rep) < 0:
        signals.notes.append(f"VT reputation: {rep}")
    signals.raw["virustotal"] = {
        "malicious": signals.malicious_votes,
        "suspicious": signals.suspicious_votes,
        "reputation": rep,
    }


async def query_host_intel(
    session: aiohttp.ClientSession,
    limiter: AsyncRateLimiter,
    host: str,
    *,
    otx_key: str,
    vt_key: str,
) -> IntelSignals:
    signals = IntelSignals()
    otx_headers = {"X-OTX-API-KEY": otx_key}

    general = await _fetch_json(session, limiter, OTX_GENERAL_URL.format(host=host), otx_headers)
    if general is not None:
        _merge_otx_general(signals, general)

    malware = await _fetch_json(session, limiter, OTX_MALWARE_URL.format(host=host), otx_headers)
    if malware is not None:
        _merge_otx_malware(signals, malware)

    if vt_key:
        vt_headers = {"x-apikey": vt_key}
        vt_data = await _fetch_json(session, limiter, VT_DOMAIN_URL.format(host=host), vt_headers)
        if vt_data is not None:
            _merge_virustotal(signals, vt_data)

    return signals


async def run_intel_queries(
    hosts: list[dict],
    *,
    otx_key: str,
    vt_key: str,
    rate_limit: float,
) -> list[dict]:
    limiter = AsyncRateLimiter(rate_per_second=rate_limit)
    results: list[dict] = []

    async with aiohttp.ClientSession() as session:
        for item in hosts:
            host = item["host"]
            signals = await query_host_intel(
                session, limiter, host, otx_key=otx_key, vt_key=vt_key,
            )
            score = calculate_risk_score(signals)
            results.append({
                "host": host,
                "live_reasons": item.get("reasons", []),
                "risk_score": score,
                "threat_level": threat_level_from_score(score),
                "pulse_count": signals.pulse_count,
                "malware_count": signals.malware_count,
                "malicious_votes": signals.malicious_votes,
                "sources": list(dict.fromkeys(signals.sources)),
                "summary": build_summary(signals, score),
                "raw_data": signals.raw,
            })
    return results


def _update_scan_intel_config(scan: Scan, **fields) -> None:
    config = dict(scan.config or {})
    intel_cfg = dict(config.get("intel") or {})
    intel_cfg.update(fields)
    config["intel"] = intel_cfg
    scan.config = config
    scan.save(update_fields=["config"])


def persist_intel_results(scan: Scan, rows: list[dict]) -> None:
    SubdomainIntelResult.objects.filter(scan=scan).delete()
    SubdomainIntelResult.objects.bulk_create([
        SubdomainIntelResult(
            scan=scan,
            hostname=row["host"],
            risk_score=row["risk_score"],
            threat_level=row["threat_level"],
            live_reasons=row["live_reasons"],
            pulse_count=row["pulse_count"],
            malware_count=row["malware_count"],
            malicious_votes=row["malicious_votes"],
            sources=row["sources"],
            summary=row["summary"],
            raw_data=row["raw_data"],
        )
        for row in rows
    ])


def run_subdomain_intel(scan_id: int) -> dict:
    """RQ worker tarafından çağrılır; asyncio ile async sorguları çalıştırır."""
    scan = Scan.objects.get(pk=scan_id)
    otx_key = getattr(settings, "OTX_API_KEY", "") or ""
    vt_key = getattr(settings, "VIRUSTOTAL_API_KEY", "") or ""
    max_hosts = int(getattr(settings, "INTEL_MAX_HOSTS", 50))
    rate_limit = float(getattr(settings, "INTEL_RATE_LIMIT", 2.0))

    if not otx_key:
        _update_scan_intel_config(
            scan,
            status="skipped",
            message="OTX_API_KEY tanımlı değil — istihbarat atlandı.",
            completed_at=timezone.now().isoformat(),
        )
        log_activity("OSINT: OTX_API_KEY yok, istihbarat atlandı.", level="warning")
        return {"ok": False, "reason": "no_api_key"}

    live_hosts = collect_live_subdomains(scan)
    if not live_hosts:
        _update_scan_intel_config(
            scan,
            status="skipped",
            message="Canlı doğrulanmış alt alan bulunamadı.",
            live_count=0,
            completed_at=timezone.now().isoformat(),
        )
        log_activity("OSINT: Canlı alt alan yok, sorgu yapılmadı.", level="info")
        return {"ok": True, "queried": 0}

    if len(live_hosts) > max_hosts:
        live_hosts = live_hosts[:max_hosts]
        log_activity(
            f"OSINT: {max_hosts} canlı hedefle sınırlandı (rate limit koruması).",
            level="warning",
        )

    _update_scan_intel_config(
        scan,
        status="running",
        live_count=len(live_hosts),
        started_at=timezone.now().isoformat(),
    )
    log_activity(
        f"OSINT: {len(live_hosts)} canlı alt alan için tehdit istihbaratı sorgulanıyor…",
        level="info",
    )

    rows = asyncio.run(
        run_intel_queries(
            live_hosts,
            otx_key=otx_key,
            vt_key=vt_key,
            rate_limit=rate_limit,
        )
    )
    persist_intel_results(scan, rows)

    top = sorted(rows, key=lambda r: r["risk_score"], reverse=True)[:5]
    _update_scan_intel_config(
        scan,
        status="completed",
        queried=len(rows),
        top_critical=[r["host"] for r in top if r["risk_score"] >= 50],
        completed_at=timezone.now().isoformat(),
    )
    log_activity(
        f"OSINT tamamlandı — {len(rows)} hedef skorlandı.",
        level="success",
    )
    if top and top[0]["risk_score"] >= 50:
        log_activity(
            f"⚠ En yüksek risk: {top[0]['host']} ({top[0]['risk_score']}/100)",
            level="warning",
        )
    return {"ok": True, "queried": len(rows)}


def intel_context_for_scan(scan: Scan) -> dict:
    """Şablon / API için istihbarat özeti."""
    results = list(scan.intel_results.all())
    intel_cfg = (scan.config or {}).get("intel") or {}
    return {
        "status": intel_cfg.get("status", "pending"),
        "message": intel_cfg.get("message", ""),
        "live_count": intel_cfg.get("live_count", 0),
        "queried": intel_cfg.get("queried", len(results)),
        "results": results,
        "top_critical": results[:5],
        "has_api_key": bool(getattr(settings, "OTX_API_KEY", "")),
    }
