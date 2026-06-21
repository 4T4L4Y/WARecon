import html
import json
import re

from scans.services.output_utils import strip_ansi

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _esc(text: str) -> str:
    return html.escape(text)


def _wrap(lines: list[str]) -> str:
    if not lines:
        return '<p class="text-muted mb-0">Sonuç yok.</p>'
    return '<div class="output-rich">' + "".join(lines) + "</div>"


def format_naabu(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if ":" in line:
            host, port = line.rsplit(":", 1)
            lines.append(
                f'<div class="output-line">'
                f'<span class="output-host">{_esc(host)}</span>'
                f'<span class="output-sep">:</span>'
                f'<span class="output-port open">{_esc(port)}</span>'
                f"</div>"
            )
        else:
            lines.append(f'<div class="output-line">{_esc(line)}</div>')
    return _wrap(lines)


def format_nmap(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        cls = "output-line"
        lower = line.lower()
        if "vulnerable" in lower or "cve-" in lower or "exploit" in lower:
            cls += " output-danger"
        elif "open" in lower and "/tcp" in lower:
            cls += " output-success"
        elif line.startswith("PORT") or line.startswith("Nmap scan"):
            cls += " output-header"
        lines.append(f'<div class="{cls}">{_esc(line)}</div>')
    return _wrap(lines)


def format_dnsx(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = strip_ansi(raw).strip()
        if not line:
            continue
        match = re.match(r"^(\S+)\s+\[([^\]]+)\]\s+\[([^\]]+)\]", line)
        if match:
            host, rtype, value = match.groups()
            lines.append(
                f'<div class="output-line">'
                f'<span class="output-host">{_esc(host)}</span>'
                f' <span class="output-sep">[{_esc(rtype)}]</span>'
                f' <span class="output-port open">{_esc(value)}</span>'
                f"</div>"
            )
        else:
            lines.append(f'<div class="output-line">{_esc(line)}</div>')
    return _wrap(lines)


def format_httpx(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = strip_ansi(raw).strip()
        if not line:
            continue
        if line.startswith("===") and line.endswith("==="):
            host = line.strip("= ").strip()
            lines.append(
                f'<div class="output-line output-header">'
                f'<i class="tim-icons icon-world mr-1"></i>{_esc(host)}'
                f"</div>"
            )
            continue
        url = line
        codes = ""
        match = re.match(r"^(https?://\S+?)(?:\s+\[(.+)\])?$", line)
        if match:
            url, codes = match.group(1), (match.group(2) or "")
        status_cls = "output-url"
        if codes:
            code_matches = re.findall(r"\d{3}", codes)
            if code_matches:
                code = int(code_matches[-1])
                if 200 <= code < 300:
                    status_cls = "status-2xx"
                elif 300 <= code < 400:
                    status_cls = "status-3xx"
                elif 400 <= code < 500:
                    status_cls = "status-4xx"
                else:
                    status_cls = "status-5xx"
        code_html = (
            f' <span class="output-status">[{_esc(codes)}]</span>' if codes else ""
        )
        lines.append(
            f'<div class="output-line {status_cls}">'
            f'<span class="output-url-text">{_esc(url)}</span>{code_html}'
            f"</div>"
        )
    return _wrap(lines)


def format_katana(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = strip_ansi(raw).strip()
        if not line:
            continue
        if line.startswith("===") and line.endswith("==="):
            host = line.strip("= ").strip()
            lines.append(
                f'<div class="output-line output-header">{_esc(host)}</div>'
            )
            continue
        lines.append(
            f'<div class="output-line output-url">'
            f'<span class="output-url-text">{_esc(line)}</span>'
            f"</div>"
        )
    return _wrap(lines)


def format_wayback(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = strip_ansi(raw).strip()
        if not line:
            continue
        if line.startswith("===") and line.endswith("==="):
            host = line.strip("= ").strip()
            lines.append(
                f'<div class="output-line output-header">{_esc(host)}</div>'
            )
            continue
        display = line if len(line) <= 160 else line[:157] + "…"
        lines.append(
            f'<div class="output-line output-url" title="{_esc(line)}">'
            f"{_esc(display)}</div>"
        )
    return _wrap(lines)


def format_nuclei(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        sev = "info"
        lower = line.lower()
        for level in ("critical", "high", "medium", "low", "info"):
            if f"[{level}]" in lower or f"{level}" in lower[:20]:
                sev = level
                break
        lines.append(f'<div class="output-line sev-{sev}">{_esc(line)}</div>')
    return _wrap(lines)


def format_subdomain(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        host = raw.strip()
        if host:
            lines.append(
                f'<div class="output-line">'
                f'<span class="output-host">{_esc(host)}</span>'
                f"</div>"
            )
    return _wrap(lines)


def format_default(text: str) -> str:
    lines = [f'<div class="output-line">{_esc(raw)}</div>' for raw in text.splitlines() if raw.strip()]
    return _wrap(lines)


FORMATTERS = {
    "naabu": format_naabu,
    "nmap": format_nmap,
    "httpx": format_httpx,
    "nuclei": format_nuclei,
    "subdomain": format_subdomain,
    "wayback": format_wayback,
    "dnsx": format_dnsx,
    "katana": format_katana,
}


def strip_html_output(text: str) -> str:
    """Plain-text çıktıya dönüştür; yanlışlıkla kaydedilmiş HTML/ANSI çıktısını temizle."""
    if not text:
        return ""
    text = strip_ansi(text)
    if "<" not in text:
        return text
    cleaned = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    cleaned = re.sub(r"</div>\s*", "\n", cleaned, flags=re.I)
    cleaned = re.sub(r"<[^>]+>", "", cleaned)
    return html.unescape(cleaned).strip()


def format_module_output(text: str, module: str) -> str:
    plain = strip_html_output(text)
    if not plain or not plain.strip():
        return '<p class="text-muted mb-0">Sonuç yok.</p>'
    formatter = FORMATTERS.get(module, format_default)
    return formatter(plain)


def parse_nmap_exploits(nmap_text: str) -> list[dict]:
    findings = []
    seen = set()
    for line in nmap_text.splitlines():
        lower = line.lower()
        if not any(k in lower for k in ("cve-", "exploit", "vulnerable", "vulners")):
            continue
        key = line.strip()
        if key in seen:
            continue
        seen.add(key)
        cve_match = re.search(r"CVE-\d{4}-\d+", line, re.I)
        findings.append({
            "summary": line.strip()[:500],
            "cve": cve_match.group(0).upper() if cve_match else "",
            "severity": "high" if "vulnerable" in lower else "medium",
        })
    return findings


def nuclei_severity_counts(nuclei_json_text: str) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    try:
        data = json.loads(nuclei_json_text)
        if not isinstance(data, list):
            return counts
        for item in data:
            sev = (item.get("info") or {}).get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
    except (json.JSONDecodeError, TypeError):
        pass
    return counts
