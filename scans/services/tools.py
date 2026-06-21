import re
from pathlib import Path

from .live_log import log_activity
from .output_paths import list_subdomains, read_combined, read_file, safe_name, scan_output_dir
from .output_utils import normalize_tool_output, prepare_url_input_file, strip_ansi, write_url_list
from .runner import run_command


def _target_file(scan_dir: Path, host: str, suffix: str) -> Path:
    return scan_dir / f"{safe_name(host)}{suffix}"


def _non_empty_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [ln.strip() for ln in read_file(path).splitlines() if ln.strip()]


def _url_list_file(scan_dir: Path, host: str, suffix: str, fallback_url: str) -> Path:
    path = _target_file(scan_dir, host, suffix)
    lines = _non_empty_lines(path)
    if lines:
        return path
    path.write_text(fallback_url.rstrip() + "\n", encoding="utf-8")
    return path


def run_subfinder(scan_id: int, domain: str, params: list[str]) -> str:
    scan_dir = scan_output_dir(scan_id)
    out = scan_dir / f"{domain}_subdomains.txt"
    if out.exists():
        out.unlink()
    args = ["subfinder", "-d", domain, "-o", str(out)]
    for param in params:
        if param == "-all":
            args.append("-all")
    run_command(args)
    return read_file(out)


def run_dnsx(scan_id: int, domain: str) -> str:
    scan_dir = scan_output_dir(scan_id)
    out = scan_dir / f"{domain}_dnsx.txt"
    sub_file = scan_dir / f"{domain}_subdomains.txt"
    if sub_file.exists() and sub_file.stat().st_size > 0:
        run_command(["dnsx", "-l", str(sub_file), "-resp", "-nc", "-o", str(out)])
    else:
        run_command(["dnsx", "-d", domain, "-resp", "-nc", "-o", str(out)])
    return normalize_tool_output(read_file(out))


def run_wayback_host(
    scan_id: int,
    host: str,
    *,
    known_urls: bool = True,
    include_subdomains: bool = False,
) -> str:
    scan_dir = scan_output_dir(scan_id)
    out = _target_file(scan_dir, host, "_wayback.txt")
    suffix_args = ["--known_urls"]
    if include_subdomains:
        suffix_args.append("--subdomain")
    args = ["waybackpy", "-u", host, *suffix_args]
    log_activity(f"Wayback: {host}")
    run_command(args, output_file=out)
    return normalize_tool_output(read_file(out))


def run_httpx_on_list(
    scan_id: int,
    host: str,
    input_file: Path,
    *,
    follow_redirects: bool = False,
    show_status: bool = False,
    match_codes: str = "",
) -> str:
    scan_dir = scan_output_dir(scan_id)
    out = _target_file(scan_dir, host, "_httpx.txt")
    base = ["httpx", "-nc"]
    if follow_redirects:
        base.append("-fr")
    if show_status:
        base.append("-sc")
    if match_codes:
        base.extend(["-mc", match_codes])
    run_command([*base, "-l", str(input_file), "-o", str(out)])
    return normalize_tool_output(read_file(out))


def _nuclei_input_file(scan_dir: Path, host: str, input_file: Path) -> Path:
    clean = _target_file(scan_dir, host, "_nuclei_input.txt")
    return prepare_url_input_file(input_file, clean)


def run_nuclei_on_list(
    scan_id: int,
    host: str,
    input_file: Path,
    templates: str,
    severities: list[str],
    *,
    tags: list[str] | None = None,
) -> str:
    scan_dir = scan_output_dir(scan_id)
    out_txt = _target_file(scan_dir, host, "_nuclei.txt")
    out_json = _target_file(scan_dir, host, "_nuclei.json")
    nuclei_input = _nuclei_input_file(scan_dir, host, input_file)
    args = [
        "nuclei", "-l", str(nuclei_input), "-nh", "-nc",
        "-o", str(out_txt), "-je", str(out_json),
    ]
    if templates:
        for template_id in [t.strip() for t in templates.split(",") if t.strip()]:
            args.extend(["-id", template_id])
    if severities:
        args.extend(["-severity", ",".join(severities)])
    if tags:
        args.extend(["-tags", ",".join(tags[:25])])
    run_command(args)
    return normalize_tool_output(read_file(out_txt))


def _katana_input_file(scan_dir: Path, host: str, httpx_file: Path | None) -> Path | None:
    if httpx_file and httpx_file.is_file() and httpx_file.stat().st_size > 0:
        clean = _target_file(scan_dir, host, "_katana_input.txt")
        return prepare_url_input_file(httpx_file, clean)
    return httpx_file


def run_katana_on_target(
    scan_id: int,
    host: str,
    *,
    depth: str = "2",
    httpx_file: Path | None = None,
) -> str:
    scan_dir = scan_output_dir(scan_id)
    out = _target_file(scan_dir, host, "_katana.txt")
    args = ["katana", "-silent", "-nc", "-depth", depth, "-o", str(out)]
    katana_input = _katana_input_file(scan_dir, host, httpx_file)
    if katana_input and katana_input.is_file() and katana_input.stat().st_size > 0:
        run_command([*args, "-list", str(katana_input)])
    else:
        run_command([*args, "-u", f"https://{host}"])
    return normalize_tool_output(read_file(out))


def parse_whatweb_tags(raw: str) -> list[str]:
    import json

    tags: set[str] = set()
    text = raw.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            plugins = entry.get("plugins") or {}
            for name in plugins:
                tag = name.lower().replace(" ", "-").replace("_", "-")
                if tag and len(tag) < 40:
                    tags.add(tag)
    except json.JSONDecodeError:
        for line in text.splitlines():
            for part in re.findall(r"\[([^\]]+)\]", line):
                tag = part.lower().replace(" ", "-")
                if tag:
                    tags.add(tag)
    return sorted(tags)[:25]


def run_whatweb_on_target(scan_id: int, host: str, url: str) -> tuple[str, list[str]]:
    scan_dir = scan_output_dir(scan_id)
    out = _target_file(scan_dir, host, "_whatweb.txt")
    json_out = _target_file(scan_dir, host, "_whatweb.json")
    args = ["whatweb", "--color=never", "--log-json=-", url]
    log_activity(f"WhatWeb: {host}")
    run_command(args, output_file=json_out)
    raw = read_file(json_out)
    if not raw.strip():
        run_command(["whatweb", "--color=never", url], output_file=out)
        raw = read_file(out)
    else:
        out.write_text(raw, encoding="utf-8")
    tags = parse_whatweb_tags(raw)
    if tags:
        log_activity(f"{host}: WhatWeb etiketleri → {', '.join(tags[:8])}", level="info")
    return normalize_tool_output(raw), tags


def run_per_subdomain_web_pipeline(
    scan_id: int,
    domain: str,
    config: dict,
    *,
    hosts: list[str] | None = None,
    run_wayback: bool,
    run_httpx: bool,
    run_nuclei: bool,
    run_katana: bool,
) -> dict[str, str]:
    """Wayback per subdomain, then HTTPX/Nuclei/Katana on URLs or fallback host."""
    scan_dir = scan_output_dir(scan_id)
    if hosts is None:
        hosts = list_subdomains(scan_dir, domain)
    if not hosts:
        hosts = [domain]
    wayback_all: list[str] = []
    httpx_all: list[str] = []
    nuclei_all: list[str] = []
    katana_all: list[str] = []
    whatweb_all: list[str] = []

    httpx_opts = {
        "follow_redirects": config.get("httpxFollowRedirects", False),
        "show_status": config.get("httpxStatusCode", False),
        "match_codes": config.get("httpxMatchCodes", ""),
    }
    templates = config.get("nucleiTemplates", "")
    template_ids = config.get("nucleiTemplateIds") or []
    if template_ids:
        templates = ",".join(template_ids)
    severities = config.get("nucleiSeverity", [])
    depth = str(config.get("katanaDepth", "2"))

    from scans.services.scan_control import check_abort

    for host in hosts:
        abort = check_abort(scan_id, "web")
        if abort == "cancel":
            break
        if abort == "skip":
            log_activity("Web adımı atlandı — mevcut çıktılarla devam.", level="warning")
            break

        log_activity(f"▸ Alt alan işleniyor: {host}", level="info")

        wayback_path = _target_file(scan_dir, host, "_wayback.txt")
        if run_wayback:
            wb = run_wayback_host(
                scan_id,
                host,
                known_urls=config.get("waybackKnownUrls", False),
                include_subdomains=config.get("includeSubdomains", False),
            )
            if wb.strip():
                wayback_all.append(f"=== {host} ===\n{wb}")
        elif wayback_path.is_file():
            wb = read_file(wayback_path)
        else:
            wb = ""

        if wb.strip():
            target_file = wayback_path
            log_activity(f"{host}: Wayback URL'leri kullanılıyor ({len(_non_empty_lines(wayback_path))} satır)")
        else:
            target_file = _url_list_file(scan_dir, host, "_targets.txt", f"https://{host}")
            log_activity(f"{host}: Wayback boş — doğrudan host hedefleniyor")

        httpx_path = _target_file(scan_dir, host, "_httpx.txt")
        if run_httpx:
            hx = run_httpx_on_list(scan_id, host, target_file, **httpx_opts)
            if hx.strip():
                httpx_all.append(f"=== {host} ===\n{hx}")
        elif httpx_path.is_file():
            hx = read_file(httpx_path)
        else:
            hx = ""

        nuclei_input = httpx_path if hx.strip() and httpx_path.is_file() else target_file
        whatweb_tags: list[str] = []
        if run_nuclei:
            primary_url = f"https://{host}"
            if hx.strip():
                from scans.services.output_utils import extract_urls_from_text

                urls = extract_urls_from_text(hx)
                if urls:
                    primary_url = urls[0]
            ww_text, whatweb_tags = run_whatweb_on_target(scan_id, host, primary_url)
            if ww_text.strip():
                whatweb_all.append(f"=== {host} ===\n{ww_text}")

        if run_nuclei:
            nu = run_nuclei_on_list(
                scan_id, host, nuclei_input, templates, severities, tags=whatweb_tags,
            )
            if nu.strip():
                nuclei_all.append(f"=== {host} ===\n{nu}")

        if run_katana:
            ka = run_katana_on_target(
                scan_id, host, depth=depth,
                httpx_file=httpx_path if hx.strip() else None,
            )
            if ka.strip():
                katana_all.append(f"=== {host} ===\n{ka}")

    return {
        "wayback": "\n".join(wayback_all),
        "httpx": "\n".join(httpx_all),
        "nuclei": "\n".join(nuclei_all),
        "katana": "\n".join(katana_all),
        "whatweb": "\n".join(whatweb_all),
    }


def run_naabu(scan_id: int, domain: str, ports: str = "") -> str:
    scan_dir = scan_output_dir(scan_id)
    out = scan_dir / f"{domain}_naabu.txt"
    args = ["naabu", "-host", domain]
    if ports:
        args.extend(["-p", ports])
    args.extend(["-o", str(out)])
    run_command(args)
    return read_file(out)


def parse_naabu_ports(naabu_text: str) -> dict[str, set[str]]:
    ports_by_host: dict[str, set[str]] = {}
    for line in naabu_text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        host, port = line.rsplit(":", 1)
        if port.isdigit():
            ports_by_host.setdefault(host, set()).add(port)
    return ports_by_host


def run_nmap_on_naabu(scan_id: int, domain: str, naabu_text: str) -> tuple[str, list[dict]]:
    from .formatters import parse_nmap_exploits

    scan_dir = scan_output_dir(scan_id)
    ports_map = parse_naabu_ports(naabu_text)
    if not ports_map:
        log_activity("Nmap: Naabu açık port bulamadı.", level="warning")
        return "", []

    combined: list[str] = []
    all_findings: list[dict] = []

    for host, ports in ports_map.items():
        port_str = ",".join(sorted(ports, key=int))
        safe = safe_name(host)
        out = scan_dir / f"{safe}_nmap.txt"
        log_activity(f"Nmap: {host} port {port_str}")
        args = [
            "nmap", "-sV", "-p", port_str,
            "--script", "vuln,exploit,banner",
            "-oN", str(out), host,
        ]
        run_command(args)
        text = read_file(out)
        if text.strip():
            combined.append(f"=== {host} ===\n{text}")
            for finding in parse_nmap_exploits(text):
                finding["host"] = host
                all_findings.append(finding)

    return "\n\n".join(combined), all_findings


def run_nuclei_exploit_verification(scan_id: int, domain: str, hosts: list[str]) -> str:
    """Optional nuclei run with exploit tags after user confirmation."""
    scan_dir = scan_output_dir(scan_id)
    targets = scan_dir / f"{domain}_exploit_targets.txt"
    lines = [f"https://{h}" if not h.startswith("http") else h for h in hosts]
    targets.write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = scan_dir / f"{domain}_nuclei_exploit.txt"
    args = ["nuclei", "-l", str(targets), "-tags", "exploit", "-nh", "-nc", "-o", str(out)]
    run_command(args)
    return read_file(out)
