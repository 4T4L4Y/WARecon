from pathlib import Path

from django.conf import settings

from .runner import run_command
from .live_log import log_activity


def outputs_dir() -> Path:
    path = Path(settings.OUTPUTS_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_combined(directory: Path, domain: str, suffix: str) -> str:
    combined = ""
    for file in sorted(directory.iterdir()):
        if file.is_file() and file.name.endswith(suffix) and domain in file.name:
            combined += file.read_text(encoding="utf-8", errors="replace")
    return combined


def run_naabu(domain: str, ports: str = "") -> str:
    out = outputs_dir() / f"{domain}_naabu.txt"
    args = ["naabu", "-host", domain]
    if ports:
        args.extend(["-p", ports])
    args.extend(["-o", str(out)])
    run_command(args)
    return read_combined(outputs_dir(), domain, "_naabu.txt")


def run_subfinder(domain: str, params: list[str]) -> str:
    out = outputs_dir() / f"{domain}_subdomains.txt"
    if out.exists():
        out.unlink()
    args = ["subfinder", "-d", domain, "-o", str(out)]
    for param in params:
        if param == "-all":
            args.append("-all")
    run_command(args)
    return read_combined(outputs_dir(), domain, "_subdomains.txt")


def run_wayback(domain: str, known_urls: bool = False, include_subdomains: bool = False) -> str:
    sub_file = outputs_dir() / f"{domain}_subdomains.txt"
    if not sub_file.exists():
        return ""

    suffix_args: list[str] = []
    if known_urls:
        suffix_args.append("--known_urls")
    if include_subdomains:
        suffix_args.append("--subdomains")

    for line in sub_file.read_text(encoding="utf-8", errors="replace").splitlines():
        subdomain = line.strip()
        if not subdomain:
            continue
        out = outputs_dir() / f"{subdomain}_wayback.txt"
        if out.exists():
            continue
        args = ["waybackpy", "-u", subdomain, *suffix_args]
        log_activity(f"Wayback sorgusu: {subdomain}")
        run_command(args, output_file=out)

    return read_combined(outputs_dir(), domain, "_wayback.txt")


def run_httpx(
    domain: str,
    follow_redirects: bool = False,
    show_status: bool = False,
    match_codes: str = "",
) -> str:
    base = ["httpx", "-nc"]
    if follow_redirects:
        base.append("-fr")
    if show_status:
        base.append("-sc")
    if match_codes:
        base.extend(["-mc", match_codes])

    wayback_files = [
        f for f in outputs_dir().iterdir()
        if f.is_file() and f.name.endswith("_wayback.txt") and domain in f.name
    ]

    if wayback_files:
        for wayback_file in wayback_files:
            out = outputs_dir() / wayback_file.name.replace("_wayback.txt", "_httpx.txt")
            run_command([*base, "-l", str(wayback_file), "-o", str(out)])
    else:
        out = outputs_dir() / f"{domain}_httpx.txt"
        run_command([*base, "-target", domain, "-o", str(out)])

    return read_combined(outputs_dir(), domain, "_httpx.txt")


def run_nuclei(domain: str, raw_url: str, templates: str, severities: list[str]) -> str:
    out_txt = outputs_dir() / f"{domain}_nuclei.txt"
    out_json = outputs_dir() / f"{domain}_nuclei.json"
    args = ["nuclei", "-u", raw_url if raw_url.startswith("http") else f"https://{domain}", "-nh", "-nc", "-o", str(out_txt), "-je", str(out_json)]

    if templates:
        for template_id in [t.strip() for t in templates.split(",") if t.strip()]:
            args.extend(["-id", template_id])
    if severities:
        args.extend(["-severity", ",".join(severities)])

    run_command(args)
    return read_combined(outputs_dir(), domain, "_nuclei.txt")


def run_dnsx(domain: str) -> str:
    out = outputs_dir() / f"{domain}_dnsx.txt"
    sub_file = outputs_dir() / f"{domain}_subdomains.txt"
    if sub_file.exists() and sub_file.stat().st_size > 0:
        run_command(["dnsx", "-l", str(sub_file), "-resp", "-o", str(out)])
    else:
        run_command(["dnsx", "-d", domain, "-resp", "-o", str(out)])
    return read_combined(outputs_dir(), domain, "_dnsx.txt")


def run_katana(domain: str, depth: str = "2") -> str:
    out = outputs_dir() / f"{domain}_katana.txt"
    httpx_file = outputs_dir() / f"{domain}_httpx.txt"
    args = ["katana", "-silent", "-depth", depth, "-o", str(out)]
    if httpx_file.exists() and httpx_file.stat().st_size > 0:
        run_command([*args, "-list", str(httpx_file)])
    else:
        run_command([*args, "-u", f"https://{domain}"])
    return read_combined(outputs_dir(), domain, "_katana.txt")
