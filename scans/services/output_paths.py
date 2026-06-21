import re
from pathlib import Path

from django.conf import settings


def scan_output_dir(scan_id: int) -> Path:
    path = Path(settings.OUTPUTS_DIR) / f"scan_{scan_id}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_name(value: str) -> str:
    return re.sub(r"[^\w.\-]", "_", value)[:200]


def read_file(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def read_combined(directory: Path, suffix: str) -> str:
    combined = ""
    for file in sorted(directory.iterdir()):
        if file.is_file() and file.name.endswith(suffix):
            combined += read_file(file)
            if not combined.endswith("\n"):
                combined += "\n"
    return combined


def list_subdomains(scan_dir: Path, domain: str) -> list[str]:
    sub_file = scan_dir / f"{domain}_subdomains.txt"
    hosts: list[str] = []
    if sub_file.is_file():
        for line in read_file(sub_file).splitlines():
            host = line.strip()
            if host:
                hosts.append(host)
    if domain not in hosts:
        hosts.insert(0, domain)
    return hosts


def cleanup_scan_outputs(scan_id: int) -> None:
    import shutil

    path = Path(settings.OUTPUTS_DIR) / f"scan_{scan_id}"
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
