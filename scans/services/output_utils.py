import re
from pathlib import Path

from .output_paths import read_file

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
URL_LINE_RE = re.compile(r"^(https?://\S+)")


def strip_ansi(text: str) -> str:
    if not text:
        return ""
    return ANSI_RE.sub("", text)


def normalize_tool_output(text: str) -> str:
    return strip_ansi(text or "").strip()


def extract_urls_from_text(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = strip_ansi(raw).strip()
        if not line or line.startswith("==="):
            continue
        match = URL_LINE_RE.match(line)
        if match:
            url = match.group(1).rstrip(".,;")
            if url not in seen:
                seen.add(url)
                urls.append(url)
            continue
        token = line.split()[0]
        if token.startswith("http://") or token.startswith("https://"):
            url = token.rstrip(".,;")
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def write_url_list(path: Path, urls: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
    return path


def prepare_url_input_file(source_file: Path, dest_file: Path) -> Path:
    """HTTPX/Wayback karışık satırlarından Nuclei/Katana için temiz URL listesi üret."""
    urls = extract_urls_from_text(read_file(source_file))
    if urls:
        return write_url_list(dest_file, urls)
    return source_file
