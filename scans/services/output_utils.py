import re
from pathlib import Path

from .output_paths import read_file

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
URL_LINE_RE = re.compile(r"^(https?://\S+)")
BRACKET_RE = re.compile(r"\[([^\]]+)\]")
STATUS_BRACKET_RE = re.compile(r"^[\d,\s]+$")


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


def parse_httpx_tech_tags(text: str) -> list[str]:
    """HTTPX -td çıktısından teknoloji etiketlerini çıkar (Nuclei -tags için)."""
    tags: set[str] = set()
    for raw in text.splitlines():
        line = strip_ansi(raw).strip()
        if not line or line.startswith("==="):
            continue
        brackets = BRACKET_RE.findall(line)
        if not brackets:
            continue
        remaining = [
            part.strip()
            for part in brackets
            if part.strip() and not STATUS_BRACKET_RE.match(part.strip())
        ]
        if not remaining:
            continue
        tech_part = remaining[-1]
        for piece in tech_part.split(","):
            tag = piece.strip().lower().replace(" ", "-").replace("_", "-")
            if tag and len(tag) < 40:
                tags.add(tag)
    return sorted(tags)[:25]


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
