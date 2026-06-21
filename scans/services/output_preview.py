from pathlib import Path

from django.conf import settings

from scans.models import ScanModuleResult
from scans.services.output_utils import normalize_tool_output

MAX_DB_OUTPUT_CHARS = 400_000
DEFAULT_PREVIEW_LINES = 2_000


def truncate_for_storage(text: str, max_chars: int = MAX_DB_OUTPUT_CHARS) -> str:
    plain = text or ""
    if len(plain) <= max_chars:
        return plain
    omitted = len(plain) - max_chars
    return (
        f"{plain[:max_chars]}\n\n"
        f"… ({omitted:,} karakter daha — tam çıktı dosyadan indirilebilir)"
    )


def read_file_head(path: Path, max_lines: int = DEFAULT_PREVIEW_LINES) -> str:
    if not path.is_file():
        return ""
    lines: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for _ in range(max_lines):
            line = handle.readline()
            if not line:
                break
            lines.append(line.rstrip("\n"))
        has_more = bool(handle.readline())
    if has_more:
        size = path.stat().st_size
        lines.append("")
        lines.append(f"… (dosya {size:,} bayt — tam liste indirilebilir)")
    return "\n".join(lines)


def result_output_path(result: ScanModuleResult) -> Path | None:
    if not result.output_file:
        return None
    path = Path(settings.OUTPUTS_DIR) / result.output_file
    return path if path.is_file() else None


def load_result_preview(
    result: ScanModuleResult,
    *,
    max_lines: int = DEFAULT_PREVIEW_LINES,
) -> str:
    path = result_output_path(result)
    if path and path.stat().st_size > 500_000:
        return normalize_tool_output(read_file_head(path, max_lines))
    if path and path.stat().st_size > 0:
        return normalize_tool_output(read_file_head(path, max_lines))
    text = result.output or ""
    if not text:
        return ""
    if len(text) > MAX_DB_OUTPUT_CHARS or text.count("\n") > max_lines:
        head = "\n".join(text.splitlines()[:max_lines])
        return normalize_tool_output(
            f"{head}\n\n… (özet gösterim — tam çıktı dosyadan indirilebilir)"
        )
    return normalize_tool_output(text)
