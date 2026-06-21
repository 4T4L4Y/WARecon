import os
import shutil
import sys
from pathlib import Path

from django.conf import settings


def tool_search_dirs() -> list[Path]:
    dirs: list[Path] = []
    venv_bin = Path(sys.prefix) / "bin"
    if venv_bin.is_dir():
        dirs.append(venv_bin)
    go_bin = Path.home() / "go" / "bin"
    if go_bin.is_dir():
        dirs.append(go_bin)
    for extra in getattr(settings, "TOOL_PATH_EXTRA", []):
        dirs.append(Path(extra))
    for part in os.environ.get("PATH", "").split(os.pathsep):
        if part:
            dirs.append(Path(part))
    return dirs


def resolve_executable(name: str) -> str | None:
    for directory in tool_search_dirs():
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


def tool_available(name: str) -> bool:
    return resolve_executable(name) is not None
