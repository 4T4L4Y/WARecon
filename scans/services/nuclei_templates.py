import json
import subprocess
import time
from functools import lru_cache
from pathlib import Path

from django.conf import settings
from django.core.cache import cache

from scans.services.tool_paths import resolve_executable

CACHE_KEY = "nuclei_template_list"
CACHE_TTL = 3600


def _templates_cache_path() -> Path:
    return Path(settings.BASE_DIR) / "outputs" / ".nuclei_templates_cache.json"


def fetch_nuclei_templates(force: bool = False) -> list[dict]:
    cached = cache.get(CACHE_KEY)
    if cached and not force:
        return cached

    path = _templates_cache_path()
    if path.is_file() and not force:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                cache.set(CACHE_KEY, data, CACHE_TTL)
                return data
        except (json.JSONDecodeError, OSError):
            pass

    nuclei = resolve_executable("nuclei")
    if not nuclei:
        return []

    try:
        proc = subprocess.run(
            [nuclei, "-tl", "-silent"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    except (subprocess.TimeoutExpired, OSError):
        return []

    templates = []
    for line in lines:
        tid = line.split("/")[-1] if "/" in line else line
        templates.append({
            "id": tid,
            "path": line,
            "name": tid.replace("-", " ").title(),
        })

    templates.sort(key=lambda x: x["id"])
    cache.set(CACHE_KEY, templates, CACHE_TTL)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(templates), encoding="utf-8")
    return templates


def search_nuclei_templates(query: str = "", limit: int = 200) -> list[dict]:
    items = fetch_nuclei_templates()
    q = query.strip().lower()
    if not q:
        return items[:limit]
    filtered = [
        t for t in items
        if q in t["id"].lower() or q in t.get("path", "").lower()
    ]
    return filtered[:limit]
