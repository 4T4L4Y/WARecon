import time
from datetime import datetime, timezone

from django.utils import timezone as dj_tz

from scans.models import Scan

SKIP_AFTER_SECONDS = 120

# UI alt-modül kimlikleri → pipeline adım kimliği (Naabu+Nmap tek adım "1")
SKIP_STEP_ALIASES: dict[str, str] = {
    "8": "1",
}


def skip_step_id(module: str) -> str:
    """Normalize UI/current_module id to pipeline step id for skip matching."""
    if not module:
        return ""
    return SKIP_STEP_ALIASES.get(module, module)


def skip_steps_match(requested: str, step: str) -> bool:
    if not requested or not step:
        return False
    return skip_step_id(requested) == skip_step_id(step)


def is_cancelled(scan_id: int) -> bool:
    return Scan.objects.filter(pk=scan_id, cancel_requested=True).exists()


def clear_cancel(scan: Scan) -> None:
    if scan.cancel_requested:
        scan.cancel_requested = False
        scan.save(update_fields=["cancel_requested"])


def request_cancel(scan: Scan) -> None:
    from scans.services.proc_registry import kill_all

    scan.cancel_requested = True
    scan.status = Scan.Status.CANCELLED
    scan.progress_message = "Tarama iptal edildi."
    scan.completed_at = dj_tz.now()
    scan.save(update_fields=[
        "cancel_requested", "status", "progress_message", "completed_at",
    ])
    kill_all(scan.pk)


def request_skip_module(scan: Scan, module: str) -> None:
    scan.skip_module_requested = skip_step_id(module)
    scan.save(update_fields=["skip_module_requested"])
    from scans.services.proc_registry import kill_all

    kill_all(scan.pk)


def consume_skip(scan: Scan, module: str) -> bool:
    if not skip_steps_match(scan.skip_module_requested, module):
        return False
    scan.skip_module_requested = ""
    scan.save(update_fields=["skip_module_requested"])
    return True


def mark_module_started(scan: Scan, module: str) -> None:
    config = dict(scan.config or {})
    config["module_started_at"] = {
        **(config.get("module_started_at") or {}),
        module: datetime.now(timezone.utc).isoformat(),
    }
    scan.config = config
    scan.save(update_fields=["config"])


def module_elapsed_seconds(scan: Scan, module: str) -> float:
    config = scan.config or {}
    started = (config.get("module_started_at") or {}).get(module)
    if not started:
        return 0.0
    try:
        dt = datetime.fromisoformat(started)
        return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds())
    except (TypeError, ValueError):
        return 0.0


def skip_available(scan: Scan) -> bool:
    if scan.status != Scan.Status.RUNNING or not scan.current_module:
        return False
    step = skip_step_id(scan.current_module)
    return module_elapsed_seconds(scan, step) >= SKIP_AFTER_SECONDS


def check_abort(scan_id: int, module: str = "") -> str | None:
    """Return 'cancel', 'skip', or None."""
    scan = Scan.objects.filter(pk=scan_id).only(
        "cancel_requested", "skip_module_requested", "status",
    ).first()
    if not scan:
        return None
    if scan.cancel_requested:
        return "cancel"
    if module and skip_steps_match(scan.skip_module_requested, module):
        return "skip"
    return None
