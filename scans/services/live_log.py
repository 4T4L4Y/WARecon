from contextvars import ContextVar

from scans.models import ScanLog, ScanModuleResult

_scan_log_ctx: ContextVar[tuple[int, str] | None] = ContextVar("scan_log_ctx", default=None)


def bind_scan_log(scan_id: int, module: str = ""):
    return _scan_log_ctx.set((scan_id, module))


def reset_scan_log(token) -> None:
    _scan_log_ctx.reset(token)


def log_activity(message: str, *, level: str = "info", module: str | None = None) -> ScanLog | None:
    ctx = _scan_log_ctx.get()
    if not ctx:
        return None
    scan_id, default_module = ctx
    return ScanLog.objects.create(
        scan_id=scan_id,
        level=level,
        message=message[:2000],
        module=module if module is not None else default_module,
    )


def module_status_for_scan(scan) -> list[dict]:
    from scans.services.pipeline import MODULE_LABELS, MODULE_MAP

    done_modules = set(
        ScanModuleResult.objects.filter(scan_id=scan.pk).values_list("module", flat=True)
    )
    items = []

    for choice in scan.modules:
        module_key = MODULE_MAP.get(choice)
        label = MODULE_LABELS.get(choice, choice)
        if module_key in done_modules:
            state = "done"
        elif scan.status == scan.Status.FAILED and choice == scan.current_module:
            state = "failed"
        elif scan.status == scan.Status.RUNNING and choice == scan.current_module:
            state = "running"
        elif scan.status == scan.Status.COMPLETED:
            state = "done" if module_key in done_modules else "skipped"
        else:
            state = "pending"
        items.append({"id": choice, "label": label, "state": state})

    return items
