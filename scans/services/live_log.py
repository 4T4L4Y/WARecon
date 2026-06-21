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
    from scans.services.pipeline import MODULE_LABELS, MODULE_MAP, WEB_MODULE_IDS

    done_modules = set(
        ScanModuleResult.objects.filter(scan_id=scan.pk).values_list("module", flat=True)
    )
    items = []

    def _state_for(choice: str, module_key: str | None) -> str:
        if module_key and module_key in done_modules:
            return "done"
        if scan.status == scan.Status.FAILED and choice == scan.current_module:
            return "failed"
        if scan.status == scan.Status.AWAITING_SUBDOMAIN_SELECTION:
            if choice == "2" or (module_key and module_key in done_modules):
                return "done"
            if choice in WEB_MODULE_IDS:
                return "pending"
            return "pending"
        if scan.status == scan.Status.AWAITING_PORT_SELECTION:
            if module_key == ScanModuleResult.Module.NAABU:
                return "done"
            if choice in ("1", "8") or module_key == ScanModuleResult.Module.NMAP:
                return "pending"
            return "pending"
        if scan.status == scan.Status.RUNNING and (
            choice == scan.current_module
            or (scan.current_module == "web" and choice in WEB_MODULE_IDS)
            or (scan.current_module in WEB_MODULE_IDS and choice == scan.current_module)
            or (scan.current_module == "8" and choice == "1")
        ):
            return "running"
        if scan.status == scan.Status.COMPLETED:
            return "done" if module_key and module_key in done_modules else "skipped"
        return "pending"

    for choice in scan.modules:
        module_key = MODULE_MAP.get(choice)
        label = MODULE_LABELS.get(choice, choice)
        items.append({
            "id": choice,
            "label": label,
            "state": _state_for(choice, module_key),
        })

    if "1" in scan.modules:
        nmap_done = ScanModuleResult.Module.NMAP in done_modules
        nmap_state = "done" if nmap_done else _state_for("8", ScanModuleResult.Module.NMAP)
        if scan.status == scan.Status.RUNNING and scan.current_module == "8":
            nmap_state = "running"
        items.append({
            "id": "8",
            "label": MODULE_LABELS.get("8", "Nmap"),
            "state": nmap_state,
        })

    return items
