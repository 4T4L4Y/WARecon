import logging
import subprocess
import time
from pathlib import Path

from scans.services.live_log import _scan_log_ctx, log_activity
from scans.services.proc_registry import register, unregister
from scans.services.scan_control import check_abort
from .tool_paths import resolve_executable

logger = logging.getLogger(__name__)


def _scan_context() -> tuple[int | None, str]:
    ctx = _scan_log_ctx.get()
    if not ctx:
        return None, ""
    return ctx


def _handle_abort(scan_id: int, module: str, proc: subprocess.Popen) -> int | None:
    abort = check_abort(scan_id, module)
    if abort == "cancel":
        log_activity("Tarama iptal edildi — süreç durduruluyor.", level="warning")
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        return 130
    if abort == "skip":
        log_activity("Modül atlandı — o ana kadarki çıktı kullanılacak.", level="warning")
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        return 0
    return None


def run_command(args: list[str], *, output_file: Path | None = None) -> int:
    """Run a CLI tool; honour cancel/skip signals for the active scan."""
    if not args:
        return 1

    tool = args[0]
    resolved = resolve_executable(tool)
    if not resolved:
        logger.warning("Tool not found: %s", tool)
        log_activity(
            f"Araç bulunamadı: {tool} (PATH veya .venv/bin kontrol edin)",
            level="error",
        )
        return 127

    scan_id, module = _scan_context()
    run_args = [resolved, *args[1:]]
    cmd_line = " ".join(run_args)
    logger.info("Running: %s", cmd_line)
    log_activity(f"$ {cmd_line}", level="cmd")

    file_handle = None
    proc = None
    try:
        if output_file is not None:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            file_handle = open(output_file, "w", encoding="utf-8")
            proc = subprocess.Popen(
                run_args,
                stdin=subprocess.DEVNULL,
                stdout=file_handle,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        else:
            proc = subprocess.Popen(
                run_args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

        if scan_id:
            register(scan_id, proc)

        stream = proc.stderr if output_file is not None else proc.stdout
        if stream:
            while True:
                if scan_id:
                    code = _handle_abort(scan_id, module, proc)
                    if code is not None:
                        return code
                line = stream.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.2)
                    continue
                line = line.rstrip()
                if line:
                    log_activity(line)
        else:
            while proc.poll() is None:
                if scan_id:
                    code = _handle_abort(scan_id, module, proc)
                    if code is not None:
                        return code
                time.sleep(0.3)

        code = proc.wait()
        if code == 0:
            log_activity("Komut tamamlandı.", level="success")
        else:
            log_activity(f"Komut çıkış kodu: {code}", level="warning")
        return code
    finally:
        if scan_id and proc is not None:
            unregister(scan_id, proc)
        if file_handle is not None:
            file_handle.close()
