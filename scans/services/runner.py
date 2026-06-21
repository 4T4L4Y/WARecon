import logging
import subprocess
from pathlib import Path

from .live_log import log_activity
from .tool_paths import resolve_executable, tool_available

logger = logging.getLogger(__name__)


def run_command(args: list[str], *, output_file: Path | None = None) -> int:
    """Run a CLI tool safely; stream stderr/stdout lines to the live activity log."""
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

    run_args = [resolved, *args[1:]]
    cmd_line = " ".join(run_args)
    logger.info("Running: %s", cmd_line)
    log_activity(f"$ {cmd_line}", level="cmd")

    file_handle = None
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
            if proc.stderr:
                for line in proc.stderr:
                    line = line.rstrip()
                    if line:
                        log_activity(line)
            code = proc.wait()
        else:
            proc = subprocess.Popen(
                run_args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            if proc.stdout:
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        log_activity(line)
            code = proc.wait()

        if code == 0:
            log_activity("Komut tamamlandı.", level="success")
        else:
            log_activity(f"Komut çıkış kodu: {code}", level="warning")
        return code
    finally:
        if file_handle is not None:
            file_handle.close()
