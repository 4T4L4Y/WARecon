import subprocess
import threading
from typing import Callable

_lock = threading.Lock()
_active: dict[int, subprocess.Popen] = {}


def register(scan_id: int, proc: subprocess.Popen) -> None:
    with _lock:
        old = _active.get(scan_id)
        if old and old is not proc and old.poll() is None:
            try:
                old.terminate()
            except OSError:
                pass
        _active[scan_id] = proc


def unregister(scan_id: int, proc: subprocess.Popen | None = None) -> None:
    with _lock:
        current = _active.get(scan_id)
        if current is None:
            return
        if proc is None or current is proc:
            _active.pop(scan_id, None)


def kill_all(scan_id: int) -> bool:
    with _lock:
        proc = _active.pop(scan_id, None)
    if not proc or proc.poll() is not None:
        return False
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except OSError:
            pass
    return True


def is_running(scan_id: int) -> bool:
    with _lock:
        proc = _active.get(scan_id)
    return proc is not None and proc.poll() is None
