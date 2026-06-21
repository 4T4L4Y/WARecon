import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(args: list[str], *, output_file: Path | None = None) -> int:
    """Run a CLI tool safely with stdin closed (avoids httpx/naabu hang)."""
    if not args:
        return 1
    if not tool_available(args[0]):
        logger.warning("Tool not found on PATH: %s", args[0])
        return 127

    logger.info("Running: %s", " ".join(args))
    stdout = None
    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        stdout = open(output_file, "w")

    try:
        result = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0 and result.stderr:
            logger.warning("stderr: %s", result.stderr[:500])
        return result.returncode
    finally:
        if stdout is not None:
            stdout.close()
