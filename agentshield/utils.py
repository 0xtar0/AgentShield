from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


def default_command_runner(command: list[str], timeout: int = 8) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return 124, stdout, stderr or "command timed out"


def mode_octal(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))


def is_group_or_world_readable(path: Path) -> bool:
    mode = stat.S_IMODE(path.stat().st_mode)
    return bool(mode & (stat.S_IRGRP | stat.S_IROTH))


def is_group_or_world_writable(path: Path) -> bool:
    mode = stat.S_IMODE(path.stat().st_mode)
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def safe_read_text(path: Path, max_bytes: int | None = None) -> str:
    with path.open("rb") as handle:
        if max_bytes is None:
            data = handle.read()
        else:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            data = handle.read(max_bytes)
    return data.decode("utf-8", errors="replace")

