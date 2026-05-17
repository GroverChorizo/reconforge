"""
Job-free subprocess runner. Decoupled from ``main.Job`` so agents can
spawn tools without dragging the legacy pipeline state machine along.

Returns are explicit:
    rc = -1 → binary missing
    rc = -2 → cancelled via cancel_event
    rc = 124 → timed out (matches GNU timeout convention)
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple


def run_proc(
    cmd: List[str],
    *,
    timeout: int = 3600,
    cancel_event: Optional[threading.Event] = None,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str]:
    """Run ``cmd`` as a subprocess. Returns ``(returncode, stdout, stderr)``."""
    if not cmd:
        return -1, "", "empty command"
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env=env,
        )
    except FileNotFoundError:
        return -1, "", f"{cmd[0]}: command not found"
    except OSError as e:
        return -1, "", str(e)

    out_buf: List[str] = []
    err_buf: List[str] = []

    def _read(stream, buf):
        try:
            for line in stream:
                buf.append(line)
        except Exception:
            pass

    t_o = threading.Thread(target=_read, args=(proc.stdout, out_buf), daemon=True)
    t_e = threading.Thread(target=_read, args=(proc.stderr, err_buf), daemon=True)
    t_o.start()
    t_e.start()

    deadline = time.time() + max(1, timeout)
    while proc.poll() is None:
        if cancel_event is not None and cancel_event.is_set():
            proc.kill()
            t_o.join(timeout=2)
            t_e.join(timeout=2)
            return -2, "".join(out_buf), "".join(err_buf)
        if time.time() > deadline:
            proc.kill()
            t_o.join(timeout=2)
            t_e.join(timeout=2)
            return 124, "".join(out_buf), "".join(err_buf)
        time.sleep(0.2)

    t_o.join(timeout=2)
    t_e.join(timeout=2)
    return (proc.returncode or 0), "".join(out_buf), "".join(err_buf)


def build_cmd(template: str, vars_: Dict[str, str]) -> List[str]:
    """Substitute ``$VAR$`` placeholders, then shell-split.

    ``shlex.split`` keeps quoted segments together (e.g. nuclei flag values
    containing spaces). Matches the behavior of ``main.build_cmd`` for the
    placeholders we use but is safer for path-like values.
    """
    s = template
    for k, v in vars_.items():
        s = s.replace(k, str(v))
    return shlex.split(s)


def which(binary: str) -> Optional[str]:
    """Thin wrapper so callers don't import shutil directly."""
    return shutil.which(binary)
