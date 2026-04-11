"""
Shared helpers for the 4.1.8.29 handover scripts.

These wrappers are intentionally simple:
- locate the live, visible WeChat UI process
- invoke the existing proven repo scripts with the right interpreter
- keep the "handover" entrypoints easy to read and easy to run

The underlying reverse-engineering work still lives in the original scripts
under /scripts. These helpers just make that work easier to consume.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"


def python_exe() -> str:
    """
    Use the known-good Python used throughout this project when present.

    We prefer C:\\Python314\\python.exe because the Frida-based WeChat scripts
    in this repo have been exercised with that interpreter repeatedly.
    """

    preferred = Path(r"C:\Python314\python.exe")
    if preferred.exists():
        return str(preferred)
    return sys.executable


def _run_powershell_json(command: str):
    """
    Execute a PowerShell snippet and parse a JSON payload from stdout.

    This is a pragmatic Windows-only helper. It avoids adding another Python
    dependency just to identify the current WeChat main window process.
    """

    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    text = completed.stdout.strip()
    if not text:
        return None
    return json.loads(text)


def find_main_wechat_process() -> dict:
    """
    Return the live visible WeChat UI process.

    Important detail:
    - there may be multiple Weixin.exe helper processes
    - only the visible one with a non-empty MainWindowTitle is safe to treat as
      the main interactive process
    """

    command = r"""
    $p = Get-Process Weixin -ErrorAction SilentlyContinue |
      Where-Object { $_.MainWindowTitle -and $_.MainWindowTitle.Trim().Length -gt 0 } |
      Select-Object -First 1 Id, MainWindowTitle, ProcessName
    if ($null -eq $p) {
      return
    }
    $p | ConvertTo-Json -Compress
    """
    result = _run_powershell_json(command)
    if not result:
        raise SystemExit("No visible WeChat UI process found. Open WeChat first.")
    return result


def find_main_wechat_pid() -> int:
    """Convenience wrapper returning only the PID."""

    process = find_main_wechat_process()
    return int(process["Id"])


def run_repo_script(script_name: str, *args: str) -> int:
    """
    Run one of the existing repo scripts and stream its output directly.

    These handover wrappers are meant to behave like normal tools, so we use
    foreground execution with inherited stdout/stderr rather than hiding output.
    """

    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        raise SystemExit(f"Missing repo script: {script_path}")

    command = [python_exe(), str(script_path), *args]
    completed = subprocess.run(command)
    return int(completed.returncode)

