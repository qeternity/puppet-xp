"""
Capture the current conversation/session list from live WeChat memory.

This wrapper targets the visible Weixin.exe main process and emits the current
conversation table discovered from the live session cache.
"""

from __future__ import annotations

import argparse

from common import find_main_wechat_process, run_repo_script


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        help="Optional JSON output path. If omitted, the script prints to stdout.",
    )
    args = parser.parse_args()

    process = find_main_wechat_process()

    # The underlying enumerator works by process name rather than PID.
    # We pass the explicit visible process name to keep the entrypoint obvious.
    command = [
        "--process",
        str(process["ProcessName"]),
        "--pretty",
    ]
    if args.output:
        command.extend(["--output", args.output])

    return run_repo_script("capture-weixin-conversations.py", *command)


if __name__ == "__main__":
    raise SystemExit(main())

