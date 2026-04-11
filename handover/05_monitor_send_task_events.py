"""
Monitor the native send-task scheduler.

This is one of the key proof hooks we used during send-path RE. It tells us
that WeChat scheduled a concrete outgoing send task and shows the conversation,
sender, and body that task carries.

It is extremely useful for:
- validating seeded arbitrary sends
- validating resend-path experiments
- checking whether a synthetic send even made it into the task pipeline
"""

from __future__ import annotations

import argparse

from common import find_main_wechat_pid, run_repo_script


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-seconds", type=int, default=1)
    args = parser.parse_args()

    pid = find_main_wechat_pid()

    return run_repo_script(
        "monitor-weixin-send-task-hook.py",
        "--pid",
        str(pid),
        "--baseline-seconds",
        str(args.baseline_seconds),
    )


if __name__ == "__main__":
    raise SystemExit(main())

