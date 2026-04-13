"""
Monitor the manager-dispatch message hook.

This is the best working new-message-style event hook we currently have on
4.1.8.29. It is better than the replay-heavy iterator hooks for "message event"
use cases, but it still needs dedupe internally.

What it emits:
- conversation id
- title
- sender username
- direction
- content
- extra raw fields useful for RE and debugging
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
        "monitor-weixin-manager-message-hook.py",
        "--pid",
        str(pid),
        "--baseline-seconds",
        str(args.baseline_seconds),
    )


if __name__ == "__main__":
    raise SystemExit(main())

