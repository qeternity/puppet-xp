"""
Perform a working seeded arbitrary send.

This is the stable arbitrary-send primitive we actually trust today.

How it works:
1. Attach to the live WeChat process.
2. Wait for the user (or operator) to send a specific *seed* body in any chat.
3. Hijack the lower native send path in-flight.
4. Rewrite the real send to a different target conversation and different body.

Why this counts as "working":
- this path has been validated repeatedly
- it is the most reliable arbitrary-send mechanism currently in the repo

Important limitation:
- this is NOT a fully detached no-UI send
- it still requires a seed send to enter the live lower-send path
"""

from __future__ import annotations

import argparse

from common import find_main_wechat_pid, run_repo_script


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trigger-body", required=True, help="Seed body to watch for")
    parser.add_argument("--conversation-id", required=True, help="Target conversation id")
    parser.add_argument("--body", required=True, help="Final body to send")
    parser.add_argument("--baseline-seconds", type=int, default=1)
    parser.add_argument(
        "--builder-only",
        action="store_true",
        help=(
            "Use the lower builder-only path. This was the stable mode for the "
            "working arbitrary-send primitive."
        ),
    )
    args = parser.parse_args()

    pid = find_main_wechat_pid()

    command = [
        "--pid",
        str(pid),
        "--trigger-body",
        args.trigger_body,
        "--conversation-id",
        args.conversation_id,
        "--body",
        args.body,
        "--baseline-seconds",
        str(args.baseline_seconds),
    ]
    if args.builder_only:
        command.append("--builder-only")

    return run_repo_script("hijack-weixin-lower-send.py", *command)


if __name__ == "__main__":
    raise SystemExit(main())

