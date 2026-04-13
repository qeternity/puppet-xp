"""
Proof-of-concept entrypoint for the detached no-UI send path.

This script is intentionally labeled as a POC because the detached path is
still not reliable enough to claim as a finished capability.

Current best-known detached recipe:
- use a fresh same-session *successful synthetic clone* as the template
- run on the known live send worker thread
- use pair mode 1
- override owner refs to {3,2} when appropriate
- repair the first hidden `ebec0` stage with a same-session inline `filehelper`
  fix JSON

What this wrapper does:
- it exposes the underlying autonomous sender with the exact knobs we ended up
  needing during RE
- it does not hide the complexity, because that complexity is still real

What it does NOT promise:
- successful delivery
- stability
- avoiding late access violations
"""

from __future__ import annotations

import argparse

from common import run_repo_script


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True, help="Live Weixin.exe PID")
    parser.add_argument("--thread-id", type=int, required=True, help="Live send worker thread id")
    parser.add_argument("--template-source", required=True, help="Successful synthetic clone source pointer")
    parser.add_argument("--template-owner", required=True, help="Successful synthetic clone owner pointer")
    parser.add_argument("--conversation-id", required=True, help="Target conversation id")
    parser.add_argument("--body", required=True, help="Detached no-UI target body")
    parser.add_argument("--ebec0-fix-file", required=True, help="Same-session first-stage repair JSON")
    parser.add_argument("--wait-ms", type=int, default=7000)
    parser.add_argument("--pair-mode", type=int, default=1)
    parser.add_argument("--owner-ref-a", type=int, default=3)
    parser.add_argument("--owner-ref-b", type=int, default=2)
    args = parser.parse_args()

    # We intentionally force the currently best-known detached mode:
    # "builder-minimal". That is the path that got closest and produced the
    # strongest detached evidence in the later sessions.
    return run_repo_script(
        "send-weixin-text-autonomous.py",
        "--pid",
        str(args.pid),
        "--thread-id",
        str(args.thread_id),
        "--mode",
        "builder-minimal",
        "--template-source",
        args.template_source,
        "--template-owner",
        args.template_owner,
        "--conversation-id",
        args.conversation_id,
        "--body",
        args.body,
        "--pair-mode",
        str(args.pair_mode),
        "--owner-ref-a",
        str(args.owner_ref_a),
        "--owner-ref-b",
        str(args.owner_ref_b),
        "--ebec0-fix-file",
        args.ebec0_fix_file,
        "--wait-ms",
        str(args.wait_ms),
    )


if __name__ == "__main__":
    raise SystemExit(main())

