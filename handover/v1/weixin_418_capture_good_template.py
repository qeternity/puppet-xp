from __future__ import annotations

import argparse
import json
import time

import frida

from weixin_418_detached_send import SCRIPT_SOURCE, resolve_weixin_dll_host_pid


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture a live-good Weixin send template without attempting detached replay."
    )
    parser.add_argument("--pid", type=int, help="Target Weixin PID. Defaults to live Weixin.dll host.")
    parser.add_argument("--conversation-id", required=True, help="Conversation id to capture from.")
    parser.add_argument("--timeout-ms", type=int, default=30000, help="How long to wait for capture.")
    parser.add_argument(
        "--post-capture-linger-ms",
        type=int,
        default=3000,
        help="How long to keep the session alive after capture to collect finalize-stage logs.",
    )
    args = parser.parse_args()

    pid = args.pid or resolve_weixin_dll_host_pid()
    device = frida.get_local_device()
    session = device.attach(pid)
    script = session.create_script(SCRIPT_SOURCE)

    def on_message(message, data):
        if message["type"] == "send":
            print(json.dumps(message["payload"], ensure_ascii=True), flush=True)
        else:
            print(json.dumps(message, ensure_ascii=True), flush=True)

    script.on("message", on_message)
    script.load()

    try:
        script.exports_sync.armcapture(args.conversation_id)
        deadline = time.time() + (args.timeout_ms / 1000.0)
        while time.time() < deadline:
            capture_state = script.exports_sync.getcapturestate()
            if capture_state and capture_state.get("status") == "captured":
                if args.post_capture_linger_ms > 0:
                    time.sleep(args.post_capture_linger_ms / 1000.0)
                print(json.dumps({"ok": True, "capture_state": capture_state}, ensure_ascii=True), flush=True)
                return 0
            time.sleep(0.05)

        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "timed out waiting for live-good template capture",
                    "capture_state": script.exports_sync.getcapturestate(),
                },
                ensure_ascii=True,
            ),
            flush=True,
        )
        return 1
    finally:
        session.detach()


if __name__ == "__main__":
    raise SystemExit(main())
