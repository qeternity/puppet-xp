"""
Monitor the native message iterator for the currently selected conversation.

This is the most direct "working" history-retrieval primitive we have in the
repo today:
- attach to the message iterator
- open a conversation in WeChat
- scroll or switch chats
- watch the decoded message rows come out

Important limitation:
- this is still tied to the UI's currently materialized conversation state
- it is not a polished "dump all local history" extractor
"""

from __future__ import annotations

from common import find_main_wechat_pid, run_repo_script


def main() -> int:
    pid = find_main_wechat_pid()

    # This long-running monitor emits decoded message rows whenever the native
    # iterator is exercised by the UI.
    return run_repo_script("monitor-weixin-message-iterator.py", "--pid", str(pid))


if __name__ == "__main__":
    raise SystemExit(main())

