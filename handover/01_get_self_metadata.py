"""
Print the current logged-in WeChat self/account metadata.

This is a thin, documented wrapper around the proven native self-account probe
for WeChat 4.1.8.29.

What it gives us:
- self username (wxid_* form)
- nickname
- account-like / alias-like fields surfaced by the native snapshot
- extra snapshot context that was useful during RE
"""

from __future__ import annotations

from common import find_main_wechat_pid, run_repo_script


def main() -> int:
    pid = find_main_wechat_pid()

    # The underlying script attaches to the live Weixin.exe UI process and
    # queries the native self/account snapshot functions we already validated.
    return run_repo_script("probe-weixin-self-account.py", "--pid", str(pid))


if __name__ == "__main__":
    raise SystemExit(main())

