"""
Build the confirmed username/alias contact table.

This wrapper rebuilds the trusted JSON artifact that maps:
- username -> alias
- alias -> username

Why this matters:
- message rows use canonical usernames (`wxid_*`, `@chatroom`, `filehelper`)
- user-facing WeChat IDs are aliases when present
- this artifact gives us the clean bridge between the two namespaces
"""

from __future__ import annotations

from common import run_repo_script


def main() -> int:
    # This script is offline and deterministic. It rebuilds the JSON table from
    # the curated current-contact-table artifact in /docs.
    return run_repo_script("build-weixin-contact-id-table.py")


if __name__ == "__main__":
    raise SystemExit(main())

