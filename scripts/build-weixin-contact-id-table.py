#!/usr/bin/env python
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = REPO_ROOT / "docs" / "weixin-4.1.8.29-current-contact-table.json"
OUTPUT_PATH = REPO_ROOT / "docs" / "weixin-4.1.8.29-contact-id-table.json"


def classify_username(username: str) -> str:
    if username.endswith("@chatroom"):
        return "chatroom"
    if username.startswith("wxid_"):
        return "wxid"
    return "builtin"


def build_rows(source_rows: list[dict]) -> list[dict]:
    rows = []
    for row in source_rows:
        username = str(row.get("username") or "")
        rows.append(
            {
                "username": username,
                "username_kind": classify_username(username),
                "name": row.get("name"),
                "alias": row.get("alias"),
                "confidence": row.get("confidence"),
                "sources": row.get("sources", []),
                "notes": row.get("notes", []),
            }
        )
    rows.sort(key=lambda item: ((item["alias"] or "").lower(), item["username"].lower()))
    return rows


def build_bidirectional_maps(rows: list[dict]) -> tuple[dict[str, str], dict[str, str]]:
    alias_to_username: dict[str, str] = {}
    username_to_alias: dict[str, str] = {}
    for row in rows:
        alias = row.get("alias")
        username = row["username"]
        if isinstance(alias, str) and alias:
            alias_to_username[alias] = username
            username_to_alias[username] = alias
    return alias_to_username, username_to_alias


def main() -> int:
    source_rows = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
    rows = build_rows(source_rows)
    alias_to_username, username_to_alias = build_bidirectional_maps(rows)

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(SOURCE_PATH),
        "row_count": len(rows),
        "confirmed_alias_pair_count": len(alias_to_username),
        "rows": rows,
        "alias_to_username": alias_to_username,
        "username_to_alias": username_to_alias,
    }

    OUTPUT_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    sys.stdout.buffer.write((json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
