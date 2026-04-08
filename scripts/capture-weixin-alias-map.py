#!/usr/bin/env python
import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import frida


SCRIPT = r"""
function toHex(buf) {
  const bytes = new Uint8Array(buf)
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i].toString(16)
    out += (b.length === 1 ? '0' : '') + b
  }
  return out
}

function rangeContains(range, addr) {
  const base = ptr(range.base)
  const end = base.add(range.size)
  return addr.compare(base) >= 0 && addr.compare(end) < 0
}

rpc.exports = {
  scan(pattern, before, after, maxhits) {
    const ranges = Process.enumerateRanges('rw-')
      .filter(r => !r.file && r.size >= 0x1000 && r.size <= 0x4000000)
    const results = []
    for (const range of ranges) {
      const matches = Memory.scanSync(ptr(range.base), range.size, pattern)
      for (const match of matches) {
        const addr = ptr(match.address)
        const start = addr.sub(before)
        const end = addr.add(after)
        if (!rangeContains(range, start) || !rangeContains(range, end.sub(1))) {
          continue
        }
        try {
          const bytes = start.readByteArray(before + after)
          results.push({
            address: addr.toString(),
            start: start.toString(),
            protection: range.protection,
            size: range.size,
            hex: toHex(bytes),
          })
        } catch (e) {}
        if (results.length >= maxhits) {
          return results
        }
      }
    }
    return results
  }
}
"""


WXID_RE = re.compile(rb'(?<![0-9A-Za-z_])(?P<id>wxid_[0-9a-z]{6,})(?![0-9A-Za-z_])')
TOKEN_RE = re.compile(rb'(?<![0-9A-Za-z_@.-])(?P<token>[A-Za-z][A-Za-z0-9_-]{4,31})(?![0-9A-Za-z_@.-])')

GENERIC_TOKENS = {
    'username', 'encryptusername', 'encrypt_username', 'nickname', 'nick_name',
    'remark', 'verifyflag', 'verify_flag', 'delflag', 'delete_flag', 'labelidlist',
    'labellist', 'domainlist', 'chatroomtype', 'chatroomnotify', 'description',
    'extbuf', 'extrabuf', 'headimgmd5', 'smallheadimgurl', 'bigheadimgurl',
    'headusername', 'headusername', 'msgsource', 'session', 'contact', 'contacts',
    'service', 'notifications', 'filehelper', 'weixin', 'sender', 'receiver',
    'message', 'messages', 'account', 'account_username', 'mmkv', 'userinfo',
    'localtype', 'local_type', 'alias', 'rowid', 'accepttype', 'brandlist',
    'brandflag', 'extinfo', 'brandinfo', 'brandiconurl', 'belong', 'contactheadimgurl',
    'username2id', 'name2id', 'encrypt_name2id', 'chatroom_member',
}


def ascii_hex(text: str) -> str:
    return ' '.join(f'{b:02x}' for b in text.encode('ascii'))


def load_contacts(path: Path) -> list[dict]:
    rows = json.loads(path.read_text(encoding='utf-8'))
    return [row for row in rows if isinstance(row, dict) and str(row.get('username', '')).startswith('wxid_')]


def known_name_keys(rows: list[dict]) -> set[str]:
    names: set[str] = set()
    for row in rows:
        for value in (row.get('name'), row.get('alias')):
            if isinstance(value, str) and value:
                names.add(value.lower())
        for value in row.get('native_labels', []) or []:
            if isinstance(value, str) and value:
                names.add(value.lower())
    return names


def find_main_weixin_pid() -> int:
    cmd = (
        "Get-Process Weixin -ErrorAction SilentlyContinue | "
        "Where-Object { $_.MainWindowTitle } | "
        "Select-Object -First 1 -ExpandProperty Id"
    )
    result = subprocess.run(
        ['powershell', '-NoProfile', '-Command', cmd],
        capture_output=True,
        text=True,
        check=False,
    )
    text = result.stdout.strip()
    if text.isdigit():
        return int(text)

    device = frida.get_local_device()
    matches = [p.pid for p in device.enumerate_processes() if p.name.lower() == 'weixin.exe']
    if not matches:
        raise SystemExit('Unable to find Weixin.exe')
    return min(matches)


def run_scan(script, pattern: str, before: int, after: int, max_hits: int) -> list[dict]:
    return script.exports_sync.scan(pattern, before, after, max_hits)


def decode_hex_snippet(hit: dict) -> bytes:
    return bytes.fromhex(hit['hex'])


def score_candidate(token: str, match_start: int, id_start: int, id_end: int, names: set[str]) -> int:
    lowered = token.lower()
    if lowered in GENERIC_TOKENS:
        return -1
    if lowered.startswith('wxid_'):
        return -1
    if lowered in names:
        return -1
    if token.startswith('wxid_'):
        return -1
    if len(token) < 5 or len(token) > 24:
        return -1
    if token.isupper():
        return -1
    if '.' in token or '/' in token or '\\' in token:
        return -1

    distance = min(abs(match_start - id_start), abs(match_start - id_end))
    if distance > 0x140:
        return -1

    score = 320 - distance
    if any(ch.isdigit() for ch in token):
        score += 45
    if token.islower():
        score += 30
    if token[0].islower():
        score += 20
    if '_' in token or '-' in token:
        score += 10
    return score


def extract_alias_candidates(blob: bytes, target_id: str, names: set[str]) -> list[dict]:
    target = target_id.encode('ascii')
    out: list[dict] = []
    for match in WXID_RE.finditer(blob):
        if match.group('id') != target:
            continue
        id_start = match.start()
        id_end = match.end()
        seen: set[str] = set()
        for token_match in TOKEN_RE.finditer(blob):
            token = token_match.group('token').decode('ascii', errors='ignore')
            if token in seen:
                continue
            seen.add(token)
            score = score_candidate(token, token_match.start(), id_start, id_end, names)
            if score < 0:
                continue
            out.append({
                'token': token,
                'score': score,
                'distance': min(abs(token_match.start() - id_start), abs(token_match.start() - id_end)),
            })
    return out


def build_alias_map(script, contact_rows: list[dict], names: set[str]) -> list[dict]:
    token_to_ids: dict[str, set[str]] = defaultdict(set)
    per_id_scores: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    per_id_hits: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for row in contact_rows:
        username = str(row.get('username') or '')
        hits = run_scan(script, ascii_hex(username), 0x120, 0x280, 40)
        for hit in hits:
            blob = decode_hex_snippet(hit)
            candidates = extract_alias_candidates(blob, username, names)
            for candidate in candidates:
                token = candidate['token']
                token_to_ids[token].add(username)
                per_id_scores[username][token] += candidate['score']
                per_id_hits[username][token] += 1

    results = []
    for row in contact_rows:
        username = str(row.get('username') or '')
        best_token = None
        best_score = -1
        details = []
        for token, score in per_id_scores[username].items():
            adjusted = score - max(0, len(token_to_ids[token]) - 1) * 120
            if per_id_hits[username][token] > 1:
                adjusted += per_id_hits[username][token] * 25
            details.append({
                'token': token,
                'score': adjusted,
                'raw_score': score,
                'hit_count': per_id_hits[username][token],
                'shared_with': sorted(token_to_ids[token]),
            })
            if adjusted > best_score:
                best_score = adjusted
                best_token = token

        details.sort(key=lambda item: (-item['score'], item['token']))
        item = {
            'username': username,
            'name': row.get('name'),
            'best_alias': best_token,
            'confidence_score': best_score,
            'candidates': details[:8],
        }
        expected_alias = row.get('alias')
        if isinstance(expected_alias, str):
            item['expected_alias'] = expected_alias
        results.append(item)

    return results


def filter_final_pairs(rows: list[dict]) -> list[dict]:
    pairs = []
    for row in rows:
        alias = row.get('best_alias')
        score = row.get('confidence_score', -1)
        if not alias or score < 180:
            continue
        pairs.append({
            'username': row['username'],
            'alias': alias,
            'name': row.get('name'),
            'confidence_score': score,
            'expected_alias': row.get('expected_alias'),
        })
    return pairs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int)
    parser.add_argument('--contacts', type=Path, default=Path('docs/weixin-4.1.8.29-current-contact-table.json'))
    parser.add_argument('--output', type=Path, default=Path('docs/weixin-4.1.8.29-live-alias-map.json'))
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    contacts_path = args.contacts if args.contacts.is_absolute() else repo_root / args.contacts
    output_path = args.output if args.output.is_absolute() else repo_root / args.output

    contact_rows = load_contacts(contacts_path)
    names = known_name_keys(contact_rows)

    pid = args.pid or find_main_weixin_pid()
    device = frida.get_local_device()
    session = device.attach(pid)
    try:
        script = session.create_script(SCRIPT)
        script.load()

        alias_rows = build_alias_map(script, contact_rows, names)
        final_pairs = filter_final_pairs(alias_rows)
        final_pairs.sort(key=lambda item: item['username'])

        payload = {
            'generated_at': subprocess.run(
                ['powershell', '-NoProfile', '-Command', 'Get-Date -Format o'],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip(),
            'pid': pid,
            'source_contacts': str(contacts_path),
            'pair_count': len(final_pairs),
            'pairs': final_pairs,
            'rows': alias_rows,
        }
        text = json.dumps(payload, indent=2, ensure_ascii=False) + '\n'
        output_path.write_text(text, encoding='utf-8')
        sys.stdout.buffer.write(text.encode('utf-8', errors='replace'))
    finally:
        session.detach()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
