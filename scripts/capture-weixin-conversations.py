#!/usr/bin/env python
import argparse
import json
import re
import sys
from collections import Counter
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


CHATROOM_RE = re.compile(rb'(?<!\d)(?P<id>\d{11,}@chatroom)(?![0-9a-z_@])')
DIRECT_RE = re.compile(rb'(?<![0-9a-z_])(?P<id>wxid_[0-9a-z]{6,})(?![0-9a-z_])')
SESSION_ITEM_RE = re.compile('session_item_([^\x00]{1,80})')


def ascii_hex(text: str) -> str:
    return ' '.join(f'{b:02x}' for b in text.encode('ascii'))


def utf16le_hex(text: str) -> str:
    return ' '.join(f'{b:02x}' for b in text.encode('utf-16le'))


def strip_controls(text: str) -> str:
    return ''.join(ch if ch == '\n' or ch == '\r' or ch == '\t' or ord(ch) >= 32 else ' ' for ch in text)


def repair_mojibake(text: str) -> str:
    if not text:
        return text
    suspicious = ('ã', 'é', 'æ', 'å', 'ä', 'ç', 'è', 'â')
    if not any(ch in text for ch in suspicious):
        return text
    for encoding in ('latin-1', 'cp1252'):
        try:
            repaired = text.encode(encoding).decode('utf-8')
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        return repaired
    return text


def normalize_title_key(text: str) -> str:
    return re.sub(r'[^0-9a-z\u4e00-\u9fff]+', '', text.lower())


def looks_like_title(text: str) -> bool:
    if not text:
        return False
    if len(text) > 80:
        return False
    lowered = text.lower()
    if any(token in lowered for token in ('wxid_', '@chatroom', 'http', 'mmhead', 'stranger', 'weixin.qq.com')):
        return False
    visible = [ch for ch in text if not ch.isspace()]
    if not visible:
        return False
    allowed = sum(
        ch.isalnum()
        or ch in " -_.,'&():/+"
        or '\u4e00' <= ch <= '\u9fff'
        or ch in ('、',)
        for ch in visible
    )
    if allowed / len(visible) < 0.8:
        return False
    return any(ch.isalpha() or '\u4e00' <= ch <= '\u9fff' for ch in text)


def collapse_tripled_title(text: str) -> str | None:
    candidate = text.strip(" \t\r\n\x00-_")
    if not looks_like_title(candidate):
        return None

    limit = min(len(candidate), 80)
    for end in range(2, limit + 1):
        prefix = candidate[:end].strip(" \t\r\n\x00-_")
        if not looks_like_title(prefix):
            continue
        key = normalize_title_key(prefix)
        if len(key) < 3:
            continue
        remainder = normalize_title_key(candidate[end:])
        if remainder.startswith(key):
            return prefix
    return candidate


def parse_title_from_blob(blob: bytes) -> str | None:
    end = blob.find(b'https://')
    if end >= 0:
        blob = blob[:end]
    if b'@stranger' in blob:
        blob = blob.split(b'@stranger', 1)[1]

    blob = blob.lstrip(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f')
    text = repair_mojibake(strip_controls(blob.decode('utf-8', errors='ignore')).strip())
    if not text:
        return None
    return collapse_tripled_title(text)


def slice_record_payload(blob: bytes, limit: int = 640) -> bytes:
    segment = blob[:limit]
    cut_points: list[int] = []
    next_chatroom = CHATROOM_RE.search(segment, 1)
    if next_chatroom:
        cut_points.append(next_chatroom.start())
    next_direct = DIRECT_RE.search(segment, 1)
    if next_direct:
        cut_points.append(next_direct.start())
    next_url = segment.find(b'https://')
    if next_url > 0:
        cut_points.append(next_url)
    if cut_points:
        segment = segment[:min(cut_points)]
    return segment


def add_source(item: dict, source: str) -> None:
    if source not in item['sources']:
        item['sources'].append(source)


def add_title_candidate(item: dict, title: str) -> None:
    candidates = item.setdefault('_title_candidates', [])
    if title and title not in candidates:
        candidates.append(title)


def title_key_set(values: list[str]) -> set[str]:
    return {normalize_title_key(repair_mojibake(value)) for value in values if value}


def is_valid_conversation_title(title: str | None, allowed_keys: set[str]) -> bool:
    if not title:
        return False
    if not looks_like_title(title):
        return False
    return normalize_title_key(repair_mojibake(title)) in allowed_keys


def find_process(device: frida.core.Device, name: str) -> int:
    matches = [p for p in device.enumerate_processes() if p.name.lower() == name.lower()]
    if not matches:
        raise SystemExit(f'Process not found: {name}')
    matches.sort(key=lambda p: p.pid)
    return matches[0].pid


def run_scan(script, pattern: str, before: int, after: int, max_hits: int) -> list[dict]:
    return script.exports_sync.scan(pattern, before, after, max_hits)


def decode_hex_snippet(hit: dict) -> bytes:
    return bytes.fromhex(hit['hex'])


def extract_chatroom_conversations(hits: list[dict]) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for hit in hits:
        blob = decode_hex_snippet(hit)
        for match in CHATROOM_RE.finditer(blob):
            conv_id = match.group('id').decode('ascii', errors='ignore')
            title = parse_title_from_blob(slice_record_payload(blob[match.end():]))
            item = results.setdefault(conv_id, {
                'conversation_id': conv_id,
                'title': None,
                'type': 'chatroom',
                'confidence': 'medium',
                'sources': [],
                '_title_candidates': [],
            })
            add_source(item, 'packed session record')
            if title:
                add_title_candidate(item, title)
                if not item['title']:
                    item['title'] = title
                    item['confidence'] = 'high'
    return results


def extract_direct_records(hits: list[dict]) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for hit in hits:
        blob = decode_hex_snippet(hit)
        for match in DIRECT_RE.finditer(blob):
            conv_id = match.group('id').decode('ascii', errors='ignore')
            title = parse_title_from_blob(slice_record_payload(blob[match.end():]))
            if not title:
                continue
            item = results.setdefault(conv_id, {
                'conversation_id': conv_id,
                'title': title,
                'type': 'direct',
                'confidence': 'medium',
                'sources': [],
                '_title_candidates': [],
            })
            add_source(item, 'packed direct record')
            add_title_candidate(item, title)
            if title and item['title'] != title:
                item['title'] = title
    return results


def extract_session_titles(hits: list[dict]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for hit in hits:
        blob = decode_hex_snippet(hit)
        text = blob.decode('utf-16le', errors='ignore')
        for match in SESSION_ITEM_RE.finditer(text):
            label = repair_mojibake(match.group(1).strip())
            if label and label not in seen:
                seen.add(label)
                labels.append(label)
    return labels


def load_contact_fallbacks(repo_root: Path) -> dict[str, dict]:
    path = repo_root / 'docs' / 'weixin-4.1.8.29-current-contact-table.json'
    if not path.exists():
        return {}
    rows = json.loads(path.read_text(encoding='utf-8'))
    return {repair_mojibake(row['name']): row for row in rows}


def load_conversation_fallbacks(repo_root: Path) -> dict[str, dict]:
    path = repo_root / 'docs' / 'weixin-4.1.8.29-current-conversation-table.json'
    if not path.exists():
        return {}
    rows = json.loads(path.read_text(encoding='utf-8'))
    results: dict[str, dict] = {}
    for row in rows:
        title = repair_mojibake(row.get('title'))
        if not title:
            continue
        results[row['conversation_id']] = {
            'conversation_id': row['conversation_id'],
            'title': title,
            'type': row.get('type'),
            'confidence': row.get('confidence'),
        }
    return results


def apply_session_title_fallbacks(
    conversations: dict[str, dict],
    session_titles: list[str],
    contact_by_name: dict[str, dict],
) -> None:
    known_titles = {item['title'] for item in conversations.values() if item.get('title')}
    unresolved_chatrooms = [item for item in conversations.values() if item['type'] == 'chatroom' and not item.get('title')]
    unmatched_labels = [title for title in session_titles if title not in known_titles]

    if 'File Transfer' in session_titles and 'filehelper' not in conversations:
        conversations['filehelper'] = {
            'conversation_id': 'filehelper',
            'title': 'File Transfer',
            'type': 'builtin',
            'confidence': 'high',
            'sources': ['session label cache'],
        }

    if any('Service Notifications' == title for title in session_titles) and 'notifymessage' not in conversations:
        conversations['notifymessage'] = {
            'conversation_id': 'notifymessage',
            'title': 'Service Notifications',
            'type': 'builtin',
            'confidence': 'medium-high',
            'sources': ['session label cache'],
        }

    for title in session_titles:
        if title in ('File Transfer', 'Service Notifications'):
            continue
        if any(item.get('title') == title for item in conversations.values()):
            continue
        if title in contact_by_name:
            row = contact_by_name[title]
            conversations[row['id']] = {
                'conversation_id': row['id'],
                'title': title,
                'type': 'direct',
                'confidence': 'medium-high',
                'sources': ['session label cache', 'contact fallback'],
            }

    group_like_labels = [
        title for title in unmatched_labels
        if any(sep in title for sep in ('、', ',')) or title.startswith('Zuma ')
    ]
    unresolved_chatrooms = [item for item in conversations.values() if item['type'] == 'chatroom' and not item.get('title')]

    if len(unresolved_chatrooms) == 1 and len(group_like_labels) == 1:
        unresolved_chatrooms[0]['title'] = group_like_labels[0]
        unresolved_chatrooms[0]['confidence'] = 'medium-high'
        unresolved_chatrooms[0].setdefault('notes', []).append(
            'title inferred by matching the only unresolved chatroom id to the only unresolved group-like session label',
        )
        add_source(unresolved_chatrooms[0], 'session label cache')


def apply_known_conversation_fallbacks(
    conversations: dict[str, dict],
    conversation_by_id: dict[str, dict],
) -> None:
    for conv_id, row in conversations.items():
        if row.get('title'):
            continue
        fallback = conversation_by_id.get(conv_id)
        if not fallback:
            continue
        row['title'] = fallback['title']
        row['confidence'] = row.get('confidence') or fallback.get('confidence') or 'medium-high'
        row.setdefault('notes', []).append('title filled from previously verified conversation anchor table')
        add_source(row, 'known conversation fallback')


def filter_conversations(
    conversations: dict[str, dict],
    session_titles: list[str],
    contact_by_name: dict[str, dict],
) -> dict[str, dict]:
    allowed_keys = title_key_set(session_titles + list(contact_by_name.keys()) + ['File Transfer', 'Service Notifications'])
    filtered: dict[str, dict] = {}
    for conv_id, row in conversations.items():
        candidates = [repair_mojibake(value) for value in row.get('_title_candidates', [])]
        title = repair_mojibake(row.get('title'))
        if row.get('type') == 'chatroom':
            valid_candidates = [value for value in candidates if is_valid_conversation_title(value, allowed_keys)]
            if valid_candidates:
                best = min(valid_candidates, key=len)
                row = dict(row)
                row['title'] = best
                row['confidence'] = 'high'
            elif title and not is_valid_conversation_title(title, allowed_keys):
                row = dict(row)
                row['title'] = None
                row['confidence'] = 'medium'
                row['notes'] = list(row.get('notes', []))
                row['notes'].append('discarded malformed packed-record title and left chatroom unresolved for session-label matching')
            else:
                row['title'] = title
            filtered[conv_id] = row
            continue

        valid_candidates = [value for value in candidates if is_valid_conversation_title(value, allowed_keys)]
        if valid_candidates:
            row = dict(row)
            row['title'] = min(valid_candidates, key=len)
            filtered[conv_id] = row
        elif is_valid_conversation_title(title, allowed_keys):
            row = dict(row)
            row['title'] = title
            filtered[conv_id] = row
    return filtered


def prune_overlapping_chatrooms(conversations: dict[str, dict]) -> dict[str, dict]:
    chatrooms = [row for row in conversations.values() if row.get('type') == 'chatroom']
    if not chatrooms:
        return conversations

    digit_lengths = Counter(len(row['conversation_id'].split('@', 1)[0]) for row in chatrooms)
    preferred_length, _ = digit_lengths.most_common(1)[0]
    drop_ids: set[str] = set()

    for row in chatrooms:
        conv_id = row['conversation_id']
        digits = conv_id.split('@', 1)[0]
        if len(digits) == preferred_length or row.get('title'):
            continue
        for other in chatrooms:
            if other['conversation_id'] == conv_id:
                continue
            other_digits = other['conversation_id'].split('@', 1)[0]
            if len(other_digits) != preferred_length:
                continue
            if digits in other_digits or other_digits in digits:
                drop_ids.add(conv_id)
                break

    return {conv_id: row for conv_id, row in conversations.items() if conv_id not in drop_ids}


def strip_private_fields(conversations: dict[str, dict]) -> list[dict]:
    rows: list[dict] = []
    for row in conversations.values():
        cleaned = {key: value for key, value in row.items() if not key.startswith('_')}
        if cleaned.get('type') == 'chatroom':
            cleaned['chat_kind'] = 'group'
        elif cleaned.get('type') == 'direct':
            cleaned['chat_kind'] = 'direct'
        elif cleaned.get('type') == 'builtin':
            cleaned['chat_kind'] = 'builtin'
        rows.append(cleaned)
    return rows


def sort_key(row: dict) -> tuple[int, str]:
    order = {'chatroom': 0, 'builtin': 1, 'direct': 2}
    return (order.get(row.get('type', ''), 9), row.get('title') or row['conversation_id'])


def main() -> None:
    parser = argparse.ArgumentParser(description='Capture Weixin 4.1.8.29 conversations from live memory')
    parser.add_argument('--process', default='Weixin.exe')
    parser.add_argument('--output', help='write JSON output to this path')
    parser.add_argument('--pretty', action='store_true')
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]

    device = frida.get_local_device()
    pid = find_process(device, args.process)
    session = device.attach(pid)
    script = session.create_script(SCRIPT)
    script.load()

    try:
        chatroom_hits = run_scan(script, ascii_hex('@chatroom'), 0x180, 0x700, 200)
        direct_hits = run_scan(script, ascii_hex('wxid_'), 0x180, 0x700, 300)
        session_hits = run_scan(script, utf16le_hex('session_item_'), 0x40, 0x140, 200)
    finally:
        script.unload()
        session.detach()

    conversations = {}
    conversations.update(extract_chatroom_conversations(chatroom_hits))
    for conv_id, row in extract_direct_records(direct_hits).items():
        conversations.setdefault(conv_id, row)

    session_titles = extract_session_titles(session_hits)
    contact_by_name = load_contact_fallbacks(repo_root)
    conversation_by_id = load_conversation_fallbacks(repo_root)
    conversations = filter_conversations(conversations, session_titles, contact_by_name)
    apply_session_title_fallbacks(conversations, session_titles, contact_by_name)
    conversations = prune_overlapping_chatrooms(conversations)
    apply_known_conversation_fallbacks(conversations, conversation_by_id)

    payload = {
        'process': args.process,
        'pid': pid,
        'session_titles': session_titles,
        'conversations': sorted(strip_private_fields(conversations), key=sort_key),
    }

    text = json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(text, encoding='utf-8')
    sys.stdout.buffer.write((text + '\n').encode('utf-8'))


if __name__ == '__main__':
    main()
