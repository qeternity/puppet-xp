# WeChat 4.1.8.29 Handover

## Preface For The Next Reverse Engineer

This handover is for a strong reverse engineer picking up the `WeChat 4.1.8.29` port in `puppet-xp`.

The mission here is not generic malware-style exploration and it is not abstract binary archaeology. The goal is to recover the minimum set of native capabilities needed to make the Windows WeChat client usable as a reliable automation backend again.

In practice, that means we are trying to re-establish five concrete product capabilities:

1. identify the logged-in self account programmatically
2. enumerate conversations and contacts with stable native identities
3. read message history with enough structure to classify rows correctly
4. receive live message events with a proof standard stronger than “some parser fired”
5. send messages programmatically, ideally with a fully detached no-UI native send

The most important operating principle is this:

- do not confuse “a hook fired” with “the feature works”

We tightened the proof standard repeatedly during this work because WeChat often produced misleading partial success:

- a task could be scheduled without the message being delivered
- a row could appear locally with a failed-send icon
- a manager-level event could look promising while the UI still disagreed

So the final standard we converged on is:

- native send-task / builder evidence
- native manager-dispatch evidence
- actual WeChat UI verification
- and, when available, mobile-side confirmation from the user

The second major principle is:

- treat seeded arbitrary send and detached no-UI send as different classes of capability

Those two paths are related, but they are not the same:

- seeded arbitrary send means hijacking a real live send already in progress
- detached no-UI send means constructing enough native context to send without any live seed send at all

This distinction matters because the seeded path is genuinely working today, while the detached path is still the last major unresolved problem.

The third major principle is:

- session-local state matters more than static structure in the detached send path

Late in the work we proved that many failures were not caused by the top-level source/owner object shape anymore. The remaining detached blocker is narrow, transient, and tied to short-lived inner helper state, especially around the hidden `ebec0` sequence. That means future progress will likely come from better reproduction of live helper context, not from broad brute-force object cloning.

Finally, use the Windows MCP path deliberately:

- restart WeChat aggressively when the session is corrupted
- prefer approved test conversations only
- single click chats, never double click them
- verify what the UI actually shows instead of trusting logs alone

If you keep those constraints in mind, the notes below should let you move quickly without re-learning the same painful lessons.

This folder is the high-signal handoff for the `4.1.8.29` porting / reverse-engineering work done in this repo.

It is meant to answer four questions clearly:

1. What is actually working today?
2. What evidence do we have for that?
3. Which scripts should someone use to reproduce the working pieces?
4. What is still unresolved, especially around detached no-UI sending?

---

## 1. Scope Of Work Completed

Across the `4.1.8.29` build we made real progress in five big areas:

- self/current-user metadata
- contact / username / alias mapping
- conversation enumeration
- message history / row extraction
- live message hooks and send-path reverse engineering

The main running notebook for all detailed discoveries is still:

- `C:\Users\Administrator\Code\puppet-xp\docs\weixin-4.1.8.29-porting-notes.md`

This `handover` folder is the distilled operational layer on top of that notebook.

---

## 2. Proven Capability Summary

### 2.1 Self / current-user metadata

Status: **working**

We found and validated a native self/account path for `4.1.8.29`.

Current verified fields on the working account:

- self `username`: `wxid_yfe3gm54e5il12`
- nickname: `Chase`
- alias: `zumalabs`

Why this matters:

- message rows use canonical native ids (`username`, usually `wxid_*`)
- to determine whether a message was sent or received, we need the current self username
- we now have that programmatically, not just from user hints

Working handover script:

- `C:\Users\Administrator\Code\puppet-xp\handover\01_get_self_metadata.py`

Underlying repo script:

- `C:\Users\Administrator\Code\puppet-xp\scripts\probe-weixin-self-account.py`

---

### 2.2 Contact mapping (`username` <-> `alias`)

Status: **working**

We standardized on WeChat-native terminology:

- `username` = canonical messaging/storage identity
- `alias` = vanity / user-facing WeChat ID when present
- `nick_name` = display name

We built a trusted artifact that maps both directions:

- `alias_to_username`
- `username_to_alias`

Current generated artifact:

- `C:\Users\Administrator\Code\puppet-xp\docs\weixin-4.1.8.29-contact-id-table.json`

Important distinction:

- the trusted table comes from the curated contact artifacts
- the old live alias scan is heuristic and should **not** be treated as canonical

Working handover script:

- `C:\Users\Administrator\Code\puppet-xp\handover\02_build_contact_table.py`

Underlying repo script:

- `C:\Users\Administrator\Code\puppet-xp\scripts\build-weixin-contact-id-table.py`

---

### 2.3 Conversation enumeration

Status: **working**

We can enumerate conversation/session entries from the live process and map ids to titles.

Verified examples:

- `27208021116@chatroom` -> `Zuma Internal`
- `wxid_3a40v7q8y4kk12` -> `Glenn`
- `wxid_ulr3oq29ruo312` -> `Max Nijhawan`
- `filehelper` -> `File Transfer`

This is session/cache-oriented conversation discovery, not full global history crawling.

Working handover script:

- `C:\Users\Administrator\Code\puppet-xp\handover\03_capture_conversations.py`

Underlying repo script:

- `C:\Users\Administrator\Code\puppet-xp\scripts\capture-weixin-conversations.py`

Useful artifacts already in repo:

- `C:\Users\Administrator\Code\puppet-xp\docs\weixin-4.1.8.29-current-conversation-table.json`
- `C:\Users\Administrator\Code\puppet-xp\docs\weixin-4.1.8.29-live-conversations.json`

---

### 2.4 Conversation history / message rows

Status: **working, but UI/materialization-bound**

We found a real native per-conversation row iterator and decoded enough of the row layout to extract:

- conversation id
- sender username
- timestamp
- content
- message kind

Key validated offsets and interpretations:

- conversation / talker fields
- sender-like fields
- timestamp field
- body field

We also proved:

- system rows are real first-class message records
- system rows can be classified from metadata, not just from text content

Important limitation:

- the current working extractor is tied to the currently materialized UI conversation state
- it is not yet the final “dump every local message across all conversations” crawler

Working handover script:

- `C:\Users\Administrator\Code\puppet-xp\handover\04_monitor_selected_conversation_history.py`

Underlying repo script:

- `C:\Users\Administrator\Code\puppet-xp\scripts\monitor-weixin-message-iterator.py`

How to use it:

1. Run the handover wrapper.
2. Open a conversation in WeChat.
3. Scroll or switch chats.
4. Watch decoded message-row payloads print to stdout.

---

### 2.5 New-message / message-event hook

Status: **working with dedupe**

We found a manager-level event hook that is much closer to the old push-style receive/send event layer than the replay-heavy iterator path.

What it emits:

- conversation id
- conversation title
- sender username
- direction
- content
- avatar / extra raw metadata

Important nuance:

- this layer still needs dedupe
- it is usable and materially better than replay-based hooks
- it is probably not the final best upstream hook

Working handover script:

- `C:\Users\Administrator\Code\puppet-xp\handover\06_monitor_manager_message_events.py`

Underlying repo script:

- `C:\Users\Administrator\Code\puppet-xp\scripts\monitor-weixin-manager-message-hook.py`

Complementary proof hook:

- `C:\Users\Administrator\Code\puppet-xp\handover\05_monitor_send_task_events.py`

That hook is especially useful for validating send-path experiments because it proves a concrete outgoing task was scheduled.

---

## 3. Sending Status

This area needs careful wording because we tightened our proof standards over time.

### 3.1 Seeded arbitrary send

Status: **working and repeatable**

This is the strongest arbitrary-send primitive we trust today.

How it works:

1. A real seed send occurs in any conversation.
2. We hijack the lower native send path in-flight.
3. The actual native send is rewritten to:
   - a different target conversation
   - a different message body

This was proven repeatedly, including with:

- native send-task hooks
- native manager-dispatch hooks
- actual WeChat UI verification
- in some cases mobile-side verification from the user

Working handover script:

- `C:\Users\Administrator\Code\puppet-xp\handover\07_send_seeded_arbitrary_message.py`

Underlying repo script:

- `C:\Users\Administrator\Code\puppet-xp\scripts\hijack-weixin-lower-send.py`

This is the best practical arbitrary-send capability currently available in the repo.

### 3.2 Fully detached no-UI send

Status: **not yet conclusively finished**

This is the key distinction:

- We have had **promising detached runs**
- We have had at least one earlier candidate that looked successful from native hooks
- But after tightening our proof standard, we should **not** claim a clean, repeatable, rigorously verified fully detached no-UI send as a finished capability yet

What is true about the detached path:

- it has gotten very close
- we know a lot about the working recipe
- the remaining blocker is narrow and tied to transient inner-builder helper state
- specifically around the hidden `ebec0` node/state sequence

Current best-known detached recipe:

- use a fresh same-session successful synthetic clone as template
- run on the live send worker thread
- use pair mode `1`
- use owner refs `{3,2}` where needed
- repair the first hidden `ebec0` stage with same-session inline `filehelper` state

What works in detached mode today:

- outer builder entry
- first `eb320`
- first repaired `ebec0`
- in some sessions, the detached path got far enough to strongly suggest we are missing only a small amount of transient inner state

What still does **not** work reliably:

- robust end-to-end detached send without any seed message
- repeatable proof through both native hooks **and** actual UI delivery confirmation

Working proof-of-concept wrapper:

- `C:\Users\Administrator\Code\puppet-xp\handover\08_send_detached_no_ui_poc.py`

Underlying repo script:

- `C:\Users\Administrator\Code\puppet-xp\scripts\send-weixin-text-autonomous.py`

This POC wrapper is intentionally exposed as a **POC**, not a production-ready send primitive.

---

## 4. Windows MCP Workflow

Later in the work we added Windows MCP UI control, which materially improved stability and speed.

That workflow now lets us:

- launch WeChat from the taskbar
- click through the `Open WeChat` gate
- recover from corrupted sessions
- choose approved test conversations quickly
- send seed messages through the UI without waiting on the user

Important UI handling note:

- when selecting a chat in WeChat, use a **single click only**
- do **not** double click a conversation entry
- in practice, double clicking can cause surprising UI state changes and has been a recurring source of bad test runs
- if a conversation is already selected, prefer a small scroll or a deliberate single click on a different chat rather than clicking the active chat again blindly

Approved test conversations for this phase were:

- `File Transfer`
- `Zuma Internal`
- `Glenn`

This became especially important because:

- seed-driven arbitrary send is the reliable send primitive today
- fast restart/recovery matters when WeChat gets corrupted during send-path RE

---

## 5. What The Handover Scripts Are For

These wrappers are intentionally thin and heavily commented.

They are not meant to replace the original RE scripts. They are meant to:

- expose the already-proven capabilities cleanly
- reduce the amount of context needed to reproduce working results
- keep the repo usable for the next person picking this up

### Included scripts

- `handover/common.py`
  - shared helper functions
  - finds the live visible WeChat UI process
  - runs the original repo scripts with the known-good Python interpreter

- `handover/01_get_self_metadata.py`
  - current self/account snapshot

- `handover/02_build_contact_table.py`
  - rebuild trusted username/alias mapping artifact

- `handover/03_capture_conversations.py`
  - capture current session conversation table

- `handover/04_monitor_selected_conversation_history.py`
  - hook the current message iterator / row materializer

- `handover/05_monitor_send_task_events.py`
  - outgoing task proof hook

- `handover/06_monitor_manager_message_events.py`
  - manager-dispatch message event hook

- `handover/07_send_seeded_arbitrary_message.py`
  - the reliable arbitrary-send primitive

- `handover/08_send_detached_no_ui_poc.py`
  - current detached no-UI proof-of-concept interface

---

## 6. Recommended Next Steps

If continuing this work, the best path is:

1. Keep using the seeded arbitrary-send primitive as the practical working send path.
2. Treat detached no-UI send as the remaining research problem.
3. Focus detached work on the inner helper state after the first repaired `ebec0`.
4. Continue using strict proof standards:
   - send-task hook
   - manager-dispatch hook
   - actual WeChat UI verification
5. Do not count a detached send as success unless it survives that stricter verification standard.
6. When driving WeChat through the UI, single-click conversations; never double click them.

---

## 7. Bottom Line

For `4.1.8.29`, the port is no longer at the “we can only poke around” stage.

We have:

- self identity
- contact mapping
- conversation enumeration
- message-row extraction
- system-row classification
- usable message events
- reliable seeded arbitrary native send

The last major unresolved piece is:

- **fully detached no-UI arbitrary send, proven to the stricter final standard**

That problem is now narrow and concrete, not broad and mysterious.
