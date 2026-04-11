# Weixin 4.1.8.29 Porting Notes

This file is the running notebook for the `wechaty-puppet-xp` port from the old
WeChat `3.9.2.23` anchor to installed/running Weixin `4.1.8.29`.

It should be updated continuously as new static and dynamic findings are
verified so we do not lose work between sessions.

## Scope

- Repo: `C:\Users\Administrator\Code\puppet-xp`
- Working branch: `3.9.2.23`
- Goal: port the injected Frida agent and native offset/struct logic from old
  `3.9.2.23` support to Weixin `4.1.8.29`
- Center of gravity:
  - `src/init-agent-script.ts`
  - `src/wechat-sidecar.ts`
  - `src/puppet-xp.ts`

## Anchor Binaries

- Old extracted anchor:
  - `releases/WeChatSetup-3.9.2.23/[3.9.2.23]/WeChatWin.dll`
- Installed target:
  - `C:\Program Files\Tencent\Weixin\Weixin.exe`
  - `C:\Program Files\Tencent\Weixin\4.1.8.29\Weixin.dll`

## High-Level Constraints

- Old `WeChatWin.dll` is x86.
- New `Weixin.dll` is x64.
- Existing agent implementation is heavily x86-specific:
  - `X86Writer`
  - x86 register assumptions
  - x86 stack/call stubs
  - old fixed struct offsets
- Porting must treat the old implementation as an anchor, not as code that can
  be mechanically retargeted.

## Old 3.9.2.23 Implementation Notes

The old implementation is concentrated in `src/init-agent-script.ts`.

Important old native anchors:

- receive hook: old `kDoAddMsg`
- self/account:
  - `kGetAccountServiceMgr`
- send text:
  - `kGetSendMessageMgr`
  - `kSendTextMsg`
  - `kFreeChatMsg`
- contacts:
  - `kGetContactMgr`
  - `kGetContactList`

Important old contact logic:

- contact enumeration is based on the contact manager getter plus contact list
  function
- old contact list iteration uses fixed-size native records of `0x438`
- old room/member logic is separate and storage-driven

## Repo / Adapter Notes

- `src/init-agent-script.ts` hardcodes offsets and native parsing
- `src/wechat-sidecar.ts` still assumes `WeChat.exe`
- `src/puppet-xp.ts` is the adapter layer above the sidecar
- known prior caveats:
  - self-info mapping is not fully trustworthy
  - `isMyMsg` adapter behavior should not be assumed correct

## Running Target

Verified live target:

- process: `Weixin.exe`
- window title: `WeChat`
- verified PID during the initial pass: `10244`

Important note:

- PID-based Frida attach works reliably
- app-name enumeration was less reliable than direct PID attach

## Ghidra / RE Setup

- Ghidra project already contains both:
  - `WeChatWin.dll`
  - `Weixin.dll`
- Direct HTTP against the local Ghidra MCP bridge was usable after restart
- Multiple programs are open, so `program=Weixin.dll` should be passed
  explicitly in MCP queries

Useful MCP endpoints used successfully:

- `/list_open_programs`
- `/switch_program`
- `/get_function_by_address`
- `/decompile_function_by_address`
- `/get_xrefs_to`
- `/search_strings`

## Early Receive-Side Anchors

These were identified and are useful because they survived string-based
re-anchoring:

- `msgsource` string at `0x187f2b48f`
- `atuserlist` string at `0x18827bbbb`

Related functions:

- `FUN_18212a5c0`
  - parses msgsource fields
- `FUN_18212bbc0`
  - serializes msgsource fields
- `FUN_1809b17c0`
  - lazy parse path for msgsource on a message object
  - observed field usage:
    - XML-like source string around `param_1 + 0x140`
    - parsed msgsource cache around `param_1 + 0x240`
    - parsed/valid flag around `param_1 + 0x268`

These are receive/XML-path anchors, not contact/session enumeration anchors.

## Important Static Findings in Weixin.dll

### Manager Bootstrap / Resolver Chain

This is the most important non-UI discovery so far.

- `FUN_180020800`
  - root/context getter
- `FUN_1802fbff0`
  - service container getter
- `FUN_180d0a700`
  - resolves `ContactManager`
- `FUN_180d0a840`
  - resolves `MessageManager`
- `FUN_180d0a980`
  - resolves `SessionManager`

Important calling detail:

- `FUN_1802fbff0` returns a pointer/ref pair
- resolver callers pass the first qword, not the full pair object

### ContactManager-Related Consumers

- `FUN_1829e00a0`
  - resolves `ContactManager`
  - subscribes to `ContactManager + 0x28`
  - strong event-subscription anchor
- `FUN_1829e10c0`
  - resolves `ContactManager`
  - calls `FUN_1828ecf90(contactMgr, ...)`
- `FUN_180e77550`
  - resolves `ContactManager`
  - calls `FUN_1828efbf0(contactMgr, ...)`

Current interpretation:

- contact behavior appears strongly event-driven
- the best verified contact-side passive anchor right now is the signal path off
  `ContactManager + 0x28`
- some identified contact manager consumers look mutating or stateful rather
  than clearly read-only

### SessionManager / MessageManager Consumers

- `FUN_18155e440`
  - very important passive event wiring function
  - subscribes to many `MessageManager` signals:
    - `+0x28`
    - `+0xa8`
    - `+0x128`
    - `+0x1a8`
    - `+0x228`
  - subscribes to `SessionManager` signals:
    - `+0x38`
    - `+0xb8`
    - `+0x138`

Current interpretation:

- session and message updates are naturally manager-signal driven
- this is a better live observation layer than UI widget constructors

### Session Snapshot Helpers

Two strong non-UI session functions were identified from strings:

- `FUN_1813e7060`
  - `GetAllSessionMaxLocalIdMap`
- `FUN_1813e9460`
  - `GetAllSessionLastMessageMap`

These appear to be much stronger enumeration/snapshot candidates than anything
in the conversation-list UI.

### Contact-Side Storage / Mapping Helpers

The best current contact-side candidates are:

- `FUN_180e15c10`
  - checks/builds `Name2Id`
- `FUN_180e17480`
  - populates `Name2Id` from contact/session-backed items

Related strings:

- `Name2Id`
- `kernel::ContactListItemInfo`
- `micromsg.AdditionalContactList`
- `CoGetContactListByCgi`
- `CoGetContactListByCgi usr_list:`

Current interpretation:

- `Name2Id` is a real local mapping path and likely part of the contact-side
  native storage model
- `CoGetContactListByCgi` is real but may be more refresh/network oriented than
  ideal for primary local enumeration
- the exact full local contact snapshot function is not fully pinned yet

## UI-Layer Findings That Did Not Pay Off

A number of UI/widget constructors and wrappers were identified, but repeated
live hooks showed they were the wrong verification layer for contact/session
enumeration.

Examples:

- contact-list ctors:
  - `FUN_183e271f0`
  - `FUN_183e281b0`
- contact wrapper/factory related:
  - `FUN_1808e5640`
  - `FUN_1808e5a10`
  - `FUN_1808dde30`
- session/recent list related:
  - `FUN_18545e6d0`
  - `FUN_18546c2c0`
  - `FUN_185460b80`
  - `FUN_18546e200`
  - `FUN_183bd1790`
  - `FUN_183bde230`

Conclusion:

- attach/hook infrastructure was fine
- these functions simply were not the correct hot paths for the requested UI
  actions
- future verification should stay at the manager/storage level first

## Live Frida Verification Performed

### Manager Resolver Probe

A one-shot read-only probe was created:

- temp file:
  - `C:\Users\Administrator\AppData\Local\Temp\weixin_manager_probe.py`

What it verified live:

- module base for `Weixin.dll`
- root/service resolver chain
- live resolution of:
  - `ContactManager`
  - `MessageManager`
  - `SessionManager`
- populated slot data for signal/cache regions

Observed live values from one verified run:

- `ContactManager obj=0x2d3b1db06d0`
  - `+0x28` signal slot populated
  - `+0xa8/+0xb8/+0xc8/+0xd8` populated
- `MessageManager obj=0x2d3b1f13a70`
  - `+0x28/+0xa8/+0x128/+0x1a8/+0x228` populated
- `SessionManager obj=0x2d3b22ac8c0`
  - `+0x38/+0xb8/+0x138` populated

This is the strongest dynamic confirmation so far that the correct anchoring
layer is the native manager layer, not the UI layer.

### Temporary UI Probe Work

Several temp probes were also used during the initial pass, for example:

- `C:\Users\Administrator\AppData\Local\Temp\weixin_live_probe.py`

Those probes were useful mainly to prove:

- background attach was working
- PID attach was stable
- the chosen UI functions were not the right targets

## Best Current Non-UI Targets

### Contacts

Strongest verified or high-confidence targets:

- `FUN_180d0a700`
  - `ContactManager` resolver
- `FUN_1829e00a0`
  - `ContactManager + 0x28` subscription anchor
- `FUN_180e15c10`
  - `Name2Id` map path
- `FUN_180e17480`
  - `Name2Id` population path

### Conversations / Sessions

Strongest verified or high-confidence targets:

- `FUN_180d0a980`
  - `SessionManager` resolver
- `FUN_18155e440`
  - session/message event subscription anchor
- `FUN_1813e7060`
  - `GetAllSessionMaxLocalIdMap`
- `FUN_1813e9460`
  - `GetAllSessionLastMessageMap`

### Receive / Message Flow

- `FUN_180d0a840`
  - `MessageManager` resolver
- `FUN_18155e440`
  - message signal subscriptions
- `FUN_1809b17c0`
  - receive-side msgsource parsing anchor
- `FUN_18212a5c0`
  - msgsource parse helper

## Current Working Hypothesis

- The correct `4.1.8.29` porting strategy is manager-first, not UI-first.
- Contacts should be re-anchored through:
  - `ContactManager`
  - its signal path at `+0x28`
  - local contact storage/mapping paths such as `Name2Id`
- Conversations should be re-anchored through:
  - `SessionManager`
  - snapshot helpers like `GetAllSessionMaxLocalIdMap`
  - snapshot helpers like `GetAllSessionLastMessageMap`
- Message receive/send work should share the same manager-level approach rather
  than trying to preserve the old x86 stub patterns.

## Open Questions

- What is the best true local contact snapshot/list function for full contact
  enumeration in `4.1.8.29`?
- Which contact-side struct layout replaces the old fixed-size `0x438` x86
  contact record?
- Which session-side structure corresponds to the old conversation/session list
  semantics needed by the puppet?
- Which manager-level paths are safe to call read-only from Frida, and which are
  mutating/subscription-only?
- What is the cleanest x64 equivalent for the old send-text call chain and
  cleanup path?

## New Live Contact Enumeration Findings

### Static-to-Live Bridge That Paid Off

The best contact-side static bridge so far is still:

- `FUN_180e15c10`
  - `Name2Id` map path
- `FUN_180e17480`
  - populates `Name2Id`
- `FUN_180e19c40`
  - helper that inserts `uint -> string` entries into a native map

Additional useful static evidence:

- `FUN_1813bbd20`
  - `ParseMessageQueryResult`
  - calls `FUN_180e17480(...)`
  - then uses the generated map to resolve ids into strings
- `FUN_1813e7060`
  - session snapshot helper
  - independently rebuilds a `Name2Id`-style map while iterating session data
- `FUN_1813e9460`
  - session last-message snapshot helper
  - feeds through `FUN_1813bbd20(...)`

Interpretation:

- the session side is definitely reusing the contact-side `Name2Id` machinery
- the contact/session mapping layer is real and live, even if the cleanest
  direct callable entrypoint has not yet been isolated

### Live Heap Enumeration Pass

To avoid waiting on UI-driven paths, a direct live heap scan was used:

- temp scripts:
  - `C:\Users\Administrator\AppData\Local\Temp\weixin_dump_glenn_context.py`
  - `C:\Users\Administrator\AppData\Local\Temp\weixin_scan_contact_records.py`
- temp raw outputs:
  - `C:\Users\Administrator\AppData\Local\Temp\weixin_glenn_context.json`
  - `C:\Users\Administrator\AppData\Local\Temp\weixin_contact_candidates.json`
- persisted reduced export:
  - `docs/weixin-4.1.8.29-contact-candidates.json`

What this verified:

- live heap records do exist that contain:
  - an ASCII `wxid_...` id
  - a nearby UTF-16 display-name string
- this is not just a UI label artifact; the same `wxid_...` records recur across
  many live cache windows and are consistent with the `Name2Id` mapping work

### Confirmed Human-Readable Match

Confirmed live mapping from the running process:

- `wxid_3a40v7q8y4kk12`
  - nearby confirmed UTF-16 display name:
    - `Glenn`

This is the first positively confirmed `id -> plain-text name` pair recovered
from the live `4.1.8.29` process without relying on a UI click path.

### First Full Contact-Candidate Extraction

The first heap-based extraction pass produced:

- `685` live `wxid_...` contact candidates
- reduced cleaned export of regex-valid ids:
  - `579`
- reduced export written to:
  - `docs/weixin-4.1.8.29-contact-candidates.json`

Important caveat:

- many entries in that export have only a heuristic label, not a fully
  confirmed display name
- the heuristic label is chosen from:
  - nearest human-readable UTF-16 string
  - or a nearby ASCII alias-like string when the nearby UTF-16 string is noisy
- one entry is positively confirmed:
  - `wxid_3a40v7q8y4kk12 -> Glenn`

Examples of plausible alias-like labels observed in the first export:

- `mishangdoulao004`
- `jinbaiwankaoya009`
- `gzsanxiangsishui`
- `shsanrenxing005`
- `chuanfenghuoguo002`
- `guoshishougongcai`
- `jiweiniaotianpin`
- `bjyuxiangkitchen008`
- `AirFranceOfficial`

Current interpretation:

- this is good enough to prove that live contact/session identifiers are present
  and enumerable from the running process
- this is not yet the final clean native contact-list API equivalent
- the next step should still be to reconnect this heap result back to the true
  `Name2Id`/contact snapshot function path, so the eventual agent port uses a
  stable function-level anchor rather than raw memory scanning

## Next Recommended Steps

1. Trace the emitters/callbacks behind `ContactManager + 0x28`.
2. Trace the emitters/callbacks behind `SessionManager + 0x38/+0xb8/+0x138`.
3. Walk outward from `FUN_1813e7060` and `FUN_1813e9460` to recover the native
   conversation/session data shapes.
4. Walk outward from `FUN_180e15c10` and `FUN_180e17480` to recover the local
   contact data shape and identify the best contact snapshot function.
5. Use the confirmed `wxid_3a40v7q8y4kk12 -> Glenn` live record as the anchor
   record for struct-layout recovery and pointer-backtracking.
6. Compare the heap-derived candidate list against the eventual function-level
   `Name2Id` or contact snapshot output so the scanning heuristic can be
   retired.
7. Keep all new findings appended to this file with clear separation between:
   - static evidence
   - live evidence
   - hypothesis
   - confirmed anchor

## 2026-04-08 Follow-Up: Native Contact Path Triage

### Executable Plan

Current working plan for contact enumeration MVP:

1. Reconfirm the true native contact entrypoint rather than assuming UI or
   session-decorator paths.
2. Keep a passive live probe attached to the running `Weixin.exe` so any real
   contact/name-mapping activity is captured without requiring UI actions.
3. Continue static recovery around `Name2Id` builder callers and any worker
   objects that survive in memory.
4. Use live object inspection to validate or reject static hypotheses quickly.
5. Preserve all findings here before any eventual repo-side instrumentation
   changes.

### New Static Findings

Additional functions inspected in `Weixin.dll`:

- `FUN_1825332d0`
  - direct caller of `FUN_180e15c10`
  - constructor-style function that also calls:
    - `FUN_1825335f0`
    - `FUN_182533830`
    - `FUN_182533a70`
    - `FUN_182533cb0`
    - `FUN_182533ef0`
  - caller:
    - `FUN_180eca3a0`

- `FUN_180ec4a00`
  - a large dispatcher on a request-like object at `param_2`
  - checks:
    - `*(int *)(param_2 + 0x20)`
    - `*(longlong *)(param_2 + 0x10)`
  - routes by the `+0x20` operation code
  - case `3` calls:
    - `FUN_180eca3a0`

- `FUN_180eca3a0`
  - constructs an outer worker object and an inner object initialized by
    `FUN_1825332d0`
  - also calls:
    - `FUN_180e114d0`
    - `FUN_1800981b0`
    - `FUN_180eff7c0`
    - `FUN_180ed8870`
  - earlier hypothesis was that this might be a contact-list root

- `FUN_1833cec80`
  - still a strong `Name2Id` worker wrapper
  - flow is:
    - initialize local map
    - `FUN_180e17480(local_48, param_1 + 0x28, &local_88)`
    - `FUN_1833cedf0(&local_38, &local_88)`
  - good evidence that it applies a built `Name2Id` map into another result
    object, but not yet proven to be the root contact snapshot API

- `FUN_1833cedf0`
  - allocates a result-apply object and passes it through `FUN_180318410`
  - appears to be a map-application callback stage after `FUN_180e17480`

### Passive Live Probe

New passive runtime probe:

- script:
  - `C:\Users\Administrator\AppData\Local\Temp\weixin_contact_dispatch_probe.py`
- logs:
  - `C:\Users\Administrator\AppData\Local\Temp\weixin_contact_dispatch_probe_out.txt`
  - `C:\Users\Administrator\AppData\Local\Temp\weixin_contact_dispatch_probe_err.txt`

What it hooks:

- `FUN_180ec4a00`
- `FUN_180eca3a0`
- `FUN_1825332d0`
- `FUN_180e15c10`
- `FUN_180e17480`
- `FUN_1833cec80`

Verification:

- attached successfully to live `Weixin.exe`
- confirmed module base:
  - `0x7ffa3f160000`
- background process stayed alive with clean heartbeats for several minutes
- no natural hits yet on those hook points in the current idle app state

Interpretation:

- the passive attachment is healthy
- the current logged-in idle app is not naturally exercising this path often
  enough for passive-only capture
- this means we need either:
  - a better passive hook closer to an always-live cache owner
  - or a callable object/worker recovered from memory

### Live Object Scan of Candidate Worker VTables

Because the passive hooks stayed quiet, live heap scans were run for worker
objects whose first field matches candidate vtable pointers recovered from the
static path.

Important result:

- a live object was found at:
  - `0x2d3b18defa0`
- it begins with vtable:
  - `PTR_FUN_187fbceb8`
- it contains a nested subobject at `+0x10` beginning with:
  - `PTR_FUN_1882ee5b8`

This is real evidence that the `FUN_180eca3a0 -> FUN_1825332d0` object family
exists live in the process right now.

### Crucial Correction

The first live object recovered from the `FUN_180eca3a0` path does **not**
look like a clean contact-list worker after inspection.

Observed linked content includes strings and structures consistent with:

- `micromsg`
- `wreportkvcomm`
- `/cgi-bin`
- `4-contact.db`
- `sqlite_master`
- `sql`
- `name`
- `type`
- `Table`
- `offsets`

Interpretation:

- the path is real and live
- but the first surviving object currently visible looks partly
  network/database/schema-related
- therefore the earlier shortcut hypothesis:
  - `FUN_180ec4a00` case `3` = direct contact list API
  - should be treated as **unproven**

This does **not** invalidate `FUN_180e15c10` / `FUN_180e17480` as strong
`Name2Id` machinery. It does mean the `180ec4a00 -> 180eca3a0` chain may be
broader or more indirect than first hoped.

### Local Data Files Check

Relevant local WeChat data files were discovered under:

- `C:\Users\Administrator\Documents\WeChat Files\wxid_yfe3gm54e5il12\Msg`

Notable files:

- `MicroMsg.db`
- `FTSContact.db`
- `OpenIMContact.db`

Attempted direct SQLite inspection failed with:

- `sqlite3.DatabaseError: file is not a database`

Interpretation:

- the on-disk stores are not plain SQLite in a directly queryable form from
  this environment
- this reinforces the importance of the live process/native path, because the
  running process clearly has usable decrypted/live structures even when the
  files do not

### Current Best Read

Confirmed:

- `Name2Id` machinery is real and central
- the old session/message decorator paths still reuse it
- live `wxid -> name` recovery works heuristically from heap memory
- a real live object family tied to `FUN_1825332d0` exists in memory

Not yet confirmed:

- the final root callable that returns the full contact snapshot
- the stable contact-record layout for `4.1.8.29`
- a clean function-level full contact enumeration equivalent to old
  `ContactMgr::getList`

### Updated Next Step

The next highest-value move is:

1. Pivot away from assuming `180ec4a00` case `3` is the direct contact API.
2. Re-anchor on:
   - `FUN_180e15c10`
   - `FUN_180e17480`
   - `FUN_1833cec80`
3. Find the object or caller that feeds `FUN_1833cec80` with a true contact
   source list at `param_1 + 0x28`, rather than a generic decorator job.
4. Keep the passive live probe running while doing that, in case the real path
   wakes up and gives a direct runtime hit.

## 2026-04-08 Follow-Up: Repeated Live Contact Entry Class

### New Live Breakthrough

A repeated live object class was recovered from the running process by scanning
for a stable vtable pointer:

- live vtable:
  - `Weixin.dll + 0x70409b8`
  - runtime:
    - `0x7ffa470409b8`

This class can be parsed as a pair of string-like fields:

- field at `+0x18`
  - contact/session id
- field at `+0x50`
  - human-readable name

Observed `Glenn` instance:

- address:
  - `0x2d3b146c1b0`
- parsed:
  - `id = wxid_3a40v7q8y4kk12`
  - `name = Glenn`

Important inferred layout from the `Glenn` object:

- `+0x00`
  - vtable = `Weixin.dll + 0x70409b8`
- `+0x18`
  - first string-like field
  - parses to the contact id
- `+0x50`
  - second string-like field
  - parses to the display name

This is the strongest per-entry live structure recovered so far.

### Batch Parse Result

A one-shot scanner was built and written to:

- `C:\Users\Administrator\AppData\Local\Temp\dump_contact_entry_vtable_scan.py`

Its output is:

- `C:\Users\Administrator\AppData\Local\Temp\contact_entry_vtable_scan.json`

Current result:

- `545` raw vtable hits
- `41` parsable objects
- `13` unique ids in the current materialized set

Confirmed sample parsed entries:

- `wxid_3a40v7q8y4kk12 -> Glenn`
- `wxid_yfe3gm54e5il12 -> Chase`
- `wxid_ulr3oq29ruo312 -> Max Nijhawan`
- `wxid_jh7tgf4ggsgs22 -> Heng Chen 陳亨`
- `wxid_shj82mm92ok622 -> Oli`
- `filehelper -> File Transfer`
- `27208021116@chatroom -> Zuma Internal`
- `26055110994@chatroom -> Zuma`
- `26085711013@chatroom -> Glenn、Simon`
- `27005821674@chatroom -> Zuma Test`

### Important Interpretation

This repeated class is real and useful, but it is **not yet proven to be the
full canonical master contact list**.

Why:

- only `13` unique ids are present in the current parsed set
- several ids are duplicated across different regions
- the set mixes:
  - direct contacts
  - chatrooms
  - special/system entries
  - some transient entries like `test456` and `Loading...`

This looks more like a partially materialized unified contact/session entry
model than a final authoritative full-contact cache.

### Strong Region Clusters

The parsed entries cluster heavily in a few arenas:

- `0x2d3b3240000`
  - `8` entries
- `0x2d3b2e30000`
  - `7` entries

Examples:

- cluster `0x2d3b3240000`
  - `26055110994@chatroom -> Zuma`
  - `26085711013@chatroom -> Glenn、Simon`
  - `wxid_yfe3gm54e5il12 -> Chase`
  - `wxid_jh7tgf4ggsgs22 -> Heng Chen 陳亨`
  - `wxid_shj82mm92ok622 -> Oli`

- cluster `0x2d3b2e30000`
  - `filehelper -> File Transfer`
  - `wxid_3a40v7q8y4kk12 -> Glenn`
  - `27208021116@chatroom -> Zuma Internal`
  - `wxid_n2wqdtmexiws22 -> Weixin users who have stopped using`
  - `wxid_yfe3gm54e5il12 -> Chase`

Interpretation:

- one or more real live backing caches are present
- but the currently materialized set still appears partial
- this is likely downstream of the canonical owner rather than the owner itself

### Current Best Hypothesis

The repeated `id/name` entry class is likely:

- a contact/session entry model object
- populated from a higher-level backing cache or snapshot
- reused in more than one region/model

This means the immediate next target is no longer “find an entry object”;
that part is done.

The immediate next target is:

- find the owner/cache that materializes these entries in bulk
- or force the contact model to fully materialize and then identify the owning
  region/object that grows

## 2026-04-08 Follow-Up: Manager Correction

### Important Correction

The previously live-verified object returned by:

- `FUN_180d0a700`

should no longer be treated as the canonical full contact manager without
qualification.

Current evidence strongly suggests this object is instead:

- a contact search / FTS / index-oriented service
- or at least a manager whose visible live state is dominated by contact FTS
  schema/index structures rather than the authoritative full contact list

This is an important correction because the earlier working assumption was:

- `FUN_180d0a700` == canonical contact owner

That assumption is now considered unsafe.

### Why The Assumption Broke

Live inspection of the object returned by `FUN_180d0a700` showed:

- manager core state at:
  - `+0xb0`
  - `+0xc0`
  - `+0xc8`
  - `+0xd0`
  - `+0xd8`
  - `+0xe0`
  - `+0xf0`
  - `+0xf8`

The `+0xc0` region looked at first like a manager-owned hash/index:

- start:
  - `0x2d3b176f160`
- end:
  - `0x2d3b176f1e0`
- mask/count-like fields:
  - `+0xd8 = 7`
  - `+0xe0 = 8`

But dumping that region showed:

- eight identical empty buckets
- all buckets point to the same sentinel:
  - `0x2d3b1d37890`

Opening the shared sentinel/root `0x2d3b1d37890` showed repeated FTS/index
schema material, including:

- `fts3_tokenizer`
- `fts5`
- `UNINDEXED`

This means the manager-owned structure we first reached there is not the full
contact record store.

### Additional Live Service Evidence

The reachable object at:

- `0x2d3b1a1d7b0`

contains:

- `contact_fts_v4`
- `fts3tokenize`

This is more direct evidence that at least part of the reachable object graph
off the current getter is a contact FTS / search layer.

### Current Interpretation

The current best interpretation is:

- `FUN_180d0a700` may be a contact-related service getter
- but the concrete live object we are landing on is centered on contact
  indexing/search structures
- the canonical master contact store likely sits in:
  - a different contact-related service
  - or another companion object behind the broader service registration cluster

### Consequence For Porting

Do **not** port `FUN_180d0a700` directly as the final replacement for the old
`WX_CONTACT_MGR_OFFSET` path yet.

Instead, the contact-side task is now:

- distinguish live services in the contact registration cluster
- identify which service is:
  - canonical contact store
  - contact FTS/search
  - OpenIM contact
  - WA contact / auxiliary

### Current Live Status

At the time of this note:

- the repeated `id/name` entry class at `Weixin.dll + 0x7ee09b8` still parses
  only a partial mixed set (`13` unique ids)
- keeping the Contacts view open did **not** increase that parsed set
- therefore that class is also not currently trusted as the canonical full
  contact owner

### Temporary Blocker

The live `Weixin` process was no longer visible from this session during the
latest follow-up pass, so additional dynamic verification requires reattaching
to a running process again.

## 2026-04-08 Contact Row Enumeration Progress

### Confirmed Live Row-Set Size

A length-based scan over the shared contact/model heap recovered:

- `53` raw row-node hits
- `9` unique contact IDs

The user confirmed that the logged-in test account currently has exactly:

- `9` contacts

This is strong evidence that the current length-based row scan is reaching the
full live contact row set for this account, even though the display-name field
layout is not fully generalized yet.

### Verified Contact ID Anchors

Confirmed live mappings so far:

- `wxid_3a40v7q8y4kk12 -> Glenn`
- `wxid_cdxvsfdqlbqw22 -> Adam - Arrow FFAs`

These are both user-verified against the real account.

### Current Interpretation

The contact work is now split into two pieces:

1. `ID` enumeration:
   - currently strong
   - the row scan appears to recover the whole live set for this account

2. `name / metadata` binding:
   - partially confirmed through anchored examples
   - not yet generalized into one stable row struct layout

### Important Note About The Current Row Scan

The successful row scan is:

- length-based, not null-terminated-string-based
- operating over the shared live contact/model heap
- good enough to recover the `9` current contact IDs

The remaining parsing problem is to bind each recovered row ID to the correct
plain-text name field consistently for all rows, not just for anchored examples
like `Glenn` and `Adam - Arrow FFAs`.

## 2026-04-08 Live `contact_list` Model Range Path

### New Live Object Discovery

A direct live scan for the `primary_table_` and `secondary_table_` table
vtables found the active `contact_list` owner objects in the running
`Weixin.exe` PID `212`.

Runtime module base:

- `Weixin.dll = 0x7ffa3ff30000`

Resolved live table instances:

- primary table object:
  - object: `0x1880df72bc0`
  - vtable: `Weixin.dll + 0x85d0738`
  - embedded `contact_list` model at `+0x1d0 -> 0x188164d0720`
- secondary table object:
  - object: `0x188136bab00`
  - vtable: `Weixin.dll + 0x85d1208`
  - embedded `contact_list` model at `+0x1d0 -> 0x18815d45d60`

### Primary vs Secondary Table Status

The **primary** table is the populated live path:

- model: `0x188164d0720`
- model vtable: `0x7ffa4844b148`
- cached base index via `FUN_181ec73c0`: `0`
- cached count via `FUN_181ec73f0`: `14`
- provider object at `model + 0x218 -> 0x1880df72d48`
- provider count via provider vtable slot `+0x8`: `19`

The **secondary** table is currently empty/inactive:

- model: `0x18815d45d60`
- model vtable: `0x7ffa4844b698`
- cached count: `0`
- provider count: `0`

### New Range Accessor Conclusion

The clearest new replacement for the old flat `getContactList` range path is
currently the `contact_list` model cache API, not a single old-style
`begin/end` function:

- `FUN_181ec73c0(model)`:
  - returns cached base index
- `FUN_181ec73f0(model)`:
  - returns cached item count
- `FUN_181ec7f40(model, globalIndex)`:
  - returns the cached row pointer for that index
- `FUN_181ec8b50(model, visitor)`:
  - walks the cached row set via callback

So the current practical range is:

- start index = `FUN_181ec73c0(model)`
- count = `FUN_181ec73f0(model)`
- row `i` = `FUN_181ec7f40(model, start + i)`

### Cache Refresh / Population Path

The strongest cache-population function identified so far is:

- `FUN_181ec8550(...)`

This function:

- receives an update/change object
- calls `FUN_181ecb8c0(...)`
- `FUN_181ecb8c0(...)` rebuilds/swaps the cached row vector at `model + 0x1b8`

Important distinction:

- this is the **cache rebuild path**
- it is not yet proven to be a single old-style
  "`return all contact rows now`" function

### Current Best Interpretation

We **do** now have a non-heuristic, live-callable row-range path for the active
contact list model.

What we **do not** have yet is a single exported-style helper that directly
returns the full canonical contact set in one call. The closest working
replacement is the live `primary_table_ -> contact_list` model plus the cached
range accessors above.

### Row-Object Parsing Progress

The first direct row-header parse was misleading. The meaningful per-row payload
is not in the short row header; it is attached deeper in the object:

- packed row metadata around `row + 0x178`
- row payload pointer at `row + 0x180`
- the most useful nested branch so far is `*(rowPayload + 0x50)`

That `+0x50` branch is the first row-derived path that yields real contact IDs
and nearby human-readable labels.

### Current Row-Derived Candidate Mappings

High-confidence row-derived mappings:

- `wxid_cdxvsfdqlbqw22 -> Adam - Arrow FFAs`
  - recovered from the `row + 0x180 -> payload + 0x50` node neighborhood
- `wxid_jh7tgf4ggsgs22 -> Heng Chen`
  - same path, with both:
    - `Heng Chen`
    - `HENGCHENCHENHENG`
- `wxid_3a40v7q8y4kk12 -> Glenn`
  - user-confirmed
  - id is present in the row-node path, but the clean display-name field is not
    yet isolated from the surrounding mixed strings
- `wxid_shj82mm92ok622 -> Oli`
  - user-confirmed
  - additionally supported by a packed memory artifact containing repeated
    `Oli` strings next to the tail of the id blob
- `wxid_yfe3gm54e5il12 -> zumalabs / Chase`
  - self account
  - user-confirmed alias + display name pairing
  - also supported by a packed memory artifact:
    - `wxid_yfe3gm54e5il12zumalabsChase`

Additional row-derived IDs recovered from the same path:

- `wxid_ulr3oq29ruo312`
  - recovered from row `12`
  - likely the Max Nijhawan contact with an alias display name
  - still unresolved from the current row-node dump

### Important Interpretation

This is the first non-heuristic contact parsing path that is:

- rooted in the live `primary_table_ -> contact_list` model
- using the model cache/range accessors
- extracting IDs from row-owned memory rather than a broad process heap scan

The remaining work is mostly **field binding / disambiguation**:

- isolate the exact label/display-name field for each row
- avoid mixed neighboring contact strings when several ids share the same node

### Live Row Cache Snapshot: 2026-04-08

Fresh live dump against the current `Weixin.exe` session confirmed the same
`contact_list` model is still active:

- module base: `0x7ffa3ff30000`
- model: `0x188164d0720`
- cached base index: `6`
- cached row count: `13`
- active row indices: `6..18`

Current direct row-derived ids visible from the live cache:

- row `6`: `wxid_yfe3gm54e5il12`
- row `7`: `wxid_cdxvsfdqlbqw22`, `wxid_3a40v7q8y4kk12`
- row `10`: `wxid_jh7tgf4ggsgs22`
- row `16`: `filehelper`
- row `17`: `weixin`
- row `18`: `filehelper`

Important caveat:

- the active cache still contains mixed/shared row blobs
- not every visible contact gets a unique one-row-one-id representation
- some rows are clearly classify/header/system rows rather than plain contacts

### Stronger Name Pairings From Focused Live Scans

Focused live scans around human-readable names produced several clean `id ->
display name` pairings that are stronger than the earlier generic heap
correlation:

- `filehelper -> File Transfer`
  - clean co-occurrence at live hit `0x188138c9828`
- `weixin -> WeChat Team`
  - clean co-occurrence at live hit `0x18814386220`
- `wxid_cdxvsfdqlbqw22 -> Adam - Arrow FFAs`
  - clean co-occurrence at live hit `0x1881572a4d0`
- `wxid_jh7tgf4ggsgs22 -> Heng Chen`
  - clean co-occurrence at live hit `0x188157367d0`
- `wxid_yfe3gm54e5il12 -> zumalabs / Chase`
  - clean co-occurrence at live hit `0x18813e71ee8`

The cleanest current display-label strings are:

- `session_item_Adam - Arrow FFAs`
- `session_item_Chase`
- `session_item_File Transfer`
- `session_item_Glenn`
- `session_item_Heng Chen 陳亨`

This is the first clean evidence that the full current display name for the
Heng Chen contact is:

- `Heng Chen 陳亨`

### Glenn, Max, And Special-Row Interpretation

New live evidence for Glenn:

- `Glenn` is present inside the live row-model recursive dump, not just the
  broad heap scan
- the strongest current hit is in the row `10` metadata neighborhood at:
  - `p10 + 0xc8 -> 0x18813e6e4a0`

Current best interpretation for Max Nijhawan:

- row `12` still owns the unresolved id blob containing:
  - `wxid_ulr3oq29ruo312`
- separate focused live scans found `Max Nijhawan` strings at addresses inside
  the same row-`12` address neighborhood:
  - `0x1880e6718f8`
  - `0x1880e671938`
- row `12` itself is at:
  - `0x1880e671670`

This is now the strongest current evidence that:

- `wxid_ulr3oq29ruo312 -> Max Nijhawan`

It is still marked as a strong inference rather than fully closed because I do
not yet have a single tiny clean blob containing only the id and name together.

### Remaining Contact Gaps

The still-interesting live ids showing up in shared/master blobs are:

- `wxid_shj82mm92ok622`
  - user-confirmed as `Oli`
- `wxid_n2wqdtmexiws22`
  - appears in shared contact-name blobs
- `wxid_j6362wqv6yqf22`
  - appears in shared contact-name blobs near `Heng Chen`

Important interpretation:

- these shared/master blobs likely hold a wider canonical contact/session name
  cache than the direct per-row `p50` branch alone
- the next useful step is to recover the owner/record layout of that shared
  contact-name blob rather than treating each mixed blob as an independent row

### Shared Contact-Name Cache Blob

A fresh targeted dump of the live blob at:

- `0x18815d92480`

produced a clean ordered ASCII name/id list:

- `filehelper`
- `weixin`
- `Chase`
- `zumalabs`
- `Service Notifications`
- `Simon`
- `Zuma Internal`
- `Zuma Test`
- `Glenn`
- `Zuma`
- `Adam - Arrow FFAs`
- `Heng Chen `
- `Oli`
- `Max Nijhawan`
- `MNijhawan9`

This blob is important because it is the first single live artifact that
contains nearly the whole visible contact-name set in one place.

Important caveat:

- the blob also contains non-contact/service labels like:
  - `Service Notifications`
  - `Zuma Internal`
  - `Zuma Test`
  - `Zuma`
- so it is likely a mixed contact/session/search name cache rather than a pure
  contact-only array

### New Direct Simon Mapping

Focused live scan for `Simon` produced the first direct id pairing:

- `Simon -> wxid_j6362wqv6yqf22`

Strongest current hit:

- `0x18816b21b29`
  - nearby values include:
    - `wxid_j6362wqv6yqf22`
    - `Simon`

This upgrades `wxid_j6362wqv6yqf22` from a background blob id to a named
contact candidate.

### Current Best 9-Contact Table

Based on the current live row-model evidence, the focused name scans, and the
user confirmations so far, the best current 9-contact set is:

- `filehelper -> File Transfer`
  - clean live co-occurrence
- `weixin -> WeChat Team`
  - clean live co-occurrence
- `wxid_yfe3gm54e5il12 -> Chase`
  - alias: `zumalabs`
  - user-confirmed
- `wxid_3a40v7q8y4kk12 -> Glenn`
  - user-confirmed
- `wxid_cdxvsfdqlbqw22 -> Adam - Arrow FFAs`
  - user-confirmed
- `wxid_jh7tgf4ggsgs22 -> Heng Chen 陳亨`
  - user-confirmed
- `wxid_shj82mm92ok622 -> Oli`
  - user-confirmed
- `wxid_ulr3oq29ruo312 -> Max Nijhawan`
  - strong live inference from row `12`
- `wxid_j6362wqv6yqf22 -> Simon`
  - direct live co-occurrence

Status of this table:

- the first 8 entries above are either direct live pairings or user-confirmed
  mappings backed by live memory artifacts
- `wxid_ulr3oq29ruo312 -> Max Nijhawan` is still the weakest link, but it is
  now a strong row-local inference rather than a loose guess

### Still-Unresolved Shared Blob Id

`wxid_n2wqdtmexiws22` still appears in shared mixed blobs, especially next to
the Oli image/name material:

- e.g. packed artifact prefix:
  - `wxid_n2wqdtmexiws22hj82mm92ok622...@strangerOliOLIOli...`

Current interpretation:

- this id likely belongs to an adjacent contact/session record in the same
  packed blob
- it is not yet needed to explain the user's stated 9-contact set, now that
  `Simon -> wxid_j6362wqv6yqf22` has been recovered

## Deterministic Contact Cache Structures

### SQLite-Like Label Leaf Page

The heap region owning the contact/name cache contains a real SQLite-style leaf
page at:

- `0x18815d916c0`

This page was dumped to:

- `%TEMP%\\weixin_sqliteish_page_916c0.bin`
- `%TEMP%\\weixin_sqliteish_page_916c0_parsed.json`

It parses cleanly as:

- page type `0x0d` (leaf table)
- `17` cells
- cell content area starting at `0x0de6`

Decoded cell payloads yield these packed label records:

- rowid `1`: `['语音记事本', 'medianote']`
- rowid `2`: `['漂流瓶', 'floatbottle']`
- rowid `3`: `['Oli']`
- rowid `4`: `['Glenn']`
- rowid `5`: `['Max Nijhawan', 'MNijhawan9', 'United Kingdom ']`
- rowid `6`: `['Heng Chen 陳亨']`
- rowid `7`: `[]`
- rowid `8`: `['Adam - Arrow FFAs']`
- rowid `9`: `['Zuma']`
- rowid `10`: `['Chase', 'zumalabs']`
- rowid `11`: `['Zuma Test']`
- rowid `12`: `[]`
- rowid `13`: `['Zuma Internal']`
- rowid `14`: `['Simon']`
- rowid `15`: `['Service Notifications']`
- rowid `16`: `['微信团队', 'weixin']`
- rowid `17`: `['文件传输助手', 'filehelper']`

This is the first deterministic, repeatable packed label source we have found.
It is not just random string soup; the page header and cell layout are valid.

Important correction after user verification:

- the user has `9` visible conversations
- one of them is a group chat titled `Zuma Internal`
- that group contains `Chase`, `Glenn`, and `Oli`

This strongly reinforces that the `0x18815d916c0` leaf page is a mixed
conversation/session label cache, not a pure canonical contact table. That
explains the presence of:

- `Zuma Internal`
- `Zuma Test`
- `Zuma`
- `Service Notifications`

So this page is still a valuable deterministic label source, but it must not be
treated as the authoritative contact list by itself.

### Stable Row Username Slot

The live `primary_table_ -> contact_list` row objects expose a stable username
slot at:

- `row + 0x248`

Direct live reads from `%TEMP%\\weixin_row_direct_slots_live.json`:

- row `6` -> `wxid_yfe3gm54e5il12`
- row `8` -> `wxid_3a40v7q8y4kk12`
- row `10` -> `wxid_jh7tgf4ggsgs22`
- row `12` -> `wxid_ulr3oq29ruo312`
- row `14` -> `wxid_shj82mm92ok622`
- row `16` -> `wxid_n2wqdtmexiws22`
- row `17` -> `weixin`
- row `18` -> `filehelper`

This is the cleanest stable id slot discovered so far in the live row-model
objects.

### Stable Nested Label Path Example

At least one row-label path is now live-confirmed structurally:

- row `15` child at `row + 0xd8`
- then nested pointer slots at `+0xd0` / `+0xe0`
- both resolve to `Adam - Arrow FFAs`

Artifact:

- `%TEMP%\\weixin_row_nested_d8_248_live.json`

This confirms the row-model is split: the visible row object does not always
carry both username and label in the same shallow slot family.

## Current Recovered Contact Table

The current best account-level contact table is captured in:

- [weixin-4.1.8.29-current-contact-table.json](/C:/Users/Administrator/Code/puppet-xp/docs/weixin-4.1.8.29-current-contact-table.json)

Summary:

- `filehelper -> File Transfer`
- `weixin -> WeChat Team`
- `wxid_yfe3gm54e5il12 -> Chase` with alias `zumalabs`
- `wxid_3a40v7q8y4kk12 -> Glenn`
- `wxid_cdxvsfdqlbqw22 -> Adam - Arrow FFAs`
- `wxid_jh7tgf4ggsgs22 -> Heng Chen 陳亨`
- `wxid_shj82mm92ok622 -> Oli`
- `wxid_ulr3oq29ruo312 -> Max Nijhawan` with alias `MNijhawan9`
- `wxid_j6362wqv6yqf22 -> Simon`

Confidence notes:

- all entries above except Max are now backed by either direct live co-occurrence,
  stable row-model slots, or user confirmation
- `wxid_ulr3oq29ruo312 -> Max Nijhawan` remains the weakest single mapping, but
  it is now supported by:
  - row `12` id slot recovery
  - the deterministic leaf-page label record
  - the earlier focused live memory locality around row `12`

## Interpretation Update: Contacts Vs Conversations

The current evidence now separates into two different structures:

1. Contact-like row model in the Contacts view

- stable username slot at `row + 0x248`
- at least one live nested display-label path via `row + 0xd8`
- this is still the best live candidate for true contact enumeration

2. Mixed session/conversation label cache

- SQLite-like leaf page at `0x18815d916c0`
- contains both person labels and conversation/system entries

Current practical interpretation:

- the row-model path remains the right place to finish true contact enumeration
- the leaf-page cache is still useful for name recovery, but it should be
  treated as a mixed label source until paired with authoritative usernames

## Conversation / Session Recovery

The session-side evidence is now stronger than the pure contact-side evidence
for one immediate use-case: recovering visible conversation ids.

### Recovered Group Chat Ids

Direct packed-record recoveries from the mixed session cache:

- `27208021116@chatroom -> Zuma Internal`
  - packed record contains:
    - chatroom id
    - `Zuma Internal`
    - mmcrhead url
- `27005821674@chatroom -> Zuma Test`
  - packed record contains:
    - chatroom id
    - `Zuma Test`
    - mmcrhead url
- `26055110994@chatroom -> Zuma`
  - packed record contains:
    - chatroom id
    - `Zuma`
    - mmcrhead url

Strong inference:

- `26085711013@chatroom -> Glenn、Simon`
  - this is currently the remaining unmapped visible group-chat id
  - it clusters in the same packed record family as the three direct group
    mappings above
  - `session_item_Glenn、Simon` exists independently in the session label cache
  - after the user clarified conversation priority, this is the best current
    interpretation, but it is still inferential rather than directly labeled in
    the same packed blob

### Session Label Evidence

Recovered session-title strings so far:

- `session_item_Glenn`
- `session_item_Chase`
- `session_item_File Transfer`
- `session_item_Adam - Arrow FFAs`
- `session_item_Heng Chen 陳亨`
- `session_item_Glenn、Simon`
- `session_item_Zuma Internal`
- `session_item_Zuma Test`
- `session_item_Zuma`

Important implication:

- the mixed cache is much more directly useful for visible conversation
  recovery than for canonical contacts
- group-chat ids are already appearing in a packed-record format that looks
  suitable for a first session/conversation enumerator

### Current Best Session/Conversation Id Table

The current session-focused checkpoint is captured in:

- [weixin-4.1.8.29-current-conversation-table.json](/C:/Users/Administrator/Code/puppet-xp/docs/weixin-4.1.8.29-current-conversation-table.json)

Immediate porting takeaway:

- if the product priority is visible conversations and conversation ids, the
  best near-term path is to pivot from the Contacts row-model to the
  session/group packed-record path first
- that path is already yielding real `@chatroom` ids with labels, which is
  closer to an MVP than the current canonical-contact work

## 2026-04-08 Live Conversation Capture Logic

### New Repo-Side Extractor

Added a standalone live extractor:

- [scripts/capture-weixin-conversations.py](/C:/Users/Administrator/Code/puppet-xp/scripts/capture-weixin-conversations.py)

Added a package script:

- `npm run capture:conversations`

Current output target:

- [weixin-4.1.8.29-live-conversations.json](/C:/Users/Administrator/Code/puppet-xp/docs/weixin-4.1.8.29-live-conversations.json)

### Current Extraction Strategy

The extractor attaches to live `Weixin.exe` with Frida and scans anonymous
`rw-` ranges for three patterns:

- ASCII `@chatroom`
- ASCII `wxid_`
- UTF-16LE `session_item_`

It then combines those into a conversation table with these rules:

- chatroom ids come from packed session-record blobs
- direct conversation ids come from `session_item_*` labels plus the recovered
  contact table fallback
- malformed packed-record titles are discarded if they do not match the
  recovered session-label set
- overlapping fake chatroom ids are pruned
- unresolved chatroom titles can be filled from the previously verified
  conversation anchor table as a last-resort fallback

### Current Live Output

Fresh live capture against the running `Weixin.exe` currently yields:

- `26085711013@chatroom -> Glenn、Simon`
- `26055110994@chatroom -> Zuma`
- `27208021116@chatroom -> Zuma Internal`
- `27005821674@chatroom -> Zuma Test`
- `filehelper -> File Transfer`
- `wxid_cdxvsfdqlbqw22 -> Adam - Arrow FFAs`
- `wxid_yfe3gm54e5il12 -> Chase`
- `wxid_3a40v7q8y4kk12 -> Glenn`
- `wxid_jh7tgf4ggsgs22 -> Heng Chen 陳亨`
- `wxid_ulr3oq29ruo312 -> Max Nijhawan`

Persisted artifact:

- [weixin-4.1.8.29-live-conversations.json](/C:/Users/Administrator/Code/puppet-xp/docs/weixin-4.1.8.29-live-conversations.json)

### User Confirmation Update

The user later clarified that the account currently has:

- `10` total conversations
- and they care about the total conversation set, not only the currently
  visible viewport rows

This means the current live extractor output count now matches the real target
count for the account.

Updated interpretation:

- the current conversation capture logic is now good enough for the requested
  MVP of `{ conversation_id, title }`
- it should be treated as a working total-conversation/session enumerator for
  this account
- a future hardening pass can still re-anchor onto the exact native
  session-list owner if we want a cleaner agent implementation than memory-scan
  synthesis

## 2026-04-08 Message Access Findings

### Live Anchor Used

The user sent a fresh outgoing text message in the Glenn direct conversation:

- conversation id: `wxid_3a40v7q8y4kk12`
- conversation title: `Glenn`
- message text: `latest message 20260408`

This was used as a live memory anchor to start the message-side pass.

### Direct Live Message-Text Hit

A targeted live scan for UTF-16 `latest message 20260408` found two hits in the
running `Weixin.exe`.

Important interpretation:

- one hit is clearly UI/style-related noise
- the other hit is a resident data-store/cache hit and is the useful one

Key useful hit:

- message text address: `0x18815d7bec8`
- resident window start in the widened scan: `0x18815d79ec8`

### First Useful Message Metadata Surface

The widened resident window around the real message-text hit surfaced these
ASCII field names:

- `content`
- `createtime`
- `displayname`
- `fromusr`

This is the first strong proof that the live process currently holds message
records or a message-backed store with at least:

- message content
- create time
- display/displayable name
- sender/source user

### Stronger Schema-Like Message Metadata Surface

A separate live Glenn-anchored scan exposed a richer deterministic metadata
surface in a SQLite/WCDB-like resident block. The recovered field names include:

- `message_content`
- `create_time`
- `user_name`
- `real_sender_id`
- `local_id`
- `server_id`
- `server_seq`
- `timestamp`
- `source`
- `origin_source`
- `compress_content`
- `packed_info_data`
- `is_session`
- `status`
- `local_type`

Other nearby storage-related tokens:

- `sqlite_master`
- `sqlite_sequence`
- `rowid`
- `BLOB`
- `TEXT`
- `tableName`
- `DeleteInfo`
- `DeleteResInfo`

Current interpretation:

- the message-side data is real and substantially richer than the current
  conversation MVP
- the live process appears to expose a message store/cache whose schema already
  tells us most of the high-value metadata fields we will want

### Important Separation

The Glenn contact/session owner block and the exact message-text block do **not**
currently co-locate in one simple scan window.

Observed behavior:

- scanning around `wxid_3a40v7q8y4kk12` finds strong contact/session-owner data
- scanning around the exact message text finds the message/data-store block
- the latest message text does not currently show up in the Glenn-id windows

Interpretation:

- the usable message path is likely not the same object family as the simple
  contact/session caches already used for conversation enumeration
- for implementation, we will probably need either:
  - the real session last-message helper path (`GetAllSessionLastMessageMap`)
  - or a direct message-store iterator/query path

### Best Current Message-Side Conclusion

We do **not** yet have a clean parser that returns message rows for a given
conversation id.

But we have now verified three crucial facts:

1. the exact outgoing message text is reachable live in memory
2. message metadata fields such as sender and create time are present in the
   same overall storage system
3. there is a richer SQLite/WCDB-like schema surface for messages than we had
   previously documented

### Next Practical Direction

The best next message-side step is to pivot from pure scanning to one of these
two native paths:

1. re-anchor and validate `GetAllSessionLastMessageMap` so we can recover the
   latest message preview/metadata per conversation
2. identify the real message-store iterator/query object behind the live
   `message_content` / `user_name` / `create_time` schema block

### Glenn Historical Message Anchor: `howdy`

The user provided an older Glenn direct-message text anchor:

- talker: `wxid_3a40v7q8y4kk12`
- title: `Glenn`
- older message text: `howdy`

A live scan of the running `Weixin.exe` found **two** resident `howdy` hits.

The stronger hit is in a Glenn-adjacent region:

- Glenn id hit: `0x18816a13e30`
- nearby `howdy` hit: `0x18816a14040`
- second nearby `howdy` copy: `0x18816a14580`

Important interpretation:

- the user confirmed there is only **one logical `howdy` message**, so these two
  hits are duplicate in-memory copies of the same message, not two distinct
  `howdy` messages
- this is still stronger than the latest-message-only anchor because it shows an
  older Glenn message still resident in memory
- the `wxid_3a40v7q8y4kk12` id and `howdy` co-reside in the same live region,
  which is good evidence that the process currently holds more than just a
  single latest-message preview for Glenn
- this still does **not** prove full-history enumeration, but it does prove
  that at least one older Glenn message is present in reachable live memory

### Glenn Historical Message Anchor: `test123`

The user provided the next Glenn message after `howdy`:

- talker: `wxid_3a40v7q8y4kk12`
- title: `Glenn`
- message text: `test123`

A live scan found **two** resident `test123` hits:

- `0x188172d78d0`
- `0x18819f611e8`

Current interpretation:

- `test123` is resident in memory, so it is another valid Glenn-history anchor
- unlike `howdy`, the recovered `test123` copies do **not** currently co-locate
  with the previously identified Glenn-adjacent region around
  `0x18816a13e30 .. 0x18816a15618`
- this suggests the process is holding message text in multiple layers/copies
  rather than a single simple per-conversation contiguous string blob
- in practice, that strengthens the case that we need the real native query
  object / iterator instead of relying on spatial string correlation alone

### First Verified Native Message Iterator Hit

The dedicated `FUN_1813ff7c0` iterator monitor eventually fired and produced a
real native message vector.

Important live result:

- query object: `0x18817367868`
- vector begin: `0x1881a307260`
- vector end: `0x1881a307780`
- row count: `2`
- parsed row size: `0x290`

Recovered rows:

1. row `0x1881a307260`
   - sender / user field (`+0x18`): `wxid_yfe3gm54e5il12`
   - talker / conversation field (`+0x38`): `27208021116@chatroom`
   - secondary sender field (`+0x58`): `wxid_yfe3gm54e5il12`
   - message body (`+0x180`): `test456`
   - candidate create-time field (`+0x124`): `1774899720`
     - UTC: `2026-03-30 19:42:00`
     - London: `2026-03-30 20:42:00 +01:00`

2. row `0x1881a3074f0`
   - sender / user field (`+0x18`): `wxid_yfe3gm54e5il12`
   - talker / conversation field (`+0x38`): `27208021116@chatroom`
   - secondary sender field (`+0x58`): `wxid_yfe3gm54e5il12`
   - message body (`+0x180`): `yo yo`
   - candidate create-time field (`+0x124`): `1774886757`
     - UTC: `2026-03-30 16:05:57`
     - London: `2026-03-30 17:05:57 +01:00`

High-confidence interpretation:

- `FUN_1813ff7c0` is a real native message iterator / materializer
- the parsed message row struct exposes at least:
  - talker / conversation id at `+0x38`
  - message content at `+0x180`
  - sender/self-like fields at `+0x18` and `+0x58`
  - candidate create time at `+0x124`
- for the recovered `Zuma Internal` rows, both `+0x18` and `+0x58` equal the
  already verified self id `wxid_yfe3gm54e5il12`, so the current best
  interpretation is that `yo yo` and `test456` were sent by the logged-in self
  account (`Chase` / alias `zumalabs`)
- `yo yo` was **not** found by a broad string scan while Glenn was selected, but
  it **was** recovered by the native iterator path, which is exactly the kind of
  distinction we were looking for

### Full Glenn Conversation Recovery From Native Iterator

After switching back into the Glenn direct conversation, the same native
iterator path (`FUN_1813ff7c0`) produced Glenn-specific message vectors.

The recovered row layout remained consistent:

- sender / user field: `+0x18`
- talker / conversation id: `+0x38`
- secondary sender-like field: `+0x58`
- optional msgsource XML: `+0x140`
- message body: `+0x180`
- candidate create time: `+0x124`

Recovered Glenn conversation id:

- `wxid_3a40v7q8y4kk12`

Recovered Glenn history, oldest to newest:

1. `2025-11-25 14:40:03 +01:00` — sender `self` — body `test`
2. `2025-11-25 14:41:53 +01:00` — sender `self` — body `test 2`
3. `2025-11-25 14:47:59 +01:00` — sender `self` — body `test 3`
4. `2025-11-25 14:49:27 +01:00` — sender `Glenn` — body `Ack`
5. `2026-03-30 17:05:26 +01:00` — sender `self` — body `test`
6. `2026-03-30 17:05:37 +01:00` — sender `self` — body `howdy`
7. `2026-03-30 20:36:12 +01:00` — sender `self` — body `test123`
8. `2026-03-30 20:42:00 +01:00` — sender `self` — body `test456`
9. `2026-04-08 17:38:18 +01:00` — sender `self` — body `latest message 20260408`
10. `2026-04-08 17:52:18 +01:00` — sender `self` — body `message probe 20260408b`
11. `2026-04-08 17:58:51 +01:00` — sender `self` — body `message probe 20260408c`

Sender interpretation:

- rows where `+0x18` and `+0x58` equal `wxid_yfe3gm54e5il12` are currently
  interpreted as `self`
- the recovered `Ack` row has `+0x18` and `+0x58` equal
  `wxid_3a40v7q8y4kk12`, so it is currently interpreted as sent by `Glenn`

Current significance:

- we now have a verified native message iterator that can return structured
  message rows including conversation id, sender identity, message body, and
  timestamp
- this is no longer just heuristic memory scraping; it is useful native
  extraction evidence for the eventual `4.1.8.29` port

### All-Messages Retrieval Strategy

The current Glenn/Zuma Internal wins are **not** yet the final goal. They prove
that the native message-row iterator exists and that the row layout is usable,
but they do not yet give an app-wide message dump by themselves.

Current best model:

1. there is a native conversation/session enumeration path
2. there is a native per-conversation message iterator / materializer
3. the missing link is direct control of the query object / paging path so we
   can invoke the iterator for any talker without relying on whichever
   conversation the UI has already loaded

Practical end-state design:

1. enumerate all conversations
   - use the existing conversation recovery path to get all talker ids
   - this gives the set of per-conversation keys to query

2. build a per-conversation message query object
   - target the `FUN_1813ff7c0` family and its wrappers
   - recover which query-object fields hold:
     - target talker id
     - page size / range size
     - cursor / offset / window
     - filter flags

3. iterate until exhaustion
   - call the per-conversation iterator repeatedly
   - use `local_id`, `server_id`, `server_seq`, or row-count exhaustion as the
     stopping condition

4. normalize rows into a stable exported schema
   - talker id
   - sender id
   - create time
   - body
   - local/server ids
   - message type / status
   - optional source/msgsource metadata

5. aggregate across all conversations
   - flatten all per-conversation pages into a global message list
   - dedupe by `server_id` / `local_id`

High-value functions for the next pass:

- `FUN_1813ff7c0`
  - confirmed message iterator / row materializer
- `FUN_181405470`
  - higher-level wrapper around the same iterator family
- `FUN_181411990`
  - another higher-level wrapper that appears to manage larger/batched flows
- `FUN_181403030`
  - helper that appears to build query/model state from parameters including
    range-like values
- `FUN_181404a00`
  - vector merge/insert helper for `0x290` message rows
- `FUN_1809aee00`
  - canonical message schema builder

Concrete next RE objective:

- identify the exact query-object layout passed into the `FUN_1813ff7c0` family
  so we can set the talker id and paging controls ourselves
- once that is pinned, the path to “all conversations -> all messages” becomes
  implementation work rather than ad hoc live observation

### Query-Object Layout Progress

The `FUN_1813ff7c0` query object is now less opaque than it was earlier.

Strongly supported by combined live capture plus decompilation:

- `param_1[0]`
  - pointer to the talker-id string object, not an inline string in the query
    struct itself
  - live `iter_enter_layout` capture for Glenn showed:
    - query object `0x18814318cc8`
    - slot `+0x0` -> pointer `0x1881705b308`
    - that pointed object decodes cleanly as `wxid_3a40v7q8y4kk12`
- `param_1[1]`
  - service / db / manager context used by `FUN_180e15710(param_1[1], ...)`
- `param_1[2]`
  - mode / kind byte or small enum used when building the schema-backed query
- `param_1[3]`
  - optional filter or range object
  - only used if `*(int *)param_1[3] != 0`
  - fed to `FUN_180e16fa0(..., param_1[3], 1)` and then folded into the query
- `param_1[4]`
  - another optional range / filter list
  - treated as an iterable pair/range and folded via `FUN_1813d1570`
- `param_1[5]`
  - additional filter set passed through `FUN_180e16fa0(local_938, param_1[5], 1)`
- `param_1[6]`
  - cancellation / stop flag pointer
  - inside the iterator loop:
    - `if (*(byte **)puVar18[6] != 0 && (**(byte **)puVar18[6] & 1) != 0) break;`
- `param_1[7]`
  - destination vector for `0x290` message rows
  - the iterator appends rows by reading the vector at `puVar18[7]`
  - this matches the live monitor result that the row vector is effectively at
    query-object offset `+0x38`

Live Glenn query-layout capture (`queryObj = 0x18814318cc8`) also confirmed:

- `+0x38`
  - is the output vector pointer
  - the pointed vector-like triple looked like:
    - begin `0x1881a386260`
    - end `0x1881a386260`
    - cap `0x1881a38af40`
  - at function entry it was empty, which is consistent with the iterator
    filling it during execution
- `+0x48`
  - value `0` on the fresh Glenn entry
- `+0x50`
  - opaque packed scalar, still unresolved
- `+0x58`
  - context / vtable-ish pointer into module memory
- `+0x60`
  - `0` on the fresh Glenn entry

### Wrapper Layout Progress

`FUN_181405470` appears to be a higher-level message-query wrapper with a
larger control object than the raw `FUN_1813ff7c0` iterator.

Useful field hints from the decomp:

- wrapper object `local_80[10]`
  - destination vector for message rows
  - later merged via `FUN_181404a00(local_80[10], *(undefined8 *)(local_80[10] + 8), ...)`
- wrapper object `local_80[5]` and `local_80[6]`
  - numeric range controls when `*local_80[4] == 0`
  - used like:
    - `uVar2 = *(uint *)local_80[5]`
    - `uVar13 = *(uint *)local_80[6]`
    - converted into `start = min(uVar2, uVar13) * 1000`
    - `end = (max(uVar2, uVar13) + 1) * 1000 - 1`
  - this strongly suggests a bounded numeric window rather than a simple bool
- wrapper object `local_80[9]`
  - another optional filter set passed to `FUN_180e16fa0`

Current interpretation:

- `FUN_1813ff7c0` is still the canonical row materializer
- but directly calling it is not enough yet because the richer query / cursor /
  cancellation state normally comes from the wrapper path
- the redirect / hijack strategy remains promising because it can reuse the
  live wrapper-built query state on the correct thread

### Redirect Attempt Status

A first in-flight talker-redirection probe was built:

- script:
  - `scripts/redirect-weixin-message-query.py`
- goal:
  - wait for a real Glenn iterator call
  - replace the talker string object in-place with another conversation id
  - capture returned rows from the same live iterator call

Status:

- the redirector stayed attached and healthy
- a single Glenn click after arming it did **not** produce a fresh iterator
  event, so there was nothing to rewrite on that attempt
- this does **not** invalidate the redirect idea; it just means the last UI
  action did not force a new query on the monitored path

### Clean-Restart Redirect Result

After restarting Weixin cleanly and reattaching only:

- `scripts/monitor-weixin-message-iterator.py`
- `scripts/redirect-weixin-message-query.py`

the in-flight redirect finally fired on a real live Glenn query.

Verified redirect event:

- source talker: `wxid_3a40v7q8y4kk12` (Glenn)
- target talker: `wxid_cdxvsfdqlbqw22` (Adam - Arrow FFAs)
- redirect log:
  - `queryObj = 0x1ea952d4028`
  - `dbCtx = 0x6360afe7f0`
  - `originalTalker = wxid_3a40v7q8y4kk12`
  - `rewrittenTalker = wxid_cdxvsfdqlbqw22`

Result:

- the redirected iterator returned successfully
- but the output vector was empty:
  - `begin == end`
  - `count = 0`

Interpretation:

- rewriting only the top-level talker string object at `param_1[0]` is **not**
  sufficient to query another conversation
- the raw iterator is still honoring additional state from the wrapper-built
  query object, almost certainly one or more of:
  - `param_1[3]`
  - `param_1[4]`
  - `param_1[5]`
  - wrapper-specific range/window state that still corresponds to the original
    Glenn query

Why this matters:

- this is still a useful win
- it proves the redirect mechanism itself works on the correct thread and on a
  live wrapper-built query
- the next task is no longer “can we rewrite a live query?” but “which
  additional query fields also encode the conversation identity or range state?”
### Multi-Slot Redirect Success

The first Glenn -> Adam redirect returning `0` rows is no longer sufficient
evidence that the redirect was incomplete by itself.

Two important corrections landed:

- the user confirmed the Adam conversation currently has **no messages in
  cache**
- the redirector was patched to rewrite **both** known talker copies in the
  live query object:
  - primary talker object at `queryObj + 0x0`
  - nested duplicate talker object at `*(queryObj + 0x20) + 0x18`

Updated script:

- `scripts/redirect-weixin-message-query.py`

New validation run:

- source talker: `wxid_3a40v7q8y4kk12` (Glenn)
- target talker: `27208021116@chatroom` (Zuma Internal)
- live redirected event:
  - `queryObj = 0x1ea96781538`
  - `dbCtx = 0x6360afe7f0`
  - rewrites:
    - `slot0 -> 27208021116@chatroom`
    - `slot20+0x18 -> 27208021116@chatroom`

Redirected result:

- the iterator returned successfully
- the output vector was **non-empty**
- returned rows:
  - `27208021116@chatroom -> test456`
  - `27208021116@chatroom -> yo yo`

Why this is a major step:

- it proves the native iterator can be steered onto a different conversation
  without the UI actually selecting that target conversation
- it proves the second talker copy in the query object matters
- it strongly suggests the remaining blocker to full arbitrary-conversation
  retrieval is not the basic conversation id rewrite anymore, but the range /
  paging state in the wrapper-built query object

Current best interpretation:

- the minimal conversation identity rewrite for `FUN_1813ff7c0` is at least:
  - `queryObj + 0x0`
  - `*(queryObj + 0x20) + 0x18`
- after those two are rewritten, the iterator can return another
  conversation's rows when the surrounding query state is compatible
- the Adam `0`-row result is now plausibly the correct result for an empty or
  not-yet-materialized message window, rather than proof that redirect was
  fundamentally broken

Implication for the all-messages goal:

- we now have the first concrete proof that arbitrary per-conversation message
  retrieval is achievable by hijacking / constructing the right query object
- the next work item is to control the query window / paging fields so we can
  request more than just the currently materialized slice

### Paging Worker Static Findings

I switched the Ghidra MCP analysis calls to explicit `program=Weixin.dll`
queries and pulled the next likely paging worker:

- `FUN_1813f86b0` at `Weixin.dll + 0x13f86b0`

Current best interpretation from the decompilation:

- this is an iterative message-history worker rather than the simple
  materialized-slice iterator
- it initializes:
  - `local_7c = 100`
  - `local_78 = 0xffffffff`
- it repeatedly calls the shared worker:
  - `FUN_1813ef9c0(...)`
- it walks the returned `0x290` message rows and, for matched rows, forwards
  them to:
  - `FUN_1813e1c00(*(param_1 + 0x30), row)`
- it uses a timestamp-like threshold at:
  - `**(uint **)(param_1 + 0x28)`
- it uses a stop/cancel byte at:
  - `**(char **)(param_1 + 0x10)`
- it uses a talker string object at:
  - `param_1 + 0x8`
- it also compares against a second string-like object at:
  - `param_1 + 0x20`

The most important implication is that `FUN_1813f86b0` appears much closer to a
true bounded / iterative history fetch than `FUN_1813ff7c0`. It is therefore
the strongest current lead for moving beyond the currently materialized Glenn
slice and toward full per-conversation history retrieval.

### Wrapper Idle / Iterator Still Active

After the fresh Weixin restart:

- `scripts/redirect-weixin-message-wrapper-query.py` attached successfully to
  `FUN_181411990`
- but simple Glenn scrolling did **not** trigger that wrapper path
- in the same period, `FUN_1813ff7c0` continued to fire repeatedly and returned
  the familiar Glenn slices:
  - a newer `7`-row slice
  - an older `4`-row slice

This is useful even though the wrapper itself stayed idle:

- it means the current UI activity is still being serviced by the iterator
  family
- but the wrapper we guessed is not the live paging driver for this exact
  interaction
- that is why the next probe should target `FUN_1813f86b0` directly instead of
  spending more time on `FUN_181411990`

### Focused Pager Probe Added

New instrumentation script:

- `scripts/probe-weixin-message-pager.py`

What it hooks:

- `FUN_1813f86b0` at `Weixin.dll + 0x13f86b0`
- `FUN_1813e1c00` at `Weixin.dll + 0x13e1c00`

What it records:

- on pager entry:
  - talker from `param_1 + 0x8`
  - secondary string from `param_1 + 0x20`
  - stop flag pointer/value from `param_1 + 0x10`
  - threshold pointer/value from `param_1 + 0x28`
  - context pointer from `param_1 + 0x18`
  - sink object from `param_1 + 0x30`
- on each forwarded row:
  - selected string fields from the row, including:
    - `0x18`
    - `0x28`
    - `0x38`
    - `0x58`
    - `0x140`
    - `0x180`
  - selected integer fields, including:
    - `0x104`
    - `0x108`
    - `0x110`
    - `0x118`
    - `0x120`
    - `0x124`
    - `0x128`
    - `0x134`
    - `0x138`

Current status:

- the probe attached cleanly to the restarted main process:
  - `pager = 0x7ffa413286b0`
  - `sink = 0x7ffa41311c00`
- stdout:
  - `C:\Users\Administrator\AppData\Local\Temp\weixin_message_pager_out.txt`
- stderr:
  - `C:\Users\Administrator\AppData\Local\Temp\weixin_message_pager_err.txt`

The next live check is to scroll Glenn with this focused probe attached and see
whether `FUN_1813f86b0` fires, which rows it forwards through `FUN_1813e1c00`,
and whether the threshold field changes across paging attempts.

### Negative Trigger Results: Pager, Snapshot, and Shared Worker

I ran three focused live probes against the restarted Weixin while Glenn stayed
selected and the user scrolled within the already-loaded 11-message history:

- `scripts/probe-weixin-message-pager.py`
  - hooks `FUN_1813f86b0`
  - result: **no hits**
- `scripts/probe-weixin-message-snapshot-worker.py`
  - hooks `FUN_1813f62e0`
  - result: **no hits**
- `scripts/probe-weixin-message-shared-worker.py`
  - hooks `FUN_1813ef9c0`
  - result: **no hits**

At the same time, the long-running iterator monitor continued to fire and
return the same Glenn slice pair:

- newer Glenn slice: `7` rows
- older Glenn slice: `4` rows

Interpretation:

- once the Glenn conversation is already resident, simple up/down scrolling is
  **not** using the deeper paging worker, the snapshot worker, or the shared
  query worker we expected
- the active path in this state appears to be even closer to the raw iterator /
  materialized-vector replay than previously assumed
- this also means the next promising direction is not “scroll harder in Glenn,”
  but rather:
  - force a genuinely uncached conversation / history path, or
  - trace the construction of the raw iterator query object itself, or
  - locate the owner of the materialized Glenn slice and then generalize from
    that container instead of waiting for workers to fire

This is still useful progress because it rules out three plausible layers for
the already-loaded Glenn scroll path and prevents more time from being spent on
those hooks for this exact UI state.

### Async Message-Load Graph

Static analysis uncovered a cleaner async loader chain on the message side:

- `FUN_1809adb70`
  - allocates a `0x60` work item
  - schedules:
    - worker body `FUN_1809aeb10`
    - cleanup `FUN_1809aeac0`
  - copies request state from `param_2`
  - stores:
    - `work + 0x48 = *(param_2 + 0x20)`
    - `work + 0x50 = retained object`
    - `work + 0x58 = retained object`

- `FUN_1809aeb10`
  - consumes that async work item
  - builds temporary helper objects from `param_1 + 0x28`
  - operates on `*(work + 0x50)` and `*(work + 0x58)`
  - calls `FUN_180030a20(...)` on the embedded request payload

- `FUN_1809c3b20`
  - **confirmed code caller** of `FUN_1809adb70`
  - xref:
    - `0x1809c417d`
  - takes `(param_1, param_2)`
  - updates conversation/controller state and queues async work
  - writes retained state into fields like:
    - `obj + 0x40`
    - `obj + 0x48`
  - calls:
    - `FUN_1809adb70(...)`

- `FUN_1809c77c0`
  - also calls `FUN_1809adb70`
  - xref:
    - `0x1809c786a`
  - looks like a bounded “request more messages” helper:
    - compares requested count with `*(obj + 0xcc)`
    - caps the requested count at `100`
    - stores the chosen count back to `obj + 0xcc`
    - builds a small request object from `*(obj + 0x18) + 0x50`
    - queues the async worker via `FUN_1809adb70(...)`

Current interpretation:

- `FUN_1809c3b20` looks like the broader conversation/session-side loader
- `FUN_1809c77c0` looks like the more explicit “load up to N more” helper
- both ultimately feed the same async worker path through `FUN_1809adb70`

### Negative Live Result: Cached Conversation Switch Still Misses Loader

I attached a focused live probe to:

- `FUN_1809c3b20`
- `FUN_1809c77c0`

and then switched:

- `Glenn -> Zuma Internal -> Glenn`

Result:

- **no hits** on either load entrypoint
- meanwhile the existing raw iterator monitor still showed the familiar cached
  slices for both conversations

Interpretation:

- once these conversations are already materially resident, a normal chat switch
  does **not** hit the async loader chain
- the async load graph is still likely real and valuable, but it probably needs
  a colder trigger:
  - freshly restarted Weixin and first-open of a conversation, or
  - a conversation/history region that is not already resident in the current
    UI state

This is still progress because the message side is no longer just “mysterious
iterator slices”; we now have a concrete async load graph with a likely
`load-more` helper capped at `100`.

### Fresh-Session Glenn Open on Correct UI PID

I corrected an important runtime issue before repeating the cold-load test:

- after restart, multiple `Weixin.exe` helper processes were present
- the real main UI process had window title `WeChat` and PID `12780`
- the probes were updated to accept `--pid` so they could attach to the exact
  UI process instead of a random helper

Updated scripts:

- `scripts/monitor-weixin-message-iterator.py`
- `scripts/probe-weixin-message-load-entrypoints.py`

Fresh-session test:

- attach cold-load entrypoint probe to `PID 12780`
- attach raw iterator monitor to `PID 12780`
- open `Glenn` for the first time in that fresh session
- do not scroll first

Result:

- the load-entrypoint probe still showed **no hits** on:
  - `FUN_1809c77c0`
  - `FUN_1809c3b20`
- the raw iterator fired immediately and returned the familiar Glenn slices:
  - one `7`-row slice
  - one `4`-row slice

Fresh-session iterator output highlights:

- query objects:
  - `0x1728f3d31e8`
  - `0x1728f4716d8`
- the first-open Glenn slice still already contained:
  - `message probe 20260408c`
  - `message probe 20260408b`
  - `latest message 20260408`
  - `test456`
  - `test123`
  - `howdy`
  - `test`
- the paired older slice still contained:
  - `Ack`
  - `test 3`
  - `test 2`
  - `test`

Interpretation:

- even on a fresh session, first-open of Glenn in the main UI process is still
  **not** going through the async load-entrypoint chain we identified
- the app is satisfying the initial Glenn view directly from a resident source
  that already has enough data to build the current materialized slices
- that means the next useful search target is likely **upstream of the iterator
  itself**, in the query-object constructor or in the owner of the resident
  materialized slice, rather than in the later async “load more” worker path

### Iterator Caller Stack Resolved Into Real Request-Builder Chain

The accurate caller trace on the correct main UI PID (`12780`) was resolved in
Ghidra and replaced the raw RVAs with a concrete request-builder chain.

Resolved stack frames:

- `0x1318a28` -> `FUN_181318970`
- `0x30ab74e` -> `FUN_1830ab710`
- `0x1316bb3` -> `FUN_181316a20`
- `0xe15af5` -> `FUN_180e15ab0`
- `0x13b2428` -> `FUN_1813b1b40`
- `0x33c5c0a` -> `FUN_1833c5b00`
- `0x2ab3390` -> `FUN_182ab3360`
- `0x320ae1` -> `FUN_180320a50`
- `0x57efc3` -> `FUN_18057ee90`
- `0x4aeceac` -> `FUN_184aece70`

This is the first useful high-confidence constructor chain above the native
message iterator.

#### `FUN_1833c5b00`: Request Owner / Entry Wrapper

This function owns a request object and forwards its key fields into the real
message builder:

- passes `param_1 + 0x88` as the conversation/talker string to
  `FUN_1813b1b40`
- passes:
  - `*(u32 *)(param_1 + 0x68)` as `param_4`
  - `*(u32 *)(param_1 + 0x60)` as `param_5`
  - `param_1 + 0x70` as `param_6`
  - `param_1 + 0x40` as `param_7`
  - `*(u32 *)(param_1 + 0x38)` as `param_8`
- retains and forwards extra object state from:
  - `param_1 + 0x28`
  - `param_1 + 0x30`
  - `param_1 + 0xc0`
  - `param_1 + 0xb8`
  - `param_1 + 0xa8`

Most importantly, this gives us a stable live hook point where we can log:

- talker id
- requested message count
- direction/mode-like flags
- builder-side cursor/window state

without having to guess from iterator output alone.

#### `FUN_1813b1b40`: `GetMsgListWithDefault...` Builder

This is the real request builder immediately above the async dispatch layer.

Key observations from decompilation:

- it constructs strings containing:
  - `GetMsgListWithDefault`
  - `GetMsgListWithDefault for session`
- it accepts the talker string as `param_3`
- it accepts a count-like value as `param_5`
- it accepts additional query/window state through:
  - `param_4`
  - `param_6`
  - `param_7`
  - `param_9`
- it allocates a `0x50` task object and ultimately dispatches through
  `FUN_180e15ab0(...)`

This is a much better target than the later speculative pager workers because
it is clearly building the session message request, not merely consuming the
result.

#### Async Dispatch Subchain Below the Builder

The builder then flows through:

- `FUN_180e15ab0`
  - thin wrapper over a worker-launch path
- `FUN_181316a20`
  - allocates another `0x50` object, stores the builder state, and dispatches
- `FUN_1830ab710`
  - validation / callback / dispatch gate
- `FUN_181318970`
  - downstream callback-style layer

Interpretation:

- the "all messages" problem is now less about finding the iterator and more
  about learning the exact semantics of the request object that
  `FUN_1833c5b00` and `FUN_1813b1b40` build
- specifically:
  - which field is the requested page size
  - which field encodes direction / anchor / default-window behavior
  - which fields need to be rewritten to query arbitrary conversations and walk
    older ranges until exhaustion

### New Focused Probe Added

Added repo instrumentation script:

- `scripts/probe-weixin-message-request-builder.py`

It hooks:

- `FUN_1833c5b00` (`Weixin.dll + 0x33c5b00`)
- `FUN_1813b1b40` (`Weixin.dll + 0x13b1b40`)

and logs:

- talker id
- request count from `obj + 0x60`
- mode/flag from `obj + 0x68`
- selected builder fields from the request owner object
- builder arguments at the `GetMsgListWithDefault...` layer
- accurate backtraces

This should be the fastest path to turning the current per-conversation
message retrieval into a controlled "all messages for this conversation" query,
and then into an app-wide conversation-by-conversation crawler.

### Builder Probe Results: Glenn vs Zuma Internal

The focused request-builder probe on the main UI process (`PID 12780`) fired
cleanly during a `Zuma Internal -> Glenn` switch.

Observed request-owner objects (`FUN_1833c5b00`) and builder args
(`FUN_1813b1b40`):

#### Zuma Internal

Two request-owner objects were observed:

- owner `0x17285d50880`
  - talker: `27208021116@chatroom`
  - `flags38 = 0xffffffff`
  - `count60 = 30`
  - `mode68 = 0`
  - `sharedC0 = 0x172867ec870`
  - `region70 + 0x18 = 0x172915e3bd0`
  - `region70 + 0x28 = 0x14`
- owner `0x1728dbe8da0`
  - talker: `27208021116@chatroom`
  - `flags38 = 0xffffffff`
  - `count60 = 28`
  - `mode68 = 0`
  - `sharedC0 = 0x1728e115790`
  - `region70 + 0x18 = 0x172875a36b0`
  - `region70 + 0x28 = 0x14`

Matching builder args:

- `param3` talker: `27208021116@chatroom`
- `param4 = 0`
- `param5 = 30` or `28`
- `param6 + 0x18` matches the request-owner `region70 + 0x18` pointer
- `param6 + 0x28 = 0x14`
- `param7` string empty
- `param8 = 0xffffffff`
- `param9 = 0x60f38ff040`

#### Glenn

Two request-owner objects were observed:

- owner `0x17285d50880`
  - talker: `wxid_3a40v7q8y4kk12`
  - `flags38 = 0xffffffff`
  - `count60 = 30`
  - `mode68 = 0`
  - `sharedC0 = 0x1728eacc7c0`
  - `region70 + 0x18 = 0x172915e3a20`
  - `region70 + 0x28 = 0x13`
- owner `0x172861f22c0`
  - talker: `wxid_3a40v7q8y4kk12`
  - `flags38 = 0xffffffff`
  - `count60 = 23`
  - `mode68 = 0`
  - `sharedC0 = 0x1728d96e730`
  - `region70 + 0x18 = 0x17291bbf9a0`
  - `region70 + 0x28 = 0x13`

Matching builder args:

- `param3` talker: `wxid_3a40v7q8y4kk12`
- `param4 = 0`
- `param5 = 30` or `23`
- `param6 + 0x18` matches the request-owner `region70 + 0x18` pointer
- `param6 + 0x28 = 0x13`
- `param7` string empty
- `param8 = 0xffffffff`
- `param9 = 0x60f38ff040`

#### Correlated Iterator Result

The same trigger produced the expected iterator results:

- Zuma Internal still returned exactly `2` rows
- Glenn still returned exactly `7 + 4` rows

Interpretation:

- `count60` / builder `param5` is a request limit or window target, not the
  final returned row count
- `param6 + 0x28` is now a strong conversation-kind discriminator:
  - `0x13` for direct chat
  - `0x14` for chatroom
- `param6 + 0x18` is conversation-specific query/window state and is likely one
  of the fields that must be controlled to page arbitrary history
- `param7` is not carrying the talker string here
- `param8` appears fixed at `0xffffffff` in these normal UI requests

This is enough to move the next phase from guesswork to controlled experiments:
rewrite `param3` talker plus the `param6` conversation-kind/window fields at the
builder layer, then test whether changing `param5` can expand the materialized
message window beyond the currently resident slice.

### Breakthrough: Zuma Internal Now Returns a 30-Row Native Slice

After additional recent messages were added to `Zuma Internal` and the convo was
actively exercised in the UI, the same native iterator path finally returned a
full 30-row slice instead of the earlier 2-row historical cache.

Observed iterator results for `27208021116@chatroom`:

- earlier steady-state result:
  - `count = 2`
  - rows: `test456`, `yo yo`
- new result after the conversation was exercised with many new messages:
  - `count = 30`
  - newest rows include:
    - `probe store 40`
    - `probe store 39`
    - `probe store 38`
    - `probe store 37`
    - `probe store 36`
    - `probe store 35`
    - `probe store 34`
    - `probe store 33`

Two corresponding iterator query objects were observed for the 30-row slice:

- `0x1728d263af8`
  - `slot0` / `slot20+0x18` talker: `27208021116@chatroom`
  - `+0x8 = 0x1728d9d54e0`
  - `+0x38 = 0x60f38ff0d0`
  - `+0x48 = 0xe228a`
- `0x172868305a8`
  - `slot0` / `slot20+0x18` talker: `27208021116@chatroom`
  - `+0x8 = 0x1728d9d54e0`
  - `+0x38 = 0x60f38ff0d0`
  - `+0x48 = 0x0`

Matching builder-layer request-owner objects:

- owner `0x1728dbe9280`
  - talker: `27208021116@chatroom`
  - `count60 = 30`
  - `mode68 = 0`
  - `region70 + 0x18 = 0x1728eef6060`
  - `region70 + 0x28 = 0x14`
- owner `0x1728f4e9b60`
  - talker: `27208021116@chatroom`
  - `count60 = 30`
  - `mode68 = 0`
  - `region70 + 0x18 = 0x17291bc7590`
  - `region70 + 0x28 = 0x14`

Interpretation:

- the native path is now proven capable of returning at least a 30-message local
  slice for a conversation
- the earlier 2-row Zuma result was not a hard limit of the iterator; it was a
  product of conversation window/state
- `count60 / param5 = 30` appears to be a real active request window size when
  the conversation state is warm enough to expose the newer local history
- the conversation-specific state at `param6 + 0x18` still changes between runs
  and remains the strongest candidate for the anchor/cursor that controls which
  30-row slice is materialized

Most important practical conclusion:

- we now have a solid local-message retrieval primitive for a selected
  conversation that can return a meaningful page (`30` rows) of structured
  message metadata
- the remaining step to "all local messages" is to learn how to advance or
  rewrite the conversation-specific window/cursor state so we can fetch the next
  older page, then repeat until exhaustion

### Zuma Internal History Shape Confirmed By UI

User verified on 2026-04-08 that, after scrolling back through `Zuma Internal`, there are only
`2` messages older than the `probe store xx` series:

- `yo yo`
- `test456`

Interpretation:

- the local `Zuma Internal` history currently appears to be the `probe store ...`
  batch plus exactly those two older messages
- this matches the earlier native iterator evidence where the oldest previously
  visible slice for `27208021116@chatroom` consisted of exactly:
  - `test456`
  - `yo yo`
- the `30`-row native page we captured is therefore likely a newest-page slice of
  a conversation whose remaining older tail is very small

Practical consequence:

- for `Zuma Internal`, the local message store is now bounded enough that we can
  treat the conversation as a near-complete paging test case
- the remaining technical work is less about proving deep history exists, and more
  about forcing or reading the older tail page programmatically so we can iterate
  arbitrary conversations without UI help

### Breakthrough: Forced Builder Count Retrieves Full Local Zuma Internal History

On 2026-04-08, a new active probe `scripts/force-weixin-message-count.py` forced the
builder-layer request count from the normal UI value (`30`) to `100` for
`27208021116@chatroom` (`Zuma Internal`).

Result:

- the native iterator returned `45` rows in a single response
- this is no longer the truncated newest-page slice; it contains the full local
  conversation history currently present for this chat

Observed forced query details:

- talker: `27208021116@chatroom`
- original builder count: `30`
- forced builder count: `100`
- iterator query object: `0x17291b60518`
- query object `+0x48`: `416403157048`
- vector count returned: `45`

The returned `45` rows include:

- `probe store 40` down through `probe store 1`
- one bare `probe store` row
- system rows:
  - `You removed "Oli" from the group chat`
  - `You removed "Glenn" from the group chat`
- older tail rows:
  - `test456`
  - `yo yo`

This is the first proof that the message-retrieval bottleneck is not a hard
iterator limit. The builder request size is an effective control surface, and
raising it can expand a selected conversation from the normal UI window (`30`)
into the full currently available local history (`45` here).

Practical conclusion:

- we now have a working native primitive to retrieve all locally available
  messages for a selected conversation, at least when the full local history is
  smaller than the forced request cap
- the next step is to combine this with conversation targeting so the same
  forced-count retrieval can be applied to arbitrary conversation IDs, not only
  the one currently selected in the UI

### Breakthrough: Arbitrary-Conversation Full Local Retrieval Via Redirect + Forced Count

On 2026-04-08, `scripts/redirect-force-weixin-message-query.py` successfully
combined two controls in one live query:

- builder-layer request count force: `30 -> 100`
- iterator-layer talker rewrite:
  - source UI talker: `wxid_3a40v7q8y4kk12` (`Glenn`)
  - target talker: `27208021116@chatroom` (`Zuma Internal`)

Verified live result:

- Weixin built a normal Glenn query
- the builder hook forced the request size to `100`
- the iterator hook rewrote both talker copies in the query object to
  `27208021116@chatroom`
- the iterator returned `45` Zuma Internal rows, not Glenn rows

Concrete observed query object:

- query object: `0x17295383fc8`
- rewrites applied:
  - `slot0 -> 27208021116@chatroom`
  - `slot20+0x18 -> 27208021116@chatroom`
- query object `+0x48_u64 = 8589934596`
- vector count returned: `45`

Returned row set included:

- `probe store 40` down through `probe store 1`
- one bare `probe store`
- system rows:
  - `You removed "Oli" from the group chat`
  - `You removed "Glenn" from the group chat`
- older tail rows:
  - `test456`
  - `yo yo`

Interpretation:

- message retrieval is no longer bound to the currently selected conversation
- a selected source conversation can be used as a carrier request, then redirected
  in-flight to an arbitrary known target conversation id
- with the count forced high enough, the target conversation can yield its full
  currently available local history in one native call when the history size is
  below the forced cap

This is the strongest message-store result so far because it demonstrates the
practical primitive we need for app-wide crawling:

1. enumerate conversations
2. trigger or synthesize a carrier request
3. redirect the talker to the target conversation id
4. raise the request count
5. collect structured native message rows

### System Message Rows Are Real First-Class Message Records

The redirected `Zuma Internal` full-history retrieval also confirmed that system
events are present in the same native message row stream as user-authored
messages.

Verified examples:

- `You removed "Oli" from the group chat`
- `You removed "Glenn" from the group chat`

These are not probe artifacts or UI-only notifications. They came back as
normal `0x290` iterator rows with their own timestamps and metadata, which means
the eventual extractor should treat system rows as part of the canonical local
message store and classify/filter them at a higher layer if needed.

Current field-level interpretation from the verified `Zuma Internal` system rows:

- content at `+0x180` is the human-readable system event text
- timestamp at `+0x124` is still populated normally
- the string layout differs from a normal user-authored group message:
  - normal self-authored group rows:
    - `+0x18 = wxid_yfe3gm54e5il12`
    - `+0x38 = 27208021116@chatroom`
    - `+0x58 = wxid_yfe3gm54e5il12`
  - system rows:
    - `+0x18 = 27208021116@chatroom`
    - `+0x38 = wxid_yfe3gm54e5il12`
    - `+0x58` absent
- integer fields also shift into a distinct signature:
  - normal text rows in this chat:
    - `+0x120 = 1`
    - `+0x128 = 2` or `3`
    - `+0x138 = 1` or `10`
    - `+0x1c0 = 1`
    - `+0x1c4 = 2`
  - verified system rows:
    - `+0x120 = 4`
    - `+0x128 = 4`
    - `+0x138 = 2`
    - `+0x1c0 = 2`
    - `+0x1c4 = 1`

So the current best interpretation is:

- actor/sender is still you (`wxid_yfe3gm54e5il12` / Chase), because the event
  text itself says `You removed ...` and `+0x38` holds your self id
- but system rows use a different field convention than ordinary text rows, so
  we should not assume `+0x18/+0x38/+0x58` mean the same thing across all
  message kinds

This signature is now wired into the active probe scripts as a programmatic
classifier:

- [monitor-weixin-message-iterator.py](/C:/Users/Administrator/Code/puppet-xp/scripts/monitor-weixin-message-iterator.py)
- [force-weixin-message-count.py](/C:/Users/Administrator/Code/puppet-xp/scripts/force-weixin-message-count.py)
- [redirect-force-weixin-message-query.py](/C:/Users/Administrator/Code/puppet-xp/scripts/redirect-force-weixin-message-query.py)

Each emitted row now carries:

- `message_kind: "system"` when the `4/4/2/2/1` metadata signature matches
- `message_kind: "user"` otherwise
- `system_signature: "4/4/2/2/1"` for matched system rows

### Self Identity And Sent-vs-Received Classification

Current verified self account for the logged-in test user:

- self wxid: `wxid_yfe3gm54e5il12`
- alias: `zumalabs`
- display name: `Chase`

This self identity has been corroborated by:

- live contact/session artifacts
- the local WeChat data path
  - `C:\Users\Administrator\Documents\WeChat Files\wxid_yfe3gm54e5il12`
- multiple message rows where the actor fields line up with user-verified
  self-authored messages

Current programmatic rule for normal user-authored message rows:

- if `message_kind == "user"` and both `+0x18` and `+0x58` equal the self wxid,
  classify the row as `sent_by_self`
- if `message_kind == "user"` and `+0x18` / `+0x58` equal some other wxid,
  classify the row as `received_from_peer`

This rule is already validated against:

- Glenn direct-chat sent rows
- Glenn direct-chat received row `Ack`
- Zuma Internal self-authored group rows

Important caution:

- for direct chats, `+0x38` is not safe to treat as a universal conversation-id
  field across all row directions
- the safest current sender test is based on the actor-like wxid fields
  `+0x18` and `+0x58`, together with the separately known self wxid
- system rows are a separate message kind and should not use the normal
  user-row sender rule

### Canonical Self/Account Manager Path

The new `4.1.8.29` self/account path is now materially pinned and live-verified
from the running `Weixin.exe`, rather than inferred only from contacts,
messages, or filesystem paths.

There appear to be two closely related native paths:

1. login/account context path
2. self snapshot/materialization path

#### 1. Login/Account Context Path

`FUN_180020800` is a thin wrapper over the global manager at `DAT_18a2ffe80`
virtual method `+0x60`. It returns a shared/ref-counted login/account context
object.

Live probe result on PID `12780`:

- shared/context wrapper returned by `FUN_180020800`
- context object pointer: `0x17286835740`
- ref/control pointer: `0x17286835730`

Small accessors on that context are now verified:

- `FUN_180303e80(ctx)` -> `ctx + 0x508`
  - current value: `1`
  - interpreted as `issyncrecord`
- `FUN_180303ea0(ctx)` -> `ctx + 0x50c == 1`
  - current value: `true`
  - interpreted as `isautologin`
- `FUN_180303eb0(ctx)` -> `ctx + 0x50c`
  - current value: `1`
  - interpreted as `pc_login_type`
- `FUN_180303ec0(ctx)` -> `ctx + 0x510`
  - current value: `1775678432`
  - interpreted as `login_sid`
- `FUN_180303e70(ctx)` -> `ctx + 0x518`
  - current value: `1775678336`
  - interpreted as login-base timestamp for `difflogintime`

This path is the best current anchor for login state and session/account flags.

#### 2. Self Snapshot / Materialization Path

`FUN_18001f540()` returns the global self/account manager object
`DAT_18a2ffe80`. The helper `FUN_180020aa0(manager, out, 1)` materializes a
self/account snapshot struct from MMKV-backed keys such as:

- `mmkv_key_user_name`
- `mmkv_key_nick_name`
- `mmkv_key_head_img_url`
- `mmkv_key_pc_account_name`
- `mmkv_key_server_id`

The snapshot struct layout is now anchored by the destructor
`FUN_1800232f0`, which frees string slots at these offsets:

- `+0x00`
- `+0x28`
- `+0x48`
- `+0x68`
- `+0x88`
- `+0xA8`
- `+0xD0`

Live probe script:

- [probe-weixin-self-account.py](/C:/Users/Administrator/Code/puppet-xp/scripts/probe-weixin-self-account.py)

Live snapshot output on PID `12780`:

- manager pointer: `0x17286574de0`
- manager vtable: `0x7ffa47cf2908`
- `user_name` at `+0x00` -> `wxid_yfe3gm54e5il12`
- `nick_name` at `+0x28` -> `Chase`
- `pc_account_name` at `+0x88` -> `ZUMA-WINDOWS-VM`
- `head_img_url` at `+0x68` -> empty in this session

Most importantly, the manager's own virtual getter at `vtable + 0x20`, cloned
via `FUN_1800f6cb0`, also returned:

- `account_username` -> `wxid_yfe3gm54e5il12`

So on this build, the canonical self/account manager path gives us the logged-in
self wxid directly, and the manager's own `account_username` value matches the
snapshot `user_name`.

#### Current Practical Rule

For robust sent-vs-received classification on arbitrary logged-in users, the
best current programmatic source of truth is:

- self wxid = `FUN_18001f540()` -> `FUN_180020aa0(manager, out, 1)` -> string
  at snapshot offset `+0x00`

Current verified value:

- self wxid: `wxid_yfe3gm54e5il12`
- display name: `Chase`

This is stronger than the earlier heuristic/corroborated identification because
it comes straight from the live native self/account manager path.

### Vanity ID <-> `wxid` Translation Path

The current best translation path is now much clearer, and it is not the same
thing as the self/account manager path.

#### 1. `Name2Id` Is Real, But It Does Not Return The Final `wxid`

The `Name2Id` side is still important, but the smaller consumer helpers show
that it resolves to a 32-bit value, not directly to a `wxid` string.

Static anchors:

- `FUN_180e15c10`
  - ensures/binds `Name2Id` on the owner object
- `FUN_180e17480`
  - populates the `Name2Id` map from contact/session-backed records
- `FUN_180e19c40`
  - low-level unordered-map insert helper
- `FUN_180e24e30`
  - single-candidate `Name2Id` consumer path
- `FUN_180e202f0`
  - batched `Name2Id` consumer path

Most important correction from decompilation:

- `FUN_180e1ecb0`
  - calls the `Name2Id` consumer path
  - writes the resolved result into a 32-bit destination slot
  - so this looks like `name -> internal contact row id` or similar, not
    `name -> wxid`

So `Name2Id` is likely the first half of translation, not the whole answer.

#### 2. The Canonical `contact` Table Carries Both `username` And `alias`

The decisive static anchor is the `contact` table schema factory
`FUN_180d930a0()`. This object explicitly registers the following fields:

- `username` at `+0x08`
- `local_type` at `+0x04`
- `alias` at `+0x28`
- `encrypt_username` at `+0x48`
- `delete_flag` at `+0x68`
- `verify_flag` at `+0x70`
- `remark` at `+0x78`
- `nick_name` at `+0xD8`
- `big_head_url` at `+0x138`
- `small_head_url` at `+0x158`
- `description` at `+0x1A0`
- `extra_buffer` at `+0x1C8`

This is the strongest current evidence that the canonical bidirectional
translation source is the contact row itself:

- `wxid` side = `username`
- alias / WeChat ID side = `alias`

#### 3. Contact Row Fetch Path

The current best row-fetch family is:

- `FUN_18250a890`
  - large contact row query/paging worker
  - builds a `Contact` query with row projection including:
    - `username`
    - `alias`
    - `encryptUsername`
    - `remark`
    - `nickName`
    - `rowid`
    - head-image fields
- `FUN_182509a40`
  - wrapper around `FUN_18250a890`
- `FUN_180bf9bd0`
  - higher-level pager that repeatedly calls `FUN_182509a40`
  - looks like a full contact-page enumerator with a large page size

Most important implementation conclusion:

- the cleanest robust translation method is probably not a dedicated
  `ResolveAliasToWxid()` function
- instead, enumerate canonical contact rows from the `contact` table and build:
  - `alias -> username`
  - `username -> alias`

That is more robust than relying on message-layer artifacts, and it naturally
extends to also returning `remark`, `nick_name`, avatars, and the other contact
metadata fields.

#### 4. Current Best Practical Plan

At this point the best translation implementation strategy is:

1. use the `contact` table row-fetch path (`FUN_182509a40` /
   `FUN_18250a890` / `FUN_180bf9bd0`)
2. extract both:
   - `username`
   - `alias`
3. treat:
   - `username` as the canonical native messaging identity (`wxid` / builtin /
     `@chatroom`)
   - `alias` as the alias / WeChat ID when present
4. build an in-memory bidirectional lookup map from the fetched contact rows

This is the strongest current answer to “how do we translate aliases and
usernames?” on `4.1.8.29`.

### Direct-Chat Example: Max Nijhawan

A clean single-row direct-chat probe was captured for `Max Nijhawan` after the
user sent `test`.

Verified conversation id:

- `wxid_ulr3oq29ruo312`

Native forced-query result:

- builder target talker: `wxid_ulr3oq29ruo312`
- returned row count: `1`
- row strings:
  - `+0x18 = wxid_yfe3gm54e5il12`
  - `+0x38 = wxid_ulr3oq29ruo312`
  - `+0x58 = wxid_yfe3gm54e5il12`
  - `+0x140 = <msgsource><alnode><fr>1</fr></alnode></msgsource>`
  - `+0x180 = test`
- row ints:
  - `+0x120 = 1`
  - `+0x124 = 1775683742`
  - `+0x128 = 2`
  - `+0x138 = 1`
  - `+0x1c0 = 1`
  - `+0x1c4 = 5`
- classified kind:
  - `message_kind = user`
  - `system_signature = null`

Timestamp conversion for `+0x124 = 1775683742`:

- London: `2026-04-08 22:29:02 +01:00`

Interpretation:

- this row is a normal user-authored direct-chat message
- sender/self fields `+0x18` and `+0x58` both equal the canonical self wxid
  `wxid_yfe3gm54e5il12`
- `+0x38` is the direct-chat conversation id / peer id

### Trusted Contact ID Table Artifact

A repo-local table builder now exists at:

- `scripts/build-weixin-contact-id-table.py`

This script does not attempt fresh heuristic alias recovery. Instead, it builds a
trusted account-local ID table from the already validated recovered contact
artifact:

- source: `docs/weixin-4.1.8.29-current-contact-table.json`
- output: `docs/weixin-4.1.8.29-contact-id-table.json`

The output includes:

- every recovered contact/builtin row
- `username`
- `username_kind`
- `name`
- `alias` when confirmed
- bidirectional maps:
  - `alias_to_username`
  - `username_to_alias`

Current confirmed alias pairs in this artifact are:

- `zumalabs -> wxid_yfe3gm54e5il12`
- `MNijhawan9 -> wxid_ulr3oq29ruo312`

This is the safest current translation table to use until the canonical contact
row fetch path (`FUN_182509a40` / `FUN_18250a890` / `FUN_180bf9bd0`) is wired
up directly in code.

### Live Message Event Probes

Two repo-local event probes now exist:

- `scripts/monitor-weixin-message-events.py`
- `scripts/monitor-weixin-receive-events.py`

Current live result on `4.1.8.29`:

- `monitor-weixin-message-events.py` hooks the materialized message iterator
  `FUN_1813ff7c0`
- `monitor-weixin-receive-events.py` hooks the msgsource/message-object parse
  path `FUN_1809b17c0` (`parseIfNeeded`) and `FUN_18212a5c0` (`parseCore`)
- both probes successfully classify:
  - `conversation_id`
  - `sender_username`
  - `direction` (`sent` / `received`)
  - `message_kind` (`user` / `system`)
  - `timestamp`
  - `content`
  - `msgsource`

Live verified send example:

- `filehelper`
  - sender: `wxid_yfe3gm54e5il12`
  - direction: `sent`
  - content: `hello`
  - timestamp: `1775688145`

Live verified group send example:

- `27208021116@chatroom` (`Zuma Internal`)
  - sender: `wxid_yfe3gm54e5il12`
  - direction: `sent`
  - content: `send test 1`
  - timestamp: `1775688379`

Important current limitation:

- these probes fire when Weixin materializes or reparses message objects, not
  yet at the precise earliest manager-signal edge
- so they already support practical event-like emission, but they can replay
  older resident rows on conversation refresh and are not yet the final minimal
  "new message only" hook

Practical interpretation:

- `parseIfNeeded` is currently the strongest live event-adjacent hook
- `FUN_1813ff7c0` is currently the strongest live structured-row hook
- the next step for a cleaner production event stream is to join one of these
  to the true manager-signal layer around `FUN_18155e440` so we only emit
  genuinely new rows instead of full replayed slices

## 2026-04-09 Manager-layer event hook checkpoint

We moved off the replay-heavy query/row-transform family and attached directly to
the `MessageManager` subscriber callback chain discovered from `FUN_18155e440`:

- batch callback: `FUN_18154fb60`
- single-item callback: `FUN_18154c6e0`
- downstream dispatch: `FUN_18154bb80`

Live probe script:

- [scripts/monitor-weixin-manager-message-hook.py](/C:/Users/Administrator/Code/puppet-xp/scripts/monitor-weixin-manager-message-hook.py)

Live result from a fresh unique send (`manager hook 1`):

- only `dispatch_callback` fired
- `batch_callback` did **not** emit a replayed `0x140` row range
- `single_callback` did **not** emit a replayed item scan
- the dispatch layer emitted two compact-object events for the fresh message and
  did **not** replay the whole cached conversation slice

Compact dispatch object observations (`FUN_18154bb80` `param_2`):

- `+0x00` -> conversation id
  - verified example: `27208021116@chatroom`
- `+0x48` -> content
  - verified example: `manager hook 1`
- `+0xa8` -> sender username
  - verified example: `wxid_yfe3gm54e5il12`
- `+0x140` -> avatar/head image URL
  - verified example: `https://mmhead.c2c.wechat.com/mmcrhead/...`
- `+0x160` -> conversation title
  - verified example: `Zuma Internal`

This is significantly closer to the old `kDoAddMsg` behavior than the earlier
`parseIfNeeded` / `FUN_181419100` probes, because it produces compact per-message
dispatch objects instead of replaying materialized query slices.

Important caveat:

- the dispatch layer currently emitted the same fresh message twice, with
  different `flag` values (`1` and `1178793217`)
- so this path looks like a real event source, but still needs a duplicate gate
  and a cleaner field map before it can be treated as the final production hook

Follow-up after adding compact-object parsing plus a short duplicate gate:

- fresh unique send `manager hook 2` produced exactly **one** manager-dispatch
  event
- no replayed cached conversation slice appeared behind it
- parsed fields from the compact dispatch object were:
  - `conversation_id = 27208021116@chatroom`
  - `title = Zuma Internal`
  - `sender_username = wxid_yfe3gm54e5il12`
  - `direction = sent`
  - `content = manager hook 2`
  - `avatar_url = https://mmhead.c2c.wechat.com/mmcrhead/...`
- candidate timestamp-like field:
  - compact object `+0x90 = 1775689665`
  - this is in the same numeric range as known message timestamps and should be
    treated as the leading timestamp candidate for this compact event form

Current interpretation:

- `FUN_18154bb80` is now the strongest live candidate for the `4.1.8.29`
  replacement of the old push-style receive/send hook
- unlike `FUN_1813ff7c0`, `FUN_181419100`, or `parseIfNeeded`, this path can
  emit a single fresh message event without replaying the whole cached query
  slice
- the next validation step is to confirm the same path on an actual received
  message and to verify whether the `+0x90` field is always the event timestamp

Current working plan:

- treat `FUN_18154bb80` as the practical event hook for now
- keep a short duplicate gate at this layer because the same fresh logical
  message can be dispatched more than once with different flags
- use the deduped compact dispatch object as the event payload source
- treat `+0x90` as the leading timestamp candidate until disproven
- keep `FUN_18154d4b0` as the analysis path for understanding the compact object
  build step and, longer term, for possibly removing the need for duplicate
  suppression

Why duplicate suppression is currently required:

- before the duplicate gate, a single fresh send produced two
  `dispatch_callback` hits carrying the same logical message content
- the duplicate pair differed by `flag` (`1` vs `1178793217`) but not by the
  user-visible message identity
- this is still much narrower than the replay-heavy query hooks because it is a
  duplicate of one fresh event, not a replay of a whole conversation slice
- after adding the duplicate gate, a fresh send (`manager hook 2`) produced
  exactly one compact event

Current recommended demo script:

- [scripts/monitor-weixin-manager-message-hook.py](/C:/Users/Administrator/Code/puppet-xp/scripts/monitor-weixin-manager-message-hook.py)
- this is the current repo-local demonstration of the working manager hook with
  duplicate suppression applied

Future TODO:

- find a better upstream hook than `FUN_18154bb80` so duplicate suppression is
  no longer necessary
- the two best current leads are:
  - `FUN_18154d4b0`, which builds the compact dispatch object before forwarding
  - the true manager callback registration/subscriber chain rooted at
    `FUN_18155e440`

Related static note:

- `FUN_1817c2c50` is called by `FUN_18154bb80` and forwards only when
  `*(FUN_18007f0f0(param_2) + 0x10) != 0`, then dispatches via the receiver
  vtable slot at `+0x48`
- this reinforces that the manager callback chain is building and forwarding a
  compact message object, not just replaying a query result row

## 2026-04-09 One-step-earlier check

We tested whether a static parent above `FUN_18154d4b0` would be a cleaner
universal hook.

Findings:

- caller tracing from the clean `FUN_18154bb80` event resolved the immediate
  parent to `FUN_18154d4b0`
- static callers of `FUN_18154d4b0` are:
  - `FUN_18154fb60` (known replay/batch path)
  - `FUN_181555210` (targeted/matching path)
- live probe on `FUN_181555210` did **not** fire for a fresh send

Practical conclusion:

- `FUN_181555210` is not a universal fresh-message parent
- `FUN_18154bb80` remains the narrowest reliable live hook pinned so far
- any future move earlier should probe `FUN_18154d4b0` directly rather than
  assuming one of its static callers is the correct universal hook

## 2026-04-09 Send-path checkpoint

Old `3.9.2.23` send path recap from `src/init-agent-script.ts`:

- native send manager getter:
  - `WX_SEND_MESSAGE_MGR_OFFSET = 0x768140`
- native text send:
  - `WX_SEND_TEXT_OFFSET = 0xce6c80`
- old flow:
  - build x86 talker/content structs
  - allocate `ecx` buffer
  - pass talker in `edx`, content on the stack
  - call text-send directly

Live `4.1.8.29` send-side narrowing:

- send-time resolver/caller cluster from dynamic tracing:
  - `FUN_1815e7290`
  - `FUN_1815e8200`
  - `FUN_1815e9960`
  - `FUN_1815766e0`
  - `FUN_181576a40`
  - wrapper family:
    - `FUN_18282fd80`
    - `FUN_182832260`

Strongest send-request builder currently pinned:

- `FUN_1815e8200`
  - allocates a `0xf0` request object
  - fills it through `FUN_1833fc800(...)`
  - then runs it through a short submit pipeline
- live probe on the request builder recovered:
  - request object carries target conversation at `+0x38`
  - verified example:
    - `27208021116@chatroom`

Important follow-up helpers:

- `FUN_1815eb0d0`
  - polymorphic/string extraction helper in the same send chain
  - live probe hit both:
    - one send-path callsite
    - one unrelated UI/error string path (`Unable to send`)
  - not yet a clean raw outgoing-text extractor

Higher wrapper currently pinned:

- `FUN_1815af8e0`
  - resolves service context
  - calls `FUN_1815e9960(..., param_1 + 8, 1)`
  - then copies `param_1 + 0x20` into an async task object via
    `FUN_180038880(...)`

Current top-level send-entry result:

- live probe on `FUN_1815af8e0` fired on a fresh send
- recovered object did **not** expose a plain text string at `+0x20`
- recovered string at `+0x38` looked like a request/task UUID:
  - `ce5a3c71-e048-454b-b2ac-4b595592cbb4`
- recipient vector elements were not plain inline `std::string` objects

Current interpretation:

- `FUN_1815af8e0` is a real top-level text-send wrapper
- `FUN_1815e8200` is a real per-recipient send-request builder
- the outgoing text is still one copy/serialization step away from the builder
  fields we have directly decoded so far

Next send-path target:

- probe the `FUN_180038880(local_48, param_1 + 0x20)` copy inside
  `FUN_1815af8e0`
- this is the strongest current lead for where the human text is copied from the
  top-level send wrapper into the async send task

Follow-up results:

- probing `FUN_180038880` inside `FUN_1815af8e0` showed that this copy does not
  carry the human message body
- on a fresh send it cloned the same UUID-like value from source to destination:
  - `10d0d457-d39d-4d29-ae62-3eeb371d7e40`
- decompilation confirms `FUN_180038880` is a composite-object clone helper, not
  a plain string copy
  - it clones nested virtual subobjects at slots `+0x48`, `+0x88`, `+0xc8`
  - and a refcounted tail object around `+0xe0`
- practical conclusion:
  - `param_1 + 0x20` in `FUN_1815af8e0` is send metadata, not raw text

Runtime caller trace above `FUN_1815af8e0`:

- live backtrace did not reveal a simple direct code wrapper above
  `FUN_1815af8e0`
- stable code frames were:
  - `FUN_180bef600`
  - `FUN_1803e48d0`
  - `FUN_1803e3710`
  - `FUN_182454580`
- `FUN_182454580` is a generic thread worker (`thread_run_`) that invokes a
  task object virtual method, confirming the send path is being entered through
  an async/task trampoline

Current send-path interpretation:

- `FUN_1815af8e0` is still a real top-level send wrapper
- `FUN_1815e9960` is a strong multi-recipient/text-send wrapper beneath it
- `FUN_1815e8200` is a strong per-recipient send-request builder
- the human text has not yet been directly decoded from the top-level async task
  object; it is likely still one object upstream of `FUN_1815af8e0` or inside a
  nested subobject passed through the async task trampoline

Task-payload copy checkpoint:

- probing `FUN_1815affc0` (the payload copy into the async send task) recovered
  a more structured object than the earlier UUID-only wrapper state
- this payload currently looks like:
  - string at `+0x08`: empty
  - vector at `+0x28`: populated
- live fresh-send result from the vector:
  - first element resolves cleanly to the target conversation id
    - `27208021116@chatroom`
  - neighboring elements carry the same UUID-like operation id
    - `85a7bb69-7b5f-4d7b-a5c7-652e3cf920ec`
  - one later element carried the plain string `order`

Current interpretation of `FUN_1815affc0` payload:

- this is the first send-side object we have recovered that clearly contains the
  real target conversation id in a structured vector form
- it still does **not** expose the human outgoing body text directly
- the outgoing text is therefore likely stored in:
  - another sibling field of the same payload object, or
  - a nested object referenced elsewhere in the async task

Async scheduled-task checkpoint:

- probing `FUN_180314950` (task scheduler) finally surfaced a send-task object
  that carries the real outgoing body text together with sender, conversation,
  and `msgsource`
- this is currently the strongest send-side artifact in `4.1.8.29`
- verified live task object example:
  - task ptr:
    - `0x183c31dd210`
  - task strings:
    - `+0x38` -> `wxid_yfe3gm54e5il12`
    - `+0x58` -> `27208021116@chatroom`
    - `+0x78` -> `wxid_yfe3gm54e5il12`
    - `+0x98` -> `27208021116@chatroom`
    - `+0xe0` -> `send sched 1`
    - `+0x100` -> `<msgsource><alnode><fr>1</fr></alnode></msgsource>`
  - nested payload at `task + 0x28`:
    - `+0x10` -> `wxid_yfe3gm54e5il12`
    - `+0x30` -> `27208021116@chatroom`
    - `+0x50` -> `wxid_yfe3gm54e5il12`
    - `+0x70` -> `27208021116@chatroom`
- an earlier scheduler hit on a sibling task object also surfaced body text in a
  nested payload window:
  - `task + 0x110 + 0x00` -> `send deep 1`
  - `task + 0x110 + 0x20` -> `p`
- current interpretation:
  - the scheduled async task object is the first send-side structure we have
    recovered that reliably co-locates:
    - self username
    - target conversation id
    - outgoing body text
    - `msgsource`
  - there are multiple scheduled task objects per send and many are noisy or
    unrelated
  - the remaining send-side job is to identify and filter the specific task
    subtype that represents the real text-send operation

Runnable send-task demo hook:

- script:
  - [scripts/monitor-weixin-send-task-hook.py](/C:/Users/Administrator/Code/puppet-xp/scripts/monitor-weixin-send-task-hook.py)
- package entrypoint:
  - `npm run monitor:send-task`
- current extraction rule:
  - hook `FUN_180314950`
  - filter scheduled tasks down to those that expose:
    - sender username
    - conversation id
    - outgoing body text
  - prefer top-level layout:
    - sender at `+0x38`
    - conversation at `+0x58`
    - body at `+0xe0`
    - `msgsource` at `+0x100`
  - fall back to nested copies:
    - sender/conversation around `task + 0x28`
    - body around `task + 0x110`
- purpose:
  - provide a clean demonstration of the currently best send-side hook candidate
    without the raw scheduler noise from the exploratory probe
- live verification:
  - fresh send `send hook 1` emitted one clean `send_task_event`
  - verified payload:
    - `conversation_id` -> `27208021116@chatroom`
    - `sender_username` -> `wxid_yfe3gm54e5il12`
    - `direction` -> `sent`
    - `content` -> `send hook 1`
    - `msgsource` -> `<msgsource><alnode><fr>1</fr></alnode></msgsource>`
  - in this clean hit, the top-level task layout was sufficient:
    - body at `+0xe0`
    - `msgsource` at `+0x100`
    - sender / conversation pairs at `+0x38/+0x58` and `+0x78/+0x98`
- TODO:
  - further narrow the task subtype so the send-task monitor can rely on one
    stable layout instead of top-level plus nested fallback parsing

## 2026-04-09 Native arbitrary send proof

Key send-side proof from the fresh `Weixin.exe` session:

- top-level wrapper hook:
  - `FUN_1815af8e0`
- verified per-recipient source object under the wrapper:
  - recipient vector at `wrapper + 0x08`
  - first entry `pair.first -> source_obj`
  - source fields:
    - `source_obj + 0xb0` -> target conversation id
    - `source_obj + 0x600` -> per-send UUID-like value
    - `source_obj + 0x660` -> outgoing body text

Live proof capture:

- real seed send built this top-level wrapper:
  - wrapper ptr: `0x25698d62e70`
  - source obj: `0x256975ff000`
  - before:
    - conversation: `27208021116@chatroom`
    - body: `h1`
    - uuid: `25ba6d4f-14f9-4727-81f7-7704071d5906`
- the in-flight hook rewrote only the source object:
  - `+0xb0` from `27208021116@chatroom` to `27208021116@chatroom`
  - `+0x660` from `h1` to `skynet`
- the hook reported:
  - after:
    - conversation: `27208021116@chatroom`
    - body: `skynet`

Independent verification from the fresh send-task monitor on the same PID:

- first task:
  - content: `sed hijack 1`
  - conversation: `27208021116@chatroom`
- second task:
  - content: `skynet`
  - conversation: `27208021116@chatroom`
  - sender: `wxid_yfe3gm54e5il12`
  - direction: `sent`
  - `msgsource`: `<msgsource><alnode><fr>1</fr></alnode></msgsource>`

Interpretation:

- this is the first successful native arbitrary-send proof for `4.1.8.29`
- it did **not** rely on UI-driving the message box
- it worked by hijacking a real top-level send wrapper in flight at
  `FUN_1815af8e0` and rewriting the per-recipient source object before the
  request builder consumed it

Current proof scripts:

- top-level hijack:
  - [scripts/hijack-weixin-top-send.py](/C:/Users/Administrator/Code/puppet-xp/scripts/hijack-weixin-top-send.py)
- top-level wrapper probe:
  - [scripts/probe-weixin-send-top-wrapper.py](/C:/Users/Administrator/Code/puppet-xp/scripts/probe-weixin-send-top-wrapper.py)
- request-source probe:
  - [scripts/probe-weixin-send-request-source.py](/C:/Users/Administrator/Code/puppet-xp/scripts/probe-weixin-send-request-source.py)
- send-task verifier:
  - [scripts/monitor-weixin-send-task-hook.py](/C:/Users/Administrator/Code/puppet-xp/scripts/monitor-weixin-send-task-hook.py)

Important caveat:

- this is still a hijack of a real seed send, not yet a standalone synthetic
  send constructor with no seed message at all
- however, it proves the exact mutable fields that control the final native send
  payload for text messages in `4.1.8.29`

## 2026-04-09 Seed-template clone send

Follow-on experiment after the `skynet` hijack proof:

- script:
  - [scripts/clone-weixin-top-wrapper-send.py](/C:/Users/Administrator/Code/puppet-xp/scripts/clone-weixin-top-wrapper-send.py)
- goal:
  - move beyond in-place hijack by cloning a valid top-level
    `FUN_1815af8e0` wrapper tree from a real seed send
  - rewrite the clone to a target conversation/body
  - invoke `FUN_1815af8e0(cloned_wrapper)` directly

Current clone strategy:

- copy `0x120` bytes of the live top-level wrapper
- copy one `0x10` recipient pair entry
- copy one `0x700` source object
- rewrite only:
  - `source_clone + 0xb0` -> target conversation
  - `source_clone + 0x660` -> target body
- keep the original UUID at `source_clone + 0x600`
- keep the original `pair.second` pointer unchanged

Live test on the fresh UI process:

- trigger body:
  - `c1`
- target:
  - conversation `27208021116@chatroom`
  - body `synthetic1`
- clone hook emitted:
  - `top_wrapper_clone_ready`
  - original wrapper `0x2569dd515a0`
  - cloned wrapper `0x25695f95b80`
  - original source `0x2569df49470`
  - cloned source `0x25698e76720`
  - before:
    - conversation `27208021116@chatroom`
    - body `c1`
    - uuid `76ffff31-cef1-4a5c-92cd-9ba961c898f4`
  - after:
    - conversation `27208021116@chatroom`
    - body `synthetic1`
    - same uuid

Independent verification from the clean send-task monitor:

- [scripts/monitor-weixin-send-task-hook.py](/C:/Users/Administrator/Code/puppet-xp/scripts/monitor-weixin-send-task-hook.py)
- emitted a fresh `send_task_event` with:
  - `conversation_id` -> `27208021116@chatroom`
  - `content` -> `synthetic1`
  - `sender_username` -> `wxid_yfe3gm54e5il12`
  - `direction` -> `sent`
  - `msgsource` -> `<msgsource><alnode><fr>1</fr></alnode></msgsource>`

Critical nuance:

- the clone invocation then faulted with:
  - `Error: access violation accessing 0x0`
- but that fault happened *after* the fresh `synthetic1` send-task event was
  observed
- this means the cloned wrapper path is now good enough to schedule a real send,
  but it is not yet stable for cleanup/follow-on ownership handling

Current interpretation:

- the remaining blocker is no longer "can a cloned valid wrapper produce a new
  send?" because the answer is now yes
- the remaining blocker is a missing cloned-owned side object or refcounted
  companion pointer that is dereferenced later in the send lifecycle
- the most suspicious field is still the unchanged `pair.second` pointer and/or
  wrapper metadata/state outside the copied `source_obj`

Updated send-state summary:

- in-place top-wrapper hijack:
  - proven and stable enough for controlled testing
- seed-template cloned wrapper:
  - proven to schedule a second native send
  - not yet stable due post-schedule access violation
- fully synthetic zero-seed send:
  - not yet achieved

TODO:

- identify which companion object behind `pair.second` or wrapper metadata must
  also be cloned or reconstructed
- determine whether the post-schedule null dereference happens in task cleanup,
  subscriber notification, or send completion bookkeeping

Additional source-object ownership finding from a fresh real send:

- real send source object:
  - `source_obj = owner_base + 0x10`
- live back-pointers inside the source object:
  - `source_obj + 0x08 -> source_obj`
  - `source_obj + 0x10 -> owner_base`
- live owner header refcounts for the tested source:
  - `owner_base + 0x08 = 5`
  - `owner_base + 0x0c = 2`

Implication:

- a relocated clone must not only copy the owner block and source object data
- it must also rebase the embedded self/owner pointers inside the source object
- earlier clone attempts did not keep these internal pointers consistent, which
  is a strong candidate explanation for the post-schedule fault

## 2026-04-09 Stronger synthetic send proof

After rebasing the source object's internal back-pointers in the cloned owned
block:

- `source_clone + 0x08 -> source_clone`
- `source_clone + 0x10 -> owned_clone`

the cloned-wrapper path produced a stronger result on the fresh UI PID `10312`.

Live trigger:

- real seed body:
  - `c3`
- cloned target body:
  - `synthetic3`
- target conversation:
  - `27208021116@chatroom`

Clone hook output:

- `top_wrapper_clone_ready`
  - original wrapper `0x295caeb1d20`
  - cloned wrapper `0x295d22e8800`
  - original source `0x295d21ee7f0`
  - original owner `0x295d21ee7e0`
  - cloned owner `0x295d2033510`
  - cloned source `0x295d2033520`
  - body rewritten from `c3` to `synthetic3`
- the hook still reported:
  - `Error: access violation accessing 0x0`

However, the important runtime proof is stronger than before:

- send-task hook emitted:
  - `content -> c3`
  - `content -> synthetic3`
- manager-dispatch hook also emitted:
  - `content -> c3`
  - `content -> synthetic3`
  - both for:
    - `conversation_id -> 27208021116@chatroom`
    - `title -> Zuma Internal`
    - `sender_username -> wxid_yfe3gm54e5il12`
    - `direction -> sent`

Interpretation:

- `synthetic3` is now proven by the stronger success criterion:
  - not only scheduled as a send task
  - but also observed on the manager-level message dispatch path
- this is the strongest evidence so far that the cloned top-wrapper path can
  produce a real native send without UI textbox driving

Remaining caveat:

- the clone invocation still throws an access-violation error in the hook
- but on this run it did not kill the main Weixin UI process, and the synthetic
  message still propagated through the manager-dispatch hook
- so the current state is:
  - functional synthetic send path: yes
  - stable/clean synthetic send path: not yet

## 2026-04-09 Stronger send success criterion

The scheduler hook alone is not enough to prove a message was truly sent.

Reason:

- [scripts/monitor-weixin-send-task-hook.py](/C:/Users/Administrator/Code/puppet-xp/scripts/monitor-weixin-send-task-hook.py)
  only proves that Weixin scheduled a send task object
- that is useful, but not sufficient to distinguish:
  - a task that is merely constructed/scheduled
  - a message that actually propagates through the message/session dispatch path

Fresh-session verification on UI PID `10312`:

- send-task hook emitted:
  - `conversation_id` -> `27208021116@chatroom`
  - `content` -> `deliver probe 1`
  - `sender_username` -> `wxid_yfe3gm54e5il12`
- manager-dispatch hook simultaneously emitted:
  - `conversation_id` -> `27208021116@chatroom`
  - `title` -> `Zuma Internal`
  - `sender_username` -> `wxid_yfe3gm54e5il12`
  - `direction` -> `sent`
  - `content` -> `deliver probe 1`
  - candidate timestamp field `+0x90` -> `1775717336`

The same manager-dispatch hook also surfaced the earlier native proof send:

- `content` -> `skynet`
- same conversation and sender

Updated rule for future synthetic-send experiments:

- `send_task_event` is necessary but not sufficient
- the stronger proof of success is a matching
  `manager_message_event` from `FUN_18154bb80`
- future send experiments should only be counted as successful when the manager
  dispatch hook confirms the same message content/conversation

## 2026-04-09 Lower-level same-thread synthetic send

After the standalone lower-level sender crashed the process when calling the
`FUN_1815e8200` family out of band, the next experiment moved that same logic
back into the real send thread as a hijack of one live seed send.

New script:

- [scripts/hijack-weixin-lower-send.py](/C:/Users/Administrator/Code/puppet-xp/scripts/hijack-weixin-lower-send.py)

What this path does:

- hook the real top-level send wrapper `FUN_1815af8e0`
- wait for a seed send with a specific trigger body
- clone only the lower-level source owner block and source object, not the full
  top wrapper
- fetch the real global send context through:
  - `FUN_180020800`
  - `FUN_1802fbff0`
  - `FUN_180633270`
- build the per-recipient request directly through:
  - `FUN_1815e8200(..., mode=1)`
- create the task tail with:
  - `FUN_1800f7b40`
  - `FUN_180038880`
  - `FUN_1815affc0`
  - `FUN_180182c10`
  - `FUN_180314950`

Fresh-session live test on UI PID `9116`:

- trigger body:
  - `llseed1`
- synthetic target:
  - conversation `27208021116@chatroom`
  - body `llsynthetic3`

Stage trace from the hook:

- reached:
  - `clone_owner`
  - `clone_source`
  - `rewrite_strings`
  - `build_pair`
  - `get_root`
  - `get_service`
  - `get_send_ctx`
  - `call_builder`
  - `alloc_task`
  - `init_task`
  - `copy_meta`
  - `copy_payload`
- then the hook reported:
  - `Error: system error`
  - at stage `copy_payload`

However, despite that hook-level error, the synthetic send itself propagated:

- send-task hook emitted:
  - `conversation_id -> 27208021116@chatroom`
  - `content -> llsynthetic3`
  - `sender_username -> wxid_yfe3gm54e5il12`
- manager-dispatch hook emitted:
  - `conversation_id -> 27208021116@chatroom`
  - `title -> Zuma Internal`
  - `content -> llsynthetic3`
  - `sender_username -> wxid_yfe3gm54e5il12`
  - `direction -> sent`

The same run also emitted the original seed send:

- `llseed1`

Interpretation:

- this is a stronger synthetic-send path than the full-wrapper clone:
  - it reuses the real send thread/context
  - it avoids cloning the entire top wrapper object graph
- it is now proven that the smaller lower-level path can produce a real native
  send confirmed by both:
  - the scheduler/send-task hook
  - the manager-dispatch hook
- a residual hook-level error still occurs around the payload-copy/scheduling
  tail, but:
  - it did not crash `Weixin.exe`
  - it did not prevent the synthetic send from propagating

Current best send-state summary:

- in-place top-wrapper field hijack:
  - proven
- full top-wrapper clone:
  - proven once, but unstable and crash-prone
- standalone lower-level source-template call:
  - still unsafe/crashy out of band
- lower-level same-thread hijack:
  - proven
  - currently the best synthetic-send technique for `4.1.8.29`

TODO:

- determine why the lower-level same-thread path reports `Error: system error`
  after `copy_payload` even though the message is successfully dispatched
- tighten the hook so it emits only one synthetic event copy
- turn the current Python/Frida prototype into the injected agent send path

Repro confirmation on the same fresh session:

- trigger body:
  - `llseed2`
- synthetic target body:
  - `llsynthetic4`
- same target conversation:
  - `27208021116@chatroom`

Result:

- reached the same stage boundary:
  - through `copy_payload`
  - then reported `Error: system error`
- still produced both proof signals:
  - `send_task_event -> llsynthetic4`
  - `manager_message_event -> llsynthetic4`
- Weixin UI process remained alive after the run

Conclusion:

- the lower-level same-thread hijack is not a one-off
- it has now reproduced on at least two synthetic bodies:
  - `llsynthetic3`
  - `llsynthetic4`
- the remaining `copy_payload`/`system error` issue is a cleanup/stability
  concern, not a blocker for proving native synthetic send capability

Third confirmation on a fresh UI session (`Weixin.exe` PID `10976`):

- trigger body:
  - `llseed3`
- synthetic target body:
  - `llsynthetic5`
- same target conversation:
  - `27208021116@chatroom`

Refined stage tracing now shows the residual fault more precisely:

- the synthetic path reaches:
  - `clone_owner_prepare`
  - `clone_owner_copy`
  - `clone_owner_rebase`
  - `clone_source_locate`
  - `clone_source_fix_backrefs`
  - `rewrite_strings_conversation`
  - `rewrite_strings_body`
  - `build_pair`
  - `get_root_prepare`
  - `get_root_call`
  - `get_service_prepare`
  - `get_service_call`
  - `get_send_ctx_prepare`
  - `get_send_ctx_call`
  - `call_builder_prepare`
  - `call_builder_call`
  - `alloc_task`
  - `init_task_call`
  - `copy_meta_prepare`
  - `copy_meta_call`
  - `copy_payload_call`
- and then throws:
  - `Error: system error`
  - at exactly `copy_payload_call`

Despite that, the synthetic send still propagated and was proven by both hooks:

- `send_task_event -> llsynthetic5`
- `manager_message_event -> llsynthetic5`

New nuance from this run:

- the send-task hook reported the same `task_ptr` for:
  - `llseed3`
  - `llsynthetic5`
- the manager-dispatch hook also reported the same `event_ptr` for:
  - `llseed3`
  - `llsynthetic5`

Interpretation:

- the lower-level same-thread hijack is very likely piggybacking on, mutating,
  or aliasing the same task/event object lineage as the original seed send
- this likely explains why:
  - the synthetic message can propagate successfully
  - while a residual `system error` is still thrown at `copyTaskPayload`
- the next stabilization task is therefore not just "make the error go away"
  but:
  - determine whether a truly independent synthetic task object can be created
  - or whether the current path should be treated as an in-place mutation of the
    live seed task

Fourth confirmation on the same UI session (`Weixin.exe` PID `10976`) changed
that interpretation in an important way.

- trigger body:
  - `llseed4`
- trigger conversation:
  - `filehelper`
- synthetic target body:
  - `llsynthetic6`
- synthetic target conversation:
  - `27208021116@chatroom`

Refined task-pointer instrumentation showed:

- allocated synthetic task object:
  - `0x20cb9c64800`
- actual `send_task_event` for `llsynthetic6`:
  - task pointer `0x20cb96d53b0`
- actual `send_task_event` for seed `llseed4`:
  - task pointer `0x20cb96d5b50`

This means:

- the synthetic send is *not* merely reusing the original seed task pointer
- and it is *not* the same object as the explicitly allocated `taskObj` in the
  current hook either

The same run also shifted the fault boundary:

- this time the hook failed earlier with:
  - `Error: access violation accessing 0xffffffffffffffff`
  - at `copy_meta_call`
- but the synthetic message still propagated and was proven by:
  - `send_task_event -> llsynthetic6`
  - `manager_message_event -> llsynthetic6`

Updated interpretation:

- the lower-level same-thread path is successfully inducing a real synthetic
  send to a different conversation, even when seeded from `filehelper`
- the actual scheduled send task for the synthetic message is being produced
  downstream by Weixin, rather than by directly scheduling our explicit
  `taskObj`
- therefore the currently most valuable part of the path is:
  - the builder invocation and its side effects
  - not the explicit task-allocation/scheduling tail after it

New stabilization direction:

- try trimming or bypassing the explicit tail:
  - `alloc_task`
  - `init_task`
  - `copy_meta`
  - `copy_payload`
  - `init_sched_ctx`
  - `schedule`
- and see whether `FUN_1815e8200(..., mode=1)` on the real send thread is
  already sufficient to cause the downstream synthetic task to be materialized

Builder-only confirmation on the same UI session (`Weixin.exe` PID `10976`):

- trigger body:
  - `llseed5`
- trigger conversation:
  - `filehelper`
- synthetic target body:
  - `llsynthetic7`
- synthetic target conversation:
  - `27208021116@chatroom`

New script mode:

- [scripts/hijack-weixin-lower-send.py](/C:/Users/Administrator/Code/puppet-xp/scripts/hijack-weixin-lower-send.py)
  with:
  - `--builder-only`

What this mode does:

- hook the real top-level send wrapper on the real send thread
- clone and rewrite only the lower-level source owner/source object
- fetch the real global send context
- call:
  - `FUN_1815e8200(sendCtx, resultBuf, pairBuf, 1)`
- stop there
- do *not* run the explicit tail:
  - `alloc_task`
  - `init_task`
  - `copy_meta`
  - `copy_payload`
  - `init_sched_ctx`
  - `schedule`

Result:

- no hook error
- no crash
- synthetic send still propagated and was proven by both hooks:
  - `send_task_event -> llsynthetic7`
  - `manager_message_event -> llsynthetic7`
- seed send also propagated independently:
  - `send_task_event -> llseed5`

Important implication:

- the explicit task-allocation/scheduling tail is not required for the working
  synthetic send path
- the real useful primitive is:
  - builder invocation on the real send thread with a rewritten lower-level
    source object
- the downstream synthetic task is then materialized by Weixin itself

Updated best send-state summary:

- in-place top-wrapper field hijack:
  - proven
- full top-wrapper clone:
  - proven once, but unstable and crash-prone
- lower-level same-thread hijack with explicit tail:
  - proven, but noisy/error-prone
- lower-level same-thread hijack, builder-only:
  - proven
  - cleanest successful synthetic send path so far
  - current best candidate for agent porting

Autonomous send follow-up, fresh-session branch:

- after a fresh WeChat restart there are no reusable live send-source objects in
  memory until something creates them
- broad source-object scans that worked on older sessions came back empty on a
  fresh session
- this means a truly autonomous send path needs either:
  - a constructor path that can build a complete source object from scratch, or
  - a smaller upstream helper that enriches the generic source object enough for
    `FUN_1815e8200`

Static send-path correction from Ghidra:

- `FUN_180633150`
  - allocates a generic `0x6b0` source/owner pair
  - returns:
    - `pair[0] = source`
    - `pair[1] = owner`
- `FUN_180696170`
  - is only the generic source-object initializer
  - it does not appear to populate the richer send-specific state required by
    the later builder path
- `FUN_181664250`
  - is not a generic text-send function
  - it is a chatroom-oriented helper that:
    - validates `@chatroom` targets
    - consumes a vector of `0x28` message-part records
    - internally calls `FUN_180633150`
    - fills the target conversation into the source object
    - builds the text payload via `FUN_1800b44a0` / `FUN_1804c9820`
    - finally calls `FUN_1815e8200(..., mode=0)`
- `FUN_1833fc800` / `FUN_1833fccd0`
  - remain the first failing point for the fresh autonomous `mode=1` builder
    branch
  - the failure happens before the later task-materialization helpers
- `FUN_181437e20`
  - is a promising richer source-object setup helper
  - it is called from `FUN_1817d1a00`, which runs after the generic source init
  - this is a likely lead for the missing send-specific source state

Current autonomous send script state:

- [scripts/send-weixin-text-autonomous.py](/C:/Users/Administrator/Code/puppet-xp/scripts/send-weixin-text-autonomous.py)
  now includes a second fresh autonomous mode:
  - `--mode fresh-pair1`
- `fresh-pair1` does:
  - call `FUN_180633150` directly to create a fresh source/owner pair
  - rewrite:
    - `source + 0xb0` conversation
    - `source + 0x600` UUID
    - `source + 0x660` body
    - `source + 0x9c = 1`
    - `source + 0xd8 = 1`
  - fetch the real global send context
  - call `FUN_1815e8200(sendCtx, resultBuf, pairBuf, 1)`
- this mode is meant to replace the earlier ad hoc inline `mode=1` builder test
  so the next live run is reproducible from a repo script

Fresh-pair correction from live source diff:

- a real live text-send source object has:
  - `source + 0x9c = 1`
  - `source + 0xa4 = 7`
  - `source + 0xc0 = conversation length`
  - `source + 0xc8 = conversation string capacity`
  - `source + 0xd8 = 1`
- the old `0xd8 = 10000` write came from the canned helper/system-message path
  and does not match a normal text-send source
- `FUN_180633150` already initializes the owner/source back-pointers and the
  `+0x600` UUID slot correctly
- after rewriting the fresh pair with:
  - `conversation = 27208021116@chatroom`
  - `body = skynet`
  - `0x9c = 1`
  - `0xd8 = 1`
  the object matches a real live text-send source much more closely

Thread-context correction:

- Frida on this VM supports `Process.runOnThread`
- running the fresh autonomous builder path on the real WeChat UI thread
  (`12220` on the current logged-in session) fixed the earlier thread-context
  mismatch and allowed `FUN_1815e8200` to run on the same thread class as the
  proven lower-send hijack
- however, the autonomous fresh-pair path still crashes WeChat later in
  `roam_server.dll` with:
  - `Application Error 1000`
  - exception `0xc0000409`
  - module `roam_server.dll`
- interpretation:
  - the builder now runs in the correct thread context
  - but a downstream roam/send dependency is still missing from the bare fresh
    pair, even though the source object itself now resembles a live text-send
    source much more closely

Autonomous follow-up on the refreshed logged-in UI sessions:

- a structural live-template scan script was added:
  - [scripts/scan-weixin-live-send-templates.py](/C:/Users/Administrator/Code/puppet-xp/scripts/scan-weixin-live-send-templates.py)
- it now uses Frida's async range enumeration API, which is the only supported
  range enumeration surface on this VM's runtime
- result on a fresh logged-in `WeChat` UI process:
  - `count = 0`
  - there are no resident lower-send source/owner blocks in memory before a
    real send creates them
- implication:
  - autonomous send cannot rely on scavenging a pre-existing live template in a
    fresh session
  - we still need either:
    - a complete constructor path, or
    - a richer builder/wrapper path that can synthesize the missing state

New autonomous constructor correction on the fresh logged-in session:

- the real long-lived richer builder object is present even before a user send:
  - live builder owner: `0x1d1c8ba0740`
  - embedded builder object: `0x1d1c8ba0750`
  - builder owner vtable: `Weixin.dll + 0x7ebc1d8`
  - builder vtable: `Weixin.dll + 0x81214f8`
- the builder owner is constructed by:
  - `FUN_180681e90`
- `FUN_180681e90`:
  - allocates `0xdb0`
  - sets owner vtable to `PTR_FUN_187ebc1d8`
  - sets refcount to `0x100000001`
  - calls `FUN_1815e1360(owner + 0x10)`
  - returns:
    - `out[0] = owner + 0x10` (embedded builder)
    - `out[1] = owner`
- correction:
  - the missing problem is not the richer builder object; it already exists
  - the remaining blocker is still the lower source pair/state that feeds the
    send item constructor cleanly

Generic lower-send pair baseline from a real live send:

- the generic `mode=1` live pair observed at `FUN_1815e8200` caller
  `Weixin.dll + 0x15e9c0b` is:
  - source: `0x224c7658050`
  - owner: `0x224c7658040`
  - owner vtable: `Weixin.dll + 0x7ebe6f8`
  - owner refs: `{7, 2}`
  - owner `+0x18 -> source`
- live source fields:
  - `+0xb0 = 27208021116@chatroom`
  - `+0x600 = 72f4d4a7-595d-473f-b6da-427bc3eac828`
  - `+0x660 = pair probe 1`
  - `+0x9c = 1`
  - `+0xd8 = 1`
- notably, the surrounding optional string fields are still empty on the real
  live pair:
  - `+0x48`
  - `+0x88`
  - `+0x180`
  - `+0x240`
  - `+0x270`
- implication:
  - the real generic send path is far thinner than expected
  - the autonomous blocker is not "populate lots of extra string fields"

Fresh-pair direct baseline from `FUN_180633150`:

- a fresh ctor dump on the live UI thread produced:
  - source: `0x224c7655e40`
  - owner: `0x224c7655e30`
  - same owner vtable: `Weixin.dll + 0x7ebe6f8`
  - owner refs: `{1, 2}`
  - owner `+0x18 -> source`
  - `+0x600` already contains a UUID
  - `+0x9c = 1`
  - `+0xd8 = 0`
  - target/body strings empty by default
- correction:
  - the fresh pair and live generic pair are the same object family
  - the remaining differences are more subtle than class/vtable mismatch
  - the high-signal deltas are:
    - `owner.ref_a = 7` vs `1`
    - `source + 0xd8 = 1` vs `0`

Autonomous retry after matching the live generic pair more closely:

- `send-weixin-text-autonomous.py --mode fresh-batch1`
  - patched to use the live-observed owner refs `{7,2}` instead of `{5,2}`
  - still rewrites:
    - `+0xb0 = conversation`
    - `+0x600 = uuid`
    - `+0x660 = body`
    - `+0x9c = 1`
    - `+0xd8 = 1`
  - result:
    - no early local `invoke_error`
    - script was destroyed before final state
    - Windows event log confirms another crash in:
      - `roam_server.dll`
      - `Application Error 1000`
      - crash time `2026-04-09 14:28:22`
      - exception `0xc0000409`
- implication:
  - matching the obvious live header fields improves the path, but does not yet
    make the fresh autonomous generic send stable
  - the remaining missing state is subtler than:
    - owner class
    - owner refcount header
    - `0xd8`
    - target/body/uuid fields

Current-session lower-pair conclusion on PID `6516`:

- fresh baseline on the live UI thread:
  - owner vtable: `Weixin.dll + 0x7ebe6f8`
  - owner refs `{1,2}`
  - `source + 0xd8 = 0`
  - `source + 0x600` already contains a UUID
  - `source + 0x680` exists but is empty
- real live generic send (`pair probe 5`) on the same process:
  - same owner vtable: `Weixin.dll + 0x7ebe6f8`
  - owner refs `{7,2}`
  - `source + 0xd8 = 1`
  - `source + 0xb0` conversation capacity `31`
  - `source + 0x600` UUID capacity `47`
  - `source + 0x660` inline body
  - `source + 0x680` still empty
- fresh ctor does *not* hide any additional non-empty string payload in:
  - `+0x48`
  - `+0x88`
  - `+0x180`
  - `+0x240`
  - `+0x270`
  - `+0x680`

Critical autonomous send result from the corrected `fresh-pair1` path:

- `send-weixin-text-autonomous.py --mode fresh-pair1 --body skynet`
  was patched to match the live pair more closely:
  - owner refs `{7,2}`
  - `source + 0xd8 = 1`
  - conversation string capacity `31`
  - UUID capacity `47`
- the live lower-source probe captured that autonomous object entering
  `FUN_1815e8200`, and it now matches the real live send pair structurally:
  - same owner class
  - same `ref_a = 7`
  - same `ref_b = 2`
  - same `+0xd8 = 1`
  - same empty optional string slots
  - same empty `+0x680`
  - target/body/uuid all present as expected
- despite that, the call still failed:
  - local path: `invoke_error` in `fresh_pair_build`
  - then later `fresh-batch1` still crashed `Weixin.exe` in `roam_server.dll`

Corrected interpretation after this result:

- the autonomous blocker is no longer in the lower source pair layout itself
- we now have strong evidence that the lower source pair can be synthesized to
  match a real live send
- the remaining failure must be in deeper call context or downstream state, for
  example:
  - the exact `param_2` / output buffer expectations for `FUN_1815e8200`
  - caller-side stack / wrapper context that the direct call path normally sets
  - later send/roam state outside the lower pair itself

Additional constructor-family findings after the current-session comparison:

- the source/owner family has two constructor paths with the same owner vtable
  (`Weixin.dll + 0x7ebe6f8`) but different initializers:
  - `FUN_180633150 -> FUN_180696170`
  - `FUN_180697630 -> FUN_180697740`
- `FUN_180697740` explicitly copies two string slots into the source object:
  - `source + 0x660`
  - `source + 0x680`
- current-session live generic pair on PID `6516` still shows:
  - `+0x660 = pair probe 5`
  - `+0x680 = ''`
- implication:
  - there is no hidden second non-empty body string in the live generic pair
  - the extra initializer family is real, but `+0x680` is not the missing live
    payload for ordinary sends

Deeper builder-context shift:

- `FUN_1815eb0d0` is not a benign output-copy helper:
  - it performs a typed extraction / cast and materializes a structured object
    from the `local_68` object passed down by `FUN_1815e8200`
- `FUN_1815eb320` and `FUN_1815ebec0` are heavily stateful:
  - they insert/look up per-target entries in builder-owned maps
  - they call into the message iterator (`FUN_1833ff7c0`) and other task/cache
    plumbing
  - they depend on `builder->0xb78` map state and per-target entry evolution
- current corrected interpretation:
  - the lower source pair can now be synthesized to match a real live send
  - the remaining blocker is more likely:
    - deeper builder-owned map state
    - per-target cache/task evolution
    - or `param_2` / intermediate object expectations inside
      `FUN_1815e8200 -> FUN_1815eb0d0`
  - less likely:
    - any remaining missing field inside the lower source pair itself

Per-send item constructor correction:

- the previously "mystery" per-send item vtable is:
  - `Weixin.dll + 0x8123cd8`
- that item is constructed directly inside:
  - `FUN_1815e8200`
- `FUN_1815e8200`:
  - allocates `0xf0`
  - sets `item.vtable = PTR_FUN_188123cd8`
  - calls:
    - `FUN_1833fc800(item + 0x10, param_3, param_4)`
  - then runs the internal map/task plumbing:
    - `FUN_1815eb320`
    - `FUN_1815ebec0`
    - `FUN_1815eb0d0`
- implication:
  - the open problem is no longer "find the item constructor"
  - the real problem is supplying a lower source pair rich enough that
    `FUN_1833fc800` / downstream send and roam code accept it

Lower source -> item population findings:

- `FUN_1833fc800` initializes the item from the lower source pair and mode
- `FUN_1833fccd0` is the deeper metadata builder used by that path
- `FUN_1833fccd0` reads many fields from the lower source object beyond just:
  - conversation `+0xb0/+0xc0`
  - body-ish strings
  - a large set of additional metadata and helper refs
- importantly, `FUN_1833fccd0` also internally creates a fresh lower pair via:
  - `FUN_180633150`
  - then calls `FUN_1815e8200(..., mode=0)`
- implication:
  - the internal autonomous-ish path exists, but the bare `FUN_180633150`
    fresh pair still lacks enough downstream state for our direct autonomous
    reuse

Top-level autonomous-ish wrapper correction:

- `FUN_181664250` is still a valid top-level autonomous-ish wrapper candidate
- but it internally falls back into the same fragile fresh lower-pair path:
  - `FUN_180633150`
  - `FUN_180633270`
  - `FUN_1815e8200(..., 0)`
- this explains why the old `fresh` branch could get deeper than the plain
  fresh-pair probe while still eventually failing/crashing

Fresh autonomous live experiments on the current session:

- `send-weixin-text-autonomous.py --mode fresh-hijack1`
  - new branch that lets `FUN_181664250` build its transient lower pair and
    flips the internal `FUN_1815e8200(..., 0)` call to `mode=1` if reached
  - result on the current logged-in session:
    - failed before `FUN_1815e8200` was ever reached
    - script reported:
      - `invoke_error` at `fresh_call_ctor`
      - `access violation accessing 0x0`
    - no `fresh_pair_captured`
    - no send-task event
    - no manager event
  - implication:
    - the current `FUN_181664250` invocation is still malformed *before* the
      internal `1815e8200` handoff point

- `send-weixin-text-autonomous.py --mode fresh-trace`
  - new trace branch to log the last internal callees reached by
    `FUN_181664250` on the real UI thread
  - current result:
    - on the first run, the trace completed cleanly enough to preserve counts:
      - `validate_target`
      - `alloc_filtered_vec`
      - `prepare_msg_map`
      - `get_root`
      - `get_service`
      - `resolve_msg_service`
      - `enrich_msg_entries`
      - `grow_filtered_vec`
    - it then failed with:
      - `invoke_error`
      - stage `fresh_call_ctor`
      - `access violation accessing 0x0`
      - no `fresh_pair_captured`
      - no send-task event
      - no manager event
    - on the next tighter run, WeChat crashed again in `roam_server.dll`
      - `Application Error 1000`
      - `Windows Error Reporting 1001`
      - crash time `2026-04-09 14:03:17`
      - module `roam_server.dll`
      - exception `0xc0000409`
      - Frida lost the script immediately after `fresh_build_entry`
  - current narrowed interpretation:
    - `FUN_181664250` is definitely getting through the initial target/message
      validation and message-service enrichment phases
    - the malformed input is now narrowed to the post-enrichment, pre-send
      window, very likely around the transient message-map insertion / filtered
      entry handling that happens before `FUN_1815e8200` is reached
    - `insert_msg_map_entry` (`FUN_1801d1170`) has not yet been observed firing
      on the failing autonomous path
  - implication:
    - `FUN_181664250` remains the right family to study, but it still reaches
      the same downstream roam crash boundary if we let it run too far with the
      current handcrafted inputs

New autonomous wrapper experiments:

- `send-weixin-text-autonomous.py --mode fresh-batch1`
  - new branch that:
    - creates a fresh generic pair via `FUN_180633150`
    - rewrites:
      - `+0xb0 = conversation`
      - `+0x600 = uuid`
      - `+0x660 = body`
      - `+0x9c = 1`
      - `+0xd8 = 1`
      - owner refs `{5,2}`
    - builds a one-element pair vector
    - calls:
      - `FUN_1815e9960(sendCtx, resultBuf, vec, 1)`
    - on the real UI thread via `Process.runOnThread`
  - result:
    - no crash
    - no task/manager event
    - clean failure at the wrapper call:
      - `Error: access violation accessing 0x0`
  - interpretation:
    - the richer batch wrapper still dereferences a null dependency when driven
      from a fresh generic pair

- `send-weixin-text-autonomous.py --mode fresh-batch0`
  - same wrapper path, but aligned to the chatroom helper semantics:
    - `+0xd8 = 10000`
    - `FUN_1815e9960(sendCtx, resultBuf, vec, 0)`
  - result:
    - the call progressed deeper than `fresh-batch1`
    - the Frida script was destroyed before final-state retrieval
    - Windows event log confirms this crashed `Weixin.exe`
      - `Application Error 1000`
      - `Windows Error Reporting 1001`
      - crash time: `2026-04-09 13:20:52`
  - interpretation:
    - `mode=0` plus `0xd8=10000` is closer to the internal chatroom helper path
      than `fresh-batch1`
    - but it is still not safe enough as an autonomous send primitive

Fresh session `compare pin 2` builder/output diff:

- passive probe:
  - `probe-weixin-send-builder-inner.py`
  - host session:
    - PID `12516`
    - main window thread `7924`
- real ordinary send:
  - body: `compare pin 2`
  - worker thread: `9536`
  - `FUN_1815e8200(..., mode=1)` path completes cleanly
- known-good real builder sequence on thread `9536`:
  - `build_enter`
  - `eb320_enter`
  - `mk_pair_copy`
  - `emit_builder_record`
  - `eb320_leave`
  - `ebec0_enter`
  - `msg_kind_get`
  - `msg_kind_get`
  - `link_builder_a`
  - `msg_flag_set`
  - `msg_flag_set`
  - `msg_flag_check`
  - `msg_flag_set`
  - `link_builder_b`
  - `msg_kind_get`
  - `msg_kind_get`
  - `msg_flag_check`
  - `msg_flag_set`
  - `msg_aux_dump`
  - second `eb320_enter`
  - `mk_pair_copy`
  - `emit_builder_record`
  - `eb320_leave`
  - `ebec0_leave retval=0xf`
  - `build_leave`

Known-good first `ebec0` key node from the real send:

- `key_strings.s0 = 27208021116@chatroom`
- `key_node.qwords`:
  - `0x18 = 0x2225e617300`
  - `0x20 = 0x2225dbd87d0`
  - `0x30 = 0x0`
  - `0x38 = 0x2225e617340`
  - `0x40 = 0x2225e1f4b80`
  - `0x48 = 0x2225df23390`
- builder state at `builder + 0xb78` matched across real/synthetic:
  - `0x90 = 0x2225d047410`
  - `0x98 = 0x2225d3611a0`
  - `0xa0 = 0x2225d361190`
  - `0xa8 = 0x7ffc917a21c8`
  - `0xb0 = 0x2225d2e81f0`
  - `0xb8 = 0x6b35575900000002`
  - `0xc0 = 0x0`

Autonomous `fresh-pair1` diff on the same session:

- autonomous call:
  - thread `9536`
  - body `skynet`
  - `FUN_1815e8200(..., mode=1)`
- it now gets through:
  - `fresh_pair_build_enter`
  - `fresh_pair_eb320_enter`
  - `mk_pair_copy`
  - `emit_builder_record`
  - `fresh_pair_eb320_leave`
  - `fresh_pair_ebec0_enter`
  - `msg_kind_get`
  - `msg_kind_get`
  - `link_builder_a`
  - `msg_flag_set`
  - `msg_flag_set`
- then fails with:
  - `invoke_error`
  - `access violation accessing 0x0`
- first autonomous `ebec0` key node on that same session differed sharply:
  - `0x18 = 0x2225df23390`
  - `0x20 = 0x2225df23380`
  - `0x30 = ASCII-like garbage`
  - `0x38 = ASCII-like garbage`
  - `0x40 = 0x6e61`
  - `0x48 = 0xf`
- interpretation:
  - the lower source pair is no longer the main mismatch
  - the first `ebec0` key node is the strongest remaining divergence
  - the autonomous path likely needs a real-session repair of that node before
    `msg_flag_check` / `link_builder_b`

Autonomous repair support:

- `send-weixin-text-autonomous.py` now supports:
  - `--ebec0-fix-json`
- this patches the first `ebec0` node during `fresh_pair_ebec0_enter`:
  - optional `q18`
  - optional `q20`
  - forced `q30 = 0`
  - optional `q38`
  - optional `q40`
  - optional `q48`
- first session-specific repair candidate captured from the real `compare pin 2`
  send:
  - `{"q18":"0x2225e617300","q20":"0x2225dbd87d0","q38":"0x2225e617340","q40":"0x2225e1f4b80","q48":"0x2225df23390"}`
- the first attempted rerun with this fix did not execute because `Weixin.exe`
  PID `12516` had already exited before Frida attached

Fresh session `compare pin 3` update:

- fresh main UI session:
  - `Weixin.exe` PID `6052`
  - main window thread `10308`
- real comparison send:
  - body `compare pin 3`
  - live send worker thread `1020`
- first real `ebec0` key node for this session:
  - `q18 = 0x1cc88b6c9e0`
  - `q20 = 0x1cc88b6c9d0`
  - `q30 = 0x1cc87faf1a0`
  - `q38 = 0x1cc87faf1a0`
  - `q40 = 0x6d6f632e7171`
  - `q48 = 0x804ed6a700000001`
- this session is important because unlike the earlier `compare pin 2` session,
  the real first key node has `q30 == q38`; forcing `q30 = 0` was wrong here

Autonomous `fresh-pair1` repair progress on the `compare pin 3` session:

- first repaired rerun using only:
  - `q18`
  - `q20`
  - `q38`
  - `q40`
  - `q48`
  still failed, but the reason became clearer:
  - the autonomous path reached the same old boundary
  - and the script-level repair log proved we were still forcing `q30 = 0`

- `send-weixin-text-autonomous.py` was then patched so `--ebec0-fix-json`
  can optionally set a real session-specific `q30` instead of always zeroing it

- second repaired rerun using the full first-node shape:
  - `q18 = 0x1cc88b6c9e0`
  - `q20 = 0x1cc88b6c9d0`
  - `q30 = 0x1cc87faf1a0`
  - `q38 = 0x1cc87faf1a0`
  - `q40 = 0x6d6f632e7171`
  - `q48 = 0x804ed6a700000001`
  produced the farthest autonomous `fresh-pair1` result so far:
  - `fresh_pair_build_enter`
  - `fresh_pair_eb320_enter`
  - `mk_pair_copy`
  - `fresh_pair_eb320_leave`
  - `fresh_pair_ebec0_enter`
  - `msg_kind_get`
  - `msg_kind_get`
  - `fresh_pair_ebec0_leave retval=0xf`
- that is a real milestone because previous `fresh-pair1` runs died before
  `fresh_pair_ebec0_leave`

Current remaining blocker after that repaired run:

- even with the full first-node repair, the autonomous script still ended with:
  - `final_state_error`
  - `script has been destroyed`
- there was still no internal:
  - `task_event`
  - `manager_event`
- the next planned check was to verify the same repaired autonomous run against
  external proof hooks:
  - `monitor-weixin-send-task-hook.py`
  - `monitor-weixin-manager-message-hook.py`
- but before that rerun could attach, `Weixin.exe` PID `6052` disappeared and
  Frida returned:
  - `ProcessNotFoundError: unable to find process with pid 6052`

Fresh session `compare pin 4` autonomous delivery check:

- fresh main UI session:
  - `Weixin.exe` PID `11644`
  - main window thread `11772`
- real comparison send:
  - body `compare pin 4`
  - worker thread `11236`
- first real `ebec0` node on this session differed from the previous session:
  - `q18 = 0x790074`
  - `q20 = 0x9fb945f33d7d7710`
  - `q30 = 0x7ffc914fdfa8`
  - `q38 = 0x0`
  - `q40 = 0x7ffc932af360`
  - `q48 = 0x20d860f6178`

Autonomous `fresh-pair1` replay on the `compare pin 4` session:

- used:
  - thread `11236`
  - `mode=1`
  - session-local `ebec0` repair values above
- result:
  - still failed before `msg_flag_check`
  - no internal `task_event`
  - no internal `manager_event`

External proof hooks on the same real main UI process:

- `monitor-weixin-send-task-hook.py --pid 11644`
- `monitor-weixin-manager-message-hook.py --pid 11644`

Observed outcome:

- scheduler/send-task hook **did** record a native outgoing task for:
  - conversation `27208021116@chatroom`
  - content `skynet`
- manager-dispatch hook **did not** record a corresponding compact send-success
  event for `skynet`
- user then visually verified in the real WeChat UI that:
  - `skynet` appears in `Zuma Internal`
  - but it has the red `!` failed-send indicator / `resend message`

Current interpretation:

- the repaired autonomous path can now create a real local outgoing message row
  and scheduled send task
- but it still does **not** complete the downstream delivery/send-success path
- this is stronger than earlier purely local builder progress:
  - the message is now present in the conversation UI
  - however it is still failing before the final delivery/ack leg
- therefore the remaining blocker is no longer “can we create a local message?”
  but “what extra state is required for a valid successful send?”
Successful manual resend of the failed `skynet` row:

- on the fresh main UI session:
  - `Weixin.exe` PID `1624`
  - main window thread `8800`
- all proof hooks were reattached to the real main UI process:
  - `monitor-weixin-send-task-hook.py --pid 1624`
  - `monitor-weixin-manager-message-hook.py --pid 1624`
  - `probe-weixin-send-entry-callers.py --pid 1624 --baseline-seconds 1`
  - `probe-weixin-send-builder-inner.py`
- after clicking the red `resend message` on the failed `skynet` row exactly once:
  - `monitor-weixin-send-task-hook.py` recorded a native outgoing task:
    - `conversation_id = 27208021116@chatroom`
    - `sender_username = wxid_yfe3gm54e5il12`
    - `content = skynet`
    - `msgsource = <msgsource><alnode><fr>1</fr></alnode></msgsource>`
  - `monitor-weixin-manager-message-hook.py` also recorded a successful compact
    manager-dispatch event for the same resend:
    - `conversation_id = 27208021116@chatroom`
    - `title = Zuma Internal`
    - `sender_username = wxid_yfe3gm54e5il12`
    - `direction = sent`
    - `content = skynet`
    - `flag = 1`
    - candidate timestamp field `+0x90 = 1775750447`
- this proves the resend click did **succeed** and reached the real send-success
  layer, not just local row/task creation

Top-level wrapper result during resend:

- `probe-weixin-send-entry-callers.py` did **not** log a new top-level
  `FUN_1815af8e0` caller for the successful resend
- current interpretation:
  - resend likely bypasses the normal top send wrapper path
  - the real resend path is lower in the builder/send stack

Successful resend builder trace on worker thread `9268`:

- first resend `eb320_enter`:
  - `map_base = 0x1e13a178030`
  - `pair_copy = 0x27db9feff0`
  - `out_ptr = 0x1e13daa5fa8`
  - `out_qwords`
    - `q0 = 0x1e13d43d9e0`
    - `q8 = 0x0`
    - `q10 = 0x14`
    - `q18 = 0x1f`
    - `q20 = 0x0`
    - `q28 = 0x0`
- first resend `ebec0_enter`:
  - `builder = 0x1e13aff0c20`
  - `key_ptr = 0x1e13daa5fa8`
  - `key_strings.s0 = 27208021116@chatroom`
  - first `key_node.ptr = 0x1e13d43d9e0`
  - first `key_node.qwords`
    - `0x18 = 0x1e13d43d9e8`
    - `0x20 = 0x1e13bde5de0`
    - `0x28 = 0x800024007524f877`
    - `0x30 = 0x7ffc914fe598`
    - `0x38 = 0x1e13bec0e10`
    - `0x40 = 0x1e13bec0e00`
    - `0x48 = 0x1e13bde5df0`
- second resend `eb320_enter`:
  - `map_base = 0x1e13a178070`
  - `pair_copy = 0x27db9feeb0`
  - `out_ptr = 0x27db9fed20`
  - `out_qwords`
    - `q0 = 0x1e13d43da70`
    - `q8 = 0x0`
    - `q10 = 0x16`
    - `q18 = 0x1f`
    - `q20 = 0x69d7cd2f00000c89`
    - `q28 = 0x345b0`
- first resend `ebec0_leave = 0xf`
- later resend `ebec0_enter`:
  - `key_ptr = 0x1e13c064b20`
  - `key_node.ptr = 0x1e13d43d3b0`
  - `key_node.qwords`
    - `0x18 = 0x1e13d43d300`
    - `0x20 = 0x1e13bde5de0`
    - `0x28 = 0x900003e17543f8ea`
    - `0x30 = 0x1e13d43daa0`
    - `0x38 = 0x1e13d43dd70`
    - `0x40 = 0x1e13dae0080`
    - `0x48 = 0x1e13dae0070`
- final resend `ebec0_leave = 0x1e13afa6640`

Current best next move after the successful manual resend:

- the fastest route to a fully successful autonomous send may be:
  1. create the failed local row / scheduled send task using the repaired
     autonomous builder path
  2. invoke WeChat's own resend path for that failed row
- resend is now the strongest known bridge between:
  - synthetic local-row creation
  - and actual downstream successful delivery
Follow-up autonomous retry on the successful resend session (`PID 1624`, worker
thread `9268`):

- retried the repaired autonomous `fresh-pair1` path on the same live resend
  worker thread using the successful resend first-node values and:
  - `pair_mode = 1`
  - body `skynet2`
- result:
  - reached:
    - `fresh_pair_build_enter`
    - `fresh_pair_eb320_enter`
    - `mk_pair_copy`
    - `emit_builder_record`
    - `fresh_pair_eb320_leave`
    - `fresh_pair_ebec0_enter`
    - `msg_kind_get`
    - `msg_kind_get`
    - `link_builder_a`
    - `msg_flag_set`
    - `msg_flag_set`
  - then failed with:
    - `invoke_error`
    - `Error: access violation accessing 0x0`
  - no external `send_task_event`
  - no external `manager_message_event`

- retried again on the same live resend worker thread using:
  - `pair_mode = 257`
  - body `skynet3`
- result:
  - got farther than the `pair_mode = 1` retry:
    - `fresh_pair_build_enter`
    - `fresh_pair_eb320_enter`
    - `mk_pair_copy`
    - `fresh_pair_eb320_leave`
    - `fresh_pair_ebec0_enter`
    - `msg_kind_get`
    - `msg_kind_get`
    - `fresh_pair_ebec0_leave retval=0xf`
  - but still no external:
    - `send_task_event`
    - `manager_message_event`
  - and `Weixin.exe` disappeared immediately afterward

Current interpretation after those retries:

- the successful manual resend worker thread and first-node repair values are
  genuinely helpful
- but simply replaying the repaired autonomous lower builder on that thread is
  still **not** enough to reproduce the successful resend path
- the next high-value target is therefore the actual resend wrapper/caller chain,
  not more blind lower-builder retries

Fresh lower-send success on clean session `PID 10040`:

- re-armed the proven builder-only lower-send hijack on:
  - `Weixin.exe` PID `10040`
  - live worker thread `2804`
  - trigger body `seedlower6`
- successful seed capture:
  - `wrapper = 0x1618a6ac770`
  - `sourceObj = 0x1618ff99e20`
  - `ownerBase = 0x1618ff99e10`
  - `conversation = 27208021116@chatroom`
  - `body = seedlower6`
  - `uuid = 67187dd2-6821-4ea1-9c9d-0eebcdff8f09`
- successful builder-only clone:
  - `owner_clone = 0x16191bc63e0`
  - `source_clone = 0x16191bc63f0`
  - `pair_buf = 0x16191478e70`
  - `send_ctx = 0x1618f75c7c0`
  - `b78 = 0x1618e94a240`
- proof:
  - send-task hook emitted:
    - `conversation_id = 27208021116@chatroom`
    - `content = skynet`
  - manager-dispatch hook emitted:
    - `conversation_id = 27208021116@chatroom`
    - `title = Zuma Internal`
    - `content = skynet`

Focused successful builder-call context capture on the same session:

- new tracer script:
  - `scripts/probe-weixin-builder-call-context.py`
- successful ordinary send frame captured for `seedlower5`:
  - `thread_id = 2804`
  - `caller_rva = 0x15e9c0b`
  - `mode = 1`
  - `send_ctx = 0x1618f75c7c0`
  - `result_buf = 0x56f49ff2a0`
  - `pair_ptr = 0x56f49ff360`
  - `source_ptr = 0x1618ee85a80`
  - `owner_ptr = 0x1618ee85a70`
  - `conversation = 27208021116@chatroom`
  - `body = seedlower5`
  - `uuid = f46857f9-812e-44eb-aa4f-bbb474ec0916`
- important good-frame field values:
  - `source + 0xb0`:
    - text `27208021116@chatroom`
    - `len = 20`
    - `cap = 31`
  - `source + 0x600`:
    - valid UUID text
    - `len = 36`
    - `cap = 47`
  - `source + 0x660`:
    - text `seedlower5`
    - `len = 10`
    - `cap = 15`
  - `source + 0x680`:
    - empty
    - `cap = 15`
  - `source + 0x9c = 1`
  - `source + 0xd8 = 1`
  - owner refs at `owner + 0x8/0xc = {7,2}`
- successful `buildOnePairRequest(...)` output:
  - `retval = result_buf`
  - `result_post_qwords`
    - `0x20 = 0xf`
    - `0x28 = 0x161892f04e0`
    - `0x30 = 0x161892f04d0`
    - `0x38 = 0x1618f75c7b0`

Detached builder-path diff and repair:

- detached replay was run on the same good worker thread:
  - `thread_id = 2804`
  - `send_ctx = 0x1618f75c7c0`
  - template clone based on the successful builder-only clone:
    - `template_source = 0x16191bc63f0`
    - `template_owner = 0x16191bc63e0`
- first detached trace (`skynet-detach1`) showed several mismatches versus the
  good frame:
  - `source + 0x600` UUID string was invalid / unreadable (`text = null`)
  - `source + 0xb0` conversation cap was only `20`, not `31`
  - owner refs were `{2,2}`, not `{7,2}`
  - result buffer was all-zero before entry
  - `caller_rva` was synthetic runtime `0x4d58051e`, not the good live caller
    `0x15e9c0b`
- this explained why the detached path still diverged despite using the correct
  worker thread and `send_ctx`

Autonomous script repair applied:

- updated `scripts/send-weixin-text-autonomous.py` builder mode to match the
  successful in-hook normalization:
  - rewrite `source + 0xb0` with forced cap `31`
  - rewrite `source + 0x600` with a fresh UUID and forced cap `47`
  - rewrite `source + 0x660`
  - force owner refs to `{7,2}`
  - force `source + 0x9c = 1`
  - force `source + 0xd8 = 1`

Detached retry after normalization fix (`skynet-detach2`):

- same thread/context:
  - `PID 10040`
  - `thread_id = 2804`
  - `send_ctx = 0x1618f75c7c0`
- result:
  - old immediate `call_builder` access violation is gone
  - the detached script now gets through:
    - `start`
    - `validate_template`
    - `clone_owner`
    - `clone_source`
    - `rewrite_strings`
    - `build_pair`
    - `build_result`
    - `get_root`
    - `get_service`
    - `get_send_ctx`
    - `call_builder`
  - after the builder call the script terminates with:
    - `final_state_error = script has been destroyed`
  - no external proof event for `skynet-detach2` was observed before the
    process disappeared

Current interpretation after the `skynet-detach2` fix:

- the normalization patch was real and necessary
- the detached/no-seed path is now significantly closer to the working in-hook
  path than before
- the remaining blocker is no longer the obvious cloned source/owner field set
- the strongest remaining gap is transient call context around the successful
  live caller:
  - detached caller RVA is still synthetic/runtime-owned
  - successful caller RVA is stable live code at `0x15e9c0b`
- next step remains:
  - capture and reproduce the caller-side transient context around the good
    `buildOnePairRequest(...)` invocation, rather than continuing blind object
    mutation

Current clean-session checkpoint on PID `13080`:

- fresh seeded lower-send success:
  - trigger: `seedlower8`
  - worker thread: `1472`
  - seed wrapper/source/owner:
    - `wrapper = 0x29bb029ebd0`
    - `sourceObj = 0x29bb73aadd0`
    - `ownerBase = 0x29bb73aadc0`
  - working cloned builder-only pair:
    - `owner_clone = 0x29bb8426d10`
    - `source_clone = 0x29bb8426d20`
    - `pair_buf = 0x29bb7983e10`
    - `send_ctx = 0x29bb6857420`
  - proof hooks both confirmed a real synthetic send:
    - send-task hook saw `content = skynet`
    - manager-dispatch hook saw `content = skynet`

Focused builder-call context diff on PID `13080`:

- ordinary seed send (`seedlower8`):
  - `thread_id = 1472`
  - `caller_rva = 0x15e9c0b`
  - `mode = 1`
  - `send_ctx = 0x29bb6857420`
  - `source + 0xb0`:
    - text `27208021116@chatroom`
    - `len = 20`
    - `cap = 31`
  - `source + 0x600`:
    - UUID `bf95a34b-0648-4d13-a0c8-817bf655cceb`
    - `len = 36`
    - `cap = 47`
  - `source + 0x660`:
    - text `seedlower8`
    - `len = 10`
    - `cap = 15`
  - owner refs:
    - `{7,2}`

- successful synthetic in-hook `skynet`:
  - `thread_id = 1472`
  - `caller_rva = 0xffffffffd1687ca1`
  - `mode = 1`
  - `send_ctx = 0x29bb6857420`
  - `source_ptr = 0x29bb8426d20`
  - `owner_ptr = 0x29bb8426d10`
  - `source + 0xb0`:
    - text `27208021116@chatroom`
    - `len = 20`
    - `cap = 20`
  - `source + 0x600`:
    - same seed UUID `bf95a34b-0648-4d13-a0c8-817bf655cceb`
    - `len = 36`
    - `cap = 47`
  - `source + 0x660`:
    - text `skynet`
    - `len = 6`
    - `cap = 15`
  - owner refs:
    - `{3,2}`
  - result buffer:
    - all-zero pre-state is acceptable
    - successful leave state:
      - `0x20 = 0xf`
      - `0x28 = 0x29bb847c310`
      - `0x30 = 0x29bb847c300`
      - `0x38 = 0x0`

Detached builder observations on the same session:

- `skynet-detach3`:
  - send-task hook observed a real scheduled task for `content = skynet-detach3`
  - manager-dispatch hook did **not** observe a matching success event
  - interpretation:
    - detached path can at least create/schedule a task or local row
    - but it still diverges before final successful send

- `skynet-detach4` with the new `builder-minimal` mode in
  `scripts/send-weixin-text-autonomous.py`:
  - detached call *did* reach `buildOnePairRequest(...)`
  - tracer captured:
    - `thread_id = 1472`
    - `caller_rva = 0x4cec051e`
    - `mode = 1`
    - `send_ctx = 0x29bb6857420`
    - `source_ptr = 0x29bb6ec00f0`
    - `owner_ptr = 0x29bb6ec00e0`
    - body `skynet-detach4`
  - detached source/owner still diverged from the successful in-hook clone:
    - owner refs were `{2,2}`, not `{3,2}`
    - builder entered but no successful leave was captured
  - interpretation:
    - the failure is now inside or after builder entry, not at the call boundary

Worker-thread callback exploration:

- new script:
  - `scripts/sample-weixin-thread-calls.py`
  - used to sample hot recurring call targets on the real send worker thread
- thread `1472` hot RVAs included:
  - `0xbd3ad0`
  - `0xbcf250`
  - `0xa1e0`
  - `0xbd3cb0`
  - plus several `0x6309... / 0x64d...` utility-heavy frames

- new autonomous callback script:
  - `scripts/send-weixin-text-via-hot-thread-hook.py`
- first callback experiment:
  - hook RVA `0xbd3ad0`
  - body `autonomous-hot1`
  - it did fire on thread `1472`
  - but the cloned template state was already degraded by the time the callback
    ran:
    - `uuid = null`
    - owner refs `{2,2}`
  - WeChat died immediately afterward, and no proof hook saw a new send
  - interpretation:
    - this was **not** a valid replacement for the successful in-hook template
    - it also showed that stale heap template pointers cannot be reused blindly
      for later callback-based autonomous sends

Current best interpretation:

- the proven seeded synthetic send path is reproducible
- the builder-context diff is real and useful
- the first hot-thread callback idea is still promising, but it must use a
  genuinely live template, not an older clone pointer that has already drifted
  in heap state
- next time this branch is retried, the callback hook should be paired with a
  fresh live seed/template capture on the same session, or another way to
  produce a current valid template before the callback fires

Fresh-session callback retest on PID `13292`:

- fresh seeded path was re-proven with:
  - trigger `seedlower9`
  - worker thread `11056`
  - seed source/owner:
    - `0x1c779c79dd0`
    - `0x1c779c79dc0`
  - successful synthetic clone:
    - `source = 0x1c77ba7e400`
    - `owner = 0x1c77ba7e3f0`
  - `send_ctx = 0x1c7791cf0c0`
  - UUID `929d1ae4-8030-4541-9496-c4a345ec3b24`
  - proof hooks both saw `content = skynet`

- callback thread sampling on the same worker thread `11056` again showed the
  same hot recurring candidates, with `0xbd3ad0` still a strong lightweight
  callback candidate:
  - `0xbd3ad0`
  - `0xbd3cb0`
  - `0xbcf250`
  - `0xa1e0`

- callback retest using the fresh successful synthetic clone pointers:
  - script:
    - `scripts/send-weixin-text-via-hot-thread-hook.py`
  - target:
    - `body = autonomous-hot2`
    - hook RVA `0xbd3ad0`
  - callback really did fire on the correct worker thread `11056`
  - but by the time the callback executed, the cloned template had already
    drifted:
    - `uuid = null`
    - owner refs `{2,2}`
  - result:
    - `hot_hook_error = access violation accessing 0x0`
    - no proof hook observed a new send

Attach-time snapshot repair for the callback script:

- `scripts/send-weixin-text-via-hot-thread-hook.py` was patched to snapshot the
  owner block and key source fields at attach time instead of rereading the live
  heap template later
- the patch added:
  - `OWNER_BLOCK_SIZE = 0x710`
  - `SNAPSHOT_BYTES`
  - `SNAPSHOT_UUID`
  - `SNAPSHOT_CONVERSATION`
  - `SNAPSHOT_CONV_CAP`
  - `SNAPSHOT_REF_A`
  - `SNAPSHOT_REF_B`
  - `template_snapshot` logging

Callback retest on PID `1952` after the snapshot patch:

- fresh seeded path was re-proven again with:
  - trigger `seedlower11`
  - worker thread `11852`
  - seed source/owner:
    - `0x241ee1c9290`
    - `0x241ee1c9280`
  - successful synthetic clone:
    - `source = 0x241f5632260`
    - `owner = 0x241f5632250`
  - `send_ctx = 0x241f4c50710`
  - UUID `cb5bec93-1b2d-4c02-ad8e-664862afd559`
  - proof hooks both saw `content = skynet`

- the first callback retry on the same session still showed:
  - `template_snapshot.uuid = null`
  - `template_snapshot.ref_a/ref_b = {2,2}`
  - then:
    - `hot_hook_error = access violation accessing 0x0`
- this clarified the real issue:
  - even at attach time, the **successful synthetic clone pointers** are already
    too stale to use as a callback template source
  - the next callback attempt must use the **fresh original seed source/owner**
    from the same session, not the later synthetic clone pointers

Unfinished follow-up:

- immediately after that finding, WeChat rolled over again before the retest
  against the fresh original seed template could be completed
- so the next callback branch should start from:
  - a fresh session
  - one fresh seeded success
  - then callback attach using the original seed source/owner, not the synthetic
    clone source/owner

## 2026-04-09 Session7 raw-owner snapshot retest

Fresh seeded success on PID `11964`:

- trigger `seedlower13`
- worker thread `6440`
- seed wrapper/source/owner:
  - `wrapper = 0x153ae004260`
  - `source = 0x153ab714e40`
  - `owner = 0x153ab714e30`
- `send_ctx = 0x153ac291a00`
- UUID `1d825b30-ce46-440c-ac16-6ab28e5adb9e`
- proof hooks again saw:
  - `content = seedlower13`
  - `content = skynet`

Raw seed snapshot captured by the patched lower-send hook:

- `sourceOffset = 16`
- `conversationCap = 31`
- raw top-send seed refs:
  - `ownerRefA = 5`
  - `ownerRefB = 2`
- full `ownerSnapshotHex` was emitted in
  `AppData\\Local\\Temp\\weixin_lower_hijack_session7.txt`

Builder-context diff on the same session:

- real seed `buildOnePairRequest(...)` entry:
  - caller RVA `0x15e9c0b`
  - mode `1`
  - `owner + 0x8/0xc = {4,2}` packed as `0x200000004`
- successful in-hook synthetic `skynet` entry:
  - caller RVA `0xffffffffce907ca1`
  - mode `1`
  - `owner + 0x8/0xc = {3,2}` packed as `0x200000003`
- successful synthetic builder leave returned a valid result buffer:
  - `q20 = 0xf`
  - `q28 = 0x153ac94b630`
  - `q30 = 0x153ac94b620`

Raw-snapshot callback retest:

- script:
  - `scripts/send-weixin-text-via-hot-thread-hook.py`
- hook RVA:
  - `0xbd3ad0`
- target:
  - `body = autonomous-hot6`
- this was the first retest using the fresh original seed source/owner plus the
  raw captured `ownerSnapshotHex`, instead of rereading stale live heap pointers
- the callback fired on the correct worker thread `6440`
- the callback built a fresh cloned pair with the expected values:
  - `conversation = 27208021116@chatroom`
  - `body = autonomous-hot6`
  - `uuid = 1d825b30-ce46-440c-ac16-6ab28e5adb9e`
  - `owner_ref_a/ref_b = {5,2}`
- but `buildOnePairRequest(...)` still faulted inside the callback:
  - first `hot_hook_error = access violation accessing 0xffffffffffffffff`
  - then repeated `hot_hook_error = access violation accessing 0x0`
- no proof hook observed a new send-task row or manager-dispatch success for
  `autonomous-hot6`

Interpretation:

- stale template pointers were **not** the only blocker
- even with a fresh raw owner snapshot and the original seed source/owner, the
  hot callback still lacks something needed for a safe builder call
- the most likely remaining mismatch is now the seed/callback header state at
  `owner + 0x8/0xc` or another callback-site-specific caller-local/context edge,
  not the basic lower source/owner object layout

Next callback experiments to try, in order:

1. reuse the same raw owner snapshot but override refs to the real builder-entry
   seed values `{4,2}`
2. if that still faults, retry with the successful synthetic builder-entry refs
   `{3,2}`
3. if both still fail, treat `0xbd3ad0` as “close but still not equivalent” and
   capture the next tighter recurring callback site on the same worker thread
   (`0xbd3cb0` / `0xbcf250`) using the same raw-snapshot method

## 2026-04-09 Session8 callback retest

Fresh seeded success on PID `1748`:

- trigger `seedlower14`
- worker thread `9392`
- seed wrapper/source/owner:
  - `wrapper = 0x1fb427122b0`
  - `source = 0x1fb41536510`
  - `owner = 0x1fb41536500`
- `send_ctx = 0x1fb4078e8d0`
- UUID `381aa980-a0f5-42ec-aff7-dcc834ec7336`
- raw seed snapshot:
  - `sourceOffset = 16`
  - `conversationCap = 31`
  - raw top-send refs `{5,2}`
  - `ownerSnapshotHex` captured in
    `AppData\\Local\\Temp\\weixin_lower_hijack_session8.txt`
- proof hooks again saw:
  - `content = seedlower14`
  - `content = skynet`

Builder-context diff on the same session:

- real seed builder entry:
  - thread `9392`
  - caller RVA `0x15e9c0b`
  - mode `1`
  - builder-entry refs `{4,2}` packed as `0x200000004`
- successful in-hook synthetic `skynet` entry:
  - thread `9392`
  - caller RVA `0xffffffffd1c57ca1`
  - mode `1`
  - builder-entry refs `{3,2}` packed as `0x200000003`
- successful synthetic builder leave again returned:
  - `q20 = 0xf`
  - `q28 = 0x1fb425a5550`
  - `q30 = 0x1fb425a5540`

Raw-snapshot callback retest with builder-entry seed refs `{4,2}`:

- script:
  - `scripts/send-weixin-text-via-hot-thread-hook.py`
- hook RVA:
  - `0xbd3ad0`
- target:
  - `body = autonomous-hot9`
- callback fired on the correct worker thread `9392`
- the cloned callback pair carried the expected fresh values:
  - `conversation = 27208021116@chatroom`
  - `body = autonomous-hot9`
  - `uuid = 381aa980-a0f5-42ec-aff7-dcc834ec7336`
  - `owner_ref_a/ref_b = {4,2}`
- failure changed shape versus the raw `{5,2}` test:
  - first `hot_hook_error = system error`
  - then repeated `hot_hook_error = access violation accessing 0x0`
- no proof hook observed a new task row or manager-dispatch success for
  `autonomous-hot9`
- immediately after this retest, `Weixin.exe` PID `1748` disappeared before the
  next `{3,2}` callback variant could be attempted

Interpretation:

- callback-site header state does matter; changing `{5,2}` -> `{4,2}` changed
  the failure shape
- but `0xbd3ad0` still is not sufficient yet for a successful builder-only
  autonomous send
- the remaining highest-value live test is still the callback retest with the
  successful synthetic builder-entry refs `{3,2}`
- if `{3,2}` still fails, the next callback site to test should be `0xbd3cb0`
  or `0xbcf250` using the same raw-snapshot method

## 2026-04-09 Session9 callback retest

Fresh seeded success on PID `7652`:

- trigger `seedlower15`
- worker thread `12936`
- seed wrapper/source/owner:
  - `wrapper = 0x1d4dd558530`
  - `source = 0x1d4dd38f8a0`
  - `owner = 0x1d4dd38f890`
- `send_ctx = 0x1d4dcb6d5e0`
- UUID `af317d2c-d55c-4502-b827-7e55f0c7465d`
- raw seed snapshot:
  - `sourceOffset = 16`
  - `conversationCap = 31`
  - raw top-send refs `{5,2}`
  - `ownerSnapshotHex` captured in
    `AppData\\Local\\Temp\\weixin_lower_hijack_session9.txt`
- proof hooks again saw:
  - `content = seedlower15`
  - `content = skynet`

Builder-context diff on the same session:

- real seed builder entry:
  - thread `12936`
  - caller RVA `0x15e9c0b`
  - mode `1`
  - builder-entry refs `{4,2}` packed as `0x200000004`
- successful in-hook synthetic `skynet` entry:
  - thread `12936`
  - caller RVA `0xffffffffcc097ca1`
  - mode `1`
  - builder-entry refs `{3,2}` packed as `0x200000003`
- successful synthetic builder leave again returned:
  - `q20 = 0xf`
  - `q28 = 0x1d4d4e52200`
  - `q30 = 0x1d4d4e521f0`

Raw-snapshot callback retest with successful synthetic refs `{3,2}`:

- script:
  - `scripts/send-weixin-text-via-hot-thread-hook.py`
- hook RVA:
  - `0xbd3ad0`
- target:
  - `body = autonomous-hot10`
- callback fired on the correct worker thread `12936`
- the cloned callback pair carried the expected fresh values:
  - `conversation = 27208021116@chatroom`
  - `body = autonomous-hot10`
  - `uuid = af317d2c-d55c-4502-b827-7e55f0c7465d`
  - `owner_ref_a/ref_b = {3,2}`
- failure shape:
  - first `hot_hook_error = access violation accessing 0xffffffffffffffff`
  - then repeated `hot_hook_error = access violation accessing 0x0`
- no proof hook observed a new task row or manager-dispatch success for
  `autonomous-hot10`
- immediately after this retest, `Weixin.exe` PID `7652` disappeared before the
  next callback-site variant could be attempted

Interpretation after Session9:

- all three high-value header-state variants at callback site `0xbd3ad0` have
  now been exercised:
  - raw top-send refs `{5,2}`
  - real seed builder-entry refs `{4,2}`
  - successful synthetic builder-entry refs `{3,2}`
- none of them produced a successful builder-only autonomous send
- this strongly suggests the remaining blocker is the callback site itself, not
  just owner/source header state

Next callback-site experiments:

1. retry the same raw-snapshot method at `0xbd3cb0`
2. if that still fails, retry at `0xbcf250`
3. if both fail, revisit whether the autonomous branch must be driven from a
   different recurring callback family or whether a lighter in-hook post-send
   queueing strategy is the better path

## 2026-04-09 Session10 callback-site retest

Fresh seeded success on PID `9792`:

- trigger `seedlower16`
- worker thread `6632`
- seed wrapper/source/owner:
  - `wrapper = 0x1facbf5a4d0`
  - `source = 0x1fac3f7a9d0`
  - `owner = 0x1fac3f7a9c0`
- `send_ctx = 0x1facb9058c0`
- UUID `5b79a57c-80f4-40d4-8d64-7ff36a2223c4`
- raw seed snapshot:
  - `sourceOffset = 16`
  - `conversationCap = 31`
  - raw top-send refs `{5,2}`
  - `ownerSnapshotHex` captured in
    `AppData\\Local\\Temp\\weixin_lower_hijack_session10.txt`
- proof hooks again saw:
  - `content = seedlower16`
  - `content = skynet`

Builder-context diff on the same session:

- real seed builder entry:
  - thread `6632`
  - caller RVA `0x15e9c0b`
  - mode `1`
  - builder-entry refs `{4,2}` packed as `0x200000004`
- successful in-hook synthetic `skynet` entry:
  - thread `6632`
  - caller RVA `0xffffffffcc697ca1`
  - mode `1`
  - builder-entry refs `{3,2}` packed as `0x200000003`
- successful synthetic builder leave again returned:
  - `q20 = 0xf`
  - `q28 = 0x1facd99a060`
  - `q30 = 0x1facd99a050`

Callback-site retest at `0xbd3cb0` using raw snapshot + `{3,2}`:

- script:
  - `scripts/send-weixin-text-via-hot-thread-hook.py`
- target:
  - `body = autonomous-hot11`
- callback fired on the correct worker thread `6632`
- the cloned callback pair carried the expected values:
  - `conversation = 27208021116@chatroom`
  - `body = autonomous-hot11`
  - `uuid = 5b79a57c-80f4-40d4-8d64-7ff36a2223c4`
  - `owner_ref_a/ref_b = {3,2}`
- failure shape:
  - first `hot_hook_error = access violation accessing 0xffffffffffffffff`
  - then repeated `hot_hook_error = access violation accessing 0x0`
- no proof hook observed a new task row or manager-dispatch success for
  `autonomous-hot11`

Callback-site retest at `0xbcf250` using raw snapshot + `{3,2}`:

- same session, same raw seed snapshot, same worker thread `6632`
- target:
  - `body = autonomous-hot12`
- `Weixin.exe` PID `9792` disappeared before the script could even attach, so
  this site was **not** successfully exercised on the live process

Interpretation after Session10:

- `0xbd3cb0` behaves like `0xbd3ad0`: correct thread and correct raw snapshot,
  but still no builder-only autonomous send
- the remaining untested hot recurring candidate from this worker-thread family
  is still `0xbcf250`
- if `0xbcf250` also fails on a fresh session, the next move should be to pivot
  away from these lightweight recurring callbacks and either:
  - queue from a different recurring callback family, or
  - move to a lighter in-hook deferred invocation strategy that preserves the
    live top-send context better than the current callback-site experiments

## 2026-04-09 Session11 final hot-callback retest

Fresh seeded success on PID `1624`:

- trigger `seedlower17`
- worker thread `688`
- seed wrapper/source/owner:
  - `wrapper = 0x2648d550400`
  - `source = 0x2648c8b10a0`
  - `owner = 0x2648c8b1090`
- `send_ctx = 0x2648b4305f0`
- UUID `b3aa3a96-e232-4ea7-97e3-92cde69b7be0`
- raw seed snapshot:
  - `sourceOffset = 16`
  - `conversationCap = 31`
  - raw top-send refs `{5,2}`
  - `ownerSnapshotHex` captured in
    `AppData\\Local\\Temp\\weixin_lower_hijack_session11.txt`
- proof hooks again saw:
  - `content = seedlower17`
  - `content = skynet`

Builder-context diff on the same session:

- real seed builder entry:
  - thread `688`
  - caller RVA `0x15e9c0b`
  - mode `1`
  - builder-entry refs `{4,2}` packed as `0x200000004`
- successful in-hook synthetic `skynet` entry:
  - thread `688`
  - caller RVA `0xffffffffc8357ca1`
  - mode `1`
  - builder-entry refs `{3,2}` packed as `0x200000003`
- successful synthetic builder leave again returned:
  - `q20 = 0xf`
  - `q28 = 0x26484d01310`
  - `q30 = 0x26484d01300`

Final hot-callback retest at `0xbcf250` using raw snapshot + `{3,2}`:

- script:
  - `scripts/send-weixin-text-via-hot-thread-hook.py`
- target:
  - `body = autonomous-hot12`
- callback fired on the correct worker thread `688`
- the cloned callback pair carried the expected values:
  - `conversation = 27208021116@chatroom`
  - `body = autonomous-hot12`
  - `uuid = b3aa3a96-e232-4ea7-97e3-92cde69b7be0`
  - `owner_ref_a/ref_b = {3,2}`
- no proof hook observed a new task row or manager-dispatch success for
  `autonomous-hot12`
- the current evidence now rules out all three hot recurring callback sites
  from this family as sufficient autonomous contexts:
  - `0xbd3ad0`
  - `0xbd3cb0`
  - `0xbcf250`

Interpretation after Session11:

- the hot-callback family is no longer the best place to spend cycles
- the lower source/owner pair and header state are good enough for successful
  in-hook synthetic sends, but those later callbacks are still missing some
  transient top-send/builder context
- the next best branch is a lighter in-hook deferred invoke that stays much
  closer to the live `topSend -> buildOnePairRequest(...)` path, rather than
  trying to revive the send later from unrelated callback sites

Follow-up no-UI autonomous tests on the still-live Session11 process:

- direct wrapper clone replay on the same worker thread `688`
  - script mode:
    - `wrapper`
  - target body:
    - `skynet-no-ui-1`
  - result:
    - immediate `topSend` fault at `access violation accessing 0x8`
    - no new send-task row
    - no manager-dispatch success

- in-place original wrapper replay on the same worker thread `688`
  - script mode:
    - `wrapper-inplace`
  - target body:
    - `skynet-no-ui-2`
  - result:
    - `topSend` returned far enough that the first fault happened during the
      attempted string restore, not at immediate entry
    - still no new send-task row
    - still no manager-dispatch success

- in-place original wrapper replay without restore
  - script mode:
    - `wrapper-inplace-no-restore`
  - target body:
    - `skynet-no-ui-3`
  - result:
    - fault moved back inside `topSend` itself:
      `access violation accessing 0xffffffffffffffff`
    - still no new send-task row
    - still no manager-dispatch success

- detached builder retry using the exact successful synthetic pair from the
  same session
  - worker thread:
    - `688`
  - exact successful pair reused:
    - `pair = 0x2648bc91190`
    - `source = 0x2648bd979d0`
    - `send_ctx = 0x2648b4305f0`
  - target body:
    - `skynet-no-ui-4`
  - result:
    - `buildOnePairRequest(...)` still faulted with
      `access violation accessing 0x0`
    - therefore even the exact pair that already succeeded once is not enough
      after the live top-send context has gone away

Interpretation after these no-UI Session11 retests:

- the blocker is now very clearly transient execution context, not object shape
- fresh wrapper reuse is not sufficient
- exact successful lower-level pair reuse is not sufficient
- the successful autonomous path still depends on being inside the live
  top-send lifecycle, not merely on having the right source/owner/pair objects
- the next highest-value branch is to localize what transient state disappears
  between the successful in-hook synthetic call and the later detached retry,
  likely by fault-localizing the detached exact-pair call on a fresh session

## 2026-04-10 Session12/13 inner-helper localization

Fresh seeded success on PID `11980` (Session12):

- trigger `seedlower18`
- worker thread `11592`
- seed wrapper/source/owner:
  - `wrapper = 0x16fe8d1b400`
  - `source = 0x16fe7ed0cd0`
  - `owner = 0x16fe7ed0cc0`
- `send_ctx = 0x16fe6d3d7a0`
- UUID `4d201412-2b95-404b-bf7c-99d8aa230561`
- raw seed snapshot:
  - `sourceOffset = 16`
  - `conversationCap = 31`
  - raw top-send refs `{5,2}`

Fresh seeded success on PID `13320` (Session13):

- trigger `seedlower20`
- worker thread `5648`
- seed wrapper/source/owner:
  - `wrapper = 0x206b111bdb0`
  - `source = 0x206b4021390`
  - `owner = 0x206b4021380`
- `send_ctx = 0x206b1726650`
- UUID `8e177231-ec82-4186-a48e-83c04a339b16`
- proof hooks saw:
  - `seedlower20`
  - `skynet-success-2`

Successful inner-helper shape on Session13:

- real seed builder entry:
  - caller RVA `0x4d84031e`
  - mode `1`
  - builder-entry refs `{4,2}`
- successful synthetic builder entry:
  - same caller RVA `0x4d84031e`
  - mode `1`
  - builder-entry refs `{3,2}`
- successful synthetic result:
  - `q20 = 0xf`
  - `q28 = 0x206b260d680`
  - `q30 = 0x206b260d670`

Successful inner-helper trace for `skynet-success-2`:

- first `eb320`:
  - `rcx = 0x0`
  - `rdx = 0x206b0ff92b0`
  - `r8 = 0xea3bbfe3d0`
  - `r9 = 0x206b16f7758`
- first `ebec0`:
  - `rcx = 0x206b1726650`
  - `rdx = 0x206b16f7758`
  - `r8 = 0x206a81b9540`
  - `r9 = 0xea3bbfde88`
  - returns `0xf`
- second `ebec0`:
  - `rcx = 0x206b1726650`
  - `rdx = 0x206b177d310`
  - `r8 = 0x206a81b9540`
  - `r9 = 0xea3bbfece8`
  - returns `0xf`
- then a second `eb320` follows and the builder returns successfully

Detached exact-pair retry on Session12:

- reused the exact successful synthetic pair from that same session:
  - `pair = 0x16fe7d84d70`
  - `source = 0x16fe92d6c30`
  - `send_ctx = 0x16fe6d3d7a0`
- target body:
  - `skynet-no-ui-6`
- result:
  - now reaches `eb320`
  - reaches first `ebec0`
  - then faults inside `ebec0` with `access violation accessing 0x0`
- proof hooks still saw a scheduled local row for `skynet-no-ui-6`
  but no manager-dispatch success

Patched Session13 detached retries:

1. Patch first detached `ebec0` `rdx` to the successful second rich node:
   - replacement:
     - `0x206b177d310`
   - result:
     - failure shape changed from null to
       `access violation accessing 0xffffffffffffffff`
   - no task success

2. Patch first detached `ebec0` `rdx` to the successful first shallow node:
   - replacement:
     - `0x206b16f7758`
   - result:
     - first `ebec0` now returns successfully
     - returned pointer:
       - `0x206b179c8f0`
     - process then dies afterward

Interpretation after Session13:

- the detached no-UI path is now definitely making it past:
  - builder entry
  - first `eb320`
  - first `ebec0`
- the remaining missing state is therefore **after the first `ebec0` leg**
- the successful path needs at least:
  - a second `ebec0` phase with a richer `rdx` node
  - and the follow-on `eb320` phase
- the next highest-value repair is to carry the detached call through the same
  two-stage `ebec0` sequence as the successful synthetic call, rather than
  treating `ebec0` as a single-shot patch point


## 2026-04-10 Session15f stable inline-helper capture

Fresh seeded success on PID `13164`:

- trigger `seedlower28`
- worker thread `2832`
- seed wrapper/source/owner:
  - `wrapper = 0x1bfb2f02ea0`
  - `source = 0x1bfb2a76820`
  - `owner = 0x1bfb2a76810`
- `send_ctx = 0x1bfb23564d0`
- UUID `5bc64af1-c377-41fc-b7ee-e28ec75161cb`
- proof hooks saw:
  - `seedlower28`
  - `skynet-success-9`

Important improvement:

- folded `eb320` / `ebec0` helper capture into the seeded lower-send hook itself
- this stayed stable on the successful seeded path, unlike the separate helper tracer
- so this is now the preferred way to harvest live helper state on future sessions

Successful inline helper shape for `seedlower28`:

- first `eb320`:
  - `rcx = 0x0`
  - `rdx = 0x1bfac563380`
  - `r8 = 0xab487ff110`
  - `r9 = 0x1bfb2341768`
  - `rdx bytes(0x40)`:
    - `0000803f35373161b05f32b2bf0100000000000000000000000f27b2bf010000800f27b2bf010000800f27b2bf01000007000000000000000800000000000000`

- first `ebec0`:
  - `rcx = 0x1bfb23564d0`
  - `rdx = 0x1bfb2341768`
  - `r8 = 0x1bfa8b8a800`
  - `r9 = 0xab487febc8`
  - `rdx qwords`:
    - `0x0 = 0x1bfb231a4c0`
    - `0x10 = 0x14`
    - `0x18 = 0x1f`
  - `rdx bytes(0x40)`:
    - `c0a431b2bf010000000000000000000014000000000000001f000000000000000000000000000000000000000000000000000000000000000000000000000000`
  - nested `q0` pointer:
    - `0x1bfb231a4c0`
  - nested `q0 bytes(0x50)`:
    - `32373230383032313131364063686174726f6f6d00508c1b00a431b2bf01000050edeab2bf01000010ae91f754d3019032373230383032313131364063686174726f6f6d007f0000f8a431b2bf010000`

- second `eb320`:
  - `rcx = 0x1bfac39e380`
  - `rdx = 0x1bfac5633c0`
  - `r8 = 0xab487fefd0`
  - `r9 = 0xab487fee40`
  - `rdx bytes(0x40)`:
    - `0000803f656e745f906132b2bf0100000000000000000000b01027b2bf010000301127b2bf010000301127b2bf01000007000000000000000800000000000000`

- builder leave succeeded and seeded lower-send synthetic also succeeded:
  - `skynet-success-9`

Interpretation after Session15f:

- the preferred stable capture path is now:
  - seeded lower-send hook with inline helper tracing
- this gives us fresh helper node state from the exact successful synthetic lifecycle
  without destabilizing WeChat as aggressively as the separate tracer
- next detached no-UI repair should use the fresh Session15f helper state, not older
  session-local pointers


## 2026-04-10 Session15f detached no-UI repair follow-up

Fresh detached replay on the still-live Session15f process:

- process:
  - `Weixin.exe` PID `13164`
- worker thread:
  - `2832`
- fresh successful synthetic clone reused as detached template:
  - `template_source = 0x1bfb41d3370`
  - `template_owner = 0x1bfb41d3360`

Harness improvements:

- `send-weixin-text-autonomous.py` now supports:
  - `key_bytes_40`
  - `q0_bytes_50`
  inside `--ebec0-fix-json`
- this allocates a fresh `0x40` key block and fresh `0x50` nested `q0` block
  from captured raw bytes, instead of trying to reuse short-lived live pointers
- the detached harness also now supports:
  - `--owner-ref-a`
  - `--owner-ref-b`
  so builder-entry header refs can be forced explicitly

Detached try 1 on Session15f:

- target body:
  - `skynet-no-ui-15`
- patch:
  - replaced first detached `ebec0` args with the live Session15f first-call
    `r8` / `r9`
  - reused the raw live key pointer directly
- result:
  - failed because the live key pointer had already gone stale
  - `effective_key_qwords` showed garbage / unrelated memory
  - then:
    - `invoke_error`
    - `access violation accessing 0xffffffffffffffff`

Detached try 2 on Session15f:

- target body:
  - `skynet-no-ui-16`
- patch:
  - fresh allocated first `ebec0` key clone from:
    - `key_bytes_40 = c0a431b2bf010000000000000000000014000000000000001f000000000000000000000000000000000000000000000000000000000000000000000000000000`
    - `q0_bytes_50 = 32373230383032313131364063686174726f6f6d00508c1b00a431b2bf01000050edeab2bf01000010ae91f754d3019032373230383032313131364063686174726f6f6d007f0000f8a431b2bf010000`
  - still used the live Session15f:
    - `replace_r8 = 0x1bfa8b8a800`
    - `replace_r9 = 0xab487febc8`
- result:
  - detached path improved materially:
    - `pair_build_enter`
    - first `eb320`
    - `mk_pair_copy`
    - first `ebec0 enter`
    - first `ebec0 leave`
  - first detached `ebec0` now returned successfully with:
    - `retval = 0x1bfb2270f00`
  - but there was still:
    - `invoke_error`
    - `access violation accessing 0x0`
  - no send-task or manager-dispatch success for `skynet-no-ui-16`

Detached try 3 on Session15f:

- target body:
  - `skynet-no-ui-17`
- patch:
  - same fresh allocated `ebec0` key/q0 clone as try 2
  - forced builder-entry owner refs to the known good synthetic header:
    - `{3,2}`
- result:
  - detached builder entered with:
    - `owner_refs = {3,2}`
  - it again made it through:
    - first `eb320`
    - first `ebec0 enter`
    - first `ebec0 leave`
  - but this time there was no immediate explicit access-violation report;
    instead the harness ended with:
    - `final_state_error`
    - `script has been destroyed`
  - the external proof hooks still saw no:
    - send-task event
    - manager-dispatch event
    for `skynet-no-ui-17`
  - `Weixin.exe` PID `13164` had exited by the time the proof-state check ran

Interpretation after Session15f detached follow-up:

- this is real progress:
  - using a fresh allocated first `ebec0` key/q0 clone is necessary
  - forcing `{3,2}` at builder entry is healthier than leaving the detached clone at
    `{2,2}`
- the detached no-UI path is now clearly past:
  - builder entry
  - first `eb320`
  - first `ebec0`
- the remaining failure is now later than the first detached `ebec0`, and the
  successful seeded path’s next distinguishing state is likely:
  - the later nested helper phase after that first `ebec0`
  - or additional transient thread-local / builder-local state that still is not
    recreated in the detached replay


## 2026-04-10 Session16 and Session17 autonomous-send status

Session16 seeded success on PID `9056`:

- `seedlower29 -> skynet-success-10` worked cleanly again
- worker thread:
  - `6744`
- proof hooks both confirmed:
  - `send_task_event` for `skynet-success-10`
  - `manager_message_event` for `skynet-success-10`
- fresh seed-side helper shape for `seedlower29`:
  - first `ebec0`:
    - `r8 = 0x29983fb9480`
    - `r9 = 0xb6499feac8`
    - `rdx bytes(0x40) = 2028858f99020000000000000000000014000000000000001f000000000000000000000000000000000000000000000000000000000000000000000000000000`
    - nested `q0 bytes(0x50) = 32373230383032313131364063686174726f6f6d0044d6f30028858f990200008061d48e990200005d5f5cd71f830080f0eb548d99020000e0eb548d99020000309aeb8c99020000209aeb8c99020000`

Session16 detached no-UI replay:

- detached replay used:
  - fresh successful synthetic template from the same session
  - builder-entry refs `{3,2}`
  - only the fresh first seed-side `ebec0` repair
- target:
  - `skynet-no-ui-18`
- result:
  - detached builder got through:
    - builder entry
    - first `eb320`
    - first `ebec0`
  - external proof hooks saw a real delivered message:
    - `send_task_event -> skynet-no-ui-18`
    - `manager_message_event -> skynet-no-ui-18`
- this is the strongest detached no-UI success so far:
  - it shows the app can autonomously send to the target conversation with no live UI seed send in that moment
  - but the path is still not deterministic enough to claim stable general use

Session16 failed detached follow-up:

- `skynet-no-ui-19`
- tried the broader two-stage patch derived from the successful synthetic
  `skynet-success-11` trace
- result:
  - no proof-hook success
  - no `send_task_event`
  - no `manager_message_event`
- interpretation:
  - blindly copying the fuller successful synthetic sequence is not yet better
    than the narrower one-stage first-`ebec0` repair

Session17 seeded success on PID `1672`:

- `seedlower31 -> skynet-success-12` worked cleanly again
- the user sent `seedlower31` twice into two conversations; the hook captured the
  target synthetic path from the matching seed
- concrete Session17 shape from that dual-send run:
  - the seed hook captured a `filehelper -> seedlower31` send and used it to
    spawn `27208021116@chatroom -> skynet-success-12`
  - the user also sent a real `27208021116@chatroom -> seedlower31` on the same
    worker thread `5716`
  - all three rows hit the proof layers:
    - `filehelper -> seedlower31`
    - `27208021116@chatroom -> skynet-success-12`
    - `27208021116@chatroom -> seedlower31`
- interpretation:
  - the extra manual send did not poison the seed capture
  - instead, it confirms the synthetic lower-send builder call and a normal UI
    send can coexist in one live top-send cycle
- proof hooks confirmed:
  - `send_task_event` for `skynet-success-12`
  - `manager_message_event` for `skynet-success-12`

Critical new capture from Session17:

- a dedicated target-body probe traced the *successful synthetic* builder path
  for `skynet-success-12` itself, not just the seed:
  - builder entry:
    - `owner_refs = {3,2}`
  - first helper phase was:
    - `ebec0` first, with a compact inline `filehelper` key block
  - then:
    - `eb320`
    - second `ebec0` with a richer chatroom node
    - third `eb320`
    - builder leave
- this proves the successful synthetic path does *not* follow exactly the same
  helper ordering as the seed-side `seedlowerXX` path

Session17 detached no-UI failures:

- `skynet-no-ui-21`
  - used the exact Session17 successful synthetic helper sequence
  - first detached `ebec0` returned successfully
  - then still faulted with:
    - `invoke_error`
    - `access violation accessing 0x0`

- `skynet-no-ui-22`
  - reverted to the narrower one-stage first seed-side `ebec0` repair, but on
    Session17
  - first detached `ebec0` returned successfully
  - then the script was destroyed before any proof-layer success
  - no `send_task_event`
  - no `manager_message_event`

Interpretation after Session16/17:

- detached no-UI send has now been *proven possible*:
  - `skynet-no-ui-18`
- but reproducibility is still not solved:
  - Session16 no-UI success did not immediately carry over to Session17
- the seeded lower-send path remains robust and repeatable across sessions:
  - `skynet-success-10`
  - `skynet-success-11`
  - `skynet-success-12`
- the strongest current conclusion is:
  - the detached path depends on a narrow transient builder/helper state that
    sometimes survives well enough after the first detached `ebec0` and
    sometimes does not
  - the first detached `ebec0` repair is necessary, but not sufficient for
    deterministic replay


## 2026-04-10 Session18 detached no-UI success on PID `13444`

Session18 seeded success:

- `seedlower32 -> skynet-success-13` worked cleanly on:
  - main PID `13444`
  - worker thread `9608`
- proof hooks confirmed:
  - `send_task_event -> skynet-success-13`
  - `manager_message_event -> skynet-success-13`

Session18 successful synthetic builder trace (`skynet-success-13`):

- builder entry:
  - `owner_refs = {3,2}`
  - `send_ctx = 0x1964f490ea0`
- successful helper order again matched the synthetic-body path:
  - first `ebec0`
  - first `eb320`
  - second `ebec0`
  - second `eb320`
  - builder leave
- fresh synthetic-body second `ebec0` capture:
  - `replace_r8 = 0x19646248940`
  - `replace_r9 = 0x49555fe318`
  - `key_bytes_40 = d0b0195096010000000000000000000014000000000000001f000000000000000000000000000000000000000000000000000000000000000000000000000000`
  - `q0_bytes_50 = 32373230383032313131364063686174726f6f6d00ff007b00ffff000000000080da3a50960100006d1d7cdb00560290806f764896010000c0b71950960100009071f651960100008071f65196010000`

Session18 seed-side helper capture (`seedlower33`):

- same worker thread:
  - `9608`
- builder entry for the real seed:
  - `conversation = 27208021116@chatroom`
  - `body = seedlower33`
  - `owner_refs = {7,2}`
- fresh seed-side first helper phase:
  - first `eb320`
  - first `ebec0`
  - second `eb320`
  - second `ebec0`
  - builder leave
- fresh seed-side first `ebec0` capture:
  - `replace_r8 = 0x19646248940`
  - `replace_r9 = 0x49555feec8`
  - `key_bytes_40 = 5097195096010000000000000000000014000000000000001f000000000000000000000000000000000000000000000000000000000000000000000000000000`
  - `q0_bytes_50 = 32373230383032313131364063686174726f6f6d001892d000971950960100006050345096010000151f04d900ce019030fdc64e96010000000000000000000076040000000000007f04000000000000`

Session18 detached no-UI replay:

- target:
  - `skynet-no-ui-23`
- detached replay used:
  - current-session successful synthetic template:
    - `source = 0x19651e27e60`
    - `owner = 0x19651e27e50`
  - worker thread:
    - `9608`
  - builder-entry refs:
    - `{3,2}`
  - current-session live synthetic-body second `ebec0` replacement:
    - `replace_r8 = 0x19646248940`
    - `replace_r9 = 0x49555fe318`
    - `key_bytes_40 = d0b0195096010000000000000000000014000000000000001f000000000000000000000000000000000000000000000000000000000000000000000000000000`
    - `q0_bytes_50 = 32373230383032313131364063686174726f6f6d00ff007b00ffff000000000080da3a50960100006d1d7cdb00560290806f764896010000c0b71950960100009071f651960100008071f65196010000`
- detached builder still logged:
  - `pair_build_enter`
  - first `eb320`
  - first repaired `ebec0`
  - `invoke_error access violation accessing 0x0`
- but despite that explicit builder-side fault, both external proof layers saw a
  real autonomous send:
  - `send_task_event -> skynet-no-ui-23`
  - `manager_message_event -> skynet-no-ui-23`

Interpretation after Session18:

- detached no-UI autonomous send is now proven again, on a second later session:
  - `skynet-no-ui-18`
  - `skynet-no-ui-23`
- the path is still not clean:
  - the detached builder can report an access violation after the first repaired
    `ebec0`
  - yet the send can still already have been materialized and dispatched
- operationally, the capability we needed is now demonstrated:
  - We can autonomously send to an arbitrary conversation without driving the UI
  - current proven target conversation:
    - `27208021116@chatroom`


## 2026-04-10 Session19 detached follow-up on PID `5436`

Session19 seeded successes:

- `seedlower34 -> skynet-success-14` worked cleanly on:
  - main PID `5436`
  - worker thread `9628`
- `seedlower35 -> skynet-success-15` also worked cleanly on the same:
  - main PID `5436`
  - worker thread `9628`
- proof hooks confirmed both seeded synthetic sends:
  - `send_task_event`
  - `manager_message_event`

Fresh successful synthetic trace for `skynet-success-15` on Session19:

- builder entry:
  - `send_ctx = 0x12f37967d90`
  - `source = 0x12f39e04ae0`
  - `owner = 0x12f39e04ad0`
  - `owner_refs = {3,2}`
  - `mode = 1`
- helper order on the successful synthetic path:
  - first `eb320`
  - first `ebec0`
  - second `ebec0`
  - second `eb320`
  - builder leave
- fresh synthetic-body first `ebec0` capture:
  - `replace_r8 = 0x12f2daaa380`
  - `replace_r9 = 0x1dca3fdec8`
  - `key_bytes_40 = 90bf03302f010000000000000000000014000000000000001f000000000000000000000000000000000000000000000000000000000000000000000000000000`
  - `q0_bytes_50 = 32373230383032313131364063686174726f6f6d006e74000f00000000000000765f696400000000524b038b2ff40080183e382bf97f0000000000000000000001007c70652c20750a000000645f636f`
- fresh synthetic-body second `ebec0` capture:
  - `replace_r8 = 0x12f2daaa380`
  - `replace_r9 = 0x1dca3fed28`
  - `key_bytes_40 = 66696c6568656c7065720000000000000a000000000000000f000000000000000000000000000000909fe088005100885063dd382f0100004045b3392f010000`

Fresh seed-side trace for `seedlower35` on Session19:

- same worker thread:
  - `9628`
- builder entry for the real seed:
  - `conversation = filehelper`
  - `body = seedlower35`
  - `owner_refs = {7,2}`
- helper order:
  - first `eb320`
  - first `ebec0`
  - second `eb320`
  - builder leave
- fresh seed-side first `ebec0` capture:
  - `replace_r8 = 0x12f2daaa140`
  - `replace_r9 = 0x1dca3fea78`
  - `key_bytes_40 = 66696c6568656c7065720000000000000a000000000000000f000000000000000000000000000000000000000000000000000000000000000000000000000000`

Session19 detached no-UI follow-up retries:

1. Detached replay `skynet-no-ui-26`
   - used:
     - successful synthetic template:
       - `source = 0x12f39e04ae0`
       - `owner = 0x12f39e04ad0`
     - worker thread:
       - `9628`
     - builder-entry refs:
       - `{3,2}`
     - single synthetic-body first `ebec0` repair:
       - `replace_r8 = 0x12f2daaa380`
       - `replace_r9 = 0x1dca3fdec8`
       - `key_bytes_40 = 90bf03302f010000000000000000000014000000000000001f000000000000000000000000000000000000000000000000000000000000000000000000000000`
       - `q0_bytes_50 = 32373230383032313131364063686174726f6f6d006e74000f00000000000000765f696400000000524b038b2ff40080183e382bf97f0000000000000000000001007c70652c20750a000000645f636f`
   - result:
     - detached builder got through:
       - `pair_build_enter`
       - first `eb320`
       - first repaired `ebec0`
     - then:
       - `invoke_error access violation accessing 0x0`
     - no proof-layer success:
       - no `send_task_event`
       - no `manager_message_event`

2. Detached replay `skynet-no-ui-27`
   - used:
     - same successful synthetic template
     - same worker thread `9628`
     - builder-entry refs `{3,2}`
     - alternate seed-side first `ebec0` repair:
       - `replace_r8 = 0x12f2daaa140`
       - `replace_r9 = 0x1dca3fea78`
       - `key_bytes_40 = 66696c6568656c7065720000000000000a000000000000000f000000000000000000000000000000000000000000000000000000000000000000000000000000`
   - result:
     - detached builder got through:
       - `pair_build_enter`
       - first `eb320`
       - first repaired `ebec0`
     - then the script was destroyed
     - no proof-layer success:
       - no `send_task_event`
       - no `manager_message_event`

3. Planned two-step synthetic-body sequence `skynet-no-ui-28`
   - intended to replay the fresh successful synthetic Session19 helper order:
     - synthetic-body first `ebec0`
     - synthetic-body second `ebec0`
   - this did not get a live run:
     - `frida.ProcessNotFoundError`
     - main `Weixin.exe` PID `5436` had already disappeared

Interpretation after Session19:

- the detached path is still sensitive even when using fresh same-session state
- on this session, both the synthetic-body first-node fix and the seed-side
  first-node fix were insufficient to recreate a detached success
- the next highest-value move is still the fuller two-step synthetic-body
  `ebec0` sequence on a fresh live session, because that is the closest exact
  helper order to the successful seeded synthetic path on Session19


## 2026-04-10 Session20 seeded captures on PID `12472`

Session20 seeded success (`seedlower36 -> skynet-success-16`):

- main PID:
  - `12472`
- worker thread:
  - `10004`
- proof hooks confirmed:
  - `send_task_event -> skynet-success-16`
  - `manager_message_event -> skynet-success-16`

Fresh successful synthetic builder trace for `skynet-success-16`:

- builder entry:
  - `send_ctx = 0x24df883c4c0`
  - `source = 0x24dfa6fe960`
  - `owner = 0x24dfa6fe950`
  - `owner_refs = {3,2}`
  - `mode = 1`
  - `caller_rva = 0xffffffffceed7ca1`
- `result_post_qwords` on successful leave:
  - `0x20 = 0xf`
  - `0x28 = 0x24dfae28710`
  - `0x30 = 0x24dfae28700`

Fresh Session20 seed capture (`seedlower37`) before corruption:

- same worker thread:
  - `10004`
- seed hook captured:
  - `wrapper = 0x24df8919190`
  - `sourceObj = 0x24dfa871d80`
  - `ownerBase = 0x24dfa871d70`
  - `conversation = filehelper`
  - `body = seedlower37`
  - `uuid = ec40147d-3b94-4f4d-aadf-a669321ef5d1`
  - `ownerRefA = 5`
  - `ownerRefB = 2`
- seeded lower-send hook also proved:
  - `skynet-success-17`

Fresh Session20 helper order from `probe-weixin-send-builder-inner.py`:

For real seed `seedlower37`:

- helper order:
  - first `eb320`
  - first `ebec0`
  - second `eb320`
  - builder leave
- first `ebec0` was again the inline `filehelper` shape:
  - `key_s0 = filehelper`
  - `r8`/`r9` not yet harvested from this probe, but the node remained the
    shallow inline filehelper form

For successful synthetic `skynet-success-17`:

- builder entry:
  - `conversation = 27208021116@chatroom`
  - `body = skynet-success-17`
  - `owner_refs = {3,2}`
  - `caller_rva = 0x4d47031e`
- helper order seen before the session corrupted:
  - first `eb320`
  - first `ebec0`
- fresh first synthetic-body `ebec0` node on this session:
  - `key_ptr = 0x24df8942178`
  - `key_s0 = 27208021116@chatroom`
  - `key_node.ptr = 0x24df8844db0`
  - `key_node.qwords`
    - `0x18 = 0x24df95ef090`
    - `0x20 = 0x24df95ef080`
    - `0x28 = 0x80001500443a5075`
    - `0x30 = 0x7453206e69676542`
    - `0x38 = 0x4d646e6553747261`
  - builder state:
    - `0x90 = 0x24df85f0c30`
    - `0x98 = 0x24df8847780`
    - `0xa0 = 0x24df8847770`
    - `0xb0 = 0x24df8834790`

Session20 outcome:

- the session corrupted before the inner helper probe could finish the full
  `skynet-success-17` sequence
- but we did recover the new session-local first synthetic-body `ebec0` node
  and a fresh seeded lower-send template on worker thread `10004`
- after that corruption, the main visible WeChat process rolled from:
  - `12472`
  to:
  - `1752`

Interpretation after Session20:

- the fresh `seedlower37` capture is still useful even though the session died
- we now have another fresh same-session synthetic-body first-node anchor for
  the next detached no-UI retry
- before the next detached replay, all hooks must be rearmed on the new live
  PID instead of reusing the dead `12472` process


## 2026-04-10 Session21 stable seeded send on PID `3908`

To reduce corruption, the active setup on this session was intentionally
lightened to just:

- seeded lower-send hook
- send-task proof hook
- manager-dispatch proof hook

The hot inner-helper tracer was not left attached during the final seeded run.

Session21 seeded success (`seedlower43 -> skynet-success-23`):

- main PID:
  - `3908`
- worker thread:
  - `14216`
- fresh seed capture:
  - `wrapper = 0x2ba87fce470`
  - `sourceObj = 0x2ba8a297bb0`
  - `ownerBase = 0x2ba8a297ba0`
  - `conversation = filehelper`
  - `body = seedlower43`
  - `uuid = 639095d3-8500-4482-8b93-3ba63a728ba7`
  - `ownerRefA = 5`
  - `ownerRefB = 2`
- successful builder-only synthetic clone:
  - `owner_clone = 0x2ba8a243910`
  - `source_clone = 0x2ba8a243920`
  - `pair_buf = 0x2ba89346f20`
  - `send_ctx = 0x2ba880eb940`
  - `b78 = 0x2ba81c87770`
  - `conversation = 27208021116@chatroom`
  - `body = skynet-success-23`

Proof hooks for Session21:

- send-task hook:
  - `filehelper -> seedlower43`
  - `27208021116@chatroom -> skynet-success-23`
- manager-dispatch hook:
  - `filehelper -> seedlower43`
  - `27208021116@chatroom -> skynet-success-23`

Session21 outcome:

- seeded arbitrary send is still healthy on a clean session
- the lighter hook set appears materially more stable than the heavier
  tracer mix used in the previous sessions
- this session gave a fresh proven template for any next detached no-UI retry

Interpretation after Session21:

- the stable milestone remains:
  - seeded synthetic send to an arbitrary conversation
- the unresolved milestone remains:
  - fully detached no-UI send without any seed message
- if detached replay is retried from this point, it should start from the
  fresh Session21 template rather than any older helper-state capture


## 2026-04-10 Session22 seeded successes and sharper detached boundary on PID `6492`

This session stayed healthier with the lighter setup:

- send-task proof hook
- manager-dispatch proof hook
- seeded lower-send hook
- and later, a fresh inner-helper tracer

### Session22 seeded success (`seedlower50 -> skynet-success-30`)

- main PID:
  - `6492`
- worker thread:
  - `10808`
- fresh seed capture:
  - `wrapper = 0x27357da4e00`
  - `sourceObj = 0x27356b0c210`
  - `ownerBase = 0x27356b0c200`
  - `conversation = filehelper`
  - `body = seedlower50`
  - `uuid = 1b1c6668-8fb4-4c0b-aae2-e513ab305ebd`
  - `ownerRefA = 5`
  - `ownerRefB = 2`
- successful builder-only synthetic clone:
  - `owner_clone = 0x27357a44cf0`
  - `source_clone = 0x27357a44d00`
  - `pair_buf = 0x27357737eb0`
  - `send_ctx = 0x27357099310`
  - `b78 = 0x273570626a0`
  - `conversation = 27208021116@chatroom`
  - `body = skynet-success-30`

Proof hooks for `seedlower50`:

- send-task hook:
  - `filehelper -> seedlower50`
  - `27208021116@chatroom -> skynet-success-30`
- manager-dispatch hook:
  - `filehelper -> seedlower50`
  - `27208021116@chatroom -> skynet-success-30`

### Session22 seeded success with full helper trace (`seedlower51 -> skynet-success-31`)

- same main PID:
  - `6492`
- same worker thread:
  - `10808`
- fresh seed capture:
  - `wrapper = 0x2734f1ab060`
  - `sourceObj = 0x27357bf5040`
  - `ownerBase = 0x27357bf5030`
  - `conversation = filehelper`
  - `body = seedlower51`
  - `uuid = e802cd85-da5d-4422-8f51-0351aa1c0b6f`
  - `ownerRefA = 5`
  - `ownerRefB = 2`
- successful builder-only synthetic clone:
  - `owner_clone = 0x273596a5a50`
  - `source_clone = 0x273596a5a60`
  - `pair_buf = 0x2735914ba00`
  - `send_ctx = 0x27357099310`
  - `b78 = 0x273570626a0`
  - `conversation = 27208021116@chatroom`
  - `body = skynet-success-31`

Proof hooks for `seedlower51`:

- send-task hook:
  - `filehelper -> seedlower51`
  - `27208021116@chatroom -> skynet-success-31`
- manager-dispatch hook:
  - `filehelper -> seedlower51`
  - `27208021116@chatroom -> skynet-success-31`

Fresh full helper order for successful synthetic `skynet-success-31`:

- builder entry:
  - `conversation = 27208021116@chatroom`
  - `body = skynet-success-31`
  - `owner_refs = {3,2}`
  - `caller_rva = 0xfffffffff08c7ca1`
- helper order:
  - first `eb320`
  - first `ebec0`
  - second `ebec0`
  - second `eb320`
  - builder leave

First synthetic-body `ebec0` on this session:

- `r8 = 0x2734d22b1c0`
- `r9 = 0x8b6a7fdea8`
- `key_ptr = 0x273571603c8`
- `key_qwords`
  - `q0 = 0x2735715a9c0`
  - `q8 = 0x0`
  - `q10 = 0x14`
  - `q18 = 0x1f`
- `key_node.ptr = 0x2735715a9c0`
- `key_node.qwords`
  - `0x0 = 0x3132303830323732`
  - `0x8 = 0x7461686340363131`
  - `0x10 = 0x383537006d6f6f72`
  - `0x18 = 0x38325f3133333232`
  - `0x20 = 0x2735805b530`
  - `0x28 = 0x80001200478b2479`
  - `0x30 = 0x16d7a7dc53672748`
  - `0x38 = 0x130f701d06ecf47e`
  - `0x40 = 0x9359bd4718686fa1`
  - `0x48 = 0x0`

Second synthetic-body `ebec0` on this session:

- `r8 = 0x2734d22b4c0`
- `r9 = 0x8b6a7fed08`
- `key_ptr = 0x273596af5e0`
- `key_qwords`
  - `q0 = 0x27356fc8740`
  - `q8 = 0x0`
  - `q10 = 0x14`
  - `q18 = 0x1f`
- `key_node.ptr = 0x27356fc8740`
- `key_node.qwords`
  - `0x0 = 0x3132303830323732`
  - `0x8 = 0x7461686340363131`
  - `0x10 = 0x6d6f6f72`
  - `0x18 = 0x0f`
  - `0x20 = 0x273000003c4`
  - `0x28 = 0x9000a8004657b691`
  - `0x30 = 0x27356fc82f0`
  - `0x38 = 0x27356fc8950`
  - `0x40 = 0x273592f2d20`
  - `0x48 = 0x273592f2d10`

### Session22 detached no-UI replay failure (`skynet-no-ui-39`)

Detached replay used:

- current-session successful synthetic template:
  - `source = 0x273596a5a60`
  - `owner = 0x273596a5a50`
- worker thread:
  - `10808`
- builder-entry refs:
  - requested `{3,2}`
  - effective entry still came in as `{7,2}`
- first detached repair used the fresh Session22 first synthetic-body `ebec0`
  values:
  - `replace_r8 = 0x2734d22b1c0`
  - `replace_r9 = 0x8b6a7fdea8`
  - cloned `key_bytes_40`
  - cloned `q0_bytes_50`
- target:
  - `skynet-no-ui-39`

Result:

- detached replay got through:
  - builder entry
  - first `eb320`
  - first repaired `ebec0` entry
- but it failed immediately inside that first repaired detached `ebec0` with:
  - `invoke_error access violation accessing 0x2735bd5d000`
- no proof-layer success:
  - no `send_task_event -> skynet-no-ui-39`
  - no `manager_message_event -> skynet-no-ui-39`

Interpretation after Session22:

- the seeded arbitrary-send path remains robust on clean sessions:
  - `skynet-success-30`
  - `skynet-success-31`
- the fresh Session22 helper trace is better than the older captures because it
  includes the full successful synthetic helper sequence on one still-live
  session
- the detached replay failure is now narrower again:
  - it is no longer obviously dying on stale session-local pointers
  - it is now dying while traversing the first cloned `ebec0` node itself
- the next repair target is therefore the internal layout of the cloned
  detached `q0`/node blob for the first `ebec0`, not the outer builder path

### Session23 seed + detached retries on `PID 7076`

Fresh clean session:

- main `Weixin.exe` PID:
  - `7076`
- worker thread for the live send path:
  - `11844`

Seeded arbitrary send still works on this session:

- trigger:
  - `seedlower57`
- seeded synthetic success:
  - `skynet-success-37`
- both proof layers saw success:
  - `send_task_event -> skynet-success-37`
  - `manager_message_event -> skynet-success-37`

Fresh session-local seed/original state:

- wrapper:
  - `0x22468423c80`
- original seed source:
  - `0x2246704b680`
- original seed owner:
  - `0x2246704b670`
- successful synthetic clone source:
  - `0x224684887f0`
- successful synthetic clone owner:
  - `0x224684887e0`
- send context:
  - `0x22466b4ca50`
- `b78`:
  - `0x22466b047e0`

Successful seeded synthetic helper sequence on this session:

- first hidden `ebec0` is still `filehelper`-like, not `272...`
  - key qwords:
    - `q0 = 0x706c6568656c6966`
    - `q8 = 0x7265`
    - `q10 = 0xa`
    - `q18 = 0xf`
  - leave:
    - `0x22466b791a0`
- next synthetic-body `ebec0` node:
  - `key_ptr = 0x22466c15bc8`
  - `key_node.ptr = 0x22466c25e90`
  - important qwords:
    - `0x18 = 0x22466c25e98`
    - `0x20 = 0x22466c0b1b0`
    - `0x28 = 0x80012e0014a20d55`
    - `0x30 = 0x0`
    - `0x38 = 0x22466c25ec0`
    - `0x40 = 0x672f34330032316c`
    - `0x48 = 0x20070756f72`
- later synthetic-body `ebec0` node:
  - `key_ptr = 0x22467cd08c0`
  - `key_node.ptr = 0x22467265b70`
  - important qwords:
    - `0x18 = 0x3737315f6d6f6f72`
    - `0x20 = 0x80`
    - `0x28 = 0x90001b00177a4d07`
    - `0x30 = 0x6566795f64697877`
    - `0x38 = 0x69356534356d6733`
    - `0x40 = 0x3634370032316c`
    - `0x48 = 0x303a646165726e00`

Detached no-UI retries on this same session:

1. `skynet-no-ui-45`

- used the fresh Session23 successful synthetic clone as template
- used the Session23 synthetic-body node bytes for the first repaired detached
  `ebec0`
- result:
  - got through:
    - builder entry
    - first `eb320`
    - first repaired detached `ebec0`
  - but first detached `ebec0` still returned `0x1`
  - then faulted with:
    - `invoke_error access violation accessing 0x0`
  - no proof-layer success:
    - no `send_task_event -> skynet-no-ui-45`
    - no `manager_message_event -> skynet-no-ui-45`

2. `skynet-no-ui-46`

- same as above, but with explicit Session23 live pointer-field overrides for
  the first and second synthetic-body `ebec0` nodes:
  - first node:
    - `q18 = 0x22466c25e98`
    - `q20 = 0x22466c0b1b0`
    - `q28 = 0x80012e0014a20d55`
    - `q30 = 0x0`
    - `q38 = 0x22466c25ec0`
    - `q40 = 0x672f34330032316c`
    - `q48 = 0x20070756f72`
  - second node:
    - `q18 = 0x3737315f6d6f6f72`
    - `q20 = 0x80`
    - `q28 = 0x90001b00177a4d07`
    - `q30 = 0x6566795f64697877`
    - `q38 = 0x69356534356d6733`
    - `q40 = 0x3634370032316c`
    - `q48 = 0x303a646165726e00`
- result:
  - first repaired detached `ebec0` now leaves with `0x1`
  - still faults later with:
    - `invoke_error access violation accessing 0x0`
  - no proof-layer success

3. `skynet-no-ui-47`

- switched the first detached `ebec0` repair to match the successful hidden
  `filehelper`-like first stage instead of forcing a `272...` node first
- exact first-step `key_bytes_40`:
  - inline `filehelper` string
  - `len = 0xa`
  - `cap = 0xf`
- second and third steps remained the fresh Session23 synthetic-body node
  repairs
- result:
  - first detached `ebec0` now matches the successful seeded path much more
    closely:
    - effective key qwords are the inline `filehelper` layout
    - first detached `ebec0_leave = 0x22466b791a0`
  - but the process/script still dies before any detached task or manager
    success is observed
  - no proof-layer success:
    - no `send_task_event -> skynet-no-ui-47`
    - no `manager_message_event -> skynet-no-ui-47`

Interpretation after Session23:

- this was real progress:
  - the detached path now reproduces the successful seeded first hidden
    `ebec0` stage much more faithfully than before
  - specifically, the inline `filehelper` first-stage repair is materially
    better than forcing a `272...` node immediately
- the remaining gap is now after that first detached hidden-stage `ebec0`
  succeeds
- the next repair target is the detached continuation after that first
  hidden-stage `ebec0`, likely one of:
  - the transition into the synthetic-body `272...` stage
  - the subsequent `eb320`
  - or later continuation state that is still not being recreated after the
    first successful detached `filehelper`-style `ebec0`
