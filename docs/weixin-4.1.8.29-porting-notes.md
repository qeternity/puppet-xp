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
