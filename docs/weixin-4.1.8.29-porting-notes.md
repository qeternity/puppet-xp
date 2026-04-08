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
  - user-confirmed vanity id + display name pairing
  - also supported by a packed memory artifact:
    - `wxid_yfe3gm54e5il12zumalabsChase`

Additional row-derived IDs recovered from the same path:

- `wxid_ulr3oq29ruo312`
  - recovered from row `12`
  - likely the Max Nijhawan contact with a vanity display name
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
  - vanity id: `zumalabs`
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
- `wxid_yfe3gm54e5il12 -> Chase` with vanity `zumalabs`
- `wxid_3a40v7q8y4kk12 -> Glenn`
- `wxid_cdxvsfdqlbqw22 -> Adam - Arrow FFAs`
- `wxid_jh7tgf4ggsgs22 -> Heng Chen 陳亨`
- `wxid_shj82mm92ok622 -> Oli`
- `wxid_ulr3oq29ruo312 -> Max Nijhawan` with vanity `MNijhawan9`
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
