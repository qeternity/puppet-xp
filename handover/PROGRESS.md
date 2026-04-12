# Detached No-UI Send Progress

Date: 2026-04-11
Target: Weixin 4.1.8.29
Objective: fully detached, no UI, no user interaction text send

## Executive Summary

We do not have a working detached send yet.

The current state is:

- Live UI-assisted send paths are instrumented and understood much better than before.
- Good live wrapper/template capture is working.
- Same-session replay using a captured live-good template is working well enough to enter the detached caller on some threads.
- Execution context is still the dominant blocker.
- Some threads crash immediately.
- Some threads enter the detached path and then wedge the send pipeline.
- The latest evidence suggests our heavy hot-path Frida tracing was itself perturbing execution on the best candidate thread, so the script has been changed to default to a lower-noise detached tracing mode.

## Important Files

- [C:\Users\Administrator\Code\puppet-xp\scripts\weixin_418_detached_send.py](C:\Users\Administrator\Code\puppet-xp\scripts\weixin_418_detached_send.py)
- [C:\Users\Administrator\Code\puppet-xp\scripts\weixin_418_capture_good_template.py](C:\Users\Administrator\Code\puppet-xp\scripts\weixin_418_capture_good_template.py)
- [C:\Users\Administrator\Code\puppet-xp\handover\MASTER.md](C:\Users\Administrator\Code\puppet-xp\handover\MASTER.md)

Most useful logs from this session:

- [C:\Users\Administrator\Code\puppet-xp\handover\capture-live-20260411-215315.out](C:\Users\Administrator\Code\puppet-xp\handover\capture-live-20260411-215315.out)
- [C:\Users\Administrator\Code\puppet-xp\handover\captured-same-session-20260411-2201.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-same-session-20260411-2201.err)
- [C:\Users\Administrator\Code\puppet-xp\handover\captured-thread2124-20260411-2211.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-thread2124-20260411-2211.err)
- [C:\Users\Administrator\Code\puppet-xp\handover\captured-thread7400-20260411-2216.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-thread7400-20260411-2216.err)
- [C:\Users\Administrator\Code\puppet-xp\handover\captured-thread8808-20260411-2220.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-thread8808-20260411-2220.err)
- [C:\Users\Administrator\Code\puppet-xp\handover\captured-thread8808-seeded-20260411-2224.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-thread8808-seeded-20260411-2224.err)

## What Is Known To Work

- Self metadata extraction.
- Contact mapping.
- Conversation enumeration.
- Message-row extraction.
- Manager-level message event monitoring.
- Seeded arbitrary send through the live client path.
- Live-good wrapper/template capture from a real UI send.

## Key Reverse-Engineering Findings

### Good finalize-stage object shape

The most stable good path signature found so far is the post-`ebec0` object shape used by `workerFinalize`.

Important fields on the good stage object:

- `typePtr = 0x7fface853808` family
- `ownerRefA = 3`
- `ownerRefB = 2`

This good shape was observed clearly in:

- [C:\Users\Administrator\Code\puppet-xp\handover\capture-live-20260411-215315.out](C:\Users\Administrator\Code\puppet-xp\handover\capture-live-20260411-215315.out)

Other observed stage shapes such as `{2,2}`, `{1,2}`, or clearly corrupt values appear later in the same pipelines and should not be treated as the canonical good source.

### Good wrapper/template capture

Same-session live-good capture is working.

Example:

- In [C:\Users\Administrator\Code\puppet-xp\handover\captured-same-session-20260411-2201.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-same-session-20260411-2201.err)
  - captured thread: `4304`
  - wrapper: `0x2066cf85290`
  - object: `0x2066cf852a0`
  - template region: `0x2066cf85378`

This solved the stale-wrapper problem. We no longer need to rely on old wrapper addresses from past sessions.

### Detached caller structure

`FUN_1815b1350` is the important detached entry (`entryB`).

The most useful disassembly facts:

- It constructs a seed object with `FUN_1815b1c80`
- It copies/normalizes into the request region with `FUN_1815b20b0`
- It fetches a pair via `FUN_180020800`
- It immediately copies out a pair via `FUN_1802fbff0`
- It normalizes that through `FUN_180633270`
- It dispatches further through `FUN_1815ea920`

Static disassembly of `FUN_1815b1350` shows:

- `FUN_180020800` call at `0x1815b14a3`
- `FUN_1802fbff0` call at `0x1815b14b4`
- `FUN_180633270` call at `0x1815b14c5`
- `FUN_1815ea920` call at `0x1815b1517`

### Crash site already identified

`FUN_1802fbff0` is a real crash point on bad threads.

Ghidra decompilation shows:

- it writes `*param_2 = 0`
- then dereferences `param_1 + 0x30`
- so if `param_1 == 0`, it faults immediately

This explains the fast failure seen on some candidate threads.

## Most Important Live Attempts

### 1. Same-session replay on captured thread 4304

Log:

- [C:\Users\Administrator\Code\puppet-xp\handover\captured-same-session-20260411-2201.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-same-session-20260411-2201.err)

What happened:

- good template capture succeeded
- detached replay launched on the exact captured thread
- replay reached `detached-runonthread-enter`
- request region looked populated
- replay never reached the deeper entry hooks in a useful way
- Frida script was destroyed while waiting

Conclusion:

- stale wrapper reuse was fixed
- execution context remained the blocker

### 2. Candidate thread 2124

Log:

- [C:\Users\Administrator\Code\puppet-xp\handover\captured-thread2124-20260411-2211.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-thread2124-20260411-2211.err)

What happened:

- good template capture succeeded on thread `2124`
- detached replay on `2124` reached:
  - `detached-runonthread-enter`
  - `detached-native-entry-call`
  - `detached-caller-enter`
- this was the first clear breakthrough showing detached replay genuinely crossing into `entryB`

Conclusion:

- thread choice matters materially
- not all worker-looking threads are equal

### 3. Candidate thread 7400 on PID 2628

Log:

- [C:\Users\Administrator\Code\puppet-xp\handover\captured-thread7400-20260411-2216.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-thread7400-20260411-2216.err)

What happened:

- timeout/session-detach issue was already fixed by this point
- replay now reported a real native failure instead of losing the agent
- `entryB` failed with:
  - `Error: access violation accessing 0x0`

Important observation:

- `detached-native-entry-error` fired
- `detached-caller-enter` did not

Conclusion:

- thread `7400` is a bad execution context
- the crash happens before meaningful detached progression

### 4. Candidate thread 8808 on PID 2628

Log:

- [C:\Users\Administrator\Code\puppet-xp\handover\captured-thread8808-20260411-2220.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-thread8808-20260411-2220.err)

What happened:

- live-good template capture succeeded on thread `8808`
- detached replay on `8808` reached:
  - `detached-runonthread-enter`
  - `detached-native-entry-call`
  - `detached-caller-enter`
  - `detached-seed-ctor-leave`
  - `detached-seed-copy-leave`
  - `thread-pair-fetch-enter`
  - `thread-pair-fetch-leave`
- after that, the detached send wedged
- the UI showed the seed stuck with a sending spinner

Important conclusion:

- `8808` is better than `7400`
- but the path wedges immediately after `threadPairFetch`
- static `entryB` says the next step should be `FUN_1802fbff0` then `FUN_180633270`
- because the live trace stopped exactly after our `thread-pair-fetch-leave` hook, the hook load itself became the prime suspect

### 5. Seeded retry with explicit request self/nickname/alias

Log:

- [C:\Users\Administrator\Code\puppet-xp\handover\captured-thread8808-seeded-20260411-2224.err](C:\Users\Administrator\Code\puppet-xp\handover\captured-thread8808-seeded-20260411-2224.err)

What happened:

- by then the WeChat process was already in a bad wedged state
- even the live-good template capture timed out

Conclusion:

- once a bad detached replay wedges the send path, that process should be discarded
- do not keep piling more attempts onto a poisoned process

## Script Changes Made This Session

All changes were in:

- [C:\Users\Administrator\Code\puppet-xp\scripts\weixin_418_detached_send.py](C:\Users\Administrator\Code\puppet-xp\scripts\weixin_418_detached_send.py)

And one helper script already added earlier:

- [C:\Users\Administrator\Code\puppet-xp\scripts\weixin_418_capture_good_template.py](C:\Users\Administrator\Code\puppet-xp\scripts\weixin_418_capture_good_template.py)

### Changes made

- Added safer capture-only workflow via `weixin_418_capture_good_template.py`
- Added better finalize tracing for captured live-good sessions
- Auto-adopted `capturedThreadId` when replaying with `--swap-with-captured-template`
- Added `detached-native-entry-call`
- Added `detached-native-entry-return`
- Added `detached-native-entry-error`
- Wrapped hot hooks in `guardHook(...)` so hook exceptions log `hook-error` instead of killing the Frida script
- Replaced risky `readRcPair(...)` usage with `safeReadRcPair(...)` in multiple detached hooks
- Added configurable `--run-timeout-ms`
- Removed the old hard-coded 5-second detached wait
- Added automatic self wxid seeding into the detached request region when explicit `--request-self-username` is not passed
- Began introducing a lower-noise detached tracing mode by default for the hottest `entryB` path hooks

### Why these changes mattered

- The Frida script was previously being destroyed mid-run.
- After hardening, failures turned into real native results instead of tooling artifacts.
- The 5-second wait had been prematurely tearing down detached callbacks.
- The request region on some runs had malformed self fields.
- The heaviest hook set is now suspected of perturbing the best candidate detached thread.

## Current Best Hypotheses

### 1. Execution thread is still the main variable

This remains the strongest overall conclusion.

- Some threads crash immediately.
- Some enter `entryB`.
- Some enter `entryB` and wedge later.

### 2. Heavy hot-path tracing can perturb `entryB`

This is now a very strong suspicion.

Reason:

- On thread `8808`, detached replay progressed further than on bad threads.
- Static `entryB` says it should continue into `FUN_1802fbff0` right after `threadPairFetch`.
- In practice, the live trace stopped after the `thread-pair-fetch-leave` hook.
- That makes the hook load itself suspect.

### 3. Request self context matters

The detached request region should not be left with empty or malformed self fields.

Earlier better-shaped request regions included:

- self wxid in the `+0x10` and `+0x50` string slots
- nickname at `+0x2a0`
- alias at `+0x300`

Known-good example values from earlier runs:

- self: `wxid_yfe3gm54e5il12`
- nickname: `Chase`
- alias: `zumalabs`

### 4. A wedged process should be abandoned quickly

Once detached replay poisons the send state:

- the UI seed may stick with a spinner
- later captures may stop working
- the process is no longer a trustworthy testbed

Killing all `Weixin.exe` processes and relaunching is the right reset.

### 5. Frida exception handling is now part of the observed failure mode

This is a newer correction to the earlier "entryB is the choke point" framing.

What changed:

- Forcing explicit detached request self-context made the request surface match prior good traces:
  - self wxid at `+0x10` and `+0x50`
  - nickname at `+0x2a0`
  - alias at `+0x300`
- With that fix in place, failure moved later.

New evidence:

- A deep-trace run on captured thread `5460` showed:
  - `detached-native-entry-call`
  - `detached-native-entry-return`
  - then a client crash
- That means `entryB` itself can complete.
- The deep-trace crash was attributed by Windows Error Reporting to `frida-agent.dll`, not `Weixin.dll`.

Low-noise explicit-self runs then showed a second important effect:

- On thread `8552`, detached replay reached:
  - `worker-entry-enter`
  - `detached-swap-check`
  - `detached-pair-swapped`
- After that, Frida reported `Error: system error`, but the `Weixin` process itself stayed alive.
- The logged native exceptions were inside `Weixin.exe` C++/UI Automation paths such as:
  - `CxxThrowException`
  - `UiaNodeFromHandle`
  - `UiaRaiseAutomationPropertyChangedEvent`

Interpretation:

- some of the current "detached failed" signals are likely Frida's handling of first-chance/internal exceptions, not necessarily a hard failure inside the detached send path itself
- the true remaining blocker is now somewhere in the post-swap / post-`entryB` async path, with Frida exception policy affecting observability

## Current Environment At Time Of Writing

This section has been corrected from the earlier stale PID `9568` snapshot.

Latest meaningful live session during this pass:

- visible main host PID `6820`
- main window title `File Transfer`
- helper/background `Weixin` PIDs also existed:
  - `844`
  - `1972`
  - `4680`

Latest useful captured worker threads:

- `9688`
  - explicit-self run showed better-shaped detached request region
  - stalled after `detached-native-entry-call`
- `5460`
  - deep-trace run showed `detached-native-entry-return`
  - then the client crashed, with WER blaming `frida-agent.dll`
- `8552`
  - low-noise explicit-self run reached `worker-entry` and `detached-pair-swapped`
  - then Frida surfaced `Error: system error` while `Weixin` stayed alive

UI state at the very end:

- `File Transfer` is still open
- manual UI seed `trace-seed-2313` is visible and stuck spinning
- the session should be treated as tainted and restarted before the next serious replay attempt

Newest useful logs from this pass:

- `captured-thread-self-20260411-2303.err`
  - explicit self metadata fixed detached request shape
- `captured-thread-self-deep-20260411-2307.err`
  - `entryB` returned, then the client crashed
- `captured-thread-self-low-20260411-2311.err`
  - low-noise run reached swap and then surfaced Frida `system error`
- `captured-thread-propagate-20260411-2313.err`
  - `exceptions: \"propagate\"` removed the immediate JS-side fatal, but the run later hung

## Recommended Next Steps

### Immediate next move

Restart `Weixin` again from the currently tainted `6820` session and re-run the same-session captured-template flow with:

- lower-noise hooks by default
- explicit request self-context
- `NativeFunction(..., { exceptions: \"propagate\" })`

Do not continue from the currently wedged spinner state.

### Best test plan

1. Confirm WeChat is in a clean `File Transfer` chat with a working text box.
2. Start a fresh detached sender session on the new visible host PID with:
   - `--wait-for-good-template filehelper`
   - `--use-captured-template-region`
   - `--swap-with-captured-template`
   - `--run-timeout-ms 70000`
   - `--request-self-username wxid_yfe3gm54e5il12`
   - `--request-nickname Chase`
   - `--request-alias zumalabs`
3. Prefer the captured thread first if the process is clean.
4. Keep `exceptions: "propagate"` in place while testing this path; `exceptions: "steal"` was turning Weixin internal exceptions into JS-side fatal failures.
5. If the run still wedges, let it sit long enough to determine whether it:
   - returns cleanly later
   - hangs with a spinner
   - crashes the client
6. Only re-enable `--deep-trace` for one-shot confirmation after a fresh restart, because it increases the risk of a Frida-agent crash.
7. If the captured thread still fails, test one alternate candidate thread on the fresh process.

### If the next run reaches further

The next useful milestones to watch for are:

- `detached-native-entry-return`
- a detached body actually appearing in `File Transfer`
- successful completion without:
  - `frida-agent.dll` crash
  - Frida `system error`
  - permanent UI spinner

### If the next run still fails after `detached-pair-swapped`

Then the next job is no longer "get into `entryB`". It is to understand the post-swap / post-return path and its interaction with Weixin UIA/C++ exceptions.

The next investigations should focus on:

- whether the exception handler should ignore or specially classify the UIA/C++ first-chance exceptions now seen in logs
- whether the detached send can be driven on a thread/context that does not trigger the same UIA path
- whether a later async completion path needs different state than the currently cloned captured wrapper provides

Use:

- coarse entry / return logging
- swap-point logging
- UI outcome
- Windows crash records

and avoid returning to heavy hot-path tracing except for brief targeted probes.

## Bottom Line

The project is not stuck at zero.

We now know:

- live-good capture works
- same-session replay works far enough to reach captured-thread detached execution on good candidate threads
- bad threads fail fast and can be excluded
- explicit detached self metadata was a real issue and is now corrected in testing
- `entryB` is not the final choke point; it can return
- heavy hot-path tracing can still perturb the run and even crash through `frida-agent.dll`
- Frida exception policy materially changes observed failures
- the remaining blocker is now after the swap / after `entryB`, in the later async path or in how first-chance Weixin exceptions are being handled during detached replay

The next run should be done on a fresh process with:

- the quieter hook set
- explicit detached self metadata
- `exceptions: "propagate"`

## Update 2026-04-11 23:44 +01:00

Additional progress from the next autonomous pass:

- active visible host was `3020` with main window title `File Transfer`
- Ghidra MCP and Windows MCP were both working during this pass
- the `File Transfer` edit control remained discoverable as UI-tree element `90`

### Desktop seed-path status

The main blocker in this pass was not detached replay itself. It was generating a fresh live-good seed on the restarted host.

Attempts that did **not** produce a new visible `File Transfer` seed message:

- Windows MCP `Type` into element `90`
- shell `WScript.Shell` `SendKeys`
- direct Win32 `WM_CHAR` posting to the visible Weixin Qt child window

Important observation:

- UIA can still report `File Transfer|Edit|Enter` as focused even when these injection paths do not actually deliver text into the chat box
- this means desktop/UI automation seeding is currently unreliable on this host/session and should not be trusted as the only way to generate the next live-good capture

### Detached runner changes made in this pass

`C:\Users\Administrator\Code\puppet-xp\scripts\weixin_418_detached_send.py` was improved in several concrete ways:

- fixed the exception-handler architecture so there is now only one active `Process.setExceptionHandler`
- narrowed exception reporting to the actual detached replay thread instead of every armed capture state
- deduplicates repeated exception signatures inside a short time window
- keeps short backtraces on emitted detached exceptions
- added tail-region inspection to `inspectOuter`
- added an opt-in `--seed-tail-from-seed-template` mode

The duplicate exception-handler fix was important:

- an older second `Process.setExceptionHandler` later in the script was overriding the newer filtered one
- after removing that override, a short capture-only smoke test became quiet again and only emitted the final timeout JSON

### New static RE finding: caller tail at `+0x390` is probably material

This pass produced one of the strongest new static findings so far.

`FUN_1815b1350` decompiled cleanly enough to confirm:

- it still performs the expected sequence:
  - `FUN_1815b1c80`
  - `FUN_1815b20b0`
  - `FUN_180020800`
  - `FUN_1802fbff0`
  - `FUN_180633270`
  - `FUN_1815ea920`
- after the main path, it allocates a follow-on async object and copies state from `param_1 + 0x390`
- that means detached replay correctness depends on more than the copied request region at `param_1 + 8`

`FUN_1802fbff0` also decompiled cleanly and confirmed the null-deref behavior seen dynamically:

- it only copies `{ +0x28, +0x30 }` out of the fetched pair-like object
- if the incoming object pointer itself is invalid, this helper crashes immediately

Most importantly, `FUN_180038880` decompiled and shows what the `+0x390` tail really is:

- it clones a structured block, not just raw padding
- it copies the leading pair fields
- then conditionally clones owned sub-objects from slots:
  - `0x48` / qword index `0x9`
  - `0x88` / qword index `0x11`
  - `0xc8` / qword index `0x19`
- and it also carries ref-counted state at:
  - `0xd8` / qword index `0x1b`
  - `0xe0` / qword index `0x1c`

Interpretation:

- leaving `caller + 0x390` fully zeroed is now a much stronger suspected cause of post-return / late-async failure
- the detached request region alone is not sufficient

### Why `--seed-tail-from-seed-template` exists now

There is a strong structural clue connecting the detached seed wrapper and the caller tail:

- the detached seed wrapper prefix before its embedded request region is exactly `0xe8` bytes
- the detached caller tail at `+0x390` is also exactly `0xe8` bytes

That is why the runner now has:

- `--seed-tail-from-seed-template`

Current behavior of that option:

- build a detached seed wrapper with the existing seed ctor
- copy its `0xe8`-byte wrapper prefix into `outer + 0x390`
- emit `detached-tail-template-prepared` with inspected tail fields

This is still experimental, but it is the first tail-seeding idea backed by a clean static size/layout match rather than guesswork.

### Recommended next move from this newer state

1. Prefer restoring a non-UI seed source if possible.
2. If a manual user seed is available again, test the next detached run with:
   - `exceptions: "propagate"`
   - explicit self metadata
   - quieter exception reporting
   - and one run with `--seed-tail-from-seed-template`
3. When evaluating the result, pay close attention to whether:
   - `detached-native-entry-return` happens
   - the new tail fields are non-zero
   - the late async path behaves differently than the older all-zero-tail runs
