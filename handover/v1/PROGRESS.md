# Detached No-UI Send Handover

Objective: achieve fully detached, no UI, no user interaction text send in Weixin 4.1.8.29.

This handoff is intentionally self-contained. The key scripts and artifacts have been copied into this folder:

- `weixin_418_detached_send.py`
- `weixin_418_capture_good_template.py`
- `weixin_418_detached_trace.js`
- `trace-20260411-150700.jsonl`
- `capture-live-20260412-071151.out`
- `sameattach-20260412-075540.err`
- `fullscreen-after-uia-enter.png`
- `fullscreen-after-invoke-item.png`

Use this folder as the starting point.

## Current Bottom Line

We do **not** have detached no-UI send yet.

The latest meaningful frontier is:

1. We can reliably produce a live-good UI send and capture its good wrapper/template.
2. We can reliably identify and instrument the detached path.
3. The most recent same-Frida-session run proved that the live runner itself can capture the good template from a real send.
4. The remaining failure is the transition from `good-template-captured` to actually executing the detached replay cleanly.

The strongest current hypothesis is that the last blocker is **handoff / execution context timing between capture and detached replay**, not basic request-region population.

## Most Important Files

### Primary script

- `handover/v1/weixin_418_detached_send.py`

This is the main active runner. It already includes:

- explicit detached self-context seeding
- tail seeding from seed template
- tail seeding from swap template
- safer single exception handler
- `swap-with-live-wrapper`
- `swap-with-live-wrapper-raw`
- same-session capture support
- `armcaptureandsend`
- `--auto-detach-after-capture`

### Capture-only helper

- `handover/v1/weixin_418_capture_good_template.py`

Use this when you want to verify live-good capture behavior without detached replay.

### Live-good trace script

- `handover/v1/weixin_418_detached_trace.js`

Use this for pure dynamic RE of good UI sends.

## Best Static RE Findings

These are stable and important.

### `FUN_1815b1350`

This is the `entryB` detached path.

Confirmed sequence:

- `FUN_1815b1c80`
- `FUN_1815b20b0`
- `FUN_180020800`
- `FUN_1802fbff0`
- `FUN_180633270`
- `FUN_1815ea920`

Key finding:

- it later clones a tail block from `caller + 0x390`
- specifically through `FUN_180038880`

Implication:

- `outer + 0x390` is real structured state
- it is not safe to leave it all zero

### `FUN_180038880`

This clones the tail block. It is not padding. It conditionally clones owned/refcounted subobjects from tail slots including:

- `+0x48`
- `+0x88`
- `+0xc8`
- refcounted fields around `+0xd8` and `+0xe0`

Implication:

- detached tail correctness matters
- the correct tail source may need to match the same wrapper family as the swapped source object

### `FUN_1802fbff0`

Earlier dynamic crash understanding is still correct:

- it copies pair fields from its source
- if the source pointer itself is bad, it crashes immediately

## Best Dynamic Findings

### Good live send family

The best clean good-path trace remains:

- `handover/v1/trace-20260411-150700.jsonl`

Important field observations from good path work:

- builder/finalizer chain produces later-stage objects
- a known good finalize-stage object had:
  - `typePtr = 0x7ff9...3808` family
  - `ownerRefA = 3`
  - `ownerRefB = 2`

That `{3,2}` stage remained a useful “good” signature.

### Fresh live-good capture example

Useful reference:

- `handover/v1/capture-live-20260412-071151.out`

That run captured:

- worker thread `6192`
- wrapper `0x296e7cb22c0`
- object `0x296e7cb22d0`
- template region `0x296e7cb23a8`

### Same-session capture inside the active detached runner

Most important latest artifact:

- `handover/v1/sameattach-20260412-075540.err`

This is the first run where the detached runner itself captured the good template in-session.

It shows:

- `capture-worker-entry`
- `good-template-captured`
- then only `worker-finalize-*` logs from the live send
- no later `detached-*` logs
- the Weixin `File Transfer` window became non-responsive

Interpretation:

- the script did capture live-good state successfully in the same Frida attachment
- the remaining problem is what happens immediately after capture when we try to pivot into detached replay

## UI Automation Findings

These matter because you need a reproducible seed path for any same-session experiment.

### What definitely worked

At one point the `File Transfer` popout window existed as its own top-level window named `File Transfer`.

On that popout, UI Automation exposed:

- `Edit` named `Enter`
- `Button` named `Send`

Setting the `ValuePattern` on `Enter`, then sending keyboard `Enter`, **did** produce a real visible outgoing message.

The proof screenshot is:

- `handover/v1/fullscreen-after-uia-enter.png`

That image shows `trace-seed-uia-enter` successfully sent at `07:54`.

### What is flaky now

On later fresh sessions, the main `WeChat` window often shows:

- `File Transfer` row selected
- blank right pane
- no loaded compose controls in the main window UI tree

Artifact:

- `handover/v1/fullscreen-after-invoke-item.png`

In that state:

- the session-list item for `File Transfer` exists
- it supports `InvokePattern`, `ValuePattern`, `SelectionItemPattern`
- but invoking it does not open the top-level `File Transfer` popout
- double-clicking the selected row is not consistently reopening the popout on fresh sessions

This is now the main UI nuisance.

## What Was Learned About Wrapper Reuse

### Cross-attach live wrapper reuse is bad

I tested:

- cloned live wrapper (`swap-with-live-wrapper`)
- raw original live wrapper (`swap-with-live-wrapper-raw`)

Result:

- both are dead ends across separate attachments

Observed symptom:

- after swap, the new pair showed object/ref pointers but the new object’s vtable read as `0x0`

Implication:

- raw or cloned live wrapper reuse across a new Frida attachment is not trustworthy
- same-session captured-template replay is the right direction

### Same-session capture is the only promising payload source now

The in-session captured block is the best candidate because:

- it is produced by the actual live worker thread
- it avoids stale wrapper lifetime issues
- it avoids cross-attach object-family corruption

## Current Script Features Relevant To Next Steps

`weixin_418_detached_send.py` now has these resume-critical features:

- `--seed-tail-from-seed-template`
- `--seed-tail-from-swap-template`
- `--swap-with-captured-template`
- `--swap-with-live-wrapper`
- `--swap-with-live-wrapper-raw`
- `--wait-for-good-template`
- `--use-captured-template-region`
- `--auto-detach-after-capture`

The new internal RPC export:

- `armcaptureandsend(...)`

Purpose:

- arm capture
- when `good-template-captured` fires, immediately schedule detached replay from the same script/session

This was added specifically because the previous Python-side round trip after capture appeared too slow or state-sensitive.

## Exact Latest Frontier

The closest thing to a “best next test” is now:

1. get a stable top-level `File Transfer` popout again
2. use the proven UIA path on that popout:
   - `Edit` named `Enter`
   - send seed body with `ValuePattern`
   - send actual Enter key
3. run `weixin_418_detached_send.py` with:
   - `--wait-for-good-template filehelper`
   - `--use-captured-template-region`
   - `--swap-with-captured-template`
   - `--seed-tail-from-swap-template`
   - `--auto-detach-after-capture`
4. confirm whether `good-template-captured` is immediately followed by `detached-runonthread-enter`

That is the shortest path from where we are now.

## Recommended Immediate Command

After restoring a real `File Transfer` send surface, the key command to retry is:

```powershell
python C:\Users\Administrator\Code\puppet-xp\handover\v1\weixin_418_detached_send.py `
  --pid <WEIXIN_DLL_HOST_PID> `
  --template-region 0x0 `
  --conversation-id filehelper `
  --body detached-sameattach-captured-<tag> `
  --entry entryB `
  --wait-for-good-template filehelper `
  --capture-timeout-ms 30000 `
  --use-captured-template-region `
  --swap-with-captured-template `
  --run-timeout-ms 70000 `
  --request-self-username wxid_yfe3gm54e5il12 `
  --request-nickname Chase `
  --request-alias zumalabs `
  --seed-tail-from-swap-template `
  --auto-detach-after-capture
```

Notes:

- `--template-region 0x0` is only a placeholder so argparse is satisfied; it should be replaced internally after capture because `--use-captured-template-region` is set.
- this command assumes you are using a same-session live-good seed to trigger capture

## Known Good Self Context

Detached request region should explicitly use:

- self username: `wxid_yfe3gm54e5il12`
- nickname: `Chase`
- alias: `zumalabs`

This was important in multiple earlier runs.

## Important Error Signatures

### Hard crash family

Several detached experiments ended with:

- `Application Error`
- `Weixin.exe`
- faulting module `frida-agent.dll`
- exception code `0xc0000005`

That means some failures are agent/script-side fatal, not clean in-app rejections.

### Same-session latest stall family

The latest same-session run produced:

- capture succeeded
- no detached logs after capture
- Weixin `File Transfer` window hung
- Python runner stayed alive

That points to a scheduling or immediate post-capture handoff issue.

## Suggested Next Investigations

Priority order:

1. Validate `--auto-detach-after-capture` on a real working popout seed surface.
2. If it still hangs before `detached-runonthread-enter`, add one rawSend right before and right after the internal `setImmediate(scheduleDetached(...))` call inside `maybeCaptureGoodTemplate`.
3. If needed, bypass `setImmediate` and call `scheduleDetached(...)` directly after capture to see whether the queueing boundary is the problem.
4. If same-session auto-launch reaches `detached-runonthread-enter` again, compare whether the resulting swapped pair retains a non-null vtable throughout the worker-entry boundary.
5. If the UI nuisance persists, solve popout opening first. The actual send trigger itself is already solved once the popout exists.

## Update 2026-04-12 09:05 +01:00

The active v1 runner was updated to make the capture-to-detached handoff observable and testable.

File changed:

- `handover/v1/weixin_418_detached_send.py`

New auto-detach handoff telemetry now emits:

- `auto-detached-launching`
- `auto-detached-before-setimmediate`
- `auto-detached-setimmediate-fired`
- `auto-detached-direct-dispatch`
- `auto-detached-schedule-enter`
- `auto-detached-schedule-return`
- `auto-detached-schedule-error`

Behavioral change:

- added CLI flag `--direct-auto-detach-after-capture`
- when used with `--auto-detach-after-capture`, the script skips the internal `setImmediate(...)` hop and calls `scheduleDetached(...)` directly from the capture path

Why this matters:

- the last same-session failure signature was too coarse
- we could see `good-template-captured`, but not whether the runner died before queueing, inside the `setImmediate` callback, or inside `scheduleDetached`
- the new logs should separate those cases cleanly on the next live run

Recommended next live sequence:

1. Reproduce the real `File Transfer` popout send surface again.
2. Retry the previous same-session command with `--auto-detach-after-capture` first.
3. If it still stalls before `detached-runonthread-enter`, compare whether the new telemetry reaches:
   - `auto-detached-before-setimmediate`
   - `auto-detached-setimmediate-fired`
   - `auto-detached-schedule-enter`
4. Then rerun the same command with `--direct-auto-detach-after-capture` to answer whether the queueing boundary itself is the blocker.

## Resume Summary

The key advances to preserve are:

- detached tail is real state, not padding
- cross-attach live wrapper reuse is unreliable
- UIA send into the `File Transfer` popout is real and works
- same-session capture inside the detached runner now works
- the remaining blocker is the immediate capture-to-detached handoff

If resuming cold, start from:

- `handover/v1/weixin_418_detached_send.py`
- `handover/v1/sameattach-20260412-075540.err`
- `handover/v1/fullscreen-after-uia-enter.png`

That combination best captures the current state of the problem.

## Update 2026-04-12 11:16 +01:00

Fully detached send has now been reproduced on the main `File Transfer` surface, without leaving WeChat crashed afterward.

Files changed:

- `handover/v1/weixin_418_detached_send.py`

Key runner changes:

- added `patchSourceBodyField(objectAddress, bodyText)` to rewrite the captured source object's `+0x660` self/body small-string before the detached replay starts
- switched long-string writes away from Frida `Memory.allocUtf8String(...)` to process-heap-backed allocations:
  - `kernel32!GetProcessHeap`
  - `ntdll!RtlAllocateHeap`
- this matters because the earlier self-field patch proved the body path, but heap corruption showed Weixin later frees these buffers itself

Important finding:

- the detached `entryB` path does not just care about the copied request-region body at `request + 0xb8`
- it also consumes the enclosing captured source object's `+0x660` small-string
- if that field still contains the UI seed text, the detached replay does not produce the intended detached body

What failed:

- `1055-selfpatch-deep`
  - self-field patched from UI seed to detached body
  - detached body visibly landed in `File Transfer`
  - WeChat later died with heap corruption (`0xc0000374`)
- `1059-safeheap`
  - same self-field/body idea, but with process-heap-backed long strings
  - detached run hit the bad-pair path and `detached-pair-swapped`
  - WeChat still died afterward

What worked:

- `1060-noswap-safeheap`
  - kept `--use-captured-template-region`
  - kept the live captured-source `+0x660` self/body patch
  - omitted `--swap-with-captured-template`
  - omitted `--seed-tail-from-swap-template`
  - detached run returned `status: done`
  - detached message `detached-noswap-safeheap-1060` appeared in `File Transfer`
  - WeChat stayed alive after an additional wait
  - no new `Application Error` event was emitted after the successful run

Stable working recipe right now:

```powershell
python handover\v1\weixin_418_detached_send.py `
  --template-region 0x0 `
  --conversation-id filehelper `
  --body detached-noswap-safeheap-1060 `
  --entry entryB `
  --wait-for-good-template filehelper `
  --auto-detach-after-capture `
  --use-captured-template-region `
  --request-self-username wxid_yfe3gm54e5il12 `
  --request-nickname Chase `
  --request-alias zumalabs `
  --post-run-wait-ms 5000
```

Operational notes:

- this still requires one manual UI seed send in the same session to capture the live-good template
- after capture, the detached send itself is no-UI
- `--swap-with-captured-template` is currently destabilizing and should be left off for the stable path

Most relevant logs:

- success with detached body visible but later crash:
  - `handover/v1/live-run-1055-selfpatch-deep.err`
- unstable safe-heap swap path:
  - `handover/v1/live-run-1059-safeheap.err`
- stable no-swap safe-heap success:
  - `handover/v1/live-run-1060-noswap-safeheap.err`

## Update 2026-04-12 12:18 +01:00

Cold-start detached send is still not solved, but the current blocker is better isolated now.

What was added to the runner:

- `handover/v1/weixin_418_detached_send.py`
  - new non-send thread probe mode:
    - `--probe-thread-context <tid>`
    - `--probe-all-threads`
  - new passive context watch mode:
    - `--watch-context-ms`
    - `--watch-max-hits`
  - these modes inspect `threadPairFetch -> pairCopyMaybe -> entryBPairNormalize` without attempting a send

Important cold-start experiment:

- `cold-run-1061-seedctor`
  - command used:
    - `--entry entryB`
    - `--thread-id 10340`
    - `--init-request-from-seed-ctor`
    - `--seed-tail-from-seed-template`
    - no capture
    - no swap
  - detached call reached:
    - `detached-runonthread-enter`
    - `detached-seed-template-prepared`
    - `detached-request-region-pre-entry`
    - `detached-native-entry-call`
  - then Weixin crashed

Crash signature:

- `Application Error`
- `Weixin.exe`
- faulting module `Weixin.dll`
- exception `0xc0000005`
- fault offset `0x00000000000f16b0`

What this strongly suggests:

- cold-start failure is not just “missing body text” or “template region malformed”
- invoking `entryB` on the visible window thread is likely wrong
- there is still an unsolved thread-affinity / live-context problem before the seed-wrapper content question is even fully reached

Current probing results:

- probing the visible WeChat window thread (`6688` in the relaunched process) returns callable results, but the fetched/copied/normalized objects decode as garbage for our current assumptions
- many other sleeping threads time out under `Process.runOnThread(...)`
- passive watch during automated conversation switching did surface real `threadPairFetch` activity on:
  - `11944`
  - `10584`
  - `10248`
  - `12060`
- but direct probing of the first surfaced thread (`11944`) still produced the same garbage-shaped context

Interpretation:

- our current decoding of the `threadPairFetch` output family is probably incomplete or wrong
- or the callable thread is still not the real thread that owns the send-ready chat context

Most relevant new logs:

- cold-start crash:
  - `handover/v1/cold-run-1061-seedctor.err`
- broad thread probe attempt:
  - `handover/v1/probe-run-1062-all-threads.out`
  - `handover/v1/probe-run-1062-all-threads.err`
- passive conversation-switch context watch:
  - `handover/v1/watch-run-1063-context.out`
  - `handover/v1/watch-run-1063-context.err`

Next best direction:

1. Fix or replace the current `threadPairFetch` output decoding assumptions.
2. Derive the true callable send-context thread without relying on manual send.
3. Only after that, retry cold-start `entryB` with either:
   - native seed wrapper plus corrected thread/context
   - or a repaired synthetic good-source path.

## Update 2026-04-12 12:55 +01:00

Cold-start detached send is still not solved. The synthetic path remains the best lead, but the latest runs show the blocker is not just "synthetic embedded request region is zero."

What changed in the runner:

- `handover/v1/weixin_418_detached_send.py`
  - synthetic good-source objects now get an embedded request block seeded from `buildDetachedSeedNative(...)`
  - that embedded request region is patched with the same conversation/body/msgsource/self-context fields used for the detached outer request
  - added return-site probes after the `FUN_180ebe570` and `FUN_180968840` callsites inside `FUN_18332df80`
  - expanded `pairCopyMaybe` logging to dump the copied source object with the same extended field view used for the synthetic source

Key cold-start experiments:

- `cold-run-1069-synth-seeded`
  - synthetic source embedded request region was no longer zeroed
  - detached outer request was also well-formed
  - Weixin still crashed before the message-prep loop item/finalize stages became visible
  - conclusion: seeding `object + 0xd8` is not sufficient by itself

- `cold-run-1070-sites`
  - explicit internal return-site probes after the item/finalize callsites still did not fire before the crash
  - the hot path again reached repeated `threadPairFetch -> pairCopyMaybe -> normalize -> chat-check`
  - conclusion: the cold path still dies before the useful item/finalize return state is available

- `cold-run-1071-donor`
  - expanded instrumentation captured a second failure mode near `entryB`
  - after detached seed-copy, a `threadPairFetch` returned a null pair on the detached thread
  - the next `pairCopyMaybe` attempt then faulted with an access violation reading `0x30`
  - crash signature:
    - PC `Weixin.dll + 0x2fbff9`
    - read access violation at `0x30`
  - this suggests a real cold-start dependency on a warm live thread context before the deeper worker/message-prep path even begins

Most relevant logs:

- `handover/v1/cold-run-1069-synth-seeded.err`
- `handover/v1/cold-run-1070-sites.err`
- `handover/v1/cold-run-1071-donor.err`

Working hypotheses after these runs:

1. The synthetic source still lacks one or more non-request fields needed by `FUN_1833fccd0` / `FUN_18332df80`.
2. Separately, some cold-start runs fail earlier because `threadPairFetch` can return null on the chosen UI thread immediately after startup/reopen.
3. The true finish line likely needs both:
   - a stable callable thread/context selection method
   - a better reconstruction of the live source-object family than the current synthetic constructor alone provides

## Update 2026-04-12 14:20 +01:00

Strategy note after review:

- the failed-message resend button path is now recorded as a plausible fallback, not the active line of work
- rationale:
  - resend likely operates on an existing failed outbound row and could bypass some of the fragile fresh-compose state
  - but it is still unproven as a route to arbitrary fully detached send
- active objective remains unchanged:
  - make the current cold-start `entryB` path work with no manual send and no UI interaction beyond Weixin already being open

Immediate execution rule:

- continue prioritizing the current detached path until it is either working or clearly exhausted
- only fall back to resend-path RE if the present cold-start source/context reconstruction line stops producing new signal

## Update 2026-04-12 14:47 +01:00

Cold-start `entryB` work produced a tighter failure map, but not a full no-seed send yet.

Runner changes:

- `handover/v1/weixin_418_detached_send.py`
  - added `--synthetic-embed-seed-mode leave-original`
  - added a deeper synthetic swap hook on `pairCopyMaybe`
  - then narrowed that deeper hook to specific late callsites after observing that swapping too early breaks the initial `entryB` normalize path

Key experiments:

- `cold-run-1073-leaveoriginal`
  - left the synthetic source object's embedded `+0xd8` region untouched
  - the synthetic embedded region stayed clean, confirming we were no longer corrupting it via memcpy/patching
  - Weixin still crashed
  - conclusion: touching the synthetic embedded request region was not the primary cold-start blocker

- `cold-run-1074-deepreswap`
  - first attempt to replace later `pairCopyMaybe` results with the prepared synthetic pair
  - this fired on the very first `entryB`-side `pairCopyMaybe`
  - immediate result: crash during the following normalize parse
  - conclusion: replacing the copied pair that early is too aggressive

- `cold-run-1075-lateswap-only`
  - narrowed the deeper hook to the two later builder-path callsites seen in prior traces
  - the run reached the later `0x332dfe7` pair-copy site, swapped in the synthetic pair there, and then died at the next normalize parse
  - conclusion: the first late builder-path copy still cannot be replaced with the synthetic object

- `cold-run-1076-lateswap-second-only`
  - narrowed the deeper hook again to only the second late builder-path `pairCopyMaybe` callsite
  - the run went much deeper than before:
    - initial `entryB` normalize succeeded
    - `workerEntry` bad-vtable swap to the synthetic pair succeeded
    - builder stages completed through `builder-message-prep-leave`
    - helper-table insertion and `worker-finalize-enter` became visible before the crash
  - no `pair-copy-maybe-swapped-synthetic` event was logged in this run
  - conclusion: limiting the extra swap to the second late site avoids the earlier normalize crashes and pushes cold-start much deeper, but a later finalize/helper seam still kills the process

Current best interpretation:

1. The initial cold-start path still needs the worker-entry synthetic swap, but not an earlier replacement of the copied live thread pair.
2. The first later builder-path `pairCopyMaybe` also appears semantically required in its original bad/live form.
3. Restricting the extra synthetic replacement away from those earlier sites moves execution materially deeper, so the remaining blocker is now likely at or after helper-table insertion / worker finalize rather than the original normalize/build loop.

Most relevant logs:

- `handover/v1/cold-run-1073-leaveoriginal.err`
- `handover/v1/cold-run-1074-deepreswap.err`
- `handover/v1/cold-run-1075-lateswap-only.err`
- `handover/v1/cold-run-1076-lateswap-second-only.err`

Best next step:

- instrument and compare the post-`builder-message-prep-leave` / `helper-table-insert` / `worker-finalize-enter` region, because that is now the deepest observed cold-start point

## Update 2026-04-12 16:30 +01:00

Cold-start fully detached send is still not solved, but the current blocker is narrower and better-understood than before.

Runner changes:

- `handover/v1/weixin_418_detached_send.py`
  - added `--probe-roam-crash-site`
    - watches for `roam_server.dll` loading and records the site at `+0x364339`
  - added `--bypass-roam-crash-site`
    - patches the `roam_server.dll + 0x364339` fast-fail instruction pair to `NOP NOP`
  - fixed a real bug in our own `pair-copy-maybe` hook
    - `this.src` / `this.dst` were not being populated on non-deep-trace runs before `onLeave`
    - that caused the repeated `hook-error: pair-copy-maybe / Error: missing argument` seen on several cold-start attempts

Key findings:

1. `roam_server.dll + 0x364339` is not ordinary business logic.
   - live inspection on a surviving process showed the bytes around the site include:
     - `... 85 c0 74 07 b9 07 00 00 00 cd 29 ...`
   - so the target offset is an `int 29h` fast-fail site, analogous to the earlier `Weixin.dll + 0xf16b0` abort seam
   - this justified adding the new explicit `--bypass-roam-crash-site` patch

2. Some fresh-session cold-start runs were being perturbed by our own instrumentation.
   - before the hook fix, multiple runs logged:
     - `hook-error / pair-copy-maybe / Error: missing argument`
   - after fixing that bug, those script-side errors no longer dominate the non-deep-trace runs

3. Fresh-session main-window-thread runs are exposing the cold context problem more clearly.
   - on a clean main-window-thread run, the path faulted with:
     - `native-exception`
     - `type: access-violation`
     - `pc: Weixin.dll + 0x2fbff9`
     - `memory.operation: read`
     - `memory.address: 0x30`
     - `rcx: 0x0`
   - that is consistent with the earlier interpretation that some cold-start sessions still reach `pairCopyMaybe` / donor handling with no valid live context on the chosen thread

4. Programmatically single-clicking `File Transfer` before the detached run did not solve cold-start send.
   - the selected-conversation experiment still died before producing a delivered detached message
   - so “conversation visibly selected” is not by itself sufficient

Representative runs:

- `handover/v1/cold-run-1100-roamprobe.err`
  - first live proof that `roam_server.dll` is loaded on the cold-send path
- `handover/v1/cold-run-1102-mainthread.err`
  - first main-window-thread run that stayed pending instead of immediately hard-crashing
- `handover/v1/cold-run-1103-main-bypass.err`
  - first roam-site bypass attempt before fixing the probe/bypass ordering
- `handover/v1/cold-run-1105-fixedhook-main.err`
  - post-hook-fix run showing the explicit `Weixin.dll + 0x2fbff9` null-context access violation
- `handover/v1/cold-run-1106-main-selected.err`
  - “selected File Transfer first” experiment; still no successful detached send

Current interpretation:

1. We now know the later `roam_server.dll` seam is an intentional fast-fail, not just an opaque crash offset.
2. Separately, we still have an earlier and more basic cold-start blocker:
   - on many fresh-session runs, the chosen thread still does not carry a valid donor/source context into `pairCopyMaybe`
3. This means bypassing `roam_server.dll` alone is not enough.
4. The next work should prioritize reliable cold-start context acquisition again, now that the script-side hook bug is fixed and the later fast-fail site is understood.

## Update 2026-04-12 18:40 +01:00

Cold-start fully detached send is still not solved, but this stretch materially moved the failure later than the old `Weixin.dll + 0x2ad85c` normalize/container crash.

What changed in the runner:

- `handover/v1/weixin_418_detached_send.py`
  - narrowed the late donor-field patch path so it no longer overwrites the copied donor object's embedded `+0xd8` request-region strings during `pairCopyMaybe`
    - we now only patch the donor talker/body-facing fields we understand (`+0xb0`, `+0x660`) and preserve the donor's own normalize/container state
  - added a probe for `Weixin.dll + 0x34290` (`FUN_180034290`)
    - this is the branch taken after `FUN_1802ad6b0` / `entryBPairNormalizeParse` when the parse-hit flag byte is `1`
    - hook names:
      - `helper-parse-hit-cast-enter`
      - `helper-parse-hit-cast-leave`

Why the min-patch change was made:

- deep trace on the older late-swap path (`cold-run-1208-donor-lateswap-deep`) showed the exact bad transition:
  - the second late `pairCopyMaybe` replacement at return offset `0x332e438` swapped in the synthetic source
  - the following `entryb-pair-normalize-parse-enter` then received the synthetic object as `arg0`
  - that synthetic object had dead hash-table/container fields at `+0x48/+0x58/+0x70` (`0x0`, `0x0`, `0xf`)
  - the process then died at the already-known `Weixin.dll + 0x2ad85c` seam inside `FUN_1802ad6b0`
- conclusion:
  - the copied donor object itself is needed to carry valid normalize/container state
  - blindly replacing it with the synthetic source during the late builder loop is wrong

Key fresh donor-thread captures from this stretch:

- `PID 12256`
  - passive watch hit thread `2140`
  - wrapper `0x2200db93970`
  - source object `0x2200d941b20`
- `PID 6600`
  - passive watch hit thread `12948`
  - wrapper `0x24c8387d990`
  - source object `0x24c8a9c7f70`
- `PID 11444`
  - passive watch hit thread `12984`
  - wrapper `0x1a2fc3efbc0`
  - source object `0x1a2fc3ebae0`

Important experiments and what they proved:

- `cold-run-1208-donor-lateswap-deep.err`
  - donor thread: `2140` on `PID 12256`
  - still using the aggressive late synthetic swap
  - showed the critical bad transition:
    - late `pair-copy-maybe-swapped-synthetic`
    - then `entryb-pair-normalize-parse-enter` with synthetic `arg0`
    - synthetic `arg0State` had dead manager/container fields
    - crash followed at the known `0x2ad85c` seam
  - this was the run that proved the copied donor manager/container state must survive the late loop

- `cold-run-1209-donor-minpatch.err`
  - donor thread: `12948` on `PID 6600`
  - first run after the min-patch change
  - important difference:
    - WeChat stayed alive instead of immediately crashing
    - the Python runner timed out waiting for detached completion
    - no new detached body appeared in `File Transfer`
  - interpretation:
    - this changed the failure mode from immediate crash to non-crashing stall / hung detached execution
    - this is the most promising practical cold path so far because it preserved process stability

- `cold-run-1211-donor-minpatch-deep.err`
  - donor thread: `12948` on `PID 6600`
  - deep-trace version of the min-patch path
  - showed the path now gets materially further than the old normalize crash:
    - repeated late `entryb-pair-normalize-parse-enter` / `...-leave`
    - corresponding `...-build-enter` / `...-build-leave`
    - `arg0` remained the live donor object (`0x24c8a9c7f70`), not the synthetic source
  - the final observed seam:
    - one more late `entryb-pair-normalize-parse-enter`
    - `...parse-leave`
    - then the script died before the corresponding build-enter
  - decompilation showed why:
    - caller `Weixin.dll + 0x36d62b` is inside `FUN_18036d5e0`
    - after `FUN_1802ad6b0`, it checks a flag byte at stack `-0x48`
    - if that byte is `1`, it does **not** call `FUN_1802ac4d0`
    - instead it goes down the `FUN_180034290` cast path
  - this justified adding the new `helper-parse-hit-cast` probe

- `cold-run-1212-donor-castprobe.err`
  - donor thread: `12984` on fresh `PID 11444`
  - min-patch path with the new `FUN_180034290` probe available
  - the path moved later again:
    - repeated late `entryb-pair-normalize-parse-enter/leave`
    - repeated `entryb-pair-normalize-build-enter/leave`
    - then:
      - `builder-message-prep-loop-key-enter`
      - `builder-message-prep-loop-key-newsapp-check-leave -> 0`
      - `builder-message-prep-loop-key-notification-check-leave -> 0`
      - `builder-message-prep-loop-key-chat-check-leave -> 40704`
      - `builder-message-prep-loop-key-brand-customer-check-leave -> 0`
    - the process died before:
      - `builder-message-prep-loop-key-fallback-check`
      - `builder-message-prep-loop-select-enter`
  - interpretation:
    - cold-start min-patch is now getting through the late normalize/build branch and through several subsequent key checks
    - the active seam has moved into the small gap after brand-customer-check and before fallback/select

Static RE that matters for the current seam map:

- old known crash seam:
  - `Weixin.dll + 0x2ad85c`
  - inside `FUN_1802ad6b0`
  - instruction:
    - `MOV R13, qword ptr [RAX + R8 + 0x8]`
  - meaning:
    - early hashed lookup / container walk on the manager object rooted at `arg0 + 0x48/+0x58/+0x70`

- caller that explains the missing build-enter after parse:
  - `FUN_18036d5e0`
  - after `CALL 0x1802ad6b0`, instruction `CMP byte ptr [RBP + -0x48],0x1`
  - if equal:
    - branch to `FUN_180034290`
  - else:
    - branch to `FUN_1802ac4d0`

- newly identified branch helper:
  - `FUN_180034290` at `Weixin.dll + 0x34290`
  - performs a type-check / cast on the parse result
  - if the cast/type check succeeds, it copies a pair-like result out
  - if not, it throws `"bad cast"`

Current best interpretation:

1. Preserving the live donor object's normalize/container state during the late builder loop is correct.
2. The old late synthetic replacement was definitely too aggressive and directly responsible for the `0x2ad85c` parse/container crash.
3. The refined min-patch path is the best cold-start candidate so far because:
   - it was the only variant in this stretch that kept WeChat alive in a non-deep run
   - deep runs pushed execution later than before, through late normalize/build and into later key checks
4. We are now dealing with a later builder-path seam, not the original normalize/container seam.

Operational notes:

- Deep-trace runs still perturb the process heavily and usually end with:
  - `{"ok": false, "error": "frida script destroyed while waiting for runOnThread completion", ...}`
  - followed by a WeChat crash
- Non-deep min-patch was more stable:
  - `cold-run-1209-donor-minpatch.err`
  - process survived, runner hung/timed out, no message surfaced in `File Transfer`
- Safe Mode recovery sequence used repeatedly and still required after crashes:
  - dismiss Chinese error report dialog via `确定(O)`
  - click visible bottom `Next` buttons only
  - final bottom button `Go to Weixin`
  - then launcher `Open WeChat`
- user instruction still applies:
  - do not double-click conversations
  - only single-click conversation changes

Most relevant artifacts from this stretch:

- `handover/v1/cold-run-1208-donor-lateswap-deep.err`
- `handover/v1/cold-run-1209-donor-minpatch.err`
- `handover/v1/cold-run-1211-donor-minpatch-deep.err`
- `handover/v1/cold-run-1212-donor-castprobe.err`
- Tencent fresh crash report folder after the 1211/1212-era crashes:
  - `C:\Users\Administrator\AppData\Roaming\Tencent\xwechat\crashinfo\reports\25e609be-d671-4220-9dfd-018efabd24af`

Best next step from this exact state:

1. Restore WeChat again and prefer the refined **non-deep** min-patch path first, because it is the only one from this stretch that kept the app alive.
2. Let that non-deep run sit longer than before while monitoring for an eventually landed detached message, even if `runOnThread` does not return quickly.
3. If more visibility is needed, add one more narrowly targeted probe in the small gap after:
   - `builder-message-prep-loop-key-brand-customer-check-leave`
   and before:
   - `builder-message-prep-loop-key-fallback-check`
   / `builder-message-prep-loop-select-enter`
4. Avoid going back to the old aggressive late synthetic swap path unless specifically needed for comparison, because it regresses to the earlier `0x2ad85c` normalize/container crash.

2026-04-12 - finalize/assert seam after forced-finalize fix
----------------------------------------------------------

This segment replaced the old incorrect understanding of `--force-loop-finalize-cast-bypass` and moved the active cold-start seam into `FUN_180968840` itself.

What changed in the runner:

- `extractForcedLoopFinalizeResult()` was fixed to reuse `inspectFinalizePromiseResultSlot()` and `safeReadPointer()` instead of raw `Memory.readPointer(...).toString()` chains.
- `--force-loop-finalize-cast-bypass` no longer replaces `FUN_180968840`.
  - It now hooks the compare helper at:
    - `builderMessagePrepLoopFinalizeTypeCompare = Weixin.dll + 0x64df380`
  - It only forces `retval = 0` when `returnAddress == finalizeTarget + 0xbd`.
- Added inner finalize probes:
  - `builderMessagePrepLoopFinalizeAwaitCheck = Weixin.dll + 0x316b50`
  - `builderMessagePrepLoopFinalizeAwaitResultSlot = Weixin.dll + 0x319290`
- New logs now available:
  - `builder-message-prep-loop-finalize-compare-enter`
  - `builder-message-prep-loop-finalize-compare-forced`
  - `builder-message-prep-loop-finalize-await-check-enter/leave`
  - `builder-message-prep-loop-finalize-await-result-slot-enter/leave`

Artifacts and conclusions:

- `cold-run-current-10144-11180-forcefinalize6.log`
  - first proof that the forced finalize helper bug was real and fixed
  - key lines:
    - `builder-message-prep-loop-finalize-forced`
    - `resultSlot.object = 0x1d434389580`
    - `forcedResult = 0x19d81316801`
    - `builder-message-prep-loop-finalize-leave retval = 0x19d81316801`
  - interpretation:
    - the old full-function replacement can now return a nonzero object-like pointer
    - but WeChat still crashes immediately after, so “nonzero return” is not enough

- Ghidra static analysis on `Weixin.dll`:
  - `FUN_180968840` at `0x180968840`
  - `FUN_180319290` at `0x180319290`
  - `FUN_180316b50` at `0x180316b50`
  - conclusions:
    - `FUN_180968840` copies the input pair, calls `FUN_180316b50`, calls `FUN_180319290`, performs a type-name compare, and on success returns `*(qword *)(*(qword *)slot + 8)`
    - `FUN_180319290` effectively returns `param_1 + 0xb8`, waits when promise state `+0xc4 == 0`, throws on rejected promise state `== 2`, otherwise returns the slot address
    - `FUN_180316b50` appears to guard await/rejected-promise behavior and can throw fatally
  - practical conclusion:
    - replacing all of `FUN_180968840` was too blunt; the better seam is inside the original finalize path

- `cold-run-current-10840-9284-forcecompare1.log`
  - first run after converting the flag to compare-force mode
  - observed:
    - `builder-message-prep-loop-finalize-enter`
    - but no:
      - `builder-message-prep-loop-finalize-compare-enter`
      - `builder-message-prep-loop-finalize-compare-forced`
      - `builder-message-prep-loop-finalize-leave`
  - interpretation:
    - original `FUN_180968840` dies before reaching the final type-name compare

- `cold-run-current-8472-4828-forcecompare2.log`
  - first run with the inner-finalize hooks enabled
  - environment:
    - PID `8472`
    - main UI thread `4828`
    - `Process.runOnThread` on `4828` succeeded
  - observed:
    - still no:
      - `builder-message-prep-loop-finalize-await-check-enter`
      - `builder-message-prep-loop-finalize-await-result-slot-enter`
      - `builder-message-prep-loop-finalize-compare-enter`
      - `builder-message-prep-loop-finalize-leave`
    - but a new critical line appeared:
      - `crash-stub-bypassed`
      - backtrace included:
        - `0x7ffb229d889a`
        - `0x7ffb2539e916`
  - interpretation:
    - the cold path now reaches the known crash/assert stub at `Weixin.dll + 0x0f16b0`
    - the backtrace lands inside or immediately adjacent to `FUN_180968840` near the `FUN_180319290` region
    - this is strong evidence that the remaining seam is an internal promise/result-state assert, not the final compare

Current best interpretation after this segment:

1. The full-function finalize replacement was masking the real failure; the nonzero forced result was not sufficient for correctness.
2. The original `FUN_180968840` path is failing before it reaches the final compare helper.
3. The latest best evidence points at an internal assert/crash path around the `FUN_180319290` call or its surrounding validation, likely because the copied promise/result family is still semantically wrong even when non-null.
4. The most useful next seam is the narrow area inside `FUN_180968840` from roughly `+0x5a` through the `FUN_180319290` callsite and the nearby crash-stub path.

Operational note:

- If Frida attach fails with `VirtualAllocEx returned 0x00000005`, first confirm whether `Weixin.exe` is still running before treating it as tooling failure.

2026-04-13 - post-finalize out-pair seam and null-pair result
-------------------------------------------------------------

This segment moved the cold detached seam past the inner finalize await/type-check logic and into the post-finalize wrapper that writes the caller's out-pair.

What changed in the runner:

- Fixed a real bug in the focused finalize hooks:
  - the inner finalize logging for:
    - `builder-message-prep-loop-finalize-await-check-enter`
    - `builder-message-prep-loop-finalize-await-result-slot-enter`
  - had been calling nonexistent `getCallerAddress(this.context)`
  - now logs:
    - `caller: this.returnAddress.toString()`
    - `callerInfo: describeAddress(this.returnAddress)`
- Added `--force-loop-finalize-await-bypass`
  - hooks:
    - `FUN_180316b50` (`Weixin.dll + 0x316b50`)
    - `FUN_180319290` (`Weixin.dll + 0x319290`)
  - behavior:
    - await-check becomes a no-op
    - await-result-slot returns `promiseObject + 0xb8`
  - new logs:
    - `builder-message-prep-loop-finalize-await-check-bypassed`
    - `builder-message-prep-loop-finalize-await-result-slot-bypassed`
- Fixed the compare-force helper field naming bug in `ensureLoopFinalizeCastBypass()`
  - old `this.force` style fields collided and caused:
    - `TypeError: no setter for property`
  - current fields are the dedicated `loopFinalizeCast*` names
- Added `--force-post-finalize-resolve-bypass`
  - targets `FUN_1833bafa0` at:
    - `Weixin.dll + 0x33bafa0`
  - first implementation was a full no-op replacement
  - current implementation writes a clean null rc-pair into the caller-provided out buffer and returns that same buffer
  - new log:
    - `builder-message-prep-post-finalize-resolve-bypassed`
    - includes `resolverPairAfter`
- Added `--probe-process-exit`
  - probes:
    - `ExitProcess`
    - `TerminateProcess`
    - `NtTerminateProcess`
    - `RtlFailFast2`
    - `RaiseFailFastException`
    - CRT `abort`
  - note:
    - initial implementation used `Module.findExportByName(...)` and had to be corrected to `Module.getExportByName(...)` with `try/catch`

Key Ghidra/static conclusions:

- `FUN_180316b50` (`0x180316b50`)
  - is essentially a promise-state guard
  - it calls the promise-state accessor and throws on rejected await state
- `FUN_180319290` (`0x180319290`)
  - effectively returns `promise + 0xb8` when resolved
  - waits only while promise state `+0xc4 == 0`
  - throws on rejected promise state `== 2`
- `FUN_1833bafa0` (`0x1833bafa0`)
  - is on the actual `FUN_18332df80` path after the builder/finalize loops
  - it writes an rc-pair into the caller-supplied output buffer
  - therefore it is not safe to simply no-op it

Primary artifacts and conclusions:

- `handover/v1/cold-run-current-8868-10012-entryB-focusedbaseline-patched.log`
  - first focused run after fixing the bad inner-finalize hook
  - previous crash cause was our own JS `ReferenceError`, not native logic

- `handover/v1/cold-run-current-10320-10672-entryB-focusedbaseline-patched2.log`
  - first clean proof that the old seam had moved into:
    - `builder-message-prep-loop-finalize-await-check-enter`
  - process died before the corresponding leave/result-slot logs

- `handover/v1/cold-run-current-4592-8004-entryB-focusedbaseline-awaitbypass.log`
  - first successful run with the await bypass enabled
  - observed:
    - `builder-message-prep-loop-finalize-await-check-bypassed`
    - `builder-message-prep-loop-finalize-await-result-slot-bypassed`
    - `builder-message-prep-loop-finalize-compare-enter`
    - `builder-message-prep-loop-finalize-compare-forced`
    - `builder-message-prep-loop-finalize-leave`
    - then a second finalize-pair ctor with caller inside `FUN_1833bafa0`
  - conclusion:
    - the inner finalize seam was behind us
    - the new crash was in or after the post-finalize wrapper chain

- `handover/v1/cold-run-current-10068-6784-entryB-focusedbaseline-allbypass.log`
  - first full no-op post-finalize bypass
  - observed:
    - `builder-message-prep-post-finalize-resolve-bypassed`
    - then process death
  - conclusion:
    - full no-op was wrong because the caller later consumed an uninitialized out-pair buffer

- `handover/v1/cold-run-current-2380-10820-entryB-focusedbaseline-nullpair-exitprobe.log`
  - current best artifact for the latest seam
  - observed:
    - all inner finalize stages completed under bypass
    - `builder-message-prep-post-finalize-resolve-bypassed`
    - `resolverPairAfter = { object: 0x0, ref: 0x0 }`
    - no native exception surfaced
    - no `process-exit-probe-hit`
    - main UI process disappeared while background `Weixin` processes remained
  - conclusion:
    - null-pair is less wrong than no-op
    - but the caller still cannot survive or accept a null rc-pair after `FUN_1833bafa0`

Direct UI verification after the null-pair run:

- reopened WeChat to the main chat UI
- single-clicked `File Transfer`
- confirmed there was no new landed detached message from the null-pair attempt
- newest visible success in chat remains:
  - `detached-noswap-safeheap-1060`
- so the null-pair run did not silently send before the UI process disappeared

Fresh live state after recovery:

- WeChat reopened normally to the full chat UI, not Safe Mode
- `File Transfer` is selected and visible
- current fresh main UI process:
  - PID `1372`
  - main window thread `5088`
  - hwnd `4195524`

Current best interpretation after this segment:

1. The inner finalize/promise seam is now behind us under the focused bypasses.
2. The active cold-start seam is the post-finalize out-pair written by `FUN_1833bafa0`, or the immediate consumer above it.
3. A null rc-pair avoids the previous heap-style AV but is still semantically unacceptable to the higher caller.
4. The next most useful move is to trace the consumer above `FUN_18332df80` / `FUN_1833bafa0` or synthesize a more faithful post-finalize rc-pair instead of nulling it.

Operational reminders:

- if `VirtualAllocEx returned 0x00000005`, verify `Weixin.exe` process liveness first
- do not double-click conversations
- use single clicks only for conversation changes

## 2026-04-13 - native post-finalize helper, return-site probes, and Watson failfast bypass

What changed in the runner:

- replaced the synthetic `FUN_1833bafa0` bypass body with a call to the real native helper:
  - `FUN_1833bb090` at `0x1833bb090`
  - new offset:
    - `postFinalizeResolveHelper: 0x33bb090`
- removed the hand-built helper-object / direct `FUN_180318410` resolve path from `ensurePostFinalizeResolveBypass()`
- added focused return-site probes for the next frames up:
  - `builderMessagePrepPostFinalizeReturnSite: 0x332f068`
  - `builderMessagePrepOuterWrapperInnerReturnSite: 0x1618078`
  - `builderMessagePrepOuterWrapperAwaitReturnSite: 0x1618087`
  - plus wrapper function entry/leave on `builderMessagePrepAuxC` / `FUN_181618040`
- added a targeted no-return assert bypass:
  - `watsonFailFast: 0x64c96c8`
  - CLI:
    - `--bypass-watson-failfast`
  - current implementation bypasses both:
    - internal `FUN_1864c96c8`
    - `ucrtbase.dll!_invoke_watson`

Key Ghidra conclusions from this segment:

- `FUN_1833bb090` is the real post-finalize promise boxing/resolution helper.
  - it allocates the 0x20 helper object itself via `FUN_186309d1c(0x20)`
  - it writes:
    - vtable = `PTR_FUN_187e79c58`
    - payload slot = raw `*param_1`
    - type descriptor = `RTTI_Type_Descriptor`
    - self-style pointer at `+0x18`
  - then it resolves the promise via `FUN_180318410`
  - then it releases the helper object
- this means the earlier fully synthetic helper-object path was too hand-wavy and likely allocator / lifetime wrong.
- `FUN_1864c96c8` decompiles to:
  - `FUN_1864c99f0();`
  - `_invoke_watson(...)`
  - no return
- the many branches from `FUN_18332df80` to `0x18332f093` therefore lead to a real Watson failfast path, not an ordinary exception.

Primary artifacts and results:

- `handover/v1/cold-run-current-7732-1032-entryB-focusedbaseline-untagged2.err`
  - fresh main-UI-thread repro before the native-helper rewrite
  - still showed the old immediate AV after `builder-message-prep-post-finalize-resolve-bypassed`
  - PC was in a heap/frida-thunk-looking region, which revived suspicion that our synthetic post-finalize helper path was itself malformed

- `handover/v1/cold-run-current-7796-4628-entryB-focusedbaseline-nativehelper.err`
  - first focused run after switching the post-finalize bypass to call native `FUN_1833bb090`
  - important change:
    - the old immediate post-bypass AV disappeared
    - `resolveError = null`
    - no `native-exception` was logged
  - but:
    - Frida still reported `script has been destroyed while waiting for runOnThread completion`
    - `Weixin.exe` was gone afterward
  - conclusion:
    - using the real native post-finalize helper is strictly better than the synthetic helper-object version
    - the cold path still terminates immediately after the post-finalize handoff

- `handover/v1/test-runonthread-4380-7120.err`
  - launcher-only host check
  - `Process.runOnThread` on the launcher main thread timed out with status still `pending`
  - conclusion:
    - the small launcher window is not a viable substitute for a healthy full-shell UI thread

- `handover/v1/cold-run-current-11168-direct-seedctor.err`
  - direct-call experiment with no `--thread-id` and no synthetic source swap
  - reached:
    - `detached-request-region-pre-entry`
    - `detached-native-entry-call`
  - then the script was destroyed and the process was gone
  - conclusion:
    - direct injected-thread execution is destructive but still confirms the current host can die even before a `runOnThread`-style wrapper is involved

- `handover/v1/cold-run-current-6648-direct-seedctor-watson.err`
  - first direct-call run with `--bypass-watson-failfast`
  - died even earlier than the previous direct-seed run
  - no `watson-failfast-bypassed` or `invoke-watson-bypassed` event was seen
  - conclusion:
    - the specific early death in that host was not the exact Watson helper we patched, or it died before reaching that site

- `handover/v1/cold-run-current-10496-direct-seedctor-watson2.err`
  - second direct-call run with the widened Watson bypass
  - reached:
    - `detached-request-region-pre-entry`
  - but still died before:
    - `detached-native-entry-call`
  - no Watson-bypass hit was logged
  - conclusion:
    - there is still at least one earlier destructive seam before native entry on some launcher-host direct runs

Operational reality discovered in this segment:

- repeated relaunches often came back only as the small `WeChat` launcher window:
  - approx rect `296 x 388`
  - buttons visible via UI Automation:
    - `Open WeChat`
    - `Switch Account`
    - `Transfer files only`
- both:
  - direct coordinate clicks
  - UI Automation `InvokePattern`
  - and later a plain mouse pass
  did not reliably advance that launcher to the full chat shell in this stretch
- thread-context / `runOnThread` behavior in the launcher-only host was poor enough that it should not be treated as equivalent to a healthy full chat UI process

Current best interpretation now:

1. The native `FUN_1833bb090` helper path is more faithful than the synthetic post-finalize boxing path and should remain the default post-finalize bypass implementation.
2. A real Watson-style failfast helper exists on the cold path (`FUN_1864c96c8`), and it is worth continuing to monitor / bypass when testing deep cold runs.
3. There are still at least two unresolved seams:
   - the post-finalize immediate termination after the now-native helper-backed bypass on a healthy UI-thread run
   - an even earlier destructive seam that can kill launcher-host direct runs before or around `detached-native-entry-call`
4. The newly added return-site probes are the right next signal on the next healthy full-shell run:
   - if `builder-message-prep-post-finalize-return-site` appears, then `FUN_1833bafa0` is no longer the active seam
   - if the wrapper probes on `FUN_181618040` appear, then we can push the investigation one frame higher

Next best move from here:

- obtain a real full-shell WeChat UI host again, not just the small launcher window
- rerun the focused cold path with:
  - native post-finalize helper bypass
  - Watson failfast bypass
  - the new post-finalize / outer-wrapper return-site probes
- then decide based on the first new post-finalize-return / outer-wrapper event:
  - continue upward into the next consumer
  - or patch the newly hit failfast / assert site if a Watson helper finally fires

## 2026-04-13 - post-finalize return proven; seam moved into FUN_18332df80 epilogue/return

Fresh full-shell success condition before the run:

- WeChat was back at the real main chat UI
- `File Transfer` was visibly selected
- fresh main UI host:
  - PID `11116`
  - main thread `5572`

Runner changes immediately before this run:

- added precise return-site probes above the post-finalize helper path:
  - `builder-message-prep-post-finalize-return-site` at `0x18332f068`
  - `builder-message-prep-outer-wrapper-enter` / `leave` on `FUN_181618040`
  - `builder-message-prep-outer-wrapper-inner-return-site` at `0x181618078`
  - `builder-message-prep-outer-wrapper-await-return-site` at `0x181618087`
- later added extra logging at the post-finalize return site for:
  - `rsp`
  - `rbp`
  - saved return address from the stack
  - expected outer-wrapper return site
  - note: that extra stack-return logging was added after the key `11116 / 5572` run below, so it is not present in that artifact yet

Key artifact:

- `handover/v1/cold-run-current-11116-5572-entryB-focusedbaseline-nativehelper-watson.err`

What this run proved:

- the native helper-backed post-finalize bypass plus Watson bypass got farther than all previous focused cold runs
- observed in order:
  - `builder-message-prep-outer-wrapper-enter`
  - the usual focused builder / loop / finalize progression
  - `builder-message-prep-post-finalize-resolve-bypassed`
  - `builder-message-prep-post-finalize-return-site`
- then Frida died while waiting for `runOnThread`, and `Weixin.exe` was gone afterward

Important negative evidence from the same artifact:

- there was **no**:
  - `builder-message-prep-outer-wrapper-inner-return-site`
  - `builder-message-prep-outer-wrapper-await-return-site`
  - `builder-message-prep-outer-wrapper-leave`
  - `watson-failfast-bypassed`
  - `invoke-watson-bypassed`
  - `process-exit-probe-hit`
  - `native-exception`

Current best interpretation after the `11116 / 5572` run:

1. We have now proven that the crash is **later** than the post-finalize helper call itself.
2. The run survived long enough to reach `FUN_18332f068`, i.e. immediately after `CALL FUN_1833bafa0`.
3. Because the outer-wrapper inner return site at `0x181618078` never fired, the active seam is now extremely narrow:
   - either inside the `FUN_18332df80` epilogue
   - or on the actual `RET` from `FUN_18332df80` back to `FUN_181618040`
4. In other words, the cold path is no longer blocked inside `FUN_1833bafa0`; it is blocked on getting safely out of `FUN_18332df80`.

Secondary operational findings after that run:

- after the crash, relaunches often came back only as the small launcher window again
- repeated attempts to advance that launcher via:
  - direct coordinate clicks
  - UIA `InvokePattern`
  - `Disable`
  - `Open WeChat`
  - `Transfer files only`
  did not reliably restore the full shell during this segment

Most useful next move from this point:

- wait for / restore a real full-shell UI host again
- rerun the focused cold path with the new post-finalize stack-return logging enabled
- inspect whether the saved return address at `0x18332f068` matches:
  - expected `FUN_181618040 + 0x38` (`0x181618078`)
- branch from that result:
  - if the saved return address is wrong, treat this as stack corruption around the post-finalize replacement path
  - if the saved return address is correct, treat this as a failfast / termination on or immediately after the `RET` out of `FUN_18332df80`

2026-04-13 - `FUN_18332df80` entry caller validated; real saved return slot confirmed and poisoned before post-finalize unwind
---------------------------------------------------------------------------------------------------------------------------

What changed in the runner:

- added `builderAuxAEntryState.byThread` and extended `builder-message-prep-aux-a-enter` to log/store:
  - `caller`
  - `entryRsp`
  - `entryRbp`
  - `entryStackReturnAddress`
- updated `builder-message-prep-post-finalize-return-site` to emit those saved entry values for the same thread
- verified in Ghidra that `FUN_18332df80` really establishes `RBP` as a frame pointer:
  - prologue:
    - `PUSH RBP`
    - `PUSH R15`
    - `PUSH R14`
    - `PUSH R13`
    - `PUSH R12`
    - `PUSH RSI`
    - `PUSH RDI`
    - `PUSH RBX`
    - `SUB RSP,0x2e8`
    - `LEA RBP,[RSP + 0x80]`
  - epilogue:
    - `MOV RAX,RDI`
    - restore `XMM6/XMM7`
    - `ADD RSP,0x2e8`
    - pop nonvolatiles
    - `RET`
- this proves `[RBP + 0x2a8]` is the *actual* caller return slot for `FUN_18332df80`
  - because entry `RSP` equals final `RET` slot and
  - `RBP = entryRSP - 0x80`

Key artifacts:

- `handover/v1/cold-run-current-11672-1276-entry-stackcmp.err`
- `handover/v1/cold-run-current-12376-4828-slotwatch.err`
- `handover/v1/cold-run-current-6440-12144-noawait.err`
- `handover/v1/cold-run-current-3700-12256-directfinalize.err`

What the `11672 / 1276` run proved:

- `builder-message-prep-aux-a-enter` fired with:
  - `caller = 0x7ffb23688077`
  - `entryStackReturnAddress = 0x7ffb23688077`
- this matches the true caller edge in `FUN_181618040`:
  - `CALL FUN_18332df80` at `0x181618072`
  - return address `0x181618077`
- so the invocation of `FUN_18332df80` arrives with the *correct* saved return address

What the `12376 / 4828` run proved:

- added `frameReturnSlot` at:
  - `builder-message-prep-loop-finalize-return-site`
  - `builder-message-prep-post-finalize-return-site`
- observed:
  - `entryStackReturnAddress = 0x7ffb23688077`
  - `builder-message-prep-loop-finalize-return-site.frameReturnSlot = 0x7ffb6e79141e`
  - `builder-message-prep-post-finalize-return-site.stackReturnAddress = 0x7ffb6e79141e`
- therefore the true saved caller return slot is already poisoned *before* the post-finalize helper wrapper completes
- this moves the active corruption seam earlier:
  - somewhere between `FUN_18332df80` entry and the `0x18332e917` site immediately after `CALL FUN_180968840`

Important correction to earlier reasoning:

- the previous uncertainty about `[RBP + 0x2a8]` being “maybe not the return slot” is now resolved
- Ghidra disassembly confirms it *is* the real saved caller return slot for `FUN_18332df80`

What the `6440 / 12144` run (`noawait`) showed:

- removing `--force-loop-finalize-await-bypass` is worse
- the path still reaches:
  - `detached-runonthread-enter`
  - request/source prep
  - `detached-native-entry-call`
- but then WeChat dies before the focused builder hooks meaningfully fire
- current interpretation:
  - native `FUN_180316b50 / FUN_180319290` are still not safe enough on cold-start
  - keep `--force-loop-finalize-await-bypass` enabled for now

What the `3700 / 12256` run (`directfinalize`) showed:

- I replaced `ensureLoopFinalizeCastBypass()` so `FUN_180968840` is fully replaced instead of only forcing the late `strcmp` result
- new direct behavior:
  - read the promise/result state from the incoming pair
  - return the native success payload directly using `extractForcedLoopFinalizeResult(...)`
  - skip the rest of `FUN_180968840`
- result so far:
  - this is *too early / too unstable* in its current form
  - the run only reached hook-install/setup logs and WeChat died before `detached-runonthread-enter`
- so the direct whole-function `FUN_180968840` bypass is not yet viable as currently implemented

Current best interpretation after this segment:

1. `FUN_18332df80` starts with the correct return address.
2. The real saved return slot is already poisoned by the time control reaches `0x18332e917` (immediately after `CALL FUN_180968840`).
3. That means the active cold-start corruption seam is *inside or before* the late `FUN_180968840` path, not in the later `FUN_1833bafa0` epilogue alone.
4. The helper-level await bypass is still needed; removing it crashes earlier.
5. A naive whole-function `FUN_180968840` direct-return bypass is not yet safe.

Best next move from here:

- revert or refine the whole-function `FUN_180968840` bypass and keep note that the current implementation is too aggressive
- keep `--force-loop-finalize-await-bypass`
- add the same `frameReturnSlot` bracket at earlier focused sites inside `FUN_18332df80`:
  - `builder-message-prep-loop-prep-enter`
  - `builder-message-prep-loop-item-return-site`
- determine whether the saved return slot flips:
  - before `FUN_180ebe570`
  - between `FUN_180ebe570` and `FUN_180968840`
  - or only during the `FUN_180968840` / finalize path
