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
