# v2 Resume Point

## Objective

The only success condition is:

- fully detached autonomous no-UI WeChat text send
- no manual seed send
- no UI typing
- no UI send click
- WeChat only needs to be open and logged in
- the message must really land in the target conversation
- WeChat must remain alive afterward

Anything that depends on a manual seed, UI-assisted send, or immediate reuse of a manually created live-good object is **not** success.

## What This v2 Folder Contains

- [weixin_418_detached_send.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/weixin_418_detached_send.py>)
  - the authoritative runner snapshot to continue from
- [PROMPT.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/PROMPT.md>)
  - instructive continuation prompt for the next session
- [README.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/README.md>)
  - quick index of files and suggested reading order
- copied helper wrappers:
  - [common.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/common.py>)
  - [01_get_self_metadata.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/01_get_self_metadata.py>)
  - [02_build_contact_table.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/02_build_contact_table.py>)
  - [03_capture_conversations.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/03_capture_conversations.py>)
  - [04_monitor_selected_conversation_history.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/04_monitor_selected_conversation_history.py>)
  - [05_monitor_send_task_events.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/05_monitor_send_task_events.py>)
  - [06_monitor_manager_message_events.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/06_monitor_manager_message_events.py>)
  - [07_send_seeded_arbitrary_message.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/07_send_seeded_arbitrary_message.py>)
  - [08_send_detached_no_ui_poc.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/08_send_detached_no_ui_poc.py>)
- copied historical context:
  - [MASTER.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/MASTER.md>)
- selected high-signal cold-run artifacts:
  - [artifacts](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts>)

## Current Runner State

The active runner state is the copied [weixin_418_detached_send.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/weixin_418_detached_send.py>).

Important current facts:

- it already contains the late cold-path instrumentation accumulated during v1
- it is configured around the hybrid await-bypass path
- `loopFinalizeAwaitBypassState.nativeCheckBudget` is currently `2`
- the current work direction is to preserve the good parts of the live donor path while preventing late finalize / bind corruption

This is the exact code snapshot the next session should continue from, not a backport target.

## Proven Findings

These are the important truths established before this handover was written:

1. The detached send path is real.
   - It was proven previously in seed-assisted same-session runs.
   - That means the native machinery exists and can be driven.

2. Seed-assisted detached replay is not the objective.
   - It works only after a manual UI seed.
   - That is explicitly below the bar for this project.

3. Cold-start detached runs do get deep into the native pipeline.
   - This is not failing at the very first gate anymore.
   - The problem is hidden live state and/or late object-family corruption, not "wrong function entirely."

4. `nativeCheckBudget = 1` is too low.
   - The first finalize never resolves.
   - The run times out while the detached thread is still active.

5. `nativeCheckBudget = 2` is materially better.
   - The first finalize resolves.
   - The run reaches the later finalize seam again.
   - WeChat still dies before message delivery, so more work is needed.

6. The highest-signal remaining anomaly is late bind / finalize source-pair corruption.
   - This is now the best current lead.
   - Existing CLI knobs already exist to test saved-source restoration around that seam.

## Latest High-Signal Run Sequence

The key artifact set copied into `v2/artifacts` is:

- [cold-run-current-1732-11920-awaithybrid-main1.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-1732-11920-awaithybrid-main1.err>)
- [cold-run-current-12488-13756-awaithybrid-main2.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-12488-13756-awaithybrid-main2.err>)
- [cold-run-current-11548-12292-awaithybrid-main3.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-11548-12292-awaithybrid-main3.err>)
- [cold-run-current-13640-6956-awaithybrid-main4.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-13640-6956-awaithybrid-main4.err>)
- [cold-run-current-12372-12312-awaithybrid-main5.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-12372-12312-awaithybrid-main5.err>)
- [cold-run-current-5272-2420-awaithybrid-main6.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-5272-2420-awaithybrid-main6.err>)
- [cold-run-current-9004-8504-awaithybrid1.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-9004-8504-awaithybrid1.err>)

What these runs mean in practical terms:

- `main1` through `main4` established that the hybrid await-bypass path is the most promising current cold-start direction.
- `main5` showed that `nativeCheckBudget = 1` is not enough:
  - first finalize remains unresolved
  - the run hangs/times out before a useful later-state comparison
- `main6` showed that `nativeCheckBudget = 2` is better:
  - first finalize resolves
  - the path advances to the later seam again
  - WeChat still dies before detached delivery completes

Taken together, these runs narrow the active problem to the later bind/finalize state rather than the earlier donor acquisition or initial normalize stage.

## Current Best Hypothesis

The cold path is now most likely failing because the late item-bind / finalize family is operating on a corrupted or wrong source pair.

Why this is the best current hypothesis:

- the earlier stages are now getting far enough that the run is meaningfully inside the detached pipeline
- `nativeCheckBudget = 2` removes the earlier "first finalize never resolved" failure mode
- the remaining bad state consistently clusters around the late bind/finalize pair handling
- the runner already exposes saved-source restore knobs that directly target this seam

This makes the next step much more concrete than earlier iterations:

- do not restart from broad exploration
- do not go back to seeded replay work
- focus on restoring the correct source pair at the late finalize seam

## Best Next Experiment

Keep the current runner snapshot and keep `nativeCheckBudget = 2`.

The next highest-value experiment is:

- run the current hybrid cold path
- add `--restore-loop-finalize-bind-source-pair saved`
- likely also add `--override-loop-finalize-source-pair saved`

Why this is the right next move:

- it directly targets the current highest-signal anomaly
- the knobs already exist, so this is a low-friction test
- it preserves the current best-performing cold path instead of replacing it with a new speculative branch

If this works, the path may survive the late finalize family and finally land a true no-seed detached message.

If it fails, the failure should still be much more informative than older runs because the earlier path is already in a better state than before.

## Operational Notes

These details mattered repeatedly during the v1 work and should carry forward into v2.

### WeChat UI handling

- when changing conversations, use a **single click only**
- do **not** double click a conversation
- double clicking can pop the chat into a separate window and poison test conditions

### Safe Mode recovery

If WeChat opens into the crash/safe-mode recovery flow:

- click `Next`
- keep clicking `Next` until the flow offers the button that returns to Weixin
- click the return/open button when it appears
- if the regular launcher window appears, click the `Open` button
- if an `错误报告` dialog appears, dismiss it with `确定`

Do not introduce extra UI actions unless needed for recovery.

### Window control caution

- do not foreground Ghidra by title when trying to focus WeChat
- Ghidra windows can contain `WeChat` / `Weixin` in their titles and are easy to target by mistake
- prefer direct launcher/window selection through Windows MCP screen interaction

### Process sanity checks

If Frida attach fails, always check process liveness first.

In prior sessions, `VirtualAllocEx returned 0x00000005` often meant:

- `Weixin.exe` had already crashed or exited
- not that Frida itself was permanently broken

## Validation Standard

Do not count anything as success unless all of these are true:

- no manual seed send happened in the successful run
- no UI message composition or UI send interaction was needed
- the detached runner caused the message to land in the target conversation
- the message body is the intended body
- WeChat remains running afterward

Anything weaker than that is diagnostic progress, not project success.

## Suggested Resume Order

1. Read [PROMPT.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/PROMPT.md>).
2. Skim [README.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/README.md>).
3. Use [weixin_418_detached_send.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/weixin_418_detached_send.py>) as the source of truth.
4. Compare `main5` and `main6` in [artifacts](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts>) to understand the budget change.
5. Start with the saved-source late-finalize experiment described above.

## Bottom Line

The project is not solved, but it is also not at square one.

The current state is:

- detached native send path proven in seeded form
- cold-start path materially advanced
- first-finalize resolution improved by `nativeCheckBudget = 2`
- best remaining lead identified as late bind/finalize source-pair corruption

The most efficient continuation is to keep this exact runner snapshot and push directly on that remaining seam.
