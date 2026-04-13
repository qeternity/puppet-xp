# Continuation Prompt

You are resuming reverse engineering work on WeChat `4.1.8.29`.

Your objective is strict and narrow:

- achieve **fully detached autonomous no-UI text sending**
- no manual seed send
- no UI-assisted composition
- no UI send click
- WeChat only needs to be open and logged in
- the detached invocation must cause a real message to land
- WeChat must survive after the send

Do **not** treat any of the following as success:

- manual seed then detached replay
- same-session capture followed by detached replay
- UI automation of the compose/send box
- a local failed row that does not really deliver
- a run that crashes WeChat after appearing to progress

## Source Of Truth

Use [weixin_418_detached_send.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/weixin_418_detached_send.py>) as the authoritative runner snapshot.

This file already contains the latest cold-path instrumentation and is where the work should continue.

## Current Resume Point

The strongest current cold-start direction is the hybrid await-bypass path with:

- `loopFinalizeAwaitBypassState.nativeCheckBudget = 2`

That change is already present in the runner.

The most important current conclusion is:

- the highest-signal remaining anomaly is **late item-bind / finalize source-pair corruption**

The next best experiment is therefore:

- keep the current runner snapshot
- keep the current budget of `2`
- test `--restore-loop-finalize-bind-source-pair saved`
- likely also test `--override-loop-finalize-source-pair saved`

The point is to preserve the good parts of the current cold path while restoring a correct source pair across the late finalize seam.

## What To Read First

1. [PROGRESS.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/PROGRESS.md>)
2. [README.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/README.md>)
3. The copied high-signal artifacts in [artifacts](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts>)

Most useful comparison:

- [cold-run-current-12372-12312-awaithybrid-main5.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-12372-12312-awaithybrid-main5.err>)
- [cold-run-current-5272-2420-awaithybrid-main6.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-5272-2420-awaithybrid-main6.err>)

Those two runs show why `nativeCheckBudget = 2` is the current baseline.

## Constraints And Standards

- Keep the strict success bar above.
- Do not broaden the scope into UI automation unless explicitly told to.
- Do not regress into "seeded send is good enough."
- Update [PROGRESS.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/PROGRESS.md>) with every meaningful finding so the resume point stays accurate.

## Practical Operating Notes

### Conversation switching

- single click only
- never double click a conversation entry

### Safe Mode / launcher recovery

If WeChat comes up in the recovery flow:

- click `Next`
- keep clicking `Next` until the flow returns to the normal launcher/open state
- click the button that returns to Weixin / opens WeChat
- if the launcher window appears, click `Open`
- if `错误报告` appears, click `确定`

Do not do anything more elaborate than that unless recovery is clearly stuck.

### Window targeting

- do not foreground Ghidra by title when trying to target WeChat
- Ghidra can contain WeChat-related titles and is easy to bring forward by mistake

### Attach failures

If Frida attach fails:

- check whether `Weixin.exe` is still running before assuming the tooling is broken

## Immediate Mission

Pick up exactly from the late finalize seam.

Start by trying to keep the current successful early cold-path behavior while restoring saved source state at the loop-finalize bind/finalize stage. The fastest valuable progress is the saved-source restore experiment, not a restart from broad exploratory tracing.
