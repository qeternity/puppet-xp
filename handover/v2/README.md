# v2 Handover

This folder is a clean handover package for continuing the WeChat detached-send reverse-engineering work from the current point.

## Mission

Achieve **fully detached autonomous no-UI text send** in WeChat.

That means:

- no manual seed send
- no UI composition
- no UI send click
- app open only
- real delivery
- WeChat survives

## Start Here

Read these first:

1. [PROMPT.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/PROMPT.md>)
2. [PROGRESS.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/PROGRESS.md>)
3. [weixin_418_detached_send.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/weixin_418_detached_send.py>)

## Important Files

- [weixin_418_detached_send.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/weixin_418_detached_send.py>)
  - main runner and current instrumentation snapshot
- [MASTER.md](</C:/Users/Administrator/Code/puppet-xp/handover/v2/MASTER.md>)
  - broader historical context from the original handover
- [artifacts](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts>)
  - selected high-signal cold-run logs that capture the latest state

## Helper Scripts

These are copied in so the next session has the same thin wrappers available:

- [common.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/common.py>)
- [01_get_self_metadata.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/01_get_self_metadata.py>)
- [02_build_contact_table.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/02_build_contact_table.py>)
- [03_capture_conversations.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/03_capture_conversations.py>)
- [04_monitor_selected_conversation_history.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/04_monitor_selected_conversation_history.py>)
- [05_monitor_send_task_events.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/05_monitor_send_task_events.py>)
- [06_monitor_manager_message_events.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/06_monitor_manager_message_events.py>)
- [07_send_seeded_arbitrary_message.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/07_send_seeded_arbitrary_message.py>)
- [08_send_detached_no_ui_poc.py](</C:/Users/Administrator/Code/puppet-xp/handover/v2/08_send_detached_no_ui_poc.py>)

## Best Current Lead

The copied runner already reflects the latest baseline:

- hybrid await-bypass cold path
- `nativeCheckBudget = 2`

The best next experiment is to target the late item-bind / finalize seam with the existing saved-source restore knobs:

- `--restore-loop-finalize-bind-source-pair saved`
- likely also `--override-loop-finalize-source-pair saved`

## Key Artifacts To Compare

- [cold-run-current-12372-12312-awaithybrid-main5.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-12372-12312-awaithybrid-main5.err>)
- [cold-run-current-5272-2420-awaithybrid-main6.err](</C:/Users/Administrator/Code/puppet-xp/handover/v2/artifacts/cold-run-current-5272-2420-awaithybrid-main6.err>)

These show why the current baseline uses `nativeCheckBudget = 2` instead of `1`.
