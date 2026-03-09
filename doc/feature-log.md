# cwacs feature log

This file tracks feature-by-feature delivery and must be updated after each feature.

## SG-001 - Scaffold and setup

Status: done

Delivered:
- `cwacs` module scaffold
- setup/config merge
- commands and autocmd wiring
- basic diagnostics namespace integration

## SG-002 - Basic tree-sitter engine

Status: done

Delivered:
- tree-sitter parser/query execution pipeline
- normalized finding struct output
- baseline built-in eval rules (js/ts/python)

## SG-003 - Diagnostics UX

Status: done

Delivered:
- richer diagnostic message format (`rule_id`, `CWE`, `confidence`)
- `:CwacsFindings`, `:CwacsExplain`, `:CwacsFinding`
- `:CwacsHelp`, `:CwacsHealth`
- scan summary with severity counts + top finding

## SG-004 - Debounce and async hardening

Status: done

Delivered:
- per-buffer scan generation guard to ignore stale scheduled callbacks
- improved timer lifecycle handling and cleanup on toggle/buffer deletion
- on-save forced scan path independent from changedtick cache
- realtime trigger includes insert-mode changes (`TextChangedI`)
- optional realtime summary notifications via `realtime.notify`
- automated test coverage for rapid edits, forced on-save scans, and deleted-buffer timers

## SG-005..SG-016

Status: pending
