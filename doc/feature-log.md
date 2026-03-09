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

Status: pending

Planned:
- stronger timer lifecycle handling
- stale scan cancellation and concurrency safeguards
- test coverage for rapid edit scenarios

## SG-005..SG-016

Status: pending
