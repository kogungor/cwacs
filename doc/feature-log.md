# cwacs feature log

This file tracks feature-by-feature delivery and must be updated after each feature.

## Progress Checklist

- [x] Scaffold and setup
- [x] Basic tree-sitter engine
- [x] Diagnostic API integration and UX
- [x] Debounce and async hardening
- [x] Dangerous functions built-ins
- [ ] Hardcoded secrets
- [ ] Compound pattern matching
- [ ] Intra-function dataflow tracker
- [ ] YAML rule loader and validator
- [ ] SQL Injection + XSS + Command Injection packs
- [ ] Insecure crypto, deserialization, path traversal, open redirect packs
- [ ] Ignore and suppress mechanisms
- [ ] JSON/SARIF export
- [ ] MCP server mode
- [ ] Vulnerability test corpus and CI
- [ ] Documentation and help completion

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
- realtime notification throttling via `realtime.notify_min_interval_ms`
- optional debug trace notifications via `realtime.debug`
- manual scan notification control via `scan.notify_on_manual`
- zero-finding notification control via `scan.notify_when_no_findings`
- parser readiness now includes install hint for missing languages
- automated test coverage for rapid edits, forced on-save scans, and deleted-buffer timers

## SG-005 - Dangerous functions built-ins

Status: done

Delivered:
- expanded Python dangerous API rules (`exec`, `os.system`, `subprocess.call`, selected deserialization patterns)
- expanded JavaScript/TypeScript dangerous API rules (`Function`, string timer execution, exec-like patterns)
- added baseline Go rule for `exec.Command(...)`
- added baseline Rust rule for `Command::new(...)`
- added parser-aware vulnerable/safe automated tests across supported languages

## SG-006..SG-016

Status: pending
