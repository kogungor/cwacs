# cwacs feature log

This file tracks feature-by-feature delivery and must be updated after each feature.

## Progress Checklist

- [x] Scaffold and setup
- [x] Basic tree-sitter engine
- [x] Diagnostic API integration and UX
- [x] Debounce and async hardening
- [x] Dangerous functions built-ins
- [x] Hardcoded secrets
- [x] Compound pattern matching
- [x] Intra-function dataflow tracker
- [x] YAML rule loader and validator
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

## SG-006 - Hardcoded secrets

Status: done

Delivered:
- added keyword-based hardcoded secret detection across supported languages (`api_key`, `secret`, `password`, `token`, `private_key` patterns)
- added entropy-based token-like hardcoded secret detection (`entropy >= 4.5` with minimum length guard)
- added false-positive suppression for environment references (`os.environ`, `process.env`, `std::env::var`, etc.)
- added placeholder suppression for common dummy values (`changeme`, `example`, `dummy`, etc.)
- added allowlist suppression support via configurable `secrets.allowlist_path`
- added optional severity reduction for secret findings in test files
- added automated vulnerable/safe feature tests for hardcoded secret detection

## SG-007 - Compound pattern matching

Status: done

Delivered:
- added generic compound line-scanning utility with `all_of` and `any_of` operators
- added compound rule execution support in the engine
- added SQL-injection style compound rules for Python, JavaScript/TypeScript, and Go
- added automated test coverage for vulnerable/safe compound detection and `any_of` semantics

## SG-008 - Intra-function dataflow tracker

Status: done

Delivered:
- added `lua/cwacs/flow.lua` — line-based intra-function taint tracker
- two-phase algorithm: Pass 1 builds taint map (source → propagation → sanitizer), Pass 2 checks sink lines
- taint metadata tracks `raw` vs `embedded` state to distinguish safe parameterized calls from dangerous string interpolation/concatenation
- sanitizer interruption: any variable wrapped in a known sanitizer loses its taint
- source patterns cover Python (`request.args`, `sys.argv`, `os.environ`, `input()`, ...), JavaScript/TypeScript (`req.body`, `req.query`, `req.params`, location APIs, ...), Go (`r.FormValue`, `r.URL.Query`, `os.Args`, ...)
- sink patterns cover SQLi, command injection, code injection, path traversal, XSS, and open redirect across Python, JS/TS, and Go
- JS/TS `const`/`let`/`var` declaration syntax handled in LHS extraction
- flow module integrated into engine — runs when `on_save.flow_analysis = true` (default) or `flow.enabled = true`
- findings carry `confidence = "high"` — compound SQLi rules from SG-007 can be elevated now that dataflow confirms taint
- playground fixtures: `vuln_flow_sqli.py`, `safe_flow_sqli.py`, `vuln_flow_chain.py`, `vuln_flow_sqli.js`, `safe_flow_sqli.js`
- 7-assertion automated test covering: direct source→sink, multi-hop chain, sanitizer suppression, parameterized-query false-positive guard, JS detection, high-confidence assertion

## SG-009 - YAML rule loader and validator

Status: done

Delivered:
- added `lua/cwacs/loader.lua` with pure-Lua YAML subset parser (list of rule maps)
- supports `.yaml` and `.yml` loading from configured `rules.custom_path`
- normalizes `language`/`languages` and `pattern`/`line_pattern` forms
- validates required schema fields (`id`, language(s), pattern)
- skips invalid rules and tracks validation errors per file/entry
- integrated custom rule loading into rules selection path (`cwacs.rules`)
- added startup reload in `setup()` and manual reload command `:CwacsReloadRules`
- added automated feature coverage for valid+invalid YAML handling and execution through engine scan

## SG-010..SG-016

Status: pending
