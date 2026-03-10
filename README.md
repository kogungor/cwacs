# cwacs.nvim

Tree-sitter based, Lua-native security linter for Neovim.

`cwacs.nvim` scans code directly in Neovim using built-in tree-sitter, then reports findings through `vim.diagnostic`.

## Current Status

- Milestones completed: scaffold and setup, basic tree-sitter engine, diagnostics UX, debounce and async management, dangerous functions built-ins, hardcoded secrets rules, compound pattern matching, intra-function dataflow tracking.
- Commands available: `:CwacsScan`, `:CwacsToggle`, `:CwacsFindings`, `:CwacsExplain`, `:CwacsHelp`, `:CwacsHealth`.
- Realtime + on-save wiring is active.
- Debounce now cancels stale scheduled scans and force-runs on save.
- Initial dangerous-function detection is implemented for Python, JavaScript/TypeScript, Go, and Rust.
- Hardcoded secret detection now includes keyword-based and high-entropy token rules with env/placeholder suppression.
- Intra-function dataflow tracker now follows source -> reassignment -> sink chains with sanitizer interruption.

## Goals

- Zero external runtime dependencies (Neovim + tree-sitter only)
- Fast editor feedback during coding
- Extensible rule architecture (built-ins + custom rules)
- OWASP-focused detection roadmap

## Requirements

- Neovim `>= 0.10` (recommended)
- Tree-sitter parsers for the languages you want to scan

## Local Installation (for development/testing)

Use local plugin path first, before publishing.

### lazy.nvim

Create `lua/kog/plugins/cwacs.lua` in your Neovim config:

```lua
return {
  {
    dir = "~/Desktop/dev/cwacs",
    name = "cwacs.nvim",
    config = function()
      require("cwacs").setup({
        enabled = true,
        realtime = {
          enabled = true,
          debounce_ms = 300,
        },
        on_save = {
          enabled = true,
          flow_analysis = true,
        },
        flow = {
          enabled = true,
        },
        scan = {
          notify_on_manual = true,
          notify_when_no_findings = true,
        },
      })
    end,
  },
}
```

Then run `:Lazy sync` and restart Neovim.

### Manual test flow

1. Open any source file (Python/JS/etc.)
2. Run `:CwacsScan`
3. Run `:lua vim.print(vim.diagnostic.get(0, { namespace = require('cwacs.diagnostics').namespace() }))`
4. Toggle realtime with `:CwacsToggle`
5. Build findings list with `:CwacsFindings`, then open with `:lopen`
6. On a finding line, show popup detail with `:CwacsExplain` (or `:CwacsFinding` alias)
7. Run `:CwacsHealth` to verify parser readiness

You can also use prepared fixtures under `playground/`.

## Feature Test Files

- One feature test file exists per milestone under `tests/features/` (`sg_001` .. `sg_016`).
- Current implemented tests: scaffold and setup, tree-sitter engine baseline, diagnostics adapter, debounce and async management, dangerous functions built-ins, hardcoded secrets rules, compound pattern matching, intra-function dataflow tracking.
- Future feature tests are already scaffolded and marked as skipped until implemented.

Run feature tests with headless Neovim:

```bash
nvim --headless -u NONE "+set rtp+=$(pwd)" "+luafile tests/run_feature_tests.lua"
```

Expected current result:
- Scaffold and setup, diagnostics adapter, and debounce and async management should pass.
- Tree-sitter engine baseline may skip if JS parser is unavailable.
- Dangerous functions built-ins may skip if required parsers are unavailable.
- Hardcoded secrets rules should pass without parser dependency.
- Compound pattern matching should pass without parser dependency.
- Intra-function dataflow tracking should pass without parser dependency.
- Remaining planned features should report skipped.

## Troubleshooting

- `:CwacsScan` always prints completion info. If findings are `0`, this can be normal.
- Current rules include `eval()`, command execution primitives, selected deserialization APIs, and SQL-injection style compound patterns.
- For compound validation, use `playground/python/vuln_sqli_concat.py`, `playground/python/safe_sqli_param.py`, and `playground/javascript/vuln_sqli_template.js`.
- For dataflow validation, use `playground/python/vuln_flow_sqli.py`, `playground/python/safe_flow_sqli.py`, `playground/python/vuln_flow_chain.py`, `playground/javascript/vuln_flow_sqli.js`, and `playground/javascript/safe_flow_sqli.js`.
- For secret validation, use `playground/python/vuln_secret.py` and `playground/javascript/vuln_secret.js`.
- If you print all diagnostics, you may mostly see LSP entries. Filter cwacs diagnostics by namespace (example in Manual test flow step 3).
- If diagnostics output is `{}`, there are no cwacs findings for the current buffer/line. Verify with `:CwacsHealth` that the language parser is installed and use a known vulnerable fixture.
- To get realtime scan notifications while typing, set `realtime.notify = true` in setup.
- If notifications are too noisy, increase `realtime.notify_min_interval_ms`.
- For temporary scan tracing, set `realtime.debug = true`.
- To hide manual scan notifications, set `scan.notify_on_manual = false`.
- To hide "0 findings" notifications, set `scan.notify_when_no_findings = false`.
- To suppress known secret literals, add them line-by-line to `.cwacs/allowlist` (or set `secrets.allowlist_path`).
- To reduce noisy secret findings in test files, keep `secrets.reduce_severity_in_tests = true`.

## Configuration

Current scaffold supports:

```lua
require("cwacs").setup({
  enabled = true,
  realtime = {
    enabled = true,
    debounce_ms = 300,
    notify = false,
    notify_min_interval_ms = 1500,
    debug = false,
  },
  on_save = {
    enabled = true,
    flow_analysis = true,
  },
  flow = {
    enabled = true,
  },
  scan = {
    notify_on_manual = true,
    notify_when_no_findings = true,
  },
  secrets = {
    allowlist_path = ".cwacs/allowlist",
    reduce_severity_in_tests = true,
    test_file_severity = "low",
  },
  test_file_patterns = {
    "_test.",
    "test_",
    ".spec.",
    ".test.",
    "/tests/",
    "/spec/",
    "/fixtures/",
  },
  rules = {
    disabled = {},
  },
})
```

## Commands

- `:CwacsScan` - run scan for current buffer and show summary
- `:CwacsToggle` - enable/disable cwacs runtime scanning
- `:CwacsFindings` - refresh location list entries for current-buffer findings (then use `:lopen`)
- `:CwacsExplain` - open float popup for finding on current line
- `:CwacsFinding` - alias of `:CwacsExplain`
- `:CwacsHelp` - show quick command help
- `:CwacsHealth` - show required parser readiness report

## Architecture (scaffold phase)

- `lua/cwacs/init.lua` - public entrypoint
- `lua/cwacs/core.lua` - command/autocmd wiring and scan orchestration
- `lua/cwacs/config.lua` - defaults and config merge
- `lua/cwacs/engine.lua` - tree-sitter scan engine (baseline rules)
- `lua/cwacs/diagnostics.lua` - diagnostic translation + namespace
- `lua/cwacs/rules/init.lua` - built-in rule registry (to be expanded)
- `plugin/cwacs.lua` - plugin load guard

## Roadmap

Implementation is tracked feature-by-feature in local `TASKS.md` (kept out of remote by local git exclude).

## In-repo Documentation

- `doc/README.md` - documentation policy and structure
- `doc/cwacs.md` - detailed project documentation
- `doc/feature-log.md` - feature-by-feature delivery log
- `doc/cwacs.txt` - Vim help scaffold

## Contributing Workflow

- Use feature branches from `dev`: `feature/*`, `bugfix/*`, `hotfix/*`
- Keep plugin working at the end of every feature
- Add or update docs/tests with each milestone

## README Maintenance Rule

README and `doc/*` are reviewed at the end of every feature and updated when behavior, config, commands, or integration changes.
