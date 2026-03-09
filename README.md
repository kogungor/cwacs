# cwacs.nvim

Tree-sitter based, Lua-native security linter for Neovim.

`cwacs.nvim` scans code directly in Neovim using built-in tree-sitter, then reports findings through `vim.diagnostic`.

## Current Status

- Milestones completed: `SG-001` scaffold, `SG-002` basic tree-sitter engine, `SG-003` diagnostics UX.
- Commands available: `:CwacsScan`, `:CwacsToggle`, `:CwacsFindings`, `:CwacsExplain`, `:CwacsHelp`, `:CwacsHealth`.
- Realtime + on-save wiring is active.
- Initial detection implemented: `eval()` for JavaScript/TypeScript and Python.

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
- Current implemented tests: `SG-001` scaffold, `SG-002` engine baseline, `SG-003` diagnostics adapter.
- Future feature tests are already scaffolded and marked as skipped until implemented.

Run feature tests with headless Neovim:

```bash
nvim --headless -u NONE "+set rtp+=$(pwd)" "+luafile tests/run_feature_tests.lua"
```

Expected current result:
- `SG-001`, `SG-002`, and `SG-003` should pass (SG-002 may skip if JS parser is unavailable).
- `SG-004` .. `SG-016` should report skipped.

## Troubleshooting

- `:CwacsScan` always prints completion info. If findings are `0`, this can be normal.
- At this stage only `eval()` rules are active, so test with files like `playground/javascript/vuln_eval.js`.
- If you print all diagnostics, you may mostly see LSP entries. Filter cwacs diagnostics by namespace (example in Manual test flow step 3).

## Configuration

Current scaffold supports:

```lua
require("cwacs").setup({
  enabled = true,
  realtime = {
    enabled = true,
    debounce_ms = 300,
  },
  on_save = {
    enabled = true,
  },
  rules = {
    disabled = {},
  },
})
```

## Commands

- `:CwacsScan` - run scan for current buffer and show summary
- `:CwacsToggle` - enable/disable cwacs runtime scanning
- `:CwacsFindings` - refresh location list entries for current-buffer findings
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
