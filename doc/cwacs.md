# cwacs.nvim

Tree-sitter based, Lua-native security lint plugin for Neovim.

## Current milestone status

- SG-001: done (scaffold + setup + runtime wiring)
- SG-002: done (baseline tree-sitter engine + eval detection)
- SG-003: done (diagnostics UX commands and messages)
- SG-004..SG-016: planned

## Commands

- `:CwacsScan` - scan current buffer and show summary
- `:CwacsToggle` - enable/disable realtime scans
- `:CwacsFindings` - refresh location list entries
- `:CwacsExplain` - float detail on current finding line
- `:CwacsFinding` - alias of `:CwacsExplain`
- `:CwacsHelp` - quick command help
- `:CwacsHealth` - parser readiness check

## Current detection coverage

- JavaScript/TypeScript: `eval(...)`
- Python: `eval(...)`

Notes:
- Rust/Go dangerous function coverage is planned under SG-005/SG-010.
- Missing tree-sitter parser for a language results in no findings for that language.

## Configuration

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

## UI model

- Primary detail UX: float popup (`:CwacsExplain`)
- Batch triage UX: location list (`:CwacsFindings` + `:lopen`)
- Scan summary UX: notify with severity counts and top finding

## Local development install

Use local path plugin spec in your Neovim config:

```lua
return {
  {
    dir = "~/Desktop/dev/cwacs",
    name = "cwacs.nvim",
    config = function()
      require("cwacs").setup({})
    end,
  },
}
```

Then run `:Lazy sync` and restart Neovim.
