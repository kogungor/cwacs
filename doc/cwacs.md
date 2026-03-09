# cwacs.nvim

Tree-sitter based, Lua-native security lint plugin for Neovim.

## Current milestone status

- Scaffold and setup: done
- Basic tree-sitter engine: done
- Diagnostic API integration and UX commands: done
- Debounce and async management: done
- Remaining planned features: pending

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
    notify = false,
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

## Debounce and async behavior

- Rapid `TextChanged` events are debounced into a single scan execution window.
- Insert-mode typing is included via `TextChangedI`.
- Stale scheduled timers are ignored via per-buffer scan generation checks.
- On-save scans force execution even if `changedtick` did not change.
- Pending timers are cleaned when buffers are deleted or wiped.
- Optional realtime summary notifications can be enabled with `realtime.notify = true`.

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
