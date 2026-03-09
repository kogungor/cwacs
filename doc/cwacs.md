# cwacs.nvim

Tree-sitter based, Lua-native security lint plugin for Neovim.

## Current milestone status

- Scaffold and setup: done
- Basic tree-sitter engine: done
- Diagnostic API integration and UX commands: done
- Debounce and async management: done
- Dangerous functions built-ins: done
- Hardcoded secrets rules: done
- Compound pattern matching: done
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

- JavaScript/TypeScript: `eval(...)`, `Function(...)`, string-based timer execution, `exec(...)` patterns
- Python: `eval(...)`, `exec(...)`, `os.system(...)`, `subprocess.call(...)`, selected deserialization APIs
- Go: `exec.Command(...)` pattern checks
- Rust: `Command::new(...)` pattern checks
- Language-agnostic secret detection: keyword-based secret assignments and high-entropy token-like literals
- Compound SQL-injection style detection: Python concatenated execute, JS template-literal query, Go sprintf+query same-line pattern

Notes:
- Missing tree-sitter parser for a language results in no findings for that language.
- Hardcoded secret rules include suppression for environment references and placeholder dummy values.
- Hardcoded secret values can be allowlisted via `.cwacs/allowlist`.
- Secret findings in test files can be severity-reduced using config.

## Configuration

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
- Realtime notification frequency can be throttled with `realtime.notify_min_interval_ms`.
- Temporary scan trace notifications can be enabled with `realtime.debug = true`.
- Manual scan summary notifications can be disabled with `scan.notify_on_manual = false`.
- Zero-finding notifications can be disabled with `scan.notify_when_no_findings = false`.
- Secret values can be suppressed through allowlist entries at `secrets.allowlist_path`.
- Secret finding severity can be reduced in test files with `secrets.reduce_severity_in_tests`.

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
