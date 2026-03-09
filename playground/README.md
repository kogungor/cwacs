# cwacs playground

Manual testing fixtures for quick local validation.

## How to use

1. Open one of the files in this folder.
2. Run `:CwacsScan`.
3. Check diagnostics with `:lua vim.print(vim.diagnostic.get(0))`.

## Fixtures

- `python/vuln_eval.py` and `python/safe_no_eval.py`
- `javascript/vuln_eval.js` and `javascript/safe_no_eval.js`
- `go/vuln_exec.go` and `go/safe_exec.go`
- `rust/vuln_command.rs` and `rust/safe_command.rs`

As rule packs land in each feature, add matching vulnerable/safe examples here.
