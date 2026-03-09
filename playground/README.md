# cwacs playground

Manual testing fixtures for quick local validation.

## How to use

1. Open one of the files in this folder.
2. Run `:CwacsScan`.
3. Check diagnostics with `:lua vim.print(vim.diagnostic.get(0))`.

## Fixtures

- `python/vuln_eval.py` and `python/safe_no_eval.py`
- `python/vuln_secret.py` and `python/safe_env_secret.py`
- `python/vuln_sqli_concat.py` and `python/safe_sqli_param.py`
- `javascript/vuln_eval.js` and `javascript/safe_no_eval.js`
- `javascript/vuln_secret.js` and `javascript/safe_env_secret.js`
- `javascript/vuln_sqli_template.js`
- `go/vuln_exec.go` and `go/safe_exec.go`
- `rust/vuln_command.rs` and `rust/safe_command.rs`

As rule packs land in each feature, add matching vulnerable/safe examples here.
