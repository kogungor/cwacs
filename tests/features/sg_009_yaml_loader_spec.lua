return {
  id = "SG-009",
  name = "YAML loader",
  run = function(ctx)
    local ok_config, config = pcall(require, "cwacs.config")
    local ok_loader, loader = pcall(require, "cwacs.loader")
    local ok_rules, rules = pcall(require, "cwacs.rules")
    local ok_engine, engine = pcall(require, "cwacs.engine")

    ctx:assert(ok_config, "cwacs.config should load")
    ctx:assert(ok_loader, "cwacs.loader should load")
    ctx:assert(ok_rules, "cwacs.rules should load")
    ctx:assert(ok_engine, "cwacs.engine should load")

    local temp_root = vim.fn.tempname() .. "_cwacs_rules"
    vim.fn.mkdir(temp_root, "p")

    local valid_yaml = table.concat({
      "- id: CWACS_CUSTOM_LUA_DANGER_PRINT",
      "  language: lua",
      "  severity: low",
      "  confidence: high",
      "  cwe: CWE-0",
      "  message: Debug print found",
      "  line_pattern: \"danger_print%s*%(\"",
      "",
      "- id: CWACS_CUSTOM_PY_BAD_SQL",
      "  languages: [python]",
      "  severity: medium",
      "  confidence: medium",
      "  cwe: CWE-89",
      "  message: Bad SQL marker found",
      "  pattern: \"BAD_SQL_MARKER\"",
    }, "\n")

    local invalid_yaml = table.concat({
      "- id: CWACS_INVALID_NO_PATTERN",
      "  language: lua",
      "  message: missing pattern should fail",
    }, "\n")

    local valid_path = temp_root .. "/custom_rules.yaml"
    local invalid_path = temp_root .. "/invalid.yaml"
    vim.fn.writefile(vim.split(valid_yaml, "\n"), valid_path)
    vim.fn.writefile(vim.split(invalid_yaml, "\n"), invalid_path)

    local loaded, errors = loader.load_path(temp_root)
    ctx:assert(#loaded == 2, "loader should load 2 valid rules")
    ctx:assert(#errors == 1, "loader should report 1 invalid rule")

    config.set({
      rules = { custom_path = temp_root },
      scan = { notify_on_manual = false, notify_when_no_findings = false },
    })
    local reloaded, reload_errors = rules.reload_custom()
    ctx:assert(#reloaded == 2, "rules.reload_custom should import 2 custom rules")
    ctx:assert(#reload_errors == 1, "rules.reload_custom should preserve validation errors")

    local lua_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[lua_buf].filetype = "lua"
    vim.api.nvim_buf_set_lines(lua_buf, 0, -1, false, {
      "local value = 1",
      "danger_print(value)",
    })

    local lua_findings = engine.scan(lua_buf)
    local lua_hit = false
    for _, f in ipairs(lua_findings) do
      if f.rule_id == "CWACS_CUSTOM_LUA_DANGER_PRINT" then
        lua_hit = true
        break
      end
    end
    ctx:assert(lua_hit, "custom YAML pattern rule should execute via engine")

    local py_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[py_buf].filetype = "python"
    vim.api.nvim_buf_set_lines(py_buf, 0, -1, false, {
      "query = 'SELECT * FROM users'",
      "marker = 'BAD_SQL_MARKER'",
    })

    local py_findings = engine.scan(py_buf)
    local py_hit = false
    for _, f in ipairs(py_findings) do
      if f.rule_id == "CWACS_CUSTOM_PY_BAD_SQL" then
        py_hit = true
        break
      end
    end
    ctx:assert(py_hit, "custom YAML rule with languages list should execute")

    vim.fn.delete(temp_root, "rf")
  end,
}
