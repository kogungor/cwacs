return {
  id = "Compound pattern matching",
  name = "Compound patterns",
  run = function(ctx)
    local ok_engine, engine = pcall(require, "cwacs.engine")
    local ok_compound, compound = pcall(require, "cwacs.util.compound")
    ctx:assert(ok_engine, "cwacs.engine should load")
    ctx:assert(ok_compound, "cwacs.util.compound should load")

    local py_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[py_buf].filetype = "python"
    vim.api.nvim_buf_set_lines(py_buf, 0, -1, false, {
      "cursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)",
    })
    local py_findings = engine.scan(py_buf)
    local py_hit = false
    for _, finding in ipairs(py_findings) do
      if finding.rule_id == "CWACS_PY_SQLI_STRING_CONCAT_EXECUTE" then
        py_hit = true
        break
      end
    end
    ctx:assert(py_hit, "python concat execute pattern should be detected")

    local py_safe_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[py_safe_buf].filetype = "python"
    vim.api.nvim_buf_set_lines(py_safe_buf, 0, -1, false, {
      "cursor.execute(\"SELECT * FROM users WHERE id=%s\", (user_id,))",
    })
    local py_safe_findings = engine.scan(py_safe_buf)
    local py_safe_hit = false
    for _, finding in ipairs(py_safe_findings) do
      if finding.rule_id == "CWACS_PY_SQLI_STRING_CONCAT_EXECUTE" then
        py_safe_hit = true
        break
      end
    end
    ctx:assert(not py_safe_hit, "parameterized execute should not trigger concat compound rule")

    local js_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[js_buf].filetype = "javascript"
    vim.api.nvim_buf_set_lines(js_buf, 0, -1, false, {
      "db.query(`SELECT * FROM users WHERE id=${userId}`)",
    })
    local js_findings = engine.scan(js_buf)
    local js_hit = false
    for _, finding in ipairs(js_findings) do
      if finding.rule_id == "CWACS_JS_SQLI_TEMPLATE_QUERY" then
        js_hit = true
        break
      end
    end
    ctx:assert(js_hit, "javascript template query pattern should be detected")

    local any_of_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[any_of_buf].filetype = "lua"
    vim.api.nvim_buf_set_lines(any_of_buf, 0, -1, false, {
      "one_line_without_hit()",
      "second_line_with_match()",
    })
    local any_of_findings = compound.scan_lines(any_of_buf, {
      id = "TEST_ANY_OF",
      severity = "low",
      confidence = "low",
      cwe = "CWE-0",
      message = "test any_of",
      compound = {
        operator = "any_of",
        clauses = {
          { type = "line_pattern", pattern = "first_miss" },
          { type = "line_pattern", pattern = "second_line_with_match" },
        },
      },
    })
    ctx:assert(#any_of_findings == 1, "any_of compound evaluation should detect a line when any clause matches")
  end,
}
