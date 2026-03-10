return {
  id = "SG-008",
  name = "Intra-function dataflow",
  run = function(ctx)
    local ok_flow, flow = pcall(require, "cwacs.flow")
    ctx:assert(ok_flow, "cwacs.flow should load without errors")

    -- -----------------------------------------------------------------------
    -- 1. Direct source → sink (Python SQLi)
    -- -----------------------------------------------------------------------
    local py_direct_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[py_direct_buf].filetype = "python"
    vim.api.nvim_buf_set_lines(py_direct_buf, 0, -1, false, {
      'user_id = request.args.get("id")',
      'query = "SELECT * FROM users WHERE id=" + user_id',
      "db.execute(query)",
    })
    local py_direct = flow.scan(py_direct_buf, "python")
    local py_direct_hit = false
    for _, f in ipairs(py_direct) do
      if f.rule_id == "CWACS_FLOW_PY_SQLI" then
        py_direct_hit = true
        break
      end
    end
    ctx:assert(py_direct_hit, "direct source→sink Python SQLi should be detected")

    -- -----------------------------------------------------------------------
    -- 2. Multi-hop reassignment chain (Python SQLi)
    -- -----------------------------------------------------------------------
    local py_chain_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[py_chain_buf].filetype = "python"
    vim.api.nvim_buf_set_lines(py_chain_buf, 0, -1, false, {
      "raw = sys.argv[1]",
      "term = raw",
      'clause = "WHERE name=" + term',
      'db.execute("SELECT * FROM items " + clause)',
    })
    local py_chain = flow.scan(py_chain_buf, "python")
    local py_chain_hit = false
    for _, f in ipairs(py_chain) do
      if f.rule_id == "CWACS_FLOW_PY_SQLI" then
        py_chain_hit = true
        break
      end
    end
    ctx:assert(py_chain_hit, "multi-hop reassignment chain Python SQLi should be detected")

    -- -----------------------------------------------------------------------
    -- 3. Sanitizer interrupts taint (Python)
    -- -----------------------------------------------------------------------
    local py_safe_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[py_safe_buf].filetype = "python"
    vim.api.nvim_buf_set_lines(py_safe_buf, 0, -1, false, {
      'user_id = request.args.get("id")',
      "safe_id = escape(user_id)",
      'db.execute("SELECT * FROM users WHERE id=" + safe_id)',
    })
    local py_safe = flow.scan(py_safe_buf, "python")
    local py_safe_hit = false
    for _, f in ipairs(py_safe) do
      if f.rule_id == "CWACS_FLOW_PY_SQLI" then
        py_safe_hit = true
        break
      end
    end
    ctx:assert(not py_safe_hit, "sanitizer should interrupt taint and suppress finding")

    -- -----------------------------------------------------------------------
    -- 4. Parameterized query — no taint reaches sink (Python)
    -- -----------------------------------------------------------------------
    local py_param_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[py_param_buf].filetype = "python"
    vim.api.nvim_buf_set_lines(py_param_buf, 0, -1, false, {
      'user_id = request.args.get("id")',
      'db.execute("SELECT * FROM users WHERE id=%s", (user_id,))',
    })
    local py_param = flow.scan(py_param_buf, "python")
    local py_param_hit = false
    for _, f in ipairs(py_param) do
      if f.rule_id == "CWACS_FLOW_PY_SQLI" then
        py_param_hit = true
        break
      end
    end
    ctx:assert(not py_param_hit, "parameterized execute should not trigger flow SQLi")

    -- -----------------------------------------------------------------------
    -- 5. JavaScript source → sink (SQLi)
    -- -----------------------------------------------------------------------
    local js_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[js_buf].filetype = "javascript"
    vim.api.nvim_buf_set_lines(js_buf, 0, -1, false, {
      "const userId = req.body.id",
      "const sql = `SELECT * FROM users WHERE id=${userId}`",
      "await db.query(sql)",
    })
    local js_findings = flow.scan(js_buf, "javascript")
    local js_hit = false
    for _, f in ipairs(js_findings) do
      if f.rule_id == "CWACS_FLOW_JS_SQLI" then
        js_hit = true
        break
      end
    end
    ctx:assert(js_hit, "JavaScript source→sink SQLi should be detected")

    -- -----------------------------------------------------------------------
    -- 6. Findings carry high confidence
    -- -----------------------------------------------------------------------
    if py_direct_hit then
      local first = py_direct[1]
      ctx:assert(first.confidence == "high", "flow findings should have high confidence")
    end
  end,
}
