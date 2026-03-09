return {
  id = "SG-002",
  name = "Tree-sitter query engine",
  run = function(ctx)
    local ok, engine = pcall(require, "cwacs.engine")
    ctx:assert(ok, "cwacs.engine should load")

    local bufnr = vim.api.nvim_create_buf(false, true)
    vim.bo[bufnr].filetype = "javascript"
    vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, {
      "function run(userInput) {",
      "  return eval(userInput)",
      "}",
    })

    local parser_ok = pcall(vim.treesitter.get_parser, bufnr, "javascript")
    if not parser_ok then
      return ctx:skip("javascript tree-sitter parser not available")
    end

    local findings = engine.scan(bufnr)
    ctx:assert(#findings >= 1, "engine should detect eval() in javascript")

    local finding = findings[1]
    ctx:assert(finding.rule_id ~= nil, "finding.rule_id should be present")
    ctx:assert(finding.message ~= nil, "finding.message should be present")
    ctx:assert(finding.severity ~= nil, "finding.severity should be present")
    ctx:assert(finding.lnum ~= nil, "finding.lnum should be present")
    ctx:assert(finding.col ~= nil, "finding.col should be present")

    local txt_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[txt_buf].filetype = "text"
    vim.api.nvim_buf_set_lines(txt_buf, 0, -1, false, { "eval(user_input)" })
    local txt_findings = engine.scan(txt_buf)
    ctx:assert(#txt_findings == 0, "unsupported language should gracefully return no findings")
  end,
}
