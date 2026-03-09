return {
  id = "Dangerous functions built-ins",
  name = "Dangerous functions",
  run = function(ctx)
    local ok_engine, engine = pcall(require, "cwacs.engine")
    ctx:assert(ok_engine, "cwacs.engine should load")

    local cases = {
      {
        lang = "python",
        filetype = "python",
        vulnerable = {
          "import os",
          "def run(user_input):",
          "    os.system(user_input)",
        },
        safe = {
          "def run(value):",
          "    return str(value)",
        },
      },
      {
        lang = "javascript",
        filetype = "javascript",
        vulnerable = {
          "function run(userInput) {",
          "  return eval(userInput)",
          "}",
        },
        safe = {
          "function run(value) {",
          "  return String(value)",
          "}",
        },
      },
      {
        lang = "go",
        filetype = "go",
        vulnerable = {
          "package main",
          "import \"os/exec\"",
          "func run(cmd string) {",
          "  exec.Command(\"sh\", \"-c\", cmd).Run()",
          "}",
        },
        safe = {
          "package main",
          "import \"fmt\"",
          "func run() {",
          "  fmt.Println(\"ok\")",
          "}",
        },
      },
      {
        lang = "rust",
        filetype = "rust",
        vulnerable = {
          "use std::process::Command;",
          "fn run() {",
          "    let _ = Command::new(\"sh\").arg(\"-c\").status();",
          "}",
        },
        safe = {
          "fn run() {",
          "    println!(\"ok\");",
          "}",
        },
      },
    }

    local checked = 0

    for _, case in ipairs(cases) do
      local vuln_buf = vim.api.nvim_create_buf(false, true)
      vim.bo[vuln_buf].filetype = case.filetype
      vim.api.nvim_buf_set_lines(vuln_buf, 0, -1, false, case.vulnerable)

      local parser_ok = pcall(vim.treesitter.get_parser, vuln_buf, case.lang)
      if parser_ok then
        checked = checked + 1

        local vulnerable_findings = engine.scan(vuln_buf)
        ctx:assert(#vulnerable_findings >= 1, case.filetype .. " vulnerable sample should produce findings")

        local safe_buf = vim.api.nvim_create_buf(false, true)
        vim.bo[safe_buf].filetype = case.filetype
        vim.api.nvim_buf_set_lines(safe_buf, 0, -1, false, case.safe)

        local safe_findings = engine.scan(safe_buf)
        ctx:assert(#safe_findings == 0, case.filetype .. " safe sample should produce no findings")
      end
    end

    if checked == 0 then
      return ctx:skip("required tree-sitter parsers are unavailable in this headless environment")
    end
  end,
}
