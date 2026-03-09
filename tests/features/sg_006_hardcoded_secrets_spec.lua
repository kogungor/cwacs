return {
  id = "Hardcoded secrets rules",
  name = "Hardcoded secrets",
  run = function(ctx)
    local ok_engine, engine = pcall(require, "cwacs.engine")
    local ok_config, config = pcall(require, "cwacs.config")
    ctx:assert(ok_engine, "cwacs.engine should load")
    ctx:assert(ok_config, "cwacs.config should load")

    local original_config = config.get()
    local allowlist_path = vim.fn.tempname()
    local allowlist_file = io.open(allowlist_path, "w")
    ctx:assert(allowlist_file ~= nil, "allowlist temp file should be created")
    allowlist_file:write("super-secret-pass-001\n")
    allowlist_file:close()

    config.set(vim.tbl_deep_extend("force", original_config, {
      secrets = {
        allowlist_path = allowlist_path,
        reduce_severity_in_tests = true,
        test_file_severity = "low",
      },
    }))

    local vulnerable_cases = {
      {
        filetype = "python",
        lines = {
          "API_KEY = \"sk_live_1234567890abcdef123456\"",
        },
      },
      {
        filetype = "javascript",
        lines = {
          "const password = \"super-secret-pass-001\";",
        },
      },
      {
        filetype = "go",
        lines = {
          "package main",
          "var token = \"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6\"",
        },
      },
    }

    local safe_cases = {
      {
        filetype = "python",
        lines = {
          "import os",
          "API_KEY = os.environ['API_KEY']",
        },
      },
      {
        filetype = "javascript",
        lines = {
          "const token = process.env.TOKEN;",
        },
      },
      {
        filetype = "python",
        lines = {
          "PASSWORD = \"changeme\"",
        },
      },
      {
        filetype = "rust",
        lines = {
          "let api_key = std::env::var(\"API_KEY\").unwrap();",
        },
      },
    }

    for _, case in ipairs(vulnerable_cases) do
      local bufnr = vim.api.nvim_create_buf(false, true)
      vim.bo[bufnr].filetype = case.filetype
      vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, case.lines)
      local findings = engine.scan(bufnr)
      if case.filetype == "javascript" then
        ctx:assert(#findings == 0, "allowlisted javascript secret value should be suppressed")
      else
        ctx:assert(#findings >= 1, case.filetype .. " vulnerable secret sample should produce findings")
      end
    end

    for _, case in ipairs(safe_cases) do
      local bufnr = vim.api.nvim_create_buf(false, true)
      vim.bo[bufnr].filetype = case.filetype
      vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, case.lines)
      local findings = engine.scan(bufnr)
      ctx:assert(#findings == 0, case.filetype .. " safe sample should produce no findings")
    end

    local test_file_buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_name(test_file_buf, vim.fs.normalize(vim.fn.getcwd() .. "/tests/fixtures/secret_test.py"))
    vim.bo[test_file_buf].filetype = "python"
    vim.api.nvim_buf_set_lines(test_file_buf, 0, -1, false, {
      "API_KEY = \"sk_live_not_allowlisted_1234567890\"",
    })
    local test_file_findings = engine.scan(test_file_buf)
    ctx:assert(#test_file_findings >= 1, "test file secret should still be detected")
    ctx:assert(test_file_findings[1].severity == "low", "test file secret severity should be lowered")

    config.set(original_config)
  end,
}
