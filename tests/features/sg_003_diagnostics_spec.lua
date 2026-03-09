return {
  id = "SG-003",
  name = "Diagnostics adapter",
  run = function(ctx)
    local ok_core, core = pcall(require, "cwacs.core")
    local ok_diag, diagnostics = pcall(require, "cwacs.diagnostics")

    ctx:assert(ok_core, "cwacs.core should load")
    ctx:assert(ok_diag, "cwacs.diagnostics should load")

    core.setup({})

    ctx:assert(vim.fn.exists(":CwacsFindings") == 2, "CwacsFindings command should exist")
    ctx:assert(vim.fn.exists(":CwacsExplain") == 2, "CwacsExplain command should exist")
    ctx:assert(vim.fn.exists(":CwacsHelp") == 2, "CwacsHelp command should exist")
    ctx:assert(vim.fn.exists(":CwacsHealth") == 2, "CwacsHealth command should exist")

    local bufnr = vim.api.nvim_create_buf(false, true)
    local findings = {
      {
        rule_id = "CWACS_TEST_RULE",
        severity = "high",
        message = "Test diagnostic message",
        lnum = 0,
        col = 0,
        end_lnum = 0,
        end_col = 5,
        cwe = "CWE-95",
        confidence = "high",
      },
    }

    diagnostics.set(bufnr, findings)
    local diags = vim.diagnostic.get(bufnr, { namespace = diagnostics.namespace() })

    ctx:assert(#diags == 1, "diagnostics should be set")
    ctx:assert(diags[1].source == "cwacs", "diagnostic source should be cwacs")
    ctx:assert(diags[1].severity == vim.diagnostic.severity.ERROR, "high should map to ERROR")
    ctx:assert(diags[1].message:find("CWACS_TEST_RULE", 1, true) ~= nil, "message should include rule id")
    ctx:assert(diags[1].message:find("CWE-95", 1, true) ~= nil, "message should include cwe")
    ctx:assert(diags[1].message:find("confidence: high", 1, true) ~= nil, "message should include confidence")
  end,
}
