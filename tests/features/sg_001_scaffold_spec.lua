return {
  id = "SG-001",
  name = "Scaffold and setup",
  run = function(ctx)
    local ok, cwacs = pcall(require, "cwacs")
    ctx:assert(ok, "cwacs module should load")

    cwacs.setup({})

    ctx:assert(vim.fn.exists(":CwacsScan") == 2, "CwacsScan command should exist")
    ctx:assert(vim.fn.exists(":CwacsToggle") == 2, "CwacsToggle command should exist")
    ctx:assert(#vim.api.nvim_get_autocmds({ group = "Cwacs" }) >= 2, "Cwacs autocmd group should be registered")
  end,
}
