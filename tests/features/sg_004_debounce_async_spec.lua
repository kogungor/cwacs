return {
  id = "Debounce and async management",
  name = "Debounce and async",
  run = function(ctx)
    local ok_core, core = pcall(require, "cwacs.core")
    local ok_engine, engine = pcall(require, "cwacs.engine")
    ctx:assert(ok_core, "cwacs.core should load")
    ctx:assert(ok_engine, "cwacs.engine should load")

    core.setup({
      realtime = { enabled = true, debounce_ms = 80 },
      on_save = { enabled = true },
    })

    local original_scan = engine.scan
    local calls = 0

    local run_ok, run_err = xpcall(function()
      engine.scan = function(bufnr)
        calls = calls + 1
        return original_scan(bufnr)
      end

      local bufnr = vim.api.nvim_create_buf(false, true)
      vim.api.nvim_set_current_buf(bufnr)
      vim.bo[bufnr].filetype = "javascript"

      vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, { "function a() { return 1 }" })
      vim.api.nvim_exec_autocmds("TextChanged", { buffer = bufnr, modeline = false })
      vim.wait(20)
      vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, { "function b() { return 2 }" })
      vim.api.nvim_exec_autocmds("TextChanged", { buffer = bufnr, modeline = false })
      vim.wait(20)
      vim.api.nvim_buf_set_lines(bufnr, 0, -1, false, { "function c() { return eval('1') }" })
      vim.api.nvim_exec_autocmds("TextChanged", { buffer = bufnr, modeline = false })

      vim.wait(250, function()
        return calls >= 1
      end, 10)

      local calls_after_debounce = calls
      ctx:assert(calls_after_debounce == 1, "rapid TextChanged events should debounce into one scan")

      vim.api.nvim_exec_autocmds("BufWritePost", { buffer = bufnr, modeline = false })
      vim.api.nvim_exec_autocmds("BufWritePost", { buffer = bufnr, modeline = false })
      vim.wait(50)
      ctx:assert(calls >= calls_after_debounce + 2, "BufWritePost should force scan even without changedtick changes")

      local bufnr2 = vim.api.nvim_create_buf(false, true)
      vim.bo[bufnr2].filetype = "javascript"
      vim.api.nvim_set_current_buf(bufnr2)
      vim.api.nvim_buf_set_lines(bufnr2, 0, -1, false, { "function z() { return eval('1') }" })
      vim.api.nvim_exec_autocmds("TextChanged", { buffer = bufnr2, modeline = false })
      vim.api.nvim_buf_delete(bufnr2, { force = true })
      local before_wait = calls
      vim.wait(150)
      ctx:assert(calls == before_wait, "pending timer on deleted buffer should not run scan")
    end, debug.traceback)

    engine.scan = original_scan

    if not run_ok then
      error(run_err)
    end
  end,
}
