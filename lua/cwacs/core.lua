local config = require("cwacs.config")
local diagnostics = require("cwacs.diagnostics")
local engine = require("cwacs.engine")

local M = {}

local state = {
  enabled = true,
  augroup = nil,
  timers = {},
  last_ticks = {},
}

local function stop_timer(bufnr)
  local timer = state.timers[bufnr]
  if not timer then
    return
  end

  timer:stop()
  timer:close()
  state.timers[bufnr] = nil
end

local function run_scan(bufnr)
  if not state.enabled or not vim.api.nvim_buf_is_valid(bufnr) then
    return {}
  end

  local current_tick = vim.api.nvim_buf_get_changedtick(bufnr)
  if state.last_ticks[bufnr] == current_tick then
    return {}
  end

  state.last_ticks[bufnr] = current_tick
  local findings = engine.scan(bufnr)
  diagnostics.set(bufnr, findings)
  return findings
end

local function schedule_scan(bufnr, debounce_ms)
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return
  end

  stop_timer(bufnr)

  local timer = vim.uv.new_timer()
  state.timers[bufnr] = timer
  timer:start(debounce_ms, 0, vim.schedule_wrap(function()
    stop_timer(bufnr)
    run_scan(bufnr)
  end))
end

local function command_scan()
  local findings = run_scan(vim.api.nvim_get_current_buf())
  vim.notify(string.format("cwacs scan complete (%d findings)", #findings), vim.log.levels.INFO)
end

function M.scan_current_buffer()
  command_scan()
end

function M.toggle()
  state.enabled = not state.enabled
  if not state.enabled then
    diagnostics.clear(vim.api.nvim_get_current_buf())
  end

  local label = state.enabled and "enabled" or "disabled"
  vim.notify("cwacs " .. label, vim.log.levels.INFO)
end

local function create_commands()
  pcall(vim.api.nvim_del_user_command, "SecurityScan")
  pcall(vim.api.nvim_del_user_command, "SecurityToggle")
  pcall(vim.api.nvim_del_user_command, "CwacsScan")
  pcall(vim.api.nvim_del_user_command, "CwacsToggle")

  vim.api.nvim_create_user_command("CwacsScan", command_scan, {
    desc = "Run cwacs scan for current buffer",
  })

  vim.api.nvim_create_user_command("CwacsToggle", M.toggle, {
    desc = "Toggle cwacs realtime scanning",
  })
end

local function create_autocmds(opts)
  if state.augroup then
    pcall(vim.api.nvim_del_augroup_by_id, state.augroup)
  end

  local group = vim.api.nvim_create_augroup("Cwacs", { clear = true })
  state.augroup = group

  vim.api.nvim_create_autocmd("TextChanged", {
    group = group,
    callback = function(args)
      if not state.enabled or not opts.realtime.enabled then
        return
      end

      schedule_scan(args.buf, opts.realtime.debounce_ms)
    end,
  })

  vim.api.nvim_create_autocmd("BufWritePost", {
    group = group,
    callback = function(args)
      if not state.enabled or not opts.on_save.enabled then
        return
      end

      run_scan(args.buf)
    end,
  })

  vim.api.nvim_create_autocmd({ "BufWipeout", "BufDelete" }, {
    group = group,
    callback = function(args)
      stop_timer(args.buf)
      state.last_ticks[args.buf] = nil
      diagnostics.clear(args.buf)
    end,
  })
end

function M.setup(user_config)
  local opts = config.set(user_config)
  state.enabled = opts.enabled

  create_commands()
  create_autocmds(opts)
end

return M
