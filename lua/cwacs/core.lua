local config = require("cwacs.config")
local diagnostics = require("cwacs.diagnostics")
local engine = require("cwacs.engine")

local M = {}

local state = {
  enabled = true,
  augroup = nil,
  timers = {},
  last_ticks = {},
  findings_by_buf = {},
}

local function severity_rank(severity)
  if severity == "critical" then
    return 1
  end
  if severity == "high" then
    return 2
  end
  if severity == "medium" then
    return 3
  end
  return 4
end

local function summarize_findings(findings)
  local summary = {
    total = #findings,
    critical = 0,
    high = 0,
    medium = 0,
    low = 0,
  }

  for _, finding in ipairs(findings) do
    local sev = finding.severity or "low"
    if summary[sev] ~= nil then
      summary[sev] = summary[sev] + 1
    end
  end

  return summary
end

local function is_parser_available(lang)
  local ok = pcall(vim.treesitter.language.add, lang)
  return ok
end

local function parser_readiness_report()
  local required = { "javascript", "typescript", "python", "go", "rust" }
  local installed = {}
  local missing = {}

  for _, lang in ipairs(required) do
    if is_parser_available(lang) then
      installed[#installed + 1] = lang
    else
      missing[#missing + 1] = lang
    end
  end

  return {
    required = required,
    installed = installed,
    missing = missing,
  }
end

local function to_loclist_items(bufnr, findings)
  local items = {}
  for _, finding in ipairs(findings) do
    items[#items + 1] = {
      bufnr = bufnr,
      lnum = (finding.lnum or 0) + 1,
      col = (finding.col or 0) + 1,
      text = string.format("%s: %s", finding.rule_id or "CWACS", finding.message or "Security finding"),
      type = (severity_rank(finding.severity) <= 2) and "E" or "W",
    }
  end
  return items
end

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
    return state.findings_by_buf[bufnr] or {}
  end

  local current_tick = vim.api.nvim_buf_get_changedtick(bufnr)
  if state.last_ticks[bufnr] == current_tick then
    return state.findings_by_buf[bufnr] or {}
  end

  state.last_ticks[bufnr] = current_tick
  local findings = engine.scan(bufnr)
  table.sort(findings, function(a, b)
    return severity_rank(a.severity) < severity_rank(b.severity)
  end)

  state.findings_by_buf[bufnr] = findings
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
  local summary = summarize_findings(findings)
  local top = findings[1]
  local top_text = ""
  if top then
    top_text = string.format(
      " | top: %s at line %d",
      top.rule_id or "CWACS",
      (top.lnum or 0) + 1
    )
  end

  vim.notify(
    string.format(
      "cwacs scan complete: %d findings (critical:%d high:%d medium:%d low:%d)%s",
      summary.total,
      summary.critical,
      summary.high,
      summary.medium,
      summary.low,
      top_text
    ),
    vim.log.levels.INFO
  )
end

local function command_findings()
  local bufnr = vim.api.nvim_get_current_buf()
  local findings = run_scan(bufnr)

  vim.fn.setloclist(0, {}, "r", {
    title = "cwacs findings",
    items = to_loclist_items(bufnr, findings),
  })

  if #findings == 0 then
    vim.notify("cwacs: no findings in current buffer", vim.log.levels.INFO)
    return
  end

  vim.notify("cwacs: location list updated (use :lopen to open)", vim.log.levels.INFO)
end

local function jump_from_loclist_item()
  local info = vim.fn.getloclist(0, { idx = 0, items = 1 })
  local idx = info.idx or 0
  local item = info.items and info.items[idx] or nil
  if not item or item.bufnr == 0 then
    return nil
  end

  vim.api.nvim_set_current_buf(item.bufnr)
  pcall(vim.api.nvim_win_set_cursor, 0, { item.lnum or 1, math.max((item.col or 1) - 1, 0) })
  return item.bufnr
end

local function command_explain()
  local bufnr = vim.api.nvim_get_current_buf()
  if vim.bo[bufnr].buftype == "quickfix" then
    bufnr = jump_from_loclist_item() or bufnr
  end

  local diagnostics_on_line = vim.diagnostic.get(bufnr, {
    namespace = diagnostics.namespace(),
    lnum = vim.api.nvim_win_get_cursor(0)[1] - 1,
  })

  if #diagnostics_on_line == 0 then
    vim.notify("cwacs: no finding on current line", vim.log.levels.INFO)
    return
  end

  vim.diagnostic.open_float(bufnr, {
    namespace = diagnostics.namespace(),
    scope = "line",
    source = "always",
    border = "rounded",
    header = "cwacs finding",
  })
end

local function command_help()
  local lines = {
    "cwacs commands:",
    "- :CwacsScan      -> scan current buffer",
    "- :CwacsToggle    -> enable/disable realtime scans",
    "- :CwacsFindings  -> refresh location list entries",
    "- :lopen          -> open location list window",
    "- :CwacsExplain   -> show detail popup on current line",
    "- :CwacsHealth    -> check tree-sitter parser readiness",
  }

  vim.notify(table.concat(lines, "\n"), vim.log.levels.INFO, { title = "cwacs help" })
end

local function command_health()
  local report = parser_readiness_report()
  local lines = {
    "cwacs parser readiness",
    "required: " .. table.concat(report.required, ", "),
    "installed: " .. (#report.installed > 0 and table.concat(report.installed, ", ") or "none"),
    "missing: " .. (#report.missing > 0 and table.concat(report.missing, ", ") or "none"),
  }

  local level = #report.missing == 0 and vim.log.levels.INFO or vim.log.levels.WARN
  vim.notify(table.concat(lines, "\n"), level, { title = "cwacs health" })
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
  pcall(vim.api.nvim_del_user_command, "CwacsFindings")
  pcall(vim.api.nvim_del_user_command, "CwacsExplain")
  pcall(vim.api.nvim_del_user_command, "CwacsFinding")
  pcall(vim.api.nvim_del_user_command, "CwacsHelp")
  pcall(vim.api.nvim_del_user_command, "CwacsHealth")

  vim.api.nvim_create_user_command("CwacsScan", command_scan, {
    desc = "Run cwacs scan for current buffer",
  })

  vim.api.nvim_create_user_command("CwacsToggle", M.toggle, {
    desc = "Toggle cwacs realtime scanning",
  })

  vim.api.nvim_create_user_command("CwacsFindings", command_findings, {
    desc = "Open location list with cwacs findings",
  })

  vim.api.nvim_create_user_command("CwacsExplain", command_explain, {
    desc = "Show cwacs finding details on current line",
  })

  vim.api.nvim_create_user_command("CwacsFinding", command_explain, {
    desc = "Alias of CwacsExplain",
  })

  vim.api.nvim_create_user_command("CwacsHelp", command_help, {
    desc = "Show cwacs command help",
  })

  vim.api.nvim_create_user_command("CwacsHealth", command_health, {
    desc = "Show cwacs parser readiness",
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
      state.findings_by_buf[args.buf] = nil
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

function M.get_findings(bufnr)
  return state.findings_by_buf[bufnr] or {}
end

return M
