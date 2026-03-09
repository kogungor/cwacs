local M = {}

local defaults = {
  enabled = true,
  realtime = {
    enabled = true,
    debounce_ms = 300,
    notify = false,
    notify_min_interval_ms = 1500,
    debug = false,
  },
  on_save = {
    enabled = true,
  },
  scan = {
    notify_on_manual = true,
    notify_when_no_findings = true,
  },
  rules = {
    disabled = {},
  },
}

local state = vim.deepcopy(defaults)

function M.defaults()
  return vim.deepcopy(defaults)
end

function M.get()
  return state
end

function M.set(user_config)
  state = vim.tbl_deep_extend("force", M.defaults(), user_config or {})
  return state
end

return M
