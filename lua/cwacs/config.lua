local M = {}

local defaults = {
  enabled = true,
  realtime = {
    enabled = true,
    debounce_ms = 300,
  },
  on_save = {
    enabled = true,
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
