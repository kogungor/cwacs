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
    flow_analysis = true,
  },
  flow = {
    enabled = true,
  },
  scan = {
    notify_on_manual = true,
    notify_when_no_findings = true,
  },
  secrets = {
    allowlist_path = ".cwacs/allowlist",
    reduce_severity_in_tests = true,
    test_file_severity = "low",
  },
  test_file_patterns = {
    "_test.",
    "test_",
    ".spec.",
    ".test.",
    "/tests/",
    "/spec/",
    "/fixtures/",
  },
  rules = {
    custom_path = ".cwacs/rules",
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
