local M = {}

local function fail(message)
  error(message, 0)
end

function M.new_context()
  local ctx = {
    assertions = 0,
  }

  function ctx:assert(condition, message)
    self.assertions = self.assertions + 1
    if not condition then
      fail(message or "assertion failed")
    end
  end

  function ctx:skip(message)
    return {
      skipped = true,
      reason = message or "skipped",
    }
  end

  return ctx
end

return M
