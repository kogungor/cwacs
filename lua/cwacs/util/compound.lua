local M = {}

local function clause_matches(line, clause)
  if clause.type == "line_pattern" then
    return line:find(clause.pattern) ~= nil
  end

  return false
end

local function evaluate_clauses(line, clauses, operator)
  if operator == "any_of" then
    for _, clause in ipairs(clauses or {}) do
      if clause_matches(line, clause) then
        return true
      end
    end
    return false
  end

  for _, clause in ipairs(clauses or {}) do
    if not clause_matches(line, clause) then
      return false
    end
  end

  return true
end

function M.scan_lines(bufnr, rule)
  local findings = {}
  local compound = rule.compound or {}
  local operator = compound.operator or "all_of"
  local clauses = compound.clauses or {}

  if #clauses == 0 then
    return findings
  end

  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
  for i, line in ipairs(lines) do
    if evaluate_clauses(line, clauses, operator) then
      local col = 0
      local end_col = #line
      local anchor = compound.anchor_pattern
      if anchor and anchor ~= "" then
        local s, e = line:find(anchor)
        if s then
          col = s - 1
          end_col = e
        end
      end

      findings[#findings + 1] = {
        rule_id = rule.id,
        severity = rule.severity,
        message = rule.message,
        lnum = i - 1,
        col = col,
        end_lnum = i - 1,
        end_col = end_col,
        cwe = rule.cwe,
        confidence = rule.confidence,
      }
    end
  end

  return findings
end

return M
