local M = {}
local rules = require("cwacs.rules")

local function resolve_lang(bufnr)
  local filetype = vim.bo[bufnr].filetype
  if filetype == "" then
    return nil
  end

  local ok, lang = pcall(vim.treesitter.language.get_lang, filetype)
  if ok and lang and lang ~= "" then
    return lang
  end

  return filetype
end

local function build_finding(rule, node)
  local start_row, start_col, end_row, end_col = node:range()
  return {
    rule_id = rule.id,
    severity = rule.severity,
    message = rule.message,
    lnum = start_row,
    col = start_col,
    end_lnum = end_row,
    end_col = end_col,
    cwe = rule.cwe,
    confidence = rule.confidence,
  }
end

local function run_rule(bufnr, lang, root, rule)
  local findings = {}
  local ok, query = pcall(vim.treesitter.query.parse, lang, rule.query)
  if not ok then
    return findings
  end

  local target_capture = rule.capture or "finding"
  for capture_id, node in query:iter_captures(root, bufnr, 0, -1) do
    local capture_name = query.captures[capture_id]
    if capture_name == target_capture then
      findings[#findings + 1] = build_finding(rule, node)
    end
  end

  return findings
end

function M.scan(bufnr)
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return {}
  end

  local lang = resolve_lang(bufnr)
  if not lang then
    return {}
  end

  local language_rules = rules.for_language(lang)
  if #language_rules == 0 then
    return {}
  end

  local parser_ok, parser = pcall(vim.treesitter.get_parser, bufnr, lang)
  if not parser_ok or not parser then
    return {}
  end

  local trees = parser:parse()
  if not trees or not trees[1] then
    return {}
  end

  local root = trees[1]:root()
  local findings = {}

  for _, rule in ipairs(language_rules) do
    local rule_findings = run_rule(bufnr, lang, root, rule)
    for _, finding in ipairs(rule_findings) do
      findings[#findings + 1] = finding
    end
  end

  return findings
end

return M
