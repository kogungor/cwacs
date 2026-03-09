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

local function build_line_finding(rule, lnum, col, end_col)
  return {
    rule_id = rule.id,
    severity = rule.severity,
    message = rule.message,
    lnum = lnum,
    col = col,
    end_lnum = lnum,
    end_col = end_col,
    cwe = rule.cwe,
    confidence = rule.confidence,
  }
end

local function append_line_pattern_findings(bufnr, rule, findings)
  if not rule.line_pattern or rule.line_pattern == "" then
    return
  end

  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
  for i, line in ipairs(lines) do
    local start_pos, end_pos = line:find(rule.line_pattern)
    if start_pos then
      findings[#findings + 1] = build_line_finding(rule, i - 1, start_pos - 1, end_pos)
    end
  end
end

local function dedupe_findings(findings)
  local deduped = {}
  local seen = {}

  for _, finding in ipairs(findings) do
    local key = table.concat({
      finding.rule_id or "",
      tostring(finding.lnum or 0),
      tostring(finding.col or 0),
      tostring(finding.end_lnum or 0),
      tostring(finding.end_col or 0),
    }, ":")

    if not seen[key] then
      seen[key] = true
      deduped[#deduped + 1] = finding
    end
  end

  return deduped
end

local function run_rule(bufnr, lang, root, rule)
  local findings = {}
  local query = nil
  local query_ok = false
  local query_used = false
  if rule.query and rule.query ~= "" then
    query_ok, query = pcall(vim.treesitter.query.parse, lang, rule.query)
  end

  if root and query_ok and query then
    query_used = true
    local target_capture = rule.capture or "finding"
    for capture_id, node in query:iter_captures(root, bufnr, 0, -1) do
      local capture_name = query.captures[capture_id]
      if capture_name == target_capture then
        findings[#findings + 1] = build_finding(rule, node)
      end
    end
  end

  if (not query_used) or #findings == 0 then
    append_line_pattern_findings(bufnr, rule, findings)
  end

  return dedupe_findings(findings)
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

  local root = nil
  local parser_ok, parser = pcall(vim.treesitter.get_parser, bufnr, lang)
  if parser_ok and parser then
    local trees = parser:parse()
    if trees and trees[1] then
      root = trees[1]:root()
    end
  end

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
