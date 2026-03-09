local M = {}
local config = require("cwacs.config")
local rules = require("cwacs.rules")
local compound = require("cwacs.util.compound")

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

local function is_secret_rule(rule_id)
  return type(rule_id) == "string" and rule_id:match("^CWACS_SECRET_") ~= nil
end

local function get_buf_path(bufnr)
  return vim.api.nvim_buf_get_name(bufnr) or ""
end

local function is_test_file(bufnr, patterns)
  local path = get_buf_path(bufnr):lower()
  if path == "" then
    return false
  end

  for _, pattern in ipairs(patterns or {}) do
    if path:find(pattern:lower(), 1, true) then
      return true
    end
  end

  return false
end

local function load_allowlist_entries(path)
  if not path or path == "" then
    return {}
  end

  local absolute = vim.fs.normalize(vim.fn.fnamemodify(path, ":p"))
  local file = io.open(absolute, "r")
  if not file then
    return {}
  end

  local entries = {}
  for line in file:lines() do
    local trimmed = line:match("^%s*(.-)%s*$")
    if trimmed ~= "" and not trimmed:match("^#") then
      entries[trimmed] = true
    end
  end

  file:close()
  return entries
end

local function apply_secret_post_filters(bufnr, findings)
  local opts = config.get()
  local secret_opts = opts.secrets or {}
  local allowlist = load_allowlist_entries(secret_opts.allowlist_path)
  local in_test_file = is_test_file(bufnr, opts.test_file_patterns)
  local reduced_severity = secret_opts.test_file_severity or "low"

  local filtered = {}
  for _, finding in ipairs(findings) do
    local skip = false

    if is_secret_rule(finding.rule_id) then
      if finding.secret_value and allowlist[finding.secret_value] then
        skip = true
      elseif secret_opts.reduce_severity_in_tests and in_test_file then
        finding.severity = reduced_severity
        finding.confidence = "low"
      end
    end

    if not skip then
      filtered[#filtered + 1] = finding
    end
  end

  return filtered
end

local function run_rule(bufnr, lang, root, rule)
  local findings = {}

  if type(rule.custom_scan) == "function" then
    local custom_ok, custom_findings = pcall(rule.custom_scan, bufnr, rule, lang)
    if custom_ok and type(custom_findings) == "table" then
      for _, finding in ipairs(custom_findings) do
        findings[#findings + 1] = finding
      end
    end
  end

  if rule.compound then
    local compound_ok, compound_findings = pcall(compound.scan_lines, bufnr, rule)
    if compound_ok and type(compound_findings) == "table" then
      for _, finding in ipairs(compound_findings) do
        findings[#findings + 1] = finding
      end
    end
  end

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

  findings = dedupe_findings(findings)
  findings = apply_secret_post_filters(bufnr, findings)
  return dedupe_findings(findings)
end

return M
