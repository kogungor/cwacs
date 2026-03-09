local M = {}

local namespace = vim.api.nvim_create_namespace("cwacs")

local severity_map = {
  critical = vim.diagnostic.severity.ERROR,
  high = vim.diagnostic.severity.ERROR,
  medium = vim.diagnostic.severity.WARN,
  low = vim.diagnostic.severity.HINT,
}

local function to_diagnostic(finding)
  local cwe_suffix = finding.cwe and (" [" .. finding.cwe .. "]") or ""
  local confidence_suffix = finding.confidence and (" (confidence: " .. finding.confidence .. ")") or ""
  return {
    lnum = finding.lnum or 0,
    col = finding.col or 0,
    end_lnum = finding.end_lnum,
    end_col = finding.end_col,
    severity = severity_map[finding.severity] or vim.diagnostic.severity.WARN,
    message = string.format(
      "%s: %s%s%s",
      finding.rule_id or "CWACS",
      finding.message or "Security finding",
      cwe_suffix,
      confidence_suffix
    ),
    source = "cwacs",
  }
end

function M.set(bufnr, findings)
  local diagnostics = {}
  for _, finding in ipairs(findings or {}) do
    diagnostics[#diagnostics + 1] = to_diagnostic(finding)
  end

  vim.diagnostic.set(namespace, bufnr, diagnostics, {})
end

function M.clear(bufnr)
  vim.diagnostic.reset(namespace, bufnr)
end

function M.namespace()
  return namespace
end

return M
