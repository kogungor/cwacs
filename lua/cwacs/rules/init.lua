local M = {}

M.builtins = {
  {
    id = "CWACS_PY_EVAL",
    languages = { "python" },
    severity = "high",
    confidence = "high",
    cwe = "CWE-95",
    message = "Avoid eval() with untrusted input",
    capture = "finding",
    query = [[
      (call
        function: (identifier) @fn
        (#eq? @fn "eval")) @finding
    ]],
  },
  {
    id = "CWACS_JS_EVAL",
    languages = { "javascript", "typescript", "tsx", "jsx" },
    severity = "high",
    confidence = "high",
    cwe = "CWE-95",
    message = "Avoid eval() with untrusted input",
    capture = "finding",
    query = [[
      (call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")) @finding
    ]],
  },
}

function M.for_language(lang)
  local selected = {}

  for _, rule in ipairs(M.builtins) do
    for _, rule_lang in ipairs(rule.languages or {}) do
      if rule_lang == lang then
        selected[#selected + 1] = rule
        break
      end
    end
  end

  return selected
end

return M
