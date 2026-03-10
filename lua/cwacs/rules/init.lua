local M = {}
local secrets = require("cwacs.util.secrets")
local config = require("cwacs.config")
local loader = require("cwacs.loader")

M.custom = {}
M.custom_errors = {}
M.custom_loaded = false

function M.reload_custom()
  local opts = config.get()
  local rules_opts = opts.rules or {}
  local custom_path = rules_opts.custom_path
  local custom, errors = loader.load_path(custom_path)
  M.custom = custom
  M.custom_errors = errors
  M.custom_loaded = true
  return custom, errors
end

M.builtins = {
  {
    id = "CWACS_PY_EVAL",
    languages = { "python" },
    severity = "high",
    confidence = "high",
    cwe = "CWE-95",
    message = "Avoid eval() with untrusted input",
    capture = "finding",
    line_pattern = "eval%s*%(",
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
    line_pattern = "eval%s*%(",
    query = [[
      (call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")) @finding
    ]],
  },
  {
    id = "CWACS_PY_EXEC",
    languages = { "python" },
    severity = "high",
    confidence = "high",
    cwe = "CWE-78",
    message = "Avoid exec() with untrusted input",
    capture = "finding",
    line_pattern = "exec%s*%(",
    query = [[
      (call
        function: (_) @fn
        (#eq? @fn "exec")) @finding
    ]],
  },
  {
    id = "CWACS_PY_OS_SYSTEM",
    languages = { "python" },
    severity = "high",
    confidence = "high",
    cwe = "CWE-78",
    message = "Avoid os.system() with untrusted input",
    capture = "finding",
    line_pattern = "os%.system%s*%(",
    query = [[
      (call
        function: (_) @fn
        (#match? @fn "^os\\.system$")) @finding
    ]],
  },
  {
    id = "CWACS_PY_SUBPROCESS_CALL",
    languages = { "python" },
    severity = "high",
    confidence = "medium",
    cwe = "CWE-78",
    message = "Review subprocess.call() usage for command injection",
    capture = "finding",
    line_pattern = "subprocess%.call%s*%(",
    query = [[
      (call
        function: (_) @fn
        (#match? @fn "^subprocess\\.call$")) @finding
    ]],
  },
  {
    id = "CWACS_PY_PICKLE_LOADS",
    languages = { "python" },
    severity = "high",
    confidence = "high",
    cwe = "CWE-502",
    message = "Avoid pickle.loads() on untrusted data",
    capture = "finding",
    line_pattern = "pickle%.loads%s*%(",
    query = [[
      (call
        function: (_) @fn
        (#match? @fn "^pickle\\.loads$")) @finding
    ]],
  },
  {
    id = "CWACS_PY_YAML_LOAD",
    languages = { "python" },
    severity = "medium",
    confidence = "medium",
    cwe = "CWE-502",
    message = "Review yaml.load() and ensure safe loader usage",
    capture = "finding",
    line_pattern = "yaml%.load%s*%(",
    query = [[
      (call
        function: (_) @fn
        (#match? @fn "^yaml\\.load$")) @finding
    ]],
  },
  {
    id = "CWACS_PY_MARSHAL_LOADS",
    languages = { "python" },
    severity = "medium",
    confidence = "medium",
    cwe = "CWE-502",
    message = "Avoid marshal.loads() on untrusted input",
    capture = "finding",
    line_pattern = "marshal%.loads%s*%(",
    query = [[
      (call
        function: (_) @fn
        (#match? @fn "^marshal\\.loads$")) @finding
    ]],
  },
  {
    id = "CWACS_JS_FUNCTION_CTOR",
    languages = { "javascript", "typescript", "tsx", "jsx" },
    severity = "high",
    confidence = "high",
    cwe = "CWE-95",
    message = "Avoid Function constructor with dynamic code",
    capture = "finding",
    line_pattern = "Function%s*%(",
    query = [[
      (call_expression
        function: (_) @fn
        (#eq? @fn "Function")) @finding
    ]],
  },
  {
    id = "CWACS_JS_SETTIMEOUT_STRING",
    languages = { "javascript", "typescript", "tsx", "jsx" },
    severity = "medium",
    confidence = "medium",
    cwe = "CWE-95",
    message = "Avoid string-based setTimeout()",
    capture = "finding",
    line_pattern = "setTimeout%s*%(%s*['\"]",
    query = [[
      (call_expression
        function: (_) @fn
        arguments: (arguments
          (string))
        (#eq? @fn "setTimeout")) @finding
    ]],
  },
  {
    id = "CWACS_JS_SETINTERVAL_STRING",
    languages = { "javascript", "typescript", "tsx", "jsx" },
    severity = "medium",
    confidence = "medium",
    cwe = "CWE-95",
    message = "Avoid string-based setInterval()",
    capture = "finding",
    line_pattern = "setInterval%s*%(%s*['\"]",
    query = [[
      (call_expression
        function: (_) @fn
        arguments: (arguments
          (string))
        (#eq? @fn "setInterval")) @finding
    ]],
  },
  {
    id = "CWACS_JS_CHILD_PROCESS_EXEC",
    languages = { "javascript", "typescript", "tsx", "jsx" },
    severity = "high",
    confidence = "medium",
    cwe = "CWE-78",
    message = "Review child_process.exec() usage for command injection",
    capture = "finding",
    line_pattern = "[%w_%.]+exec%s*%(",
    query = [[
      (call_expression
        function: (_) @fn
        (#match? @fn "(^|\\.)exec$")) @finding
    ]],
  },
  {
    id = "CWACS_GO_EXEC_COMMAND",
    languages = { "go" },
    severity = "high",
    confidence = "medium",
    cwe = "CWE-78",
    message = "Review exec.Command() usage for command injection",
    capture = "finding",
    line_pattern = "exec%.Command%s*%(",
    query = [[
      (call_expression
        function: (_) @fn
        (#match? @fn "exec\\.Command$")) @finding
    ]],
  },
  {
    id = "CWACS_RUST_COMMAND_NEW",
    languages = { "rust" },
    severity = "high",
    confidence = "medium",
    cwe = "CWE-78",
    message = "Review Command::new() usage for command injection",
    capture = "finding",
    line_pattern = "Command::new%s*%(",
    query = [[
      (call_expression
        function: (_) @fn
        (#match? @fn "Command::new$")) @finding
    ]],
  },
  {
    id = "CWACS_PY_SQLI_STRING_CONCAT_EXECUTE",
    languages = { "python" },
    severity = "high",
    confidence = "medium",
    cwe = "CWE-89",
    message = "Potential SQL injection: string concatenation in execute()",
    compound = {
      operator = "all_of",
      anchor_pattern = "execute%s*%(",
      clauses = {
        { type = "line_pattern", pattern = "execute%s*%(" },
        { type = "line_pattern", pattern = "%+" },
      },
    },
  },
  {
    id = "CWACS_JS_SQLI_TEMPLATE_QUERY",
    languages = { "javascript", "typescript", "tsx", "jsx" },
    severity = "high",
    confidence = "medium",
    cwe = "CWE-89",
    message = "Potential SQL injection: template literal in query()",
    compound = {
      operator = "all_of",
      anchor_pattern = "query%s*%(",
      clauses = {
        { type = "line_pattern", pattern = "query%s*%(" },
        { type = "line_pattern", pattern = "%${" },
      },
    },
  },
  {
    id = "CWACS_GO_SQLI_SPRINTF_DBQUERY",
    languages = { "go" },
    severity = "high",
    confidence = "medium",
    cwe = "CWE-89",
    message = "Potential SQL injection: fmt.Sprintf used in db.Query",
    compound = {
      operator = "all_of",
      anchor_pattern = "db%.Query%s*%(",
      clauses = {
        { type = "line_pattern", pattern = "db%.Query%s*%(" },
        { type = "line_pattern", pattern = "fmt%.Sprintf%s*%(" },
      },
    },
  },
  {
    id = "CWACS_SECRET_KEYWORD_ASSIGN",
    languages = { "python", "javascript", "typescript", "tsx", "jsx", "go", "rust", "lua" },
    severity = "high",
    confidence = "high",
    cwe = "CWE-798",
    message = "Potential hardcoded secret assignment detected",
    custom_scan = function(bufnr, rule)
      local findings = {}
      local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
      for i, line in ipairs(lines) do
        local match = secrets.keyword_secret_match(line)
        if match then
          findings[#findings + 1] = {
            rule_id = rule.id,
            severity = rule.severity,
            message = rule.message,
            lnum = i - 1,
            col = match.col,
            end_lnum = i - 1,
            end_col = match.end_col,
            cwe = rule.cwe,
            confidence = rule.confidence,
            secret_value = match.value,
          }
        end
      end
      return findings
    end,
  },
  {
    id = "CWACS_SECRET_HIGH_ENTROPY",
    languages = { "python", "javascript", "typescript", "tsx", "jsx", "go", "rust", "lua" },
    severity = "medium",
    confidence = "medium",
    cwe = "CWE-798",
    message = "High-entropy hardcoded token-like string detected",
    custom_scan = function(bufnr, rule)
      local findings = {}
      local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
      for i, line in ipairs(lines) do
        local match = secrets.high_entropy_secret_match(line)
        if match then
          findings[#findings + 1] = {
            rule_id = rule.id,
            severity = rule.severity,
            message = rule.message,
            lnum = i - 1,
            col = match.col,
            end_lnum = i - 1,
            end_col = match.end_col,
            cwe = rule.cwe,
            confidence = rule.confidence,
            secret_value = match.value,
            entropy = match.entropy,
          }
        end
      end
      return findings
    end,
  },
}

function M.for_language(lang)
  local selected = {}

  if not M.custom_loaded then
    M.reload_custom()
  end

  for _, rule in ipairs(M.builtins) do
    for _, rule_lang in ipairs(rule.languages or {}) do
      if rule_lang == lang then
        selected[#selected + 1] = rule
        break
      end
    end
  end

  for _, rule in ipairs(M.custom or {}) do
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
