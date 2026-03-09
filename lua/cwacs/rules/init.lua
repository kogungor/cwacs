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
