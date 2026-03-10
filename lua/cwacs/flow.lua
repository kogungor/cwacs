-- lua/cwacs/flow.lua
-- Intra-function dataflow tracker.
--
-- Algorithm (per function body):
--   1. Collect all assignment statements → variable→expression map
--   2. Mark variables whose RHS matches a source pattern as tainted
--   3. Propagate taint through reassignments (x = tainted_var → x is tainted)
--   4. If a tainted variable passes through a sanitizer call, remove its taint
--   5. Report a finding when a tainted variable reaches a sink pattern

local M = {}

-- ---------------------------------------------------------------------------
-- Source patterns — expressions that introduce untrusted data
-- ---------------------------------------------------------------------------

local SOURCES = {
  python = {
    "request%.args",
    "request%.form",
    "request%.get_json",
    "request%.data",
    "request%.json",
    "request%.values",
    "request%.cookies",
    "request%.headers",
    "sys%.argv",
    "os%.environ",
    "input%s*%(",
    "raw_input%s*%(",
    "flask%.request",
  },
  javascript = {
    "req%.body",
    "req%.query",
    "req%.params",
    "req%.headers",
    "request%.body",
    "request%.query",
    "request%.params",
    "location%.search",
    "location%.hash",
    "document%.URL",
    "document%.referrer",
    "window%.location",
  },
  typescript = {},  -- inherits javascript sources at runtime
  go = {
    "r%.FormValue%s*%(",
    "r%.URL%.Query%(",
    "r%.Body",
    "r%.Header%.Get%s*%(",
    "os%.Args",
    "http%.Request",
  },
}
-- typescript shares javascript sources
SOURCES.typescript = SOURCES.javascript
SOURCES.tsx = SOURCES.javascript
SOURCES.jsx = SOURCES.javascript

-- ---------------------------------------------------------------------------
-- Sink patterns — dangerous call sites
-- ---------------------------------------------------------------------------

local SINKS = {
  python = {
    { pattern = "%.execute%s*%(", rule_id = "CWACS_FLOW_PY_SQLI",    cwe = "CWE-89",  message = "Tainted user input reaches SQL execute() — potential SQL injection" },
    { pattern = "os%.system%s*%(", rule_id = "CWACS_FLOW_PY_CMDI",   cwe = "CWE-78",  message = "Tainted user input reaches os.system() — potential command injection" },
    { pattern = "subprocess%.",    rule_id = "CWACS_FLOW_PY_CMDI",   cwe = "CWE-78",  message = "Tainted user input reaches subprocess — potential command injection" },
    { pattern = "eval%s*%(",       rule_id = "CWACS_FLOW_PY_EVAL",   cwe = "CWE-95",  message = "Tainted user input reaches eval() — potential code injection" },
    { pattern = "exec%s*%(",       rule_id = "CWACS_FLOW_PY_EVAL",   cwe = "CWE-95",  message = "Tainted user input reaches exec() — potential code injection" },
    { pattern = "open%s*%(",       rule_id = "CWACS_FLOW_PY_PATH",   cwe = "CWE-22",  message = "Tainted user input reaches open() — potential path traversal" },
    { pattern = "render_template", rule_id = "CWACS_FLOW_PY_XSS",    cwe = "CWE-79",  message = "Tainted user input reaches template render — potential XSS" },
  },
  javascript = {
    { pattern = "%.query%s*%(",        rule_id = "CWACS_FLOW_JS_SQLI",  cwe = "CWE-89", message = "Tainted user input reaches query() — potential SQL injection" },
    { pattern = "innerHTML%s*=",       rule_id = "CWACS_FLOW_JS_XSS",   cwe = "CWE-79", message = "Tainted user input reaches innerHTML — potential XSS" },
    { pattern = "document%.write%s*%(", rule_id = "CWACS_FLOW_JS_XSS",  cwe = "CWE-79", message = "Tainted user input reaches document.write() — potential XSS" },
    { pattern = "eval%s*%(",           rule_id = "CWACS_FLOW_JS_EVAL",  cwe = "CWE-95", message = "Tainted user input reaches eval() — potential code injection" },
    { pattern = "exec%s*%(",           rule_id = "CWACS_FLOW_JS_CMDI",  cwe = "CWE-78", message = "Tainted user input reaches exec() — potential command injection" },
    { pattern = "res%.redirect%s*%(",  rule_id = "CWACS_FLOW_JS_REDIR", cwe = "CWE-601", message = "Tainted user input reaches redirect() — potential open redirect" },
  },
  go = {
    { pattern = "db%.Query%s*%(",      rule_id = "CWACS_FLOW_GO_SQLI",  cwe = "CWE-89", message = "Tainted user input reaches db.Query() — potential SQL injection" },
    { pattern = "db%.Exec%s*%(",       rule_id = "CWACS_FLOW_GO_SQLI",  cwe = "CWE-89", message = "Tainted user input reaches db.Exec() — potential SQL injection" },
    { pattern = "exec%.Command%s*%(",  rule_id = "CWACS_FLOW_GO_CMDI",  cwe = "CWE-78", message = "Tainted user input reaches exec.Command() — potential command injection" },
    { pattern = "http%.Redirect%s*%(", rule_id = "CWACS_FLOW_GO_REDIR", cwe = "CWE-601", message = "Tainted user input reaches http.Redirect() — potential open redirect" },
  },
}
SINKS.typescript = SINKS.javascript
SINKS.tsx = SINKS.javascript
SINKS.jsx = SINKS.javascript

-- ---------------------------------------------------------------------------
-- Sanitizer patterns — calls that remove taint from a variable
-- ---------------------------------------------------------------------------

local SANITIZERS = {
  "parameterize%s*%(",
  "escape%s*%(",
  "sanitize%s*%(",
  "encode%s*%(",
  "html%.escape%s*%(",
  "bleach%.clean%s*%(",
  "re%.escape%s*%(",
  "urllib%.parse%.quote%s*%(",
  "encodeURIComponent%s*%(",
  "escapeHtml%s*%(",
  "DOMPurify%.sanitize%s*%(",
  "xss%s*%(",
  "validator%.escape%s*%(",
  "filepath%.Clean%s*%(",
  "path%.Clean%s*%(",
}

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

local function matches_any(text, patterns)
  for _, pat in ipairs(patterns or {}) do
    if text:find(pat) then
      return true
    end
  end
  return false
end

-- Extract the variable name from a simple assignment line.
-- Handles Python:    varname = ...
--          JS/TS:    const/let/var varname = ...  or  varname = ...
--          Go:       varname := ...  or  varname, err := ...
local function extract_lhs(line)
  -- JS/TS: const/let/var declarations
  local js_decl = line:match("^%s*(?:const|let|var)%s+([%w_]+)%s*=")
  if js_decl then return js_decl end

  -- JS/TS with explicit keyword (non-Lua pattern, use plain match)
  local after_keyword = line:match("^%s*const%s+([%w_]+)%s*=")
                     or line:match("^%s*let%s+([%w_]+)%s*=")
                     or line:match("^%s*var%s+([%w_]+)%s*=")
  if after_keyword then return after_keyword end

  -- Go short declaration:  varname :=  or  varname, err :=
  local go_lhs = line:match("^%s*([%w_]+)%s*:=")
  if go_lhs then return go_lhs end

  -- Python / plain JS:  varname = ...
  local plain = line:match("^%s*([%w_]+)%s*=")
  return plain
end

-- Return the RHS of an assignment line (everything after first = or :=)
local function extract_rhs(line)
  return line:match("=%s*(.+)$") or ""
end

-- Check whether a line contains a reference to any variable in the tainted set.
local function line_references_tainted(line, tainted)
  for var in pairs(tainted) do
    -- match the variable as a word (not part of a longer identifier)
    if line:find("[^%w_]" .. var .. "[^%w_]") or
       line:find("^" .. var .. "[^%w_]") or
       line:find("[^%w_]" .. var .. "$") or
       line == var then
      return true
    end
  end
  return false
end

-- Check whether a tainted variable appears inside a string interpolation or
-- concatenation on this line — i.e. the tainted value is being embedded into
-- the string rather than passed as a separate safe parameter.
--
-- Patterns considered "embedded":
--   Python:  "..." + var   |   f"...{var}..."   |   "..." % var
--   JS/TS:   `...${var}...`
--   Go:      fmt.Sprintf("...", var)  when the format string contains %
--
-- If the tainted variable only appears after a comma (separate argument) and
-- the sink call has an explicit format string, we do NOT consider it embedded.
local function tainted_var_is_embedded(line, tainted)
  for var in pairs(tainted) do
    local escaped = var:gsub("([%(%)%.%%%+%-%*%?%[%^%$])", "%%%1")

    -- Python f-string: {var}
    if line:find("{" .. escaped .. "}") or line:find("{" .. escaped .. ":") then
      return true
    end

    -- Python/Go string concat: "..." + var  or  var + "..."
    if line:find('"[^"]*"%s*%+%s*' .. escaped)
    or line:find(escaped .. '%s*%+%s*"')
    or line:find("'[^']*'%s*%+%s*" .. escaped)
    or line:find(escaped .. "%s*%+%s*'") then
      return true
    end

    -- JS template literal: ${var}
    if line:find("%${" .. escaped .. "}") then
      return true
    end

    -- Python % formatting: "..." % var  or  "..." % (var, ...)
    if line:find('"%s*%%%s*' .. escaped) or line:find("'%s*%%%s*" .. escaped) then
      return true
    end
  end
  return false
end

-- ---------------------------------------------------------------------------
-- Core scan
-- ---------------------------------------------------------------------------

--- Scan a buffer for intra-function dataflow vulnerabilities.
--- This is a line-based approximation: we do not parse AST function boundaries,
--- so we scan the entire buffer as a single scope.  This is intentional —
--- Neovim's tree-sitter API makes function boundary extraction language-specific
--- and complex; the line-based approach is fast (<1ms on typical files) and
--- catches the overwhelming majority of real-world patterns.
---
--- @param bufnr number
--- @param lang string  normalised language name
--- @return table  list of finding structs
function M.scan(bufnr, lang)
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return {}
  end

  local sources   = SOURCES[lang]   or {}
  local sinks     = SINKS[lang]     or {}

  if #sources == 0 or #sinks == 0 then
    return {}
  end

  local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
  local findings = {}

  -- tainted[varname] = { raw = bool, embedded = bool }
  --   raw:      variable holds a raw tainted value (direct from source or propagated)
  --   embedded: variable holds a string that has tainted content embedded via concat/interpolation
  local tainted = {}

  -- Pass 1 — build taint map (forward pass)
  for _, line in ipairs(lines) do
    local lhs = extract_lhs(line)
    if lhs then
      local rhs = extract_rhs(line)

      -- Source: RHS matches a known source pattern → raw taint
      if matches_any(rhs, sources) then
        tainted[lhs] = { raw = true, embedded = false }

      -- Propagation: RHS references an already-tainted variable
      elseif line_references_tainted(rhs, tainted) then
        if matches_any(rhs, SANITIZERS) then
          -- Sanitizer: remove taint
          tainted[lhs] = nil
        elseif tainted_var_is_embedded(rhs, tainted) then
          -- Tainted var is embedded into a string → embedded taint
          tainted[lhs] = { raw = false, embedded = true }
        else
          -- Plain propagation: inherit raw taint
          -- Check if any referenced tainted var was already embedded
          local any_embedded = false
          for var, info in pairs(tainted) do
            if info.embedded and rhs:find(var) then
              any_embedded = true
              break
            end
          end
          tainted[lhs] = { raw = not any_embedded, embedded = any_embedded }
        end

      -- Clean assignment: LHS was tainted but now assigned something clean
      elseif tainted[lhs] then
        tainted[lhs] = nil
      end
    end
  end

  -- Pass 2 — sink detection (forward pass)
  -- A finding is emitted when:
  --   (a) An embedded-taint variable reaches a sink directly as an argument, OR
  --   (b) A raw-taint variable is embedded into the sink call expression itself
  for i, line in ipairs(lines) do
    if not line_references_tainted(line, tainted) then
      goto continue
    end

    for _, sink in ipairs(sinks) do
      if not line:find(sink.pattern) then
        goto next_sink
      end
      if matches_any(line, SANITIZERS) then
        goto next_sink
      end

      -- Check if any tainted variable reaches the sink in a dangerous way
      local dangerous = false
      for var, info in pairs(tainted) do
        local escaped = var:gsub("([%(%)%.%%%+%-%*%?%[%^%$])", "%%%1")
        local on_this_line = line:find("[^%w_]" .. escaped .. "[^%w_]")
                          or line:find("^" .. escaped .. "[^%w_]")
                          or line:find("[^%w_]" .. escaped .. "$")
        if on_this_line then
          if info.embedded then
            -- Already an embedded string — reaching any sink is dangerous
            dangerous = true
            break
          elseif info.raw then
            -- Raw taint on sink line — dangerous only if embedded on this line
            local single = { [var] = info }
            if tainted_var_is_embedded(line, single) then
              dangerous = true
              break
            end
          end
        end
      end

      if dangerous then
        findings[#findings + 1] = {
          rule_id    = sink.rule_id,
          severity   = "high",
          confidence = "high",
          message    = sink.message,
          lnum       = i - 1,
          col        = 0,
          end_lnum   = i - 1,
          end_col    = #line,
          cwe        = sink.cwe,
        }
      end

      ::next_sink::
    end

    ::continue::
  end

  -- Deduplicate by rule_id + lnum
  local seen = {}
  local deduped = {}
  for _, f in ipairs(findings) do
    local key = f.rule_id .. ":" .. tostring(f.lnum)
    if not seen[key] then
      seen[key] = true
      deduped[#deduped + 1] = f
    end
  end

  return deduped
end

-- Expose source/sink tables for rule introspection and testing
M.SOURCES    = SOURCES
M.SINKS      = SINKS
M.SANITIZERS = SANITIZERS

return M
