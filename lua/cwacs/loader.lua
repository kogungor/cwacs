local M = {}

local function trim(s)
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function split_csv(text)
  local values = {}
  for part in text:gmatch("[^,]+") do
    values[#values + 1] = trim(part)
  end
  return values
end

local function parse_scalar(raw)
  local value = trim(raw or "")
  if value == "" then
    return ""
  end

  if value == "true" then
    return true
  end
  if value == "false" then
    return false
  end

  local quoted = value:match('^"(.*)"$') or value:match("^'(.*)'$")
  if quoted ~= nil then
    return quoted
  end

  local list = value:match("^%[(.*)%]$")
  if list then
    local out = {}
    for _, item in ipairs(split_csv(list)) do
      local clean = item:match('^"(.*)"$') or item:match("^'(.*)'$") or item
      if clean ~= "" then
        out[#out + 1] = clean
      end
    end
    return out
  end

  local num = tonumber(value)
  if num ~= nil then
    return num
  end

  return value
end

local function parse_yaml_subset(content)
  local rules = {}
  local current = nil

  for raw_line in (content .. "\n"):gmatch("(.-)\n") do
    local line = raw_line:gsub("\r$", "")
    local stripped = trim(line)
    if stripped ~= "" and not stripped:match("^#") then
      local item_key, item_val = stripped:match("^%-%s*([%w_]+)%s*:%s*(.-)%s*$")
      if item_key then
        current = {}
        current[item_key] = parse_scalar(item_val)
        rules[#rules + 1] = current
      elseif stripped:match("^%-%s*$") then
        current = {}
        rules[#rules + 1] = current
      else
        local key, val = stripped:match("^([%w_]+)%s*:%s*(.-)%s*$")
        if key and current then
          current[key] = parse_scalar(val)
        end
      end
    end
  end

  return rules
end

local function normalize_languages(rule)
  if type(rule.languages) == "table" and #rule.languages > 0 then
    return rule.languages
  end
  if type(rule.language) == "string" and rule.language ~= "" then
    return { rule.language }
  end
  return nil
end

local function normalize_rule(raw)
  local languages = normalize_languages(raw)
  if not languages then
    return nil, "missing language/languages"
  end
  if type(raw.id) ~= "string" or raw.id == "" then
    return nil, "missing id"
  end

  local line_pattern = raw.line_pattern or raw.pattern
  if type(line_pattern) ~= "string" or line_pattern == "" then
    return nil, "missing line_pattern/pattern"
  end

  local normalized = {
    id = raw.id,
    languages = languages,
    severity = raw.severity or "medium",
    confidence = raw.confidence or "medium",
    cwe = raw.cwe or "CWE-0",
    message = raw.message or ("Custom rule hit: " .. raw.id),
    capture = raw.capture,
    query = raw.query,
    line_pattern = line_pattern,
  }

  return normalized
end

local function read_file(path)
  local file = io.open(path, "r")
  if not file then
    return nil
  end
  local content = file:read("*a")
  file:close()
  return content
end

function M.load_path(path)
  local loaded = {}
  local errors = {}

  if not path or path == "" then
    return loaded, errors
  end

  local absolute = vim.fs.normalize(vim.fn.fnamemodify(path, ":p"))
  if vim.fn.isdirectory(absolute) ~= 1 then
    return loaded, errors
  end

  for name, kind in vim.fs.dir(absolute) do
    if kind == "file" and name:match("%.ya?ml$") then
      local full = absolute .. "/" .. name
      local content = read_file(full)
      if not content then
        errors[#errors + 1] = string.format("%s: cannot read file", name)
      else
        local ok_parse, parsed = pcall(parse_yaml_subset, content)
        if not ok_parse then
          errors[#errors + 1] = string.format("%s: parse error", name)
        else
          for idx, raw_rule in ipairs(parsed) do
            local rule, err = normalize_rule(raw_rule)
            if rule then
              loaded[#loaded + 1] = rule
            else
              errors[#errors + 1] = string.format("%s[%d]: %s", name, idx, err)
            end
          end
        end
      end
    end
  end

  table.sort(loaded, function(a, b)
    return (a.id or "") < (b.id or "")
  end)

  return loaded, errors
end

return M
