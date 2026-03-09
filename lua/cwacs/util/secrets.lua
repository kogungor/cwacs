local M = {}

local secret_keys = {
  "api_key",
  "apikey",
  "secret",
  "password",
  "passwd",
  "pwd",
  "token",
  "private_key",
}

local placeholder_values = {
  "changeme",
  "change_me",
  "example",
  "sample",
  "dummy",
  "test",
  "password",
  "secret",
  "token",
  "your_api_key",
  "none",
  "null",
}

local function is_comment_line(line)
  local trimmed = line:match("^%s*(.-)%s*$") or ""
  return trimmed:match("^#") or trimmed:match("^//") or trimmed:match("^%-%-")
end

local function has_env_reference(line)
  local lower = line:lower()
  return lower:find("os%.environ", 1, false)
    or lower:find("os%.getenv", 1, false)
    or lower:find("process%.env", 1, false)
    or lower:find("std::env::var", 1, false)
    or lower:find("vim%.env", 1, false)
end

local function extract_first_quoted_value(line)
  local d_start, d_end, d_val = line:find('"([^"]+)"')
  local s_start, s_end, s_val = line:find("'([^']+)'")

  if d_start and s_start then
    if d_start < s_start then
      return d_start, d_end, d_val
    end
    return s_start, s_end, s_val
  end

  if d_start then
    return d_start, d_end, d_val
  end

  if s_start then
    return s_start, s_end, s_val
  end

  return nil
end

local function has_secret_key_name(left_side)
  local normalized = left_side:lower():gsub("[^%w_%-]", "")
  for _, key in ipairs(secret_keys) do
    if normalized:find(key, 1, true) then
      return true
    end
  end
  return false
end

local function is_placeholder_value(value)
  local lower = value:lower()
  local normalized = lower:gsub("[^%w]", "")
  for _, item in ipairs(placeholder_values) do
    local normalized_item = item:gsub("[^%w]", "")
    if lower == item or normalized == normalized_item then
      return true
    end
  end
  return false
end

function M.entropy(value)
  if not value or value == "" then
    return 0
  end

  local counts = {}
  local len = #value
  for i = 1, len do
    local c = value:sub(i, i)
    counts[c] = (counts[c] or 0) + 1
  end

  local entropy = 0
  for _, count in pairs(counts) do
    local p = count / len
    entropy = entropy - (p * (math.log(p) / math.log(2)))
  end

  return entropy
end

function M.keyword_secret_match(line)
  if is_comment_line(line) or has_env_reference(line) then
    return nil
  end

  local eq_pos = line:find("=") or line:find(":")
  if not eq_pos then
    return nil
  end

  local left = line:sub(1, eq_pos - 1)
  if not has_secret_key_name(left) then
    return nil
  end

  local start_pos, end_pos, value = extract_first_quoted_value(line)
  if not start_pos or not value then
    return nil
  end

  if is_placeholder_value(value) then
    return nil
  end

  return {
    col = start_pos - 1,
    end_col = end_pos,
    value = value,
  }
end

function M.high_entropy_secret_match(line)
  if is_comment_line(line) or has_env_reference(line) then
    return nil
  end

  local eq_pos = line:find("=") or line:find(":")
  if not eq_pos then
    return nil
  end

  local _, _, value = extract_first_quoted_value(line)
  if not value or #value < 20 then
    return nil
  end

  if is_placeholder_value(value) then
    return nil
  end

  local entropy = M.entropy(value)
  if entropy < 4.5 then
    return nil
  end

  local start_pos, end_pos = line:find(value, 1, true)
  if not start_pos then
    return nil
  end

  return {
    col = start_pos - 1,
    end_col = end_pos,
    value = value,
    entropy = entropy,
  }
end

return M
