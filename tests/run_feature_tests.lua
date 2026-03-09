local helper = require("tests.helpers.feature_spec")

local specs = {
  "tests.features.sg_001_scaffold_spec",
  "tests.features.sg_002_tree_sitter_engine_spec",
  "tests.features.sg_003_diagnostics_spec",
  "tests.features.sg_004_debounce_async_spec",
  "tests.features.sg_005_dangerous_functions_spec",
  "tests.features.sg_006_hardcoded_secrets_spec",
  "tests.features.sg_007_compound_patterns_spec",
  "tests.features.sg_008_dataflow_spec",
  "tests.features.sg_009_yaml_loader_spec",
  "tests.features.sg_010_sqli_xss_cmdi_spec",
  "tests.features.sg_011_crypto_deser_path_redirect_spec",
  "tests.features.sg_012_ignore_suppress_spec",
  "tests.features.sg_013_export_spec",
  "tests.features.sg_014_mcp_spec",
  "tests.features.sg_015_corpus_ci_spec",
  "tests.features.sg_016_docs_spec",
}

local passed = 0
local failed = 0
local skipped = 0

for _, spec_name in ipairs(specs) do
  local ok, spec = pcall(require, spec_name)
  if not ok then
    failed = failed + 1
    print("FAIL  " .. spec_name .. " (load error: " .. tostring(spec) .. ")")
  else
    local ctx = helper.new_context()
    local run_ok, result = pcall(spec.run, ctx)

    if not run_ok then
      failed = failed + 1
      print("FAIL  " .. spec.id .. " " .. spec.name .. " (" .. tostring(result) .. ")")
    elseif type(result) == "table" and result.skipped then
      skipped = skipped + 1
      print("SKIP  " .. spec.id .. " " .. spec.name .. " (" .. tostring(result.reason) .. ")")
    else
      passed = passed + 1
      print("PASS  " .. spec.id .. " " .. spec.name .. " (assertions=" .. ctx.assertions .. ")")
    end
  end
end

print(string.format("\nSummary: passed=%d failed=%d skipped=%d", passed, failed, skipped))

if failed > 0 then
  vim.cmd("cquit 1")
else
  vim.cmd("qa")
end
