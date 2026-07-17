const fs = require("fs");
const crypto = require("crypto");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const failureToken = require("./failure-report-token");

const SOURCE_LIMIT = 1.5 * 1024 * 1024;
const REQUEST_LIMIT = 4 * 1024 * 1024;
const RESPONSE_LIMIT = 4 * 1024 * 1024;
const LURAPH_SAFEPOINT_BUDGET = String(Math.max(30_000_000,
  Math.min(500_000_000, Number(process.env.LURAPH_SAFEPOINT_BUDGET) || 100_000_000)));
const LURAPH_PROGRESS_PREFIX = "@@LURAPH_PROGRESS@@";
const LURAPH_CS_MODES = new Set(["off", "shadow", "on"]);
const APP_ROOT = path.resolve(__dirname, "..");
const MONOREPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const PROJECT_ROOT = process.env.ALEX_PROJECT_ROOT || (fs.existsSync(path.join(APP_ROOT, "tools")) ? APP_ROOT : MONOREPO_ROOT);
const TOOL = path.join(PROJECT_ROOT, "tools", "auto_deobfuscator.py");
const NATIVE_DEOBFUSCATOR = process.env.ALEX_DEOBFUSCATOR_BINARY || (process.platform === "linux"
  ? path.join(PROJECT_ROOT, "bin", "alex_deobfuscator-linux-x64")
  : path.join(MONOREPO_ROOT, "build", "alex_deobfuscator"));
const MODES = new Set(["auto", "exact", "reconstruct", "disassemble"]);
const PROFILES = new Set(["executor-client", "roblox-client"]);
const STRUCTURAL_FALLBACK_NAME = "(?:local|function|captured_value|cell|vm_value|vm_temporary|registers|mutable_cell)_\\d+";
const STRUCTURAL_FALLBACK_PATTERN = new RegExp(`\\b${STRUCTURAL_FALLBACK_NAME}\\b`, "g");
const STRUCTURAL_FALLBACK_EXACT = new RegExp(`^${STRUCTURAL_FALLBACK_NAME}$`);
const GENERATED_SEMANTIC_NAME = "(?:argument|callback|value|values|condition|snapshot|forwarded_value|indexed_value|upvalue|upvalue_cell|state_cell|number|text|frame|text_button|text_label|ui_stroke|ui_corner|connection|merged_[a-z_]+|working_[a-z_]+)_\\d+";
const GENERATED_SEMANTIC_PATTERN = new RegExp(`\\b${GENERATED_SEMANTIC_NAME}\\b`, "g");

function luraphCsMode(value = process.env.LURAPH_CS_MODE) {
  const mode = String(value || "off").toLowerCase();
  return LURAPH_CS_MODES.has(mode) ? mode : "off";
}

function luraphCsBinary() {
  if (process.env.LURAPH_CS_BINARY) return process.env.LURAPH_CS_BINARY;
  if (process.platform === "linux") return path.join(PROJECT_ROOT, "bin", "luraph-cs");
  return path.join(MONOREPO_ROOT, "luraph_c#", "publish", "luraph-cs");
}

function shouldShadowLuraph(source, rateValue = process.env.LURAPH_CS_SHADOW_RATE) {
  const parsed = Number(rateValue == null ? 1 : rateValue);
  const rate = Number.isFinite(parsed) ? Math.max(0, Math.min(1, parsed)) : 1;
  if (rate === 0) return false;
  if (rate === 1) return true;
  const sample = crypto.createHash("sha256").update(source).digest().readUInt32BE(0) / 0x100000000;
  return sample < rate;
}

function resolveWallTimeout(input) {
  const mode = ["auto", "custom", "unlimited"].includes(input.time_limit) ? input.time_limit : (input.wall_timeout != null ? "custom" : "auto");
  if (mode === "unlimited") return { mode, seconds: 0 };
  if (mode === "custom") return { mode, seconds: Math.max(1, Math.min(280, Number(input.wall_timeout) || 40)) };
  return { mode, seconds: process.env.VERCEL ? 240 : 120 };
}

function send(res, status, value) {
  let body = JSON.stringify(value);
  if (Buffer.byteLength(body) > RESPONSE_LIMIT) {
    status = 500;
    body = JSON.stringify({ ok: false, error: { code: "response_too_large", message: "Analysis metadata exceeded the response limit." } });
  }
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(body);
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > REQUEST_LIMIT) throw Object.assign(new Error("encoded request exceeds 4 MiB"), { status: 413, code: "request_too_large" });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw Object.assign(new Error("invalid JSON"), { status: 400, code: "invalid_request" });
  }
}

function boundedFile(file, limit = RESPONSE_LIMIT) {
  if (!file || !fs.existsSync(file)) return null;
  const size = fs.statSync(file).size;
  const length = Math.min(size, limit);
  const buffer = Buffer.alloc(length);
  const descriptor = fs.openSync(file, "r");
  try {
    fs.readSync(descriptor, buffer, 0, length, 0);
  } finally {
    fs.closeSync(descriptor);
  }
  return { text: buffer.toString("utf8"), bytes: size, truncated: size > limit };
}

function sanitizePaths(value, temporary) {
  if (Array.isArray(value)) return value.map((item) => sanitizePaths(item, temporary));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitizePaths(item, temporary)]));
  }
  if (typeof value !== "string") return value;
  return value.replaceAll(temporary, "<analysis-workspace>").replaceAll(PROJECT_ROOT, "<project>");
}

function hasWeAreDevsV1Banner(source) {
  return /https:\/\/wearedevs\.net\/obfuscator/i.test(source)
    && /return\s*\(\s*function\s*\(\s*\.\.\.\s*\)/.test(source);
}

function hasWeAreDevsV1Envelope(source) {
  const text = String(source || "");
  if (text.length <= 5000) return false;
  const varargWrapper = /^\s*(?:--\[\[[\s\S]*?\]\]\s*)?return\s*\(\s*function\s*\(\s*\.\.\.\s*\)/.test(text);
  const encodedStringTable = /local\s+[A-Za-z_]\w*\s*=\s*\{\s*"\\\d{1,3}/.test(text);
  const flattenedDispatcher = /while\s+[A-Za-z_]\w*\s+do\s+if/.test(text);
  const executorEnvironmentTail = /\)\s*\(\s*getfenv\s+and\s+getfenv\(\)\s*or\s+_ENV\s*,\s*unpack\s+or\s+table\s*\[/.test(text);
  return varargWrapper && encodedStringTable && flattenedDispatcher && executorEnvironmentTail;
}

function isWeAreDevsV1(source) {
  return hasWeAreDevsV1Banner(source) || hasWeAreDevsV1Envelope(source);
}

function isLuraphEnvelope(source) {
  const text = String(source || "").replace(/^\uFEFF/, "");
  const firstLine = text.match(/^[ \t]*--[^\r\n]*/)?.[0] || "";
  const classic = /protected using Luraph Obfuscator(?:\s+v?[0-9]+(?:\.[0-9]+){0,2})?/i.test(firstLine);
  const luaAuthLph = /^\s*la_code\s*=\s*\d+\s*;\s*la_script_id\s*=\s*['"][A-Za-z0-9_-]+['"]/i.test(text)
    && /luaauth\.com/i.test(text.slice(0, 2000))
    && /return\s*\(\s*\{/.test(text)
    && /LPH\$/.test(text);
  return classic || luaAuthLph;
}

function isNativeLuraphAdapter(adapter) {
  return String(adapter || "").startsWith("luraph-");
}

function readJsonFile(file, fallback, limit = RESPONSE_LIMIT) {
  try {
    const size = fs.statSync(file).size;
    if (size > limit) return { version: 2, omitted: true, reason: "response_limit", bytes: size };
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch { return fallback; }
}

function looksLikeWeAreDevsVm(source) {
  // A banner is useful family-routing evidence on input, but it is not proof
  // that reconstructed output still contains the protector VM. Some valid
  // lifts preserve provenance comments, so quality scoring requires the
  // structural envelope instead of assigning an automatic zero for a comment.
  return hasWeAreDevsV1Envelope(source)
    || (source.length > 5000 && source.includes("getfenv and getfenv()or _ENV") && /while\s+[A-Za-z_]\w*\s+do\s+if/.test(source));
}

function hasUsableWeAreDevsTrace(result) {
  return Number.isInteger(result?.code)
    && /^\[ALEX_WD_STATE:[0-9a-f]{16}\]\s+-?\d+/m.test(String(result.stdout || ""));
}

function hasUsableLuraphTrace(result) {
  return Number.isInteger(result?.code)
    && /^@@LPH_(?:CALL_V2|VM)@@\t/m.test(String(result.stdout || ""));
}

function analyzeSourceQuality(source) {
  const text = String(source || "").replaceAll("\r\n", "\n");
  const lines = text.split("\n");
  const lineCount = Math.max(1, lines.length - (lines.at(-1) === "" ? 1 : 0));
  const structuralFallbackNames = text.match(STRUCTURAL_FALLBACK_PATTERN) || [];
  const structuralFallbackUnique = new Set(structuralFallbackNames);
  const temporaryNames = text.match(/\b(?:temporary|vm_temporary_\d+)\b/g) || [];
  const generatedSemanticNames = text.match(GENERATED_SEMANTIC_PATTERN) || [];
  const generatedSemanticUnique = new Set(generatedSemanticNames);
  const registerTables = new Set();
  const cells = new Set();
  let trivialAliases = 0;
  let structuralFallbackLines = 0;
  let temporaryLines = 0;
  let captureArtifactLines = 0;
  let registerTableLines = 0;
  let registerAccesses = 0;
  let registerSpillLines = 0;
  let registerSpillAccesses = 0;
  let semanticStateLines = 0;
  let semanticStateAccesses = 0;
  let cellAccessLines = 0;
  let cellAccesses = 0;
  let stateMachineLines = 0;
  let longNumberLines = 0;
  let oversizedDeclarationLines = 0;

  for (const line of lines) {
    const lineStructuralFallbacks = line.match(STRUCTURAL_FALLBACK_PATTERN) || [];
    if (lineStructuralFallbacks.length > 0) structuralFallbackLines += 1;
    const alias = line.match(/^\s*(?:local\s+)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;?\s*(?:--.*)?$/);
    const rhsIsIdentifier = alias && !["nil", "true", "false"].includes(alias[2]);
    if (rhsIsIdentifier && [alias[1], alias[2]].some((name) => name === "temporary" || STRUCTURAL_FALLBACK_EXACT.test(name))) {
      trivialAliases += 1;
    }
    if (/\b(?:temporary|vm_temporary_\d+)\b/.test(line)) temporaryLines += 1;
    if (/\b(?:captured_value_\d+|cell_\d+|mutable_cell_\d+|__captures)\b/.test(line)) captureArtifactLines += 1;
    const indexedRegisters = line.matchAll(/\b((?:local|registers)_\d+)\s*\)?\s*\[/g);
    let indexedRegisterLine = false;
    for (const match of indexedRegisters) {
      registerTables.add(match[1]);
      indexedRegisterLine = true;
      registerAccesses += 1;
    }
    if (indexedRegisterLine) registerTableLines += 1;
    const spillAccesses = [...line.matchAll(/\b__rbx_register_spill_\d+\.slot_\d+\b/g)].length;
    if (spillAccesses > 0) {
      registerSpillLines += 1;
      registerSpillAccesses += spillAccesses;
    }
    const stateAccesses = [...line.matchAll(/\bscript_state(?:_\d+)?\.[A-Za-z_]\w*\b/g)].length;
    if (stateAccesses > 0) {
      semanticStateLines += 1;
      semanticStateAccesses += stateAccesses;
    }
    const indexedCells = line.matchAll(/\b((?:cell|mutable_cell)_\d+)\s*\)?\s*\[/g);
    let indexedCellLine = false;
    for (const match of indexedCells) {
      cells.add(match[1]);
      indexedCellLine = true;
      cellAccesses += 1;
    }
    if (indexedCellLine) cellAccessLines += 1;
    if (/\b__state\b|while\s+__state\s*~=\s*nil/.test(line)) stateMachineLines += 1;
    if (/\b\d+\.\d{8,}\b/.test(line)) longNumberLines += 1;
    if (/^\s*local\s+/.test(line) && line.length > 240 && (line.match(/,/g) || []).length >= 12)
      oversizedDeclarationLines += 1;
  }

  const ratio = (count) => count / lineCount;
  const generatedNameDensity = generatedSemanticNames.length / lineCount;
  const semanticStateDensity = semanticStateLines / lineCount;
  const penalties = {
    generic_identifiers: Math.min(30, ratio(structuralFallbackNames.length) * 30),
    generated_semantic_names: Math.min(30, generatedNameDensity * 22),
    temporary_lines: Math.min(15, ratio(temporaryLines) * 100),
    trivial_aliases: Math.min(12, ratio(trivialAliases) * 150),
    capture_artifacts: Math.min(10, ratio(captureArtifactLines) * 140),
    register_tables: Math.min(25, ratio(registerTableLines) * 60),
    register_spill: Math.min(15, ratio(registerSpillLines) * 40),
    semantic_state_spill: Math.min(20, semanticStateDensity * 70),
    oversized_scope: Math.min(10, oversizedDeclarationLines * 5),
    long_numbers: Math.min(3, ratio(longNumberLines) * 60),
    state_machine: stateMachineLines > 0 ? 50 : 0,
    protected_wrapper: looksLikeWeAreDevsVm(text) ? 100 : 0,
  };
  let penalty = Object.values(penalties).reduce((total, value) => total + value, 0);
  if (penalties.protected_wrapper > 0) penalty = 100;
  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  const level = score >= 95 ? "source-like" : score >= 75 ? "readable" : score >= 45 ? "lifted" : "vm-shaped";

  return {
    version: 4,
    score,
    level,
    penalties: Object.fromEntries(Object.entries(penalties).map(([name, value]) => [name, Math.round(value * 10) / 10])),
    lines: lineCount,
    generic_identifier_occurrences: structuralFallbackNames.length,
    generic_identifiers: structuralFallbackUnique.size,
    structural_fallback_identifier_occurrences: structuralFallbackNames.length,
    structural_fallback_identifiers: structuralFallbackUnique.size,
    structural_fallback_lines: structuralFallbackLines,
    generated_semantic_identifier_occurrences: generatedSemanticNames.length,
    generated_semantic_identifiers: generatedSemanticUnique.size,
    generated_semantic_name_density: Math.round(generatedNameDensity * 10000) / 10000,
    trivial_alias_assignments: trivialAliases,
    structural_alias_assignments: trivialAliases,
    temporary_identifier_occurrences: temporaryNames.length,
    temporary_lines: temporaryLines,
    capture_artifact_lines: captureArtifactLines,
    register_table_lines: registerTableLines,
    register_tables: registerTables.size,
    register_accesses: registerAccesses,
    register_spill_lines: registerSpillLines,
    register_spill_accesses: registerSpillAccesses,
    semantic_state_lines: semanticStateLines,
    semantic_state_accesses: semanticStateAccesses,
    semantic_state_density: Math.round(semanticStateDensity * 10000) / 10000,
    oversized_declaration_lines: oversizedDeclarationLines,
    cell_access_lines: cellAccessLines,
    cell_accesses: cellAccesses,
    cells: cells.size,
    state_machine_lines: stateMachineLines,
    long_number_lines: longNumberLines,
  };
}

function normalizeProgressEvent(event = {}) {
  const metrics = { ...(event.metrics || {}) };
  if (event.stage === "structure_refine" && metrics.refinement_passes == null && metrics.passes != null) {
    const passes = Number(metrics.passes);
    if (Number.isFinite(passes) && passes >= 0) metrics.refinement_passes = passes;
  }
  return { ...event, metrics };
}

function parseLuraphProgressLine(line, attempt = 1) {
  if (!String(line).startsWith(LURAPH_PROGRESS_PREFIX)) return null;
  try {
    const event = JSON.parse(String(line).slice(LURAPH_PROGRESS_PREFIX.length));
    if (!event || typeof event !== "object" || typeof event.stage !== "string") return null;
    return normalizeProgressEvent({
      ...event,
      status: typeof event.status === "string" ? event.status : "running",
      message: typeof event.message === "string" ? event.message : event.stage,
      metrics: event.metrics && typeof event.metrics === "object" ? event.metrics : {},
      attempt: Number.isInteger(event.attempt) ? event.attempt : attempt,
      backend: "dotnet",
    });
  } catch {
    return null;
  }
}

function buildReconstructionQuality(report = {}, sourceQuality = null) {
  const candidate = report.reconstruction_candidate || {};
  const readability = candidate.readability || {};
  const refinementPass = [...(report.passes || [])].reverse().find((pass) => pass.stage === "structure_refine") || {};
  const structurePass = [...(report.passes || [])].reverse().find((pass) => pass.stage === "structure") || {};
  const existing = report.reconstruction_quality || {};
  const sources = [existing, readability, refinementPass, structurePass];
  const metric = (...names) => {
    for (const source of sources) {
      for (const name of names) {
        if (source?.[name] == null || source[name] === "") continue;
        const value = Number(source[name]);
        if (Number.isFinite(value) && value >= 0) return value;
      }
    }
    return null;
  };
  const boolean = (...values) => {
    for (const value of values) if (typeof value === "boolean") return value;
    return null;
  };
  const exact = report.status === "recovered_exact" && report.exact_source === true;
  const reconstructed = report.status === "reconstructed" && !exact;
  const compiled = boolean(
    report.verification?.output?.compiled,
    report.verification?.compiled,
    candidate.compiled,
    existing.verification?.compiled,
  );
  const equivalent = boolean(report.verification?.runtime?.equivalent, existing.verification?.equivalent);
  const boundedOnly = report.verification?.runtime?.bounded_only === true;
  const temporaryValuesInlined = metric("temporary_values_inlined", "temporary_aliases_removed", "single_use_temporaries_inlined");
  const generatedExpressionsInlined = metric("generated_expressions_inlined", "single_use_expressions_inlined");
  const guardClausesFlattened = metric("guard_clauses_flattened");
  const redundantParenthesesRemoved = metric("redundant_parentheses_removed");
  const stableCaptureCellsScalarized = metric("stable_capture_cells_scalarized");
  const stableCaptureAccessesScalarized = metric("stable_capture_accesses_scalarized");
  const producerAliasesCoalesced = metric("producer_aliases_coalesced");
  const writeOnlyResultPacksRemoved = metric("write_only_result_packs_removed");
  const refinementPasses = metric("refinement_passes", "passes");
  const captureReloadsRemoved = metric("capture_reloads_removed", "alias_reloads_eliminated");
  const vmAliasesRemoved = temporaryValuesInlined == null && generatedExpressionsInlined == null && captureReloadsRemoved == null
    ? null
    : (temporaryValuesInlined || 0) + (generatedExpressionsInlined || 0) + (captureReloadsRemoved || 0);

  let claim = "No reconstructed source was emitted";
  let description = "Recovery stopped before complete, compilable source could be proven.";
  if (exact) {
    claim = "Exact source-bearing payload recovered";
    description = "A source-bearing payload was recovered and accepted by the source-claim checks.";
  } else if (reconstructed) {
    claim = "Reconstructed Luau, not original source";
    description = "Behavior and structure were rebuilt; original names, comments, and formatting were not recovered.";
  } else if (report.status === "disassembled") {
    claim = "VM disassembly only";
    description = "The VM was decoded without claiming reconstructed source.";
  }

  return {
    version: 1,
    claim: exact ? "exact_source" : reconstructed ? "reconstructed_not_original" : report.status || "blocked",
    title: claim,
    description,
    original_source_recovered: exact,
    structured_regions: metric("structured_regions", "regions_structured"),
    register_tables_scalarized: metric("register_tables_scalarized"),
    register_slots_scalarized: metric("register_slots_scalarized", "register_table_slots_scalarized"),
    register_accesses_scalarized: metric("register_accesses_scalarized", "register_table_accesses_scalarized"),
    temporary_aliases_removed: temporaryValuesInlined,
    temporary_values_inlined: temporaryValuesInlined,
    generated_expressions_inlined: generatedExpressionsInlined,
    guard_clauses_flattened: guardClausesFlattened,
    redundant_parentheses_removed: redundantParenthesesRemoved,
    stable_capture_cells_scalarized: stableCaptureCellsScalarized,
    stable_capture_accesses_scalarized: stableCaptureAccessesScalarized,
    producer_aliases_coalesced: producerAliasesCoalesced,
    write_only_result_packs_removed: writeOnlyResultPacksRemoved,
    refinement_passes: refinementPasses,
    capture_reloads_removed: captureReloadsRemoved,
    vm_aliases_removed: vmAliasesRemoved,
    callback_aliases_promoted: metric("callback_aliases_promoted"),
    semantic_fidelity_score: equivalent === true && !boundedOnly ? 100 : equivalent === false ? 0 : null,
    source_quality_score: sourceQuality?.score ?? metric("source_quality_score"),
    source_quality_level: sourceQuality?.level || existing.source_quality_level || null,
    remaining_temporary_lines: sourceQuality?.temporary_lines ?? null,
    remaining_trivial_aliases: sourceQuality?.trivial_alias_assignments ?? null,
    remaining_structural_fallback_identifiers: sourceQuality?.structural_fallback_identifiers ?? null,
    remaining_structural_fallback_identifier_occurrences: sourceQuality?.structural_fallback_identifier_occurrences ?? null,
    remaining_register_accesses: sourceQuality?.register_accesses ?? null,
    remaining_cell_accesses: sourceQuality?.cell_accesses ?? null,
    verification: { compiled, equivalent },
  };
}

function buildRefinementMetrics(quality = {}) {
  const names = [
    "refinement_passes",
    "stable_capture_cells_scalarized",
    "stable_capture_accesses_scalarized",
    "producer_aliases_coalesced",
    "write_only_result_packs_removed",
    "guard_clauses_flattened",
    "redundant_parentheses_removed",
  ];
  return Object.fromEntries(names
    .filter((name) => quality[name] != null)
    .map((name) => [name, quality[name]]));
}

function validateSourceClaim(inputSource, candidate, report) {
  if (!["recovered_exact", "reconstructed"].includes(report.status)) return null;
  let code = "";
  let message = "";
  const normalizedInput = inputSource.replaceAll("\r\n", "\n").trim();
  const normalizedOutput = String(candidate?.text || "").replaceAll("\r\n", "\n").trim();
  if (!candidate || !normalizedOutput) {
    code = "source_output_missing";
    message = "the adapter claimed recovery without producing source";
  } else if (candidate.truncated) {
    code = "source_output_truncated";
    message = "the recovered source exceeded the safe response limit";
  } else if (normalizedOutput === normalizedInput) {
    code = "source_unchanged";
    message = "the adapter returned the protected input unchanged";
  } else if (looksLikeWeAreDevsVm(normalizedOutput)) {
    code = "protector_wrapper_returned";
    message = "the adapter returned a still-protected VM wrapper instead of semantic source";
  }
  if (!code) return candidate;
  report.status = "blocked";
  report.exact_source = false;
  report.diagnostics = Array.isArray(report.diagnostics) ? report.diagnostics : [];
  report.diagnostics.unshift({ stage: "claim", code, message });
  report.verification = { ...(report.verification || {}), compiled: false, source_claim_accepted: false };
  if (report.artifacts) report.artifacts.source = null;
  return null;
}

function fitResponse(response) {
  const omitted = [];
  const replacements = [
    ["payload_closure_ir", { version: 1, omitted: true, reason: "response_limit" }],
    ["semantic_ir", { version: 2, omitted: true, reason: "response_limit" }],
    ["constants", { version: 2, omitted: true, reason: "response_limit" }],
    ["artifact_graph", { version: 2, omitted: true, reason: "response_limit" }],
    ["cfg", { version: 2, omitted: true, reason: "response_limit" }],
    ["readable_lift", { text: "", bytes: response.readable_lift?.bytes || 0, truncated: true, omitted: true }],
    ["disassembly", { text: "", bytes: response.disassembly?.bytes || 0, truncated: true, omitted: true }],
  ];
  for (const [key, replacement] of replacements) {
    if (Buffer.byteLength(JSON.stringify(response)) <= RESPONSE_LIMIT - 16 * 1024) break;
    response[key] = replacement;
    omitted.push(key);
  }
  if (omitted.length) response.omitted_artifacts = omitted;
  return response;
}

function attachFailureReporting(response, source) {
  if (response.status !== "blocked") return response;
  const first = response.diagnostics?.[0] || response.report?.diagnostics?.[0] || {};
  const diagnostic = String(first.code || "analysis_blocked");
  const issued = failureToken.issue(source, diagnostic);
  const failureId = issued?.nonce || crypto.randomUUID();
  console.warn(JSON.stringify({
    event: "deobfuscation_failed",
    failure_id: failureId,
    backend: response.backend || "legacy-python",
    adapter: response.adapter || "generic",
    diagnostic,
  }));
  response.failure_report = issued ? {
    eligible: true,
    token: issued.token,
    failure_id: issued.nonce,
    expires_at: new Date(issued.expires_at).toISOString(),
  } : { eligible: false, reason: "reporting_not_configured" };
  return response;
}

function normalizeRuntimeValue(value, chunkPaths) {
  if (Array.isArray(value)) return value.map((item) => normalizeRuntimeValue(item, chunkPaths));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalizeRuntimeValue(item, chunkPaths)]));
  }
  if (typeof value !== "string") return value;
  let normalized = value;
  for (const chunkPath of chunkPaths) normalized = normalized.replaceAll(chunkPath, "<chunk>");
  return normalized
    .replace(/<chunk>:\d+/g, "<chunk>:<line>")
    .replace(/loadstring:\d+/g, "loadstring:<line>")
    .replace(/\b(table|function|thread|userdata):\s*0x[0-9a-f]+\b/gi, (_, kind) => `${kind.toLowerCase()}: <identity>`);
}

function runtimeProjection(report, chunkPaths) {
  const scheduler = report?.scheduler || {};
  return normalizeRuntimeValue({
    status: report?.status ?? null,
    termination_reason: report?.termination_reason ?? null,
    returns: report?.returns ?? [],
    stdout: report?.stdout ?? [],
    stderr: report?.stderr ?? [],
    error: report?.error ?? null,
    engine: report?.engine ?? null,
    network_requirements: report?.network_requirements ?? [],
    scheduler: {
      budget_reached: scheduler.budget_reached ?? false,
      errors: scheduler.errors ?? [],
      events: Array.isArray(scheduler.events)
        ? scheduler.events.map(({ kind, frame, time }) => ({ kind, frame, time }))
        : [],
      frames: scheduler.frames ?? 0,
      pending: scheduler.pending ?? null,
      stop_reason: scheduler.stop_reason ?? null,
      timed_out: scheduler.timed_out ?? false,
      virtual_time: scheduler.virtual_time ?? 0,
    },
  }, chunkPaths);
}

function luraphPayloadProjection(report, chunkPaths) {
  return normalizeRuntimeValue({
    status: report?.status ?? null,
    termination_reason: report?.termination_reason ?? null,
    returns: report?.returns ?? [],
    stdout: report?.stdout ?? [],
    stderr: report?.stderr ?? [],
    error: report?.error ?? null,
    network_requirements: report?.network_requirements ?? [],
  }, chunkPaths);
}

async function verifyNativeCandidate({ runtime, inputPath, candidatePath, temporary, wallTimeout, adapter = "" }) {
  if (!fs.existsSync(runtime) || !fs.existsSync(candidatePath)) return { attempted: false, equivalent: false, reason: "candidate_unavailable" };
  const execute = async (script, label) => {
    const reportPath = path.join(temporary, `verify-${label}.json`);
    const outputPath = path.join(temporary, `verify-${label}-captures`);
    const runtimeArguments = [
      "--profile", "executor-client",
      "--execution-mode", "faithful",
      "--network-policy", "offline",
      "--clock", "virtual",
      "--timeout", String(wallTimeout === 0 ? 0 : Math.max(1, Math.min(20, wallTimeout))),
      "--capture-min", "1",
      "--analysis-hooks", "off",
      "--no-normalize-pcall-errors",
      "--no-capture-string-hooks",
    ];
    if (isNativeLuraphAdapter(adapter) && label === "original") {
      runtimeArguments.push(
        "--memory-limit-mb", "768",
        "--unsupported", "trace-nil",
        "--luraph-mode", "force",
        "--luraph-max-steps", LURAPH_SAFEPOINT_BUDGET,
        "--luraph-stall-steps", "0",
        "--no-native-codegen",
      );
    }
    runtimeArguments.push(
      "--report", reportPath,
      "--out", outputPath,
      script,
    );
    const processResult = await runTool(runtime, runtimeArguments,
      wallTimeout === 0 ? 0 : Math.max(2_000, Math.min(22_000, (wallTimeout + 1) * 1000)), 1024 * 1024);
    return { processResult, report: readJsonFile(reportPath, null, 1024 * 1024) };
  };
  try {
    const original = await execute(inputPath, "original");
    const candidate = await execute(candidatePath, "candidate");
    if (!original.report || !candidate.report) return { attempted: true, equivalent: false, reason: "runtime_report_missing" };
    const paths = [inputPath, candidatePath];
    const payloadScopedLuraph = isNativeLuraphAdapter(adapter);
    const originalProjection = payloadScopedLuraph
      ? luraphPayloadProjection(original.report, paths)
      : runtimeProjection(original.report, paths);
    const candidateProjection = payloadScopedLuraph
      ? luraphPayloadProjection(candidate.report, paths)
      : runtimeProjection(candidate.report, paths);
    const equivalent = original.processResult.code === candidate.processResult.code
      && JSON.stringify(originalProjection) === JSON.stringify(candidateProjection);
    const sharedTerminationReason = original.report.termination_reason === candidate.report.termination_reason
      ? original.report.termination_reason
      : null;
    const boundedOnly = equivalent && ["runtime_error", "wall_timeout", "instruction_budget"].includes(sharedTerminationReason);
    return {
      attempted: true,
      equivalent,
      bounded_only: boundedOnly,
      scope: payloadScopedLuraph ? "complete_traced_payload_activation" : "full_runtime_report",
      protector_scaffolding_excluded: payloadScopedLuraph ? ["engine_lifecycle", "scheduler_internal_events"] : [],
      shared_termination_reason: sharedTerminationReason,
      reason: equivalent ? (boundedOnly ? "runtime_prefix_match" : "runtime_reports_match") : "runtime_reports_differ",
      compared: payloadScopedLuraph
        ? ["status", "termination_reason", "returns", "stdout", "stderr", "errors", "network_requirements"]
        : ["status", "termination_reason", "returns", "stdout", "stderr", "errors", "engine_effects", "network_requirements", "scheduler"],
      normalization: ["chunk_paths", "line_numbers", "lua_identity_addresses", "protector_only_missing_globals"],
      original_exit_code: original.processResult.code,
      candidate_exit_code: candidate.processResult.code,
      first_difference: equivalent ? null : { original: originalProjection, candidate: candidateProjection },
    };
  } catch (error) {
    return { attempted: true, equivalent: false, reason: error.code || "runtime_verification_failed" };
  }
}

function promoteVerifiedCandidate({ report, outputPath, verification, candidatePath = path.join(outputPath, "reconstructed_candidate.luau") }) {
  const reconstructedPath = path.join(outputPath, "reconstructed.luau");
  fs.copyFileSync(candidatePath, reconstructedPath);
  report.status = "reconstructed";
  report.exact_source = false;
  report.fallback_used = false;
  report.diagnostics = (report.diagnostics || []).filter((item) => item.code !== "semantic_lift_incomplete");
  report.reconstruction_candidate = {
    ...(report.reconstruction_candidate || {}),
    runtime_verified: true,
    promoted: true,
    path: "reconstructed.luau",
  };
  const mapPath = path.join(outputPath, "reconstruction_map.json");
  const reconstructionMap = readJsonFile(mapPath, { version: 2, statements: [] });
  reconstructionMap.output = "reconstructed.luau";
  reconstructionMap.verified = true;
  fs.writeFileSync(mapPath, `${JSON.stringify(reconstructionMap, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  const liftedBlocks = new Set((reconstructionMap.statements || []).map((item) => item.state)).size;
  report.coverage = {
    ...(report.coverage || {}),
    scope: "trace_reachable_payload",
    unresolved_operations: 0,
    blocks: { ...(report.coverage?.blocks || {}), lifted: liftedBlocks },
    instructions: { ...(report.coverage?.instructions || {}), lifted: report.reconstruction_candidate.statements || 0 },
    prototypes: { ...(report.coverage?.prototypes || {}), reconstructed: report.reconstruction_candidate.functions || 0 },
  };
  const liftPass = (report.passes || []).find((item) => item.stage === "lift");
  if (liftPass) Object.assign(liftPass, { ok: true, unresolved: 0, runtime_verified: true });
  report.passes = [...(report.passes || []), { stage: "verify", ok: true, backend: "rbx_luau_runtime", network_policy: "offline" }];
  report.verification = {
    ...(report.verification || {}),
    compiled: true,
    source_claim_accepted: true,
    output: { ...(report.verification?.output || {}), available: true, compiled: true },
    runtime: verification,
  };
  report.artifacts = { ...(report.artifacts || {}), source: "reconstructed.luau", candidate: "reconstructed_candidate.luau" };
  fs.writeFileSync(path.join(outputPath, "deobfuscation_report.json"), `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

function countFrom(value, ...names) {
  if (Number.isFinite(Number(value))) return Number(value);
  if (!value || typeof value !== "object") return 0;
  for (const name of names) {
    if (Number.isFinite(Number(value[name]))) return Number(value[name]);
  }
  return 0;
}

function adaptDotnetCoverage(value = {}) {
  const prototypes = countFrom(value.prototypes);
  const instructions = countFrom(value.instructions);
  const reachableInstructions = countFrom(value.reachable_instructions);
  const classifiedInstructions = countFrom(value.classified_instructions);
  const constants = countFrom(value.constants);
  const blocks = countFrom(value.blocks);
  const lifted = countFrom(value.lifted_operations);
  const unresolved = countFrom(value.unresolved_operations);
  return {
    containers: countFrom(value.containers),
    totals: { prototypes, instructions, constants, blocks },
    prototypes: { total: prototypes, recovered: prototypes },
    instructions: { total: instructions, classified: classifiedInstructions, lifted },
    constants: { total: constants, decoded: constants },
    blocks: { total: blocks, recovered: blocks, lifted: value.statement_coverage_complete ? blocks : 0 },
    normalized_instructions: lifted,
    lifted_operations: lifted,
    unresolved_operations: unresolved,
    statement_coverage: {
      complete: value.statement_coverage_complete === true,
      covered_instructions: lifted,
      total_instructions: reachableInstructions || lifted,
      decoder_prototypes: countFrom(value.decoder_prototypes),
    },
  };
}

function adaptDotnetVerification(value = {}, status = "blocked", unresolved = 0) {
  const compiled = value.compiled === true;
  const equivalent = value.equivalent === true;
  const sourceClaimAccepted = status === "reconstructed" && compiled && equivalent && unresolved === 0;
  return {
    ...value,
    compiled,
    source_claim_accepted: sourceClaimAccepted,
    output: {
      attempted: value.compile_attempted === true,
      available: status === "reconstructed",
      compiled,
    },
    runtime: {
      attempted: value.runtime_attempted === true,
      equivalent,
      bounded_only: value.bounded_only === true,
      reason: value.reason || null,
    },
  };
}

function adaptDotnetReport(value = {}) {
  let status = String(value.status || "blocked").toLowerCase();
  const coverage = adaptDotnetCoverage(value.coverage || {});
  const verification = adaptDotnetVerification(value.verification || {}, status, coverage.unresolved_operations);
  const diagnostics = Array.isArray(value.diagnostics) ? [...value.diagnostics] : [];
  if (status === "reconstructed" && verification.source_claim_accepted !== true) {
    status = "blocked";
    verification.source_claim_accepted = false;
    diagnostics.unshift({
      stage: "verify",
      code: "dotnet_source_claim_rejected",
      message: "the C# worker did not prove complete compilation and runtime equivalence",
    });
  }
  const stages = Array.isArray(value.stages) ? value.stages : [];
  return {
    ...value,
    schema_version: Number(value.schema_version) || 1,
    backend: "dotnet",
    adapter: value.adapter || "luraph-v14.7",
    status,
    exact_source: value.exact_source === true,
    coverage,
    verification,
    diagnostics,
    stages,
    passes: stages.map((stage) => ({
      stage: stage.stage,
      ok: stage.status !== "failed",
      status: stage.status,
      message: stage.message,
      ...(stage.metrics || {}),
    })),
    artifacts: value.artifacts && typeof value.artifacts === "object" ? value.artifacts : {},
  };
}

function outputArtifact(outputPath, name, fallback = null) {
  const selected = typeof name === "string" && name ? name : fallback;
  if (!selected || path.isAbsolute(selected)) return null;
  const root = path.resolve(outputPath);
  const file = path.resolve(root, selected);
  const prefix = root.endsWith(path.sep) ? root : `${root}${path.sep}`;
  return file.startsWith(prefix) ? file : null;
}

function boundedArtifact(outputPath, name, fallback = null, limit = RESPONSE_LIMIT) {
  return boundedFile(outputArtifact(outputPath, name, fallback), limit);
}

function jsonArtifact(outputPath, name, fallbackName, empty, limit = RESPONSE_LIMIT) {
  const file = outputArtifact(outputPath, name, fallbackName);
  return file ? readJsonFile(file, empty, limit) : empty;
}

function sourceFreeProjection(response = {}) {
  const coverage = response.coverage || {};
  const totals = coverage.totals || {};
  const verification = response.verification || {};
  const runtime = verification.runtime || {};
  return {
    status: response.status || null,
    coverage: {
      prototypes: countFrom(totals.prototypes ?? coverage.prototypes, "total", "recovered", "decoded"),
      instructions: countFrom(totals.instructions ?? coverage.instructions, "total", "classified", "decoded"),
      constants: countFrom(totals.constants ?? coverage.constants, "total", "decoded"),
      blocks: countFrom(totals.blocks ?? coverage.blocks, "total", "recovered", "lifted"),
      lifted_operations: countFrom(coverage.lifted_operations ?? coverage.instructions, "lifted"),
      unresolved_operations: countFrom(coverage.unresolved_operations),
    },
    verification: {
      compiled: verification.compiled === true || verification.output?.compiled === true,
      attempted: runtime.attempted === true || verification.runtime_attempted === true,
      equivalent: runtime.equivalent === true || verification.equivalent === true,
      bounded_only: runtime.bounded_only === true || verification.bounded_only === true,
    },
  };
}

function buildLuraphCsArgs({ inputPath, outputPath, runtime, wallTimeout }) {
  const timeout = wallTimeout === 0 ? 2_147_483_647 : Math.max(1, wallTimeout);
  return [
    "deobfuscate", inputPath,
    "--output", outputPath,
    "--runtime", runtime,
    "--timeout", String(timeout),
    "--max-steps", LURAPH_SAFEPOINT_BUDGET,
    "--json",
    "--progress-jsonl",
  ];
}

async function runDotnetLuraph({ source, temporary, inputPath, outputPath, wallTimeout, runtime, onProgress }) {
  const binary = luraphCsBinary();
  if (!fs.existsSync(binary)) {
    throw Object.assign(new Error("C# Luraph worker is unavailable"), { status: 503, code: "luraph_cs_unavailable" });
  }
  fs.mkdirSync(outputPath, { recursive: true, mode: 0o700 });
  let progressQueue = Promise.resolve();
  const args = buildLuraphCsArgs({ inputPath, outputPath, runtime, wallTimeout });
  const result = await runTool(binary, args, wallTimeout === 0 ? 0 : (wallTimeout + 5) * 1000, 512 * 1024, (line) => {
    const event = parseLuraphProgressLine(line);
    if (!event) return false;
    progressQueue = progressQueue.then(() => onProgress?.(event));
    return true;
  });
  await progressQueue;
  if (![0, 2].includes(result.code)) {
    const detail = String(result.stderr || result.stdout || "").split(/\r?\n/).filter(Boolean)[0] || `process exited ${result.code}`;
    throw Object.assign(new Error(`C# Luraph worker failed: ${detail.slice(0, 300)}`), { status: 422, code: "luraph_cs_failed" });
  }
  const rawReport = readJsonFile(path.join(outputPath, "report.json"), null);
  if (!rawReport || rawReport.backend !== "dotnet" || rawReport.adapter !== "luraph-v14.7") {
    throw Object.assign(new Error("C# Luraph worker did not produce a valid report"), { status: 422, code: "luraph_cs_report_invalid" });
  }
  const report = adaptDotnetReport(rawReport);
  const artifacts = report.artifacts;
  const reconstructedPath = outputArtifact(outputPath, artifacts.reconstructed, "reconstructed.luau");
  let sourceResult = report.status === "reconstructed" ? boundedFile(reconstructedPath) : null;
  sourceResult = validateSourceClaim(source, sourceResult, report);
  const sourceQuality = sourceResult ? analyzeSourceQuality(sourceResult.text) : null;
  if (sourceQuality) report.source_quality = sourceQuality;
  report.artifacts = {
    ...artifacts,
    source: sourceResult && reconstructedPath ? path.basename(reconstructedPath) : null,
  };
  report.source_output = report.artifacts.source;
  const reconstructionQuality = buildReconstructionQuality(report, sourceQuality);
  report.reconstruction_quality = reconstructionQuality;
  const candidate = report.status === "reconstructed"
    ? null
    : boundedArtifact(outputPath, artifacts.candidate, "candidate.luau", 512 * 1024);
  return {
    ok: true,
    status: report.status,
    exact_source: report.exact_source,
    backend: "dotnet",
    adapter: "luraph-v14.7",
    coverage: report.coverage,
    verification: report.verification,
    source_quality: sourceQuality,
    reconstruction_quality: reconstructionQuality,
    diagnostics: report.diagnostics,
    source: sourceResult,
    candidate,
    readable_lift: candidate,
    disassembly: boundedArtifact(outputPath, artifacts.disassembly, "disassembly.txt", 512 * 1024),
    semantic_ir: jsonArtifact(outputPath, artifacts.semantic_ir, "semantic_ir.json", { version: 1, prototypes: [] }),
    cfg: jsonArtifact(outputPath, artifacts.cfg, "cfg.json", { version: 1, nodes: [], edges: [] }),
    constants: jsonArtifact(outputPath, artifacts.constants, "constants.json", { version: 1, constants: [] }),
    reconstruction_map: jsonArtifact(outputPath, artifacts.mapping, "mapping.json", { version: 1, statements: [] }),
    opcode_handlers: jsonArtifact(outputPath, artifacts.opcode_handlers, "opcode_handlers.json", { version: 1, handlers: [] }),
    vm: jsonArtifact(outputPath, artifacts.vm, "vm.json", { version: 1, prototypes: [] }),
    envelope_analysis: jsonArtifact(outputPath, artifacts.envelope, "envelope.json", null),
    legacy_container: jsonArtifact(outputPath, artifacts.legacy_container, "legacy_container.json", null),
    artifact_graph: { version: 1, nodes: [], edges: [] },
    report: sanitizePaths({ ...report, input: { path: "input.luau" } }, temporary),
  };
}

async function runLuraphWithMode(context, dependencies = {}) {
  const selected = luraphCsMode(dependencies.mode);
  const runNative = dependencies.runNative || runNativeDeobfuscator;
  const runDotnet = dependencies.runDotnet || runDotnetLuraph;
  const shadowLog = dependencies.shadowLog || ((value) => console.info(JSON.stringify(value)));
  const serveNative = async (extra = {}) => ({
    ...(await runNative(context)),
    rollout: { luraph_cs_mode: selected, served_backend: "native-cpp", ...extra },
  });
  if (selected === "off") return serveNative();
  if (selected === "on") {
    try {
      return {
        ...(await runDotnet(context)),
        rollout: { luraph_cs_mode: selected, served_backend: "dotnet", fallback: false },
      };
    } catch (error) {
      await context.onProgress?.({
        stage: "detect",
        status: "running",
        message: "The C# worker stopped, so this job is using the native rollback path",
        metrics: { backend: "native-cpp", fallback: true, reason: error.code || "luraph_cs_failed" },
      });
      return serveNative({ fallback: true, reason: error.code || "luraph_cs_failed" });
    }
  }
  if (!shouldShadowLuraph(context.source, dependencies.shadowRate)) {
    return serveNative({ shadow_sampled: false });
  }
  const shadowOutput = path.join(context.temporary, "luraph-cs-shadow");
  const [nativeResult, dotnetResult] = await Promise.allSettled([
    runNative(context),
    runDotnet({ ...context, outputPath: shadowOutput, onProgress: null }),
  ]);
  let comparison = null;
  try {
    if (dotnetResult.status === "fulfilled") {
      const nativeProjection = nativeResult.status === "fulfilled" ? sourceFreeProjection(nativeResult.value) : null;
      const dotnetProjection = sourceFreeProjection(dotnetResult.value);
      comparison = {
        match: nativeProjection != null && JSON.stringify(nativeProjection) === JSON.stringify(dotnetProjection),
        native: nativeProjection,
        dotnet: dotnetProjection,
      };
      shadowLog({ event: "luraph_cs_shadow", ...comparison });
    } else {
      comparison = { match: false, native: nativeResult.status === "fulfilled" ? sourceFreeProjection(nativeResult.value) : null, dotnet: null };
      shadowLog({ event: "luraph_cs_shadow", ...comparison });
    }
  } finally {
    fs.rmSync(shadowOutput, { recursive: true, force: true });
  }
  if (nativeResult.status === "rejected") throw nativeResult.reason;
  return {
    ...nativeResult.value,
    rollout: {
      luraph_cs_mode: selected,
      served_backend: "native-cpp",
      shadow_sampled: true,
      shadow_match: comparison?.match === true,
    },
  };
}

async function runNativeDeobfuscator({ source, mode, temporary, inputPath, outputPath, wallTimeout, runtime, onProgress }) {
  if (!fs.existsSync(NATIVE_DEOBFUSCATOR)) {
    throw Object.assign(new Error("native deobfuscator is unavailable"), { status: 503, code: "native_unavailable" });
  }
  let nativeAttempt = 0;
  let progressQueue = Promise.resolve();
  const invokeNative = (tracePath = null) => {
    nativeAttempt += 1;
    return runTool(NATIVE_DEOBFUSCATOR, [
      inputPath, "--output-dir", outputPath, "--mode", mode, "--report", "-", "--progress-jsonl",
      ...(tracePath ? ["--trace", tracePath] : []),
    ], wallTimeout === 0 ? 0 : (wallTimeout + 5) * 1000, 256 * 1024, (line) => {
      if (!line.startsWith("@@ALEX_PROGRESS@@")) return false;
      try {
        const event = JSON.parse(line.slice("@@ALEX_PROGRESS@@".length));
        progressQueue = progressQueue.then(() => onProgress?.(normalizeProgressEvent({ ...event, attempt: nativeAttempt })));
      } catch {
        // Malformed progress output remains hidden from the public job stream.
      }
      return true;
    });
  };
  let result = await invokeNative();
  await progressQueue;
  const reportPath = path.join(outputPath, "deobfuscation_report.json");
  if (!fs.existsSync(reportPath)) {
    const diagnostic = String(result.stderr || result.stdout || "").split(/\r?\n/).filter(Boolean)[0] || `process exited ${result.code}`;
    throw Object.assign(new Error(`native analysis did not produce a report: ${diagnostic.slice(0, 500)}`), { status: 422, code: "analysis_failed" });
  }
  let report = readJsonFile(reportPath, {});
  const traceProbe = path.join(outputPath, "trace_probe.luau");
  for (let probePass = 0; probePass < 2 && report.status === "blocked" && fs.existsSync(traceProbe) && fs.existsSync(runtime); probePass += 1) {
    const luraphProbe = isNativeLuraphAdapter(report.adapter);
    await onProgress?.({
      stage: "lift",
      status: "running",
      message: luraphProbe
        ? "Tracing externally visible Luraph payload calls in the bounded offline runtime"
        : "Tracing reachable payload states in the bounded offline runtime",
      metrics: { probe_pass: probePass + 1, network_policy: "offline", adapter: report.adapter || "unknown" },
    });
    const traceOutput = path.join(temporary, `trace-runtime-${probePass + 1}`);
    const tracePath = path.join(temporary, `state-trace-${probePass + 1}.txt`);
    let traceRun = null;
    try {
      const probeArguments = [
        "--profile", "executor-client",
        "--execution-mode", "faithful",
        "--network-policy", "offline",
        "--clock", "virtual",
        "--timeout", String(wallTimeout === 0 ? 0 : Math.max(1, Math.min(30, wallTimeout))),
        "--capture-min", "1",
        "--no-normalize-pcall-errors",
        "--no-capture-string-hooks",
      ];
      if (luraphProbe) {
        probeArguments.push(
          "--memory-limit-mb", "768",
          "--unsupported", "trace-nil",
          "--luraph-mode", "force",
          "--luraph-max-steps", LURAPH_SAFEPOINT_BUDGET,
          "--luraph-stall-steps", "0",
          "--no-native-codegen",
          "--probe-trace", tracePath,
        );
      }
      probeArguments.push(
        "--out", traceOutput,
        traceProbe,
      );
      traceRun = await runTool(runtime, probeArguments,
        wallTimeout === 0 ? 0 : Math.max(2_000, Math.min(32_000, (wallTimeout + 1) * 1000)), 4 * 1024 * 1024);
    } catch {
      traceRun = null;
    }
    const probeTrace = luraphProbe && fs.existsSync(tracePath)
      ? boundedFile(tracePath, 64 * 1024 * 1024)?.text || ""
      : String(traceRun?.stdout || "");
    const traceResult = traceRun ? { ...traceRun, stdout: probeTrace } : null;
    if (luraphProbe ? hasUsableLuraphTrace(traceResult) : hasUsableWeAreDevsTrace(traceResult)) {
      await onProgress?.({
        stage: "lift",
        status: "running",
        message: traceRun.code === 0
          ? "Importing the bounded VM-state trace"
          : "Importing VM-state evidence captured before the payload stopped",
        metrics: { probe_pass: probePass + 1, runtime_exit_code: traceRun.code, partial_trace: traceRun.code !== 0 },
      });
      if (!luraphProbe)
        fs.writeFileSync(tracePath, probeTrace, { encoding: "utf8", mode: 0o600 });
      result = await invokeNative(tracePath);
      await progressQueue;
      report = readJsonFile(reportPath, {});
      if (report.runtime_trace?.snapshot_complete === true) break;
    } else break;
  }
  const candidatePath = path.join(outputPath, "reconstructed_candidate.luau");
  const candidateCanClaimSource = report.reconstruction_candidate?.compiled === true
    && report.reconstruction_candidate?.source_claim_eligible === true
    && report.reconstruction_candidate?.kind === "structured_luau";
  if (report.status === "blocked" && mode !== "exact" && mode !== "disassemble" && candidateCanClaimSource) {
    await onProgress?.({
      stage: "verify",
      status: "running",
      message: "Differentially executing protected and reconstructed programs",
      metrics: { runtime: "rbx_luau_runtime", network_policy: "offline" },
    });
    let selectedCandidate = candidatePath;
    let verification = await verifyNativeCandidate({ runtime, inputPath, candidatePath, temporary, wallTimeout, adapter: report.adapter });
    const semanticCandidate = path.join(outputPath, "semantic_state_machine_candidate.luau");
    if (verification.equivalent !== true && fs.existsSync(semanticCandidate)) {
      const semanticVerification = await verifyNativeCandidate({
        runtime,
        inputPath,
        candidatePath: semanticCandidate,
        temporary,
        wallTimeout,
        adapter: report.adapter,
      });
      if (semanticVerification.equivalent === true) {
        selectedCandidate = semanticCandidate;
        verification = { ...semanticVerification, readability_fallback: true };
        report.reconstruction_candidate = {
          ...(report.reconstruction_candidate || {}),
          representation: "semantic_state_machine",
          readability: {
            ...(report.reconstruction_candidate?.readability || {}),
            applied: false,
            fallback_reason: "readable_runtime_mismatch",
          },
        };
      }
    }
    if (verification.equivalent === true) {
      promoteVerifiedCandidate({ report, outputPath, verification, candidatePath: selectedCandidate });
      await onProgress?.({
        stage: "verify",
        status: "done",
        message: verification.bounded_only
          ? "Runtime behavior matched until both executions reached the same bounded failure"
          : "Runtime behavior matches the protected program",
        metrics: { equivalent: true, bounded_only: verification.bounded_only === true, shared_termination_reason: verification.shared_termination_reason || null, original_exit_code: verification.original_exit_code, candidate_exit_code: verification.candidate_exit_code },
      });
    } else {
      report.verification = { ...(report.verification || {}), runtime: verification };
      report.diagnostics = Array.isArray(report.diagnostics) ? report.diagnostics : [];
      report.diagnostics.unshift({
        stage: "verify",
        code: "runtime_equivalence_failed",
        message: "the reconstructed payload did not match the protected program under the bounded offline runtime",
        details: { reason: verification.reason || "runtime_reports_differ" },
      });
      fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
      await onProgress?.({
        stage: "verify",
        status: "failed",
        message: "Runtime equivalence could not be proven",
        metrics: { equivalent: false, reason: verification.reason || "runtime_reports_differ" },
      });
    }
  }
  if (report.status === "reconstructed" && isNativeLuraphAdapter(report.adapter)) {
    const reconstructedPath = path.join(outputPath, "reconstructed.luau");
    await onProgress?.({
      stage: "verify",
      status: "running",
      message: "Differentially executing the protected Luraph program and trace reconstruction",
      metrics: { runtime: "rbx_luau_runtime", network_policy: "offline" },
    });
    const verification = await verifyNativeCandidate({
      runtime,
      inputPath,
      candidatePath: reconstructedPath,
      temporary,
      wallTimeout,
      adapter: report.adapter,
    });
    report.verification = { ...(report.verification || {}), runtime: verification };
    if (verification.equivalent === true) {
      report.verification.source_claim_accepted = true;
      report.passes = [...(report.passes || []), { stage: "verify", ok: true, backend: "rbx_luau_runtime", network_policy: "offline" }];
      await onProgress?.({
        stage: "verify",
        status: "done",
        message: "The reconstructed Luau matches the protected Luraph program",
        metrics: { equivalent: true, original_exit_code: verification.original_exit_code, candidate_exit_code: verification.candidate_exit_code },
      });
    } else {
      report.status = "blocked";
      report.verification.source_claim_accepted = false;
      report.diagnostics = Array.isArray(report.diagnostics) ? report.diagnostics : [];
      report.diagnostics.unshift({
        stage: "verify",
        code: "luraph_runtime_equivalence_failed",
        message: "the trace reconstruction did not match the protected Luraph program under the bounded offline runtime",
        details: { reason: verification.reason || "runtime_reports_differ" },
      });
      if (report.artifacts) report.artifacts.source = null;
      await onProgress?.({
        stage: "verify",
        status: "failed",
        message: "Luraph runtime equivalence could not be proven",
        metrics: { equivalent: false, reason: verification.reason || "runtime_reports_differ" },
      });
    }
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  }
  const observedCandidateName = report.artifacts?.candidate === "payload_candidate.luau"
    ? report.artifacts.candidate
    : null;
  const observedCandidatePath = observedCandidateName ? path.join(outputPath, observedCandidateName) : null;
  if (report.status === "blocked" && isNativeLuraphAdapter(report.adapter) && observedCandidatePath && fs.existsSync(observedCandidatePath)) {
    await onProgress?.({
      stage: "verify",
      status: "running",
      message: "Differentially executing the protected Luraph program and observed payload candidate",
      metrics: { runtime: "rbx_luau_runtime", network_policy: "offline", source_claim: false },
    });
    const candidateVerification = await verifyNativeCandidate({
      runtime,
      inputPath,
      candidatePath: observedCandidatePath,
      temporary,
      wallTimeout,
      adapter: report.adapter,
    });
    report.verification = {
      ...(report.verification || {}),
      candidate: {
        ...(report.verification?.candidate || {}),
        available: true,
        compiled: report.verification?.candidate?.compiled === true,
        differentially_verified: candidateVerification.equivalent === true,
        source_claim: false,
        runtime: candidateVerification,
      },
    };
    report.passes = [
      ...(report.passes || []).filter((pass) => pass.stage !== "payload_candidate_verify"),
      {
        stage: "payload_candidate_verify",
        ok: candidateVerification.equivalent === true,
        backend: "rbx_luau_runtime",
        network_policy: "offline",
        source_claim: false,
      },
    ];
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await onProgress?.({
      stage: "verify",
      status: candidateVerification.equivalent === true ? "done" : "failed",
      message: candidateVerification.equivalent === true
        ? "Observed payload behavior matches; complete reconstructed source is still withheld"
        : "Observed payload candidate did not match the protected program",
      metrics: {
        equivalent: candidateVerification.equivalent === true,
        source_claim: false,
        reason: candidateVerification.reason || null,
        original_exit_code: candidateVerification.original_exit_code ?? null,
        candidate_exit_code: candidateVerification.candidate_exit_code ?? null,
      },
    });
  }
  const sourceFile = report.status === "recovered_exact"
    ? path.join(outputPath, "source_exact.luau")
    : path.join(outputPath, "reconstructed.luau");
  let sourceResult = ["recovered_exact", "reconstructed"].includes(report.status) ? boundedFile(sourceFile) : null;
  sourceResult = validateSourceClaim(source, sourceResult, report);
  const sourceQuality = sourceResult ? analyzeSourceQuality(sourceResult.text) : null;
  if (sourceQuality) report.source_quality = sourceQuality;
  const reconstructionQuality = buildReconstructionQuality(report, sourceQuality);
  report.reconstruction_quality = reconstructionQuality;
  const refinementMetrics = buildRefinementMetrics(reconstructionQuality);
  if (Object.keys(refinementMetrics).length) {
    await onProgress?.({
      stage: "structure_refine",
      status: "done",
      message: "Readability refinement evidence recorded",
      metrics: refinementMetrics,
    });
  }
  if (sourceQuality) {
    if (reconstructionQuality.structured_regions != null) {
      await onProgress?.({
        stage: "structure_flow",
        status: "done",
        message: `${reconstructionQuality.structured_regions} control-flow regions reconstructed`,
        metrics: { regions_structured: reconstructionQuality.structured_regions },
      });
    }
    const dataflowMetrics = {
      register_tables_scalarized: reconstructionQuality.register_tables_scalarized,
      register_table_slots_scalarized: reconstructionQuality.register_slots_scalarized,
      register_table_accesses_scalarized: reconstructionQuality.register_accesses_scalarized,
      single_use_temporaries_inlined: reconstructionQuality.temporary_aliases_removed,
      single_use_expressions_inlined: reconstructionQuality.generated_expressions_inlined,
      callback_aliases_promoted: reconstructionQuality.callback_aliases_promoted,
    };
    if (Object.values(dataflowMetrics).some((value) => value != null)) {
      await onProgress?.({
        stage: "structure_dataflow",
        status: "done",
        message: "Register and alias cleanup evidence recorded",
        metrics: Object.fromEntries(Object.entries(dataflowMetrics).filter(([, value]) => value != null)),
      });
    }
    await onProgress?.({
      stage: "structure_source",
      status: "done",
      message: "Source reconstruction quality measured",
      metrics: {
        source_quality_score: sourceQuality.score,
        source_quality_level: sourceQuality.level,
        generic_identifiers: sourceQuality.generic_identifiers,
        structural_fallback_identifiers: sourceQuality.structural_fallback_identifiers,
        trivial_alias_assignments: sourceQuality.trivial_alias_assignments,
        capture_artifact_lines: sourceQuality.capture_artifact_lines,
        register_accesses: sourceQuality.register_accesses,
        cell_accesses: sourceQuality.cell_accesses,
        remaining_temporary_lines: reconstructionQuality.remaining_temporary_lines,
        compiled: reconstructionQuality.verification.compiled,
      },
    });
  }
  if (!sourceResult && mode !== "disassemble") {
    const liftPass = (report.passes || []).find((pass) => pass.stage === "lift") || {};
    const guardHotspot = report.coverage?.guard_hotspot;
    if (isNativeLuraphAdapter(report.adapter) && guardHotspot?.available === true) {
      await onProgress?.({
        stage: "guard_hotspot",
        status: "failed",
        message: "Reached VM semantics are classified; execution remains inside the pre-payload guard graph",
        metrics: guardHotspot,
      });
    } else {
      await onProgress?.({
        stage: "lift",
        status: "failed",
        message: isNativeLuraphAdapter(report.adapter)
          ? "The Luraph payload was decoded, but reachable semantic operations remain unresolved"
          : "Reachable operations remain unresolved after bounded tracing",
        metrics: liftPass,
      });
    }
    if (report.verification?.candidate?.runtime?.attempted !== true) {
      await onProgress?.({ stage: "verify", status: "skipped", message: "Verification requires reconstructed source or a proven payload candidate", metrics: {} });
    }
  } else if (mode === "disassemble") {
    await onProgress?.({ stage: "lift", status: "skipped", message: "VM-only mode stops after CFG recovery", metrics: {} });
    for (const stage of ["structure_flow", "structure_closures", "structure_dataflow", "structure_source"])
      await onProgress?.({ stage, status: "skipped", message: "VM-only mode does not emit source", metrics: {} });
    await onProgress?.({ stage: "provenance", status: "skipped", message: "VM-only mode does not map reconstructed source", metrics: {} });
    await onProgress?.({ stage: "structure_refine", status: "skipped", message: "VM-only mode does not refine source", metrics: {} });
    await onProgress?.({ stage: "verify", status: "skipped", message: "VM-only mode does not verify reconstructed source", metrics: {} });
  }
  return {
    ok: true,
    status: report.status,
    exact_source: report.exact_source === true,
    backend: "native-cpp",
    adapter: report.adapter || "unsupported",
    coverage: report.coverage || null,
    verification: report.verification || null,
    source_quality: sourceQuality,
    reconstruction_quality: reconstructionQuality,
    diagnostics: report.diagnostics || [],
    source: sourceResult,
    candidate: observedCandidatePath ? boundedFile(observedCandidatePath, 512 * 1024) : null,
    candidate_provenance: readJsonFile(path.join(outputPath, "payload_candidate_provenance.json"), null),
    payload_closure_ir: readJsonFile(path.join(outputPath, "payload_closure_ir.json"), null, 4 * 1024 * 1024),
    guard_hotspot: readJsonFile(path.join(outputPath, "guard_hotspot.json"), null, 1024 * 1024),
    readable_lift: boundedFile(path.join(outputPath, "lifted_program.txt"), 512 * 1024),
    disassembly: boundedFile(path.join(outputPath, "vm_disassembly.txt"), 512 * 1024),
    semantic_ir: readJsonFile(path.join(outputPath, "semantic_ir.json"), { version: 2, prototypes: [], basic_blocks: [] }),
    cfg: readJsonFile(path.join(outputPath, "cfg.json"), { version: 2, nodes: [], edges: [] }),
    constants: readJsonFile(path.join(outputPath, "constants.json"), { version: 2, constants: [] }),
    reconstruction_map: readJsonFile(path.join(outputPath, "reconstruction_map.json"), { version: 2, statements: [] }),
    artifact_graph: readJsonFile(path.join(outputPath, "artifact_graph.json"), { version: 2, nodes: [], edges: [] }),
    envelope_analysis: readJsonFile(path.join(outputPath, "luraph_envelope_analysis.json"), null),
    report: sanitizePaths({
      ...report,
      input: { ...report.input, path: "input.luau" },
      source_output: sourceResult ? path.basename(sourceFile) : null,
    }, temporary),
  };
}

function runTool(program, args, timeoutMs, outputLimit = 256 * 1024, onStderrLine = null) {
  return new Promise((resolve, reject) => {
    const detached = process.platform !== "win32";
    const child = spawn(program, args, {
      cwd: PROJECT_ROOT,
      env: {
        PATH: process.env.PATH || "/usr/bin:/bin",
        HOME: process.env.HOME || os.tmpdir(),
        TMPDIR: process.env.TMPDIR || os.tmpdir(),
        DOTNET_BUNDLE_EXTRACT_BASE_DIR: process.env.DOTNET_BUNDLE_EXTRACT_BASE_DIR || path.join(os.tmpdir(), "luraph-dotnet"),
        PYTHONDONTWRITEBYTECODE: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
      detached,
    });
    let stdout = "";
    let stderr = "";
    let stderrLines = "";
    let settled = false;
    let timeoutError = null;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      error ? reject(error) : resolve(value);
    };
    const timer = timeoutMs > 0 ? setTimeout(() => {
      timeoutError = Object.assign(new Error("analysis exceeded its wall-time budget"), { status: 504, code: "analysis_timeout" });
      try {
        if (detached && child.pid) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    }, timeoutMs) : null;
    child.stdout.on("data", (chunk) => { if (stdout.length < outputLimit) stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => {
      stderrLines += chunk.toString();
      const lines = stderrLines.split(/\r?\n/);
      stderrLines = lines.pop() || "";
      for (const line of lines) {
        const consumed = onStderrLine?.(line) === true;
        if (!consumed && stderr.length < outputLimit) stderr += `${line}\n`;
      }
    });
    child.on("error", () => finish(Object.assign(new Error("automatic deobfuscator is unavailable"), { status: 503, code: "deobfuscator_unavailable" })));
    child.on("close", (code) => {
      if (stderrLines) {
        const consumed = onStderrLine?.(stderrLines) === true;
        if (!consumed && stderr.length < outputLimit) stderr += stderrLines;
      }
      finish(timeoutError, { code, stdout, stderr });
    });
  });
}

module.exports = async function deobfuscate(req, res) {
  if (req.method !== "POST") return send(res, 405, { ok: false, error: { code: "method_not_allowed" } });
  let temporary;
  const onProgress = typeof req.analysisProgress === "function" ? req.analysisProgress : null;
  try {
    const input = await readJson(req);
    const source = String(input.source || "");
    if (!source.trim()) throw Object.assign(new Error("source is required"), { status: 400, code: "invalid_request" });
    if (Buffer.byteLength(source) > SOURCE_LIMIT) throw Object.assign(new Error("source exceeds 1.5 MiB"), { status: 413, code: "source_too_large" });
    const mode = MODES.has(input.mode) ? input.mode : "auto";
    const profile = PROFILES.has(input.profile) ? input.profile : "executor-client";
    const passes = Math.max(1, Math.min(12, Number(input.max_passes) || 6));
    const timeLimit = resolveWallTimeout(input);
    const wallTimeout = timeLimit.seconds;
    const instructionBudget = Math.max(1000, Math.min(50000000, Number(input.instruction_budget) || 10000000));
    const runtime = process.env.RBX_RUNTIME_BINARY || (process.platform === "linux"
      ? path.join(PROJECT_ROOT, "bin", "rbx_luau_runtime-linux-x64")
      : path.join(MONOREPO_ROOT, "build", "rbx_luau_runtime"));
    const compiler = process.env.ALEXFUSCATOR_BINARY || (process.platform === "linux"
      ? path.join(PROJECT_ROOT, "bin", "alexfuscator-linux-x64")
      : path.join(MONOREPO_ROOT, "build", "alexfuscator"));
    const standalone = path.join(PROJECT_ROOT, "bin", "auto-deobfuscator-linux-x64");
    const toolProgram = process.platform === "linux" && fs.existsSync(standalone) ? standalone : "python3";
    const toolArgs = toolProgram === standalone ? [] : [TOOL];
    const luraphFamily = isLuraphEnvelope(source);
    const nativeFamily = isWeAreDevsV1(source) || luraphFamily;
    if (!nativeFamily && ((toolProgram !== standalone && !fs.existsSync(TOOL)) || !fs.existsSync(runtime) || !fs.existsSync(compiler))) {
      throw Object.assign(new Error("deobfuscation binaries are unavailable"), { status: 503, code: "deobfuscator_unavailable" });
    }

    temporary = fs.mkdtempSync(path.join(os.tmpdir(), "alex-auto-deobf-web-"));
    const inputPath = path.join(temporary, "input.luau");
    const outputPath = path.join(temporary, "result");
    fs.writeFileSync(inputPath, source, { encoding: "utf8", mode: 0o600 });
    if (nativeFamily) {
      const context = { source, mode, temporary, inputPath, outputPath, wallTimeout, runtime, onProgress };
      const nativeResponse = luraphFamily
        ? await runLuraphWithMode(context, { mode: process.env.LURAPH_CS_MODE })
        : await runNativeDeobfuscator(context);
      nativeResponse.time_limit = { mode: timeLimit.mode, seconds: wallTimeout || null, platform_cap_seconds: process.env.VERCEL ? 300 : null };
      return send(res, 200, fitResponse(attachFailureReporting(nativeResponse, source)));
    }
    await onProgress?.({
      stage: "detect",
      status: "done",
      message: "Generic adapter selected after structural family detection",
      metrics: { adapter: "auto", input_bytes: Buffer.byteLength(source) },
    });
    await onProgress?.({
      stage: "decode",
      status: "running",
      message: "Running bounded offline decoding and instrumentation passes",
      metrics: { max_passes: passes, instruction_budget: instructionBudget },
    });
    const result = await runTool(toolProgram, [...toolArgs,
      inputPath, "--output-dir", outputPath, "--runtime", runtime, "--alexfuscator", compiler,
      "--deobfuscator", NATIVE_DEOBFUSCATOR,
      "--mode", mode, "--profile", profile, "--adapter", "auto", "--max-passes", String(passes),
      "--wall-timeout", String(wallTimeout), "--instruction-budget", String(instructionBudget),
      "--network", "offline", "--no-progress",
    ], wallTimeout === 0 ? 0 : (wallTimeout + 10) * 1000);
    const reportPath = path.join(outputPath, "deobfuscation_report.json");
    if (!fs.existsSync(reportPath)) {
      const diagnostic = String(result.stderr || result.stdout || "").split(/\r?\n/).filter(Boolean)[0] || `process exited ${result.code}`;
      throw Object.assign(new Error(`analysis did not produce a report: ${diagnostic.slice(0, 500)}`), { status: 422, code: "analysis_failed" });
    }
    const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    const passByStage = new Map((report.passes || []).map((pass) => [pass.stage, pass]));
    for (const stage of ["decode", "cfg", "normalize", "lift", "structure_flow", "structure_closures", "structure_dataflow", "structure_source", "provenance", "structure_refine"]) {
      const reportStage = passByStage.has(stage)
        ? stage
        : stage.startsWith("structure_") || stage === "provenance" ? "structure" : stage === "normalize" ? "lift" : stage;
      const pass = passByStage.get(reportStage);
      await onProgress?.(normalizeProgressEvent({
        stage,
        status: pass?.ok === false ? "failed" : "done",
        message: pass ? `${stage} pass ${pass.ok === false ? "reported an unresolved condition" : "completed"}` : `${stage} stage completed`,
        metrics: pass || {},
      }));
    }
    await onProgress?.({
      stage: "verify",
      status: report.verification?.runtime?.equivalent === true ? "done" : "failed",
      message: report.verification?.runtime?.equivalent === true ? "Runtime behavior matches" : "Runtime equivalence was not proven",
      metrics: report.verification?.runtime || {},
    });
    let sourceResult = report.status === "recovered_exact"
      ? boundedFile(path.join(outputPath, "source_exact.luau"))
      : boundedFile(path.join(outputPath, "reconstructed.luau"));
    sourceResult = validateSourceClaim(source, sourceResult, report);
    const sourceQuality = sourceResult ? analyzeSourceQuality(sourceResult.text) : null;
    if (sourceQuality) report.source_quality = sourceQuality;
    const reconstructionQuality = buildReconstructionQuality(report, sourceQuality);
    report.reconstruction_quality = reconstructionQuality;
    const response = {
      ok: true,
      status: report.status,
      exact_source: report.exact_source,
      backend: report.backend || "legacy-python",
      adapter: report.adapter,
      coverage: report.coverage || null,
      verification: report.verification || null,
      source_quality: sourceQuality,
      reconstruction_quality: reconstructionQuality,
      diagnostics: report.diagnostics || [],
      source: sourceResult,
      readable_lift: boundedFile(path.join(outputPath, "lifted_program.txt"), 512 * 1024),
      disassembly: boundedFile(path.join(outputPath, "vm_disassembly.txt"), 512 * 1024),
      semantic_ir: readJsonFile(path.join(outputPath, "semantic_ir.json"), { version: 2, prototypes: [], basic_blocks: [] }),
      cfg: readJsonFile(path.join(outputPath, "cfg.json"), { version: 2, nodes: [], edges: [] }),
      constants: readJsonFile(path.join(outputPath, "constants.json"), { version: 2, constants: [] }),
      reconstruction_map: readJsonFile(path.join(outputPath, "reconstruction_map.json"), { version: 2, statements: [] }),
      artifact_graph: readJsonFile(path.join(outputPath, "artifact_graph.json"), { version: 2, nodes: [], edges: [] }),
      report: sanitizePaths({
        ...report,
        input: { ...report.input, path: "input.luau" },
        output_dir: null,
        source_output: sourceResult ? (report.status === "recovered_exact" ? "source_exact.luau" : "reconstructed.luau") : null,
      }, temporary),
      time_limit: { mode: timeLimit.mode, seconds: wallTimeout || null, platform_cap_seconds: process.env.VERCEL ? 300 : null },
    };
    return send(res, 200, fitResponse(attachFailureReporting(response, source)));
  } catch (error) {
    const requestId = crypto.randomUUID();
    const code = error.code || "analysis_error";
    const publicMessages = {
      invalid_request: "Request JSON or source is invalid.",
      request_too_large: "The encoded request exceeds 4 MiB.",
      source_too_large: "Source exceeds 1.5 MiB.",
      native_unavailable: "The native analyzer is unavailable.",
      deobfuscator_unavailable: "The analyzer is unavailable.",
      analysis_timeout: "Analysis exceeded its wall-time budget.",
      analysis_failed: "Analysis did not produce a valid report.",
    };
    console.error(JSON.stringify({ event: "deobfuscation_request_failed", request_id: requestId, code }));
    return send(res, error.status || 500, {
      ok: false,
      error: { code, message: publicMessages[code] || "Analysis failed.", request_id: requestId },
    });
  } finally {
    if (temporary) fs.rmSync(temporary, { recursive: true, force: true });
  }
};

module.exports._test = {
  analyzeSourceQuality,
  buildReconstructionQuality,
  buildRefinementMetrics,
  buildLuraphCsArgs,
  fitResponse,
  hasWeAreDevsV1Envelope,
  hasUsableLuraphTrace,
  hasUsableWeAreDevsTrace,
  adaptDotnetCoverage,
  adaptDotnetReport,
  isLuraphEnvelope,
  isWeAreDevsV1,
  looksLikeWeAreDevsVm,
  luraphCsMode,
  normalizeRuntimeValue,
  normalizeProgressEvent,
  parseLuraphProgressLine,
  luraphPayloadProjection,
  runLuraphWithMode,
  runtimeProjection,
  shouldShadowLuraph,
  sourceFreeProjection,
  validateSourceClaim,
};
