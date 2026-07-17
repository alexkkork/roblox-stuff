const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { Readable } = require("node:stream");

const deobfuscate = require("./deobfuscate-handler");
const {
  analyzeSourceQuality,
  adaptDotnetCoverage,
  adaptDotnetReport,
  buildReconstructionQuality,
  buildRefinementMetrics,
  buildLuraphCsArgs,
  fitResponse,
  hasWeAreDevsV1Envelope,
  hasUsableLuraphTrace,
  hasUsableWeAreDevsTrace,
  isLuraphEnvelope,
  isWeAreDevsV1,
  looksLikeWeAreDevsVm,
  luraphCsMode,
  normalizeRuntimeValue,
  normalizeProgressEvent,
  parseLuraphProgressLine,
  runLuraphWithMode,
  runtimeProjection,
  shouldShadowLuraph,
  sourceFreeProjection,
  validateSourceClaim,
} = deobfuscate._test;

const ROOT = path.resolve(__dirname, "..", "..", "..");
const NATIVE = path.join(ROOT, "build", "alex_deobfuscator");
const RUNTIME = path.join(ROOT, "build", "rbx_luau_runtime");
const STATE_MACHINE_SAMPLE = path.join(ROOT, "tests", "deobfuscation_corpus", "wearedevs_obfuscated", "020_state_machine.luau");
const LURAPH_SUBJECT = path.join(ROOT, "tests", "fixtures", "luraph", "subject_1b642e9523c1.luau");

function report(status = "reconstructed") {
  return { status, exact_source: false, diagnostics: [], verification: { compiled: true }, artifacts: { source: "reconstructed.luau" } };
}

test("rejects unchanged source claims", () => {
  const value = report();
  const candidate = validateSourceClaim("print('hello')\n", { text: "print('hello')\r\n", bytes: 15, truncated: false }, value);
  assert.equal(candidate, null);
  assert.equal(value.status, "blocked");
  assert.equal(value.diagnostics[0].code, "source_unchanged");
  assert.equal(value.artifacts.source, null);
});

test("rejects still-protected VM wrappers", () => {
  const input = "-- protected input";
  const wrapper = `${"x".repeat(5100)} getfenv and getfenv()or _ENV while state do if state then end end`;
  const value = report();
  assert.equal(validateSourceClaim(input, { text: wrapper, bytes: wrapper.length, truncated: false }, value), null);
  assert.equal(value.diagnostics[0].code, "protector_wrapper_returned");
});

test("accepts a distinct readable reconstruction", () => {
  const value = report();
  const candidate = { text: "local value = 2\nprint(value)\n", bytes: 29, truncated: false };
  assert.equal(validateSourceClaim("return(function(...) end)(...)", candidate, value), candidate);
  assert.equal(value.status, "reconstructed");
});

test("routes bannerless WeAreDevs v1 envelopes to the native adapter", () => {
  const protectedSource = fs.readFileSync(STATE_MACHINE_SAMPLE, "utf8");
  const bannerless = protectedSource.replace(/^\s*--\[\[[\s\S]*?\]\]\s*/, "");
  assert.doesNotMatch(bannerless.slice(0, 120), /wearedevs\.net\/obfuscator/i);
  assert.equal(hasWeAreDevsV1Envelope(bannerless), true);
  assert.equal(isWeAreDevsV1(bannerless), true);
});

test("routes a leading Luraph protection envelope to the native adapter", () => {
  assert.equal(isLuraphEnvelope("-- This file was protected using Luraph Obfuscator v14.7 [https://lura.ph/]\nreturn({}):P()(...);"), true);
  assert.equal(isLuraphEnvelope("\uFEFF  -- protected using luraph obfuscator v15.0\nreturn({})"), true);
  assert.equal(isLuraphEnvelope("print('Luraph Obfuscator')"), false);
  assert.equal(isLuraphEnvelope("-- unrelated\n-- protected using Luraph Obfuscator v14.7"), false);
});

test("keeps the C# Luraph worker off unless rollout opts in", async () => {
  const calls = [];
  const result = await runLuraphWithMode({ source: "luraph", onProgress: null }, {
    mode: "off",
    runNative: async () => { calls.push("native"); return { backend: "native-cpp", status: "blocked" }; },
    runDotnet: async () => { calls.push("dotnet"); return { backend: "dotnet", status: "blocked" }; },
  });
  assert.deepEqual(calls, ["native"]);
  assert.equal(luraphCsMode(""), "off");
  assert.equal(luraphCsMode("unknown"), "off");
  assert.equal(result.backend, "native-cpp");
  assert.deepEqual(result.rollout, { luraph_cs_mode: "off", served_backend: "native-cpp" });
});

test("serves C# output in on mode", async () => {
  const calls = [];
  const result = await runLuraphWithMode({ source: "luraph", onProgress: null }, {
    mode: "on",
    runNative: async () => { calls.push("native"); return { backend: "native-cpp" }; },
    runDotnet: async () => { calls.push("dotnet"); return { backend: "dotnet", status: "reconstructed" }; },
  });
  assert.deepEqual(calls, ["dotnet"]);
  assert.equal(result.backend, "dotnet");
  assert.deepEqual(result.rollout, { luraph_cs_mode: "on", served_backend: "dotnet", fallback: false });
});

test("falls back to C++ when the C# worker fails", async () => {
  const calls = [];
  const progress = [];
  const result = await runLuraphWithMode({
    source: "luraph",
    onProgress: async (event) => progress.push(event),
  }, {
    mode: "on",
    runDotnet: async () => {
      calls.push("dotnet");
      throw Object.assign(new Error("stopped"), { code: "luraph_cs_failed" });
    },
    runNative: async () => { calls.push("native"); return { backend: "native-cpp", status: "blocked" }; },
  });
  assert.deepEqual(calls, ["dotnet", "native"]);
  assert.equal(result.backend, "native-cpp");
  assert.deepEqual(result.rollout, {
    luraph_cs_mode: "on",
    served_backend: "native-cpp",
    fallback: true,
    reason: "luraph_cs_failed",
  });
  assert.equal(progress[0].metrics.fallback, true);
});

test("parses C# progress JSONL and ignores other stderr", () => {
  const line = '@@LURAPH_PROGRESS@@{"stage":"lift","status":"running","message":"lifting","metrics":{"instructions":42}}';
  const event = parseLuraphProgressLine(line, 2);
  assert.equal(event.stage, "lift");
  assert.equal(event.backend, "dotnet");
  assert.equal(event.attempt, 2);
  assert.equal(event.metrics.instructions, 42);
  assert.equal(parseLuraphProgressLine("normal stderr"), null);
  assert.equal(parseLuraphProgressLine("@@LURAPH_PROGRESS@@{"), null);
});

test("builds the single supported C# deobfuscation command", () => {
  const args = buildLuraphCsArgs({
    inputPath: "/tmp/input.luau",
    outputPath: "/tmp/result",
    runtime: "/app/bin/rbx_luau_runtime",
    wallTimeout: 45,
  });
  assert.deepEqual(args.slice(0, 8), [
    "deobfuscate", "/tmp/input.luau",
    "--output", "/tmp/result",
    "--runtime", "/app/bin/rbx_luau_runtime",
    "--timeout", "45",
  ]);
  assert.equal(args[8], "--max-steps");
  assert.match(args[9], /^\d+$/);
  assert.deepEqual(args.slice(10), ["--json", "--progress-jsonl"]);
});

test("adapts flat C# coverage and verification to the public schema", () => {
  const coverage = adaptDotnetCoverage({
    containers: 1,
    prototypes: 29,
    instructions: 8548,
    reachable_instructions: 385,
    classified_instructions: 8548,
    decoder_prototypes: 2,
    constants: 144,
    blocks: 385,
    lifted_operations: 385,
    unresolved_operations: 0,
    statement_coverage_complete: true,
  });
  const reportValue = adaptDotnetReport({
    status: "reconstructed",
    backend: "dotnet",
    adapter: "luraph-v14.7",
    coverage: {
      containers: 1,
      prototypes: 29,
      instructions: 8548,
      reachable_instructions: 385,
      classified_instructions: 8548,
      decoder_prototypes: 2,
      constants: 144,
      blocks: 385,
      lifted_operations: 385,
      unresolved_operations: 0,
      statement_coverage_complete: true,
    },
    verification: { compile_attempted: true, compiled: true, runtime_attempted: true, equivalent: true },
    artifacts: { reconstructed: "reconstructed.luau" },
  });
  assert.equal(coverage.prototypes.total, 29);
  assert.equal(coverage.instructions.lifted, 385);
  assert.equal(coverage.instructions.classified, 8548);
  assert.equal(coverage.blocks.recovered, 385);
  assert.equal(coverage.normalized_instructions, 385);
  assert.equal(coverage.statement_coverage.complete, true);
  assert.equal(coverage.statement_coverage.total_instructions, 385);
  assert.equal(reportValue.status, "reconstructed");
  assert.equal(reportValue.verification.output.compiled, true);
  assert.equal(reportValue.verification.runtime.equivalent, true);
  assert.equal(reportValue.verification.source_claim_accepted, true);
});

test("shadow metadata never includes source or diagnostics", () => {
  assert.equal(shouldShadowLuraph("same source", 1), true);
  assert.equal(shouldShadowLuraph("same source", 0), false);
  const projection = sourceFreeProjection({
    status: "blocked",
    source: { text: "private source" },
    diagnostics: [{ message: "private detail" }],
    coverage: { totals: { prototypes: 2, instructions: 10, constants: 3, blocks: 4 }, unresolved_operations: 1 },
    verification: { compiled: true, runtime: { attempted: true, equivalent: false } },
  });
  const json = JSON.stringify(projection);
  assert.doesNotMatch(json, /private source|private detail/);
  assert.deepEqual(projection.coverage, {
    prototypes: 2,
    instructions: 10,
    constants: 3,
    blocks: 4,
    lifted_operations: 0,
    unresolved_operations: 1,
  });
});

test("shadow mode serves native output and deletes C# artifacts", async () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "luraph-shadow-test-"));
  const logs = [];
  try {
    const result = await runLuraphWithMode({ source: "protected source", temporary, onProgress: null }, {
      mode: "shadow",
      shadowRate: 1,
      shadowLog: (value) => logs.push(value),
      runNative: async () => ({
        backend: "native-cpp",
        status: "blocked",
        coverage: { unresolved_operations: 1 },
        verification: { compiled: false },
      }),
      runDotnet: async ({ outputPath }) => {
        fs.mkdirSync(outputPath, { recursive: true });
        fs.writeFileSync(path.join(outputPath, "reconstructed.luau"), "private source");
        return {
          backend: "dotnet",
          status: "blocked",
          source: { text: "private source" },
          diagnostics: [{ message: "private detail" }],
          coverage: { unresolved_operations: 1 },
          verification: { compiled: false },
        };
      },
    });
    assert.equal(result.backend, "native-cpp");
    assert.equal(result.rollout.luraph_cs_mode, "shadow");
    assert.equal(result.rollout.served_backend, "native-cpp");
    assert.equal(fs.existsSync(path.join(temporary, "luraph-cs-shadow")), false);
    assert.equal(logs.length, 1);
    assert.doesNotMatch(JSON.stringify(logs[0]), /private source|private detail|protected source/);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test("native service returns bounded Luraph metadata without a source claim", {
  skip: !fs.existsSync(NATIVE),
  timeout: 10_000,
}, async () => {
  const source = [
    "-- This file was protected using Luraph Obfuscator v14.7 [https://lura.ph/]",
    "return({",
    "P=function(self)return function(...)return ... end end,",
    "readu8=function(s,i)return string.byte(s,i)end,",
    `payload=[=[LPH@${"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@".repeat(20)}]=]`,
    "}):P()(...);",
  ].join("\n");
  const request = Readable.from([Buffer.from(JSON.stringify({ source, mode: "auto" }))]);
  request.method = "POST";
  let responseBody = "";
  const response = {
    statusCode: 200,
    headers: {},
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    end(value) { responseBody = String(value || ""); },
  };

  await deobfuscate(request, response);
  assert.equal(response.statusCode, 200, responseBody);
  const payload = JSON.parse(responseBody);
  assert.equal(payload.ok, true);
  assert.equal(payload.status, "blocked");
  assert.equal(payload.backend, "native-cpp");
  assert.equal(payload.adapter, "luraph-v14.7");
  assert.equal(payload.exact_source, false);
  assert.equal(payload.source, null);
  assert.equal(payload.coverage.payload_decoded, false);
  assert.equal(payload.cfg.payload_cfg_recovered, false);
  assert.equal(payload.semantic_ir.status, "unavailable");
  assert.equal(payload.envelope_analysis.source_recovery_attempted, false);
  assert.equal(payload.report.artifacts.source, null);
  assert.ok(payload.diagnostics.some((item) => item.code === "luraph_payload_decode_unimplemented"));
});

test("watermark comments do not zero reconstructed source quality", () => {
  const reconstructed = [
    "--[[ v1.0.0 https://wearedevs.net/obfuscator ]]",
    "return (function(...)",
    '  local message = "hello"',
    "  print(message)",
    "end)(...)",
  ].join("\n");
  const quality = analyzeSourceQuality(reconstructed);
  assert.equal(isWeAreDevsV1(reconstructed), true);
  assert.equal(looksLikeWeAreDevsVm(reconstructed), false);
  assert.equal(quality.penalties.protected_wrapper, 0);
  assert.equal(quality.score, 100);
});

test("keeps valid state evidence captured before a traced payload error", () => {
  const trace = "[ALEX_WD_STATE:94ac1665a5756e2a]\t14304698\n";
  assert.equal(hasUsableWeAreDevsTrace({ code: 0, stdout: trace }), true);
  assert.equal(hasUsableWeAreDevsTrace({ code: 1, stdout: trace }), true);
  assert.equal(hasUsableWeAreDevsTrace({ code: 1, stdout: "[main_runtime_error] stopped" }), false);
  assert.equal(hasUsableWeAreDevsTrace({ code: null, stdout: trace }), false);
});

test("recognizes both Luraph call discovery and refined VM traces", () => {
  assert.equal(hasUsableLuraphTrace({ code: 0, stdout: "@@LPH_CALL_V2@@\t12\t3\n" }), true);
  assert.equal(hasUsableLuraphTrace({ code: 1, stdout: "@@LPH_VM@@\t12\t3\n" }), true);
  assert.equal(hasUsableLuraphTrace({ code: 0, stdout: "anti tamper BYPASSED\n" }), false);
});

test("runtime verification canonicalizes only Lua identity addresses", () => {
  const original = {
    status: "completed",
    termination_reason: "completed",
    stdout: ["Mixed:\tNested\ttable: 0x0000000814c377f0", "hash=0xdeadbeef"],
  };
  const candidate = {
    status: "completed",
    termination_reason: "completed",
    stdout: ["Mixed:\tNested\ttable: 0x00000008c8a03820", "hash=0xdeadbeef"],
  };
  assert.deepEqual(runtimeProjection(original, []), runtimeProjection(candidate, []));
  assert.deepEqual(
    normalizeRuntimeValue(["function: 0xABC", "thread: 0x123", "userdata: 0x456", "0xABC"], []),
    ["function: <identity>", "thread: <identity>", "userdata: <identity>", "0xABC"],
  );
  candidate.stdout[1] = "hash=0xcafebabe";
  assert.notDeepEqual(runtimeProjection(original, []), runtimeProjection(candidate, []));
});

test("measures source-like output separately from lifted VM artifacts", () => {
  const clean = analyzeSourceQuality('local players = game:GetService("Players")\nprint(players.LocalPlayer)\n');
  const lifted = analyzeSourceQuality([
    "local local_1, local_2, captured_value_3",
    "local_1 = game",
    "temporary = local_1",
    "local_2 = temporary",
    "captured_value_3 = local_2",
    "local_2[17] = captured_value_3",
    "local __state = 42",
    "while __state ~= nil do",
    "end",
  ].join("\n"));
  assert.equal(clean.level, "source-like");
  assert.equal(clean.state_machine_lines, 0);
  assert.ok(lifted.score < clean.score);
  assert.equal(lifted.level, "vm-shaped");
  assert.ok(lifted.trivial_alias_assignments >= 3);
  assert.ok(lifted.capture_artifact_lines >= 2);
  assert.equal(lifted.register_tables, 1);
  assert.equal(lifted.register_table_lines, 1);
  assert.ok(lifted.state_machine_lines >= 2);
});

test("structural role renaming does not inflate source quality", () => {
  const legacy = analyzeSourceQuality([
    "local local_1 = {}",
    "local local_2 = { nil }",
    "local temporary = local_1",
    "local local_3 = temporary",
    "local_1[1] = local_3",
    "local_2[1] = local_1[1]",
    "return local_2[1]",
  ].join("\n"));
  const renamed = analyzeSourceQuality([
    "local registers_1 = {}",
    "local mutable_cell_1 = { nil }",
    "local vm_temporary_1 = registers_1",
    "local vm_value_1 = vm_temporary_1",
    "registers_1[1] = vm_value_1",
    "mutable_cell_1[1] = registers_1[1]",
    "return mutable_cell_1[1]",
  ].join("\n"));

  assert.equal(renamed.version, 4);
  assert.ok(renamed.score <= legacy.score, `${renamed.score} should not exceed ${legacy.score}`);
  assert.equal(renamed.structural_fallback_identifiers, 4);
  assert.equal(renamed.structural_fallback_identifier_occurrences, 11);
  assert.equal(renamed.structural_fallback_lines, 7);
  assert.equal(renamed.structural_alias_assignments, 2);
  assert.equal(renamed.temporary_identifier_occurrences, 2);
  assert.equal(renamed.temporary_lines, 2);
  assert.equal(renamed.register_tables, 1);
  assert.equal(renamed.register_accesses, 2);
  assert.equal(renamed.cells, 1);
  assert.equal(renamed.cell_accesses, 2);
  assert.equal(renamed.capture_artifact_lines, 3);
});

test("quality analysis does not count literal assignments as aliases", () => {
  const quality = analyzeSourceQuality([
    "registers_1 = nil",
    "vm_value_1 = true",
    "vm_value_2 = false",
    "vm_value_3 = registers_1",
  ].join("\n"));
  assert.equal(quality.trivial_alias_assignments, 1);
});

test("idiomatic Luau names score better than numbered structural fallbacks", () => {
  const structural = analyzeSourceQuality([
    "local registers_1 = {}",
    "local mutable_cell_1 = { nil }",
    "local vm_temporary_1 = registers_1",
    "mutable_cell_1[1] = vm_temporary_1",
    "return mutable_cell_1[1]",
  ].join("\n"));
  const idiomatic = analyzeSourceQuality([
    "local registers_by_player = {}",
    "local mutable_cell_count = 0",
    "local vm_temporary_budget = registers_by_player",
    "registers_by_player[1] = vm_temporary_budget",
    "return registers_by_player[1], mutable_cell_count",
  ].join("\n"));

  assert.equal(idiomatic.score, 100);
  assert.ok(idiomatic.score > structural.score);
  assert.equal(idiomatic.structural_fallback_identifiers, 0);
  assert.equal(idiomatic.temporary_identifier_occurrences, 0);
  assert.equal(idiomatic.register_accesses, 0);
  assert.equal(idiomatic.cell_accesses, 0);
});

test("source quality reports emitted register spills instead of hiding them", () => {
  const quality = analyzeSourceQuality(`local __rbx_register_spill_1 = {}\n__rbx_register_spill_1.slot_1 = 42\nprint(__rbx_register_spill_1.slot_1)\n`);
  assert.equal(quality.register_spill_accesses, 2);
  assert.equal(quality.register_spill_lines, 2);
  assert.ok(quality.penalties.register_spill > 0);
  assert.ok(quality.score < 100);
});

test("semantic state fields remain visible as reconstruction debt", () => {
  const quality = analyzeSourceQuality(`local script_state = {}\nscript_state.auto_weave = true\nprint(script_state.auto_weave)\n`);
  assert.equal(quality.semantic_state_accesses, 2);
  assert.equal(quality.semantic_state_lines, 2);
  assert.equal(quality.penalties.register_spill, 0);
  assert.ok(quality.penalties.semantic_state_spill > 0);
  assert.ok(quality.score < 100);
});

test("generated semantic-looking names cannot earn a perfect score", () => {
  const quality = analyzeSourceQuality([
    "local callback_83 = function(argument_1)",
    "    local value_139 = argument_1.Character",
    "    return value_139",
    "end",
    "players.PlayerAdded:Connect(callback_83)",
  ].join("\n"));
  assert.equal(quality.generated_semantic_identifiers, 3);
  assert.ok(quality.penalties.generated_semantic_names > 0);
  assert.ok(quality.score < 100);
});

test("large synthetic declaration scopes cannot earn a perfect score", () => {
  const names = Array.from({ length: 30 }, (_, index) => `descriptive_binding_${index + 1}`);
  const quality = analyzeSourceQuality(`local ${names.join(", ")}\nprint(descriptive_binding_1)\n`);
  assert.equal(quality.oversized_declaration_lines, 1);
  assert.ok(quality.penalties.oversized_scope > 0);
  assert.ok(quality.score < 100);
});

test("bounded runtime matches do not claim a 100 semantic fidelity score", () => {
  const quality = buildReconstructionQuality({
    status: "reconstructed",
    reconstruction_candidate: { compiled: true, readability: {} },
    verification: { compiled: true, runtime: { equivalent: true, bounded_only: true } },
  });
  assert.equal(quality.verification.equivalent, true);
  assert.equal(quality.semantic_fidelity_score, null);
});

test("normalizes native reconstruction evidence without claiming original source", () => {
  const value = buildReconstructionQuality({
    status: "reconstructed",
    exact_source: false,
    reconstruction_candidate: {
      compiled: true,
      readability: {
        regions_structured: 14,
        register_tables_scalarized: 2,
        register_table_slots_scalarized: 69,
        register_table_accesses_scalarized: 8740,
        single_use_temporaries_inlined: 117,
        alias_reloads_eliminated: 83,
        callback_aliases_promoted: 6,
      },
    },
    verification: { output: { compiled: true }, runtime: { equivalent: true } },
  }, {
    score: 38,
    level: "vm-shaped",
    temporary_lines: 1147,
    trivial_alias_assignments: 1712,
    structural_fallback_identifiers: 4,
    structural_fallback_identifier_occurrences: 2281,
    register_accesses: 874,
    cell_accesses: 93,
  });

  assert.equal(value.claim, "reconstructed_not_original");
  assert.equal(value.original_source_recovered, false);
  assert.equal(value.title, "Reconstructed Luau, not original source");
  assert.match(value.description, /original names, comments, and formatting were not recovered/);
  assert.equal(value.structured_regions, 14);
  assert.equal(value.register_tables_scalarized, 2);
  assert.equal(value.register_slots_scalarized, 69);
  assert.equal(value.register_accesses_scalarized, 8740);
  assert.equal(value.temporary_aliases_removed, 117);
  assert.equal(value.temporary_values_inlined, 117);
  assert.equal(value.capture_reloads_removed, 83);
  assert.equal(value.vm_aliases_removed, 200);
  assert.equal(value.callback_aliases_promoted, 6);
  assert.equal(value.semantic_fidelity_score, 100);
  assert.equal(value.remaining_structural_fallback_identifiers, 4);
  assert.equal(value.remaining_structural_fallback_identifier_occurrences, 2281);
  assert.equal(value.remaining_register_accesses, 874);
  assert.equal(value.remaining_cell_accesses, 93);
  assert.deepEqual(value.verification, { compiled: true, equivalent: true });
});

test("normalizes dedicated refinement evidence and preserves measured zeroes", () => {
  const value = buildReconstructionQuality({
    status: "reconstructed",
    passes: [{
      stage: "structure_refine",
      passes: 2,
      stable_capture_cells_scalarized: 3,
      stable_capture_accesses_scalarized: 14,
      producer_aliases_coalesced: 5,
      write_only_result_packs_removed: 1,
      guard_clauses_flattened: 0,
      redundant_parentheses_removed: 8,
    }],
  });

  assert.deepEqual(buildRefinementMetrics(value), {
    refinement_passes: 2,
    stable_capture_cells_scalarized: 3,
    stable_capture_accesses_scalarized: 14,
    producer_aliases_coalesced: 5,
    write_only_result_packs_removed: 1,
    guard_clauses_flattened: 0,
    redundant_parentheses_removed: 8,
  });
});

test("normalizes native structure_refine progress to the public metric name", () => {
  const event = normalizeProgressEvent({
    stage: "structure_refine",
    status: "done",
    metrics: { passes: 1, dead_assignments_removed: 4 },
  });
  assert.equal(event.metrics.passes, 1);
  assert.equal(event.metrics.refinement_passes, 1);
  assert.equal(event.metrics.dead_assignments_removed, 4);
});

test("keeps unavailable reconstruction evidence distinct from measured zero", () => {
  const unavailable = buildReconstructionQuality({ status: "blocked", verification: {} });
  assert.equal(unavailable.structured_regions, null);
  assert.equal(unavailable.register_slots_scalarized, null);
  assert.deepEqual(unavailable.verification, { compiled: null, equivalent: null });

  const measured = buildReconstructionQuality({
    status: "reconstructed",
    passes: [{ stage: "structure", regions_structured: 0, register_table_slots_scalarized: 0 }],
    verification: { compiled: false, runtime: { equivalent: false } },
  });
  assert.equal(measured.structured_regions, 0);
  assert.equal(measured.register_slots_scalarized, 0);
  assert.deepEqual(measured.verification, { compiled: false, equivalent: false });
});

test("reserves exact-source wording for a verified exact-source status", () => {
  const exact = buildReconstructionQuality({ status: "recovered_exact", exact_source: true, verification: { compiled: true } });
  const contradictory = buildReconstructionQuality({ status: "recovered_exact", exact_source: false, verification: { compiled: true } });
  assert.equal(exact.claim, "exact_source");
  assert.equal(exact.original_source_recovered, true);
  assert.equal(contradictory.original_source_recovered, false);
  assert.notEqual(contradictory.claim, "exact_source");
});

test("deobfuscator UI exposes reconstruction evidence and honest wording", () => {
  const html = fs.readFileSync(path.join(ROOT, "web", "rbx-runtime-runner", "public", "deobfuscator.html"), "utf8");
  const client = fs.readFileSync(path.join(ROOT, "web", "rbx-runtime-runner", "public", "deobfuscator.js"), "utf8");
  for (const label of [
    "Structured regions",
    "Register slots scalarized",
    "Register accesses scalarized",
    "VM aliases removed",
    "Callback aliases promoted",
    "Refinement passes",
    "Stable capture cells scalarized",
    "Stable capture accesses scalarized",
    "Producer aliases coalesced",
    "Write-only result packs removed",
    "Guard clauses flattened",
    "Redundant parentheses removed",
  ])
    assert.match(html, new RegExp(label));
  assert.match(html, /data-stage="structure_refine"/);
  assert.match(html, /Reconstructed Luau, not original source/);
  assert.match(client, /renderReconstructionQuality\(payload\)/);
  for (const metric of [
    "refinement_passes",
    "stable_capture_cells_scalarized",
    "stable_capture_accesses_scalarized",
    "producer_aliases_coalesced",
    "write_only_result_packs_removed",
    "guard_clauses_flattened",
    "redundant_parentheses_removed",
  ]) assert.match(client, new RegExp(metric));
});

test("fits oversized metadata by omitting large artifacts", () => {
  const response = {
    ok: true,
    semantic_ir: { data: "x".repeat(4 * 1024 * 1024) },
    constants: { data: "y".repeat(1024 * 1024) },
    artifact_graph: {},
    cfg: {},
    disassembly: { text: "" },
  };
  fitResponse(response);
  assert.ok(Buffer.byteLength(JSON.stringify(response)) < 4 * 1024 * 1024);
  assert.ok(response.omitted_artifacts.includes("semantic_ir"));
});

test("native trace promotes a verified state-machine reconstruction", {
  skip: ![NATIVE, RUNTIME, STATE_MACHINE_SAMPLE].every((file) => fs.existsSync(file)),
  timeout: 30_000,
}, async () => {
  const request = Readable.from([Buffer.from(JSON.stringify({
    source: fs.readFileSync(STATE_MACHINE_SAMPLE, "utf8"),
    mode: "reconstruct",
    wallTimeout: 10,
  }))]);
  request.method = "POST";
  let responseBody = "";
  const response = {
    statusCode: 200,
    headers: {},
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    end(value) { responseBody = String(value || ""); },
  };

  await deobfuscate(request, response);
  assert.equal(response.statusCode, 200, responseBody);
  const payload = JSON.parse(responseBody);
  assert.equal(payload.ok, true);
  assert.equal(payload.status, "reconstructed");
  assert.equal(payload.backend, "native-cpp");
  assert.equal(payload.adapter, "wearedevs-v1");
  assert.equal(payload.verification.runtime.equivalent, true);
  assert.equal(payload.coverage.unresolved_operations, 0);
  assert.ok(payload.coverage.blocks.lifted > 1);
  assert.equal(new Set(payload.reconstruction_map.statements.map((item) => item.state)).size, payload.coverage.blocks.lifted);
  assert.equal(payload.source.truncated, false);
  assert.equal(payload.report.reconstruction_candidate.representation, "structured_control_flow");
  assert.ok(payload.report.reconstruction_candidate.readability.regions_structured > 0);
  assert.equal(payload.source_quality.version, 4);
  assert.ok(payload.source_quality.score >= 0 && payload.source_quality.score <= 100);
  assert.equal(payload.report.source_quality.score, payload.source_quality.score);
  assert.equal(payload.reconstruction_quality.claim, "reconstructed_not_original");
  assert.equal(payload.reconstruction_quality.original_source_recovered, false);
  assert.equal(payload.reconstruction_quality.verification.compiled, true);
  assert.equal(payload.reconstruction_quality.verification.equivalent, true);
  assert.equal(payload.reconstruction_quality.structured_regions, payload.report.reconstruction_candidate.readability.regions_structured);
  assert.match(payload.source.text, /Control flow, closures, globals, properties, and method calls were reconstructed/);
  assert.doesNotMatch(payload.source.text, /while __state ~= nil do/);
  assert.doesNotMatch(payload.source.text, /wearedevs\.net\/obfuscator/i);
  assert.deepEqual(payload.diagnostics, []);
});

test("Luraph payload closure reconstructs source with complete instruction coverage", {
  skip: ![NATIVE, RUNTIME, LURAPH_SUBJECT].every((file) => fs.existsSync(file)),
  timeout: 45_000,
}, async () => {
  const request = Readable.from([Buffer.from(JSON.stringify({
    source: fs.readFileSync(LURAPH_SUBJECT, "utf8"),
    mode: "reconstruct",
    wallTimeout: 20,
  }))]);
  request.method = "POST";
  let responseBody = "";
  const response = {
    statusCode: 200,
    headers: {},
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    end(value) { responseBody = String(value || ""); },
  };

  await deobfuscate(request, response);
  assert.equal(response.statusCode, 200, responseBody);
  const payload = JSON.parse(responseBody);
  assert.equal(payload.ok, true);
  assert.equal(payload.status, "reconstructed");
  assert.equal(payload.adapter, "luraph-v14.7");
  assert.equal(payload.exact_source, false);
  assert.equal(payload.source.text, 'print("anti tamper BYPASSED")\n');
  assert.equal(payload.source.truncated, false);
  assert.equal(payload.candidate, null);
  assert.equal(payload.report.artifacts.source, "reconstructed.luau");
  assert.equal(payload.report.source_output, "reconstructed.luau");

  assert.equal(payload.coverage.statement_coverage.complete, true);
  assert.equal(payload.coverage.statement_coverage.covered_instructions, 385);
  assert.equal(payload.coverage.statement_coverage.total_instructions, 385);
  assert.equal(payload.coverage.statement_coverage.decoder_prototypes, 2);
  assert.equal(payload.reconstruction_map.statement_coverage_complete, true);
  assert.equal(payload.reconstruction_map.instruction_coverage.length, 385);
  const dispositions = new Set(payload.reconstruction_map.instruction_coverage.map((item) => item.disposition));
  assert.ok(dispositions.has("emitted_statement"));
  assert.ok(dispositions.has("runtime_value_producer"));
  assert.ok(dispositions.has("runtime_value_decoder_elided"));
  const tracePass = payload.report.passes.findLast((pass) => pass.stage === "trace");
  assert.equal(tracePass.payload_activation_complete, true);
  assert.equal(tracePass.payload_calls, 1);

  assert.equal(payload.verification.source_claim_accepted, true);
  assert.equal(payload.verification.runtime.attempted, true);
  assert.equal(payload.verification.runtime.equivalent, true);
  assert.equal(payload.verification.runtime.bounded_only, false);
  assert.equal(payload.verification.runtime.scope, "complete_traced_payload_activation");
  assert.deepEqual(payload.verification.runtime.protector_scaffolding_excluded, ["engine_lifecycle", "scheduler_internal_events"]);

  const verificationPass = payload.report.passes.findLast((pass) => pass.stage === "verify");
  assert.equal(verificationPass.ok, true);
  assert.ok(payload.diagnostics.some((item) => item.code === "luraph_trace_payload_reconstructed"));
  assert.ok(!payload.diagnostics.some((item) => item.code === "luraph_semantic_payload_incomplete"));
});
