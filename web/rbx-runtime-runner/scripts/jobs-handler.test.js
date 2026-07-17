const assert = require("node:assert/strict");
const test = require("node:test");
const {
  RUNTIME_STAGES,
  STAGES,
  applyProgress,
  finalMessage,
  initialStatus,
  jobKind,
  publicStatus,
  requestedLimit,
  route,
  validateInput,
} = require("./jobs-handler")._test;

test("job routes expose create, status, and finished capability URLs", () => {
  const id = "abcdefghijklmnopqrstuvwxyz_0123456789";
  assert.deepEqual(route({ url: "/jobs/create" }), { action: "create" });
  assert.deepEqual(route({ url: `/jobs/status/${id}` }), { action: "status", id });
  assert.deepEqual(route({ url: `/jobs/finished/${id}` }), { action: "finished", id });
  assert.deepEqual(route({ url: `/api/jobs?action=status&id=${id}` }), { action: "status", id });
  assert.deepEqual(route({ url: "/jobs/status/not-safe" }), { action: null });
});

test("actual stage events advance monotonically and retain richer lift metrics", () => {
  const status = initialStatus("abcdefghijklmnopqrstuvwxyz_0123456789");
  applyProgress(status, { stage: "detect", status: "done", message: "family found", metrics: { confidence: 1 } });
  applyProgress(status, { stage: "cfg", status: "done", message: "cfg recovered", metrics: { states: 41 } });
  applyProgress(status, {
    stage: "lift",
    status: "running",
    message: "lifting",
    metrics: { selected_prototypes: 3, payload_blocks: 29, normalized_blocks: 41 },
  });
  applyProgress(status, { stage: "decode", status: "done", attempt: 2, message: "trace decode", metrics: { constants: 12 } });
  assert.equal(status.current_stage, "lift");
  assert.equal(status.stages.decode.attempts, 2);
  assert.equal(status.stages.lift.metrics.selected_prototypes, 3);
  assert.equal(status.stages.lift.metrics.payload_blocks, 29);
});

test("structure_refine is a first-class stage with normalized refinement evidence", () => {
  const status = initialStatus("abcdefghijklmnopqrstuvwxyz_0123456789");
  assert.ok(STAGES.indexOf("provenance") < STAGES.indexOf("structure_refine"));
  assert.ok(STAGES.indexOf("structure_refine") < STAGES.indexOf("verify"));
  assert.deepEqual(status.stages.structure_refine, { status: "pending", attempts: 0, metrics: {} });

  applyProgress(status, { stage: "provenance", status: "done", metrics: { mapped_statements: 12 } });
  applyProgress(status, {
    stage: "structure_refine",
    status: "done",
    metrics: {
      passes: 1,
      stable_capture_cells_scalarized: 2,
      stable_capture_accesses_scalarized: 9,
      producer_aliases_coalesced: 3,
      write_only_result_packs_removed: 0,
      guard_clauses_flattened: 4,
      redundant_parentheses_removed: 7,
    },
  });

  assert.equal(status.current_stage, "structure_refine");
  assert.equal(status.stages.structure_refine.metrics.refinement_passes, 1);
  assert.equal(status.stages.structure_refine.metrics.write_only_result_packs_removed, 0);
  assert.equal(status.stages.structure_refine.metrics.redundant_parentheses_removed, 7);
});

test("status responses advertise one-second polling while work is active", () => {
  const status = initialStatus("abcdefghijklmnopqrstuvwxyz_0123456789");
  status.state = "running";
  status.stages.detect = { status: "running", attempts: 1, started_at: new Date(Date.now() - 1200).toISOString(), metrics: {} };
  const output = publicStatus(status);
  assert.equal(output.poll_after_ms, 1000);
  assert.ok(output.elapsed_ms >= 0);
  assert.ok(output.stage_elapsed_ms >= 1000);
  status.state = "completed";
  assert.equal(publicStatus(status).poll_after_ms, 0);
});

test("unlimited jobs remove the analyzer timer while retaining any platform cap", () => {
  const status = initialStatus("abcdefghijklmnopqrstuvwxyz_0123456789", { time_limit: "unlimited" });
  assert.equal(status.time_limit.mode, "unlimited");
  assert.equal(status.time_limit.seconds, null);
});

test("runtime jobs expose their own ordered execution stages", () => {
  const status = initialStatus("abcdefghijklmnopqrstuvwxyz_0123456789", {
    kind: "runtime",
    script: "return true",
    timeout: 75,
  });
  assert.equal(status.version, 2);
  assert.equal(status.kind, "runtime");
  assert.equal(status.current_stage, "compile");
  assert.deepEqual(status.stage_order, RUNTIME_STAGES);
  assert.deepEqual(Object.keys(status.stages), RUNTIME_STAGES);

  applyProgress(status, { stage: "compile", status: "done", metrics: { source_bytes: 11 } });
  applyProgress(status, { stage: "execute", status: "running", message: "executing" });
  applyProgress(status, { stage: "bootstrap", status: "done" });
  assert.equal(status.current_stage, "execute");
  assert.equal(status.stages.compile.metrics.source_bytes, 11);
  assert.equal(publicStatus(status).stage_progress.total, RUNTIME_STAGES.length);
});

test("job kinds infer old deobfuscation requests and explicit runtime requests", () => {
  assert.equal(jobKind({ source: "return true" }), "deobfuscation");
  assert.equal(jobKind({ script: "return true" }), "runtime");
  assert.equal(jobKind({ source: "return true", kind: "runtime", script: "return true" }), "runtime");
  assert.throws(() => jobKind({ kind: "unknown" }), /deobfuscation or runtime/);
});

test("runtime validation uses the site's 900,000-byte upload contract", () => {
  assert.deepEqual(validateInput("runtime", { script: "return true" }), { source: "return true", bytes: 11 });
  assert.throws(() => validateInput("runtime", { script: "" }), /script is required/);
  assert.throws(() => validateInput("runtime", { script: "x".repeat(900_001) }), /900,000 bytes/);
});

test("runtime limits are custom and retain the hosted execution ceiling", () => {
  const previous = process.env.VERCEL;
  process.env.VERCEL = "1";
  try {
    const limit = requestedLimit({ kind: "runtime", script: "return true", timeout: 999 }, "runtime");
    assert.deepEqual(limit, { mode: "custom", seconds: 280, platform_cap_seconds: 300 });
  } finally {
    if (previous == null) delete process.env.VERCEL;
    else process.env.VERCEL = previous;
  }
});

test("runtime job summaries retain blocked execution state and reason", () => {
  const result = {
    payload: {
      ok: true,
      terminationReason: "blocked",
      blockedReason: "module dependency is still pending",
      runtimeReport: { execution_state: "blocked" },
    },
  };
  assert.equal(finalMessage("runtime", result, true), "module dependency is still pending");
});
