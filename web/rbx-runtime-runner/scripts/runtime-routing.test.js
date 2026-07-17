"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  HEAVY_SOURCE_BYTES,
  LURAPH_JOB_TIMEOUT_SECONDS,
  LURAPH_MAX_STEPS,
  RUNTIME_STAGES,
  hasLuraphSignature,
  normalizeRuntimeJobInput,
  requestedTimeout,
  runtimeQueueReason,
  sourceBytes,
} = require("./runtime-routing");

test("short ordinary programs remain on the synchronous /api/run path", () => {
  assert.equal(runtimeQueueReason({ script: "return 42", timeout: 10 }), null);
  assert.equal(hasLuraphSignature("local LPH = 1; return LPH"), false);
});

test("large UTF-8 sources route by encoded byte count", () => {
  const script = `--${"é".repeat(Math.ceil(HEAVY_SOURCE_BYTES / 2))}`;
  const reason = runtimeQueueReason({ script, timeout: 10 });
  assert.equal(reason.code, "source_size");
  assert.equal(reason.bytes, sourceBytes(script));
  assert.ok(reason.bytes > HEAVY_SOURCE_BYTES);
});

test("requested runs over 50 seconds route to the runtime queue", () => {
  assert.equal(runtimeQueueReason({ script: "return true", timeout: 50 }), null);
  assert.deepEqual(runtimeQueueReason({ script: "return true", timeout: 51 }), {
    code: "requested_timeout",
    seconds: 51,
    threshold: 50,
  });
});

test("known Luraph wrapper markers route even when the source is small", () => {
  for (const script of [
    "LPH_NO_VIRTUALIZE(function() return 1 end)()",
    "-- Luraph Obfuscator\nreturn true",
    "return({decode=function(self,x) return self:LPH(x) end})",
    "return({q=function() end}):q()({})",
  ]) {
    assert.equal(runtimeQueueReason({ script, timeout: 10 }).code, "luraph_signature");
  }
});

test("queued Luraph gets the isolated long-run preset instead of UI sampling defaults", () => {
  const normalized = normalizeRuntimeJobInput({
    script: "return({q=function() end}):q()({})",
    timeout: 10,
    luraphMode: "auto",
    luraphMaxSteps: 50_000_000,
  });
  assert.equal(normalized.timeout, LURAPH_JOB_TIMEOUT_SECONDS);
  assert.equal(normalized.luraphMode, "force");
  assert.equal(normalized.luraphMaxSteps, LURAPH_MAX_STEPS);
  assert.equal(normalized.luraphStallSteps, 0);
});

test("an explicit longer Luraph timeout is retained", () => {
  const normalized = normalizeRuntimeJobInput({
    script: "-- Luraph VM\nreturn true",
    timeout: 120,
    luraphMaxSteps: 900_000_000,
  });
  assert.equal(normalized.timeout, 120);
  assert.equal(normalized.luraphMaxSteps, 900_000_000);
});

test("runtime stage order is stable and covers final report states", () => {
  assert.deepEqual(RUNTIME_STAGES, ["compile", "bootstrap", "execute", "network_wait", "steady_state", "complete"]);
});

test("hosted timeouts clamp below the function platform cap", () => {
  assert.equal(requestedTimeout({ timeout: 999 }, true), 280);
  assert.equal(requestedTimeout({ timeout: 999 }, false), 999);
  assert.equal(requestedTimeout({}, true), 10);
});
