"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  buildArgs,
  dependencyRequirementsFromReport,
  networkRequirementsFromTrace,
  normalizeScenario,
  terminationReasonFor,
} = require("../api/run")._test;

function argsFor(payload = {}) {
  return buildArgs(payload, "input.luau", "captures", "trace.jsonl", "", "report.json");
}

test("scenario v2 keeps ModuleScript source in the privileged sidecar", () => {
  const encoded = normalizeScenario({
    version: 2,
    instances: [{ id: "module", class: "ModuleScript", name: "Module", parent: "ReplicatedStorage" }],
    module_sources: { module: "return false" },
  });
  const scenario = JSON.parse(encoded);
  assert.equal(scenario.module_sources.module, "return false");
  assert.equal(Object.hasOwn(scenario.instances[0], "source"), false);
  assert.throws(() => normalizeScenario({
    version: 2,
    instances: [{ id: "module", class: "ModuleScript", source: "return true" }],
  }), /source belongs in module_sources/);
});

test("legacy scenario v1 remains loadable during schema migration", () => {
  const encoded = normalizeScenario({
    version: 1,
    instances: [{ id: "module", class: "ModuleScript", source: "return true" }],
  });
  assert.equal(JSON.parse(encoded).version, 1);
});

test("web runtime arguments carry release-729 execution controls", () => {
  const args = argsFor({
    profile: "executor-client",
    executionMode: "diagnostic",
    memoryLimitMb: 256,
    deterministicSeed: 42,
    executorPreset: "opiumware",
    filesystem: "memory",
    registerOverflow: "spill",
  });
  assert.deepEqual(args.slice(args.indexOf("--execution-mode"), args.indexOf("--execution-mode") + 2), ["--execution-mode", "diagnostic"]);
  assert.ok(args.includes("--memory-limit-mb"));
  assert.ok(args.includes("--deterministic-seed"));
  assert.ok(args.includes("--executor-preset"));
  assert.ok(args.includes("--filesystem"));
  assert.deepEqual(args.slice(args.indexOf("--register-overflow"), args.indexOf("--register-overflow") + 2), ["--register-overflow", "spill"]);
  assert.deepEqual(args.slice(args.indexOf("--luraph-max-steps"), args.indexOf("--luraph-max-steps") + 2), ["--luraph-max-steps", "2000000000"]);
  assert.deepEqual(args.slice(args.indexOf("--luraph-stall-steps"), args.indexOf("--luraph-stall-steps") + 2), ["--luraph-stall-steps", "0"]);
});

test("faithful website runs fail closed against analysis-hook overrides", () => {
  const args = argsFor({
    executionMode: "faithful",
    analysisHooks: "on",
    captureStringHooks: true,
    tracePcallErrors: true,
  });
  const hookIndex = args.indexOf("--analysis-hooks");
  assert.equal(args[hookIndex + 1], "off");
  assert.ok(args.includes("--no-capture-string-hooks"));
  assert.equal(args.includes("--capture-string-hooks"), false);
  assert.equal(args.includes("--trace-pcall-errors"), false);
});

test("pcall diagnostics are available only in diagnostic mode", () => {
  const args = argsFor({ executionMode: "diagnostic", tracePcallErrors: true });
  assert.ok(args.includes("--trace-pcall-errors"));
});

test("hosted requests can never enable private-network CLI access", () => {
  const previousVercel = process.env.VERCEL;
  const previousLocal = process.env.RBX_RUNTIME_ALLOW_PRIVATE_NETWORK;
  process.env.VERCEL = "1";
  process.env.RBX_RUNTIME_ALLOW_PRIVATE_NETWORK = "1";
  try {
    assert.equal(argsFor({ allowPrivateNetwork: true }).includes("--allow-private-network"), false);
  } finally {
    if (previousVercel == null) delete process.env.VERCEL;
    else process.env.VERCEL = previousVercel;
    if (previousLocal == null) delete process.env.RBX_RUNTIME_ALLOW_PRIVATE_NETWORK;
    else process.env.RBX_RUNTIME_ALLOW_PRIVATE_NETWORK = previousLocal;
  }
});

test("private-network access is an explicit local operator setting, not a request field", () => {
  const previousVercel = process.env.VERCEL;
  const previousLocal = process.env.RBX_RUNTIME_ALLOW_PRIVATE_NETWORK;
  delete process.env.VERCEL;
  try {
    delete process.env.RBX_RUNTIME_ALLOW_PRIVATE_NETWORK;
    assert.equal(argsFor({ allowPrivateNetwork: true }).includes("--allow-private-network"), false);
    process.env.RBX_RUNTIME_ALLOW_PRIVATE_NETWORK = "1";
    assert.equal(argsFor({}).includes("--allow-private-network"), true);
  } finally {
    if (previousVercel == null) delete process.env.VERCEL;
    else process.env.VERCEL = previousVercel;
    if (previousLocal == null) delete process.env.RBX_RUNTIME_ALLOW_PRIVATE_NETWORK;
    else process.env.RBX_RUNTIME_ALLOW_PRIVATE_NETWORK = previousLocal;
  }
});

test("a zero-exit blocked runtime report does not fall through to completed", () => {
  const runtimeReport = {
    status: "blocked",
    execution_state: "blocked",
    termination_reason: "completed",
    blocked_reason: "module dependency is still pending",
    dependency_requirements: [{
      kind: "runtime_api",
      name: "Workspace.StreamingTargetRadius",
      reason: "unsupported",
      required: true,
    }],
  };
  const terminationReason = terminationReasonFor({
    code: 0,
    signal: null,
    stdout: "",
    stderr: "",
    runtimeReport,
    networkRequirements: [],
  });
  assert.equal(terminationReason, "blocked");
  assert.deepEqual(dependencyRequirementsFromReport(runtimeReport), runtimeReport.dependency_requirements);
});

test("network approval remains the actionable reason for a blocked runtime", () => {
  const runtimeReport = {
    status: "blocked",
    execution_state: "blocked",
    termination_reason: "blocked",
    network_requirements: [{ host: "assets.example.test", url: "https://assets.example.test/payload" }],
    dependency_requirements: [{
      kind: "network_host",
      name: "assets.example.test",
      url: "https://assets.example.test/payload",
      reason: "network_policy",
      required: true,
    }],
  };
  const networkRequirements = networkRequirementsFromTrace([], runtimeReport);
  assert.equal(terminationReasonFor({
    code: 0,
    signal: null,
    stdout: "",
    stderr: "",
    runtimeReport,
    networkRequirements,
  }), "network_required");
  assert.deepEqual(networkRequirements, [{
    host: "assets.example.test",
    url: "https://assets.example.test/payload",
    policy: "allowlist",
  }]);
  assert.deepEqual(dependencyRequirementsFromReport(runtimeReport), runtimeReport.dependency_requirements);
});

test("instruction-budget failure keeps its native termination reason", () => {
  const runtimeReport = {
    status: "instruction_budget",
    execution_state: "failed",
    termination_reason: "instruction_budget",
    error: "instruction safepoint budget exhausted after 2000000 steps",
  };
  assert.equal(terminationReasonFor({
    code: 1,
    signal: null,
    stdout: "",
    stderr: "",
    runtimeReport,
    networkRequirements: [],
  }), "instruction_budget");
});
