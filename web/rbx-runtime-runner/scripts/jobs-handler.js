"use strict";

const crypto = require("crypto");
const { Readable } = require("stream");
const deobfuscate = require("./deobfuscate-handler");
const store = require("./job-store");
const {
  RUNTIME_STAGES,
  normalizeRuntimeJobInput,
  requestedTimeout,
  validateRuntimeInput,
} = require("./runtime-routing");

const SOURCE_LIMIT = 1.5 * 1024 * 1024;
const REQUEST_LIMIT = 4 * 1024 * 1024;
const DEOBFUSCATION_STAGES = Object.freeze([
  "detect",
  "decode",
  "cfg",
  "normalize",
  "guard_hotspot",
  "lift",
  "structure_flow",
  "structure_closures",
  "structure_dataflow",
  "structure_source",
  "provenance",
  "structure_refine",
  "verify",
]);
const STAGES = DEOBFUSCATION_STAGES;
const JOB_KINDS = Object.freeze(["deobfuscation", "runtime"]);

function send(res, status, value, headers = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  for (const [name, content] of Object.entries(headers)) res.setHeader(name, content);
  res.end(JSON.stringify(value));
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > REQUEST_LIMIT) {
      throw Object.assign(new Error("encoded request exceeds 4 MiB"), { status: 413, code: "request_too_large" });
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw Object.assign(new Error("invalid JSON"), { status: 400, code: "invalid_request" });
  }
}

function links(id) {
  return {
    status: `/jobs/status/${id}`,
    finished: `/jobs/finished/${id}`,
  };
}

function jobKind(input = {}, requestedKind = null) {
  const inferred = requestedKind || input.kind || (Object.prototype.hasOwnProperty.call(input, "script") ? "runtime" : "deobfuscation");
  if (!JOB_KINDS.includes(inferred)) {
    throw Object.assign(new Error("kind must be deobfuscation or runtime"), { status: 400, code: "invalid_job_kind" });
  }
  return inferred;
}

function stagesFor(kind) {
  return kind === "runtime" ? [...RUNTIME_STAGES] : [...DEOBFUSCATION_STAGES];
}

function requestedLimit(input = {}, kind = jobKind(input)) {
  if (kind === "runtime") {
    return {
      mode: "custom",
      seconds: requestedTimeout(input),
      platform_cap_seconds: process.env.VERCEL ? 300 : null,
    };
  }

  const mode = ["auto", "custom", "unlimited"].includes(input.time_limit)
    ? input.time_limit
    : (input.wall_timeout != null ? "custom" : "auto");
  const seconds = mode === "unlimited"
    ? null
    : mode === "custom"
      ? Math.max(1, Math.min(280, Number(input.wall_timeout) || 40))
      : (process.env.VERCEL ? 240 : 120);
  return { mode, seconds, platform_cap_seconds: process.env.VERCEL ? 300 : null };
}

function validateInput(kind, input = {}) {
  if (kind === "runtime") return validateRuntimeInput(input);
  const source = String(input.source || "");
  if (!source.trim()) {
    throw Object.assign(new Error("source is required"), { status: 400, code: "invalid_request" });
  }
  if (Buffer.byteLength(source) > SOURCE_LIMIT) {
    throw Object.assign(new Error("source exceeds 1.5 MiB"), { status: 413, code: "source_too_large" });
  }
  return { source, bytes: Buffer.byteLength(source) };
}

function initialStatus(id, input = {}, requestedKind = null) {
  const kind = jobKind(input, requestedKind);
  const stageOrder = stagesFor(kind);
  const now = new Date();
  return {
    version: 2,
    id,
    kind,
    state: "queued",
    current_stage: stageOrder[0],
    stage_order: stageOrder,
    message: kind === "runtime" ? "Queued for native Luau execution" : "Queued for native analysis",
    revision: 1,
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    expires_at: new Date(now.getTime() + store.JOB_TTL_MS).toISOString(),
    time_limit: requestedLimit(input, kind),
    stages: Object.fromEntries(stageOrder.map((stage) => [stage, { status: "pending", attempts: 0, metrics: {} }])),
    links: links(id),
  };
}

function progressMetrics(stage, metrics = {}) {
  const normalized = { ...metrics };
  if (stage === "structure_refine" && normalized.refinement_passes == null && normalized.passes != null) {
    const passes = Number(normalized.passes);
    if (Number.isFinite(passes) && passes >= 0) normalized.refinement_passes = passes;
  }
  return normalized;
}

function applyProgress(status, event = {}) {
  const stageOrder = Array.isArray(status.stage_order) && status.stage_order.length
    ? status.stage_order
    : Object.keys(status.stages || {});
  const stage = stageOrder.includes(event.stage) ? event.stage : status.current_stage;
  const stageIndex = stageOrder.indexOf(stage);
  const currentIndex = stageOrder.indexOf(status.current_stage);
  const now = new Date().toISOString();
  const previous = status.stages[stage] || { status: "pending", attempts: 0, metrics: {} };
  const eventStatus = ["running", "done", "failed", "skipped"].includes(event.status) ? event.status : "running";
  status.stages[stage] = {
    ...previous,
    status: eventStatus,
    attempts: Math.max(Number(previous.attempts || 0), Number(event.attempt || 1)),
    started_at: previous.started_at || now,
    completed_at: ["done", "failed", "skipped"].includes(eventStatus) ? now : null,
    message: String(event.message || previous.message || ""),
    metrics: { ...(previous.metrics || {}), ...progressMetrics(stage, event.metrics) },
  };
  if (stageIndex >= currentIndex || eventStatus === "failed") status.current_stage = stage;
  status.state = "running";
  status.message = status.stages[status.current_stage]?.message || status.message;
  return status;
}

function publicStatus(status) {
  const now = Date.now();
  const stage = status.stages?.[status.current_stage] || {};
  const stageOrder = status.stage_order || Object.keys(status.stages || {});
  const terminal = new Set(["done", "failed", "skipped"]);
  const completedStages = stageOrder.filter((name) => terminal.has(status.stages?.[name]?.status)).length;
  return {
    ...status,
    elapsed_ms: Math.max(0, now - Date.parse(status.created_at)),
    stage_elapsed_ms: stage.started_at ? Math.max(0, now - Date.parse(stage.started_at)) : 0,
    stage_progress: { completed: completedStages, total: stageOrder.length },
    poll_after_ms: ["queued", "running"].includes(status.state) ? 1000 : 0,
  };
}

function invokeHandler(handler, input, configureRequest) {
  return new Promise((resolve, reject) => {
    const req = Readable.from([Buffer.from(JSON.stringify(input))]);
    req.method = "POST";
    configureRequest?.(req);
    const headers = new Map();
    const res = {
      statusCode: 200,
      setHeader(name, value) { headers.set(String(name).toLowerCase(), value); },
      end(body) {
        try {
          resolve({ statusCode: this.statusCode, headers, payload: JSON.parse(String(body || "{}")) });
        } catch (error) {
          reject(error);
        }
      },
    };
    Promise.resolve(handler(req, res)).catch(reject);
  });
}

function invokeAnalyzer(input, analysisProgress) {
  return invokeHandler(deobfuscate, input, (req) => {
    req.analysisProgress = analysisProgress;
  });
}

function invokeRuntime(input, runtimeProgress) {
  // Lazy loading avoids a cycle: /api/run delegates heavy workloads back to
  // this module, while an internal runtime job calls /api/run exactly once.
  const runtime = require("../api/run");
  return invokeHandler(runtime, input, (req) => {
    req.runtimeJob = true;
    req.runtimeProgress = runtimeProgress;
  });
}

function finalMessage(kind, result, succeeded) {
  if (kind === "deobfuscation") {
    return succeeded ? "Analysis complete" : (result.payload?.error?.message || "Analysis failed");
  }
  if (!succeeded) return result.payload?.error?.message || "Runtime worker failed";
  if (result.payload?.terminationReason === "network_required") return "Network approval required";
  if (result.payload?.terminationReason === "instruction_budget") return "VM instruction budget exhausted";
  if (result.payload?.terminationReason === "blocked" || result.payload?.runtimeReport?.execution_state === "blocked") {
    return result.payload?.blockedReason || "Runtime execution is blocked";
  }
  if (result.payload?.terminationReason === "virtual_budget" || result.payload?.runtimeReport?.execution_state === "steady_state") {
    return "Runtime reached a healthy steady state";
  }
  return result.payload?.ok ? "Runtime complete" : "Runtime finished with diagnostics";
}

async function runJob(id, input, kind) {
  try {
    await store.updateStatus(id, (status) => {
      status.state = "running";
      status.message = kind === "runtime" ? "Waiting for an isolated runtime slot" : "Starting native analysis";
      status.started_at = new Date().toISOString();
      return status;
    });

    const onProgress = async (event) => {
      await store.updateStatus(id, (status) => applyProgress(status, event));
    };
    const result = kind === "runtime"
      ? await invokeRuntime(input, onProgress)
      : await invokeAnalyzer(input, onProgress);
    const completedAt = new Date().toISOString();
    const current = await store.getStatus(id);
    const transportOk = result.statusCode >= 200 && result.statusCode < 300;
    const succeeded = kind === "runtime" ? transportOk : (transportOk && result.payload?.ok === true);
    const finalStatus = current || initialStatus(id, input, kind);
    finalStatus.state = succeeded ? "completed" : "failed";
    finalStatus.message = finalMessage(kind, result, succeeded);
    finalStatus.completed_at = completedAt;
    finalStatus.updated_at = completedAt;
    finalStatus.revision = Number(finalStatus.revision || 0) + 1;
    finalStatus.result_status = kind === "runtime"
      ? (result.payload?.runtimeReport?.execution_state || result.payload?.terminationReason || null)
      : (result.payload?.status || null);

    if (kind === "runtime" && succeeded && finalStatus.stages.complete?.status === "pending") {
      finalStatus.stages.complete = {
        ...finalStatus.stages.complete,
        status: "done",
        attempts: 1,
        started_at: completedAt,
        completed_at: completedAt,
        message: finalStatus.message,
        metrics: {},
      };
      finalStatus.current_stage = "complete";
    }

    for (const stage of finalStatus.stage_order) {
      if (finalStatus.stages[stage].status === "pending") {
        finalStatus.stages[stage] = {
          ...finalStatus.stages[stage],
          status: "skipped",
          completed_at: completedAt,
          message: succeeded ? "Not required for this workload" : "Not reached",
        };
      }
    }
    await store.finish(id, result.payload, finalStatus);
  } catch (error) {
    const failed = await store.updateStatus(id, (status) => {
      status.state = "failed";
      status.message = status.kind === "runtime" ? "Runtime worker failed" : "Analysis worker failed";
      status.completed_at = new Date().toISOString();
      status.error = { code: error.code || "job_failed", message: status.message };
      const active = status.stages[status.current_stage];
      if (active) active.status = "failed";
      return status;
    });
    if (failed) {
      await store.finish(id, {
        ok: false,
        error: { code: error.code || "job_failed", message: failed.message },
      }, failed);
    } else {
      await store.removeRequest(id);
    }
  }
}

function schedule(promise) {
  if (process.env.VERCEL) {
    try {
      const { waitUntil } = require("@vercel/functions");
      waitUntil(promise);
      return;
    } catch {
      // The guarded job promise records the worker failure in durable status.
    }
  }
  promise.catch(() => {});
}

async function enqueue(requestedKind, input = {}) {
  const kind = jobKind(input, requestedKind);
  validateInput(kind, input);
  const normalizedInput = kind === "runtime" ? normalizeRuntimeJobInput(input) : input;
  const normalized = { ...normalizedInput, kind };
  const id = crypto.randomBytes(24).toString("base64url");
  const status = initialStatus(id, normalized, kind);
  await store.create(id, normalized, status);
  schedule(runJob(id, normalized, kind));
  return {
    ok: true,
    id,
    kind,
    state: "queued",
    poll_after_ms: 1000,
    time_limit: status.time_limit,
    links: links(id),
  };
}

function route(req) {
  const parsed = new URL(req.url || "/", "http://localhost");
  const path = parsed.pathname;
  if (path === "/jobs/create" || (path === "/api/jobs" && parsed.searchParams.get("action") === "create")) return { action: "create" };
  const match = path.match(/^\/jobs\/(status|finished)\/([A-Za-z0-9_-]{20,80})$/);
  if (match) return { action: match[1], id: match[2] };
  if (path === "/api/jobs") {
    const action = parsed.searchParams.get("action");
    const id = parsed.searchParams.get("id");
    if (["status", "finished"].includes(action) && /^[A-Za-z0-9_-]{20,80}$/.test(id || "")) return { action, id };
  }
  return { action: null };
}

async function jobs(req, res) {
  const selected = route(req);
  try {
    if (selected.action === "create") {
      if (req.method !== "POST") return send(res, 405, { ok: false, error: { code: "method_not_allowed" } });
      const input = await readJson(req);
      const created = await enqueue(jobKind(input), input);
      return send(res, 202, created, { "Retry-After": "1" });
    }

    if (selected.action === "status") {
      if (req.method !== "GET") return send(res, 405, { ok: false, error: { code: "method_not_allowed" } });
      const status = await store.getStatus(selected.id);
      if (!status) return send(res, 404, { ok: false, error: { code: "job_not_found", message: "Job was not found or has expired." } });
      if (Date.parse(status.expires_at) <= Date.now()) {
        await store.expire(selected.id);
        return send(res, 410, { ok: false, error: { code: "job_expired", message: "Job has expired." } });
      }
      return send(res, 200, { ok: true, job: publicStatus(status) }, { "Retry-After": "1" });
    }

    if (selected.action === "finished") {
      if (req.method !== "GET") return send(res, 405, { ok: false, error: { code: "method_not_allowed" } });
      const status = await store.getStatus(selected.id);
      if (!status) return send(res, 404, { ok: false, error: { code: "job_not_found", message: "Job was not found or has expired." } });
      if (status.state === "queued" || status.state === "running") {
        return send(res, 409, { ok: false, error: { code: "job_not_finished", message: "Job is still running." }, job: publicStatus(status) }, { "Retry-After": "1" });
      }
      const result = await store.getResult(selected.id);
      if (!result) return send(res, 503, { ok: false, error: { code: "job_result_unavailable", message: "Finished result is unavailable." } });
      return send(res, status.state === "completed" ? 200 : 422, result);
    }

    return send(res, 404, { ok: false, error: { code: "route_not_found" } });
  } catch (error) {
    const known = Number.isInteger(error.status) && typeof error.code === "string";
    return send(res, known ? error.status : 503, {
      ok: false,
      error: { code: known ? error.code : "jobs_unavailable", message: known ? error.message : "Job service is unavailable." },
    });
  }
}

module.exports = jobs;
module.exports.enqueue = enqueue;
module.exports._test = {
  DEOBFUSCATION_STAGES,
  JOB_KINDS,
  RUNTIME_STAGES,
  STAGES,
  applyProgress,
  finalMessage,
  initialStatus,
  jobKind,
  publicStatus,
  requestedLimit,
  route,
  stagesFor,
  validateInput,
};
