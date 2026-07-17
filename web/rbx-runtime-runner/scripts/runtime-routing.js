"use strict";

const HEAVY_SOURCE_BYTES = 250 * 1024;
const MAX_RUNTIME_SOURCE_BYTES = 900_000;
const SYNC_TIMEOUT_SECONDS = 50;
const HOSTED_TIMEOUT_SECONDS = 280;
const LOCAL_TIMEOUT_SECONDS = 60 * 60;
const DEFAULT_RUNTIME_TIMEOUT_SECONDS = 10;
const LURAPH_JOB_TIMEOUT_SECONDS = 280;
const LURAPH_MAX_STEPS = 2_000_000_000;

const RUNTIME_STAGES = Object.freeze([
  "compile",
  "bootstrap",
  "execute",
  "network_wait",
  "steady_state",
  "complete",
]);

// These are public wrapper markers, not a claim that an arbitrary minified
// script is Luraph. Large inputs are independently routed by byte size.
const LURAPH_MARKERS = Object.freeze([
  /\bLPH_(?:NO_)?VIRTUALIZE\b/,
  /\bLPH_NO_UPVALUES\b/,
  /\bLuraph(?:Devirtualizer|Obfuscator|VM)?\b/i,
  /:LPH(?:[^A-Za-z0-9_]|$)/,
  /\):[dq]\(\)\(/,
]);

function sourceBytes(source) {
  return Buffer.byteLength(String(source || ""), "utf8");
}

function hasLuraphSignature(source) {
  const text = String(source || "");
  return LURAPH_MARKERS.some((pattern) => pattern.test(text));
}

function requestedTimeout(input = {}, hosted = Boolean(process.env.VERCEL)) {
  const parsed = Number(input.timeout);
  const fallback = DEFAULT_RUNTIME_TIMEOUT_SECONDS;
  const maximum = hosted ? HOSTED_TIMEOUT_SECONDS : LOCAL_TIMEOUT_SECONDS;
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(1, Math.min(maximum, parsed));
}

function runtimeQueueReason(input = {}) {
  const source = String(input.script || "");
  const bytes = sourceBytes(source);
  if (bytes > HEAVY_SOURCE_BYTES) return { code: "source_size", bytes, threshold: HEAVY_SOURCE_BYTES };
  if (Number(input.timeout) > SYNC_TIMEOUT_SECONDS) {
    return { code: "requested_timeout", seconds: Number(input.timeout), threshold: SYNC_TIMEOUT_SECONDS };
  }
  if (hasLuraphSignature(source)) return { code: "luraph_signature", bytes };
  return null;
}

function normalizeRuntimeJobInput(input = {}) {
  const normalized = { ...input };
  const reason = runtimeQueueReason(normalized);
  if (!reason) return normalized;

  const source = String(normalized.script || "");
  const luraph = hasLuraphSignature(source) || String(normalized.luraphMode || "auto") === "force";
  const requestedSeconds = Number(normalized.timeout);
  if ((luraph || reason.code === "source_size") &&
      (!Number.isFinite(requestedSeconds) || requestedSeconds <= DEFAULT_RUNTIME_TIMEOUT_SECONDS)) {
    normalized.timeout = LURAPH_JOB_TIMEOUT_SECONDS;
  }

  if (luraph) {
    normalized.luraphMode = "force";
    const requestedSteps = Number(normalized.luraphMaxSteps);
    if (!Number.isFinite(requestedSteps) || requestedSteps <= 50_000_000) {
      normalized.luraphMaxSteps = LURAPH_MAX_STEPS;
    }
    if (normalized.luraphStallSteps == null) normalized.luraphStallSteps = 0;
  }
  return normalized;
}

function validateRuntimeInput(input = {}) {
  const source = String(input.script || "");
  const bytes = sourceBytes(source);
  if (!source.trim()) {
    throw Object.assign(new Error("script is required"), { status: 400, code: "invalid_request" });
  }
  if (bytes > MAX_RUNTIME_SOURCE_BYTES) {
    throw Object.assign(new Error("script exceeds 900,000 bytes"), { status: 413, code: "source_too_large" });
  }
  return { source, bytes };
}

module.exports = {
  HEAVY_SOURCE_BYTES,
  DEFAULT_RUNTIME_TIMEOUT_SECONDS,
  HOSTED_TIMEOUT_SECONDS,
  LURAPH_JOB_TIMEOUT_SECONDS,
  LURAPH_MAX_STEPS,
  LOCAL_TIMEOUT_SECONDS,
  MAX_RUNTIME_SOURCE_BYTES,
  RUNTIME_STAGES,
  SYNC_TIMEOUT_SECONDS,
  hasLuraphSignature,
  normalizeRuntimeJobInput,
  requestedTimeout,
  runtimeQueueReason,
  sourceBytes,
  validateRuntimeInput,
};
