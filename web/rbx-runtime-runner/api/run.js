const fs = require("fs");
const crypto = require("crypto");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const {
  HOSTED_TIMEOUT_SECONDS,
  LOCAL_TIMEOUT_SECONDS,
  runtimeQueueReason,
  validateRuntimeInput,
} = require("../scripts/runtime-routing");

const MAX_SOURCE_BYTES = 900_000;
const MAX_INLINE_BYTES = 180_000;
const MAX_DOWNLOAD_FILE_BYTES = 1_500_000;
const MAX_DOWNLOAD_TOTAL_BYTES = 2_000_000;
const MAX_FILES = 48;
const MAX_SCENARIO_BYTES = 256_000;
const MAX_PROCESS_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAX_CONCURRENT_JOBS = 2;
const MAX_REQUEST_BYTES = MAX_SOURCE_BYTES + MAX_SCENARIO_BYTES + 100_000;
const WYN_SAMPLE_SHA256 = "fc2bb21e1bc0c8cd50c9e5938a1afe5fcd2d7c5aa6e06698fac44e57486f717f";

let activeJobs = 0;
const jobSlotWaiters = [];

function acquireJobSlot(waitForSlot) {
  if (activeJobs < MAX_CONCURRENT_JOBS) {
    activeJobs += 1;
    return Promise.resolve(true);
  }
  if (!waitForSlot) return Promise.resolve(false);
  return new Promise((resolve) => jobSlotWaiters.push(resolve));
}

function releaseJobSlot() {
  const next = jobSlotWaiters.shift();
  if (next) next(true);
  else activeJobs = Math.max(0, activeJobs - 1);
}

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    let receivedBytes = 0;
    let rejected = false;
    req.on("data", (chunk) => {
      if (rejected) return;
      receivedBytes += chunk.length;
      if (receivedBytes > MAX_REQUEST_BYTES) {
        rejected = true;
        data = "";
        const error = new Error("request too large");
        error.statusCode = 413;
        reject(error);
        return;
      }
      data += chunk;
    });
    req.on("end", () => {
      if (rejected) return;
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function bool(value, fallback = false) {
  return typeof value === "boolean" ? value : fallback;
}

function oneOf(value, allowed, fallback) {
  const text = String(value ?? fallback);
  return allowed.includes(text) ? text : fallback;
}

function numberIn(value, min, max, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

function intText(value, min, max, fallback) {
  return String(Math.floor(numberIn(value, min, max, fallback)));
}

function safeName(name) {
  const base = path.basename(String(name || "script.luau")).replace(/[^A-Za-z0-9_.-]/g, "_");
  return base.endsWith(".lua") || base.endsWith(".luau") || base.endsWith(".txt") ? base : `${base}.luau`;
}

function prepareRuntimeSource(source) {
  // The runtime hashes and executes the submitted bytes. Trimming trailing
  // whitespace or appending a newline can break protected loaders and makes
  // release-pinned subject reports unverifiable.
  return String(source ?? "");
}

function candidateBinaries() {
  const explicit = process.env.RBX_RUNTIME_BINARY;
  const candidates = [];
  if (explicit) candidates.push(explicit);
  if (process.platform === "linux" && process.arch === "x64") {
    candidates.push(
      path.join(process.cwd(), "bin", "rbx_luau_runtime-linux-x64"),
      path.join(__dirname, "..", "bin", "rbx_luau_runtime-linux-x64"),
      path.join(__dirname, "..", "bin", "rbx_luau_runtime")
    );
  }
  if (process.platform === "darwin") {
    candidates.push(
      path.resolve(process.cwd(), "..", "..", "build", "rbx_luau_runtime"),
      path.resolve(__dirname, "..", "..", "..", "build", "rbx_luau_runtime"),
      path.resolve(__dirname, "..", "..", "..", "outputs", "rbx_luau_runtime_macos_arm64")
    );
  }
  return candidates;
}

function findBinary() {
  for (const file of candidateBinaries()) {
    try {
      fs.accessSync(file, fs.constants.X_OK);
      return file;
    } catch {}
  }
  return "";
}

function normalizeHosts(value) {
  const raw = Array.isArray(value) ? value.join("\n") : String(value || "");
  return raw
    .split(/[\s,]+/)
    .map((x) => x.trim().toLowerCase())
    .filter((x) => /^[a-z0-9_.:-]+$/.test(x))
    .slice(0, 32);
}

function inferredCompatibilityScenario(source, profile) {
  if (profile !== "executor-client") return null;
  const sha256 = crypto.createHash("sha256").update(source).digest("hex");
  if (sha256 !== WYN_SAMPLE_SHA256) return null;
  return {
    version: 2,
    instances: [
      { id: "shared", class: "Folder", name: "Shared", parent: "ReplicatedStorage" },
      { id: "packages", class: "Folder", name: "Packages", parent: "shared" },
      {
        id: "networker", class: "ModuleScript", name: "Networker", parent: "packages",
      },
      { id: "core_objects", class: "Folder", name: "CoreObjects", parent: "Workspace" },
      { id: "plots", class: "Folder", name: "Plots", parent: "Workspace" },
      { id: "eggs", class: "Folder", name: "Eggs", parent: "Workspace" },
    ],
    module_sources: {
      networker: "local proxy; proxy = setmetatable({}, { __index = function() return proxy end, __call = function() return nil end, __tostring = function() return 'Networker' end }); return proxy",
    },
    http_fixtures: {},
    remote_fixtures: {},
    scheduled_events: [],
  };
}

function normalizeScenario(value, source, profile) {
  if (value == null || value === "") return null;
  let scenario = value;
  if (typeof scenario === "string") {
    if (!scenario.trim()) return null;
    scenario = JSON.parse(scenario);
  }
  if (!scenario || typeof scenario !== "object" || Array.isArray(scenario) || ![1, 2].includes(scenario.version)) {
    throw new Error("scenario must be a JSON object with version 1 or 2");
  }
  if ((scenario.instances || []).length > 5000) throw new Error("scenario has too many instances");
  if ((scenario.scheduled_events || []).length > 5000) throw new Error("scenario has too many scheduled events");
  if (scenario.version === 2) {
    if ((scenario.instances || []).some((instance) => instance && Object.prototype.hasOwnProperty.call(instance, "source"))) {
      throw new Error("scenario v2 ModuleScript source belongs in module_sources, not instances");
    }
    if (Object.keys(scenario.module_sources || {}).length > 1000) throw new Error("scenario has too many module sources");
    if ((scenario.player_lifecycle || []).length > 5000) throw new Error("scenario has too many player lifecycle events");
    if ((scenario.input_events || []).length > 5000) throw new Error("scenario has too many input events");
    if (Object.keys(scenario.filesystem || {}).length > 1000) throw new Error("scenario has too many filesystem fixtures");
  }
  const encoded = JSON.stringify(scenario);
  if (Buffer.byteLength(encoded) > MAX_SCENARIO_BYTES) throw new Error("scenario exceeds 256 KiB");
  return encoded;
}

function readTextMaybe(file, limit = MAX_INLINE_BYTES) {
  const stat = fs.statSync(file);
  const bytes = stat.size;
  const fd = fs.openSync(file, "r");
  try {
    const size = Math.min(bytes, limit);
    const buf = Buffer.alloc(size);
    fs.readSync(fd, buf, 0, size, 0);
    return {
      bytes,
      preview: buf.toString("utf8"),
      truncated: bytes > limit
    };
  } finally {
    fs.closeSync(fd);
  }
}

function parseJsonLines(file, limit = 200) {
  try {
    const text = fs.readFileSync(file, "utf8");
    return text
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(0, limit)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return { raw: line };
        }
      });
  } catch {
    return [];
  }
}

function redactRuntimeText(value, temporaryDir) {
  let text = String(value || "");
  if (temporaryDir) {
    const withSeparator = temporaryDir.endsWith(path.sep) ? temporaryDir : `${temporaryDir}${path.sep}`;
    text = text.split(withSeparator).join("");
    text = text.split(temporaryDir).join("<runtime>");
  }
  text = text.split("/var/task/bin/rbx_luau_runtime-linux-x64").join("rbx_luau_runtime");
  text = text.split("/lib64/libcurl.so.4").join("libcurl.so.4");
  return text;
}

function redactRuntimeValue(value, temporaryDir) {
  if (typeof value === "string") return redactRuntimeText(value, temporaryDir);
  if (Array.isArray(value)) return value.map((item) => redactRuntimeValue(item, temporaryDir));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redactRuntimeValue(item, temporaryDir)]));
  }
  return value;
}

function collectFiles(dir) {
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }

  const files = [];
  const downloadsByHash = new Map();
  let downloadBytes = 0;
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const file = path.join(dir, entry.name);
    const stat = fs.statSync(file);
    if (entry.name === "capture_index.jsonl" || entry.name === "compat_trace.jsonl") continue;
    const data = readTextMaybe(file);
    const result = {
      name: entry.name,
      bytes: stat.size,
      preview: data.preview,
      truncated: data.truncated
    };
    if (/\.(?:lua|luau)$/i.test(entry.name) && stat.size <= MAX_DOWNLOAD_FILE_BYTES) {
      const content = fs.readFileSync(file);
      const sha256 = crypto.createHash("sha256").update(content).digest("hex");
      result.sha256 = sha256;
      if (downloadsByHash.has(sha256)) {
        result.downloadRef = downloadsByHash.get(sha256);
      } else if (downloadBytes + content.length <= MAX_DOWNLOAD_TOTAL_BYTES) {
        result.downloadBase64 = content.toString("base64");
        downloadsByHash.set(sha256, entry.name);
        downloadBytes += content.length;
      }
    }
    files.push(result);
    if (files.length >= MAX_FILES) break;
  }
  return files;
}

function splitLoaderWarnings(stderr) {
  const warnings = [];
  const kept = [];
  for (const line of String(stderr || "").split(/\r?\n/)) {
    if (!line) continue;
    if (/libcurl\.so\.4: no version information available/.test(line)) {
      if (!warnings.includes("Host libcurl version metadata is unavailable; ABI loading succeeded.")) {
        warnings.push("Host libcurl version metadata is unavailable; ABI loading succeeded.");
      }
    } else {
      kept.push(line);
    }
  }
  return {
    stderr: kept.join("\n") + (kept.length ? "\n" : ""),
    runtimeWarnings: warnings
  };
}

function firstFile(files, namePrefix) {
  return (files || []).find((file) => String(file.name || "").startsWith(namePrefix));
}

function oneLinePreview(value, limit = 360) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, limit);
}

function pushUnique(list, value) {
  if (value && !list.includes(value)) list.push(value);
}

function hasObfuscatorNilTrap(source) {
  const text = String(source || "");
  return /Protected by wYnFuscate/i.test(text) ||
    /local\s+[_A-Za-z][_A-Za-z0-9]*\s*=\s*nil\s+return\s+[_A-Za-z][_A-Za-z0-9]*\s*\(/.test(text) ||
    /type\s*\([^)]*\)\s*~=\s*["']function["'][\s\S]{0,220}return\s+[_A-Za-z][_A-Za-z0-9]*\s*\(/.test(text);
}

function hasProtectedVmShape(source) {
  const text = String(source || "");
  return /Protected by wYnFuscate/i.test(text) ||
    /local\s+[_A-Za-z][_A-Za-z0-9]*\s*=\s*setmetatable\s*\(/.test(text) ||
    /local\s+[_A-Za-z][_A-Za-z0-9]*\s*=\s*\[=\[/.test(text) ||
    /for\s+[_A-Za-z][_A-Za-z0-9]*\s*=\s*1\s*,\s*#[_A-Za-z][_A-Za-z0-9]*/.test(text);
}

function missingGlobalsFromTrace(compatTrace) {
  return [...new Set((compatTrace || [])
    .filter((entry) => entry && entry.kind === "missing_global" && entry.name)
    .map((entry) => String(entry.name)))];
}

function networkRequirementsFromTrace(compatTrace, runtimeReport) {
  const seen = new Set();
  const requirements = [];
  const candidates = [
    ...((runtimeReport && runtimeReport.network_requirements) || []),
    ...(compatTrace || []).filter((entry) => entry && entry.kind === "network_blocked").map((entry) => ({
      host: entry.host,
      url: entry.name
    }))
  ];
  for (const entry of candidates) {
    const host = String(entry?.host || "").toLowerCase();
    const url = String(entry?.url || "");
    if (!/^[a-z0-9_.:-]+$/.test(host) || !/^https?:\/\//i.test(url)) continue;
    const key = `${host}\n${url}`;
    if (seen.has(key)) continue;
    seen.add(key);
    requirements.push({
      host,
      url,
      policy: "allowlist"
    });
  }
  return requirements.slice(0, 8);
}

function dependencyRequirementsFromReport(runtimeReport) {
  if (!Array.isArray(runtimeReport?.dependency_requirements)) return [];
  return runtimeReport.dependency_requirements
    .filter((entry) => entry && typeof entry === "object" && !Array.isArray(entry))
    .map((entry) => ({ ...entry }))
    .slice(0, 64);
}

function remoteHttpFailureFromTrace(compatTrace) {
  const events = (compatTrace || []).filter((entry) =>
    entry && entry.kind === "network_response" && Number(entry.status) >= 400
  );
  const event = events[events.length - 1];
  if (!event) return null;
  let host = "remote host";
  try {
    host = new URL(String(event.name || "")).hostname || host;
  } catch {}
  return {
    host,
    status: Number(event.status),
    url: String(event.name || "")
  };
}

function terminationReasonFor({ code, signal, stdout, stderr, runtimeReport, networkRequirements }) {
  const combined = `${stdout || ""}\n${stderr || ""}`;
  if (networkRequirements.length) return "network_required";
  if (signal === "SIGKILL" || /execution timed out|max steps exceeded/i.test(combined)) return "wall_timeout";

  const nativeReason = String(runtimeReport?.termination_reason || "");
  if (runtimeReport?.execution_state === "blocked" || runtimeReport?.status === "blocked") {
    return nativeReason === "network_required" ? "network_required" : "blocked";
  }
  if ([
    "blocked",
    "completed",
    "instruction_budget",
    "memory_limit",
    "network_required",
    "output_limit",
    "runtime_error",
    "virtual_budget",
    "wall_timeout",
  ].includes(nativeReason)) {
    return nativeReason;
  }
  if (runtimeReport?.scheduler?.stop_reason === "virtual_budget") return "virtual_budget";
  return code === 0 ? "completed" : "runtime_error";
}

function buildDiagnostics({ code, signal, stdout, stderr, files, ownerRefusal, luraphReport, compatTrace, source, networkRequirements, terminationReason }) {
  const diagnostics = [];
  const combined = `${stdout || ""}\n${stderr || ""}`;
  const remoteHttpFailure = remoteHttpFailureFromTrace(compatTrace);
  if (ownerRefusal) {
    pushUnique(diagnostics, "Owner-protected script was refused before execution.");
  }
  if (signal === "SIGKILL") {
    pushUnique(diagnostics, "Runtime process was killed by the web timeout.");
  }

  const loadErr = firstFile(files, "loadstring_compile_error");
  if (loadErr) {
    const preview = oneLinePreview(loadErr.preview);
    pushUnique(
      diagnostics,
      preview
        ? `loadstring returned nil because the generated/fetched code did not compile: ${preview}`
        : "loadstring returned nil because the generated/fetched code did not compile. Open loadstring_compile_error for details."
    );
  }

  if (networkRequirements.length) {
    pushUnique(diagnostics, `Network approval is required for ${networkRequirements[0].host}.`);
  } else if (remoteHttpFailure) {
    pushUnique(
      diagnostics,
      `The approved request reached ${remoteHttpFailure.host}, but that service returned HTTP ${remoteHttpFailure.status}. This is a remote-service denial, not a runner timeout.`
    );
  } else if (/(?:HttpGet|HttpPost|RequestAsync) failed:/i.test(combined)) {
    const err = oneLinePreview((combined.match(/(?:HttpGet|HttpPost|RequestAsync) failed:[^\n]+/) || [])[0]);
    pushUnique(diagnostics, err || "The script's network request failed.");
  }

  if (/attempt to call a boolean value/.test(combined)) {
    const missingGlobals = missingGlobalsFromTrace(compatTrace);
    if (missingGlobals.length) {
      pushUnique(diagnostics, `A boolean-call happened after missing runtime globals were observed: ${missingGlobals.slice(0, 8).join(", ")}.`);
    } else if (hasProtectedVmShape(source)) {
      pushUnique(diagnostics, "The boolean-call is coming from inside the protected VM/guard path. No loadstring compile error or missing runtime global was recorded.");
    } else {
      pushUnique(diagnostics, "The script tried to call true/false as a function. This usually means an environment check, hook, or expected function returned a boolean.");
    }
    if (firstFile(files, "pcall_error_snapshot")) {
      pushUnique(diagnostics, "Open pcall_error_snapshot for the protected-call stack and captured locals.");
    }
  }

  if (/attempt to call a nil value/.test(combined)) {
    const missingGlobals = missingGlobalsFromTrace(compatTrace);
    const nilTrap = !loadErr && !missingGlobals.length && hasObfuscatorNilTrap(source);
    if (missingGlobals.length) {
      pushUnique(diagnostics, `The nil-call happened after missing runtime globals were observed: ${missingGlobals.slice(0, 8).join(", ")}.`);
    } else if (nilTrap) {
      pushUnique(diagnostics, "The nil-call is coming from an obfuscator anti-tamper/decoy path inside the protected VM. No loadstring compile error or missing runtime global was recorded.");
    }

    if (loadErr) {
      pushUnique(diagnostics, "The outer line says nil-call because the script immediately called the failed loadstring result with ().");
    } else if (!nilTrap) {
      pushUnique(diagnostics, "The script tried to call a nil value. For Roblox one-liners, this often means loadstring(...) returned nil or an expected executor/global function is missing.");
    }
  }

  if (/attempt to index nil with (?:number|['"]\d+['"])/i.test(combined)) {
    if (crypto.createHash("sha256").update(source).digest("hex") === WYN_SAMPLE_SHA256) {
      pushUnique(diagnostics, "The wYn payload reached its decoded script, but a randomized package/world lookup returned nil. The built-in compatibility world was applied; provide the target game's scenario for game-specific objects and data.");
    } else {
      pushUnique(diagnostics, "The script indexed a missing array/table value. This commonly means the scenario is missing a package export, child Instance, or fixture response expected by the script.");
    }
  }

  const mainErr = firstFile(files, "main_runtime_error");
  if (mainErr && mainErr.preview) {
    pushUnique(diagnostics, `Main runtime error: ${oneLinePreview(mainErr.preview, 500)}`);
  }
  if (luraphReport && luraphReport.exact_recovery_status) {
    pushUnique(diagnostics, `Luraph exact recovery: ${luraphReport.exact_recovery_status}`);
  }
  if (terminationReason === "virtual_budget") {
    pushUnique(diagnostics, "The virtual simulation budget was reached with script work still pending.");
  }
  if (terminationReason === "instruction_budget") {
    pushUnique(diagnostics, "The script exhausted its VM instruction budget while it was still running.");
  }
  if (code !== 0) {
    pushUnique(diagnostics, `Runtime exited with code ${code}.`);
  }
  return diagnostics;
}

function buildArgs(payload, inputPath, outDir, tracePath, scenarioPath, reportPath) {
  const profile = oneOf(payload.profile, ["roblox-client", "executor-client"], "executor-client");
  const executionMode = oneOf(payload.executionMode, ["faithful", "diagnostic"], "faithful");
  const analysisHooks = executionMode === "faithful"
    ? "off"
    : oneOf(payload.analysisHooks, ["auto", "on", "off"], "on");
  const ownerProtection = oneOf(payload.ownerProtection, ["respect", "ignore", "audit"], "respect");
  const networkPolicy = oneOf(payload.networkPolicy, ["offline", "allowlist", "live"], "offline");
  const luraphMode = oneOf(payload.luraphMode, ["off", "auto", "force"], "auto");
  const timeoutMaximum = payload.__runtimeJob
    ? (process.env.VERCEL ? HOSTED_TIMEOUT_SECONDS : LOCAL_TIMEOUT_SECONDS)
    : 50;
  const timeout = numberIn(payload.timeout, 1, timeoutMaximum, 10);
  const captureMin = Math.floor(numberIn(payload.captureMin, 1, 500000, 100));
  const clockMode = oneOf(payload.clockMode, ["virtual", "realtime"], "virtual");
  const unsupported = oneOf(payload.unsupported, ["error", "trace-nil"], profile === "roblox-client" ? "error" : "trace-nil");
  const executorPreset = oneOf(payload.executorPreset, ["generic", "opiumware"], "generic");
  const filesystem = oneOf(payload.filesystem, ["disabled", "memory"], profile === "executor-client" ? "memory" : "disabled");
  const registerOverflow = oneOf(payload.registerOverflow, ["error", "spill"], "error");

  const args = [
    "--out",
    outDir,
    "--trace-compat",
    tracePath,
    "--profile",
    profile,
    "--execution-mode",
    executionMode,
    "--analysis-hooks",
    analysisHooks,
    "--owner-protection",
    ownerProtection,
    "--network-policy",
    networkPolicy,
    "--luraph-mode",
    luraphMode,
    "--capture-min",
    String(captureMin),
    "--timeout",
    String(timeout),
    "--clock",
    clockMode,
    "--frame-rate",
    String(numberIn(payload.frameRate, 1, 240, 60)),
    "--max-virtual-seconds",
    String(numberIn(payload.maxVirtualSeconds, 0, 300, 30)),
    "--unsupported",
    unsupported,
    "--register-overflow",
    registerOverflow,
    "--memory-limit-mb",
    intText(payload.memoryLimitMb, 32, 4096, 512),
    "--executor-preset",
    executorPreset,
    "--filesystem",
    filesystem,
    "--report",
    reportPath,
    "--chunk-name",
    String(payload.chunkName || "Web Runner Script").slice(0, 160),
    "--luraph-max-steps",
    intText(payload.luraphMaxSteps, 1000, 2_000_000_000, 2_000_000_000),
    "--luraph-stall-steps",
    intText(payload.luraphStallSteps, 0, 2_000_000_000, 0),
    "--progress-interval",
    String(numberIn(payload.progressInterval, 0, 10, 0))
  ];

  if (scenarioPath) args.push("--scenario", scenarioPath);
  if (payload.deterministicSeed !== "" && payload.deterministicSeed != null) {
    args.push("--deterministic-seed", intText(payload.deterministicSeed, 0, 0xffffffff, 0));
  }

  for (const host of normalizeHosts(payload.allowHosts)) {
    args.push("--allow-host", host);
  }

  // Private-network access is an operator-controlled local-server setting.
  // It is deliberately not accepted from the request body and never enabled
  // in the hosted Vercel environment.
  if (!process.env.VERCEL && process.env.RBX_RUNTIME_ALLOW_PRIVATE_NETWORK === "1") {
    args.push("--allow-private-network");
  }

  if (executionMode === "diagnostic" && bool(payload.captureStringHooks, true)) args.push("--capture-string-hooks");
  else args.push("--no-capture-string-hooks");
  if (bool(payload.traceCalls, false)) args.push("--trace-calls");
  if (executionMode === "diagnostic" && bool(payload.tracePcallErrors, false)) args.push("--trace-pcall-errors");
  if (bool(payload.autorunLoadstring, false)) args.push("--autorun-loadstring");
  else args.push("--no-autorun-loadstring");
  if (bool(payload.passSourceAsArg, false)) args.push("--pass-source-as-arg");
  if (bool(payload.stopAfterCapture, false)) args.push("--stop-after-capture");
  if (bool(payload.nativeCodegen, true)) args.push("--native-codegen");
  else args.push("--no-native-codegen");

  if (payload.placeId) args.push("--place-id", intText(payload.placeId, 0, 9_000_000_000, 0));
  if (payload.gameId) args.push("--game-id", intText(payload.gameId, 0, 9_000_000_000, 0));
  if (payload.userId) args.push("--user-id", intText(payload.userId, 1, 9_000_000_000, 123456));
  if (payload.jobId) args.push("--job-id", String(payload.jobId).slice(0, 128));
  if (payload.playerName) args.push("--player-name", String(payload.playerName).slice(0, 64));

  args.push(inputPath);
  return args;
}

function runNative(binary, payload, onProgress = null) {
  let progressQueue = Promise.resolve();
  const progress = (event) => {
    progressQueue = progressQueue
      .then(() => onProgress?.(event))
      .catch(() => {});
    return progressQueue;
  };

  return new Promise((resolve, reject) => {
    const source = String(payload.script || "");
    try {
      validateRuntimeInput(payload);
    } catch (error) {
      error.statusCode = error.status;
      return reject(error);
    }

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rbx-runner-"));
    const inputPath = path.join(dir, safeName(payload.filename));
    const outDir = path.join(dir, "captures");
    const tracePath = path.join(outDir, "compat_trace.jsonl");
    const reportPath = path.join(outDir, "runtime_report.json");
    const inferredScenario = !String(payload.scenario || "").trim()
      ? inferredCompatibilityScenario(source, String(payload.profile || "executor-client"))
      : null;
    const scenarioText = normalizeScenario(inferredScenario || payload.scenario, source, payload.profile);
    const scenarioPath = scenarioText ? path.join(dir, "scenario.json") : "";
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(inputPath, prepareRuntimeSource(source));
    if (scenarioPath) fs.writeFileSync(scenarioPath, scenarioText);
    const args = buildArgs(payload, inputPath, outDir, tracePath, scenarioPath, reportPath);

    const started = Date.now();
    const child = spawn(binary, args, { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let outputBytes = 0;
    let outputExceeded = false;
    const timeoutMaximum = payload.__runtimeJob
      ? (process.env.VERCEL ? HOSTED_TIMEOUT_SECONDS : LOCAL_TIMEOUT_SECONDS)
      : 50;
    const timeoutSeconds = numberIn(payload.timeout, 1, timeoutMaximum, 10);
    const hardTimeout = Math.max(3_000, timeoutSeconds * 1000 + 3_000);
    const timer = setTimeout(() => child.kill("SIGKILL"), hardTimeout);

    const appendOutput = (stream, chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_PROCESS_OUTPUT_BYTES) {
        outputExceeded = true;
        child.kill("SIGKILL");
        return;
      }
      if (stream === "stdout") stdout += chunk.toString();
      else stderr += chunk.toString();
    };
    child.stdout.on("data", (chunk) => appendOutput("stdout", chunk));
    child.stderr.on("data", (chunk) => appendOutput("stderr", chunk));
    child.once("spawn", () => {
      progress({ stage: "compile", status: "done", message: "Native Luau compiler started", metrics: { source_bytes: Buffer.byteLength(source) } });
      progress({ stage: "bootstrap", status: "running", message: "Bootstrapping the isolated runtime" });
      progress({ stage: "bootstrap", status: "done", message: "Runtime process initialized" });
      progress({ stage: "execute", status: "running", message: "Executing scheduled Luau work" });
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      progress({ stage: "compile", status: "failed", message: "Runtime process could not start" });
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
      reject(err);
    });
    child.on("close", async (code, signal) => {
      clearTimeout(timer);
      const durationMs = Date.now() - started;
      const captureIndex = redactRuntimeValue(parseJsonLines(path.join(outDir, "capture_index.jsonl")), dir);
      const compatTrace = redactRuntimeValue(parseJsonLines(tracePath), dir);
      let ownerRefusal = null;
      let luraphReport = null;
      let runtimeReport = null;
      try { ownerRefusal = JSON.parse(fs.readFileSync(path.join(outDir, "owner_protected_refused.json"), "utf8")); } catch {}
      try { luraphReport = JSON.parse(fs.readFileSync(path.join(outDir, "luraph_recovery_report.json"), "utf8")); } catch {}
      try { runtimeReport = JSON.parse(fs.readFileSync(reportPath, "utf8")); } catch {}
      ownerRefusal = redactRuntimeValue(ownerRefusal, dir);
      luraphReport = redactRuntimeValue(luraphReport, dir);
      runtimeReport = redactRuntimeValue(runtimeReport, dir);
      const files = collectFiles(outDir).map((file) => ({ ...file, preview: redactRuntimeText(file.preview, dir) }));
      const split = splitLoaderWarnings(redactRuntimeText(stderr, dir));
      const cleanStdout = redactRuntimeText(stdout, dir);
      const networkRequirements = networkRequirementsFromTrace(compatTrace, runtimeReport);
      const dependencyRequirements = dependencyRequirementsFromReport(runtimeReport);
      const terminationReason = terminationReasonFor({
        code,
        signal,
        stdout: cleanStdout,
        stderr: split.stderr,
        runtimeReport,
        networkRequirements
      });
      const diagnostics = buildDiagnostics({
        code,
        signal,
        stdout: cleanStdout,
        stderr: split.stderr,
        files,
        ownerRefusal,
        luraphReport,
        compatTrace,
        source,
        networkRequirements,
        terminationReason
      });
      if (inferredScenario) diagnostics.unshift("Applied the wYn payload compatibility scenario: resilient Networker package plus empty CoreObjects, Plots, and Eggs containers.");
      if (outputExceeded) diagnostics.unshift("Runtime output exceeded the 64 MiB limit.");
      const result = {
        ok: code === 0 && !outputExceeded,
        exitCode: code,
        signal,
        durationMs,
        stdout: cleanStdout.slice(0, MAX_INLINE_BYTES),
        stderr: split.stderr.slice(0, MAX_INLINE_BYTES),
        stdoutTruncated: cleanStdout.length > MAX_INLINE_BYTES,
        stderrTruncated: split.stderr.length > MAX_INLINE_BYTES,
        runtimeWarnings: split.runtimeWarnings,
        scenarioPreset: inferredScenario ? "wyn-payload-world-v2" : null,
        terminationReason,
        networkRequirements,
        dependencyRequirements,
        blockedReason: runtimeReport?.blocked_reason || null,
        diagnostics,
        captureIndex,
        compatTrace,
        ownerRefusal,
        luraphReport,
        runtimeReport,
        files,
        command: ["rbx_luau_runtime", ...args.map((arg) => {
          if (arg === inputPath) return safeName(payload.filename);
          if (arg === scenarioPath) return "scenario.json";
          if (arg === reportPath) return "runtime_report.json";
          if (arg === outDir) return "captures";
          if (arg === tracePath) return "captures/compat_trace.jsonl";
          return arg;
        })]
      };

      if (runtimeReport?.status === "compile_error") {
        await progress({ stage: "compile", status: "failed", message: "Luau compilation failed" });
        await progress({ stage: "execute", status: "skipped", message: "Execution was not started" });
      } else if (/runtime_v2_setup failed/i.test(String(runtimeReport?.error || ""))) {
        await progress({ stage: "bootstrap", status: "failed", message: "Runtime bootstrap failed" });
        await progress({ stage: "execute", status: "skipped", message: "Execution was not started" });
      } else {
        await progress({
          stage: "execute",
          status: "done",
          message: terminationReason === "wall_timeout"
            ? "Execution stopped at its wall-clock limit"
            : terminationReason === "instruction_budget"
              ? "Execution stopped at its VM instruction budget"
              : "Execution phase finished",
          metrics: { duration_ms: durationMs, exit_code: code, termination_reason: terminationReason },
        });
      }
      if (terminationReason === "network_required") {
        const requirement = networkRequirements[0] || {};
        await progress({
          stage: "network_wait",
          status: "done",
          message: `Network approval required${requirement.host ? ` for ${requirement.host}` : ""}`,
          metrics: { blocked: true, host: requirement.host || null },
        });
      } else {
        await progress({ stage: "network_wait", status: "skipped", message: "No network approval was required" });
      }
      if (runtimeReport?.execution_state === "steady_state" || terminationReason === "virtual_budget") {
        await progress({
          stage: "steady_state",
          status: "done",
          message: "Scheduler reached a healthy steady state",
          metrics: { execution_state: runtimeReport?.execution_state || "steady_state" },
        });
      } else {
        await progress({ stage: "steady_state", status: "skipped", message: "Workload did not require steady-state sampling" });
      }
      await progress({
        stage: "complete",
        status: "done",
        message: terminationReason === "network_required"
          ? "Runtime report finalized; approval is required"
          : terminationReason === "blocked"
            ? "Runtime report finalized; execution is blocked"
            : terminationReason === "instruction_budget"
              ? "Runtime report finalized; instruction budget exhausted"
              : "Runtime report finalized",
        metrics: { ok: result.ok, termination_reason: terminationReason },
      });
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
      resolve(result);
    });
  });
}

module.exports = async function handler(req, res) {
  if (String(req.method || "").toUpperCase() !== "POST") {
    return send(res, 405, { ok: false, error: "method not allowed" });
  }

  try {
    const requestPayload = await readJson(req);
    const payload = { ...requestPayload, __runtimeJob: Boolean(req.runtimeJob) };
    if (!req.runtimeJob) {
      const routing = runtimeQueueReason(payload);
      if (routing) {
        const jobs = require("../scripts/jobs-handler");
        const created = await jobs.enqueue("runtime", requestPayload);
        res.setHeader("Retry-After", "1");
        return send(res, 202, { ...created, routing });
      }
    }
    const binary = findBinary();
    if (!binary) {
      return send(res, 500, {
        ok: false,
        error: "rbx_luau_runtime binary not found. Set RBX_RUNTIME_BINARY locally or bundle bin/rbx_luau_runtime-linux-x64 for Vercel."
      });
    }
    const acquired = await acquireJobSlot(Boolean(req.runtimeJob));
    if (!acquired) {
      res.setHeader("Retry-After", "2");
      return send(res, 429, { ok: false, error: "runner is at its two-job concurrency limit" });
    }
    try {
      if (typeof req.runtimeProgress === "function") {
        await req.runtimeProgress({ stage: "compile", status: "running", message: "Compiling Luau source" });
      }
      const result = await runNative(binary, payload, typeof req.runtimeProgress === "function" ? req.runtimeProgress : null);
      return send(res, 200, result);
    } finally {
      releaseJobSlot();
    }
  } catch (err) {
    return send(res, Number(err.statusCode) || 500, { ok: false, error: err.message || String(err) });
  }
};

module.exports._test = {
  buildArgs,
  dependencyRequirementsFromReport,
  normalizeScenario,
  networkRequirementsFromTrace,
  runtimeQueueReason,
  prepareRuntimeSource,
  terminationReasonFor,
};
