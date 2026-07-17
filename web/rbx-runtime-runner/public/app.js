const $ = (id) => document.getElementById(id);
const traceModel = window.RbxTraceModel;

const sampleScript = `local RunService = game:GetService("RunService")
local Players = game:GetService("Players")

local order = { "start" }
task.defer(function() table.insert(order, "defer") end)
task.spawn(function()
    table.insert(order, "spawn")
    task.wait()
    table.insert(order, "resume")
end)

local folder = Instance.new("Folder", workspace)
folder.Name = "RuntimeSample"
folder:SetAttribute("Ready", true)

task.wait()
print("client", Players.LocalPlayer.Name)
print("frame", RunService:IsClient(), table.concat(order, " > "))
print("instance", folder:GetFullName(), folder:GetAttribute("Ready"))

return { ok = true, placeId = game.PlaceId }`;

const MAX_LOCAL_FILE_BYTES = 900_000;
let lastResult = null;
let currentFilename = "web_runner_script.luau";
let pendingRemoteFetch = false;
let traceEvents = [];
let traceCursor = 0;
let traceTimer = null;
let tracePaused = false;
let watchEnabled = true;
let advancedReturnFocus = null;
let previousNetworkPolicy = "offline";

function readForm() {
  return {
    script: $("script").value,
    filename: currentFilename,
    profile: $("profile").value,
    executionMode: $("executionMode").value,
    analysisHooks: $("analysisHooks").value,
    clockMode: $("clockMode").value,
    unsupported: $("unsupported").value,
    registerOverflow: $("registerOverflow").value,
    frameRate: Number($("frameRate").value || 60),
    maxVirtualSeconds: Number($("maxVirtualSeconds").value || 30),
    scenario: $("scenario").value.trim(),
    ownerProtection: $("ownerProtection").value,
    networkPolicy: $("networkPolicy").value,
    allowHosts: $("allowHosts").value,
    timeout: Number($("timeout").value || 10),
    memoryLimitMb: Number($("memoryLimitMb").value || 512),
    deterministicSeed: $("deterministicSeed").value,
    executorPreset: $("executorPreset").value,
    filesystem: $("filesystem").value,
    captureMin: Number($("captureMin").value || 100),
    luraphMode: $("luraphMode").value,
    luraphMaxSteps: Number($("luraphMaxSteps").value || 2000000000),
    progressInterval: Number($("progressInterval").value || 0),
    captureStringHooks: $("captureStringHooks").checked,
    traceCalls: $("traceCalls").checked,
    tracePcallErrors: $("tracePcallErrors").checked,
    autorunLoadstring: $("autorunLoadstring").checked,
    passSourceAsArg: $("passSourceAsArg").checked,
    stopAfterCapture: $("stopAfterCapture").checked,
    nativeCodegen: $("nativeCodegen").checked,
    placeId: $("placeId").value,
    gameId: $("gameId").value,
    userId: $("userId").value,
    jobId: $("jobId").value,
    playerName: $("playerName").value,
    chunkName: $("chunkName").value || "Web Runner Script"
  };
}

function updateSegment(groupId, value) {
  const group = $(groupId);
  if (!group) return;
  for (const button of group.querySelectorAll("button[data-value]")) {
    const selected = button.dataset.value === value;
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-pressed", String(selected));
  }
}

function applyConfig(config) {
  if (!config || typeof config !== "object") return;
  const map = {
    script: "script",
    profile: "profile",
    executionMode: "executionMode",
    analysisHooks: "analysisHooks",
    clockMode: "clockMode",
    unsupported: "unsupported",
    registerOverflow: "registerOverflow",
    frameRate: "frameRate",
    maxVirtualSeconds: "maxVirtualSeconds",
    scenario: "scenario",
    ownerProtection: "ownerProtection",
    networkPolicy: "networkPolicy",
    allowHosts: "allowHosts",
    timeout: "timeout",
    memoryLimitMb: "memoryLimitMb",
    deterministicSeed: "deterministicSeed",
    executorPreset: "executorPreset",
    filesystem: "filesystem",
    captureMin: "captureMin",
    luraphMode: "luraphMode",
    luraphMaxSteps: "luraphMaxSteps",
    progressInterval: "progressInterval",
    placeId: "placeId",
    gameId: "gameId",
    userId: "userId",
    jobId: "jobId",
    playerName: "playerName",
    chunkName: "chunkName"
  };
  for (const [key, id] of Object.entries(map)) {
    if (config[key] === undefined || !$(id)) continue;
    if (key === "scenario" && typeof config[key] === "object") $(id).value = JSON.stringify(config[key], null, 2);
    else $(id).value = Array.isArray(config[key]) ? config[key].join("\n") : String(config[key]);
  }
  if (config.executionMode !== undefined && config.analysisHooks === undefined) {
    $("analysisHooks").value = $("executionMode").value === "faithful" ? "off" : "on";
  }
  if (config.executionMode !== undefined && config.captureStringHooks === undefined) {
    $("captureStringHooks").checked = $("executionMode").value === "diagnostic";
  }
  if (config.executionMode !== undefined && config.tracePcallErrors === undefined) {
    $("tracePcallErrors").checked = $("executionMode").value === "diagnostic";
  }
  if (config.profile !== undefined && config.filesystem === undefined) {
    $("filesystem").value = $("profile").value === "roblox-client" ? "disabled" : "memory";
  }
  for (const key of [
    "captureStringHooks",
    "traceCalls",
    "tracePcallErrors",
    "autorunLoadstring",
    "passSourceAsArg",
    "stopAfterCapture",
    "nativeCodegen"
  ]) {
    if (config[key] !== undefined && $(key)) $(key).checked = Boolean(config[key]);
  }
  updateSegment("profileSegments", $("profile").value);
  updateSegment("clockSegments", $("clockMode").value);
  updateEditorMetrics();
  previousNetworkPolicy = $("networkPolicy").value;
  updateEnvironmentSummary();
}

function setStatus(text, kind = "") {
  const el = $("status");
  el.className = `run-status ${kind}`.trim();
  el.querySelector(".status-text").textContent = text;
}

function setRunning(running) {
  const button = $("run");
  button.disabled = running;
  $("allowNetworkRetry").disabled = running;
  button.classList.toggle("running", running);
  button.querySelector("span:last-child").textContent = running ? "Running" : "Run script";
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error?.message || json.error || json.stderr || "runner failed");
  return json;
}

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function runtimeStageLabel(stage) {
  return ({
    compile: "Compiling Luau",
    bootstrap: "Bootstrapping runtime",
    execute: "Executing workload",
    network_wait: "Resolving network policy",
    steady_state: "Sampling steady state",
    complete: "Finalizing report"
  })[stage] || "Running workload";
}

function renderRuntimeJob(job) {
  const elapsed = Math.max(0, Number(job.elapsed_ms || 0) / 1000);
  const active = job.stages?.[job.current_stage] || {};
  const progress = job.stage_progress || {};
  setStatus(active.message || job.message || runtimeStageLabel(job.current_stage), job.state === "failed" ? "bad" : job.state === "completed" ? "ok" : "busy");
  $("runSummary").textContent = [
    `job ${String(job.id || "").slice(0, 10)}`,
    runtimeStageLabel(job.current_stage),
    progress.total ? `${progress.completed || 0}/${progress.total} stages` : null,
    `${elapsed.toFixed(elapsed < 10 ? 1 : 0)}s`
  ].filter(Boolean).join(" · ");
  if (watchEnabled) {
    $("traceState").textContent = runtimeStageLabel(job.current_stage);
    $("traceProgress").textContent = progress.total ? `${progress.completed || 0} / ${progress.total}` : "live";
  }
}

async function waitForRuntimeJob(created) {
  let job = null;
  while (true) {
    const response = await fetch(created.links.status, { headers: { accept: "application/json" }, cache: "no-store" });
    const payload = await response.json();
    if (!response.ok || !payload.ok) throw new Error(payload.error?.message || "Runtime job status is unavailable");
    job = payload.job;
    renderRuntimeJob(job);
    if (!["queued", "running"].includes(job.state)) break;
    await sleep(Math.max(250, Number(job.poll_after_ms) || 1000));
  }

  const response = await fetch(created.links.finished, { headers: { accept: "application/json" }, cache: "no-store" });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error?.message || payload.error || job?.message || "Runtime job failed");
  return payload;
}

function renderJson(value) {
  return JSON.stringify(value, null, 2);
}

function safeClientFilename(name) {
  const clean = String(name || "script.luau").split(/[\\/]/).pop().replace(/[^A-Za-z0-9_.-]/g, "_");
  return /\.(?:lua|luau|txt)$/i.test(clean) ? clean : `${clean}.luau`;
}

function setEditorSource(source, filename = currentFilename) {
  currentFilename = safeClientFilename(filename);
  $("sourceName").textContent = currentFilename;
  $("script").value = String(source || "");
  updateEditorMetrics();
}

function artifactPayload(file, files) {
  if (file.downloadBase64) return file.downloadBase64;
  if (!file.downloadRef) return "";
  return files.find((candidate) => candidate.name === file.downloadRef)?.downloadBase64 || "";
}

function downloadArtifact(file, files) {
  const encoded = artifactPayload(file, files);
  if (!encoded) {
    setStatus("Full artifact is unavailable", "warn");
    return;
  }
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  const href = URL.createObjectURL(new Blob([bytes], { type: "text/plain;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = safeClientFilename(file.name);
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
  setStatus(`Download started: ${file.name}`, "ok");
}

function primaryDiagnostic(data) {
  const diagnostics = data.diagnostics || [];
  return diagnostics.find((line) => !/^Runtime exited with code /.test(line)) || diagnostics[0] || "";
}

function renderFiles(files) {
  const root = $("files");
  root.innerHTML = "";
  if (!files || !files.length) {
    root.innerHTML = '<div class="empty-list"><strong>No files</strong><span>0 capture artifacts</span></div>';
    return;
  }
  for (const file of files) {
    const details = document.createElement("details");
    details.className = "file";
    details.open = /error|refused|report/i.test(file.name || "");
    const summary = document.createElement("summary");
    const name = document.createElement("span");
    name.textContent = file.name;
    const size = document.createElement("small");
    size.textContent = `${Number(file.bytes || 0).toLocaleString()} B${file.truncated ? " · preview" : ""}`;
    summary.append(name, size);
    const pre = document.createElement("pre");
    pre.textContent = file.preview || "";
    const body = document.createElement("div");
    body.className = "file-body";
    if (artifactPayload(file, files)) {
      const toolbar = document.createElement("div");
      toolbar.className = "file-toolbar";
      const hash = document.createElement("code");
      hash.textContent = file.sha256 ? `sha256 ${file.sha256.slice(0, 12)}` : "complete artifact";
      const download = document.createElement("button");
      download.className = "button file-download";
      download.type = "button";
      download.title = `Download ${file.name}`;
      download.setAttribute("aria-label", `Download ${file.name}`);
      download.innerHTML = '<span class="download-glyph" aria-hidden="true">↓</span><span>Download</span>';
      download.addEventListener("click", () => downloadArtifact(file, files));
      toolbar.append(hash, download);
      body.append(toolbar);
    }
    body.append(pre);
    details.append(summary, body);
    if (pendingRemoteFetch && /^captured_httpget\.lua$/i.test(file.name || "")) details.open = true;
    root.append(details);
  }
}

function renderResult(data) {
  lastResult = data;
  const stdout = data.stdout || "";
  const stderr = data.stderr || "";
  const networkRequirement = (data.networkRequirements || [])[0] || null;
  $("stdout").textContent = stdout;
  $("stderr").textContent = stderr;
  $("stderr").hidden = !stderr;
  $("networkConsent").hidden = !networkRequirement;
  $("networkConsentHost").textContent = networkRequirement?.host || "";
  $("networkConsentUrl").textContent = networkRequirement?.url || "";
  const hasConsoleResult = Boolean(stdout || stderr || networkRequirement);
  $("consoleEmpty").hidden = hasConsoleResult;
  $("consoleResult").hidden = !hasConsoleResult;

  $("meta").textContent = renderJson({
    ok: data.ok,
    exitCode: data.exitCode,
    signal: data.signal,
    durationMs: data.durationMs,
    terminationReason: data.terminationReason,
    blockedReason: data.blockedReason,
    networkRequirements: data.networkRequirements,
    dependencyRequirements: data.dependencyRequirements,
    diagnostics: data.diagnostics,
    runtimeWarnings: data.runtimeWarnings,
    ownerRefusal: data.ownerRefusal,
    luraphReport: data.luraphReport,
    command: data.command
  });
  $("runtimeReport").textContent = renderJson(data.runtimeReport || {});
  $("captureIndex").textContent = renderJson(data.captureIndex || []);
  $("compatTrace").textContent = renderJson(data.compatTrace || []);
  renderFiles(data.files || []);

  const scheduler = data.runtimeReport?.scheduler || {};
  const runtimeCount = data.runtimeReport && Object.keys(data.runtimeReport).length ? 1 : 0;
  const hookCount = (data.captureIndex || []).length + (data.compatTrace || []).length;
  $("runtimeBadge").textContent = String(runtimeCount);
  $("hookBadge").textContent = String(hookCount);
  $("fileBadge").textContent = String((data.files || []).length);
  if (watchEnabled && (data.durationMs != null || data.exitCode != null || data.terminationReason)) prepareTraceReplay(data);
  $("runSummary").textContent = [
    data.runtimeReport?.profile || $("profile").value,
    data.runtimeReport?.clock || $("clockMode").value,
    data.runtimeReport?.register_overflow?.chunks_rewritten
      ? `${data.runtimeReport.register_overflow.bindings_spilled} locals spilled`
      : null,
    Number.isFinite(scheduler.frames) ? `${scheduler.frames} frames` : null,
    data.terminationReason || null,
    Number.isFinite(data.durationMs) ? `${data.durationMs} ms` : null
  ].filter(Boolean).join(" · ");
}

function clearResult() {
  renderResult({
    stdout: "",
    stderr: "",
    captureIndex: [],
    compatTrace: [],
    runtimeReport: {},
    files: [],
    diagnostics: []
  });
}

async function run() {
  const form = readForm();
  if (form.scenario) JSON.parse(form.scenario);
  setRunning(true);
  setStatus("Running", "busy");
  $("runSummary").textContent = `${form.profile} · ${form.clockMode} · network ${form.networkPolicy}`;
  clearResult();
  if (watchEnabled) beginLiveTrace();
  try {
    let data = await postJson("/api/run", form);
    if (data.kind === "runtime" && data.state === "queued" && data.links) {
      setStatus("Queued for long-running execution", "busy");
      data = await waitForRuntimeJob(data);
    }
    renderResult(data);
    const diagnostic = primaryDiagnostic(data);
    if (data.terminationReason === "network_required") {
      const host = data.networkRequirements?.[0]?.host || "external host";
      setStatus(`Network approval required: ${host}`, "warn");
    } else if (data.terminationReason === "blocked") {
      const dependency = data.dependencyRequirements?.[0];
      const reason = data.blockedReason
        || (dependency?.name ? `Waiting for ${dependency.kind || "dependency"}: ${dependency.name}` : "Runtime execution is blocked");
      setStatus(reason, "warn");
    } else if (data.terminationReason === "virtual_budget") {
      const virtualTime = Number(data.runtimeReport?.scheduler?.virtual_time || form.maxVirtualSeconds || 0);
      setStatus(`Sampled ${virtualTime.toFixed(2)}s of virtual time`, "ok");
    } else if (data.terminationReason === "wall_timeout") {
      setStatus(diagnostic || "Wall-clock timeout", "bad");
    } else if (data.terminationReason === "instruction_budget") {
      setStatus(diagnostic || "VM instruction budget exhausted", "bad");
    } else {
      setStatus(data.ok ? `Completed in ${(data.durationMs / 1000).toFixed(2)}s` : (diagnostic || "Runtime error"), data.ok ? "ok" : "warn");
    }
    if (pendingRemoteFetch && data.terminationReason !== "network_required") {
      const artifact = (data.files || []).find((file) => /^captured_httpget\.lua$/i.test(file.name || ""));
      if (artifact && artifactPayload(artifact, data.files || [])) {
        switchOutputTab("files");
        setStatus(`Fetched ${formatBytes(artifact.bytes || 0)} from the approved host`, "ok");
      }
      pendingRemoteFetch = false;
    }
  } catch (err) {
    setStatus(err.message, "bad");
    $("stderr").textContent = err.message;
    $("stderr").hidden = false;
    $("consoleEmpty").hidden = true;
    $("consoleResult").hidden = false;
  } finally {
    setRunning(false);
  }
}

function setTraceExplanation(event) {
  $("traceCategory").textContent = event.category;
  $("traceHeadline").textContent = event.headline;
  $("traceDescription").textContent = event.description;
  $("traceConfidence").textContent = event.confidence;
  $("traceConfidence").className = `trace-confidence ${event.confidence.toLowerCase()}`;
}

function appendTraceRow(event, index, pending = false) {
  const row = document.createElement("button");
  row.className = `trace-row${pending ? " pending" : ""}`;
  row.type = "button";
  row.innerHTML = `<span class="trace-index">${String(index + 1).padStart(2, "0")}</span><span class="trace-node"></span><span class="trace-row-copy"><small>${event.category}</small><strong></strong><span></span></span>`;
  row.querySelector("strong").textContent = event.headline;
  row.querySelector(".trace-row-copy > span").textContent = event.description;
  row.addEventListener("click", () => { setTraceExplanation(event); document.querySelectorAll(".trace-row.current").forEach((item) => item.classList.remove("current")); row.classList.add("current"); });
  $("traceTimeline").append(row);
  return row;
}

function playTraceStep() {
  clearTimeout(traceTimer);
  if (tracePaused || traceCursor >= traceEvents.length) {
    if (traceCursor >= traceEvents.length) $("traceState").textContent = "Replay complete";
    return;
  }
  document.querySelectorAll(".trace-row.current").forEach((row) => row.classList.remove("current"));
  const event = traceEvents[traceCursor];
  const row = appendTraceRow(event, traceCursor);
  row.classList.add("current");
  setTraceExplanation(event);
  traceCursor += 1;
  $("traceProgress").textContent = `${traceCursor} / ${traceEvents.length}`;
  $("liveTraceBadge").textContent = String(traceEvents.length);
  $("traceTimeline").scrollTop = $("traceTimeline").scrollHeight;
  const speed = $("traceSpeed").value;
  const delay = speed === "custom"
    ? Math.max(10, 1000 / Math.max(0.2, Math.min(100, Number($("customTraceRate").value) || 10)))
    : Number(speed || 550);
  traceTimer = setTimeout(playTraceStep, delay);
}

function prepareTraceReplay(data) {
  traceEvents = traceModel.buildTraceEvents(data, {
    source: $("script").value,
    filename: currentFilename,
    chunkName: $("chunkName").value || "Web Runner Script",
    profile: $("profile").value,
    clock: $("clockMode").value
  });
  traceCursor = 0;
  tracePaused = false;
  $("traceTimeline").innerHTML = "";
  $("tracePause").textContent = "Pause";
  $("traceState").textContent = "Replaying evidence";
  $("liveTraceTab").hidden = false;
  $("liveTraceTab").classList.add("trace-active");
  switchOutputTab("live");
  playTraceStep();
}

function beginLiveTrace() {
  clearTimeout(traceTimer);
  $("liveTraceTab").hidden = false;
  $("liveTraceTab").classList.add("trace-active");
  $("traceTimeline").innerHTML = "";
  $("traceState").textContent = "Process running";
  $("traceProgress").textContent = "live";
  switchOutputTab("live");
  const event = traceModel.createTraceEvent("START", "Preparing instrumented runtime", "Direct evidence will appear after the runtime finishes collecting compiler, scheduler, API, output, and network events.", "Direct");
  appendTraceRow(event, 0).classList.add("current", "running");
  setTraceExplanation(event);
}

function replayTrace() {
  if (!traceEvents.length) return;
  traceCursor = 0;
  tracePaused = false;
  $("traceTimeline").innerHTML = "";
  $("tracePause").textContent = "Pause";
  $("traceState").textContent = "Replaying evidence";
  playTraceStep();
}

function allowNetworkAndRetry() {
  const requirement = lastResult?.networkRequirements?.[0];
  if (!requirement || !/^[a-z0-9_.:-]+$/i.test(requirement.host || "")) return;

  const hosts = new Set(
    $("allowHosts").value
      .split(/[\s,]+/)
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean)
  );
  hosts.add(requirement.host.toLowerCase());
  $("allowHosts").value = [...hosts].join("\n");
  $("networkPolicy").value = "allowlist";
  updateEnvironmentSummary();
  run().catch((err) => setStatus(err.message, "bad"));
}

function copyPrompt() {
  const prompt = `Return ONLY JSON for the ALEX Roblox Luau runtime runner, with no markdown.
Schema:
{
  "script": "Luau source",
  "profile": "executor-client or roblox-client",
  "executionMode": "faithful or diagnostic",
  "analysisHooks": "on, off, or auto",
  "clockMode": "virtual or realtime",
  "unsupported": "error or trace-nil",
  "registerOverflow": "error or spill",
  "frameRate": 60,
  "maxVirtualSeconds": 30,
  "scenario": {"version": 2, "instances": [], "module_sources": {}, "http_fixtures": {}, "scheduled_events": []},
  "networkPolicy": "offline, allowlist, or live",
  "memoryLimitMb": 512,
  "executorPreset": "generic or opiumware",
  "filesystem": "memory or disabled",
  "captureStringHooks": true,
  "traceCalls": false,
  "tracePcallErrors": false,
  "playerName": "Player",
  "userId": 123456
}`;
  navigator.clipboard.writeText(prompt).then(() => setStatus("AI config prompt copied", "ok"));
}

async function loadLocalFile(file) {
  if (!file) return;
  if (!/\.(?:lua|luau|txt)$/i.test(file.name || "")) throw new Error("Choose a .lua, .luau, or .txt file");
  if (file.size > MAX_LOCAL_FILE_BYTES) throw new Error("Luau file exceeds 900 KB");
  setEditorSource(await file.text(), file.name);
  pendingRemoteFetch = false;
  clearResult();
  setStatus(`Loaded ${file.name}`, "ok");
}

function bindFileDropZone() {
  const editor = document.querySelector(".editor-shell");
  let dragDepth = 0;

  const containsFiles = (event) => Array.from(event.dataTransfer?.types || []).includes("Files");
  const reset = () => {
    dragDepth = 0;
    editor.classList.remove("file-drag-active");
  };

  window.addEventListener("dragover", (event) => {
    if (containsFiles(event)) event.preventDefault();
  });
  window.addEventListener("drop", (event) => {
    if (containsFiles(event)) event.preventDefault();
  });
  editor.addEventListener("dragenter", (event) => {
    if (!containsFiles(event)) return;
    event.preventDefault();
    dragDepth += 1;
    editor.classList.add("file-drag-active");
  });
  editor.addEventListener("dragover", (event) => {
    if (!containsFiles(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  });
  editor.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) editor.classList.remove("file-drag-active");
  });
  editor.addEventListener("drop", async (event) => {
    event.preventDefault();
    event.stopPropagation();
    const files = Array.from(event.dataTransfer?.files || []);
    reset();
    if (!files.length) return;
    if (files.length > 1) {
      setStatus("Drop one .lua, .luau, or .txt file at a time", "bad");
      return;
    }
    try {
      await loadLocalFile(files[0]);
      $("script").focus();
    } catch (err) {
      setStatus(err.message, "bad");
    }
  });
  window.addEventListener("dragend", reset);
}

function openFetchDialog() {
  $("fetchDialog").showModal();
  requestAnimationFrame(() => $("fetchUrl").select());
}

function prepareRemoteFetch(event) {
  event.preventDefault();
  let url;
  try {
    url = new URL($("fetchUrl").value.trim());
  } catch {
    setStatus("Enter a valid HTTP(S) URL", "bad");
    return;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    setStatus("Only HTTP(S) URLs are supported", "bad");
    return;
  }
  $("profile").value = "executor-client";
  $("unsupported").value = "trace-nil";
  $("executionMode").value = "diagnostic";
  $("analysisHooks").value = "on";
  $("captureStringHooks").checked = true;
  $("captureMin").value = "1";
  updateSegment("profileSegments", "executor-client");
  setEditorSource(`local body = game:HttpGet(${JSON.stringify(url.href)})\nprint("fetched", #body, "bytes")`, "remote_fetch.luau");
  pendingRemoteFetch = true;
  $("fetchDialog").close();
  switchOutputTab("console");
  run().catch((err) => setStatus(err.message, "bad"));
}

function switchOutputTab(name) {
  for (const tab of document.querySelectorAll(".output-tab")) {
    const selected = tab.dataset.tab === name;
    tab.classList.toggle("selected", selected);
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
  }
  for (const view of document.querySelectorAll(".output-view")) {
    const selected = view.dataset.view === name;
    view.classList.toggle("selected", selected);
    view.hidden = !selected;
  }
}

function openAdvanced() {
  advancedReturnFocus = document.activeElement;
  $("drawerBackdrop").hidden = false;
  $("advancedDrawer").removeAttribute("inert");
  requestAnimationFrame(() => {
    $("drawerBackdrop").classList.add("open");
    $("advancedDrawer").classList.add("open");
    $("advancedDrawer").setAttribute("aria-hidden", "false");
    $("closeAdvanced").focus();
  });
}

function closeAdvanced() {
  $("drawerBackdrop").classList.remove("open");
  $("advancedDrawer").classList.remove("open");
  $("advancedDrawer").setAttribute("aria-hidden", "true");
  setTimeout(() => {
    $("drawerBackdrop").hidden = true;
    $("advancedDrawer").setAttribute("inert", "");
  }, 180);
  if (advancedReturnFocus instanceof HTMLElement) advancedReturnFocus.focus();
}

function keepFocusInAdvanced(event) {
  if (event.key !== "Tab" || !$("advancedDrawer").classList.contains("open")) return;
  const focusable = [...$("advancedDrawer").querySelectorAll("button, input, select, textarea, [href], [tabindex]:not([tabindex='-1'])")]
    .filter((item) => !item.disabled && !item.hidden);
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function updateEditorMetrics() {
  const source = $("script").value;
  const count = source.split("\n").length;
  $("lineNumbers").textContent = Array.from({ length: count }, (_, index) => index + 1).join("\n");
  $("sourceSize").textContent = formatBytes(new TextEncoder().encode(source).length);
}

function updateEnvironmentSummary() {
  const network = $("networkPolicy").value;
  $("networkState").textContent = network.toUpperCase();
  if (!lastResult) $("runSummary").textContent = `${$("clockMode").value} time · ${$("frameRate").value || 60} fps · network ${network}`;
}

function bindSegment(groupId, targetId, onChange) {
  const group = $(groupId);
  group.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-value]");
    if (!button) return;
    $(targetId).value = button.dataset.value;
    updateSegment(groupId, button.dataset.value);
    if (onChange) onChange(button.dataset.value);
    updateEnvironmentSummary();
  });
}

function copyActiveOutput() {
  const active = document.querySelector(".output-view.selected");
  const text = active?.innerText || "";
  navigator.clipboard.writeText(text).then(() => setStatus("Output copied", "ok"));
}

window.RbxRunner = { applyConfig };

document.addEventListener("DOMContentLoaded", () => {
  setEditorSource(sampleScript, currentFilename);
  bindFileDropZone();
  try {
    const pending = localStorage.getItem("rbxRunnerConfig");
    if (pending) {
      localStorage.removeItem("rbxRunnerConfig");
      applyConfig(JSON.parse(pending));
      setStatus("AI config loaded", "ok");
    }
  } catch {}

  bindSegment("profileSegments", "profile", (profile) => {
    $("unsupported").value = profile === "roblox-client" ? "error" : "trace-nil";
    $("filesystem").value = profile === "roblox-client" ? "disabled" : "memory";
    if ($("executionMode").value === "faithful") $("analysisHooks").value = "off";
  });
  bindSegment("clockSegments", "clockMode");

  $("run").addEventListener("click", () => run().catch((err) => setStatus(err.message, "bad")));
  $("watchMode").addEventListener("click", () => {
    watchEnabled = !watchEnabled;
    $("watchMode").classList.toggle("active", watchEnabled);
    $("watchMode").setAttribute("aria-pressed", String(watchEnabled));
    if (!watchEnabled) $("liveTraceTab").classList.remove("trace-active");
  });
  $("tracePause").addEventListener("click", () => { tracePaused = !tracePaused; $("tracePause").textContent = tracePaused ? "Resume" : "Pause"; if (!tracePaused) playTraceStep(); });
  $("traceReplay").addEventListener("click", replayTrace);
  $("traceSpeed").addEventListener("change", () => {
    $("customTraceRateLabel").hidden = $("traceSpeed").value !== "custom";
    if (!tracePaused && traceCursor < traceEvents.length) playTraceStep();
  });
  $("customTraceRate").addEventListener("input", () => { if (!tracePaused && traceCursor < traceEvents.length) playTraceStep(); });
  $("allowNetworkRetry").addEventListener("click", allowNetworkAndRetry);
  $("sample").addEventListener("click", () => setEditorSource(sampleScript, "web_runner_script.luau"));
  $("clear").addEventListener("click", () => { setEditorSource("", currentFilename); $("script").focus(); });
  $("uploadFile").addEventListener("click", () => $("localFileInput").click());
  $("localFileInput").addEventListener("change", async (event) => {
    try {
      await loadLocalFile(event.target.files?.[0]);
    } catch (err) {
      setStatus(err.message, "bad");
    } finally {
      event.target.value = "";
    }
  });
  $("openFetch").addEventListener("click", openFetchDialog);
  $("fetchForm").addEventListener("submit", prepareRemoteFetch);
  $("closeFetch").addEventListener("click", () => $("fetchDialog").close());
  $("cancelFetch").addEventListener("click", () => $("fetchDialog").close());
  $("copyPrompt").addEventListener("click", copyPrompt);
  $("copyOutput").addEventListener("click", copyActiveOutput);
  $("openAdvanced").addEventListener("click", openAdvanced);
  $("closeAdvanced").addEventListener("click", closeAdvanced);
  $("drawerBackdrop").addEventListener("click", closeAdvanced);
  previousNetworkPolicy = $("networkPolicy").value;
  $("networkPolicy").addEventListener("change", () => {
    const selected = $("networkPolicy").value;
    if (selected === "live") {
      $("networkPolicy").value = previousNetworkPolicy;
      updateEnvironmentSummary();
      $("networkDialog").showModal();
      return;
    }
    previousNetworkPolicy = selected;
    updateEnvironmentSummary();
  });
  $("networkDialogForm").addEventListener("submit", (event) => {
    event.preventDefault();
    previousNetworkPolicy = "live";
    $("networkPolicy").value = "live";
    $("networkDialog").close();
    updateEnvironmentSummary();
    setStatus("Live network enabled for trusted scripts", "warn");
  });
  $("cancelLiveNetwork").addEventListener("click", () => $("networkDialog").close());
  $("executionMode").addEventListener("change", () => {
    const diagnostic = $("executionMode").value === "diagnostic";
    $("analysisHooks").value = diagnostic ? "on" : "off";
    $("captureStringHooks").checked = diagnostic;
    $("tracePcallErrors").checked = diagnostic;
  });
  $("frameRate").addEventListener("input", updateEnvironmentSummary);

  for (const tab of document.querySelectorAll(".output-tab")) {
    tab.addEventListener("click", () => switchOutputTab(tab.dataset.tab));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const tabs = [...document.querySelectorAll(".output-tab")].filter((item) => !item.hidden);
      const current = tabs.indexOf(tab);
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      switchOutputTab(tabs[next].dataset.tab);
      tabs[next].focus();
    });
  }

  $("script").addEventListener("input", updateEditorMetrics);
  $("script").addEventListener("scroll", () => { $("lineNumbers").scrollTop = $("script").scrollTop; });
  $("script").addEventListener("keydown", (event) => {
    if (event.key === "Tab") {
      event.preventDefault();
      const start = event.target.selectionStart;
      const end = event.target.selectionEnd;
      event.target.setRangeText("    ", start, end, "end");
      updateEditorMetrics();
    }
    if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      run().catch((err) => setStatus(err.message, "bad"));
    }
  });

  document.addEventListener("keydown", (event) => {
    keepFocusInAdvanced(event);
    if (event.key === "Escape" && $("advancedDrawer").classList.contains("open")) closeAdvanced();
  });

  clearResult();
  updateEditorMetrics();
  updateEnvironmentSummary();
});
