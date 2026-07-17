const byId = (id) => document.getElementById(id);

async function loadVerifiedBuildRating() {
  try {
    const response = await fetch("/deobfuscator-build.json", { cache: "no-store" });
    if (!response.ok) return;
    const rating = await response.json();
    if (!Number.isFinite(rating.score)) return;
    byId("verifiedBuildScore").innerHTML = `${Math.round(rating.score)}<small>/100</small>`;
    byId("verifiedBuildState").textContent = rating.runtime_equivalent
      ? "runtime matched"
      : rating.runtime_prefix_matched ? "bounded match" : "verification pending";
    byId("verifiedBuildRating").title = `${rating.benchmark || "Current benchmark"} · ${rating.level || "measured"} · ${rating.verified_at || "latest run"}`;
  } catch {
    // The embedded score remains visible when the optional metadata file is unavailable.
  }
}
const source = byId("source");
const views = {};
let activeTab = "source";
let result = null;

function selectSegments(container, hidden) {
  byId(container).addEventListener("click", (event) => {
    const button = event.target.closest("button[data-value]");
    if (!button) return;
    byId(container).querySelectorAll("button").forEach((item) => item.classList.toggle("selected", item === button));
    byId(hidden).value = button.dataset.value;
  });
}

function updateSource() {
  const lines = Math.max(1, source.value.split("\n").length);
  byId("lineNumbers").textContent = Array.from({ length: lines }, (_, index) => index + 1).join("\n");
  const bytes = new Blob([source.value]).size;
  byId("sourceSize").textContent = bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`;
}

function invalidateFailureReport() {
  if (result?.failure_report) result.failure_report = null;
  byId("sendFailedSample").hidden = true;
}

function status(label, state = "") {
  byId("status").className = `run-status ${state}`;
  byId("status").querySelector(".status-text").textContent = label;
}

function showTab(name) {
  activeTab = name;
  document.querySelectorAll("#resultTabs button").forEach((button) => {
    const selected = button.dataset.tab === name;
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  byId("emptyResult").hidden = true;
  byId("resultView").hidden = false;
  byId("resultView").textContent = views[name] || "No artifact was produced for this view.";
  byId("downloadResult").disabled = !views[name];
}

function encode(value) { return JSON.stringify(value, null, 2); }

function resetPipeline() {
  document.querySelectorAll("#analysisPipeline span").forEach((item) => {
    item.className = "";
    item.querySelector("small").textContent = "Waiting";
    item.removeAttribute("title");
  });
}

function compactNumber(value) {
  const number = Number(value || 0);
  return number >= 1000 ? `${(number / 1000).toFixed(number >= 10000 ? 0 : 1)}k` : String(number);
}

function stageMetric(stage, data) {
  const metrics = data?.metrics || {};
  if (data?.status === "pending") return "Waiting";
  if (stage === "detect" && metrics.confidence != null) return `${Math.round(Number(metrics.confidence) * 100)}% match`;
  if (stage === "decode" && metrics.constants != null) return `${compactNumber(metrics.constants)} constants`;
  if (stage === "cfg" && (metrics.reachable_states != null || metrics.reachable != null)) return `${compactNumber(metrics.reachable_states ?? metrics.reachable)} states`;
  if (stage === "normalize" && metrics.normalized_instructions != null) return `${compactNumber(metrics.normalized_instructions)} ops`;
  if (stage === "guard_hotspot" && metrics.observed_steps != null) return `${compactNumber(metrics.observed_steps)} steps`;
  if (stage === "guard_hotspot" && metrics.observed_prototypes != null) return `${compactNumber(metrics.observed_prototypes)} protos`;
  if (stage === "lift" && metrics.lifted_instructions != null) return `${compactNumber(metrics.lifted_instructions)} ops`;
  if (stage === "lift" && metrics.payload_blocks != null) return `${compactNumber(metrics.payload_blocks)} blocks`;
  if (stage === "structure_flow" && metrics.regions_structured != null) return `${compactNumber(metrics.regions_structured)} regions`;
  if (stage === "structure_closures" && metrics.prototypes_nested != null) return `${compactNumber(metrics.prototypes_nested)} protos`;
  if (stage === "structure_dataflow" && metrics.register_table_accesses_scalarized != null) return `${compactNumber(metrics.register_table_accesses_scalarized)} accesses`;
  if (stage === "structure_dataflow" && metrics.single_use_temporaries_inlined != null) return `${compactNumber(metrics.single_use_temporaries_inlined)} aliases`;
  if (stage === "structure_dataflow" && metrics.dead_assignments_removed != null) return `${compactNumber(metrics.dead_assignments_removed)} pruned`;
  if (stage === "structure_source" && metrics.source_quality_score != null) return `${metrics.source_quality_score}/100`;
  if (stage === "structure_source" && metrics.semantic_locals_promoted != null) return `${compactNumber(metrics.semantic_locals_promoted)} locals`;
  if (stage === "provenance" && metrics.mapped_statements != null) return `${compactNumber(metrics.mapped_statements)} links`;
  if (stage === "structure_refine" && (metrics.refinement_passes != null || metrics.passes != null)) {
    const passes = Number(metrics.refinement_passes ?? metrics.passes);
    return `${compactNumber(passes)} ${passes === 1 ? "pass" : "passes"}`;
  }
  if (stage === "verify" && metrics.equivalent === true) return "Equivalent";
  if (stage === "verify" && metrics.equivalent === false) return "Mismatch";
  if (stage === "verify" && metrics.compiled === true) return "Compiled";
  if (stage === "verify" && metrics.compiled === false) return "Compile failed";
  if (data?.status === "running") return "Running";
  if (data?.status === "done") return "Complete";
  if (data?.status === "failed") return "Stopped";
  return "Skipped";
}

function renderJob(job) {
  document.querySelectorAll("#analysisPipeline span").forEach((item) => {
    const stage = item.dataset.stage;
    const data = job.stages?.[stage] || { status: "pending", metrics: {} };
    item.className = data.status === "running" ? "active" : data.status;
    item.querySelector("small").textContent = stageMetric(stage, data);
    item.title = data.message || `${stage} ${data.status}`;
  });
  const elapsed = (Number(job.elapsed_ms || 0) / 1000).toFixed(0);
  const active = job.stages?.[job.current_stage] || {};
  status(job.message || active.message || "Analyzing", job.state === "failed" ? "bad" : job.state === "completed" ? "ok" : "busy");
  byId("runSummary").textContent = `job ${job.id.slice(0, 10)} · ${job.current_stage} · ${elapsed}s · revision ${job.revision}`;
}

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function reportMetric(payload, ...names) {
  const quality = payload.reconstruction_quality || {};
  const readability = payload.report?.reconstruction_candidate?.readability || {};
  const refinement = [...(payload.report?.passes || [])].reverse().find((pass) => pass.stage === "structure_refine") || {};
  const structure = [...(payload.report?.passes || [])].reverse().find((pass) => pass.stage === "structure") || {};
  for (const source of [quality, readability, refinement, structure]) {
    for (const name of names) {
      if (source?.[name] == null || source[name] === "") continue;
      const value = Number(source[name]);
      if (Number.isFinite(value) && value >= 0) return value;
    }
  }
  return null;
}

function setMetric(id, value, suffix = "") {
  byId(id).textContent = value == null ? "—" : `${compactNumber(value)}${suffix}`;
}

function setProof(id, value, passed, failed, unknown) {
  const element = byId(id);
  element.className = `quality-proof ${value === true ? "pass" : value === false ? "fail" : "unknown"}`;
  element.querySelector("b").textContent = value === true ? passed : value === false ? failed : unknown;
}

function renderReconstructionQuality(payload) {
  const quality = payload.reconstruction_quality || {};
  const exact = payload.exact_source === true && payload.status === "recovered_exact";
  const reconstructed = payload.status === "reconstructed" && !exact;
  const observedCandidate = payload.status === "blocked" && Boolean(payload.candidate?.text);
  const readableLift = payload.status === "blocked" && Boolean(payload.readable_lift?.text);
  const candidateVerification = payload.verification?.candidate || {};
  const payloadClosure = payload.coverage?.payload_closure || {};
  const section = byId("resultQuality");
  section.hidden = false;
  section.className = `result-quality ${exact ? "exact" : reconstructed ? "reconstructed" : payload.status || "blocked"}`;
  byId("qualityKicker").textContent = exact ? "Verified source claim" : reconstructed ? "Honest recovery claim" : observedCandidate ? "Observed payload proof" : readableLift ? "Readable semantic lift" : payload.status === "disassembled" ? "Analysis boundary" : "Recovery boundary";
  byId("qualityTitle").textContent = observedCandidate ? "Verified payload candidate; full source is still withheld" : readableLift ? "Semantic lift available; source reconstruction pending" : quality.title || (exact
    ? "Exact source-bearing payload recovered"
    : reconstructed ? "Reconstructed Luau, not original source" : payload.status === "disassembled" ? "VM disassembly only" : "No reconstructed source was emitted");
  const candidateCoverage = payloadClosure.available
    ? ` Static VM semantics cover ${payloadClosure.static_semantic_lifted}/${payloadClosure.instructions}; ${payloadClosure.static_semantic_unresolved} remaining operations are ${payloadClosure.unresolved_observed_instructions}/${payloadClosure.static_semantic_unresolved} observed on the verified path.`
    : "";
  byId("qualityDescription").textContent = observedCandidate ? `A bounded producer slice compiled and matched the protected program, but unresolved reachable VM operations prevent a complete-source claim.${candidateCoverage}` : readableLift ? "Recovered behavior is explained in plain language under Lift; clean compilable Luau has not been proven yet." : quality.description || (reconstructed
    ? "Behavior and structure were rebuilt; original names, comments, and formatting were not recovered."
    : exact ? "A source-bearing payload was recovered and accepted by the source-claim checks." : "Recovery stopped before complete, compilable source could be proven.");

  const compiled = typeof quality.verification?.compiled === "boolean"
    ? quality.verification.compiled
    : observedCandidate ? candidateVerification.compiled ?? null : payload.verification?.output?.compiled ?? payload.verification?.compiled ?? null;
  const equivalent = typeof quality.verification?.equivalent === "boolean"
    ? quality.verification.equivalent
    : observedCandidate ? candidateVerification.runtime?.equivalent ?? null : payload.verification?.runtime?.equivalent ?? null;
  const boundedOnly = observedCandidate
    ? candidateVerification.runtime?.bounded_only === true
    : payload.verification?.runtime?.bounded_only === true;
  setProof("qualityCompile", compiled, "Passed", "Failed", "Not reported");
  const fidelity = quality.semantic_fidelity_score ?? (equivalent === true ? 100 : equivalent === false ? 0 : null);
  setProof("qualityEquivalent", equivalent, boundedOnly ? "Bounded match" : fidelity == null ? "Equivalent" : `${fidelity}/100`, "0/100", "Not tested");

  setMetric("qualityRegions", reportMetric(payload, "structured_regions", "regions_structured"));
  setMetric("qualitySlots", reportMetric(payload, "register_slots_scalarized", "register_table_slots_scalarized"));
  setMetric("qualityAccesses", reportMetric(payload, "register_accesses_scalarized", "register_table_accesses_scalarized"));
  const temporaryValues = reportMetric(payload, "temporary_values_inlined", "temporary_aliases_removed", "single_use_temporaries_inlined");
  const captureReloads = reportMetric(payload, "capture_reloads_removed", "alias_reloads_eliminated");
  const aliasCleanup = reportMetric(payload, "vm_aliases_removed") ??
    (temporaryValues == null && captureReloads == null ? null : (temporaryValues || 0) + (captureReloads || 0));
  setMetric("qualityTemporaries", aliasCleanup);
  setMetric("qualityCallbacks", reportMetric(payload, "callback_aliases_promoted"));
  setMetric("qualityRefinementPasses", reportMetric(payload, "refinement_passes", "passes"));
  setMetric("qualityCaptureCells", reportMetric(payload, "stable_capture_cells_scalarized"));
  setMetric("qualityCaptureAccesses", reportMetric(payload, "stable_capture_accesses_scalarized"));
  setMetric("qualityProducerAliases", reportMetric(payload, "producer_aliases_coalesced"));
  setMetric("qualityResultPacks", reportMetric(payload, "write_only_result_packs_removed"));
  setMetric("qualityGuardClauses", reportMetric(payload, "guard_clauses_flattened"));
  setMetric("qualityParentheses", reportMetric(payload, "redundant_parentheses_removed"));
  const score = payload.source_quality?.score ?? quality.source_quality_score ?? null;
  setMetric("qualityScore", score, score == null ? "" : "/100");

  const tables = reportMetric(payload, "register_tables_scalarized");
  byId("qualityTables").textContent = tables == null ? "table evidence unavailable" : `${compactNumber(tables)} register ${tables === 1 ? "table" : "tables"} affected`;
  const remaining = payload.source_quality?.temporary_lines ?? quality.remaining_temporary_lines ?? null;
  const cleanupParts = [];
  if (temporaryValues != null) cleanupParts.push(`${compactNumber(temporaryValues)} inline`);
  if (captureReloads != null) cleanupParts.push(`${compactNumber(captureReloads)} reload`);
  if (remaining != null) cleanupParts.push(`${compactNumber(remaining)} left`);
  byId("qualityTemporaryRemainder").textContent = cleanupParts.length ? cleanupParts.join(" · ") : "cleanup evidence unavailable";
  const sourceQuality = payload.source_quality;
  const debtLabels = {
    generated_semantic_names: "generated names",
    semantic_state_spill: "state spill",
    oversized_scope: "oversized scope",
    generic_identifiers: "VM names",
    state_machine: "state machine",
  };
  const debts = Object.entries(sourceQuality?.penalties || {})
    .filter(([name, value]) => Number(value) > 0 && debtLabels[name])
    .sort((left, right) => Number(right[1]) - Number(left[1]))
    .slice(0, 3)
    .map(([name, value]) => `${debtLabels[name]} ${Number(value).toFixed(1)}`);
  const qualityLevel = sourceQuality?.level || quality.source_quality_level || "not measured";
  byId("qualityLevel").textContent = debts.length ? `${qualityLevel} · ${debts.join(" · ")}` : qualityLevel;
}

function coverageSummary(payload) {
  const coverage = payload.coverage;
  if (!coverage) return `${payload.adapter || "generic"} · ${payload.backend || "legacy"}`;
  const blocks = coverage.blocks || {};
  const instructions = coverage.instructions || {};
  const normalized = coverage.normalized_instructions || 0;
  const control = coverage.unresolved_control_edges || 0;
  const quality = payload.source_quality;
  const reconstruction = payload.reconstruction_quality || {};
  const equivalent = payload.verification?.runtime?.equivalent ?? payload.verification?.candidate?.runtime?.equivalent;
  const boundedOnly = payload.verification?.runtime?.bounded_only === true || payload.verification?.candidate?.runtime?.bounded_only === true;
  const verified = equivalent === true
    ? boundedOnly ? "bounded runtime match" : "runtime equivalent"
    : equivalent === false ? "runtime mismatch" : "runtime not tested";
  const lifted = blocks.lifted ? `${blocks.lifted} payload blocks lifted` : `${blocks.recovered || 0}/${blocks.total || 0} blocks recovered`;
  const regions = reportMetric(payload, "structured_regions", "regions_structured");
  const structured = regions == null ? "" : ` · ${regions} regions structured`;
  const qualitySummary = quality ? ` · source quality ${quality.score}/100 ${quality.level}` : "";
  const claim = reconstruction.claim === "reconstructed_not_original" ? "reconstructed, not original" : reconstruction.claim === "exact_source" ? "exact source" : null;
  const payloadClosure = coverage.payload_closure || {};
  const closureSummary = payloadClosure.available
    ? ` · ${payloadClosure.static_semantic_lifted}/${payloadClosure.instructions} static VM ops · ${payloadClosure.protector_internal_instructions || 0} protector-internal · ${payloadClosure.unresolved_observed_instructions || 0}/${payloadClosure.static_semantic_unresolved || 0} observed-only`
    : "";
  return `${payload.backend || "native"} · ${claim ? `${claim} · ` : ""}${lifted}${structured}${qualitySummary} · ${normalized}/${instructions.total || 0} normalized · ${control} unresolved edges${closureSummary} · ${verified}`;
}

async function loadFile(file) {
  if (!file) return;
  if (!/\.(?:lua|luau|txt)$/i.test(file.name || "")) throw new Error("Choose a .lua, .luau, or .txt file");
  if (file.size > 1.5 * 1024 * 1024) throw new Error("Script exceeds 1.5 MiB");
  source.value = await file.text();
  invalidateFailureReport();
  byId("sourceName").textContent = file.name;
  updateSource();
  source.focus();
  status(`Loaded ${file.name}`, "ok");
}

function bindDropZone() {
  const editor = source.closest(".editor-shell");
  let depth = 0;
  const hasFiles = (event) => Array.from(event.dataTransfer?.types || []).includes("Files");
  const reset = () => { depth = 0; editor.classList.remove("file-drag-active"); };
  window.addEventListener("dragover", (event) => { if (hasFiles(event)) event.preventDefault(); });
  window.addEventListener("drop", (event) => { if (hasFiles(event)) event.preventDefault(); });
  editor.addEventListener("dragenter", (event) => { if (!hasFiles(event)) return; event.preventDefault(); depth += 1; editor.classList.add("file-drag-active"); });
  editor.addEventListener("dragover", (event) => { if (!hasFiles(event)) return; event.preventDefault(); event.dataTransfer.dropEffect = "copy"; });
  editor.addEventListener("dragleave", () => { depth = Math.max(0, depth - 1); if (!depth) editor.classList.remove("file-drag-active"); });
  editor.addEventListener("drop", async (event) => {
    event.preventDefault();
    event.stopPropagation();
    const files = Array.from(event.dataTransfer?.files || []);
    reset();
    if (files.length !== 1) return status("Drop one script at a time", "bad");
    try { await loadFile(files[0]); } catch (error) { status(error.message, "bad"); }
  });
  window.addEventListener("dragend", reset);
}

async function analyze() {
  if (!source.value.trim()) return status("Paste or upload Luau first", "bad");
  byId("analyze").disabled = true;
  byId("analyze").classList.add("running");
  byId("sendFailedSample").hidden = true;
  byId("resultQuality").hidden = true;
  resetPipeline();
  document.querySelector('[data-stage="detect"]').classList.add("active");
  document.querySelector('[data-stage="detect"] small').textContent = "Starting";
  status("Creating analysis job", "busy");
  try {
    const timeLimit = byId("timeLimitMode").value;
    const requestBody = JSON.stringify({
      source: source.value,
      mode: byId("mode").value,
      profile: byId("profile").value,
      max_passes: Number(byId("maxPasses").value),
      time_limit: timeLimit,
      ...(timeLimit === "custom" ? { wall_timeout: Number(byId("wallTimeout").value) } : {}),
      instruction_budget: Number(byId("instructionBudget").value),
    });
    if (new Blob([requestBody]).size > 4 * 1024 * 1024) throw new Error("Encoded request exceeds 4 MiB");
    const createdResponse = await fetch("/jobs/create", { method: "POST", headers: { "content-type": "application/json" }, body: requestBody });
    const created = await createdResponse.json();
    if (!createdResponse.ok || !created.ok) throw new Error(created.error?.message || "Analysis job could not be created");
    let job;
    while (true) {
      const statusResponse = await fetch(created.links.status, { headers: { accept: "application/json" }, cache: "no-store" });
      const statusPayload = await statusResponse.json();
      if (!statusResponse.ok || !statusPayload.ok) throw new Error(statusPayload.error?.message || "Job status is unavailable");
      job = statusPayload.job;
      renderJob(job);
      if (!["queued", "running"].includes(job.state)) break;
      await sleep(Math.max(250, Number(job.poll_after_ms) || 1000));
    }
    const response = await fetch(created.links.finished, { headers: { accept: "application/json" }, cache: "no-store" });
    const payload = await response.json();
    if (!response.ok || !payload.ok) throw new Error(payload.error?.message || "Analysis failed");
    result = payload;
    for (const name of Object.keys(views)) delete views[name];
    views.source = payload.source?.text || "";
    views.candidate = payload.candidate?.text || "";
    views.lift = payload.readable_lift?.text || "";
    views.disassembly = payload.disassembly?.text || "";
    views.ir = encode(payload.semantic_ir);
    views.cfg = encode(payload.cfg);
    views.graph = encode({
      artifact_graph: payload.artifact_graph,
      candidate_provenance: payload.candidate_provenance,
      payload_closure: payload.payload_closure_ir,
      guard_hotspot: payload.guard_hotspot,
    });
    views.report = encode(payload.report);
    const labels = { recovered_exact: "Exact source", reconstructed: "Reconstructed", disassembled: "Disassembled", blocked: "Blocked" };
    const hasCandidate = payload.status === "blocked" && Boolean(views.candidate);
    byId("resultStatus").textContent = hasCandidate ? "Payload candidate" : labels[payload.status] || payload.status;
    byId("resultStatus").className = `result-status ${payload.status}`;
    renderReconstructionQuality(payload);
    if (payload.status === "blocked") {
      const diagnostic = payload.diagnostics?.[0] || payload.report?.diagnostics?.[0] || {};
      views.source = `SOURCE WITHHELD\n\n[${diagnostic.code || "analysis_blocked"}] ${diagnostic.message || "Complete semantic recovery was not proven."}\n\nNo partial VM wrapper was presented as recovered source.`;
    }
    const preferred = hasCandidate ? "candidate" : payload.status === "blocked" && views.lift ? "lift" : views.source ? "source" : "disassembly";
    showTab(preferred);
    status(labels[payload.status] || "Analysis complete", payload.status === "blocked" ? "bad" : "ok");
    byId("runSummary").textContent = coverageSummary(payload);
    byId("sendFailedSample").hidden = !payload.failure_report?.eligible;
  } catch (error) {
    const active = document.querySelector("#analysisPipeline span.active") || document.querySelector('[data-stage="detect"]');
    active.className = "failed";
    active.querySelector("small").textContent = "Failed";
    status(error.message, "bad");
  } finally {
    byId("analyze").disabled = false;
    byId("analyze").classList.remove("running");
  }
}

selectSegments("modeSegments", "mode");
selectSegments("profileSegments", "profile");
byId("timeLimitMode").addEventListener("change", () => { byId("customTimeRow").hidden = byId("timeLimitMode").value !== "custom"; });
source.addEventListener("input", () => { invalidateFailureReport(); updateSource(); });
bindDropZone();
byId("clear").addEventListener("click", () => { source.value = ""; invalidateFailureReport(); updateSource(); source.focus(); });
byId("uploadFile").addEventListener("click", () => byId("fileInput").click());
byId("fileInput").addEventListener("change", async () => { const file = byId("fileInput").files[0]; if (!file) return; try { await loadFile(file); } catch (error) { status(error.message, "bad"); } finally { byId("fileInput").value = ""; } });
byId("analyze").addEventListener("click", analyze);
byId("resultTabs").addEventListener("click", (event) => { const button = event.target.closest("button[data-tab]"); if (button) showTab(button.dataset.tab); });
byId("resultTabs").addEventListener("keydown", (event) => {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const tabs = [...byId("resultTabs").querySelectorAll("button[data-tab]")];
  const current = tabs.indexOf(document.activeElement);
  if (current < 0) return;
  event.preventDefault();
  const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
  showTab(tabs[next].dataset.tab);
  tabs[next].focus();
});
byId("downloadResult").addEventListener("click", () => { const text = views[activeTab]; if (!text) return; const extension = ["source", "candidate"].includes(activeTab) ? "luau" : ["lift", "disassembly"].includes(activeTab) ? "txt" : "json"; const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([text], { type: "text/plain" })); link.download = `${activeTab}.${extension}`; link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 1000); });
byId("sendFailedSample").addEventListener("click", () => { byId("reportConsent").checked = false; byId("confirmReport").disabled = true; byId("reportId").hidden = true; byId("reportDialog").showModal(); });
byId("reportConsent").addEventListener("change", () => { byId("confirmReport").disabled = !byId("reportConsent").checked; });
byId("closeReport").addEventListener("click", () => byId("reportDialog").close());
byId("cancelReport").addEventListener("click", () => byId("reportDialog").close());
byId("reportForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!result?.failure_report?.token || !byId("reportConsent").checked) return;
  byId("confirmReport").disabled = true;
  byId("confirmReport").textContent = "Sending…";
  let submitted = false;
  try {
    const response = await fetch("/api/deobfuscation-report", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ source: source.value, token: result.failure_report.token, consent: true }) });
    const payload = await response.json();
    if (!response.ok || !payload.ok) throw new Error(payload.error?.message || "Report could not be sent");
    submitted = true;
    byId("reportId").textContent = payload.duplicate ? "This sample is already stored" : `Report ${String(payload.report_id).slice(0, 12)} sent`;
    byId("reportId").hidden = false;
    byId("sendFailedSample").hidden = true;
    status("Failed sample sent for review", "ok");
  } catch (error) {
    status(error.message, "bad");
  } finally {
    byId("confirmReport").textContent = "Send sample";
    byId("confirmReport").disabled = submitted || !byId("reportConsent").checked;
  }
});
loadVerifiedBuildRating();
updateSource();
