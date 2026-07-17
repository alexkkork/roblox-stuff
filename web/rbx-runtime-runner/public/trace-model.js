(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.RbxTraceModel = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const MAX_EXAMPLES = 6;
  const MAX_TRACE_EVENTS = 220;
  const ENVIRONMENT_SCAN_KIND = /^(?:missing_(?:global|member)|stub_method|unsupported(?:_|$))/i;
  const INTERNAL_CODEGEN_NAMES = new Set([
    "roblox_runtime_setup",
    "roblox_runtime_v2_setup",
    "roblox_high_fidelity_setup",
    "roblox_host_scrub",
    "roblox_analysis_scrub",
    "source_candidate_parse_tmp.lua"
  ]);

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function cleanText(value, fallback = "", limit = 180) {
    const text = String(value == null ? fallback : value)
      .replace(/[\u0000-\u001f\u007f]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    return text.length > limit ? `${text.slice(0, limit - 3)}...` : text;
  }

  function singularOrPlural(count, singular, plural = `${singular}s`) {
    return count === 1 ? singular : plural;
  }

  function createTraceEvent(category, headline, description, confidence = "Direct", raw = null, extra = {}) {
    return {
      category,
      headline,
      description,
      confidence,
      raw,
      ...extra
    };
  }

  function cleanChunkName(name) {
    return cleanText(name, "this chunk", 120).replace(/^=/, "");
  }

  function isInternalCodegenEvent(event, context = {}) {
    const name = cleanChunkName(event?.name).toLowerCase();
    const requestedChunk = cleanChunkName(context.chunkName || "").toLowerCase();
    if (requestedChunk && name === requestedChunk) return false;
    if (INTERNAL_CODEGEN_NAMES.has(name)) return true;
    const basename = name.split(/[\\/]/).pop();
    if (INTERNAL_CODEGEN_NAMES.has(basename)) return true;
    return /^\(?internal\)?$/.test(name) || /^roblox_(?:runtime|host|analysis)_.+_setup$/.test(name);
  }

  function countMatches(source, pattern) {
    return (String(source || "").match(pattern) || []).length;
  }

  function detectWeAreDevsStyle(source) {
    const text = String(source || "");
    const decimalEscapeCount = countMatches(text, /\\\d{3}/g);
    const encodedStringTable = decimalEscapeCount >= 16 && /local\s+[_A-Za-z][_A-Za-z0-9]*\s*=\s*\{\s*["']/s.test(text);
    const permutationLoop = /for\s+[_A-Za-z][_A-Za-z0-9]*\s*,\s*[_A-Za-z][_A-Za-z0-9]*\s+in\s+ipairs\s*\(\s*\{\s*\{/s.test(text) &&
      /while\s+[_A-Za-z][_A-Za-z0-9]*\s*\[[^\]]+\]\s*<\s*[_A-Za-z][_A-Za-z0-9]*\s*\[[^\]]+\]\s*do/s.test(text);
    const decoderPrimitives = ["table.concat", "string.char", "string.sub", "math.floor"]
      .filter((name) => text.includes(name)).length;
    const customAlphabetDecoder = decoderPrimitives >= 3 && /(?:\\061|["']=["'])/.test(text) && /%/.test(text);
    const varargEnvironmentWrapper = /function\s*\(\s*\.\.\.\s*\)/s.test(text) &&
      /getfenv\s+and\s+getfenv\s*\(\s*\)\s*or\s+_ENV/s.test(text);
    const flattenedDispatcher = /while\s+([_A-Za-z][_A-Za-z0-9]*)\s+do\s+if\s+\1\s*</s.test(text);

    const evidence = [];
    if (encodedStringTable) evidence.push("decimal-escaped string table");
    if (permutationLoop) evidence.push("in-place table permutation");
    if (customAlphabetDecoder) evidence.push("custom 64-symbol decoder shape");
    if (varargEnvironmentWrapper) evidence.push("vararg environment wrapper");
    if (flattenedDispatcher) evidence.push("flattened numeric dispatcher");

    return {
      matched: encodedStringTable && customAlphabetDecoder && flattenedDispatcher && (permutationLoop || varargEnvironmentWrapper),
      evidence,
      decimalEscapeCount,
      encodedStringTable,
      customAlphabetDecoder
    };
  }

  function environmentName(event) {
    return cleanText(event?.name || event?.method || event?.member || event?.api || "unnamed API", "unnamed API", 100);
  }

  function summarizeEnvironmentScan(rawEvents) {
    if (!rawEvents.length) return null;
    const byKind = new Map();
    const byName = new Map();
    for (const event of rawEvents) {
      const kind = cleanText(event?.kind, "unsupported", 60);
      const name = environmentName(event);
      byKind.set(kind, (byKind.get(kind) || 0) + 1);
      byName.set(name, (byName.get(name) || 0) + 1);
    }
    const examples = [...byName.entries()]
      .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
      .slice(0, MAX_EXAMPLES);
    const exampleText = examples.map(([name, count]) => `${name} (${count}x)`).join(", ");
    const breakdown = [...byKind.entries()]
      .map(([kind, count]) => `${kind.replaceAll("_", " ")} ${count}`)
      .join(", ");
    const count = rawEvents.length;
    const uniqueCount = byName.size;
    return createTraceEvent(
      "SCAN",
      "Protector/environment scan summarized",
      `Direct evidence: ${count} unavailable or restricted API ${singularOrPlural(count, "check")} were recorded across ${uniqueCount} unique ${singularOrPlural(uniqueCount, "name")}. ` +
        `Examples: ${exampleText || "unnamed API"}. Breakdown: ${breakdown}. Grouping these checks as a protector or host-capability scan is an inference about intent.`,
      "Direct",
      {
        kind: "environment_scan",
        count,
        uniqueCount,
        examples: examples.map(([name, occurrences]) => ({ name, occurrences })),
        byKind: Object.fromEntries(byKind),
        events: rawEvents
      },
      { phase: "PROTECTOR_SCAN", count }
    );
  }

  function explainCompatEvent(event, context = {}) {
    const kind = cleanText(event?.kind, "runtime_event", 80);
    const name = cleanText(event?.name || event?.method || event?.url, "", 180);
    const searchable = `${kind} ${name}`;

    if (kind.includes("native_codegen")) {
      if (kind.includes("unavailable")) return null;
      if (isInternalCodegenEvent(event, context)) return null;
      const label = cleanChunkName(name);
      const compiled = Number(event?.functionsCompiled || 0);
      const total = Number(event?.functionsTotal || 0);
      const partial = kind.includes("partial") || (total > 0 && compiled < total);
      return createTraceEvent(
        "COMPILE",
        partial ? "User chunk was partially compiled" : "User chunk compiled",
        `Direct evidence: the native Luau compiler processed ${label}; ${compiled.toLocaleString()} of ${total.toLocaleString()} functions compiled${event?.result ? ` (${cleanText(event.result, "", 80)})` : ""}.`,
        "Direct",
        event,
        { dedupeKey: `codegen:${kind}:${label}:${compiled}:${total}:${event?.result || ""}` }
      );
    }

    if (/network|http|request/i.test(searchable)) {
      const target = cleanText(event?.url || event?.name || event?.host, "an HTTP(S) target", 180);
      const status = Number(event?.status);
      const action = kind === "network_blocked"
        ? "was blocked by the selected network policy"
        : Number.isFinite(status) && status > 0
          ? `returned HTTP ${status}`
          : "was recorded by the runtime";
      return createTraceEvent(
        "NETWORK",
        kind === "network_blocked" ? "External request blocked" : "External request observed",
        `Direct evidence: ${target} ${action}.`,
        "Direct",
        event,
        { dedupeKey: `network:${kind}:${target}:${Number.isFinite(status) ? status : ""}` }
      );
    }

    if (/pcall|error|exception|fault/i.test(kind)) {
      const detail = cleanText(event?.message || event?.detail || name || kind, "The runtime recorded an error.", 180);
      return createTraceEvent(
        "ERROR",
        kind.includes("pcall") ? "Protected call raised an error" : "Runtime error observed",
        `Direct evidence: ${detail}`,
        "Direct",
        event,
        { dedupeKey: `error:${kind}:${detail}` }
      );
    }

    if (/loadstring|loaded_chunk|bytecode/i.test(searchable)) {
      const label = name || kind;
      return createTraceEvent(
        "UNPACK",
        "Generated Luau chunk observed",
        `Direct evidence: the runtime recorded ${label}. This proves another chunk or bytecode-bearing value appeared, but does not prove that original source was recovered.`,
        "Direct",
        event,
        { dedupeKey: `unpack:${kind}:${label}` }
      );
    }

    if (/concat|gsub|buffer|string|decode|decrypt/i.test(searchable)) {
      const label = name || kind;
      return createTraceEvent(
        "DECODE",
        "Data transformation may be decoder work",
        `Direct evidence: the runtime recorded ${label}. Interpreting that operation as payload decoding is inferred; this event did not expose plaintext source.`,
        "Inferred",
        event,
        { dedupeKey: `decode:${kind}:${label}` }
      );
    }

    const label = name || kind.replaceAll("_", " ");
    return createTraceEvent(
      "RUNTIME",
      kind.replaceAll("_", " "),
      name ? `Direct evidence: the runtime recorded an operation for ${name}.` : "Direct evidence: the runtime recorded a script-visible operation.",
      "Direct",
      event,
      { dedupeKey: `runtime:${kind}:${label}` }
    );
  }

  function summarizeScheduler(scheduler) {
    const rawEvents = asArray(scheduler?.events);
    const errors = [];
    const routine = [];
    for (const event of rawEvents) {
      if (String(event?.kind || "").toLowerCase() === "error") errors.push(event);
      else routine.push(event);
    }

    const narrated = [];
    if (routine.length) {
      const byKind = new Map();
      const frames = new Set();
      let lastTime = 0;
      for (const event of routine) {
        const kind = cleanText(event?.kind, "scheduler event", 60);
        byKind.set(kind, (byKind.get(kind) || 0) + 1);
        if (event?.frame != null) frames.add(String(event.frame));
        const time = Number(event?.time);
        if (Number.isFinite(time)) lastTime = Math.max(lastTime, time);
      }
      const breakdown = [...byKind.entries()]
        .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
        .slice(0, MAX_EXAMPLES)
        .map(([kind, count]) => `${kind.replaceAll("_", " ")} ${count}`)
        .join(", ");
      narrated.push(createTraceEvent(
        "SCHEDULE",
        "Scheduler activity summarized",
        `Direct evidence: ${routine.length} scheduler ${singularOrPlural(routine.length, "record")} were grouped${frames.size ? ` across ${frames.size} ${singularOrPlural(frames.size, "frame")}` : ""} through ${lastTime.toFixed(3)}s. ` +
          `${breakdown || "No event kinds were named"}. Routine resume, yield, and completion bookkeeping is collapsed here; it is not evidence of decoding.`,
        "Direct",
        { kind: "scheduler_summary", count: routine.length, byKind: Object.fromEntries(byKind), events: routine },
        { phase: "SCHEDULER", count: routine.length }
      ));
    }
    for (const event of errors) {
      const detail = cleanText(event?.detail || event?.message || "A scheduled thread failed.", "A scheduled thread failed.", 180);
      narrated.push(createTraceEvent(
        "ERROR",
        "Scheduled thread failed",
        `Direct evidence: ${detail}`,
        "Direct",
        event,
        { dedupeKey: `scheduler-error:${detail}` }
      ));
    }
    for (const error of asArray(scheduler?.errors)) {
      const detail = cleanText(error?.message || error?.detail || error, "A scheduled thread failed.", 180);
      narrated.push(createTraceEvent(
        "ERROR",
        "Scheduler reported an error",
        `Direct evidence: ${detail}`,
        "Direct",
        error,
        { dedupeKey: `scheduler-error:${detail}` }
      ));
    }
    return narrated;
  }

  function outputEvent(stdout) {
    const text = String(stdout || "");
    if (!text.trim()) return null;
    const lines = text.split(/\r?\n/).filter((line) => line.trim());
    const userLines = lines.filter((line) => !/^\s*\[(?:capture|runner)\]/i.test(line));
    const preview = cleanText(userLines[0] || lines[0] || "", "output recorded", 140);
    return createTraceEvent(
      "OUTPUT",
      userLines.length ? "Payload or script output observed" : "Runtime output observed",
      `Direct evidence: stdout contains ${lines.length} non-empty ${singularOrPlural(lines.length, "line")} and ${text.length.toLocaleString()} characters. First visible line: ${preview}. Output alone does not identify how protected code was decoded.`,
      "Direct",
      { kind: "stdout", lines: lines.length, characters: text.length, preview },
      { phase: "PAYLOAD" }
    );
  }

  function collapseRepeatedEvents(events) {
    const collapsed = [];
    const positions = new Map();
    for (const original of events) {
      if (!original) continue;
      const event = { ...original };
      const key = event.dedupeKey || JSON.stringify([event.category, event.headline, event.description]);
      if (!positions.has(key)) {
        positions.set(key, collapsed.length);
        collapsed.push(event);
        continue;
      }
      const existing = collapsed[positions.get(key)];
      existing.count = (existing.count || 1) + 1;
      if (!existing.rawEvents) existing.rawEvents = existing.raw == null ? [] : [existing.raw];
      if (event.raw != null && existing.rawEvents.length < 24) existing.rawEvents.push(event.raw);
    }
    return collapsed.map((event) => {
      if (!event.count || event.count < 2) return event;
      return {
        ...event,
        headline: `${event.headline} (${event.count}x)`,
        description: `${event.description} ${event.count} identical runtime records were grouped into this event.`
      };
    });
  }

  function limitTraceEvents(events) {
    if (events.length <= MAX_TRACE_EVENTS) return events;
    const criticalCategory = /^(?:START|DETECT|DECODE|COMPILE|SCAN|NETWORK|ERROR|OUTPUT|DONE|STOP)$/;
    const critical = new Set(events.filter((event) => criticalCategory.test(event.category)));
    const selected = new Set();
    for (const event of events) {
      if (critical.has(event)) selected.add(event);
    }
    for (const event of events) {
      if (selected.size >= MAX_TRACE_EVENTS) break;
      selected.add(event);
    }
    return events.filter((event) => selected.has(event));
  }

  function buildTraceEvents(data = {}, context = {}) {
    const profile = cleanText(data.runtimeReport?.profile || context.profile, "runtime", 80);
    const clock = cleanText(data.runtimeReport?.clock || context.clock, "virtual", 40);
    const events = [createTraceEvent(
      "START",
      "Runtime process started",
      `Direct evidence: execution started with the ${profile} profile and ${clock} time.`,
      "Direct"
    )];

    const structure = detectWeAreDevsStyle(context.source || data.source || "");
    if (structure.matched) {
      events.push(createTraceEvent(
        "DETECT",
        "WeAreDevs-style VM wrapper detected",
        `Structural inference: the source contains ${structure.evidence.length} independent wrapper traits: ${structure.evidence.join(", ")}. ` +
          "This resembles the WeAreDevs v1 family, but the structure does not reveal the original payload.",
        "Inferred",
        { kind: "wearedevs_style_structure", ...structure },
        { phase: "DETECT" }
      ));
      events.push(createTraceEvent(
        "DECODE",
        "Encoded wrapper constants identified",
        `Structural inference: ${structure.decimalEscapeCount.toLocaleString()} decimal escapes feed a custom character-decoder shape before the flattened dispatcher. ` +
          "This suggests wrapper-constant decoding; no plaintext payload or completed decryption was directly observed.",
        "Inferred",
        { kind: "wearedevs_style_decoder", ...structure },
        { phase: "DECODE" }
      ));
    }

    const compatTrace = asArray(data.compatTrace);
    const scanEvents = compatTrace.filter((event) => ENVIRONMENT_SCAN_KIND.test(String(event?.kind || "")));
    const compatEvents = compatTrace
      .filter((event) => !ENVIRONMENT_SCAN_KIND.test(String(event?.kind || "")))
      .map((event) => explainCompatEvent(event, context))
      .filter(Boolean);
    events.push(...compatEvents.filter((event) => event.category === "COMPILE"));
    events.push(summarizeEnvironmentScan(scanEvents));
    events.push(...compatEvents.filter((event) => event.category !== "COMPILE"));

    for (const item of asArray(data.captureIndex).slice(0, 40)) {
      const name = cleanText(item?.name || item?.path || item?.kind, "captured artifact", 140);
      const generated = /loadstring|loaded_chunk|script|httpget/i.test(name);
      events.push(createTraceEvent(
        generated ? "CAPTURE" : "ARTIFACT",
        generated ? "Generated artifact captured" : "Runtime artifact captured",
        `Direct evidence: ${name} was preserved for inspection${item?.bytes ? ` (${Number(item.bytes).toLocaleString()} bytes)` : ""}. A capture is not original source unless separate source-bearing verification proves it.`,
        "Direct",
        item,
        { dedupeKey: `capture:${item?.kind || ""}:${name}:${item?.bytes || ""}` }
      ));
    }

    events.push(...summarizeScheduler(data.runtimeReport?.scheduler || {}));
    for (const requirement of asArray(data.networkRequirements)) {
      const host = cleanText(requirement?.host, "external host", 120);
      const url = cleanText(requirement?.url, host, 180);
      events.push(createTraceEvent(
        "NETWORK",
        "Network permission required",
        `Direct evidence: ${url} was blocked. The request cannot continue until ${host} is explicitly allowed.`,
        "Direct",
        requirement,
        { dedupeKey: `network-requirement:${host}:${url}` }
      ));
    }

    events.push(outputEvent(data.stdout));
    if (String(data.stderr || "").trim()) {
      const firstLine = String(data.stderr).split(/\r?\n/).find((line) => line.trim()) || "The runtime reported an error.";
      events.push(createTraceEvent(
        "ERROR",
        "Runtime diagnostic",
        `Direct evidence: ${cleanText(firstLine, "The runtime reported an error.", 200)}`,
        "Direct",
        { kind: "stderr", value: firstLine },
        { dedupeKey: `stderr:${cleanText(firstLine, "", 200)}` }
      ));
    }

    const ok = Boolean(data.ok);
    events.push(createTraceEvent(
      ok ? "DONE" : "STOP",
      ok ? "Execution completed" : "Execution stopped",
      `Direct evidence: the runtime reported ${cleanText(data.terminationReason, ok ? "completed" : "runtime_error", 80)} after ${Number(data.durationMs || 0).toLocaleString()} ms.`,
      "Direct"
    ));

    return limitTraceEvents(collapseRepeatedEvents(events.filter(Boolean)));
  }

  return {
    buildTraceEvents,
    collapseRepeatedEvents,
    createTraceEvent,
    detectWeAreDevsStyle,
    explainCompatEvent,
    isInternalCodegenEvent,
    summarizeEnvironmentScan,
    summarizeScheduler
  };
});
