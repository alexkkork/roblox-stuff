const $ = (id) => document.getElementById(id);

const aiPrompt = `Return ONLY one JSON object for the RBX Luau Runtime Runner.
Do not use markdown, bullets, commentary, or extra text.
Put the full Luau script in the "script" string. If the script contains backslashes, escape them for JSON.
If you do not have the script yet, return JSON with "script": "PASTE_THE_PROTECTED_LUAU_HERE" and ask me to replace that value.

Schema:
{
  "script": "Luau source to run",
  "profile": "executor-client",
  "executionMode": "diagnostic",
  "analysisHooks": "on",
  "ownerProtection": "respect",
  "networkPolicy": "offline",
  "allowHosts": ["raw.githubusercontent.com"],
  "timeout": 10,
  "captureStringHooks": true,
  "traceCalls": false,
  "tracePcallErrors": true,
  "autorunLoadstring": false,
  "luraphMode": "auto",
  "luraphMaxSteps": 50000000,
  "playerName": "Player",
  "userId": 123456
}

The user will paste your entire answer into /ai. Make it parseable JSON first try.`;

function setStatus(text, kind = "") {
  const el = $("aiStatus");
  el.textContent = text;
  el.className = `status ${kind}`.trim();
}

function normalizeAiText(text) {
  return String(text || "")
    .replace(/^\uFEFF/, "")
    .replace(/[\u200B-\u200D\u2060]/g, "")
    .replace(/\u00A0/g, " ")
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'");
}

function removeTrailingCommasOutsideStrings(text) {
  let out = "";
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === ",") {
      let j = i + 1;
      while (/\s/.test(text[j] || "")) j += 1;
      if (text[j] === "}" || text[j] === "]") continue;
    }
    out += ch;
  }
  return out;
}

function repairJsonStringEscapes(text) {
  let out = "";
  let inString = false;
  let escaped = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];

    if (!inString) {
      out += ch;
      if (ch === '"') inString = true;
      continue;
    }

    if (escaped) {
      escaped = false;
      out += ch;
      continue;
    }

    if (ch === '"') {
      inString = false;
      out += ch;
      continue;
    }

    if (ch === "\\") {
      const next = text[i + 1] || "";
      if (/["\\/bfnrt]/.test(next)) {
        out += ch;
        escaped = true;
      } else if (next === "u" && /^[0-9A-Fa-f]{4}$/.test(text.slice(i + 2, i + 6))) {
        out += ch;
        escaped = true;
      } else {
        out += "\\\\";
      }
      continue;
    }

    if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch < " ") out += `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`;
    else out += ch;
  }

  return out;
}

function jsonObjectCandidates(text) {
  const normalized = normalizeAiText(text).trim();
  if (!normalized) throw new Error("paste the AI response first");

  const candidates = [];
  const fences = normalized.matchAll(/```(?:json|javascript|js)?\s*([\s\S]*?)```/gi);
  for (const match of fences) candidates.push(match[1].trim());
  candidates.push(normalized);

  let start = -1;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < normalized.length; i += 1) {
    const ch = normalized[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
    } else if (ch === "{") {
      if (depth === 0) start = i;
      depth += 1;
    } else if (ch === "}" && depth > 0) {
      depth -= 1;
      if (depth === 0 && start >= 0) candidates.push(normalized.slice(start, i + 1));
    }
  }

  return [...new Set(candidates.filter(Boolean))];
}

function parseJsonCandidate(candidate) {
  const variants = [];
  variants.push(candidate);
  variants.push(removeTrailingCommasOutsideStrings(candidate));
  variants.push(repairJsonStringEscapes(candidate));
  variants.push(repairJsonStringEscapes(removeTrailingCommasOutsideStrings(candidate)));

  let lastError = null;
  for (const variant of [...new Set(variants)]) {
    try {
      const parsed = JSON.parse(variant);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("JSON must be an object");
      return parsed;
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error("invalid JSON");
}

function extractJson(text) {
  const errors = [];
  for (const candidate of jsonObjectCandidates(text)) {
    try {
      return parseJsonCandidate(candidate);
    } catch (err) {
      errors.push(err.message);
    }
  }
  const detail = errors.length ? ` Last parser error: ${errors[errors.length - 1]}` : "";
  throw new Error(`could not find a valid JSON object in that text.${detail}`);
}

function configWarnings(config) {
  const warnings = [];
  const script = String(config.script || "");
  if (/PASTE_THE_PROTECTED_LUAU_HERE/.test(script)) {
    warnings.push("The script field still has the placeholder. Replace PASTE_THE_PROTECTED_LUAU_HERE with the real Luau before running.");
  }
  if (/(^|[^A-Za-z0-9_])\*G\b/.test(script)) {
    warnings.push("The script contains *G. That usually means _G was copied from formatted markdown; copy from a code block or replace it with _G.");
  }
  if (/function\s*\(\s*\*/.test(script)) {
    warnings.push("The script contains function(*, ...). That usually means an underscore parameter was markdown-mangled.");
  }
  return warnings;
}

function normalizeConfig(config) {
  const out = { ...config };
  if (Array.isArray(out.allowHosts)) out.allowHosts = out.allowHosts.join("\n");
  if (!out.profile) out.profile = "executor-client";
  if (!out.analysisHooks) out.analysisHooks = "on";
  if (!out.ownerProtection) out.ownerProtection = "respect";
  if (!out.networkPolicy) out.networkPolicy = "offline";
  if (!out.timeout) out.timeout = 10;
  if (!out.script) out.script = "";
  return out;
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || json.stderr || "runner failed");
  return json;
}

function render(value) {
  $("parsed").textContent = JSON.stringify(value, null, 2);
}

function primaryDiagnostic(data) {
  const diagnostics = data.diagnostics || [];
  return diagnostics.find((line) => !/^Runtime exited with code /.test(line)) || diagnostics[0] || "";
}

let parsedConfig = null;

function setReviewReady(ready) {
  $("runAi").disabled = !ready;
  $("openRunner").disabled = !ready;
}

function parseAi() {
  try {
    parsedConfig = normalizeConfig(extractJson($("aiInput").value));
    render(parsedConfig);
    setReviewReady(true);
    const warnings = configWarnings(parsedConfig);
    setStatus(warnings.length ? `Config ready for review. ${warnings[0]}` : "Config ready. Review it below, then choose where to run it.", warnings.length ? "warn" : "ok");
    return true;
  } catch (err) {
    parsedConfig = null;
    render({});
    setReviewReady(false);
    setStatus(err.message, "bad");
    return false;
  }
}

async function runAi() {
  if (!parsedConfig) {
    setStatus("Extract and review the config before running it.", "warn");
    return;
  }
  $("runAi").disabled = true;
  setStatus("Running...");
  try {
    const data = await postJson("/api/run", parsedConfig);
    $("aiOutput").textContent = JSON.stringify(data, null, 2);
    const firstDiag = primaryDiagnostic(data);
    const diag = firstDiag ? ` ${firstDiag}` : "";
    setStatus(`${data.ok ? "Done" : "Runtime error"} in ${(data.durationMs / 1000).toFixed(2)}s.${diag}`, data.ok ? "ok" : "warn");
  } catch (err) {
    setStatus(err.message, "bad");
  } finally {
    $("runAi").disabled = !parsedConfig;
  }
}

function openInRunner() {
  if (!parsedConfig) {
    setStatus("Extract and review the config before opening it in the Runner.", "warn");
    return;
  }
  localStorage.setItem("rbxRunnerConfig", JSON.stringify(parsedConfig));
  location.href = "/";
}

document.addEventListener("DOMContentLoaded", () => {
  $("prompt").value = aiPrompt;
  $("copyAiPrompt").addEventListener("click", () => {
    navigator.clipboard.writeText(aiPrompt).then(() => setStatus("Prompt copied.", "ok"));
  });
  $("extract").addEventListener("click", parseAi);
  $("runAi").addEventListener("click", runAi);
  $("openRunner").addEventListener("click", openInRunner);
  $("aiInput").addEventListener("input", () => {
    if (!parsedConfig) return;
    parsedConfig = null;
    render({});
    setReviewReady(false);
    setStatus("Response changed. Extract it again to review the latest config.", "warn");
  });
  setReviewReady(false);
});
