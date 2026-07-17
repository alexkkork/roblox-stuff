const $ = (id) => document.getElementById(id);
const input = $("input");
const output = $("output");
let fullOutput = "";
let inputFilename = "script.luau";
const byteSize = (value) => new TextEncoder().encode(value).length;
const formatSize = (bytes) => bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1024 / 1024).toFixed(2)} MB`;

const levels = ["preset", "off", "standard", "aggressive", "maximum"];
for (const id of ["controlFlow", "constantProtection", "vmDiversity", "tamperDensity"]) {
  for (const level of levels) {
    const option = document.createElement("option");
    option.value = level;
    option.textContent = level[0].toUpperCase() + level.slice(1);
    $(id).appendChild(option);
  }
}

function status(text, kind = "") {
  $("status").textContent = text;
  $("status").className = kind;
}

function selectedProfile() {
  return document.querySelector('input[name="profile"]:checked').value;
}

function intent() {
  return {
    language: $("language").value,
    profile: selectedProfile(),
    runtime: $("runtime").value,
    key_mode: $("onlineKeys").checked ? "online" : "standalone",
    format: $("format").value,
    analysis_notice: $("analysisNotice").value,
    advanced: {
      control_flow: $("controlFlow").value,
      constant_protection: $("constantProtection").value,
      vm_diversity: $("vmDiversity").value,
      tamper_density: $("tamperDensity").value,
      environment_binding: $("environmentBinding").value,
      game_id: $("gameId").value.trim()
    }
  };
}

async function postJson(url, body, headers = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const failure = await response.json().catch(() => ({}));
    throw new Error(failure.error?.message || failure.error || `request failed: ${response.status}`);
  }
  return response;
}

async function compile() {
  if (!input.value.trim()) return status("Source is empty.", "bad");
  const run = $("run");
  run.disabled = true;
  fullOutput = "";
  output.value = "";
  $("buildMeta").textContent = "";
  try {
    status("Requesting compile token...");
    const selected = intent();
    const tokenResponse = await postJson("/api/compile-token", selected);
    const token = await tokenResponse.json();
    status("Compiling...");
    const response = await postJson(`${token.worker_url.replace(/\/$/, "")}/v2/compile`, {
      version: 2,
      source: input.value,
      filename: inputFilename,
      seed: $("seed").value.trim() || "auto",
      ...selected
    }, { Authorization: `Bearer ${token.token}` });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let received = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      received += value.length;
      fullOutput += decoder.decode(value, { stream: true });
      if (fullOutput.length <= 1_500_000) output.value = fullOutput;
      status(`Receiving ${received.toLocaleString()} bytes...`);
      $("outputMeta").textContent = formatSize(received);
    }
    fullOutput += decoder.decode();
    output.value = fullOutput.length > 1_500_000 ? `${fullOutput.slice(0, 1_500_000)}\n\n-- preview truncated` : fullOutput;
    const build = response.headers.get("X-Alex-Build-Id") || "complete";
    const seed = response.headers.get("X-Alex-Seed") || "auto";
    const backend = response.headers.get("X-Alex-Backend") || "unknown";
    const vmVersion = response.headers.get("X-Alex-VM-Version") || "?";
    const language = response.headers.get("X-Alex-Language") || selected.language;
    const gameLocked = response.headers.get("X-Alex-Game-Lock") === "enabled";
    $("buildMeta").textContent = `${language} · ${selected.profile} · VM ${vmVersion} · ${backend}${gameLocked ? " · game locked" : ""} · seed ${seed} · ${build}`;
    status(`${received.toLocaleString()} bytes`, "ok");
  } catch (error) {
    status(error.message, "bad");
  } finally {
    run.disabled = false;
  }
}

$("onlineKeys").addEventListener("change", () => {
  if ($("onlineKeys").checked) $("runtime").value = "executor";
});
$("runtime").addEventListener("change", () => {
  if ($("runtime").value !== "executor") $("onlineKeys").checked = false;
});
$("environmentBinding").addEventListener("change", () => {
  const binding = $("environmentBinding").value;
  if (binding !== "portable") $("runtime").value = binding;
  if (binding !== "executor") $("onlineKeys").checked = false;
});
$("gameId").addEventListener("input", () => {
  $("gameId").value = $("gameId").value.replace(/\D/g, "").replace(/^0+(?=\d)/, "");
});
$("run").addEventListener("click", compile);
$("clear").addEventListener("click", () => { input.value = ""; input.dispatchEvent(new Event("input")); input.focus(); });
$("open").addEventListener("click", () => $("filePicker").click());
$("filePicker").addEventListener("change", async () => {
  const file = $("filePicker").files[0];
  if (!file) return;
  inputFilename = file.name;
  input.value = await file.text();
  input.dispatchEvent(new Event("input"));
  status(file.name, "ok");
});
input.addEventListener("input", () => { $("inputMeta").textContent = formatSize(byteSize(input.value)); });
input.addEventListener("dragover", (event) => event.preventDefault());
input.addEventListener("drop", async (event) => {
  event.preventDefault();
  const file = event.dataTransfer.files[0];
  if (!file) return;
  inputFilename = file.name;
  input.value = await file.text();
  input.dispatchEvent(new Event("input"));
});
document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") { event.preventDefault(); compile(); }
});
$("copy").addEventListener("click", async () => { await navigator.clipboard.writeText(fullOutput || output.value); status("Copied.", "ok"); });
$("download").addEventListener("click", () => {
  const url = URL.createObjectURL(new Blob([fullOutput || output.value], { type: "application/x-luau" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: "alexfuscated.luau" });
  document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
});

fetch("/api/health").then((response) => response.json()).then((health) => {
  $("health").textContent = health.ok ? "v2 ready" : "offline";
}).catch(() => { $("health").textContent = "offline"; });
input.value = 'print("hello from alexfuscator")';
input.dispatchEvent(new Event("input"));
