const crypto = require("crypto");
const { base64url, randomBase64url, sha256 } = require("./crypto");

const TOKEN = "mDRz6Mz5Ym66cly1x9TwT9hLi3D6AKAYkJ2fNl0gicd5dwuaoHRuDx7g54kAJnKO";

function env(name) {
  return String(process.env[name] || "");
}

function generatedKeyBundle(real) {
  if (!real) {
    return {
      kind: "cache_probe",
      client_id: `alex-${randomBase64url(8)}`,
      build_id: `build-${Date.now().toString(36)}-${randomBase64url(6)}`,
      boot_key_b64: randomBase64url(32),
      master_wrap_key_b64: randomBase64url(32),
      boot_keys_json: { main: randomBase64url(32) },
      encrypted_keyset: randomBase64url(96),
      rotation: Math.floor(Math.random() * 9999)
    };
  }
  return {
    kind: "alex_key_vault_bundle_v1",
    client_id: env("ALEX_CLIENT_ID"),
    build_id: env("ALEX_BUILD_ID"),
    boot_key_b64: env("ALEX_BOOT_KEY_B64"),
    master_wrap_key_b64: env("ALEX_MASTER_WRAP_KEY_B64"),
    boot_keys_json: env("ALEX_BOOT_KEYS_JSON"),
    encrypted_keyset: env("ALEX_ENCRYPTED_KEYSET"),
    vault_path_token: env("ALEX_VAULT_PATH_TOKEN") || TOKEN,
    issued_at: new Date().toISOString()
  };
}

function noiseWord(seed, i) {
  const h = sha256(`${seed}:${i}:${randomBase64url(8)}`);
  const s = base64url(h).replace(/[_-]/g, "");
  return s.slice(0, 8 + (h[0] % 18));
}

function splitPayload(text) {
  const raw = base64url(Buffer.from(text, "utf8")).split("").reverse().join("");
  const parts = [];
  let i = 0;
  while (i < raw.length) {
    const n = 7 + (raw.charCodeAt(i) % 19);
    parts.push(raw.slice(i, i + n));
    i += n;
  }
  return parts;
}

function payloadNodes(bundle, seed) {
  const encoded = splitPayload(JSON.stringify(bundle));
  const nodes = [];
  for (let i = 0; i < encoded.length; i++) {
    const id = noiseWord(seed, `p:${i}`);
    const left = randomBase64url(6);
    const right = randomBase64url(5);
    nodes.push(`<i data-k="${id}" data-n="${i}" data-x="${left}${encoded[i]}${right}" hidden></i>`);
  }
  return nodes;
}

function garbageNodes(seed, count) {
  const tags = ["div", "span", "template", "code", "s", "b", "u", "em"];
  const out = [];
  for (let i = 0; i < count; i++) {
    const tag = tags[i % tags.length];
    const a = noiseWord(seed, `a:${i}`);
    const b = randomBase64url(12 + (i % 24));
    const c = randomBase64url(20 + (i % 40));
    const hidden = i % 3 === 0 ? " hidden" : "";
    out.push(`<${tag} data-${a}="${b}" class="x${i % 97}"${hidden}>${c}</${tag}>`);
  }
  return out;
}

function interleave(a, b) {
  const out = [];
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) {
    if (b[i]) out.push(b[i]);
    if (a[i]) out.push(a[i]);
  }
  return out;
}

function noiseHtml({ real = false, status = 404, path = "" } = {}) {
  const seed = `${Date.now()}:${path}:${randomBase64url(16)}`;
  const bundle = generatedKeyBundle(real);
  const payload = payloadNodes(bundle, seed);
  const garbage = garbageNodes(seed, real ? 2600 : 3000);
  const mixed = interleave(payload, garbage).join("");
  const marker = real ? "edge-cache-hit" : "edge-cache-miss";
  const title = real ? "cache" : "not found";
  return {
    status,
    html: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>body{margin:0;background:#080b10;color:#1a202c;font:12px ui-monospace,monospace;overflow:auto}.x1{display:none}.wrap{max-width:1200px;margin:0 auto;padding:24px;opacity:.19;word-break:break-all}.m{color:#263240}</style></head><body data-state="${marker}" data-edge="${randomBase64url(24)}"><main class="wrap"><h1 class="m">${status}</h1>${mixed}</main></body></html>`
  };
}

module.exports = { TOKEN, generatedKeyBundle, noiseHtml };
