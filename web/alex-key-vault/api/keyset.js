const {
  aesGcmDecrypt,
  aesGcmEncrypt,
  base64url,
  decodeKey,
  fromBase64url,
  randomBase64url,
  sha256,
  timingSafeEqualText
} = require("../lib/crypto");
const {
  HEADER_NAMES,
  canonicalPath,
  deriveResponseKey,
  header,
  makeProof,
  responseAad,
  responseAadHash
} = require("../lib/protocol");

function sendJson(res, status, body, origin) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Access-Control-Allow-Headers", Object.values(HEADER_NAMES).join(", "));
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (origin) res.setHeader("Access-Control-Allow-Origin", origin);
  res.end(JSON.stringify(body));
}

function allowedOrigin(req) {
  const origin = header(req.headers, "origin");
  const allowed = String(process.env.ALEX_ALLOWED_ORIGINS || "*").split(",").map((x) => x.trim()).filter(Boolean);
  if (!origin) return "";
  if (allowed.includes("*") || allowed.includes(origin)) return origin;
  return "";
}

function configuredList(name, fallback) {
  const raw = String(process.env[name] || fallback || "");
  return raw.split(",").map((x) => x.trim()).filter(Boolean);
}

function getBootKey(kid) {
  const keysJson = process.env.ALEX_BOOT_KEYS_JSON;
  if (keysJson) {
    const keys = JSON.parse(keysJson);
    const selected = keys[kid] || keys.main;
    if (!selected) throw new Error("unknown key id");
    return decodeKey(selected, `boot key ${kid}`);
  }
  if (process.env.ALEX_BOOT_KEY_B64) return decodeKey(process.env.ALEX_BOOT_KEY_B64, "ALEX_BOOT_KEY_B64");
  if (process.env.NODE_ENV === "production" || process.env.VERCEL) throw new Error("ALEX_BOOT_KEY_B64 is required");
  return sha256("alex-key-vault-dev-boot-key").subarray(0, 32);
}

function loadKeyset() {
  if (process.env.ALEX_ENCRYPTED_KEYSET) {
    const master = decodeKey(process.env.ALEX_MASTER_WRAP_KEY_B64, "ALEX_MASTER_WRAP_KEY_B64");
    const box = JSON.parse(fromBase64url(process.env.ALEX_ENCRYPTED_KEYSET).toString("utf8"));
    const decoded = aesGcmDecrypt(master, box, "alex-keyset-inner-v1").toString("utf8");
    return JSON.parse(decoded);
  }
  if (process.env.ALEX_KEYSET_JSON) return JSON.parse(process.env.ALEX_KEYSET_JSON);
  return {
    demo: true,
    message: "Set ALEX_KEYSET_JSON or ALEX_ENCRYPTED_KEYSET in Vercel env.",
    createdAt: new Date().toISOString()
  };
}

function validate(req) {
  const path = canonicalPath(req.url);
  const method = String(req.method || "GET").toUpperCase();
  const fields = {
    method,
    path,
    client: header(req.headers, HEADER_NAMES.client),
    build: header(req.headers, HEADER_NAMES.build),
    kid: header(req.headers, HEADER_NAMES.kid) || "main",
    time: header(req.headers, HEADER_NAMES.time),
    nonce: header(req.headers, HEADER_NAMES.nonce),
    proof: header(req.headers, HEADER_NAMES.proof)
  };
  if (method !== "GET") return { ok: false, status: 405, error: "method" };
  if (!fields.client || !fields.build || !fields.time || !fields.nonce || !fields.proof) return { ok: false, status: 404, error: "missing" };
  const clients = configuredList("ALEX_CLIENT_ID", "alex-client");
  const builds = configuredList("ALEX_BUILD_ID", "dev-build");
  if (!clients.includes(fields.client) || !builds.includes(fields.build)) return { ok: false, status: 404, error: "unknown" };
  if (!/^[A-Za-z0-9_-]{16,160}$/.test(fields.nonce)) return { ok: false, status: 404, error: "nonce" };
  const now = Math.floor(Date.now() / 1000);
  const sent = Number(fields.time);
  const skew = Math.max(30, Number(process.env.ALEX_MAX_CLOCK_SKEW_SECONDS || 300));
  if (!Number.isFinite(sent) || Math.abs(now - sent) > skew) return { ok: false, status: 404, error: "time" };
  const bootKey = getBootKey(fields.kid);
  const expected = makeProof(bootKey, fields);
  if (!timingSafeEqualText(expected, fields.proof)) return { ok: false, status: 404, error: "proof" };
  return { ok: true, fields, bootKey };
}

module.exports = function handler(req, res) {
  const origin = allowedOrigin(req);
  if (String(req.method || "").toUpperCase() === "OPTIONS") return sendJson(res, 204, {}, origin || "*");
  if (header(req.headers, "origin") && !origin) return sendJson(res, 404, { ok: false, error: "not_found" }, "");
  try {
    const checked = validate(req);
    if (!checked.ok) return sendJson(res, checked.status, { ok: false, error: "not_found" }, origin || "*");
    const issuedAt = Math.floor(Date.now() / 1000);
    const serverNonce = randomBase64url(24);
    const payload = {
      v: 1,
      client: checked.fields.client,
      build: checked.fields.build,
      kid: checked.fields.kid,
      issuedAt,
      expiresAt: issuedAt + 120,
      keyset: loadKeyset()
    };
    const aadFields = { ...checked.fields, serverNonce };
    const responseKey = deriveResponseKey(checked.bootKey, aadFields);
    const box = aesGcmEncrypt(responseKey, JSON.stringify(payload), responseAad(aadFields));
    return sendJson(res, 200, {
      ok: true,
      v: 1,
      kid: checked.fields.kid,
      serverNonce,
      aadHash: responseAadHash(aadFields),
      body: box,
      receipt: base64url(sha256(`${checked.fields.client}:${checked.fields.build}:${checked.fields.nonce}:${serverNonce}`))
    }, origin || "*");
  } catch (err) {
    return sendJson(res, 404, { ok: false, error: "not_found" }, origin || "*");
  }
};
