const crypto = require("crypto");

const PROFILES = new Set(["compatibility", "hardened", "maximum"]);
const RUNTIMES = new Set(["universal", "roblox", "executor"]);
const KEY_MODES = new Set(["standalone", "online"]);
const FORMATS = new Set(["one-line", "pretty"]);
const LANGUAGES = new Set(["auto", "luau", "alex"]);
const LEVELS = new Set(["preset", "off", "standard", "aggressive", "maximum"]);
const BINDINGS = new Set(["portable", "roblox", "executor"]);

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function tokenSecret() {
  const configured = process.env.ALEX_COMPILE_TOKEN_SECRET;
  if (configured) return Buffer.from(configured, "utf8");
  if (process.env.NODE_ENV === "production") throw new Error("compile token service is not configured");
  return crypto.createHash("sha256").update("alexfuscator-local-compile-token").digest();
}

function signPart(part) {
  return base64url(crypto.createHmac("sha256", tokenSecret()).update(part).digest());
}

function encodeToken(payload) {
  const part = base64url(JSON.stringify(payload));
  return `${part}.${signPart(part)}`;
}

function decodeToken(token) {
  const [part, signature, extra] = String(token || "").split(".");
  if (!part || !signature || extra) throw new Error("invalid compile token");
  const expected = Buffer.from(signPart(part));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) throw new Error("invalid compile token");
  const payload = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  if (payload.v !== 2 || !payload.jti || payload.exp < Math.floor(Date.now() / 1000)) throw new Error("expired compile token");
  return payload;
}

function choice(value, allowed, fallback, label) {
  const normalized = String(value || fallback).toLowerCase();
  if (!allowed.has(normalized)) throw new Error(`invalid ${label}`);
  return normalized;
}

function normalizeGameId(value) {
  const text = String(value || "").trim();
  if (!text || text.toLowerCase() === "off" || text.toLowerCase() === "none") return "";
  if (!/^[0-9]+$/.test(text)) throw new Error("game ID must be a positive Roblox universe ID");
  const gameId = BigInt(text);
  if (gameId < 1n || gameId > 9007199254740991n) throw new Error("game ID is outside Luau's exact integer range");
  return gameId.toString();
}

function normalizeIntent(input = {}) {
  const profile = choice(input.profile, PROFILES, "maximum", "profile");
  const runtime = choice(input.runtime, RUNTIMES, "universal", "runtime");
  const keyMode = choice(input.key_mode, KEY_MODES, "standalone", "key mode");
  if (keyMode === "online" && runtime !== "executor") throw new Error("online keys require the executor runtime");
  const advanced = input.advanced || {};
  const analysisNotice = String(input.analysis_notice || "");
  if (analysisNotice.length > 512) throw new Error("analysis notice is too long");
  return {
    language: choice(input.language, LANGUAGES, "auto", "language"),
    profile,
    runtime,
    key_mode: keyMode,
    format: choice(input.format, FORMATS, "one-line", "format"),
    analysis_notice: analysisNotice,
    advanced: {
      control_flow: choice(advanced.control_flow, LEVELS, "preset", "control flow"),
      constant_protection: choice(advanced.constant_protection, LEVELS, "preset", "constant protection"),
      vm_diversity: choice(advanced.vm_diversity, LEVELS, "preset", "VM diversity"),
      tamper_density: choice(advanced.tamper_density, LEVELS, "preset", "tamper density"),
      environment_binding: choice(advanced.environment_binding, BINDINGS, "portable", "environment binding"),
      game_id: normalizeGameId(advanced.game_id)
    }
  };
}

function requestIdentifier(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  const salt = process.env.ALEX_RATE_LIMIT_HMAC_SECRET || tokenSecret();
  return crypto.createHmac("sha256", salt).update(forwarded).digest("hex");
}

function workerUrl(req) {
  if (process.env.ALEX_WORKER_PUBLIC_URL) return process.env.ALEX_WORKER_PUBLIC_URL;
  const host = String(req?.headers?.["x-forwarded-host"] || req?.headers?.host || "").split(",")[0].trim();
  if (process.env.VERCEL && host) {
    const protocol = String(req?.headers?.["x-forwarded-proto"] || "https").split(",")[0].trim();
    return `${protocol}://${host}`;
  }
  return "http://127.0.0.1:8792";
}

function issueToken(req, input) {
  if (Object.prototype.hasOwnProperty.call(input || {}, "source") || Object.prototype.hasOwnProperty.call(input || {}, "script")) {
    throw new Error("source must be sent directly to the compile worker");
  }
  const now = Math.floor(Date.now() / 1000);
  const intent = normalizeIntent(input);
  const payload = {
    v: 2,
    jti: crypto.randomBytes(18).toString("base64url"),
    iat: now,
    exp: now + 90,
    rid: requestIdentifier(req),
    ...intent
  };
  return {
    token: encodeToken(payload),
    expires_at: payload.exp,
    worker_url: workerUrl(req),
    intent
  };
}

module.exports = { decodeToken, encodeToken, issueToken, normalizeGameId, normalizeIntent, workerUrl };
