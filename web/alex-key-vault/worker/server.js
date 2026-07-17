const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { Readable } = require("stream");
const { spawn } = require("child_process");
const { decodeToken, normalizeIntent, resolveInputLanguage } = require("../lib/compile-token");
const { decodeAdminToken } = require("../lib/admin-auth");

const SOURCE_LIMIT = 1.5 * 1024 * 1024;
const IS_VERCEL = Boolean(process.env.VERCEL);
const OUTPUT_LIMIT = IS_VERCEL ? 4 * 1024 * 1024 : 64 * 1024 * 1024;
const TIMEOUT_MS = 5 * 60 * 1000;
const CREDIT_LIMIT = 30;
const CONCURRENCY_LIMIT = 2;
const COSTS = { compatibility: 1, hardened: 2, maximum: 5 };
const LEVEL_FIELDS = ["control_flow", "constant_protection", "vm_diversity", "tamper_density"];
const memoryState = { tokens: new Map(), quotas: new Map(), concurrency: new Map(), bonuses: new Map(), users: new Map() };
let redisPromise;

class RestRedisClient {
  constructor(url, token) {
    this.url = String(url).replace(/\/$/, "");
    this.token = token;
  }

  async command(parts) {
    const response = await fetch(this.url, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
      body: JSON.stringify(parts)
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.error) throw new Error(payload.error || `Redis request failed: ${response.status}`);
    return payload.result;
  }

  eval(script, options) { return this.command(["EVAL", script, String(options.keys.length), ...options.keys, ...options.arguments]); }
  decr(key) { return this.command(["DECR", key]); }
  get(key) { return this.command(["GET", key]); }
  incrBy(key, value) { return this.command(["INCRBY", key, String(value)]); }
  sendCommand(parts) { return this.command(parts); }
  set(key, value, options = {}) {
    const expiry = options.EX ? ["EX", String(options.EX)] : [];
    return this.command(["SET", key, String(value), ...expiry]);
  }
  async hGetAll(key) {
    const values = await this.command(["HGETALL", key]);
    const result = {};
    for (let index = 0; index < (values || []).length; index += 2) result[values[index]] = values[index + 1];
    return result;
  }
  hSet(key, values) {
    return this.command(["HSET", key, ...Object.entries(values).flatMap(([field, value]) => [field, String(value)])]);
  }
  zAdd(key, entry) { return this.command(["ZADD", key, String(entry.score), entry.value]); }
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(body));
}

function allowedOrigin(req, res) {
  const origin = String(req.headers.origin || "");
  const allowed = String(process.env.ALEX_ALLOWED_ORIGINS || "http://127.0.0.1:8791,http://localhost:8791")
    .split(",").map((value) => value.trim()).filter(Boolean);
  if (!origin) return true;
  if (!allowed.includes("*") && !allowed.includes(origin)) return false;
  res.setHeader("Access-Control-Allow-Origin", allowed.includes("*") ? "*" : origin);
  res.setHeader("Vary", "Origin");
  res.setHeader(
    "Access-Control-Expose-Headers",
    [
      "X-Alex-Build-Id",
      "X-Alex-Seed",
      "X-Alex-Profile",
      "X-Alex-Effective-Profile",
      "X-Alex-Runtime",
      "X-Alex-Key-Mode",
      "X-Alex-Game-Lock",
      "X-Alex-Output-Bytes",
      "X-Alex-Backend",
      "X-Alex-VM-Version",
      "X-Alex-IR-Version",
      "X-Alex-Language",
    ].join(","),
  );
  return true;
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > SOURCE_LIMIT + 64 * 1024) throw Object.assign(new Error("source exceeds 1.5 MiB"), { code: "source_too_large", status: 413 });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw Object.assign(new Error("invalid JSON"), { code: "invalid_request", status: 400 });
  }
}

function binaryPath() {
  const localBuild = path.resolve(__dirname, "..", "..", "..", "build", "alexfuscator");
  const linuxBundle = path.resolve(__dirname, "..", "bin", "alexfuscator-linux-x64");
  const candidates = [process.env.ALEXFUSCATOR_BINARY, ...(process.platform === "darwin" ? [localBuild] : [linuxBundle, localBuild])].filter(Boolean);
  return candidates.find((candidate) => {
    try { fs.accessSync(candidate, fs.constants.X_OK); return true; } catch { return false; }
  }) || "";
}

async function redisClient() {
  const restUrl = process.env.UPSTASH_REDIS_REST_URL;
  const restToken = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!process.env.REDIS_URL && !(restUrl && restToken)) return null;
  if (!redisPromise) {
    redisPromise = (async () => {
      if (restUrl && restToken) return new RestRedisClient(restUrl, restToken);
      const { createClient } = require("redis");
      const client = createClient({ url: process.env.REDIS_URL });
      client.on("error", () => {});
      await client.connect();
      return client;
    })();
  }
  return redisPromise;
}

function redisConfigured() {
  return Boolean(process.env.REDIS_URL || (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN));
}

function hourBucket() {
  return Math.floor(Date.now() / 3600000);
}

async function acquire(payload) {
  const cost = COSTS[payload.profile];
  const redis = await redisClient();
  const tokenKey = `alex:v2:token:${payload.jti}`;
  const quotaKey = `alex:v2:quota:${payload.rid}:${hourBucket()}`;
  const concurrencyKey = `alex:v2:concurrency:${payload.rid}`;
  const bonusKey = `alex:v2:bonus:${payload.rid}`;
  const userKey = `alex:v2:user:${payload.rid}`;
  if (redis) {
    const script = `
      if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end
      local quota = tonumber(redis.call('GET', KEYS[2]) or '0')
      local total = quota + tonumber(ARGV[1])
      local overflow = math.max(0, total - tonumber(ARGV[2]))
      local bonus = tonumber(redis.call('GET', KEYS[4]) or '0')
      if overflow > bonus then return -2 end
      local active = tonumber(redis.call('GET', KEYS[3]) or '0')
      if active >= tonumber(ARGV[3]) then return -3 end
      redis.call('SET', KEYS[1], '1', 'EX', ARGV[4])
      redis.call('SET', KEYS[2], math.min(total, tonumber(ARGV[2])), 'EX', 3700)
      if overflow > 0 then redis.call('DECRBY', KEYS[4], overflow) end
      redis.call('INCR', KEYS[3]); redis.call('EXPIRE', KEYS[3], 310)
      redis.call('HSET', KEYS[5], 'last_seen', ARGV[5], 'last_profile', ARGV[6])
      redis.call('ZADD', KEYS[6], ARGV[5], ARGV[7])
      return 1`;
    const result = Number(await redis.eval(script, {
      keys: [tokenKey, quotaKey, concurrencyKey, bonusKey, userKey, "alex:v2:users"],
      arguments: [String(cost), String(CREDIT_LIMIT), String(CONCURRENCY_LIMIT), String(Math.max(1, payload.exp - Math.floor(Date.now() / 1000))), String(Date.now()), payload.profile, payload.rid]
    }));
    if (result !== 1) throwLimit(result);
    return async () => {
      const value = await redis.decr(concurrencyKey);
      if (value < 0) await redis.set(concurrencyKey, "0", { EX: 310 });
    };
  }

  if (process.env.NODE_ENV === "production" && process.env.ALEX_ALLOW_EPHEMERAL_STATE !== "1") {
    throw Object.assign(new Error("Redis is required by the production worker"), { code: "worker_unavailable", status: 503 });
  }
  const now = Date.now();
  if (memoryState.tokens.get(payload.jti) > now) throwLimit(-1);
  const quota = memoryState.quotas.get(quotaKey) || 0;
  const overflow = Math.max(0, quota + cost - CREDIT_LIMIT);
  const bonus = memoryState.bonuses.get(payload.rid) || 0;
  if (overflow > bonus) throwLimit(-2);
  const active = memoryState.concurrency.get(payload.rid) || 0;
  if (active >= CONCURRENCY_LIMIT) throwLimit(-3);
  memoryState.tokens.set(payload.jti, payload.exp * 1000);
  memoryState.quotas.set(quotaKey, Math.min(CREDIT_LIMIT, quota + cost));
  if (overflow) memoryState.bonuses.set(payload.rid, bonus - overflow);
  memoryState.concurrency.set(payload.rid, active + 1);
  memoryState.users.set(payload.rid, { last_seen: Date.now(), last_profile: payload.profile });
  return async () => memoryState.concurrency.set(payload.rid, Math.max(0, (memoryState.concurrency.get(payload.rid) || 1) - 1));
}

function requireAdmin(req) {
  const authorization = String(req.headers.authorization || "");
  if (!authorization.startsWith("Bearer ")) throw Object.assign(new Error("missing admin session"), { code: "admin_unauthorized", status: 401 });
  try { return decodeAdminToken(authorization.slice(7)); }
  catch (error) { throw Object.assign(error, { code: "admin_unauthorized", status: 401 }); }
}

async function listAdminUsers() {
  const redis = await redisClient();
  if (redis) {
    const raw = await redis.sendCommand(["ZREVRANGE", "alex:v2:users", "0", "199", "WITHSCORES"]);
    const entries = [];
    for (let index = 0; index < raw.length; index += 2) entries.push({ rid: raw[index], score: Number(raw[index + 1]) });
    return Promise.all(entries.map(async ({ rid, score }) => {
      const [metadata, usedText, bonusText, activeText] = await Promise.all([
        redis.hGetAll(`alex:v2:user:${rid}`),
        redis.get(`alex:v2:quota:${rid}:${hourBucket()}`),
        redis.get(`alex:v2:bonus:${rid}`),
        redis.get(`alex:v2:concurrency:${rid}`)
      ]);
      const used = Number(usedText || 0);
      const bonus = Number(bonusText || 0);
      return { id: rid, last_seen: Number(metadata.last_seen || score), last_profile: metadata.last_profile || "unknown", used, bonus, active: Number(activeText || 0), available: Math.max(0, CREDIT_LIMIT - used) + bonus };
    }));
  }
  return [...memoryState.users.entries()].sort((a, b) => b[1].last_seen - a[1].last_seen).slice(0, 200).map(([rid, metadata]) => {
    const used = memoryState.quotas.get(`alex:v2:quota:${rid}:${hourBucket()}`) || 0;
    const bonus = memoryState.bonuses.get(rid) || 0;
    return { id: rid, ...metadata, used, bonus, active: memoryState.concurrency.get(rid) || 0, available: Math.max(0, CREDIT_LIMIT - used) + bonus };
  });
}

async function grantCredits(rid, credits) {
  if (!/^[a-f0-9]{64}$/.test(rid)) throw Object.assign(new Error("invalid user identifier"), { code: "invalid_request", status: 400 });
  if (!Number.isInteger(credits) || credits < 1 || credits > 10000) throw Object.assign(new Error("credits must be an integer from 1 to 10000"), { code: "invalid_request", status: 400 });
  const redis = await redisClient();
  if (redis) {
    const bonus = await redis.incrBy(`alex:v2:bonus:${rid}`, credits);
    await Promise.all([
      redis.hSet(`alex:v2:user:${rid}`, { last_adjusted: String(Date.now()) }),
      redis.zAdd("alex:v2:users", { score: Date.now(), value: rid })
    ]);
    return Number(bonus);
  }
  const bonus = (memoryState.bonuses.get(rid) || 0) + credits;
  memoryState.bonuses.set(rid, bonus);
  if (!memoryState.users.has(rid)) memoryState.users.set(rid, { last_seen: Date.now(), last_profile: "unknown" });
  return bonus;
}

function throwLimit(result) {
  if (result === -1) throw Object.assign(new Error("compile token was already used"), { code: "token_consumed", status: 409 });
  if (result === -2) throw Object.assign(new Error("hourly weighted credit limit exceeded"), { code: "rate_limited", status: 429 });
  throw Object.assign(new Error("two compile jobs are already active"), { code: "concurrency_limited", status: 429 });
}

function onlineMasters() {
  if (process.env.ALEX_ONLINE_KEY_MASTERS_JSON) return JSON.parse(process.env.ALEX_ONLINE_KEY_MASTERS_JSON);
  if (process.env.NODE_ENV === "production") throw new Error("online key masters are not configured");
  return { local: "alexfuscator-local-online-master" };
}

function signCapability(part, master) {
  return crypto.createHmac("sha256", master).update(part).digest("base64url");
}

function onlineCapability(jti) {
  const masters = onlineMasters();
  const kid = process.env.ALEX_ONLINE_KEY_ID || Object.keys(masters)[0];
  const master = masters[kid];
  if (!master) throw new Error("active online key id is missing");
  const payload = { v: 1, kid, jti, exp: Math.floor(Date.now() / 1000) + Number(process.env.ALEX_ONLINE_KEY_TTL_SECONDS || 2592000) };
  const part = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const capability = `${part}.${signCapability(part, master)}`;
  const material = Buffer.from(crypto.hkdfSync("sha256", Buffer.from(master), Buffer.from(jti), Buffer.from("alexfuscator-online-v1"), 32)).toString("base64url");
  return { capability, material };
}

function resolveCapability(token) {
  const [part, signature, extra] = String(token || "").split(".");
  if (!part || !signature || extra) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(part, "base64url").toString("utf8")); } catch { return null; }
  const master = onlineMasters()[payload.kid];
  if (!master || payload.v !== 1 || payload.exp < Math.floor(Date.now() / 1000)) return null;
  const expected = Buffer.from(signCapability(part, master));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return null;
  return Buffer.from(crypto.hkdfSync("sha256", Buffer.from(master), Buffer.from(payload.jti), Buffer.from("alexfuscator-online-v1"), 32)).toString("base64url");
}

function validateCompilePayload(input, token) {
  if (input.version !== 2) throw Object.assign(new Error("version must be 2"), { code: "invalid_request", status: 400 });
  const source = String(input.source || "");
  if (!source.trim()) throw Object.assign(new Error("source is required"), { code: "invalid_request", status: 400 });
  if (Buffer.byteLength(source) > SOURCE_LIMIT) throw Object.assign(new Error("source exceeds 1.5 MiB"), { code: "source_too_large", status: 413 });
  const intent = normalizeIntent(input);
  const expected = normalizeIntent(token);
  if (JSON.stringify(intent) !== JSON.stringify(expected)) throw Object.assign(new Error("compile request does not match its token"), { code: "token_mismatch", status: 403 });
  const seed = String(input.seed || "auto");
  if (seed !== "auto" && !/^[0-9]+$/.test(seed)) throw Object.assign(new Error("seed must be auto or an unsigned integer"), { code: "invalid_request", status: 400 });
  const filename = String(input.filename || "script.luau");
  if (filename.length > 255 || /[\\/\0]/.test(filename)) throw Object.assign(new Error("filename must be a simple file name"), { code: "invalid_request", status: 400 });
  const effectiveLanguage = resolveInputLanguage(intent.language, filename);
  return { source, seed, filename, effective_language: effectiveLanguage, ...intent };
}

function compile(binary, request, token) {
  return new Promise((resolve, reject) => {
    const args = ["--stdin", "--stdout", "--diagnostics-json", "--report-fd", "3", "--language", request.effective_language, "--profile", request.profile, "--runtime", request.runtime, "--key-mode", request.key_mode, "--format", request.format, "--seed", request.seed];
    for (const field of LEVEL_FIELDS) args.push(`--${field.replaceAll("_", "-")}`, request.advanced[field]);
    args.push("--environment-binding", request.advanced.environment_binding);
    if (request.advanced.game_id) args.push("--game-id", request.advanced.game_id);
    if (request.analysis_notice) args.push("--analysis-notice", request.analysis_notice);
    if (request.key_mode === "online") {
      const online = onlineCapability(token.jti);
      const origin = String(process.env.ALEX_WORKER_PUBLIC_URL || `http://127.0.0.1:${process.env.PORT || 8792}`).replace(/\/$/, "");
      args.push("--online-key-url", `${origin}/v2/key/${online.capability}`, "--online-key-material", online.material);
    }
    const child = spawn(binary, args, { stdio: ["pipe", "pipe", "pipe", "pipe"], env: { PATH: process.env.PATH || "/usr/bin:/bin" } });
    const output = [];
    let outputBytes = 0;
    let stderr = "";
    let reportText = "";
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      error ? reject(error) : resolve(value);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(Object.assign(new Error("compile exceeded five minutes"), { code: "compile_timeout", status: 504 }));
    }, TIMEOUT_MS);
    child.stdout.on("data", (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > OUTPUT_LIMIT) {
        child.kill("SIGKILL");
        const limit = IS_VERCEL ? "4 MiB" : "64 MiB";
        finish(Object.assign(new Error(`generated output exceeds ${limit}`), { code: "output_too_large", status: 413 }));
      } else output.push(chunk);
    });
    child.stderr.on("data", (chunk) => { if (stderr.length < 65536) stderr += chunk.toString(); });
    child.stdio[3].on("data", (chunk) => { if (reportText.length < 262144) reportText += chunk.toString(); });
    child.on("error", () => finish(Object.assign(new Error("native compiler is unavailable"), { code: "native_unavailable", status: 503 })));
    child.on("close", (code) => {
      if (settled) return;
      if (code !== 0) {
        let diagnostic = { code: "compile_failed", message: "native compiler rejected the input" };
        try { diagnostic = JSON.parse(stderr.trim()).error || diagnostic; } catch {}
        return finish(Object.assign(new Error(diagnostic.message), { code: diagnostic.code || "compile_failed", status: 422, diagnostic }));
      }
      let report = {};
      try { report = JSON.parse(reportText); } catch {}
      if (report.report_version !== 4 || report.backend !== "alexvm6" || report.vm_version !== 6 || report.ir_version !== 2 || report.language !== request.effective_language || report.profile !== request.profile || report.fallback_used !== false) {
        return finish(Object.assign(new Error("native compiler returned an unexpected protection backend"), { code: "compiler_contract_violation", status: 502 }));
      }
      finish(null, { output, outputBytes, report });
    });
    child.stdin.end(request.source);
  });
}

async function handleCompile(req, res) {
  const authorization = String(req.headers.authorization || "");
  if (!authorization.startsWith("Bearer ")) throw Object.assign(new Error("missing compile token"), { code: "unauthorized", status: 401 });
  let token;
  try { token = decodeToken(authorization.slice(7)); } catch (error) { throw Object.assign(error, { code: "unauthorized", status: 401 }); }
  const request = validateCompilePayload(await readJson(req), token);
  const release = await acquire(token);
  try {
    const binary = binaryPath();
    if (!binary) throw Object.assign(new Error("native compiler is unavailable"), { code: "native_unavailable", status: 503 });
    const result = await compile(binary, request, token);
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/x-luau; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Alex-Build-Id", crypto.createHash("sha256").update(`${token.jti}:${result.report.seed || request.seed}`).digest("hex").slice(0, 16));
    res.setHeader("X-Alex-Seed", String(result.report.seed || request.seed));
    res.setHeader("X-Alex-Profile", request.profile);
    res.setHeader("X-Alex-Effective-Profile", String(result.report.profile));
    res.setHeader("X-Alex-Backend", String(result.report.backend));
    res.setHeader("X-Alex-VM-Version", String(result.report.vm_version));
    res.setHeader("X-Alex-IR-Version", String(result.report.ir_version));
    res.setHeader("X-Alex-Language", String(result.report.language));
    res.setHeader("X-Alex-Runtime", request.runtime);
    res.setHeader("X-Alex-Key-Mode", request.key_mode);
    if (request.advanced.game_id) res.setHeader("X-Alex-Game-Lock", "enabled");
    res.setHeader("X-Alex-Output-Bytes", String(result.outputBytes));
    Readable.from(result.output).pipe(res);
  } finally {
    await release();
  }
}

async function handler(req, res) {
  if (!allowedOrigin(req, res)) return json(res, 403, { ok: false, error: { code: "origin_denied" } });
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.setHeader("Access-Control-Allow-Methods", "POST,GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Authorization,Content-Type");
    return res.end();
  }
  const pathname = req.alexPathname || new URL(req.url, "http://worker.local").pathname;
  if (req.method === "GET" && pathname === "/health") return json(res, binaryPath() ? 200 : 503, { ok: Boolean(binaryPath()), service: "alexfuscator-worker-v2", native: Boolean(binaryPath()), redis: redisConfigured() });
  if (req.method === "GET" && pathname.startsWith("/v2/key/")) {
    const material = resolveCapability(decodeURIComponent(pathname.slice("/v2/key/".length)));
    if (!material) return json(res, 404, { ok: false, error: { code: "capability_invalid" } });
    res.statusCode = 200; res.setHeader("Content-Type", "text/plain; charset=utf-8"); res.setHeader("Cache-Control", "no-store"); return res.end(material);
  }
  if (req.method === "GET" && pathname === "/v2/admin/users") {
    try {
      requireAdmin(req);
      const users = await listAdminUsers();
      return json(res, 200, { ok: true, users, summary: { users: users.length, active: users.reduce((sum, user) => sum + user.active, 0), used_this_hour: users.reduce((sum, user) => sum + user.used, 0), bonus_balance: users.reduce((sum, user) => sum + user.bonus, 0) } });
    } catch (error) {
      return json(res, error.status || 500, { ok: false, error: { code: error.code || "admin_error", message: error.message || "Admin request failed." } });
    }
  }
  if (req.method === "POST" && pathname === "/v2/admin/credits") {
    try {
      requireAdmin(req);
      const input = await readJson(req);
      const bonus = await grantCredits(String(input.user_id || ""), Number(input.credits));
      return json(res, 200, { ok: true, user_id: input.user_id, bonus });
    } catch (error) {
      return json(res, error.status || 500, { ok: false, error: { code: error.code || "admin_error", message: error.message || "Admin request failed." } });
    }
  }
  if (req.method === "POST" && pathname === "/v2/compile") {
    try { return await handleCompile(req, res); }
    catch (error) {
      const diagnostic = error.diagnostic || {};
      return json(res, error.status || 500, { ok: false, error: {
        code: error.code || "worker_error",
        message: error.message || "worker error",
        ...(diagnostic.stage ? { stage: diagnostic.stage } : {}),
        ...(diagnostic.language ? { language: diagnostic.language } : {}),
        ...(diagnostic.kind ? { kind: diagnostic.kind } : {}),
        ...(diagnostic.location ? { location: diagnostic.location } : {}),
        ...(diagnostic.prototype ? { prototype: diagnostic.prototype } : {}),
        ...(diagnostic.instruction !== undefined ? { instruction: diagnostic.instruction } : {})
      } });
    }
  }
  return json(res, 404, { ok: false, error: { code: "not_found" } });
}

module.exports = handler;

if (require.main === module) {
  http.createServer(handler).listen(Number(process.env.PORT || 8792), "0.0.0.0");
}
