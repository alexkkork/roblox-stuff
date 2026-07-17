const crypto = require("crypto");

const MAX_AGE_MS = 15 * 60 * 1000;

function secret() {
  return process.env.DEOBFUSCATION_REPORT_SECRET || "";
}

function validSecret() {
  return Buffer.byteLength(secret()) >= 32;
}

function configured() {
  const blob = Boolean(process.env.BLOB_READ_WRITE_TOKEN)
    || Boolean(process.env.VERCEL_OIDC_TOKEN && process.env.BLOB_STORE_ID);
  return validSecret() && blob && Boolean(process.env.CRON_SECRET);
}

function sourceHash(source) {
  return crypto.createHash("sha256").update(source).digest("hex");
}

function signature(payload) {
  return crypto.createHmac("sha256", secret()).update(payload).digest("base64url");
}

function dedupeHash(source) {
  if (!validSecret()) throw Object.assign(new Error("failure report token is unavailable"), { status: 503, code: "report_unavailable" });
  return crypto.createHmac("sha256", secret()).update("deobfuscation-report\0").update(source).digest("hex");
}

function issue(source, diagnostic) {
  if (!configured()) return null;
  const value = {
    v: 1,
    nonce: crypto.randomUUID(),
    source_hash: sourceHash(source),
    diagnostic: String(diagnostic || "analysis_failed").slice(0, 120),
    expires_at: Date.now() + MAX_AGE_MS,
  };
  const payload = Buffer.from(JSON.stringify(value)).toString("base64url");
  return { token: `${payload}.${signature(payload)}`, ...value };
}

function verify(token, source) {
  if (!validSecret() || typeof token !== "string") throw Object.assign(new Error("failure report token is unavailable"), { status: 503, code: "report_unavailable" });
  const [payload, provided, extra] = token.split(".");
  if (!payload || !provided || extra) throw Object.assign(new Error("invalid failure report token"), { status: 403, code: "invalid_report_token" });
  const expected = signature(payload);
  const left = Buffer.from(provided);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) throw Object.assign(new Error("invalid failure report token"), { status: 403, code: "invalid_report_token" });
  let value;
  try { value = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")); } catch { throw Object.assign(new Error("invalid failure report token"), { status: 403, code: "invalid_report_token" }); }
  if (value.v !== 1 || Date.now() > Number(value.expires_at) || value.source_hash !== sourceHash(source)) {
    throw Object.assign(new Error("failure report token expired or does not match this script"), { status: 403, code: "invalid_report_token" });
  }
  return value;
}

module.exports = { configured, dedupeHash, issue, verify, sourceHash };
