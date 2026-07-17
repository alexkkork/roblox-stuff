const crypto = require("crypto");

function sessionSecret() {
  const value = process.env.ALEX_ADMIN_SESSION_SECRET;
  if (value) return Buffer.from(value, "utf8");
  if (process.env.NODE_ENV === "production") throw new Error("admin sessions are not configured");
  return crypto.createHash("sha256").update("alexfuscator-local-admin-session").digest();
}

function sign(part) {
  return crypto.createHmac("sha256", sessionSecret()).update(part).digest("base64url");
}

function verifyPassword(password) {
  const configured = process.env.ALEX_ADMIN_PASSWORD_HASH;
  if (!configured) {
    if (process.env.NODE_ENV === "production") throw new Error("admin login is not configured");
    const expected = Buffer.from(process.env.ALEX_ADMIN_PASSWORD || "admin2-local");
    const actual = Buffer.from(String(password || ""));
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  }
  const [salt, expectedHex, extra] = configured.split(":");
  if (!salt || !expectedHex || extra) throw new Error("admin password hash is malformed");
  const expected = Buffer.from(expectedHex, "hex");
  const actual = crypto.scryptSync(String(password || ""), salt, expected.length);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function issueAdminToken(password) {
  if (!verifyPassword(password)) return null;
  const now = Math.floor(Date.now() / 1000);
  const payload = { v: 1, scope: "admin", iat: now, exp: now + 20 * 60, jti: crypto.randomBytes(18).toString("base64url") };
  const part = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return { token: `${part}.${sign(part)}`, expires_at: payload.exp };
}

function decodeAdminToken(token) {
  const [part, signature, extra] = String(token || "").split(".");
  if (!part || !signature || extra) throw new Error("invalid admin session");
  const expected = Buffer.from(sign(part));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) throw new Error("invalid admin session");
  const payload = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  if (payload.v !== 1 || payload.scope !== "admin" || payload.exp < Math.floor(Date.now() / 1000)) throw new Error("expired admin session");
  return payload;
}

module.exports = { decodeAdminToken, issueAdminToken };
