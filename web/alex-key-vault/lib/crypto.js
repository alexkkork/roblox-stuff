const crypto = require("crypto");

function toBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  return Buffer.from(String(value), "utf8");
}

function base64url(input) {
  return Buffer.from(input).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64url(value) {
  const text = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = text + "=".repeat((4 - (text.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

function decodeKey(value, label = "key") {
  const text = String(value || "").trim();
  if (!text) throw new Error(`${label} is missing`);
  const raw = /^[0-9a-f]{64}$/i.test(text) ? Buffer.from(text, "hex") : fromBase64url(text);
  if (raw.length < 32) throw new Error(`${label} must decode to at least 32 bytes`);
  return raw.subarray(0, 32);
}

function sha256(value) {
  return crypto.createHash("sha256").update(toBuffer(value)).digest();
}

function hmacBase64url(key, value) {
  return base64url(crypto.createHmac("sha256", toBuffer(key)).update(toBuffer(value)).digest());
}

function timingSafeEqualText(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  if (left.length !== right.length) {
    const max = Math.max(left.length, right.length, 32);
    crypto.timingSafeEqual(Buffer.concat([left, Buffer.alloc(max - left.length)]), Buffer.concat([right, Buffer.alloc(max - right.length)]));
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

function hkdfSha256(secret, salt, info, length = 32) {
  return Buffer.from(crypto.hkdfSync("sha256", toBuffer(secret), toBuffer(salt), toBuffer(info), length));
}

function aesGcmEncrypt(key, plaintext, aad = "") {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", toBuffer(key).subarray(0, 32), iv);
  cipher.setAAD(toBuffer(aad));
  const ciphertext = Buffer.concat([cipher.update(toBuffer(plaintext)), cipher.final()]);
  return {
    iv: base64url(iv),
    ciphertext: base64url(ciphertext),
    tag: base64url(cipher.getAuthTag())
  };
}

function aesGcmDecrypt(key, box, aad = "") {
  const decipher = crypto.createDecipheriv("aes-256-gcm", toBuffer(key).subarray(0, 32), fromBase64url(box.iv));
  decipher.setAAD(toBuffer(aad));
  decipher.setAuthTag(fromBase64url(box.tag));
  return Buffer.concat([decipher.update(fromBase64url(box.ciphertext)), decipher.final()]);
}

function randomBase64url(bytes = 32) {
  return base64url(crypto.randomBytes(bytes));
}

module.exports = {
  aesGcmDecrypt,
  aesGcmEncrypt,
  base64url,
  decodeKey,
  fromBase64url,
  hmacBase64url,
  hkdfSha256,
  randomBase64url,
  sha256,
  timingSafeEqualText,
  toBuffer
};
