const crypto = require("crypto");
const { base64url, fromBase64url, hkdfSha256, randomBase64url, sha256, timingSafeEqualText } = require("./crypto");

const DEFAULT_DB_SIZE = 1000000;

function masterKey() {
  const raw = process.env.ALEX_EXTERNAL_KEY_MASTER_B64 || process.env.ALEX_MASTER_WRAP_KEY_B64 || process.env.ALEX_BOOT_KEY_B64 || "";
  if (raw) return fromBase64url(raw).subarray(0, 32);
  return sha256("alex-external-key-dev-master").subarray(0, 32);
}

function dbSize() {
  const n = Number(process.env.ALEX_EXTERNAL_KEY_DB_SIZE || DEFAULT_DB_SIZE);
  return Number.isFinite(n) && n > 0 ? Math.min(Math.floor(n), 1000000) : DEFAULT_DB_SIZE;
}

function hmac(key, text) {
  return base64url(crypto.createHmac("sha256", key).update(String(text)).digest());
}

function hmacHex(key, text) {
  return crypto.createHmac("sha256", key).update(String(text)).digest("hex");
}

function makeRecord() {
  const size = dbSize();
  const slot = crypto.randomInt(0, size);
  const nonce = crypto.randomBytes(18).toString("hex");
  const signature = hmacHex(masterKey(), `${slot}.${nonce}`).slice(0, 32);
  const slug = `${slot}-${nonce}-${signature}`;
  return {
    slot,
    nonce,
    signature,
    slug,
    path: `/api/external-key?slug=${slug}`
  };
}

function parseSlug(slugText) {
  const slug = String(slugText || "").replace(/^vault-key-/, "").replace(/\.html$/i, "");
  const match = slug.match(/^(\d+)-([0-9a-f]{16,})-([0-9a-f]{16,})$/i) || slug.match(/^(\d+)~([A-Za-z0-9_-]{16,})~([A-Za-z0-9_-]{16,})$/);
  if (!match) return null;
  const slot = Number(match[1]);
  if (!Number.isSafeInteger(slot) || slot < 0 || slot >= dbSize()) return null;
  return {
    slot,
    nonce: match[2],
    signature: match[3],
    slug: `${match[1]}-${match[2]}-${match[3]}`
  };
}

function deriveRecordKey(record) {
  const salt = sha256(`slot:${record.slot}:nonce:${record.nonce}:sig:${record.signature}`);
  return hkdfSha256(masterKey(), salt, `alex-external-payload-key-v1:${record.slot}`, 32);
}

function validateRecord(slugText) {
  const record = parseSlug(slugText);
  if (!record) return null;
  const expected = /^[0-9a-f]+$/i.test(record.signature)
    ? hmacHex(masterKey(), `${record.slot}.${record.nonce}`).slice(0, record.signature.length)
    : hmac(masterKey(), `${record.slot}.${record.nonce}`).slice(0, record.signature.length);
  if (!timingSafeEqualText(expected, record.signature)) return null;
  return record;
}

function hiddenKeyHtml(record, real = true) {
  const key = real ? deriveRecordKey(record) : crypto.randomBytes(32);
  const hex = key.toString("hex");
  const chunks = [];
  for (let i = 0; i < hex.length; i += 8) chunks.push(hex.slice(i, i + 8));
  const seed = `${record.slug}:${real}:${Date.now()}`;
  const junk = [];
  for (let i = 0; i < 3600; i++) {
    const name = base64url(sha256(`${seed}:name:${i}`)).slice(0, 16);
    const value = randomBase64url(18 + (i % 32));
    const tag = ["div", "span", "code", "template", "b", "s"][i % 6];
    junk.push(`<${tag} data-${name}="${value}" class="n${i % 173}" hidden>${randomBase64url(24)}</${tag}>`);
  }
  const fixedNoise = (n) => {
    let out = "";
    while (out.length < n) out += randomBase64url(n);
    return out.slice(0, n);
  };
  const keyNodes = chunks.map((chunk, i) => {
    return `<i data-n="${i}" data-x="${fixedNoise(8)}${chunk}${fixedNoise(7)}" hidden></i>`;
  });
  const mixed = [];
  const total = Math.max(junk.length, keyNodes.length);
  for (let i = 0; i < total; i++) {
    if (junk[i]) mixed.push(junk[i]);
    if (keyNodes[i]) mixed.push(keyNodes[i]);
  }
  return `<!doctype html><html><head><meta charset="utf-8"><title>${real ? "edge" : "cache"}</title><style>body{margin:0;background:#070a0f;color:#121923;font:12px monospace}.w{padding:32px;word-break:break-all;opacity:.17}</style></head><body data-db="${dbSize()}" data-s="${record.slot}"><main class="w">${mixed.join("")}</main></body></html>`;
}

module.exports = {
  DEFAULT_DB_SIZE,
  dbSize,
  deriveRecordKey,
  hiddenKeyHtml,
  makeRecord,
  validateRecord
};
