const { base64url, hmacBase64url, hkdfSha256, sha256 } = require("./crypto");

const HEADER_NAMES = {
  client: "x-alex-client",
  build: "x-alex-build",
  kid: "x-alex-kid",
  time: "x-alex-time",
  nonce: "x-alex-nonce",
  proof: "x-alex-proof"
};

function header(headers, name) {
  if (!headers) return "";
  const direct = headers[name] || headers[name.toLowerCase()];
  if (Array.isArray(direct)) return String(direct[0] || "");
  return String(direct || "");
}

function canonicalPath(url) {
  return String(url || "/api/keyset").split("?")[0] || "/api/keyset";
}

function proofPayload(fields) {
  return [
    "alex-key-vault-proof-v1",
    String(fields.method || "GET").toUpperCase(),
    fields.path || "/api/keyset",
    fields.client || "",
    fields.build || "",
    fields.kid || "main",
    fields.time || "",
    fields.nonce || ""
  ].join("\n");
}

function makeProof(bootKey, fields) {
  return hmacBase64url(bootKey, proofPayload(fields));
}

function responseAad(fields) {
  return JSON.stringify({
    v: 1,
    method: String(fields.method || "GET").toUpperCase(),
    path: fields.path || "/api/keyset",
    client: fields.client || "",
    build: fields.build || "",
    kid: fields.kid || "main",
    time: fields.time || "",
    nonce: fields.nonce || "",
    serverNonce: fields.serverNonce || ""
  });
}

function deriveResponseKey(bootKey, fields) {
  const salt = sha256(responseAad(fields));
  const info = `alex-key-vault-response-v1:${fields.client}:${fields.build}:${fields.kid}`;
  return hkdfSha256(bootKey, salt, info, 32);
}

function responseAadHash(fields) {
  return base64url(sha256(responseAad(fields)));
}

module.exports = {
  HEADER_NAMES,
  canonicalPath,
  deriveResponseKey,
  header,
  makeProof,
  proofPayload,
  responseAad,
  responseAadHash
};
