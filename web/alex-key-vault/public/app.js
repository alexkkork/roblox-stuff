const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToBase64url(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64urlToBytes(value) {
  const padded = String(value || "").replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (String(value || "").length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function randomBase64url(bytes = 32) {
  const out = new Uint8Array(bytes);
  crypto.getRandomValues(out);
  return bytesToBase64url(out);
}

async function sha256Bytes(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

async function hmacBase64url(keyBytes, text) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(text));
  return bytesToBase64url(new Uint8Array(sig));
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
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

async function deriveResponseKey(bootKeyBytes, fields) {
  const salt = await sha256Bytes(responseAad(fields));
  const base = await crypto.subtle.importKey("raw", bootKeyBytes, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: enc.encode(`alex-key-vault-response-v1:${fields.client}:${fields.build}:${fields.kid}`)
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function decryptResponseBox(bootKeyText, requestFields, response) {
  const fields = { ...requestFields, serverNonce: response.serverNonce };
  const key = await deriveResponseKey(base64urlToBytes(bootKeyText), fields);
  const data = concatBytes(base64urlToBytes(response.body.ciphertext), base64urlToBytes(response.body.tag));
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64urlToBytes(response.body.iv),
      additionalData: enc.encode(responseAad(fields)),
      tagLength: 128
    },
    key,
    data
  );
  return JSON.parse(dec.decode(plaintext));
}

async function encryptInnerKeyset(masterKeyText, keyset) {
  const key = await crypto.subtle.importKey("raw", base64urlToBytes(masterKeyText), "AES-GCM", false, ["encrypt"]);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: enc.encode("alex-keyset-inner-v1"),
      tagLength: 128
    },
    key,
    enc.encode(JSON.stringify(keyset))
  ));
  const box = {
    v: 1,
    alg: "A256GCM",
    iv: bytesToBase64url(iv),
    ciphertext: bytesToBase64url(encrypted.subarray(0, encrypted.length - 16)),
    tag: bytesToBase64url(encrypted.subarray(encrypted.length - 16))
  };
  return bytesToBase64url(enc.encode(JSON.stringify(box)));
}

function currentEnvText(encryptedKeyset = "") {
  return [
    `ALEX_CLIENT_ID=${$("clientId").value.trim()}`,
    `ALEX_BUILD_ID=${$("buildId").value.trim()}`,
    `ALEX_BOOT_KEY_B64=${$("bootKey").value.trim()}`,
    `ALEX_MASTER_WRAP_KEY_B64=${$("masterKey").value.trim()}`,
    encryptedKeyset ? `ALEX_ENCRYPTED_KEYSET=${encryptedKeyset}` : `ALEX_KEYSET_JSON=${JSON.stringify(JSON.parse($("keysetJson").value))}`,
    "ALEX_ALLOWED_ORIGINS=*",
    "ALEX_MAX_CLOCK_SKEW_SECONDS=300"
  ].join("\n");
}

function writeOutput(value) {
  $("output").textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function testFetch() {
  const endpoint = $("endpoint").value.trim() || `${location.origin}/api/keyset`;
  const url = new URL(endpoint, location.href);
  const fields = {
    method: "GET",
    path: url.pathname,
    client: $("clientId").value.trim(),
    build: $("buildId").value.trim(),
    kid: $("kid").value.trim() || "main",
    time: String(Math.floor(Date.now() / 1000)),
    nonce: randomBase64url(24)
  };
  const proof = await hmacBase64url(base64urlToBytes($("bootKey").value.trim()), proofPayload(fields));
  const response = await fetch(url.toString(), {
    method: "GET",
    headers: {
      "x-alex-client": fields.client,
      "x-alex-build": fields.build,
      "x-alex-kid": fields.kid,
      "x-alex-time": fields.time,
      "x-alex-nonce": fields.nonce,
      "x-alex-proof": proof
    }
  });
  const json = await response.json();
  if (!response.ok || !json.ok) throw new Error(JSON.stringify(json));
  const decrypted = await decryptResponseBox($("bootKey").value.trim(), fields, json);
  writeOutput({ requestHeaders: { ...fields, proof }, encryptedResponse: json, decrypted });
}

async function packageKeyset() {
  const keyset = JSON.parse($("keysetJson").value);
  const encrypted = await encryptInnerKeyset($("masterKey").value.trim(), keyset);
  writeOutput(`${currentEnvText(encrypted)}\n\nvercel env add ALEX_ENCRYPTED_KEYSET production`);
}

async function refreshHealth() {
  try {
    const res = await fetch("/api/health");
    const json = await res.json();
    $("health").textContent = json.ok ? "api online" : "api error";
  } catch {
    $("health").textContent = "api offline";
  }
}

$("endpoint").value = `${location.origin}/api/keyset`;
async function initDevDefaults() {
  if (["127.0.0.1", "localhost"].includes(location.hostname) && !$("bootKey").value.trim()) {
    $("bootKey").value = bytesToBase64url(await sha256Bytes("alex-key-vault-dev-boot-key"));
    $("masterKey").value = randomBase64url(32);
  }
}
$("generateKeys").addEventListener("click", () => {
  $("bootKey").value = randomBase64url(32);
  $("masterKey").value = randomBase64url(32);
  writeOutput(currentEnvText());
});
$("copyEnv").addEventListener("click", async () => {
  const text = currentEnvText();
  await navigator.clipboard.writeText(text);
  writeOutput(`${text}\n\ncopied`);
});
$("packageKeyset").addEventListener("click", () => packageKeyset().catch((err) => writeOutput(`error: ${err.message}`)));
$("testFetch").addEventListener("click", () => testFetch().catch((err) => writeOutput(`error: ${err.message}`)));
refreshHealth();
initDevDefaults();
