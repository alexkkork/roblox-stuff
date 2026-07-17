const handler = require("../api/keyset");
const { deriveResponseKey, makeProof, responseAad } = require("../lib/protocol");
const { aesGcmDecrypt, decodeKey, randomBase64url } = require("../lib/crypto");
const { normalizeIntent, resolveInputLanguage } = require("../lib/compile-token");

function callApi(req) {
  return new Promise((resolve) => {
    const headers = {};
    const res = {
      statusCode: 200,
      setHeader(name, value) {
        headers[name.toLowerCase()] = value;
      },
      end(body) {
        resolve({ statusCode: this.statusCode, headers, body: body ? String(body) : "" });
      }
    };
    handler(req, res);
  });
}

async function main() {
  const intent = normalizeIntent({ language: "alex", profile: "compatibility" });
  if (intent.language !== "alex") throw new Error("Alex language intent was not preserved");
  if (resolveInputLanguage("auto", "fixture.alex") !== "alex" || resolveInputLanguage("auto", "fixture.luau") !== "luau") {
    throw new Error("automatic input language resolution failed");
  }
  const boot = randomBase64url(32);
  process.env.ALEX_CLIENT_ID = "self-client";
  process.env.ALEX_BUILD_ID = "self-build";
  process.env.ALEX_BOOT_KEY_B64 = boot;
  process.env.ALEX_KEYSET_JSON = JSON.stringify({ payload_key: "alpha", second_layer_key: "beta" });

  const fields = {
    method: "GET",
    path: "/api/keyset",
    client: "self-client",
    build: "self-build",
    kid: "main",
    time: String(Math.floor(Date.now() / 1000)),
    nonce: randomBase64url(24)
  };
  const bootKey = decodeKey(boot, "boot");
  const proof = makeProof(bootKey, fields);
  const response = await callApi({
    method: "GET",
    url: "/api/keyset",
    headers: {
      "x-alex-client": fields.client,
      "x-alex-build": fields.build,
      "x-alex-kid": fields.kid,
      "x-alex-time": fields.time,
      "x-alex-nonce": fields.nonce,
      "x-alex-proof": proof
    }
  });
  if (response.statusCode !== 200) throw new Error(`unexpected status ${response.statusCode}: ${response.body}`);
  const json = JSON.parse(response.body);
  const aadFields = { ...fields, serverNonce: json.serverNonce };
  const responseKey = deriveResponseKey(bootKey, aadFields);
  const decrypted = JSON.parse(aesGcmDecrypt(responseKey, json.body, responseAad(aadFields)).toString("utf8"));
  if (decrypted.keyset.payload_key !== "alpha") throw new Error("decrypted payload mismatch");
  const denied = await callApi({
    method: "GET",
    url: "/api/keyset",
    headers: {
      "x-alex-client": fields.client,
      "x-alex-build": fields.build,
      "x-alex-kid": fields.kid,
      "x-alex-time": fields.time,
      "x-alex-nonce": randomBase64url(24),
      "x-alex-proof": "bad"
    }
  });
  if (denied.statusCode === 200) throw new Error("bad proof was accepted");
  console.log(JSON.stringify({ ok: true, status: response.statusCode, denied: denied.statusCode, decrypted }, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
