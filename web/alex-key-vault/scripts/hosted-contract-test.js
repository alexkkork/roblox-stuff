const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

process.env.NODE_ENV = "test";
delete process.env.VERCEL;
process.env.ALEX_COMPILE_TOKEN_SECRET = "alexvm6-hosted-contract-test-secret";
process.env.ALEX_ALLOWED_ORIGINS = "http://127.0.0.1:8791";

const handler = require("../worker/server");
const {
  decodeToken,
  encodeToken,
  issueToken,
  normalizeIntent,
  resolveInputLanguage
} = require("../lib/compile-token");

const FAKE_OUTPUT = "return 42\n";
let tokenSequence = 0;

function nextToken(intent) {
  tokenSequence += 1;
  const now = Math.floor(Date.now() / 1000);
  const jti = `contract-${tokenSequence}-${crypto.randomBytes(8).toString("hex")}`;
  return encodeToken({
    v: 2,
    jti,
    iat: now,
    exp: now + 60,
    rid: crypto.createHash("sha256").update(jti).digest("hex"),
    ...intent
  });
}

function makeRequest({
  language = "auto",
  filename = "fixture.alex",
  profile = "compatibility",
  runtime = "universal",
  keyMode = "standalone",
  gameId = "",
  sourceControl = {}
} = {}) {
  const intent = normalizeIntent({
    language,
    profile,
    runtime,
    key_mode: keyMode,
    advanced: { game_id: gameId }
  });
  return {
    version: 2,
    source: JSON.stringify(sourceControl),
    filename,
    seed: "314159",
    ...intent
  };
}

async function postCompile(baseUrl, request, token, origin = "http://127.0.0.1:8791") {
  const response = await fetch(`${baseUrl}/v2/compile`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Origin: origin
    },
    body: JSON.stringify(request)
  });
  const body = await response.text();
  return { response, body };
}

function writeFakeCompiler(directory) {
  const compilerPath = path.join(directory, "fake-alexfuscator");
  const source = `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : "";
};
let control = {};
try { control = JSON.parse(fs.readFileSync(0, "utf8")); } catch {}
const seed = option("--seed");
const report = {
  report_version: 4,
  backend: "alexvm6",
  vm_version: 6,
  ir_version: 2,
  profile: option("--profile"),
  language: option("--language"),
  fallback_used: false,
  seed: seed === "auto" ? "271828" : seed
};
Object.assign(report, control.override || {});
for (const field of control.remove || []) delete report[field];
fs.writeFileSync(3, Object.prototype.hasOwnProperty.call(control, "raw_report") ? String(control.raw_report) : JSON.stringify(report));
process.stdout.write(${JSON.stringify(FAKE_OUTPUT)});
`;
  fs.writeFileSync(compilerPath, source, { mode: 0o755 });
  return compilerPath;
}

function testLanguageAndTokenRules() {
  assert.equal(normalizeIntent({}).language, "auto");
  assert.equal(normalizeIntent({ language: "ALEX" }).language, "alex");
  assert.equal(normalizeIntent({ language: "LUAU" }).language, "luau");
  assert.throws(() => normalizeIntent({ language: "lua" }), /invalid language/);

  assert.equal(resolveInputLanguage("auto", "fixture.alex"), "alex");
  assert.equal(resolveInputLanguage("auto", "FIXTURE.ALEX"), "alex");
  assert.equal(resolveInputLanguage("auto", "fixture.luau"), "luau");
  assert.equal(resolveInputLanguage("auto", "fixture.lua"), "luau");
  assert.equal(resolveInputLanguage("auto", "fixture.txt"), "luau");
  assert.equal(resolveInputLanguage("auto", "fixture.alex.txt"), "luau");
  assert.equal(resolveInputLanguage("auto"), "luau");
  assert.equal(resolveInputLanguage("luau", "fixture.alex"), "luau");
  assert.equal(resolveInputLanguage("alex", "fixture.luau"), "alex");

  const req = {
    headers: { host: "127.0.0.1:8792", "x-forwarded-for": "192.0.2.10" },
    socket: { remoteAddress: "192.0.2.10" }
  };
  const issued = issueToken(req, { language: "alex", profile: "hardened" });
  const decoded = decodeToken(issued.token);
  assert.equal(decoded.language, "alex");
  assert.equal(decoded.profile, "hardened");
  assert.deepEqual(issued.intent, normalizeIntent({ language: "alex", profile: "hardened" }));
  assert.throws(() => issueToken(req, { language: "alex", source: "print(1)" }), /source must be sent directly/);

  const [part, signature] = issued.token.split(".");
  const replacement = signature.endsWith("A") ? "B" : "A";
  assert.throws(() => decodeToken(`${part}.${signature.slice(0, -1)}${replacement}`), /invalid compile token/);
  const alteredPayload = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  alteredPayload.language = "luau";
  const alteredPart = Buffer.from(JSON.stringify(alteredPayload)).toString("base64url");
  assert.throws(() => decodeToken(`${alteredPart}.${signature}`), /invalid compile token/);
  assert.throws(() => decodeToken(`${issued.token}.extra`), /invalid compile token/);
  assert.throws(() => decodeToken(encodeToken({ ...decoded, v: 1 })), /expired compile token/);
  assert.throws(() => decodeToken(encodeToken({ ...decoded, jti: "" })), /expired compile token/);
  assert.throws(() => decodeToken(encodeToken({ ...decoded, exp: 1 })), /expired compile token/);
}

async function expectSuccessfulCompile(baseUrl, options, expectedLanguage) {
  const request = makeRequest(options);
  const token = nextToken(normalizeIntent(request));
  const { response, body } = await postCompile(baseUrl, request, token);
  assert.equal(response.status, 200, body);
  assert.equal(body, FAKE_OUTPUT);
  assert.match(response.headers.get("content-type") || "", /^application\/x-luau/);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("access-control-allow-origin"), "http://127.0.0.1:8791");
  const exposed = response.headers.get("access-control-expose-headers") || "";
  for (const header of [
    "X-Alex-Build-Id",
    "X-Alex-Seed",
    "X-Alex-Profile",
    "X-Alex-Effective-Profile",
    "X-Alex-Output-Bytes",
    "X-Alex-Backend",
    "X-Alex-VM-Version",
    "X-Alex-IR-Version",
    "X-Alex-Language"
  ]) assert.match(exposed, new RegExp(header), `${header} is not exposed to browsers`);
  assert.equal(response.headers.get("x-alex-backend"), "alexvm6");
  assert.equal(response.headers.get("x-alex-vm-version"), "6");
  assert.equal(response.headers.get("x-alex-ir-version"), "2");
  assert.equal(response.headers.get("x-alex-language"), expectedLanguage);
  assert.equal(response.headers.get("x-alex-profile"), request.profile);
  assert.equal(response.headers.get("x-alex-effective-profile"), request.profile);
  assert.equal(response.headers.get("x-alex-runtime"), request.runtime);
  assert.equal(response.headers.get("x-alex-key-mode"), request.key_mode);
  assert.equal(response.headers.get("x-alex-seed"), request.seed);
  assert.equal(response.headers.get("x-alex-output-bytes"), String(Buffer.byteLength(FAKE_OUTPUT)));
  assert.match(response.headers.get("x-alex-build-id") || "", /^[a-f0-9]{16}$/);
  return response;
}

async function testWorkerContract(baseUrl) {
  const gameLocked = await expectSuccessfulCompile(baseUrl, {
    language: "auto",
    filename: "program.ALEX",
    profile: "hardened",
    runtime: "roblox",
    gameId: "123456789"
  }, "alex");
  assert.equal(gameLocked.headers.get("x-alex-game-lock"), "enabled");

  const explicitLuau = await expectSuccessfulCompile(baseUrl, {
    language: "luau",
    filename: "program.alex"
  }, "luau");
  assert.equal(explicitLuau.headers.get("x-alex-game-lock"), null);
  await expectSuccessfulCompile(baseUrl, {
    language: "alex",
    filename: "program.luau"
  }, "alex");

  const signedRequest = makeRequest({ language: "auto", filename: "signed.alex" });
  const signedToken = nextToken(normalizeIntent(signedRequest));
  signedRequest.language = "alex";
  const mismatch = await postCompile(baseUrl, signedRequest, signedToken);
  assert.equal(mismatch.response.status, 403, mismatch.body);
  assert.equal(JSON.parse(mismatch.body).error.code, "token_mismatch");

  const violations = [
    ["report version", { report_version: 3 }],
    ["report version type", { report_version: "4" }],
    ["backend", { backend: "register_vm_v5" }],
    ["VM version", { vm_version: 5 }],
    ["VM version type", { vm_version: "6" }],
    ["IR version", { ir_version: 1 }],
    ["profile", { profile: "maximum" }],
    ["language", { language: "luau" }],
    ["fallback", { fallback_used: true }],
    ["fallback type", { fallback_used: "false" }]
  ];
  for (const [label, override] of violations) {
    const request = makeRequest({
      language: "auto",
      filename: "contract.alex",
      sourceControl: { override }
    });
    const token = nextToken(normalizeIntent(request));
    const result = await postCompile(baseUrl, request, token);
    assert.equal(result.response.status, 502, `${label}: ${result.body}`);
    assert.equal(JSON.parse(result.body).error.code, "compiler_contract_violation", label);
  }

  for (const field of ["report_version", "backend", "vm_version", "ir_version", "profile", "language", "fallback_used"]) {
    const request = makeRequest({
      language: "auto",
      filename: "missing-field.alex",
      sourceControl: { remove: [field] }
    });
    const result = await postCompile(baseUrl, request, nextToken(normalizeIntent(request)));
    assert.equal(result.response.status, 502, `${field}: ${result.body}`);
    assert.equal(JSON.parse(result.body).error.code, "compiler_contract_violation", field);
  }

  const malformed = makeRequest({
    filename: "malformed-report.alex",
    sourceControl: { raw_report: "not-json" }
  });
  const malformedResult = await postCompile(baseUrl, malformed, nextToken(normalizeIntent(malformed)));
  assert.equal(malformedResult.response.status, 502, malformedResult.body);
  assert.equal(JSON.parse(malformedResult.body).error.code, "compiler_contract_violation");
}

async function main() {
  testLanguageAndTokenRules();
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "alexvm6-contract-"));
  const server = http.createServer(handler);
  try {
    process.env.ALEXFUSCATOR_BINARY = writeFakeCompiler(temporary);
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    await testWorkerContract(`http://127.0.0.1:${address.port}`);
  } finally {
    if (server.listening) await new Promise((resolve) => server.close(resolve));
    fs.rmSync(temporary, { recursive: true, force: true });
  }
  console.log(JSON.stringify({
    ok: true,
    language_cases: 3,
    token_integrity: "passed",
    rejected_report_contracts: 18,
    response_metadata: "passed"
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
