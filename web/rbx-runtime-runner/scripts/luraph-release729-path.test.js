"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const SITE_ROOT = path.resolve(__dirname, "..");
const PROJECT_ROOT = path.resolve(SITE_ROOT, "..", "..");
const SUBJECT_PATH = path.join(PROJECT_ROOT, "tests", "fixtures", "luraph", "subject_ea93959c47e6.luau");
const BUNDLED_RUNTIME = path.join(SITE_ROOT, "bin", "rbx_luau_runtime-linux-x64");

const SUBJECT_BYTES = 368_779;
const SUBJECT_SHA256 = "ea93959c47e6ada393fdf3d5ad884b6fd713aa5d76ac7259e84bd18464153e15";
const RELEASE_STRINGS = Object.freeze([
  "6e9b580e2e24643214caf0f4bbbb3db911ca30f3",
  "0.729.0.7290838",
  "88de6ce88153b2c7d226d7c2d22752e6e04d266c28b36809d9d61bf8256cf6bd",
  SUBJECT_SHA256,
  "--execution-mode",
  "--deterministic-seed",
  "--filesystem",
]);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

test("the web path preserves the exact hash-pinned Luraph source bytes", () => {
  const source = fs.readFileSync(SUBJECT_PATH);
  assert.equal(source.length, SUBJECT_BYTES);
  assert.equal(sha256(source), SUBJECT_SHA256);

  const prepareRuntimeSource = require("../api/run")._test.prepareRuntimeSource;
  assert.equal(typeof prepareRuntimeSource, "function", "api/run must expose its byte-preserving source preparation contract");
  const prepared = Buffer.from(prepareRuntimeSource(source.toString("utf8")), "utf8");
  assert.equal(prepared.length, SUBJECT_BYTES, "the site must not append a newline or trim the submitted program");
  assert.equal(sha256(prepared), SUBJECT_SHA256, "the runtime must receive the exact submitted program");
});

test("the hosted native artifact is the release-729 runner expected by api/run", () => {
  assert.equal(fs.existsSync(BUNDLED_RUNTIME), true, "the hosted Linux runtime artifact is missing");
  const binary = fs.readFileSync(BUNDLED_RUNTIME);
  for (const value of RELEASE_STRINGS) {
    assert.notEqual(binary.indexOf(Buffer.from(value)), -1, `hosted runtime is missing release-729 contract string: ${value}`);
  }
});

test("the route that owns queued runtime work has the full hosted duration", () => {
  const config = JSON.parse(fs.readFileSync(path.join(SITE_ROOT, "vercel.json"), "utf8"));
  assert.ok(
    Number(config.functions?.["api/run.js"]?.maxDuration) >= 300,
    "api/run creates and owns waitUntil runtime jobs, so its function duration cannot remain at the 60-second synchronous limit",
  );
  assert.ok(Number(config.functions?.["api/jobs.js"]?.maxDuration) >= 300);
});

test("the runner UI identifies the pinned engine release", () => {
  const html = fs.readFileSync(path.join(SITE_ROOT, "public", "index.html"), "utf8");
  assert.match(html, /Release 729\b/);
  assert.doesNotMatch(html, /Release 728\b/);
});
