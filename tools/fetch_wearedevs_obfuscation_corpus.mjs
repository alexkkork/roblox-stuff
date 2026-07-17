import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const project = path.resolve(import.meta.dirname, "..");
const sourceDir = path.join(project, "tests", "deobfuscation_corpus", "source");
const outputDir = path.join(project, "tests", "deobfuscation_corpus", "wearedevs_obfuscated");
const endpoint = "https://wearedevs.net/api/obfuscate";
const delayMs = Math.max(1000, Number(process.env.WRD_DELAY_MS || 1250));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

fs.mkdirSync(outputDir, { recursive: true });
const filenames = fs.readdirSync(sourceDir).filter((name) => name.endsWith(".luau")).sort();
const results = [];
const writeManifest = () => fs.writeFileSync(path.join(outputDir, "manifest.json"), `${JSON.stringify({
  version: 1,
  endpoint,
  fetched_at: new Date().toISOString(),
  request_count: results.filter((item) => item.status === "fetched").length,
  file_count: results.length,
  files: results,
}, null, 2)}\n`);

for (const [offset, filename] of filenames.entries()) {
  const destination = path.join(outputDir, filename);
  const source = fs.readFileSync(path.join(sourceDir, filename), "utf8");
  if (fs.existsSync(destination)) {
    const obfuscated = fs.readFileSync(destination, "utf8");
    results.push({ filename, status: "cached", source_sha256: sha256(source), output_sha256: sha256(obfuscated), output_bytes: Buffer.byteLength(obfuscated) });
    continue;
  }

  let response;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "user-agent": "Alexfuscator-Corpus-Research/1.0",
      },
      body: JSON.stringify({ script: source }),
    });
    if (response.status !== 429 && response.status < 500) break;
    await sleep(delayMs * attempt * 4);
  }

  if (!response.ok) {
    const detail = (await response.text()).slice(0, 300);
    throw new Error(`${filename}: HTTP ${response.status}: ${detail}`);
  }
  const body = await response.json();
  if (body.success !== true || typeof body.obfuscated !== "string" || !body.obfuscated.length) {
    results.push({
      filename,
      status: "rejected",
      source_sha256: sha256(source),
      reason: String(body.message || body.error || "endpoint returned no obfuscated source").slice(0, 300),
    });
    process.stdout.write(`[${offset + 1}/${filenames.length}] rejected ${filename}\n`);
    writeManifest();
    if (offset + 1 < filenames.length) await sleep(delayMs);
    continue;
  }

  fs.writeFileSync(destination, body.obfuscated, "utf8");
  results.push({ filename, status: "fetched", source_sha256: sha256(source), output_sha256: sha256(body.obfuscated), output_bytes: Buffer.byteLength(body.obfuscated) });
  process.stdout.write(`[${offset + 1}/${filenames.length}] ${filename}\n`);
  writeManifest();
  if (offset + 1 < filenames.length) await sleep(delayMs);
}

writeManifest();
const outputCount = results.filter((item) => item.status === "fetched" || item.status === "cached").length;
const rejectedCount = results.filter((item) => item.status === "rejected").length;
console.log(`Saved ${outputCount} obfuscated files; ${rejectedCount} submissions were rejected by the endpoint`);
