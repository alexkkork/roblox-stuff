const { del, get, put } = require("@vercel/blob");

const memory = globalThis.__alexDeobfuscationJobs || new Map();
globalThis.__alexDeobfuscationJobs = memory;

const ROOT = "deobfuscation-jobs";
const JOB_TTL_MS = 60 * 60 * 1000;

function blobEnabled() {
  return Boolean(process.env.BLOB_READ_WRITE_TOKEN || (process.env.VERCEL && process.env.BLOB_STORE_ID));
}

function pathname(id, kind) {
  return `${ROOT}/${id}/${kind}.json`;
}

async function streamText(stream) {
  if (!stream) return "";
  return new Response(stream).text();
}

async function readJson(id, kind) {
  if (!blobEnabled()) return memory.get(`${id}:${kind}`) || null;
  const result = await get(pathname(id, kind), { access: "private", useCache: false });
  if (!result?.stream) return null;
  return JSON.parse(await streamText(result.stream));
}

async function writeJson(id, kind, value) {
  if (!blobEnabled()) {
    memory.set(`${id}:${kind}`, structuredClone(value));
    return;
  }
  await put(pathname(id, kind), JSON.stringify(value), {
    access: "private",
    addRandomSuffix: false,
    allowOverwrite: true,
    contentType: "application/json",
    cacheControlMaxAge: 60,
  });
}

async function remove(id, kind) {
  if (!blobEnabled()) {
    memory.delete(`${id}:${kind}`);
    return;
  }
  try { await del(pathname(id, kind)); } catch { /* Expired or already removed. */ }
}

function cleanupMemory() {
  const now = Date.now();
  const expired = new Set();
  for (const [key, value] of memory) {
    if (value?.expires_at && Date.parse(value.expires_at) <= now) expired.add(key.split(":")[0]);
  }
  for (const id of expired) {
    memory.delete(`${id}:request`);
    memory.delete(`${id}:status`);
    memory.delete(`${id}:result`);
  }
}

async function create(id, request, status) {
  cleanupMemory();
  await writeJson(id, "request", request);
  await writeJson(id, "status", status);
}

async function updateStatus(id, update) {
  const current = await readJson(id, "status");
  if (!current) return null;
  const next = typeof update === "function" ? update(structuredClone(current)) : { ...current, ...update };
  next.updated_at = new Date().toISOString();
  next.revision = Number(current.revision || 0) + 1;
  await writeJson(id, "status", next);
  return next;
}

async function finish(id, result, status) {
  await writeJson(id, "result", result);
  await writeJson(id, "status", status);
  await remove(id, "request");
}

async function expire(id) {
  await Promise.all([remove(id, "request"), remove(id, "status"), remove(id, "result")]);
}

module.exports = {
  JOB_TTL_MS,
  create,
  expire,
  finish,
  getRequest: (id) => readJson(id, "request"),
  getResult: (id) => readJson(id, "result"),
  getStatus: (id) => readJson(id, "status"),
  removeRequest: (id) => remove(id, "request"),
  updateStatus,
};
