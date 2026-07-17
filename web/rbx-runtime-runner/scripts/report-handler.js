const { put } = require("@vercel/blob");
const failureToken = require("./failure-report-token");

const SOURCE_LIMIT = 1.5 * 1024 * 1024;
const REQUEST_LIMIT = 4 * 1024 * 1024;

function send(res, status, value) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(value));
}

async function readJson(req) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > REQUEST_LIMIT) throw Object.assign(new Error("report exceeds the size limit"), { status: 413, code: "report_too_large" });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw Object.assign(new Error("invalid JSON"), { status: 400, code: "invalid_request" }); }
}

module.exports = async function reportFailure(req, res) {
  if (req.method !== "POST") return send(res, 405, { ok: false, error: { code: "method_not_allowed" } });
  let reportId = null;
  try {
    const input = await readJson(req);
    if (input.consent !== true) throw Object.assign(new Error("explicit consent is required"), { status: 400, code: "consent_required" });
    const source = String(input.source || "");
    if (!source.trim() || Buffer.byteLength(source) > SOURCE_LIMIT) throw Object.assign(new Error("source is missing or too large"), { status: 400, code: "invalid_source" });
    const verified = failureToken.verify(input.token, source);
    reportId = failureToken.dedupeHash(source);
    const submittedAt = new Date();
    const pathname = `deobfuscation-failures/${reportId}.json`;
    const payload = {
      version: 1,
      report_id: reportId,
      submitted_at: submittedAt.toISOString(),
      delete_after: new Date(submittedAt.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      diagnostic: verified.diagnostic,
      source,
    };
    await put(pathname, JSON.stringify(payload), {
      access: "private",
      addRandomSuffix: false,
      allowOverwrite: false,
      contentType: "application/json",
      cacheControlMaxAge: 60,
    });
    return send(res, 201, { ok: true, report_id: reportId, duplicate: false });
  } catch (error) {
    const duplicate = error?.name === "BlobPreconditionFailedError" || /already exists|precondition/i.test(String(error?.message || ""));
    if (duplicate && reportId) return send(res, 200, { ok: true, report_id: reportId, duplicate: true });
    const known = Number.isInteger(error?.status) && typeof error?.code === "string";
    return send(res, known ? error.status : 503, {
      ok: false,
      error: {
        code: known ? error.code : "report_unavailable",
        message: known ? error.message : "report storage is unavailable",
      },
    });
  }
};
