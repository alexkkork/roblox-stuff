const { issueAdminToken } = require("../lib/admin-auth");
const { workerUrl } = require("../lib/compile-token");

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(body));
}

module.exports = async function handler(req, res) {
  if (String(req.method || "").toUpperCase() !== "POST") return send(res, 405, { ok: false, error: { code: "method_not_allowed" } });
  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 4096) throw new Error("request too large");
      chunks.push(chunk);
    }
    const input = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    const session = issueAdminToken(input.password);
    if (!session) return send(res, 401, { ok: false, error: { code: "invalid_credentials", message: "Invalid admin password." } });
    return send(res, 200, { ok: true, ...session, worker_url: workerUrl(req) });
  } catch (error) {
    const unavailable = String(error.message || "").includes("configured");
    return send(res, unavailable ? 503 : 400, { ok: false, error: { code: unavailable ? "admin_unavailable" : "invalid_request", message: error.message || "Invalid request." } });
  }
};
