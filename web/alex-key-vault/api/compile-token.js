const { issueToken } = require("../lib/compile-token");

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(body));
}

function readSmallJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 16 * 1024) {
        reject(new Error("token request is too large"));
        req.destroy();
      } else chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {});
      } catch {
        reject(new Error("invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

module.exports = async function handler(req, res) {
  if (String(req.method || "").toUpperCase() !== "POST") return send(res, 405, { ok: false, error: { code: "method_not_allowed" } });
  try {
    const result = issueToken(req, await readSmallJson(req));
    return send(res, 200, { ok: true, ...result });
  } catch (error) {
    const message = error.message || String(error);
    const status = message.includes("configured") ? 503 : 400;
    return send(res, status, { ok: false, error: { code: status === 503 ? "token_unavailable" : "invalid_request", message } });
  }
};
