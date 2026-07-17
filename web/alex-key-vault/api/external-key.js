const { hiddenKeyHtml, validateRecord } = require("../lib/external-key-vault");

module.exports = function handler(req, res) {
  const url = new URL(req.url || "/api/external-key", "https://local.invalid");
  const slug = url.searchParams.get("slug") || "";
  const record = validateRecord(slug);
  const real = Boolean(record);
  const fallback = record || { slot: 0, nonce: "decoy", signature: "decoy", slug: "decoy" };
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(hiddenKeyHtml(fallback, real));
};
