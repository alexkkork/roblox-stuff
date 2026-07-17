const { noiseHtml } = require("../lib/noise-html");

module.exports = function handler(req, res) {
  const url = new URL(req.url || "/api/noise404", "https://local.invalid");
  const page = noiseHtml({ real: false, status: 404, path: url.searchParams.get("path") || url.pathname });
  res.statusCode = 404;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(page.html);
};
