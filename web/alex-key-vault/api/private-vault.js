const { timingSafeEqualText } = require("../lib/crypto");
const { TOKEN, noiseHtml } = require("../lib/noise-html");

module.exports = function handler(req, res) {
  const url = new URL(req.url || "/api/private-vault", "https://local.invalid");
  const supplied = url.searchParams.get("token") || url.searchParams.get("slug") || "";
  const expected = process.env.ALEX_VAULT_PATH_TOKEN || TOKEN;
  const real = Boolean(supplied && expected && timingSafeEqualText(supplied, expected));
  const page = noiseHtml({ real, status: 200, path: supplied || url.pathname });
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(page.html);
};
