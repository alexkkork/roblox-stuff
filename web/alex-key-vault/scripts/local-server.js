const fs = require("fs");
const http = require("http");
const path = require("path");
const health = require("../api/health");
const keyset = require("../api/keyset");
const obfuscate = require("../api/obfuscate");
const compileToken = require("../api/compile-token");
const adminSession = require("../api/admin-session");
const privateVault = require("../api/private-vault");
const noise404 = require("../api/noise404");
const externalKey = require("../api/external-key");

const root = path.resolve(__dirname, "..", "public");
const port = Number(process.env.PORT || 8791);

const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8"
};

function adapt(req, res, handler) {
  handler(req, {
    statusCode: 200,
    setHeader(name, value) {
      res.setHeader(name, value);
    },
    end(body) {
      res.statusCode = this.statusCode;
      res.end(body);
    }
  });
}

http.createServer((req, res) => {
  if (req.url.split("?")[0] === "/api/health") return adapt(req, res, health);
  if (req.url.split("?")[0] === "/api/keyset") return adapt(req, res, keyset);
  if (req.url.split("?")[0] === "/api/obfuscate") return adapt(req, res, obfuscate);
  if (req.url.split("?")[0] === "/api/compile-token") return adapt(req, res, compileToken);
  if (req.url.split("?")[0] === "/api/admin-session") return adapt(req, res, adminSession);
  if (req.url.split("?")[0] === "/api/private-vault") return adapt(req, res, privateVault);
  if (req.url.split("?")[0] === "/api/external-key") return adapt(req, res, externalKey);
  if (req.url.split("?")[0].startsWith("/vault-key-")) {
    req.url = `/api/external-key?slug=${encodeURIComponent(req.url.split("?")[0].replace(/^\/vault-key-/, ""))}`;
    return adapt(req, res, externalKey);
  }
  if (req.url.split("?")[0].startsWith("/vault-")) return adapt(req, res, privateVault);
  const requested = req.url.split("?")[0];
  const raw = requested === "/" ? "/index.html" : requested === "/admin2" ? "/admin2.html" : requested;
  const file = path.normalize(path.join(root, raw));
  if (!file.startsWith(root)) {
    res.statusCode = 404;
    return res.end("not found");
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      req.url = `/api/noise404?path=${encodeURIComponent(raw)}`;
      return adapt(req, res, noise404);
    }
    res.setHeader("Content-Type", types[path.extname(file)] || "application/octet-stream");
    res.end(data);
  });
}).listen(port, "127.0.0.1", () => {
  console.log(`Alex Key Vault local: http://127.0.0.1:${port}/`);
});
