const fs = require("fs");
const http = require("http");
const path = require("path");
const run = require("../api/run");
const deobfuscate = require("./deobfuscate-handler");
const jobs = require("./jobs-handler");
const reportFailure = require("./report-handler");
const cleanupReports = require("../api/cleanup-deobfuscation-reports");

const root = path.resolve(__dirname, "..", "public");
const port = Number(process.env.PORT || 8792);
const host = String(process.env.HOST || "127.0.0.1");

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

function staticFileFor(urlPath) {
  if (urlPath === "/") return "/index.html";
  if (urlPath === "/ai") return "/ai.html";
  if (urlPath === "/deobfuscator") return "/deobfuscator.html";
  if (urlPath === "/documentation") return "/documentation.html";
  return urlPath;
}

function setSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'");
}

function runtimeReady() {
  const project = process.env.ALEX_PROJECT_ROOT || path.resolve(__dirname, "..", "..", "..");
  const binary = process.env.RBX_RUNTIME_BINARY || path.join(project, "build", "rbx_luau_runtime");
  try {
    fs.accessSync(binary, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function deobfuscatorReady() {
  const project = process.env.ALEX_PROJECT_ROOT || path.resolve(__dirname, "..", "..", "..");
  const runtime = process.env.RBX_RUNTIME_BINARY || path.join(project, "build", "rbx_luau_runtime");
  const compiler = process.env.ALEXFUSCATOR_BINARY || path.join(project, "build", "alexfuscator");
  const native = process.env.ALEX_DEOBFUSCATOR_BINARY || path.join(project, "build", "alex_deobfuscator");
  return [runtime, compiler, native, path.join(project, "tools", "auto_deobfuscator.py")].every((file) => fs.existsSync(file));
}

http.createServer((req, res) => {
  const urlPath = req.url.split("?")[0];
  setSecurityHeaders(res);
  if (urlPath === "/api/health") {
    const runtime = runtimeReady();
    const deobfuscator = deobfuscatorReady();
    const ready = runtime && deobfuscator;
    res.statusCode = ready ? 200 : 503;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    return res.end(JSON.stringify({ ok: ready, service: "alex-runtime", runtime: runtime ? "ready" : "unavailable", deobfuscator: deobfuscator ? "ready" : "unavailable" }));
  }
  if (urlPath === "/api/run") return adapt(req, res, run);
  if (urlPath === "/api/deobfuscate") return adapt(req, res, deobfuscate);
  if (urlPath === "/api/jobs" || urlPath === "/jobs/create" || urlPath.startsWith("/jobs/status/") || urlPath.startsWith("/jobs/finished/")) return adapt(req, res, jobs);
  if (urlPath === "/api/deobfuscation-report") return adapt(req, res, reportFailure);
  if (urlPath === "/api/cleanup-deobfuscation-reports") return adapt(req, res, cleanupReports);

  const raw = staticFileFor(urlPath);
  const file = path.resolve(root, `.${raw}`);
  if (!file.startsWith(`${root}${path.sep}`)) {
    res.statusCode = 404;
    return res.end("not found");
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.statusCode = 404;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      return res.end("not found");
    }
    res.setHeader("Content-Type", types[path.extname(file)] || "application/octet-stream");
    res.end(data);
  });
}).listen(port, host, () => {
  const displayHost = host === "0.0.0.0" ? "127.0.0.1" : host;
  console.log(`RBX Luau Runtime Runner local: http://${displayHost}:${port}/`);
});
