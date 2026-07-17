module.exports = function handler(_req, res) {
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify({
    ok: true,
    service: "alex-key-vault",
    protocol: 2,
    source_path: "browser-to-worker",
    worker: process.env.ALEX_WORKER_PUBLIC_URL ? "configured" : "local-default",
    native_fallback: false
  }));
};
