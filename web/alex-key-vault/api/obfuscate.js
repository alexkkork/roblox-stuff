module.exports = function handler(_req, res) {
  res.statusCode = 410;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify({
    ok: false,
    error: {
      code: "direct_compile_required",
      message: "Request a compile token from /api/compile-token and send source directly to the worker."
    }
  }));
};
