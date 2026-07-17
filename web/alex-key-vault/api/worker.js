const workerHandler = require("../worker/server");

const ROUTES = {
  compile: "/v2/compile",
  health: "/health",
  admin_users: "/v2/admin/users",
  admin_credits: "/v2/admin/credits"
};

module.exports = function handler(req, res) {
  const route = String(req.query?.route || "");
  if (route === "key") {
    const capability = String(req.query?.capability || "");
    req.alexPathname = `/v2/key/${encodeURIComponent(capability)}`;
  } else {
    req.alexPathname = ROUTES[route] || "/not-found";
  }
  return workerHandler(req, res);
};
