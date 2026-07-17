const { randomBase64url } = require("../lib/crypto");

const client = `alex-${randomBase64url(8)}`;
const build = `build-${Date.now().toString(36)}-${randomBase64url(6)}`;
const boot = randomBase64url(32);
const master = randomBase64url(32);

console.log([
  `ALEX_CLIENT_ID=${client}`,
  `ALEX_BUILD_ID=${build}`,
  `ALEX_BOOT_KEY_B64=${boot}`,
  `ALEX_MASTER_WRAP_KEY_B64=${master}`,
  `ALEX_BOOT_KEYS_JSON={"main":"${boot}"}`,
  "ALEX_ALLOWED_ORIGINS=*",
  "ALEX_MAX_CLOCK_SKEW_SECONDS=300"
].join("\n"));
