const crypto = require("crypto");

const password = process.argv[2];
if (!password) {
  console.error("usage: node scripts/hash-admin-password.js PASSWORD");
  process.exit(1);
}
const salt = crypto.randomBytes(16).toString("hex");
const hash = crypto.scryptSync(password, salt, 32).toString("hex");
console.log(`${salt}:${hash}`);
