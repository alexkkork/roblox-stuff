const fs = require("fs");
const path = require("path");
const { aesGcmEncrypt, base64url, decodeKey } = require("../lib/crypto");

function usage() {
  console.error("usage: node scripts/package-keyset.js keyset.json [master-key-base64url]");
  process.exit(1);
}

const input = process.argv[2];
if (!input) usage();

const masterText = process.argv[3] || process.env.ALEX_MASTER_WRAP_KEY_B64;
const master = decodeKey(masterText, "master key");
const keyset = JSON.parse(fs.readFileSync(path.resolve(input), "utf8"));
const box = aesGcmEncrypt(master, JSON.stringify(keyset), "alex-keyset-inner-v1");
const packed = base64url(Buffer.from(JSON.stringify({ v: 1, alg: "A256GCM", ...box }), "utf8"));

console.log(`ALEX_ENCRYPTED_KEYSET=${packed}`);
