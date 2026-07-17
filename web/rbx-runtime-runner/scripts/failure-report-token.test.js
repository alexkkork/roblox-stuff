const assert = require("node:assert/strict");
const test = require("node:test");

const token = require("./failure-report-token");

test("report tokens require the full private-storage contract", () => {
  const previous = {
    secret: process.env.DEOBFUSCATION_REPORT_SECRET,
    blob: process.env.BLOB_READ_WRITE_TOKEN,
    cron: process.env.CRON_SECRET,
  };
  try {
    process.env.DEOBFUSCATION_REPORT_SECRET = "0123456789abcdef0123456789abcdef";
    delete process.env.BLOB_READ_WRITE_TOKEN;
    delete process.env.CRON_SECRET;
    assert.equal(token.configured(), false);
    assert.equal(token.issue("print('private')", "blocked"), null);

    process.env.BLOB_READ_WRITE_TOKEN = "test-private-blob-token";
    process.env.CRON_SECRET = "test-cron-secret";
    assert.equal(token.configured(), true);
    const issued = token.issue("print('private')", "blocked");
    assert.ok(issued?.token);
    assert.equal(token.verify(issued.token, "print('private')").diagnostic, "blocked");
    assert.throws(() => token.verify(issued.token, "print('different')"), /does not match/);
    assert.equal(token.dedupeHash("same"), token.dedupeHash("same"));
    assert.notEqual(token.dedupeHash("same"), token.dedupeHash("different"));
  } finally {
    if (previous.secret === undefined) delete process.env.DEOBFUSCATION_REPORT_SECRET;
    else process.env.DEOBFUSCATION_REPORT_SECRET = previous.secret;
    if (previous.blob === undefined) delete process.env.BLOB_READ_WRITE_TOKEN;
    else process.env.BLOB_READ_WRITE_TOKEN = previous.blob;
    if (previous.cron === undefined) delete process.env.CRON_SECRET;
    else process.env.CRON_SECRET = previous.cron;
  }
});
