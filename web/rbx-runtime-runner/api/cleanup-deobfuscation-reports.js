const { del, list } = require("@vercel/blob");

module.exports = async function cleanup(req, res) {
  const authorization = String(req.headers?.authorization || "");
  if (!process.env.CRON_SECRET || authorization !== `Bearer ${process.env.CRON_SECRET}`) {
    res.statusCode = 401;
    return res.end(JSON.stringify({ ok: false, error: "unauthorized" }));
  }
  const removeBefore = async (prefix, cutoff) => {
    let cursor;
    let removed = 0;
    do {
      const page = await list({ prefix, cursor, limit: 1000 });
      const expired = page.blobs.filter((blob) => new Date(blob.uploadedAt).getTime() < cutoff);
      if (expired.length) {
        await del(expired.map((blob) => blob.url));
        removed += expired.length;
      }
      cursor = page.hasMore ? page.cursor : undefined;
    } while (cursor);
    return removed;
  };
  const failureReports = await removeBefore("deobfuscation-failures/", Date.now() - 30 * 24 * 60 * 60 * 1000);
  const jobArtifacts = await removeBefore("deobfuscation-jobs/", Date.now() - 2 * 60 * 60 * 1000);
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify({ ok: true, removed: failureReports + jobArtifacts, failure_reports: failureReports, job_artifacts: jobArtifacts }));
};
