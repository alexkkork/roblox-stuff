function vaultPage() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Alex Key Vault</title>
    <link rel="stylesheet" href="/styles.css">
  </head>
  <body>
    <main class="shell">
      <section class="hero">
        <div>
          <p class="eyebrow">Alexfuscator key gate</p>
          <h1>Public endpoint, private proof.</h1>
          <p class="sub">Serve encrypted key bundles only to clients that can build the custom proof headers, then wrap every response again per request.</p>
        </div>
        <div class="status" id="health">checking api...</div>
      </section>

      <section class="grid">
        <div class="panel">
          <h2>Build identity</h2>
          <label>Endpoint <input id="endpoint" spellcheck="false"></label>
          <div class="row">
            <label>Client ID <input id="clientId" spellcheck="false" value="alex-client"></label>
            <label>Build ID <input id="buildId" spellcheck="false" value="dev-build"></label>
          </div>
          <label>Key ID <input id="kid" spellcheck="false" value="main"></label>
          <label>Boot key baked into protected code <input id="bootKey" spellcheck="false" placeholder="base64url 32-byte key"></label>
          <label>Master wrap key for encrypted Vercel env <input id="masterKey" spellcheck="false" placeholder="base64url 32-byte key"></label>
          <div class="actions">
            <button id="generateKeys">Generate keys</button>
            <button id="copyEnv">Copy env</button>
          </div>
        </div>

        <div class="panel">
          <h2>Sensitive keyset</h2>
          <textarea id="keysetJson" spellcheck="false">{
  "payload_key": "replace-me",
  "second_layer_key": "replace-me-too",
  "rotation": 1
}</textarea>
          <div class="actions">
            <button id="packageKeyset">Create encrypted env bundle</button>
            <button id="testFetch">Test fetch + decrypt</button>
          </div>
        </div>
      </section>

      <section class="panel wide">
        <h2>Output</h2>
        <pre id="output"></pre>
      </section>
    </main>
    <script src="/app.js"></script>
  </body>
</html>`;
}

module.exports = { vaultPage };
