#!/usr/bin/env python3
"""Local web UI for the WeAreDevs deobfuscator."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import wearedevs_deobfuscator as wd  # noqa: E402
import local_luau_deobfuscator as locald  # noqa: E402

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
WEB_ROOT = PROJECT_ROOT / "outputs" / "wearedevs_web"
REQUEST_ROOT = WEB_ROOT / "requests"
RUN_ROOT = WEB_ROOT / "runs"
LOCAL_RUN_ROOT = WEB_ROOT / "local_runs"
DEOBF_LOCK = threading.Lock()


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return {}
    return json.loads(handler.rfile.read(length).decode())


def safe_stem(value: str) -> str:
    value = Path(value or "pasted_script.lua").name
    if not value.endswith((".lua", ".luau", ".txt")):
        value += ".lua"
    return wd.slugify(Path(value).stem) + ".lua"


def render_index() -> bytes:
    return INDEX_HTML.encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "WeAreDevsDeobfuscator/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print("[web] " + fmt % args)

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = render_index()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = render_index()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/file":
            query = parse_qs(parsed.query)
            path = Path(query.get("path", [""])[0]).resolve()
            try:
                path.relative_to(WEB_ROOT.resolve())
            except ValueError:
                json_response(self, 403, {"ok": False, "error": "path outside web output root"})
                return
            if not path.exists() or not path.is_file():
                json_response(self, 404, {"ok": False, "error": "file not found"})
                return
            body = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        json_response(self, 404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/deobfuscate":
            self.handle_deobfuscate()
            return
        if parsed.path == "/api/open-output":
            self.handle_open_output()
            return
        json_response(self, 404, {"ok": False, "error": "not found"})

    def handle_deobfuscate(self) -> None:
        try:
            payload = read_json(self)
            source = str(payload.get("script", ""))
            if not source.strip():
                json_response(self, 400, {"ok": False, "error": "paste a script first"})
                return

            request_id = time.strftime("%Y%m%d_%H%M%S") + f"_{os.getpid()}_{time.time_ns() % 1_000_000_000:09d}"
            request_dir = REQUEST_ROOT / request_id
            request_dir.mkdir(parents=True, exist_ok=True)
            input_path = request_dir / safe_stem(str(payload.get("filename", "pasted_script.lua")))
            input_path.write_text(source.rstrip("\n") + "\n")

            capture = io.StringIO()
            with DEOBF_LOCK:
                with contextlib.redirect_stdout(capture):
                    mode = str(payload.get("mode", "auto"))
                    if mode == "local" or (mode == "auto" and not locald.looks_like_wearedevs(source)):
                        report = locald.deobfuscate_file(input_path, LOCAL_RUN_ROOT, open_output=False)
                    elif mode == "wearedevs_static" or payload.get("static_only"):
                        report = wd.deobfuscate_static_only(input_path, RUN_ROOT, open_output=False)
                    else:
                        runtime = wd.pick_runtime(None)
                        report = wd.deobfuscate(input_path, RUN_ROOT, runtime, open_output=False)

            final_path = Path(report["final_source"])
            output = final_path.read_text(errors="replace")
            compact_report = {
                "final_kind": report.get("final_kind"),
                "verified_same_behavior": report.get("verified_same_behavior"),
                "verified_same_return": report.get("verified_same_return"),
                "verified_same_stdout": report.get("verified_same_stdout"),
                "semantic_recovery_status": report.get("semantic_recovery_status"),
                "exact_recovery_status": report.get("exact_recovery_status"),
                "output_dir": report.get("output_dir"),
                "final_source": report.get("final_source"),
                "report_path": report.get("report_path") or str(Path(report["output_dir"]) / "wearedevs_deobfuscation_report.json"),
                "mode": report.get("mode"),
            }
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "output": output,
                    "log": capture.getvalue(),
                    "report": compact_report,
                    "download_url": "/api/file?path=" + quote(str(final_path)),
                },
            )
        except Exception as exc:
            json_response(
                self,
                500,
                {
                    "ok": False,
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )

    def handle_open_output(self) -> None:
        try:
            payload = read_json(self)
            path = Path(str(payload.get("path", ""))).resolve()
            try:
                path.relative_to(WEB_ROOT.resolve())
            except ValueError:
                json_response(self, 403, {"ok": False, "error": "path outside web output root"})
                return
            if not path.exists():
                json_response(self, 404, {"ok": False, "error": "folder not found"})
                return
            if sys.platform == "darwin":
                ok = subprocess.run(["open", str(path)], check=False).returncode == 0
            else:
                ok = False
            json_response(self, 200, {"ok": ok})
        except Exception as exc:
            json_response(self, 500, {"ok": False, "error": str(exc)})


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Luau Deobfuscator</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #111316;
      --panel: #181b20;
      --panel-2: #20242b;
      --line: #303641;
      --text: #edf1f7;
      --muted: #a8b1bf;
      --accent: #62c77b;
      --accent-2: #65a8ff;
      --danger: #ff7777;
      --shadow: rgba(0, 0, 0, .35);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
    }
    .app {
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr auto;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 18px;
      border-bottom: 1px solid var(--line);
      background: #15181d;
    }
    h1 {
      margin: 0;
      font-size: 16px;
      font-weight: 700;
      letter-spacing: 0;
    }
    .status {
      color: var(--muted);
      font-size: 13px;
      white-space: nowrap;
    }
    main {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 12px;
      padding: 12px;
      min-height: 0;
    }
    section {
      min-width: 0;
      min-height: 0;
      display: grid;
      grid-template-rows: auto 1fr;
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: 0 14px 32px var(--shadow);
    }
    .bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      min-height: 46px;
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-2);
    }
    .label {
      font-size: 13px;
      color: var(--muted);
      font-weight: 650;
    }
    .buttons {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    button, .download, select {
      height: 32px;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      border: 1px solid var(--line);
      background: #252b34;
      color: var(--text);
      padding: 0 10px;
      font: inherit;
      font-size: 13px;
      text-decoration: none;
    }
    button, .download {
      cursor: pointer;
    }
    select {
      min-width: 116px;
      cursor: pointer;
    }
    button:hover, .download:hover { border-color: #516071; background: #2d3540; }
    button.primary {
      background: var(--accent);
      border-color: var(--accent);
      color: #061309;
      font-weight: 750;
    }
    button.primary:hover { background: #79db91; }
    button:disabled { opacity: .55; cursor: wait; }
    textarea {
      width: 100%;
      height: 100%;
      resize: none;
      border: 0;
      outline: 0;
      padding: 14px;
      background: #0f1115;
      color: #f4f7fb;
      font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      tab-size: 4;
      white-space: pre;
      overflow: auto;
    }
    textarea[readonly] { color: #dce6f3; }
    footer {
      min-height: 72px;
      border-top: 1px solid var(--line);
      background: #15181d;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      padding: 10px 12px;
    }
    .meta {
      min-width: 0;
      display: grid;
      gap: 5px;
      font: 12px/1.35 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--muted);
    }
    .good { color: var(--accent); }
    .bad { color: var(--danger); }
    .path {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    @media (max-width: 860px) {
      main { grid-template-columns: 1fr; grid-template-rows: minmax(320px, 1fr) minmax(320px, 1fr); }
      footer { grid-template-columns: 1fr; }
      .status { display: none; }
    }
  </style>
</head>
<body>
  <div class="app">
    <header>
      <h1>Luau Deobfuscator</h1>
      <div class="status" id="status">Ready on localhost</div>
    </header>
    <main>
      <section>
        <div class="bar">
          <div class="label">Input Script</div>
          <div class="buttons">
            <button id="clearBtn" title="Clear input">Clear</button>
            <select id="modeSelect" title="Deobfuscation mode">
              <option value="auto">Auto</option>
              <option value="local">Local</option>
              <option value="wearedevs">WeAreDevs</option>
              <option value="wearedevs_static">Static</option>
            </select>
            <button class="primary" id="runBtn" title="Run deobfuscator">Run</button>
          </div>
        </div>
        <textarea id="input" spellcheck="false" placeholder="Paste obfuscated Lua/Luau here..."></textarea>
      </section>
      <section>
        <div class="bar">
          <div class="label">Output deobfuscated.luau</div>
          <div class="buttons">
            <button id="copyBtn" title="Copy output">Copy</button>
            <a class="download" id="downloadLink" download="deobfuscated.luau" href="#" title="Download output">Download</a>
          </div>
        </div>
        <textarea id="output" readonly spellcheck="false" placeholder="Deobfuscated output appears here..."></textarea>
      </section>
    </main>
    <footer>
      <div class="meta">
        <div id="resultLine">No run yet.</div>
        <div class="path" id="pathLine"></div>
      </div>
      <div class="buttons">
        <button id="openBtn" title="Open output folder">Open Folder</button>
      </div>
    </footer>
  </div>
  <script>
    const input = document.getElementById('input');
    const output = document.getElementById('output');
    const statusEl = document.getElementById('status');
    const resultLine = document.getElementById('resultLine');
    const pathLine = document.getElementById('pathLine');
    const runBtn = document.getElementById('runBtn');
    const clearBtn = document.getElementById('clearBtn');
    const copyBtn = document.getElementById('copyBtn');
    const openBtn = document.getElementById('openBtn');
    const downloadLink = document.getElementById('downloadLink');
    const modeSelect = document.getElementById('modeSelect');
    let lastOutputDir = null;

    function setBusy(busy) {
      runBtn.disabled = busy;
      runBtn.textContent = busy ? 'Running...' : 'Run';
      statusEl.textContent = busy ? 'Deobfuscating...' : 'Ready on localhost';
    }

    function setDownload(text) {
      if (downloadLink.dataset.url) URL.revokeObjectURL(downloadLink.dataset.url);
      const blob = new Blob([text || ''], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      downloadLink.href = url;
      downloadLink.dataset.url = url;
    }

    runBtn.addEventListener('click', async () => {
      const script = input.value;
      output.value = '';
      resultLine.textContent = 'Running...';
      resultLine.className = '';
      pathLine.textContent = '';
      lastOutputDir = null;
      setBusy(true);
      try {
        const res = await fetch('/api/deobfuscate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ script, filename: 'pasted_script.lua', mode: modeSelect.value })
        });
        const data = await res.json();
        if (!data.ok) throw new Error(data.error || 'deobfuscation failed');
        output.value = data.output || '';
        setDownload(output.value);
        lastOutputDir = data.report.output_dir;
        const ok = data.report.verified_same_behavior;
        const mode = data.report.mode || modeSelect.value;
        resultLine.textContent = ok === null || ok === undefined
          ? `${data.report.final_kind} | mode: ${mode}`
          : `${data.report.final_kind} | verified behavior: ${ok}`;
        resultLine.className = ok === false ? 'bad' : 'good';
        pathLine.textContent = data.report.final_source;
      } catch (err) {
        resultLine.textContent = err.message;
        resultLine.className = 'bad';
        output.value = '';
      } finally {
        setBusy(false);
      }
    });

    clearBtn.addEventListener('click', () => {
      input.value = '';
      input.focus();
    });

    copyBtn.addEventListener('click', async () => {
      await navigator.clipboard.writeText(output.value);
      statusEl.textContent = 'Copied output';
      setTimeout(() => statusEl.textContent = 'Ready on localhost', 1200);
    });

    openBtn.addEventListener('click', async () => {
      if (!lastOutputDir) return;
      await fetch('/api/open-output', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: lastOutputDir })
      });
    });

    setDownload('');
  </script>
</body>
</html>
"""


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Local web UI for WeAreDevs deobfuscation")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--open", action="store_true", help="Open the site in the default browser")
    args = parser.parse_args()

    WEB_ROOT.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"Serving Luau deobfuscator at {url}")
    if args.open and sys.platform == "darwin":
        subprocess.run(["open", url], check=False)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
