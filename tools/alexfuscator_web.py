#!/usr/bin/env python3
"""Localhost UI wrapper for the C++ Alexfuscator binary."""

from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"
DEFAULT_PORT = 8787
WEB_ROOT = PROJECT_ROOT / "outputs" / "alexfuscator_web"
REQUEST_ROOT = WEB_ROOT / "requests"
RUN_ROOT = WEB_ROOT / "runs"
RUNTIME_RUN_ROOT = WEB_ROOT / "runtime_runs"
INLINE_OUTPUT_LIMIT = 1_500_000
INLINE_FILE_LIMIT = 120_000


def normalize_layers(value: object) -> str:
    text = str(value if value is not None else "1").strip()
    if not text.isdigit():
        return "1"
    return text.lstrip("0") or "1"


def fallback_used(mode: object) -> bool:
    return "fallback" in str(mode or "").lower()


def byte_count(value: object, fallback: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return fallback
    return number if number >= 0 else fallback


def layer_timeout_seconds(layers_text: str, source_bytes: int) -> int:
    try:
        layers = int(layers_text)
    except ValueError:
        layers = 1
    # Large layer counts grow quickly, but a linear timeout makes accidental
    # million-layer requests effectively hang the local UI. Use a sublinear
    # estimate and let the native process report/timeout cleanly.
    return max(90, 60 + int(layers ** 0.5) * 8 + source_bytes // 8000)


def find_binary(explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(
        [
            PROJECT_ROOT / "build" / "alexfuscator",
            PROJECT_ROOT / "work" / "build" / "alexfuscator",
            PROJECT_ROOT / "cmake-build-release" / "alexfuscator",
        ]
    )
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    raise FileNotFoundError("could not find alexfuscator binary; build it first or pass --binary")


def find_runtime_binary(explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(
        [
            PROJECT_ROOT / "build" / "rbx_luau_runtime",
            PROJECT_ROOT / "work" / "build" / "rbx_luau_runtime",
            PROJECT_ROOT / "cmake-build-release" / "rbx_luau_runtime",
            PROJECT_ROOT / "outputs" / "rbx_luau_runtime_macos_arm64",
        ]
    )
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    raise FileNotFoundError("could not find rbx_luau_runtime binary; build it first or pass --runtime-binary")


def request_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S") + f"_{os.getpid()}_{time.time_ns() % 1_000_000_000:09d}"


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def split_hosts(value: object) -> list[str]:
    if isinstance(value, list):
        raw = [str(item) for item in value]
    else:
        raw = str(value or "").replace("\n", ",").split(",")
    hosts = []
    for item in raw:
        host = item.strip().lower()
        if host:
            hosts.append(host)
    return hosts


def safe_choice(value: object, allowed: set[str], default: str) -> str:
    text = str(value if value is not None else default)
    return text if text in allowed else default


def summarize_output_files(root: Path) -> list[dict]:
    files: list[dict] = []
    if not root.exists():
        return files
    for path in sorted([p for p in root.rglob("*") if p.is_file()])[:80]:
        try:
            path.relative_to(WEB_ROOT.resolve())
        except ValueError:
            continue
        size = path.stat().st_size
        preview = ""
        text_like = path.suffix.lower() in {".txt", ".lua", ".luau", ".json", ".jsonl", ".log"}
        if text_like and size <= INLINE_FILE_LIMIT:
            preview = path.read_text(errors="replace")
        elif text_like:
            preview = path.read_text(errors="replace")[:INLINE_FILE_LIMIT] + "\n\n-- preview truncated --\n"
        files.append(
            {
                "name": path.name,
                "path": str(path),
                "bytes": size,
                "download_url": "/api/file?path=" + quote(str(path)),
                "preview": preview,
            }
        )
    return files


def extract_json_text(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped

    fence = "```"
    start = stripped.find(fence)
    while start != -1:
        line_end = stripped.find("\n", start + len(fence))
        if line_end == -1:
            break
        end = stripped.find(fence, line_end + 1)
        if end == -1:
            break
        candidate = stripped[line_end + 1 : end].strip()
        if candidate.startswith("{") and candidate.endswith("}"):
            return candidate
        start = stripped.find(fence, end + len(fence))

    first = stripped.find("{")
    while first != -1:
        depth = 0
        in_string = False
        escape = False
        for index in range(first, len(stripped)):
            ch = stripped[index]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return stripped[first : index + 1]
        first = stripped.find("{", first + 1)
    raise ValueError("Could not find a JSON object in the pasted AI response")


def parse_ai_payload(text: str) -> dict:
    json_text = extract_json_text(text)
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        # Some AIs still emit single-quoted pseudo-JSON. Accept it locally,
        # then normalize it back to real JSON for display.
        data = ast.literal_eval(json_text)
    if not isinstance(data, dict):
        raise ValueError("AI payload must be a JSON object")
    tool = safe_choice(data.get("tool"), {"runner", "obfuscator"}, "runner")
    options = data.get("options", {})
    if not isinstance(options, dict):
        options = {}
    script = str(data.get("script", ""))
    if not script and isinstance(data.get("input"), str):
        script = str(data.get("input"))
    return {"tool": tool, "script": script, "options": options}


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return {}
    return json.loads(handler.rfile.read(length).decode())


def safe_stem(value: str) -> str:
    name = Path(value or "pasted_script.luau").name
    if not name.endswith((".lua", ".luau", ".txt")):
        name += ".luau"
    keep = []
    for ch in Path(name).stem:
        keep.append(ch if ch.isalnum() or ch in ("-", "_") else "_")
    stem = "".join(keep).strip("_") or "pasted_script"
    return stem + ".luau"


class Handler(BaseHTTPRequestHandler):
    server_version = "AlexfuscatorWeb/1.0"
    alex_binary: Path

    def log_message(self, fmt: str, *args: object) -> None:
        print("[alexfuscator-web] " + fmt % args)

    def do_HEAD(self) -> None:
        if urlparse(self.path).path == "/":
            body = INDEX_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = INDEX_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/health":
            json_response(self, 200, {"ok": True, "status": "running", "binary": str(self.alex_binary)})
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
            size = path.stat().st_size
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            with path.open("rb") as fh:
                shutil.copyfileobj(fh, self.wfile, length=1024 * 1024)
            return
        json_response(self, 404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/obfuscate":
            self.handle_obfuscate()
            return
        if parsed.path == "/api/open-output":
            self.handle_open_output()
            return
        json_response(self, 404, {"ok": False, "error": "not found"})

    def handle_obfuscate(self) -> None:
        try:
            payload = read_json(self)
            source = str(payload.get("script", ""))
            if not source.strip():
                json_response(self, 400, {"ok": False, "error": "paste a script first"})
                return

            profile = str(payload.get("profile", "maximum"))
            profile = {"fast": "compatibility", "balanced": "hardened", "max": "maximum"}.get(profile, profile)
            if profile not in {"compatibility", "hardened", "maximum"}:
                json_response(self, 400, {"ok": False, "error": "bad profile"})
                return
            layers_text = normalize_layers(payload.get("layers", 1))
            integrity = bool(payload.get("integrity", True))
            one_line = bool(payload.get("oneLine", True))
            env_lock = bool(payload.get("envLock", True))
            analysis_notice = str(payload.get("analysisNotice", "")).strip()
            owner_lock = str(payload.get("ownerLock", "off"))
            if owner_lock not in {"off", "sign", "sign-and-lock"}:
                owner_lock = "off"
            owner_private_key = str(payload.get("ownerPrivateKey", "")).strip()

            request_id = time.strftime("%Y%m%d_%H%M%S") + f"_{os.getpid()}_{time.time_ns() % 1_000_000_000:09d}"
            request_dir = REQUEST_ROOT / request_id
            run_dir = RUN_ROOT / request_id
            request_dir.mkdir(parents=True, exist_ok=True)
            run_dir.mkdir(parents=True, exist_ok=True)

            input_path = request_dir / safe_stem(str(payload.get("filename", "pasted_script.luau")))
            output_path = run_dir / (input_path.stem + ".obf.luau")
            debug_path = run_dir / "debug_map.json"
            input_path.write_text(source.rstrip("\n") + "\n")

            cmd = [
                str(self.alex_binary),
                str(input_path),
                "-o",
                str(output_path),
                "--profile",
                profile,
                "--layers",
                layers_text,
                "--target",
                "roblox-luau",
                "--report",
                str(debug_path),
            ]
            if analysis_notice:
                cmd.extend(["--analysis-notice", analysis_notice])
            if owner_lock != "off":
                if not owner_private_key:
                    json_response(self, 400, {"ok": False, "error": "Owner lock needs a private key path"})
                    return
                cmd.extend(["--owner-protect", owner_lock, "--owner-private-key", owner_private_key])
            cmd.append("--one-line" if one_line else "--pretty")
            if not integrity:
                cmd.append("--no-integrity")
            cmd.append("--env-lock" if env_lock else "--no-env-lock")
            timeout = layer_timeout_seconds(layers_text, len(source))
            try:
                proc = subprocess.run(cmd, cwd=PROJECT_ROOT, text=True, capture_output=True, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                try:
                    input_path.unlink()
                except FileNotFoundError:
                    pass
                json_response(
                    self,
                    504,
                    {
                        "ok": False,
                        "error": f"alexfuscator timed out after {timeout}s; try fewer layers or a smaller script",
                        "stdout": exc.stdout or "",
                        "stderr": exc.stderr or "",
                    },
                )
                return
            if proc.returncode != 0:
                try:
                    input_path.unlink()
                except FileNotFoundError:
                    pass
                json_response(
                    self,
                    400,
                    {
                        "ok": False,
                        "error": proc.stderr.strip() or proc.stdout.strip() or "alexfuscator failed",
                        "stdout": proc.stdout,
                        "stderr": proc.stderr,
                    },
                )
                return

            output_size = output_path.stat().st_size
            debug_payload = {}
            if debug_path.exists():
                try:
                    debug_payload = json.loads(debug_path.read_text())
                except Exception:
                    debug_payload = {}
            native_mode = str(debug_payload.get("mode", ""))
            actual_layers = str(debug_payload.get("layers", layers_text))
            raw_output_bytes = byte_count(debug_payload.get("output_bytes"), output_size)
            native_fallback_used = bool(debug_payload.get("fallback_used", fallback_used(native_mode)))
            output_too_large = output_size > INLINE_OUTPUT_LIMIT
            if output_too_large:
                with output_path.open("rb") as fh:
                    output = fh.read(INLINE_OUTPUT_LIMIT).decode(errors="replace")
                output += "\n\n-- Output is large; use Download or Open Folder for the full file.\n"
            else:
                output = output_path.read_text(errors="replace")
            try:
                input_path.unlink()
            except FileNotFoundError:
                pass
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "output": output,
                    "output_truncated": output_too_large,
                    "output_bytes": output_size,
                    "raw_output_bytes": raw_output_bytes,
                    "requested_layers": layers_text,
                    "actual_layers": actual_layers,
                    "analysis_notice": debug_payload.get("analysis_notice", bool(analysis_notice)),
                    "owner_protect": debug_payload.get("owner_protect", owner_lock),
                    "owner_locked": debug_payload.get("owner_locked", owner_lock == "sign-and-lock"),
                    "mode": "native",
                    "native_mode": native_mode,
                    "backend": debug_payload.get("backend"),
                    "vm_version": debug_payload.get("vm_version"),
                    "ir_version": debug_payload.get("ir_version"),
                    "fallback_used": native_fallback_used,
                    "stage2_decoys": debug_payload.get("stage2_decoy_count"),
                    "stage2_chunk_size": debug_payload.get("stage2_chunk_size"),
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                    "output_path": str(output_path),
                    "output_dir": str(run_dir),
                    "download_url": "/api/file?path=" + quote(str(output_path)),
                },
            )
        except Exception as exc:
            json_response(self, 500, {"ok": False, "error": str(exc), "traceback": traceback.format_exc()})

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
            ok = subprocess.run(["open", str(path)], check=False).returncode == 0 if sys.platform == "darwin" else False
            json_response(self, 200, {"ok": ok})
        except Exception as exc:
            json_response(self, 500, {"ok": False, "error": str(exc)})


class LocalServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Alexfuscator</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #101214;
      --panel: #181c20;
      --panel2: #22272e;
      --line: #343b45;
      --text: #edf2f7;
      --muted: #a8b2bf;
      --accent: #65d48b;
      --danger: #ff7e7e;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: var(--bg); color: var(--text); }
    .app { min-height: 100vh; display: grid; grid-template-rows: auto 1fr auto; }
    header, footer { background: #15181c; border-color: var(--line); }
    header { min-height: 54px; border-bottom: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 0 16px; }
    h1 { margin: 0; font-size: 17px; letter-spacing: 0; }
    .status { color: var(--muted); font-size: 13px; white-space: nowrap; }
    main { min-height: 0; display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 12px; padding: 12px; }
    section { min-width: 0; min-height: 0; display: grid; grid-template-rows: auto 1fr; border: 1px solid var(--line); background: var(--panel); }
    .bar { min-height: 46px; display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 8px 10px; background: var(--panel2); border-bottom: 1px solid var(--line); }
    .label { color: var(--muted); font-size: 13px; font-weight: 700; }
    .buttons { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 8px; }
    button, select, input, .download {
      height: 32px; border: 1px solid var(--line); background: #2a3139; color: var(--text); padding: 0 10px;
      font: inherit; font-size: 13px; text-decoration: none; display: inline-flex; align-items: center; gap: 7px;
    }
    button, select, .download { cursor: pointer; }
    button:hover, select:hover, input:hover, .download:hover { border-color: #566372; background: #323a44; }
    button.primary { background: var(--accent); border-color: var(--accent); color: #06130b; font-weight: 800; }
    button.primary:hover { background: #78e39c; }
    button:disabled { opacity: .55; cursor: wait; }
    select { min-width: 118px; }
    input { width: 78px; }
    input[type="checkbox"] { width: 16px; height: 16px; padding: 0; accent-color: var(--accent); }
    .toggle { height: 32px; display: inline-flex; align-items: center; gap: 6px; color: var(--muted); font-size: 13px; }
    textarea {
      width: 100%; height: 100%; resize: none; border: 0; outline: 0; padding: 14px; background: #0d0f12; color: #f7fafc;
      font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      tab-size: 4; white-space: pre; overflow: auto;
    }
    textarea[readonly] { color: #dfe8f3; }
    footer { min-height: 70px; border-top: 1px solid var(--line); display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; align-items: center; padding: 10px 12px; }
    .meta { min-width: 0; display: grid; gap: 5px; color: var(--muted); font: 12px/1.35 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .good { color: var(--accent); }
    .bad { color: var(--danger); }
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
      <h1>Alexfuscator</h1>
      <div class="status" id="status">Ready on localhost</div>
    </header>
    <main>
      <section>
        <div class="bar">
          <div class="label">Input Luau</div>
          <div class="buttons">
            <button id="clearBtn">Clear</button>
            <select id="profile">
              <option value="maximum">Maximum</option>
              <option value="hardened">Hardened</option>
              <option value="compatibility">Compatibility</option>
            </select>
            <label class="toggle">Extra Layers</label>
            <input id="layers" type="text" inputmode="numeric" pattern="[0-9]*" value="7" title="Outer encryption layers" autocomplete="off" />
            <label class="toggle"><input id="oneLine" type="checkbox" checked />One-line</label>
            <label class="toggle"><input id="integrity" type="checkbox" checked />Integrity</label>
            <label class="toggle"><input id="envLock" type="checkbox" checked />Roblox lock</label>
            <input id="analysisNotice" type="text" placeholder="Analysis notice" title="Optional informational notice" autocomplete="off" />
            <label class="toggle">Owner Lock</label>
            <select id="ownerLock">
              <option value="off" selected>Off</option>
              <option value="sign">Sign</option>
              <option value="sign-and-lock">Sign + Lock</option>
            </select>
            <input id="ownerPrivateKey" type="text" placeholder="keys/alex_owner.private" title="Owner private key path" autocomplete="off" />
            <button class="primary" id="runBtn">Obfuscate</button>
          </div>
        </div>
        <textarea id="input" spellcheck="false" placeholder="Paste Luau here..."></textarea>
      </section>
      <section>
        <div class="bar">
          <div class="label">Output</div>
          <div class="buttons">
            <button id="copyBtn">Copy</button>
            <a class="download" id="download" href="#" download="alexfuscated.luau">Download</a>
          </div>
        </div>
        <textarea id="output" readonly spellcheck="false" placeholder="Obfuscated output appears here..."></textarea>
      </section>
    </main>
    <footer>
      <div class="meta">
        <div id="result">No run yet.</div>
        <div class="path" id="path"></div>
      </div>
      <div class="buttons"><button id="openBtn">Open Folder</button></div>
    </footer>
  </div>
  <script>
    const input = document.getElementById('input');
    const output = document.getElementById('output');
    const runBtn = document.getElementById('runBtn');
    const clearBtn = document.getElementById('clearBtn');
    const copyBtn = document.getElementById('copyBtn');
    const openBtn = document.getElementById('openBtn');
    const profile = document.getElementById('profile');
    const layers = document.getElementById('layers');
    const oneLine = document.getElementById('oneLine');
    const integrity = document.getElementById('integrity');
    const envLock = document.getElementById('envLock');
    const analysisNotice = document.getElementById('analysisNotice');
    const ownerLock = document.getElementById('ownerLock');
    const ownerPrivateKey = document.getElementById('ownerPrivateKey');
    const statusEl = document.getElementById('status');
    const resultEl = document.getElementById('result');
    const pathEl = document.getElementById('path');
    const download = document.getElementById('download');
    let outputDir = '';
    const profileLayerDefaults = {maximum: 7, hardened: 3, compatibility: 1};

    profile.onchange = () => {
      if (!layers.dataset.manual) layers.value = profileLayerDefaults[profile.value] || 3;
    };
    function normalizeLayers(value) {
      const digits = String(value || '1').replace(/[^0-9]/g, '');
      return digits.replace(/^0+/, '') || '1';
    }

    layers.oninput = () => {
      layers.dataset.manual = '1';
      layers.value = normalizeLayers(layers.value);
    };

    async function postJSON(url, body) {
      const res = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
      const json = await res.json();
      if (!res.ok || !json.ok) throw new Error(json.error || 'Request failed');
      return json;
    }

    runBtn.onclick = async () => {
      runBtn.disabled = true;
      statusEl.textContent = 'Obfuscating...';
      resultEl.textContent = 'Working...';
      resultEl.className = '';
      output.value = '';
      download.removeAttribute('href');
      try {
        const requestedLayers = normalizeLayers(layers.value || profileLayerDefaults[profile.value] || 1);
        const data = await postJSON('/api/obfuscate', {
          script: input.value,
          profile: profile.value,
          layers: requestedLayers,
          oneLine: oneLine.checked,
          integrity: integrity.checked,
          envLock: envLock.checked,
          analysisNotice: analysisNotice.value,
          ownerLock: ownerLock.value,
          ownerPrivateKey: ownerPrivateKey.value,
          filename: 'pasted_script.luau'
        });
        output.value = data.output;
        outputDir = data.output_dir;
        download.href = data.download_url;
        const sizeText = data.output_bytes ? ` (${data.output_bytes.toLocaleString()} bytes)` : '';
        const layerText = data.requested_layers ? ` requested=${data.requested_layers}; actual=${data.actual_layers || data.requested_layers};` : '';
        const modeText = data.mode ? ` mode=${data.mode};` : '';
        const nativeModeText = data.native_mode ? ` native=${data.native_mode};` : '';
        const fallbackText = typeof data.fallback_used === 'boolean' ? ` fallback=${data.fallback_used ? 'yes' : 'no'};` : '';
        const vmText = data.backend ? ` ${data.backend} vm=${data.vm_version || '?'} ir=${data.ir_version || '?'};` : '';
        const ownerText = data.owner_protect && data.owner_protect !== 'off' ? ` owner=${data.owner_protect}${data.owner_locked ? ':locked' : ''};` : '';
        const stage2Text = data.stage2_decoys ? ` stage2-decoys=${data.stage2_decoys};` : '';
        const rawSizeText = data.raw_output_bytes && data.raw_output_bytes !== data.output_bytes ? ` raw=${data.raw_output_bytes.toLocaleString()} bytes;` : '';
        const truncText = data.output_truncated ? ' Preview shown; full file is in Download/Open Folder.' : '';
        resultEl.textContent = `${modeText}${nativeModeText}${vmText}${fallbackText}${ownerText}${layerText}${stage2Text}${rawSizeText} ` + (data.stdout.trim() || 'Obfuscation complete.') + sizeText + truncText;
        resultEl.className = 'good';
        pathEl.textContent = data.output_path;
        statusEl.textContent = 'Done';
      } catch (err) {
        resultEl.textContent = err.message;
        resultEl.className = 'bad';
        statusEl.textContent = 'Error';
      } finally {
        runBtn.disabled = false;
      }
    };
    clearBtn.onclick = () => { input.value = ''; input.focus(); };
    copyBtn.onclick = async () => { await navigator.clipboard.writeText(output.value); statusEl.textContent = 'Copied'; };
    openBtn.onclick = async () => {
      if (!outputDir) return;
      try { await postJSON('/api/open-output', {path: outputDir}); } catch (err) { resultEl.textContent = err.message; resultEl.className = 'bad'; }
    };
  </script>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", help="Path to alexfuscator executable")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    Handler.alex_binary = find_binary(args.binary)
    WEB_ROOT.mkdir(parents=True, exist_ok=True)
    server = LocalServer((HOST, args.port), Handler)
    url = f"http://{HOST}:{args.port}/"
    print(f"Alexfuscator UI running at {url}")
    print(f"Using binary: {Handler.alex_binary}")
    if sys.platform == "darwin":
        subprocess.run(["open", url], check=False)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Alexfuscator UI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
