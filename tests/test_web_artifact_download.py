#!/usr/bin/env python3

import argparse
import base64
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import socket
import subprocess
import threading
import time
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
WEB = ROOT / "web" / "rbx-runtime-runner"
PAYLOAD = ("-- artifact fixture\nlocal value = \"" + ("a" * 300_000) + "\"\nreturn value\n").encode()


def node_executable():
    configured = os.environ.get("NODE_EXECUTABLE")
    if configured:
        return configured
    homebrew = pathlib.Path("/opt/homebrew/bin/node")
    if homebrew.is_file():
        return str(homebrew)
    discovered = shutil.which("node") or shutil.which("nodejs")
    if discovered:
        return discovered
    raise RuntimeError("Node.js was not found; set NODE_EXECUTABLE")


class ArtifactHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/artifact.luau":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, _format, *_args):
        pass


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_server(url, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("web runner exited before becoming ready")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError("web runner did not become ready")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    args = parser.parse_args()

    fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ArtifactHandler)
    fixture_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    fixture_thread.start()

    runner_port = free_port()
    environment = os.environ.copy()
    environment.update({
        "PORT": str(runner_port),
        "RBX_RUNTIME_BINARY": str(args.runtime.resolve()),
        "RBX_RUNTIME_ALLOW_PRIVATE_NETWORK": "1",
    })
    runner = subprocess.Popen(
        [node_executable(), "scripts/local-server.js"],
        cwd=WEB,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        wait_for_server(f"http://127.0.0.1:{runner_port}/", runner)
        artifact_url = f"http://127.0.0.1:{fixture.server_port}/artifact.luau"
        request_body = json.dumps({
            "script": f'local body=game:HttpGet("{artifact_url}")\nprint(#body)',
            "filename": "remote_fetch.luau",
            "profile": "executor-client",
            "executionMode": "diagnostic",
            "analysisHooks": "on",
            "networkPolicy": "allowlist",
            "allowHosts": "127.0.0.1",
            "captureMin": 1,
        }).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{runner_port}/api/run",
            data=request_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.load(response)

        if not result.get("ok") or result.get("terminationReason") != "completed":
            raise RuntimeError(f"artifact fetch failed: {result}")
        files = {item["name"]: item for item in result.get("files", [])}
        primary = files.get("captured_httpget.lua")
        duplicate = files.get("httpget_0001.lua")
        if not primary or not duplicate:
            raise RuntimeError(f"expected HTTP captures were missing: {list(files)}; result={result}")
        decoded = base64.b64decode(primary.get("downloadBase64", ""))
        expected_hash = hashlib.sha256(PAYLOAD).hexdigest()
        if decoded != PAYLOAD or primary.get("sha256") != expected_hash:
            raise RuntimeError("downloadable artifact did not preserve the exact response bytes")
        if duplicate.get("downloadRef") != primary["name"] or duplicate.get("downloadBase64"):
            raise RuntimeError("duplicate artifact was not represented by a download reference")
        if not primary.get("truncated") or len(primary.get("preview", "")) >= len(PAYLOAD):
            raise RuntimeError("large artifact preview was not bounded")
    finally:
        runner.terminate()
        try:
            runner.wait(timeout=3)
        except subprocess.TimeoutExpired:
            runner.kill()
            runner.wait(timeout=3)
        fixture.shutdown()
        fixture.server_close()
        fixture_thread.join(timeout=2)

    print("Web artifact download OK: complete bytes, SHA-256, bounded preview, and duplicate reference")


if __name__ == "__main__":
    main()
