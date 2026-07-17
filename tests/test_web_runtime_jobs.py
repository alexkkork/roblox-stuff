#!/usr/bin/env python3
"""Black-box heavy runtime job routing, progress, and network retry test."""

from __future__ import annotations

import argparse
import http.server
import json
import os
import pathlib
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
WEB = ROOT / "web" / "rbx-runtime-runner"
RUNTIME_STAGES = ["compile", "bootstrap", "execute", "network_wait", "steady_state", "complete"]


def node_executable() -> str:
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


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"queued-network-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request_json(url: str, body=None, timeout=10):
    encoded = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def wait_for_page(url: str, process: subprocess.Popen) -> None:
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


def run_job(base: str, payload: dict):
    status_code, created = request_json(f"{base}/api/run", payload, timeout=15)
    if status_code != 202 or not created.get("ok") or created.get("kind") != "runtime":
        raise RuntimeError(f"heavy /api/run request was not queued: {status_code}: {created}")
    if created.get("routing", {}).get("code") != "source_size":
        raise RuntimeError(f"heavy source had the wrong routing reason: {created}")

    deadline = time.monotonic() + 30
    job = None
    while time.monotonic() < deadline:
        code, status = request_json(base + created["links"]["status"])
        if code != 200 or not status.get("ok"):
            raise RuntimeError(f"runtime job status failed: {code}: {status}")
        job = status["job"]
        if job.get("state") not in {"queued", "running"}:
            break
        time.sleep(max(0.05, min(0.25, job.get("poll_after_ms", 1000) / 1000)))
    else:
        raise RuntimeError("runtime job did not finish within 30 seconds")

    if job.get("state") != "completed" or job.get("stage_order") != RUNTIME_STAGES:
        raise RuntimeError(f"runtime job did not complete with the expected stage model: {job}")
    if job.get("stages", {}).get("complete", {}).get("status") != "done":
        raise RuntimeError(f"runtime job did not finalize its report stage: {job}")
    code, result = request_json(base + created["links"]["finished"])
    if code != 200:
        raise RuntimeError(f"finished runtime result was unavailable: {code}: {result}")
    return job, result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    args = parser.parse_args()

    fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    fixture_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    fixture_thread.start()
    port = free_port()
    environment = os.environ.copy()
    environment.update({
        "PORT": str(port),
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
        base = f"http://127.0.0.1:{port}"
        wait_for_page(base + "/", runner)
        target = f"http://127.0.0.1:{fixture.server_port}/payload"
        source = f'local body = game:HttpGet("{target}")\nprint("queued-runtime-ok", body)\nreturn body\n--' + ("x" * 260_000)
        common = {
            "script": source,
            "filename": "heavy_runtime_job.luau",
            "profile": "executor-client",
            "executionMode": "faithful",
            "networkPolicy": "offline",
            "timeout": 10,
        }
        blocked_job, blocked = run_job(base, common)
        requirement = (blocked.get("networkRequirements") or [None])[0]
        if blocked.get("terminationReason") != "network_required" or not requirement:
            raise RuntimeError(f"offline queued job did not return its exact network requirement: {blocked}")
        if blocked_job.get("stages", {}).get("network_wait", {}).get("status") != "done":
            raise RuntimeError("network-blocked job did not expose the network_wait progress stage")

        _, retried = run_job(base, {
            **common,
            "networkPolicy": "allowlist",
            "allowHosts": requirement["host"],
        })
        if not retried.get("ok") or retried.get("terminationReason") != "completed":
            raise RuntimeError(f"approved queued job did not complete: {retried}")
        if "queued-runtime-ok\tqueued-network-ok" not in retried.get("stdout", ""):
            raise RuntimeError(f"approved queued job returned the wrong output: {retried.get('stdout')!r}")
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

    print("Web runtime jobs OK: heavy routing, six progress stages, offline requirement, allowlist retry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
