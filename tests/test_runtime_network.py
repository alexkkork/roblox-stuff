#!/usr/bin/env python3
import argparse
import http.server
import json
import math
import os
import pathlib
import subprocess
import tempfile
import threading


ROOT = pathlib.Path(__file__).resolve().parents[1]


def runtime_timeout(seconds):
    raw_scale = os.environ.get("RBX_RUNTIME_TEST_TIMEOUT_SCALE", "1")
    try:
        scale = float(raw_scale)
    except ValueError as error:
        raise RuntimeError(f"RBX_RUNTIME_TEST_TIMEOUT_SCALE must be numeric, got {raw_scale!r}") from error
    if not math.isfinite(scale) or scale < 1:
        raise RuntimeError("RBX_RUNTIME_TEST_TIMEOUT_SCALE must be finite and at least 1")
    return f"{seconds * scale:g}"


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    port = 0

    def do_GET(self):
        if self.path == "/inspect":
            fingerprint = self.headers.get("Opiumware-Fingerprint", "")
            user_identifier = self.headers.get("Opiumware-User-Identifier", "")
            synthetic = (
                len(fingerprint) == 96
                and all(character in "0123456789abcdef" for character in fingerprint)
                and user_identifier == fingerprint
            )
            body = "|".join((
                self.headers.get("User-Agent", ""),
                self.headers.get("X-Compat", ""),
                self.headers.get("Cookie", ""),
                "synthetic" if synthetic else "plain",
            )).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/denied":
            body = b"denied-body"
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Denied", "yes")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/same":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        if self.path == "/cross":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.2:{self.port}/ok")
            self.end_headers()
            return
        if self.path == "/ok":
            body = b"redirect-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args):
        pass


def execute(runtime, source, temp, name, extra):
    script = temp / f"{name}.luau"
    report = temp / f"{name}-report.json"
    trace = temp / f"{name}-trace.jsonl"
    script.write_text(source)
    result = subprocess.run([
        str(runtime), "--profile", "executor-client", "--execution-mode", "diagnostic", "--analysis-hooks", "on",
        "--clock", "virtual", "--timeout", runtime_timeout(3), "--report", str(report),
        "--trace-compat", str(trace), "--out", str(temp / f"{name}-captures"), "--allow-private-network",
        *extra, str(script),
    ], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    payload = json.loads(report.read_text())
    events = [json.loads(line) for line in trace.read_text().splitlines() if line]
    return result, payload, events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    args = parser.parse_args()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    RedirectHandler.port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        with tempfile.TemporaryDirectory(prefix="rbx-network-") as temporary:
            temp = pathlib.Path(temporary)
            same_url = f"http://127.0.0.1:{server.server_port}/same"
            same, same_report, same_events = execute(
                args.runtime,
                f'local response = game:GetService("HttpService"):RequestAsync({{Url="{same_url}"}})\n'
                'assert(response.Success and response.Body == "redirect-ok")\nprint("same-host-redirect-ok")\n',
                temp,
                "same-host",
                ["--network-policy", "allowlist", "--allow-host", "127.0.0.1"],
            )
            if same.returncode or "same-host-redirect-ok" not in same.stdout:
                raise RuntimeError(f"same-host redirect failed:\n{same.stdout}\n{same.stderr}")
            if same_report.get("termination_reason") != "completed":
                raise RuntimeError(f"same-host redirect report was not completed: {same_report}")
            if not any(event.get("kind") == "network_redirect" for event in same_events):
                raise RuntimeError("same-host redirect was not traced")

            data_model_http, data_model_http_report, _ = execute(
                args.runtime,
                f'assert(game:HttpGet("{same_url}") == "redirect-ok")\n'
                f'assert(game:HttpGetAsync("{same_url}") == "redirect-ok")\n'
                'print("executor-datamodel-http-ok")\n',
                temp,
                "executor-datamodel-http",
                ["--network-policy", "allowlist", "--allow-host", "127.0.0.1"],
            )
            if data_model_http.returncode or "executor-datamodel-http-ok" not in data_model_http.stdout:
                raise RuntimeError(f"executor DataModel HTTP methods failed:\n{data_model_http.stdout}\n{data_model_http.stderr}")
            if data_model_http_report.get("termination_reason") != "completed":
                raise RuntimeError(f"executor DataModel HTTP methods did not complete: {data_model_http_report}")

            roblox_data_model_http, _, _ = execute(
                args.runtime,
                'local ok, message = pcall(function() return game:HttpGet("https://example.com") end)\n'
                'assert(not ok and string.find(message, "not a valid member", 1, true))\n'
                'print("roblox-datamodel-http-hidden-ok")\n',
                temp,
                "roblox-datamodel-http",
                ["--profile", "roblox-client"],
            )
            if roblox_data_model_http.returncode or "roblox-datamodel-http-hidden-ok" not in roblox_data_model_http.stdout:
                raise RuntimeError(
                    f"Roblox DataModel exposed executor HTTP methods:\n{roblox_data_model_http.stdout}\n{roblox_data_model_http.stderr}"
                )

            inspect_url = f"http://127.0.0.1:{server.server_port}/inspect"
            inspect, inspect_report, _ = execute(
                args.runtime,
                f'local first = request({{Url="{inspect_url}", Headers={{["X-Compat"]="yes"}}, Cookies={{session="abc"}}}})\n'
                'assert(first.Success and first.Body == "Roblox/WinInet|yes|session=abc|plain")\n'
                f'local second = request({{Url="{inspect_url}", Headers={{["User-Agent"]="Opiumware-Test"}}}})\n'
                'assert(second.Success and second.Body == "Opiumware-Test|||plain")\n'
                'assert(type(second.Cookies) == "table")\nprint("executor-request-shape-ok")\n',
                temp,
                "executor-generic-shape",
                ["--network-policy", "allowlist", "--allow-host", "127.0.0.1"],
            )
            if inspect.returncode or "executor-request-shape-ok" not in inspect.stdout:
                raise RuntimeError(f"executor request shape failed:\n{inspect.stdout}\n{inspect.stderr}")
            if inspect_report.get("termination_reason") != "completed":
                raise RuntimeError(f"executor request shape did not complete: {inspect_report}")

            opiumware, opiumware_report, _ = execute(
                args.runtime,
                f'local response = request({{Url="{inspect_url}"}})\n'
                'assert(response.Success and response.Body == "Roblox/WinInet|||synthetic")\n'
                'print("opiumware-request-shape-ok")\n',
                temp,
                "executor-opiumware-shape",
                ["--executor-preset", "opiumware", "--network-policy", "allowlist", "--allow-host", "127.0.0.1"],
            )
            if opiumware.returncode or "opiumware-request-shape-ok" not in opiumware.stdout:
                raise RuntimeError(f"Opiumware request shape failed:\n{opiumware.stdout}\n{opiumware.stderr}")
            if opiumware_report.get("termination_reason") != "completed":
                raise RuntimeError(f"Opiumware request shape did not complete: {opiumware_report}")

            roblox, roblox_report, _ = execute(
                args.runtime,
                f'local response = game:GetService("HttpService"):RequestAsync({{Url="{inspect_url}"}})\n'
                'assert(response.Success and response.Body == "Roblox/WinInet|||plain")\n'
                'print("roblox-request-shape-ok")\n',
                temp,
                "roblox-shape",
                ["--profile", "roblox-client", "--network-policy", "allowlist", "--allow-host", "127.0.0.1"],
            )
            if roblox.returncode or "roblox-request-shape-ok" not in roblox.stdout:
                raise RuntimeError(f"Roblox request shape failed:\n{roblox.stdout}\n{roblox.stderr}")
            if roblox_report.get("termination_reason") != "completed":
                raise RuntimeError(f"Roblox request shape did not complete: {roblox_report}")

            denied_url = f"http://127.0.0.1:{server.server_port}/denied"
            denied, denied_report, denied_events = execute(
                args.runtime,
                f'local response = game:GetService("HttpService"):RequestAsync({{Url="{denied_url}"}})\n'
                'assert(response.Success == false and response.StatusCode == 403)\n'
                'assert(response.StatusMessage == "Forbidden" and response.Body == "denied-body")\n'
                'assert(response.Headers["X-Denied"] == "yes")\nprint("http-error-response-ok")\n',
                temp,
                "http-error-response",
                ["--network-policy", "allowlist", "--allow-host", "127.0.0.1"],
            )
            if denied.returncode or "http-error-response-ok" not in denied.stdout:
                raise RuntimeError(f"HTTP error response was not returned:\n{denied.stdout}\n{denied.stderr}")
            if denied_report.get("termination_reason") != "completed":
                raise RuntimeError(f"HTTP error response did not complete: {denied_report}")
            if not any(event.get("kind") == "network_response" and event.get("status") == 403 for event in denied_events):
                raise RuntimeError(f"HTTP error response was not traced: {denied_events}")

            cross_url = f"http://127.0.0.1:{server.server_port}/cross"
            cross, cross_report, cross_events = execute(
                args.runtime,
                f'game:GetService("HttpService"):RequestAsync({{Url="{cross_url}"}})\n',
                temp,
                "cross-host",
                ["--network-policy", "allowlist", "--allow-host", "127.0.0.1"],
            )
            blocked = [event for event in cross_events if event.get("kind") == "network_blocked"]
            if cross.returncode == 0 or cross_report.get("termination_reason") != "network_required":
                raise RuntimeError(f"cross-host redirect was not blocked: {cross_report}")
            if not blocked or blocked[-1].get("host") != "127.0.0.2":
                raise RuntimeError(f"redirect escaped the approved host: {cross_events}")

            scheme, scheme_report, _ = execute(
                args.runtime,
                'game:GetService("HttpService"):RequestAsync({Url="file:///etc/passwd"})\n',
                temp,
                "scheme",
                ["--network-policy", "live"],
            )
            if scheme.returncode == 0 or "HTTP or HTTPS" not in scheme.stderr:
                raise RuntimeError(f"non-HTTP scheme was not rejected: {scheme.stderr}")
            if scheme_report.get("termination_reason") != "runtime_error":
                raise RuntimeError(f"non-HTTP scheme received the wrong termination reason: {scheme_report}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    print("Runtime network OK: private opt-in, generic and Opiumware personas, HTTP errors, redirects, and scheme restriction")


if __name__ == "__main__":
    main()
