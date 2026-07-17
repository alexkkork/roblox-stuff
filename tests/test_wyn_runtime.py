#!/usr/bin/env python3
import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED_SHA256 = "fc2bb21e1bc0c8cd50c9e5938a1afe5fcd2d7c5aa6e06698fac44e57486f717f"
EXPECTED_URL = "https://wynfuscate.com/api/scripts/keytxt_auth.lua"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    parser.add_argument("--sample", type=pathlib.Path, required=True)
    args = parser.parse_args()

    digest = hashlib.sha256(args.sample.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise RuntimeError(f"unexpected wYn sample hash: {digest}")

    with tempfile.TemporaryDirectory(prefix="wyn-runtime-") as temporary:
        temp = pathlib.Path(temporary)
        report = temp / "runtime-report.json"
        trace = temp / "compat-trace.jsonl"
        started = time.monotonic()
        result = subprocess.run([
            str(args.runtime), "--profile", "executor-client", "--analysis-hooks", "on",
            "--owner-protection", "respect", "--network-policy", "offline", "--luraph-mode", "auto",
            "--timeout", "5", "--clock", "virtual", "--unsupported", "trace-nil",
            "--report", str(report), "--trace-compat", str(trace), "--out", str(temp / "captures"),
            str(args.sample),
        ], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        elapsed = time.monotonic() - started

        payload = json.loads(report.read_text())
        events = [json.loads(line) for line in trace.read_text().splitlines() if line]
        blocked = [event for event in events if event.get("kind") == "network_blocked"]
        if result.returncode == 0:
            raise RuntimeError("offline wYn run unexpectedly completed")
        if elapsed >= 5 or "execution timed out" in result.stderr:
            raise RuntimeError(f"wYn run still reached the wall watchdog after {elapsed:.2f}s")
        if payload.get("termination_reason") != "network_required":
            raise RuntimeError(f"unexpected wYn termination: {payload}")
        if not blocked or blocked[-1].get("host") != "wynfuscate.com" or blocked[-1].get("name") != EXPECTED_URL:
            raise RuntimeError(f"wYn key-service requirement was not captured: {blocked}")

        probe = temp / "wyn-probe.luau"
        generated = subprocess.run([
            "python3", str(ROOT / "tools" / "wynfuscate_deobfuscator.py"), str(args.sample),
            "--emit-runtime-probe", str(probe), "--probe-capture-fail-traps",
        ], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if generated.returncode:
            raise RuntimeError(f"wYn probe generation failed: {generated.stderr}")
        probe_result = subprocess.run([
            str(args.runtime), "--minimal-env", "--analysis-hooks", "on", "--timeout", "0.1",
            "--out", str(temp / "probe-captures"), str(probe),
        ], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "main_compile_error" in probe_result.stderr or "Malformed string" in probe_result.stderr:
            raise RuntimeError(f"generated wYn probe does not compile: {probe_result.stderr}")

    print(f"wYn runtime OK: network requirement reached in {elapsed:.2f}s without a wall timeout")


if __name__ == "__main__":
    main()
