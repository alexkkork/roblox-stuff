#!/usr/bin/env python3
"""A call-only Luraph trace must never be promoted to reconstructed source."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "luraph"
SUBJECT = FIXTURES / "subject_1b642e9523c1.luau"
TRACE = FIXTURES / "subject_1b642e9523c1_payload_trace.log"


def run_runtime(runtime: pathlib.Path, source: pathlib.Path, report: pathlib.Path, *, luraph: bool) -> subprocess.CompletedProcess[str]:
    command = [
        str(runtime),
        "--profile", "roblox-client",
        "--execution-mode", "faithful",
        "--analysis-hooks", "off",
        "--network-policy", "offline",
        "--clock", "virtual",
        "--timeout", "15" if luraph else "5",
        "--memory-limit-mb", "768" if luraph else "256",
        "--unsupported", "trace-nil" if luraph else "error",
        "--no-native-codegen",
        "--report", str(report),
    ]
    if luraph:
        command.extend((
            "--luraph-mode", "force",
            "--luraph-max-steps", "30000000",
            "--luraph-stall-steps", "0",
        ))
    command.append(str(source))
    return subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-trace-reconstruction-") as temporary:
        temp = pathlib.Path(temporary)
        output = temp / "output"
        completed = subprocess.run(
            [
                str(args.deobfuscator),
                str(SUBJECT),
                "--output-dir", str(output),
                "--mode", "reconstruct",
                "--trace", str(TRACE),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        if completed.returncode != 2:
            raise RuntimeError(f"call-only trace should remain blocked:\n{completed.stdout}\n{completed.stderr}")

        reconstructed = output / "reconstructed.luau"
        if reconstructed.exists():
            raise RuntimeError("call-only trace was falsely emitted as reconstructed source")
        report = json.loads((output / "deobfuscation_report.json").read_text(encoding="utf-8"))
        if (report.get("status") != "blocked" or report.get("exact_source") is not False
                or report.get("artifacts", {}).get("source") is not None
                or report.get("verification", {}).get("source_claim_accepted") is not False):
            raise RuntimeError(f"call-only trace made an incorrect source claim: {report}")
        trace_pass = next((item for item in report.get("passes", []) if item.get("stage") == "trace"), {})
        if (trace_pass.get("payload_calls") != 1
                or trace_pass.get("payload_activation_complete") is not True
                or report.get("coverage", {}).get("runtime_decode", {}).get("available") is not False):
            raise RuntimeError(f"call observation was not retained truthfully: {trace_pass}")

    print("Luraph call-only trace truthfulness OK: observed output remained source-withheld")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
