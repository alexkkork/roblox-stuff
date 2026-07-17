#!/usr/bin/env python3
"""Ensure generated Luraph VM source is retained without an exact-source claim."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def generated_interpreter() -> str:
    handlers = []
    padding = "dispatcher_padding_" * 24
    for index in range(40):
        handlers.append(
            f"handler_{index}=function() local padding='{padding}' "
            "while true do break end return padding end"
        )
    return "local V=...;return({" + ",".join(handlers) + ",yield=coroutine.yield})"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-interpreter-truth-") as temporary:
        temp = pathlib.Path(temporary)
        subject = temp / "subject.luau"
        report_path = temp / "runtime-report.json"
        source = generated_interpreter()
        if len(source) < 16 * 1024:
            raise RuntimeError("synthetic interpreter does not exercise the large-source guard")
        subject.write_text(
            "-- Luraph generated-interpreter truthfulness fixture\n"
            f"local generated = [====[{source}]====]\n"
            "assert(loadstring(generated, 'Luraph   '))\n"
            "print('generated-interpreter-truth-ok')\n",
            encoding="utf-8",
        )

        completed = subprocess.run(
            [
                str(args.runtime),
                "--profile", "executor-client",
                "--execution-mode", "faithful",
                "--analysis-hooks", "off",
                "--network-policy", "offline",
                "--clock", "virtual",
                "--timeout", "10",
                "--unsupported", "trace-nil",
                "--luraph-mode", "force",
                "--luraph-save-intermediates",
                "--luraph-stall-steps", "0",
                "--capture-min", "1",
                "--no-native-codegen",
                "--report", str(report_path),
                "--out", str(temp),
                str(subject),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        if completed.returncode != 0 or "generated-interpreter-truth-ok" not in completed.stdout:
            raise RuntimeError(f"synthetic subject failed:\n{completed.stdout}\n{completed.stderr}")

        recovery = json.loads((temp / "luraph_recovery_report.json").read_text(encoding="utf-8"))
        if recovery.get("exact_recovery_status") == "recovered" or recovery.get("original_luau_exact"):
            raise RuntimeError(f"generated interpreter was falsely claimed as exact source: {recovery}")
        interpreter = recovery.get("luraph_generated_interpreter")
        if not interpreter or not pathlib.Path(interpreter).is_file():
            raise RuntimeError("generated interpreter was not retained as an intermediate artifact")
        observations = recovery.get("observations") or []
        if not any(item.get("classification") == "generated_vm_interpreter" for item in observations):
            raise RuntimeError("generated interpreter classification evidence is missing")
        payload = recovery.get("payload_evidence") or {}
        if payload.get("source_claim") != "none":
            raise RuntimeError(f"runtime behavior was incorrectly presented as source: {payload}")
        events = payload.get("events") or []
        if not any(item.get("kind") == "stdout" and item.get("value") == "generated-interpreter-truth-ok" for item in events):
            raise RuntimeError(f"script-visible output evidence is missing: {payload}")

    print("Luraph generated-interpreter truthfulness OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
