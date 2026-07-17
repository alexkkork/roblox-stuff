#!/usr/bin/env python3
"""Ensure generated closure bridges are never claimed as exact Luraph source."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-bridge-truth-") as temporary:
        temp = pathlib.Path(temporary)
        report_path = temp / "runtime-report.json"
        completed = subprocess.run(
            [
                str(args.runtime),
                "--profile", "roblox-client",
                "--execution-mode", "faithful",
                "--analysis-hooks", "off",
                "--network-policy", "offline",
                "--clock", "virtual",
                "--timeout", "15",
                "--memory-limit-mb", "768",
                "--unsupported", "trace-nil",
                "--luraph-mode", "force",
                "--luraph-save-intermediates",
                "--luraph-max-steps", "30000000",
                "--luraph-stall-steps", "0",
                "--capture-min", "1",
                "--capture-string-hooks",
                "--no-native-codegen",
                "--report", str(report_path),
                "--out", str(temp),
                str(SUBJECT),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=25,
        )
        if completed.returncode != 0 or "anti tamper BYPASSED" not in completed.stdout:
            raise RuntimeError(f"capture-mode subject failed:\n{completed.stdout}\n{completed.stderr}")
        recovery = json.loads((temp / "luraph_recovery_report.json").read_text(encoding="utf-8"))
        if recovery.get("exact_recovery_status") == "recovered" or recovery.get("original_luau_exact"):
            raise RuntimeError(f"closure bridge was falsely claimed as exact source: {recovery}")
        bridge = recovery.get("luraph_runtime_closure_bridge")
        if not bridge or not pathlib.Path(bridge).is_file():
            raise RuntimeError("closure bridge was not retained as an intermediate artifact")
        observations = recovery.get("observations") or []
        if not any(item.get("classification") == "closure_bridge" for item in observations):
            raise RuntimeError("closure bridge classification evidence is missing")

    print("Luraph bridge truthfulness OK: bridge retained, exact source claim rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
