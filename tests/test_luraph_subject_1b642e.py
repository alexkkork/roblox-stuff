#!/usr/bin/env python3
"""Hash-pinned acceptance regression for the Path2D Luraph workload."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "luraph"
MANIFEST_PATH = FIXTURE_DIR / "subject_1b642e9523c1_manifest.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    subject = FIXTURE_DIR / manifest["filename"]
    payload = subject.read_bytes()
    if len(payload) != manifest["bytes"]:
        raise RuntimeError("Luraph regression fixture byte count changed")
    if hashlib.sha256(payload).hexdigest() != manifest["sha256"]:
        raise RuntimeError("Luraph regression fixture SHA-256 changed")

    with tempfile.TemporaryDirectory(prefix="luraph-1b642e-") as temporary:
        report_path = pathlib.Path(temporary) / "report.json"
        command = [
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
            "--luraph-max-steps", "30000000",
            "--luraph-stall-steps", "0",
            "--no-native-codegen",
            "--report", str(report_path),
            str(subject),
        ]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=25,
        )
        if not report_path.is_file():
            raise RuntimeError("runtime did not emit the Luraph acceptance report")
        report = json.loads(report_path.read_text(encoding="utf-8"))

    actual_stdout = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if completed.returncode != 0 or actual_stdout != manifest["expected_stdout"]:
        raise RuntimeError(
            f"Luraph subject failed (exit={completed.returncode})\n"
            f"stdout={actual_stdout!r}\nstderr={completed.stderr}\nreport={report}"
        )
    if report.get("execution_state") != "completed" or report.get("termination_reason") != "completed":
        raise RuntimeError(f"Luraph subject did not complete cleanly: {report}")
    if report.get("workload", {}).get("input_sha256") != manifest["sha256"]:
        raise RuntimeError("runtime report lost the Luraph subject identity")
    if report.get("unsupported"):
        raise RuntimeError(f"Luraph subject encountered unsupported APIs: {report['unsupported']}")

    print("Luraph subject 1b642e acceptance OK: anti-tamper VM reached its payload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
