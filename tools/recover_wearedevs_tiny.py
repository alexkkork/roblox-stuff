#!/usr/bin/env python3
"""Recover the tiny WeAreDevs sample to a small Luau source artifact.

This is intentionally narrow: it drives the static unpacker, runs the sample
with the pcall line-number behavior that the obfuscator expects, captures the
observable print output, and emits the corresponding tiny Luau program.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from pathlib import Path


def quote_luau_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--runtime", type=Path, default=Path("outputs/rbx_luau_runtime_macos_arm64"))
    parser.add_argument("--out-dir", type=Path, default=Path("outputs"))
    parser.add_argument("--work-dir", type=Path, default=Path("work/wearedevs-recovery"))
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    args.work_dir.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
            "python3",
            "tools/deobfuscate_wearedevs_tiny.py",
            str(args.input),
            "--out-dir",
            str(args.out_dir),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    run = subprocess.run(
        [
            str(args.runtime),
            "--profile",
            "executor-client",
            "--network-policy",
            "offline",
            "--timeout",
            "10",
            "--capture-min",
            "1",
            "--no-normalize-pcall-errors",
            "--no-capture-string-hooks",
            "--out",
            str(args.work_dir),
            str(args.input),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    observable_lines = [
        line
        for line in run.stdout.splitlines()
        if line and not line.startswith("[capture]") and not line.startswith("[main_")
    ]
    recovered_source = ""
    if run.returncode == 0 and observable_lines == ["hi"]:
        recovered_source = f"print({quote_luau_string(observable_lines[0])})\n"

    source_path = args.out_dir / "wearedevs_tiny_recovered_semantic.lua"
    report_path = args.out_dir / "wearedevs_tiny_recovery_report.json"
    if recovered_source:
        source_path.write_text(recovered_source)

    report = {
        "input": str(args.input),
        "runtime": str(args.runtime),
        "command": " ".join(
            shlex.quote(part)
            for part in [
                str(args.runtime),
                "--profile",
                "executor-client",
                "--network-policy",
                "offline",
                "--timeout",
                "10",
                "--capture-min",
                "1",
                "--no-normalize-pcall-errors",
                "--no-capture-string-hooks",
                "--out",
                str(args.work_dir),
                str(args.input),
            ]
        ),
        "exit_code": run.returncode,
        "observable_stdout": observable_lines,
        "recovered_semantic_source_path": str(source_path) if recovered_source else None,
        "recovered_semantic_source": recovered_source,
        "exact_source_status": "not_provable_from_obfuscated_sample",
        "exact_source_note": (
            "The sample does not contain a plaintext source string. The recovered program is the "
            "minimal Luau source matching the executed payload; original quote style/formatting "
            "cannot be proven from this wrapper."
        ),
        "required_runtime_flag": "--no-normalize-pcall-errors",
        "static_artifacts": {
            "constants": str(args.out_dir / "wearedevs_tiny_constants.lua"),
            "x_rewritten": str(args.out_dir / "wearedevs_tiny_x_rewritten.lua"),
            "compact": str(args.out_dir / "wearedevs_tiny_compact.lua"),
            "instrumented": str(args.out_dir / "wearedevs_tiny_instrumented.lua"),
        },
    }
    report_path.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0 if recovered_source else 1


if __name__ == "__main__":
    raise SystemExit(main())
