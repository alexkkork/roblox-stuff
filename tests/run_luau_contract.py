#!/usr/bin/env python3
"""Run one Luau conformance program and validate its release-729 report."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    parser.add_argument("--script", type=pathlib.Path, required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--profile", choices=("roblox-client", "executor-client"), default="roblox-client")
    parser.add_argument("--scenario", type=pathlib.Path)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--allow-unsupported", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rbx-luau-contract-") as temporary:
        temp = pathlib.Path(temporary)
        report_path = temp / "report.json"
        command = [
            str(args.runtime),
            "--profile", args.profile,
            "--execution-mode", "faithful",
            "--analysis-hooks", "off",
            "--network-policy", "offline",
            "--clock", "virtual",
            "--timeout", str(args.timeout),
            "--report", str(report_path),
            "--out", str(temp / "captures"),
        ]
        if args.scenario:
            command.extend(("--scenario", str(args.scenario)))
        command.append(str(args.script))
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout + 10,
        )
        if completed.returncode:
            raise RuntimeError(f"contract failed ({completed.returncode}):\n{completed.stdout}\n{completed.stderr}")
        if args.marker not in completed.stdout:
            raise RuntimeError(f"contract marker {args.marker!r} is missing:\n{completed.stdout}\n{completed.stderr}")
        if not report_path.is_file():
            raise RuntimeError("runtime did not write its report")
        report = json.loads(report_path.read_text(encoding="utf-8"))

    if report.get("version") != 3 or report.get("engine_release") != "729":
        raise RuntimeError(f"wrong report contract: version={report.get('version')} release={report.get('engine_release')}")
    if report.get("execution_mode") != "faithful" or report.get("profile") != args.profile:
        raise RuntimeError("runtime report did not preserve the requested faithful profile")
    if report.get("execution_state") not in {"completed", "steady_state"}:
        raise RuntimeError(f"contract did not complete cleanly: {report.get('execution_state')}: {report.get('error')}")
    if report.get("unsupported") and not args.allow_unsupported:
        raise RuntimeError(f"contract encountered unsupported APIs: {report['unsupported']}")
    print(f"Luau contract OK: {args.script.name} ({args.marker})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
