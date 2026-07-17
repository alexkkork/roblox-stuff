#!/usr/bin/env python3
"""Generate and behavior-check a Balenci/WeAreDevs reconstruction.

This is intentionally a release gate, not a source-recovery heuristic.  It runs
the protected and reconstructed chunks in fresh runtime processes and reports
the same source-quality score used by the hosted deobfuscator.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_DEOBFUSCATOR = ROOT / "build" / "alex_deobfuscator"
DEFAULT_RUNTIME = ROOT / "build" / "rbx_luau_runtime"
QUALITY_ANALYZER = ROOT / "web" / "rbx-runtime-runner" / "scripts" / "deobfuscate-handler.js"
DEFAULT_NODE = pathlib.Path("/opt/homebrew/bin/node")


def run(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def normalize_runtime_value(value: Any, chunks: tuple[pathlib.Path, ...]) -> Any:
    if isinstance(value, list):
        return [normalize_runtime_value(item, chunks) for item in value]
    if isinstance(value, dict):
        return {key: normalize_runtime_value(item, chunks) for key, item in value.items()}
    if not isinstance(value, str):
        return value
    normalized = value
    for chunk in chunks:
        normalized = normalized.replace(str(chunk), "<chunk>")
    normalized = re.sub(r"<chunk>:\d+", "<chunk>:<line>", normalized)
    return re.sub(r"loadstring:\d+", "loadstring:<line>", normalized)


def runtime_projection(report: dict[str, Any], chunks: tuple[pathlib.Path, ...]) -> dict[str, Any]:
    scheduler = report.get("scheduler") or {}
    projection = {
        "status": report.get("status"),
        "termination_reason": report.get("termination_reason"),
        "returns": report.get("returns", []),
        "stdout": report.get("stdout", []),
        "stderr": report.get("stderr", []),
        "error": report.get("error"),
        "engine": report.get("engine"),
        "network_requirements": report.get("network_requirements", []),
        "scheduler": {
            "budget_reached": scheduler.get("budget_reached", False),
            "errors": scheduler.get("errors", []),
            "events": [
                {key: event.get(key) for key in ("kind", "frame", "time")}
                for event in scheduler.get("events", [])
            ],
            "frames": scheduler.get("frames", 0),
            "pending": scheduler.get("pending"),
            "stop_reason": scheduler.get("stop_reason"),
            "timed_out": scheduler.get("timed_out", False),
            "virtual_time": scheduler.get("virtual_time", 0),
        },
    }
    return normalize_runtime_value(projection, chunks)


def execute_runtime(runtime: pathlib.Path, source: pathlib.Path, report_path: pathlib.Path, timeout: float) -> dict[str, Any]:
    result = run(
        [
            str(runtime),
            "--profile",
            "executor-client",
            "--executor-preset",
            "opiumware",
            "--execution-mode",
            "faithful",
            "--clock",
            "virtual",
            "--frame-rate",
            "60",
            "--max-virtual-seconds",
            "30",
            "--unsupported",
            "trace-nil",
            "--analysis-hooks",
            "off",
            "--network-policy",
            "offline",
            "--timeout",
            "25",
            "--report",
            str(report_path),
            str(source),
        ],
        timeout,
    )
    if not report_path.is_file():
        raise RuntimeError(
            f"runtime omitted {report_path} (exit {result.returncode})\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return json.loads(report_path.read_text(encoding="utf-8"))


def generate_candidate(
    deobfuscator: pathlib.Path,
    source: pathlib.Path,
    output_dir: pathlib.Path,
    trace: pathlib.Path | None,
    timeout: float,
) -> tuple[pathlib.Path, dict[str, Any]]:
    command = [
        str(deobfuscator),
        str(source),
        "--output-dir",
        str(output_dir),
        "--mode",
        "reconstruct",
        "--report",
        "-",
    ]
    if trace is not None:
        command.extend(["--trace", str(trace)])
    result = run(command, timeout)
    report_path = output_dir / "deobfuscation_report.json"
    candidate = output_dir / "reconstructed_candidate.luau"
    if not report_path.is_file() or not candidate.is_file():
        raise RuntimeError(
            f"deobfuscator withheld its candidate (exit {result.returncode})\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return candidate, json.loads(report_path.read_text(encoding="utf-8"))


def analyze_quality(node: pathlib.Path, candidate: pathlib.Path) -> dict[str, Any]:
    script = (
        "const fs=require('fs');"
        "const h=require(process.argv[1])._test;"
        "process.stdout.write(JSON.stringify(h.analyzeSourceQuality(fs.readFileSync(process.argv[2],'utf8'))));"
    )
    result = run([str(node), "-e", script, str(QUALITY_ANALYZER), str(candidate)], 15)
    if result.returncode != 0:
        raise RuntimeError(f"quality analyzer failed:\n{result.stderr}")
    return json.loads(result.stdout)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path, help="protected WeAreDevs Luau input")
    parser.add_argument("--candidate", type=pathlib.Path, help="check an existing reconstruction")
    parser.add_argument("--output-dir", type=pathlib.Path, default=pathlib.Path("/tmp/balenci-quality-gate"))
    parser.add_argument("--trace", type=pathlib.Path)
    parser.add_argument("--deobfuscator", type=pathlib.Path, default=DEFAULT_DEOBFUSCATOR)
    parser.add_argument("--runtime", type=pathlib.Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--node", type=pathlib.Path, default=DEFAULT_NODE)
    parser.add_argument("--analysis-timeout", type=float, default=90.0)
    parser.add_argument("--runtime-timeout", type=float, default=45.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = args.source.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    deobfuscation_report: dict[str, Any] | None = None

    if args.candidate is None:
        trace = args.trace.expanduser().resolve() if args.trace else None
        candidate, deobfuscation_report = generate_candidate(
            args.deobfuscator.expanduser().resolve(), source, output_dir, trace, args.analysis_timeout
        )
    else:
        candidate = args.candidate.expanduser().resolve()

    quality = analyze_quality(args.node.expanduser(), candidate)
    source_report_path = output_dir / "runtime-protected.json"
    candidate_report_path = output_dir / "runtime-reconstructed.json"
    source_report = execute_runtime(args.runtime.expanduser().resolve(), source, source_report_path, args.runtime_timeout)
    candidate_report = execute_runtime(
        args.runtime.expanduser().resolve(), candidate, candidate_report_path, args.runtime_timeout
    )
    chunks = (source, candidate)
    protected_projection = runtime_projection(source_report, chunks)
    reconstructed_projection = runtime_projection(candidate_report, chunks)
    equivalent = protected_projection == reconstructed_projection

    reached_target = equivalent and quality.get("score") == 100
    summary = {
        "ok": reached_target,
        "candidate": str(candidate),
        "compiled": candidate_report.get("status") != "compile_error",
        "runtime_equivalent": equivalent,
        "quality": quality,
        "deobfuscation_status": (deobfuscation_report or {}).get("status"),
        "protected_status": source_report.get("status"),
        "reconstructed_status": candidate_report.get("status"),
        "projection_difference": None
        if equivalent
        else {"protected": protected_projection, "reconstructed": reconstructed_projection},
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if reached_target else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2), file=sys.stderr)
        raise SystemExit(2)
