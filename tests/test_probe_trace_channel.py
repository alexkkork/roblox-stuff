#!/usr/bin/env python3
"""Dedicated Luraph probe-trace output channel contract."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


PROBE_TRACE_LIMIT_BYTES = 64 * 1024 * 1024
MAX_PROBE_TRACE_LIMIT_BYTES = 1024 * 1024 * 1024


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    args = parser.parse_args()

    marker_lines = [
        "@@LPH_PROTO_V1@@\t7\tD,G",
        "@@LPH_STEP_V1@@\t11\t7\t3\t22\t4\t0",
    ]
    ordinary_line = "ordinary-runtime-output\t42"

    with tempfile.TemporaryDirectory(prefix="rbx-probe-trace-channel-") as temporary:
        root = Path(temporary)
        script_path = root / "subject.luau"
        trace_path = root / "probe-trace.log"
        report_path = root / "report.json"
        script_path.write_text(
            "\n".join(
                [
                    'print("@@LPH_PROTO_V1@@", 7, "D,G")',
                    'print("ordinary-runtime-output", 42)',
                    'print("@@LPH_STEP_V1@@", 11, 7, 3, 22, 4, 0)',
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        def run_runtime(
            run_trace_path: Path,
            run_report_path: Path,
            *extra_args: str,
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    str(args.runtime.resolve()),
                    "--profile",
                    "executor-client",
                    "--execution-mode",
                    "faithful",
                    "--network-policy",
                    "offline",
                    "--clock",
                    "virtual",
                    "--timeout",
                    "5",
                    "--no-native-codegen",
                    "--analysis-hooks",
                    "off",
                    "--probe-trace",
                    str(run_trace_path),
                    *extra_args,
                    "--report",
                    str(run_report_path),
                    str(script_path),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )

        completed = run_runtime(trace_path, report_path)

        if completed.returncode != 0:
            raise AssertionError(
                f"runtime exited {completed.returncode}:\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )

        expected_trace = ("\n".join(marker_lines) + "\n").encode("utf-8")
        actual_trace = trace_path.read_bytes()
        report = json.loads(report_path.read_text(encoding="utf-8"))

        if actual_trace != expected_trace:
            raise AssertionError(
                f"dedicated trace contents differ:\nexpected={expected_trace!r}\nactual={actual_trace!r}"
            )
        if ordinary_line in actual_trace.decode("utf-8"):
            raise AssertionError("ordinary print leaked into the dedicated probe trace")

        if completed.stdout.splitlines() != [ordinary_line]:
            raise AssertionError(f"unexpected runtime stdout: {completed.stdout!r}")
        if "@@LPH_" in completed.stdout or "@@LPH_" in completed.stderr:
            raise AssertionError("probe marker leaked into process output")
        if report.get("stdout") != [ordinary_line] or report.get("stderr") != []:
            raise AssertionError(
                f"ordinary output was not preserved in the report: "
                f"stdout={report.get('stdout')!r} stderr={report.get('stderr')!r}"
            )
        if "@@LPH_" in json.dumps(report.get("stdout")) or "@@LPH_" in json.dumps(report.get("stderr")):
            raise AssertionError("probe marker leaked into report output")

        limits = report.get("limits") or {}
        actual_size = trace_path.stat().st_size
        if limits.get("probe_trace_bytes") != actual_size or actual_size != len(expected_trace):
            raise AssertionError(
                f"probe trace byte count is not truthful: limits={limits!r} size={actual_size}"
            )
        if limits.get("probe_trace_limit_bytes") != PROBE_TRACE_LIMIT_BYTES:
            raise AssertionError(f"wrong probe trace cap: {limits!r}")
        if limits.get("probe_trace_limit_hit") is not False:
            raise AssertionError(f"probe trace unexpectedly reported a cap hit: {limits!r}")
        if limits["probe_trace_bytes"] > limits["probe_trace_limit_bytes"]:
            raise AssertionError(f"probe trace accounting exceeds its reported cap: {limits!r}")

        custom_trace_path = root / "custom-probe-trace.log"
        custom_report_path = root / "custom-report.json"
        custom_limit = len(expected_trace)
        custom_completed = run_runtime(
            custom_trace_path,
            custom_report_path,
            "--probe-trace-limit-bytes",
            str(custom_limit),
        )
        if custom_completed.returncode != 0:
            raise AssertionError(
                f"runtime rejected an exact custom trace cap:\n"
                f"stdout:\n{custom_completed.stdout}\nstderr:\n{custom_completed.stderr}"
            )
        custom_limits = json.loads(
            custom_report_path.read_text(encoding="utf-8")
        ).get("limits", {})
        if custom_trace_path.read_bytes() != expected_trace:
            raise AssertionError("custom trace cap changed the accepted trace contents")
        if custom_limits.get("probe_trace_limit_bytes") != custom_limit:
            raise AssertionError(f"custom probe trace cap was not reported: {custom_limits!r}")
        if custom_limits.get("probe_trace_bytes") != custom_limit:
            raise AssertionError(f"custom probe trace byte count is not exact: {custom_limits!r}")
        if custom_limits.get("probe_trace_limit_hit") is not False:
            raise AssertionError(f"exact custom probe trace cap was reported as hit: {custom_limits!r}")

        capped_trace_path = root / "capped-probe-trace.log"
        capped_report_path = root / "capped-report.json"
        capped_limit = len((marker_lines[0] + "\n").encode("utf-8"))
        capped_completed = run_runtime(
            capped_trace_path,
            capped_report_path,
            "--probe-trace-limit-bytes",
            str(capped_limit),
        )
        if capped_completed.returncode == 0:
            raise AssertionError("runtime did not enforce the custom probe trace cap")
        capped_limits = json.loads(
            capped_report_path.read_text(encoding="utf-8")
        ).get("limits", {})
        if capped_trace_path.read_bytes() != (marker_lines[0] + "\n").encode("utf-8"):
            raise AssertionError("probe trace cap did not preserve only the accepted prefix")
        if capped_limits.get("probe_trace_limit_bytes") != capped_limit:
            raise AssertionError(f"enforced probe trace cap was not reported: {capped_limits!r}")
        if capped_limits.get("probe_trace_bytes") != capped_limit:
            raise AssertionError(f"capped probe trace byte count is not truthful: {capped_limits!r}")
        if capped_limits.get("probe_trace_limit_hit") is not True:
            raise AssertionError(f"probe trace cap hit was not reported: {capped_limits!r}")

        invalid_limits = [
            ("0", "must be at least 1"),
            (str(MAX_PROBE_TRACE_LIMIT_BYTES + 1), "must not exceed"),
        ]
        for value, expected_error in invalid_limits:
            invalid_completed = run_runtime(
                root / f"invalid-{value}.log",
                root / f"invalid-{value}.json",
                "--probe-trace-limit-bytes",
                value,
            )
            if invalid_completed.returncode == 0:
                raise AssertionError(f"runtime accepted invalid probe trace cap {value}")
            if expected_error not in invalid_completed.stderr:
                raise AssertionError(
                    f"runtime gave the wrong error for probe trace cap {value}: "
                    f"{invalid_completed.stderr!r}"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
