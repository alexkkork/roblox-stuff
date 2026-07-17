#!/usr/bin/env python3
"""Faithful roblox-client loadstring compatibility for forced Luraph workloads."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "luraph_compat"
SUPPLIED_SAMPLE = pathlib.Path("/Users/alexkkork/Downloads/--- (9)-obfuscated (1).lua")


def run_case(
    runtime: pathlib.Path,
    script: pathlib.Path,
    directory: pathlib.Path,
    name: str,
    *,
    luraph_mode: str,
    timeout: float,
) -> tuple[subprocess.CompletedProcess[str], dict]:
    report_path = directory / f"{name}-report.json"
    command = [
        str(runtime),
        "--profile", "roblox-client",
        "--execution-mode", "faithful",
        "--analysis-hooks", "off",
        "--network-policy", "offline",
        "--clock", "virtual",
        "--timeout", str(timeout),
        "--luraph-mode", luraph_mode,
        "--luraph-max-steps", "2000000000",
        "--luraph-stall-steps", "0",
        "--native-codegen",
        "--report", str(report_path),
        "--out", str(directory / f"{name}-captures"),
        str(script),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 10,
        )
    except subprocess.TimeoutExpired as error:
        raise AssertionError(f"{name}: runtime process exceeded its hard timeout") from error

    if not report_path.is_file():
        raise AssertionError(
            f"{name}: runtime did not write a report (exit={completed.returncode})\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed, json.loads(report_path.read_text(encoding="utf-8"))


def require_success(
    name: str,
    completed: subprocess.CompletedProcess[str],
    report: dict,
    marker: str,
) -> None:
    if completed.returncode != 0 or marker not in completed.stdout:
        raise AssertionError(
            f"{name}: compatibility probe failed (exit={completed.returncode})\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}\nreport:\n{report}"
        )
    if report.get("profile") != "roblox-client" or report.get("execution_mode") != "faithful":
        raise AssertionError(f"{name}: runtime did not preserve faithful roblox-client mode: {report}")
    if report.get("execution_state") != "completed":
        raise AssertionError(f"{name}: probe did not complete cleanly: {report}")


def audit_ordinary_mode(runtime: pathlib.Path, directory: pathlib.Path) -> None:
    completed, report = run_case(
        runtime,
        FIXTURES / "ordinary_roblox_client.luau",
        directory,
        "ordinary",
        luraph_mode="auto",
        timeout=5,
    )
    require_success(
        "ordinary",
        completed,
        report,
        "ordinary-roblox-client-loadstring-hidden-ok",
    )


def audit_forced_luraph_mode(runtime: pathlib.Path, directory: pathlib.Path) -> None:
    completed, report = run_case(
        runtime,
        FIXTURES / "forced_luraph_loadstring.luau",
        directory,
        "forced-luraph",
        luraph_mode="force",
        timeout=5,
    )
    require_success(
        "forced-luraph",
        completed,
        report,
        "forced-luraph-native-loadstring-ok",
    )


def audit_supplied_sample(
    runtime: pathlib.Path,
    directory: pathlib.Path,
    sample: pathlib.Path,
    timeout: float,
) -> bool:
    if not sample.is_file():
        return False

    completed, report = run_case(
        runtime,
        sample,
        directory,
        "supplied-sample",
        luraph_mode="force",
        timeout=timeout,
    )
    printed_son = any(line.strip() == "son" for line in completed.stdout.splitlines())
    timed_out = report.get("termination_reason") == "wall_timeout"
    if completed.returncode != 0 or not printed_son or timed_out:
        raise AssertionError(
            "supplied-sample: expected a successful run that prints an exact 'son' line "
            f"without timing out (exit={completed.returncode}, termination="
            f"{report.get('termination_reason')!r})\nstdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}\nreport:\n{report}"
        )
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    parser.add_argument("--sample", type=pathlib.Path, default=SUPPLIED_SAMPLE)
    parser.add_argument("--sample-timeout", type=float, default=15)
    args = parser.parse_args()
    if args.sample_timeout <= 0:
        parser.error("--sample-timeout must be positive")

    runtime = args.runtime.resolve()
    with tempfile.TemporaryDirectory(prefix="luraph-runtime-compat-") as temporary:
        directory = pathlib.Path(temporary)
        audit_ordinary_mode(runtime, directory)
        audit_forced_luraph_mode(runtime, directory)
        sample_ran = audit_supplied_sample(runtime, directory, args.sample, args.sample_timeout)

    sample_status = "sample passed" if sample_ran else "sample absent (skipped)"
    print(f"Luraph runtime compatibility OK: ordinary hidden; forced native loadstring; {sample_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
