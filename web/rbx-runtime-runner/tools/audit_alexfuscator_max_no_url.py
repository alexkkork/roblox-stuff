#!/usr/bin/env python3
"""Audit max-profile Alexfuscator output for the no-URL plaintext leak case."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


SAMPLE_SOURCE = """\
local sentinel = "ALEXFUSCATOR_MAX_NO_URL_SENTINEL_7f3d2a"
local value = 40 + 2
print("ALEXFUSCATOR_MAX_NO_URL_RESULT", sentinel, value)
"""

PLAINTEXT_NEEDLES = [
    "ALEXFUSCATOR_MAX_NO_URL_SENTINEL_7f3d2a",
    "ALEXFUSCATOR_MAX_NO_URL_RESULT",
]

EXPECTED_RUNTIME_LINE = (
    "ALEXFUSCATOR_MAX_NO_URL_RESULT\t"
    "ALEXFUSCATOR_MAX_NO_URL_SENTINEL_7f3d2a\t"
    "42"
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def is_executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def first_executable(candidates: list[Path]) -> Path | None:
    for candidate in candidates:
        if is_executable(candidate):
            return candidate
    return None


def as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def find_alexfuscator(root: Path, override: str | None) -> Path | None:
    if override:
        return Path(override)
    env_path = os.environ.get("ALEXFUSCATOR")
    if env_path:
        return Path(env_path)
    return first_executable(
        [
            root / "build" / "alexfuscator",
            root / "build" / "Debug" / "alexfuscator",
            root / "build" / "Release" / "alexfuscator",
            root / "outputs" / "alexfuscator" / "alexfuscator-macos-arm64",
            root / "outputs" / "alexfuscator" / "alexfuscator-linux-x64",
            root / "work" / "build" / "alexfuscator",
            root / "work" / "build-ubuntu-x86_64" / "alexfuscator",
            root / "work" / "build-linux-glibc-2.36" / "alexfuscator",
        ]
    )


def find_runtime(root: Path, override: str | None) -> tuple[Path | None, bool]:
    if override:
        return Path(override), True
    env_path = os.environ.get("RBX_LUAU_RUNTIME")
    if env_path:
        return Path(env_path), True
    return (
        first_executable(
            [
                root / "build" / "rbx_luau_runtime",
                root / "outputs" / "rbx_luau_runtime_macos_arm64",
                root / "outputs" / "rbx_luau_runtime_linux_x86_64_glibc_2.36",
                root / "outputs" / "rbx_luau_runtime_ubuntu_x86_64",
                root / "work" / "build" / "rbx_luau_runtime",
                root / "work" / "build-ubuntu-x86_64" / "rbx_luau_runtime",
                root / "work" / "build-linux-glibc-2.36" / "rbx_luau_runtime",
            ]
        ),
        False,
    )


def run_command(command: list[str], timeout: float) -> dict[str, object]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return {
            "command": command,
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "exit_code": None,
            "stdout": as_text(exc.stdout),
            "stderr": as_text(exc.stderr),
            "timed_out": True,
        }


def observable_runtime_lines(stdout: str) -> list[str]:
    return [
        line
        for line in stdout.splitlines()
        if line and not line.startswith("[capture]") and not line.startswith("[main_")
    ]


def build_report(args: argparse.Namespace) -> dict[str, object]:
    root = repo_root()
    alexfuscator = find_alexfuscator(root, args.alexfuscator)
    runtime, runtime_required = find_runtime(root, args.runtime)
    report: dict[str, object] = {
        "ok": False,
        "repo_root": str(root),
        "sample": {
            "name": "max_no_url",
            "bytes": len(SAMPLE_SOURCE.encode()),
            "has_url": "://" in SAMPLE_SOURCE or "www." in SAMPLE_SOURCE.lower(),
            "plaintext_needles": PLAINTEXT_NEEDLES,
        },
        "alexfuscator": {"path": str(alexfuscator) if alexfuscator else None},
        "checks": {},
        "runtime": {"status": "not_run"},
    }

    if not alexfuscator or not is_executable(alexfuscator):
        report["error"] = "alexfuscator executable not found"
        return report

    temp_dir = tempfile.mkdtemp(prefix="alexfuscator_max_no_url_")
    work_dir = Path(temp_dir)
    if args.keep_temp:
        report["work_dir"] = str(work_dir)

    try:
        input_path = work_dir / "max_no_url_sample.luau"
        output_path = work_dir / "max_no_url_sample.obf.luau"
        debug_path = work_dir / "debug_map.json"
        input_path.write_text(SAMPLE_SOURCE)

        alex_cmd = [
            str(alexfuscator),
            str(input_path),
            "-o",
            str(output_path),
            "--profile",
            "max",
            "--target",
            "roblox-luau",
            "--debug-map",
            str(debug_path),
            "--max-vm-v2",
            "--one-line",
            "--compat-test-mode",
        ]
        alex_run = run_command(alex_cmd, args.timeout)
        report["alexfuscator"] = {
            "path": str(alexfuscator),
            "command": alex_run["command"],
            "exit_code": alex_run["exit_code"],
            "stdout": alex_run["stdout"],
            "stderr": alex_run["stderr"],
            "timed_out": alex_run["timed_out"],
        }

        output_text = output_path.read_text() if output_path.exists() else ""
        leaked_needles = [needle for needle in PLAINTEXT_NEEDLES if needle in output_text]
        checks = {
            "output_exists": output_path.exists(),
            "output_bytes": len(output_text.encode()),
            "one_line": bool(output_text) and "\n" not in output_text and "\r" not in output_text,
            "leaked_plaintext_needles": leaked_needles,
            "no_plaintext_needle_leaks": not leaked_needles,
            "sample_has_no_url": not report["sample"]["has_url"],
        }
        report["checks"] = checks

        alex_ok = (
            alex_run["exit_code"] == 0
            and checks["output_exists"]
            and checks["one_line"]
            and checks["no_plaintext_needle_leaks"]
            and checks["sample_has_no_url"]
        )
        if not alex_ok:
            return report

        if args.skip_runtime:
            report["runtime"] = {"status": "skipped"}
            report["ok"] = True
            return report

        if runtime is None:
            report["runtime"] = {"status": "missing"}
            report["ok"] = True
            return report

        if not is_executable(runtime):
            report["runtime"] = {
                "status": "missing",
                "path": str(runtime),
                "required": runtime_required,
            }
            report["ok"] = not runtime_required
            return report

        capture_dir = work_dir / "captures"
        runtime_cmd = [
            str(runtime),
            "--profile",
            "executor-client",
            "--network-policy",
            "offline",
            "--timeout",
            str(args.runtime_timeout),
            "--capture-min",
            "1",
            "--no-capture-string-hooks",
            "--out",
            str(capture_dir),
            str(output_path),
        ]
        runtime_run = run_command(runtime_cmd, args.runtime_timeout + 5)
        observed = observable_runtime_lines(str(runtime_run["stdout"]))
        runtime_ok = runtime_run["exit_code"] == 0 and observed == [EXPECTED_RUNTIME_LINE]
        report["runtime"] = {
            "status": "run",
            "path": str(runtime),
            "command": runtime_run["command"],
            "exit_code": runtime_run["exit_code"],
            "stdout": runtime_run["stdout"],
            "stderr": runtime_run["stderr"],
            "timed_out": runtime_run["timed_out"],
            "observable_stdout": observed,
            "expected_stdout": [EXPECTED_RUNTIME_LINE],
            "matches_expected_stdout": runtime_ok,
        }
        report["ok"] = runtime_ok
        return report
    finally:
        if not args.keep_temp:
            shutil.rmtree(work_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alexfuscator", help="Path to alexfuscator; defaults to common build/output paths")
    parser.add_argument("--runtime", help="Path to rbx_luau_runtime; defaults to auto-detect if present")
    parser.add_argument("--skip-runtime", action="store_true", help="Do not run rbx_luau_runtime even if present")
    parser.add_argument("--timeout", type=float, default=60.0, help="Alexfuscator timeout in seconds")
    parser.add_argument("--runtime-timeout", type=float, default=10.0, help="Runtime timeout in seconds")
    parser.add_argument("--keep-temp", action="store_true", help="Keep the temporary work directory and include it in JSON")
    args = parser.parse_args()

    report = build_report(args)
    print(json.dumps(report, indent=2))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
