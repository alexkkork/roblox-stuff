#!/usr/bin/env python3
"""Register and upvalue overflow policy contract."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def execute(runtime: pathlib.Path, source: str, mode: str):
    with tempfile.TemporaryDirectory(prefix="rbx-register-overflow-") as temporary:
        root = pathlib.Path(temporary)
        script = root / "subject.luau"
        report = root / "report.json"
        script.write_text(source, encoding="utf-8")
        completed = subprocess.run(
            [
                str(runtime),
                "--minimal-env",
                "--no-native-codegen",
                "--network-policy", "offline",
                "--luau-debug-level", "2",
                "--timeout", "3",
                "--register-overflow", mode,
                "--out", str(root / "captures"),
                "--report", str(report),
                str(script),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        return completed, json.loads(report.read_text(encoding="utf-8"))


def local_pressure_source() -> str:
    declarations = [f"local value_{index} = {index}" for index in range(1, 206)]
    uses = ["local total = 0", *(f"total += value_{index}" for index in range(1, 206))]
    return "\n".join([*declarations, *uses, 'print("overflow-local-ok", total)'])


def upvalue_pressure_source() -> str:
    lines = ["local function outer()"]
    lines.extend(f"local outer_{index} = {index}" for index in range(1, 111))
    lines.append("return function()")
    lines.extend(f"local middle_{index} = {index}" for index in range(1, 111))
    lines.extend(["return function()", "local total = 0"])
    lines.extend(f"total += outer_{index}" for index in range(1, 111))
    lines.extend(f"total += middle_{index}" for index in range(1, 111))
    lines.extend(['print("overflow-upvalue-ok", total)', "end", "end", "end", "outer()()()"])
    return "\n".join(lines)


def local_function_pressure_source() -> str:
    declarations = [f"local function callback_{index}() return {index} end" for index in range(1, 206)]
    uses = ["local total = 0", *(f"total += callback_{index}()" for index in range(1, 206))]
    return "\n".join([*declarations, *uses, 'print("overflow-functions-ok", total)'])


def disconnected_scope_pressure_source() -> str:
    lines = ["local total = 0"]
    for batch in range(1, 4):
        values = range((batch - 1) * 80 + 1, batch * 80 + 1)
        lines.extend(f"local batch_{batch}_{value} = {value}" for value in values)
        lines.extend(f"total += batch_{batch}_{value}" for value in values)
    lines.append('print("overflow-scopes-ok", total)')
    return "\n".join(lines)


def declaration_sinking_pressure_source() -> str:
    setup = [f"local setup_{index} = {index}" for index in range(1, 71)]
    slots = [f"slot_{index}" for index in range(1, 151)]
    lines = ["local total = 0", *setup, "total += setup_1 + setup_70", "local " + ", ".join(slots)]
    lines.append("local before = function() return slot_1 end")
    for index in range(1, 151):
        lines.extend([f"slot_{index} = {index}", f"total += slot_{index}"])
    lines.append('print("overflow-sinking-ok", total, before() == 1)')
    return "\n".join(lines)


def require_spilled(completed: subprocess.CompletedProcess, report: dict, marker: str) -> None:
    usage = report.get("register_overflow") or {}
    if completed.returncode != 0 or marker not in completed.stdout:
        raise RuntimeError(f"spilled program failed:\n{completed.stdout}\n{completed.stderr}")
    if usage.get("mode") != "spill" or usage.get("chunks_rewritten") != 1:
        raise RuntimeError(f"runtime did not report its overflow rewrite: {usage}")
    if usage.get("bindings_spilled", 0) <= 0 or usage.get("functions_rewritten", 0) <= 0:
        raise RuntimeError(f"runtime reported an empty overflow rewrite: {usage}")


def require_narrowed(
    completed: subprocess.CompletedProcess,
    report: dict,
    marker: str,
    *,
    declarations: bool,
) -> None:
    usage = report.get("register_overflow") or {}
    if completed.returncode != 0 or marker not in completed.stdout:
        raise RuntimeError(f"narrowed program failed:\n{completed.stdout}\n{completed.stderr}")
    if usage.get("mode") != "spill" or usage.get("chunks_rewritten") != 1:
        raise RuntimeError(f"runtime did not report its overflow rewrite: {usage}")
    if usage.get("bindings_spilled", 0) != 0:
        raise RuntimeError(f"lifetime narrowing unexpectedly fell back to spilling: {usage}")
    if usage.get("bindings_narrowed", 0) <= 0 or usage.get("functions_rewritten", 0) <= 0:
        raise RuntimeError(f"runtime reported an empty lifetime rewrite: {usage}")
    if usage.get("scopes_narrowed", 0) <= 0:
        raise RuntimeError(f"runtime did not create lexical lifetime scopes: {usage}")
    if declarations and usage.get("declarations_sunk", 0) <= 0:
        raise RuntimeError(f"runtime did not sink the multi-local declaration: {usage}")
    if not declarations and usage.get("declarations_sunk", 0) != 0:
        raise RuntimeError(f"initialized declarations were unexpectedly relocated: {usage}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    args = parser.parse_args()

    rejected, rejected_report = execute(args.runtime, local_pressure_source(), "error")
    if rejected.returncode == 0 or rejected_report.get("termination_reason") != "runtime_error":
        raise RuntimeError("default overflow policy did not preserve Luau's compiler error")
    if "Out of local registers" not in (rejected_report.get("error") or ""):
        raise RuntimeError(f"wrong default compiler diagnostic: {rejected_report.get('error')}")

    scope_run, scope_report = execute(args.runtime, disconnected_scope_pressure_source(), "spill")
    require_narrowed(scope_run, scope_report, "overflow-scopes-ok\t28920", declarations=False)

    sinking_run, sinking_report = execute(args.runtime, declaration_sinking_pressure_source(), "spill")
    require_narrowed(sinking_run, sinking_report, "overflow-sinking-ok\t11396\ttrue", declarations=True)

    local_run, local_report = execute(args.runtime, local_pressure_source(), "spill")
    require_spilled(local_run, local_report, "overflow-local-ok\t21115")

    function_run, function_report = execute(args.runtime, local_function_pressure_source(), "spill")
    require_spilled(function_run, function_report, "overflow-functions-ok\t21115")

    upvalue_run, upvalue_report = execute(args.runtime, upvalue_pressure_source(), "spill")
    require_spilled(upvalue_run, upvalue_report, "overflow-upvalue-ok\t12210")
    if upvalue_report["register_overflow"]["functions_rewritten"] < 2:
        raise RuntimeError("upvalue pressure was not reduced across enclosing functions")

    print("register-overflow-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
