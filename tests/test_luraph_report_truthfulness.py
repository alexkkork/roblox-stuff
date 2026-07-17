#!/usr/bin/env python3
"""Regression contract for truthful Luraph workload and budget reporting.

This test deliberately distinguishes an interrupt/safepoint limit from a real
scheduler steady state.  It is kept standalone so integration can opt into the
contract once the report producer implements it.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


def run_case(
    runtime: pathlib.Path,
    directory: pathlib.Path,
    name: str,
    source: str,
    *,
    max_steps: int = 1_000_000,
    max_virtual_seconds: float = 1.0,
    wall_timeout: float = 10.0,
    scenario: dict = None,
) -> tuple[subprocess.CompletedProcess[str], dict]:
    script = directory / f"{name}.luau"
    report = directory / f"{name}.json"
    captures = directory / f"{name}-captures"
    script.write_text(source, encoding="utf-8")
    arguments = [
        str(runtime),
        "--profile", "executor-client",
        "--execution-mode", "faithful",
        "--analysis-hooks", "off",
        "--executor-preset", "generic",
        "--filesystem", "memory",
        "--network-policy", "offline",
        "--clock", "virtual",
        "--max-virtual-seconds", str(max_virtual_seconds),
        "--timeout", str(wall_timeout),
        "--luraph-mode", "force",
        "--luraph-max-steps", str(max_steps),
        "--luraph-stall-steps", "0",
        "--native-codegen",
        "--report", str(report),
        "--out", str(captures),
    ]
    if scenario is not None:
        scenario_path = directory / f"{name}-scenario.json"
        scenario_path.write_text(json.dumps(scenario), encoding="utf-8")
        arguments.extend(["--scenario", str(scenario_path)])
    arguments.append(str(script))
    completed = subprocess.run(
        arguments,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    if not report.is_file():
        raise AssertionError(
            f"{name}: no report (exit={completed.returncode})\n"
            f"stdout={completed.stdout[-1000:]!r}\nstderr={completed.stderr[-1000:]!r}"
        )
    return completed, json.loads(report.read_text(encoding="utf-8"))


def native_tasks(report: dict) -> list[dict]:
    runtime = report.get("native_runtime") or {}
    scheduler = runtime.get("scheduler") or {}
    return [task for task in scheduler.get("tasks") or [] if isinstance(task, dict)]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def audit_no_activity_codegen(runtime: pathlib.Path, directory: pathlib.Path) -> None:
    completed, report = run_case(
        runtime,
        directory,
        "codegen_is_not_payload",
        "-- Luraph VM\nlocal total = 0\nfor i = 1, 100 do total += i end\n",
    )
    workload = report.get("workload") or {}
    require(completed.returncode == 0, f"no-activity completion exited {completed.returncode}")
    require(report.get("execution_state") == "completed", f"no-activity state: {report.get('execution_state')!r}")
    require((report.get("codegen") or {}).get("chunks_native_succeeded", 0) > 0, "case did not exercise native CodeGen")
    require(workload.get("payload_activity") is False, f"CodeGen events were counted as payload: {workload!r}")
    require(not (workload.get("activity_evidence") or []), f"no-op chunk has activity evidence: {workload!r}")


def audit_safepoint_limit(runtime: pathlib.Path, directory: pathlib.Path) -> None:
    completed, report = run_case(
        runtime,
        directory,
        "safepoint_limit_is_failure",
        "-- Luraph VM\nlocal counter = 0\nwhile true do counter += 1 end\n",
        max_steps=20_000,
    )
    workload = report.get("workload") or {}
    scheduler = report.get("scheduler") or {}
    require(completed.returncode != 0, "forced safepoint termination returned success")
    require(report.get("execution_state") == "failed", f"safepoint state: {report.get('execution_state')!r}")
    require(report.get("status") == "instruction_budget", f"safepoint status: {report.get('status')!r}")
    require(report.get("termination_reason") == "instruction_budget", f"safepoint termination: {report.get('termination_reason')!r}")
    require(report.get("steady_state_reason") is None, "safepoint failure has a healthy steady-state reason")
    require(scheduler.get("stop_reason") == "instruction_budget", f"scheduler stop reason: {scheduler.get('stop_reason')!r}")
    require(scheduler.get("budget_reached") is True, "scheduler did not record the exhausted budget")
    require(workload.get("safepoints", 20_017) <= 20_016, f"safepoint cap overran materially: {workload!r}")
    require(workload.get("payload_activity") is False, f"busy-loop bookkeeping was counted as payload: {workload!r}")
    require(not (workload.get("activity_evidence") or []), f"busy loop has fabricated activity evidence: {workload!r}")
    require(isinstance(report.get("error"), str) and report["error"], "safepoint failure omitted its error")
    require(any(task.get("state") == "failed" for task in native_tasks(report)), "native failed task was hidden")


def audit_sentinel_is_not_trusted(runtime: pathlib.Path, directory: pathlib.Path) -> None:
    completed, report = run_case(
        runtime,
        directory,
        "sentinel_text_is_an_error",
        "-- Luraph VM\nerror('__RBX_INSTRUCTION_BUDGET__')\n",
    )
    require(completed.returncode != 0, "script-forged budget sentinel returned success")
    require(report.get("execution_state") == "failed", f"forged sentinel state: {report.get('execution_state')!r}")
    require(report.get("status") == "runtime_error", f"forged sentinel status: {report.get('status')!r}")
    require(report.get("termination_reason") == "runtime_error", f"forged sentinel termination: {report.get('termination_reason')!r}")
    require(report.get("steady_state_reason") is None, "forged sentinel produced a steady-state reason")
    require((report.get("scheduler") or {}).get("budget_reached") is not True, "forged sentinel exhausted a host budget")


def audit_protected_host_limits(runtime: pathlib.Path, directory: pathlib.Path) -> None:
    protected = "-- Luraph VM\nlocal ok, err = pcall(function() while true do end end)\nreturn ok, err\n"
    completed, report = run_case(runtime, directory, "pcall_cannot_catch_budget", protected, max_steps=20_000)
    require(completed.returncode != 0, "pcall converted the host instruction budget into success")
    require(report.get("status") == "instruction_budget", f"protected budget status: {report.get('status')!r}")
    require(report.get("execution_state") == "failed", f"protected budget state: {report.get('execution_state')!r}")
    require(not (report.get("returns") or []), f"protected budget leaked caught sentinel returns: {report.get('returns')!r}")

    completed, report = run_case(
        runtime,
        directory,
        "pcall_cannot_catch_timeout",
        protected,
        max_steps=0,
        wall_timeout=0.25,
    )
    require(completed.returncode != 0, "pcall converted the host wall timeout into success")
    require(report.get("termination_reason") == "wall_timeout", f"protected timeout reason: {report.get('termination_reason')!r}")
    require(report.get("execution_state") == "failed", f"protected timeout state: {report.get('execution_state')!r}")
    require(not (report.get("returns") or []), f"protected timeout leaked caught error returns: {report.get('returns')!r}")


def audit_signal_steady_state(runtime: pathlib.Path, directory: pathlib.Path) -> None:
    completed, report = run_case(
        runtime,
        directory,
        "signal_wait_is_steady",
        "-- Luraph VM\nlocal event = Instance.new('BindableEvent')\nevent.Event:Wait()\n",
    )
    reason = report.get("steady_state_reason")
    tasks = native_tasks(report)
    require(completed.returncode == 0, f"signal wait exited {completed.returncode}")
    require(report.get("execution_state") == "steady_state", f"signal state: {report.get('execution_state')!r}")
    require(isinstance(reason, str) and reason.startswith("waiting_signal:"), f"signal reason: {reason!r}")
    require(any(task.get("state") == "waiting-signal" for task in tasks), f"signal waiter missing: {tasks!r}")
    require(not any(task.get("state") == "failed" for task in tasks), f"signal steady state contains a failed task: {tasks!r}")


def audit_timer_steady_state(runtime: pathlib.Path, directory: pathlib.Path) -> None:
    completed, report = run_case(
        runtime,
        directory,
        "timer_wait_is_steady",
        "-- Luraph VM\ntask.wait(10)\n",
        max_virtual_seconds=0.25,
    )
    tasks = native_tasks(report)
    require(completed.returncode == 0, f"timer wait exited {completed.returncode}")
    require(report.get("execution_state") == "steady_state", f"timer state: {report.get('execution_state')!r}")
    require(report.get("status") == "virtual_budget", f"timer status: {report.get('status')!r}")
    require(report.get("steady_state_reason") == "virtual_time_budget", f"timer reason: {report.get('steady_state_reason')!r}")
    require(any(task.get("state") == "waiting-timer" for task in tasks), f"timer waiter missing: {tasks!r}")
    require(not any(task.get("state") == "failed" for task in tasks), f"timer steady state contains a failed task: {tasks!r}")


def audit_pre_main_task_failure(runtime: pathlib.Path, directory: pathlib.Path) -> None:
    completed, report = run_case(
        runtime,
        directory,
        "pre_main_failure_is_not_steady",
        "-- Luraph VM\nlocal event = Instance.new('BindableEvent')\nevent.Event:Wait()\n",
        scenario={
            "version": 2,
            "scheduled_property_changes": [
                {"at": 0, "target": "game.DoesNotExist", "property": "Name", "value": "bad"},
            ],
        },
    )
    tasks = native_tasks(report)
    require(completed.returncode != 0, "pre-main scenario task failure returned success")
    require(report.get("execution_state") == "failed", f"pre-main failure state: {report.get('execution_state')!r}")
    require(report.get("steady_state_reason") is None, "pre-main failure was labeled steady")
    require(any(task.get("state") == "failed" for task in tasks), f"pre-main failed task missing: {tasks!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    with tempfile.TemporaryDirectory(prefix="luraph-report-truth-") as temporary:
        directory = pathlib.Path(temporary)
        audit_no_activity_codegen(runtime, directory)
        audit_safepoint_limit(runtime, directory)
        audit_sentinel_is_not_trusted(runtime, directory)
        audit_protected_host_limits(runtime, directory)
        audit_signal_steady_state(runtime, directory)
        audit_timer_steady_state(runtime, directory)
        audit_pre_main_task_failure(runtime, directory)
    print("Luraph reporting truthfulness: 8/8 passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
