#!/usr/bin/env python3
"""Black-box Wave-2/3 contracts for the release-729 runtime.

This harness deliberately uses only the public CLI, scenario v2, script-visible
Roblox APIs, and report v3.  It is kept out of CTest until the primary owner
chooses the final integration point.  A failure therefore identifies a gap in
the built runner rather than reaching into private C++ test hooks.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Iterable


ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED_API_SHA256 = "88de6ce88153b2c7d226d7c2d22752e6e04d266c28b36809d9d61bf8256cf6bd"
EXPECTED_LUAU_COMMIT = "6e9b580e2e24643214caf0f4bbbb3db911ca30f3"
NETWORK_URL = "https://blackbox.invalid/release-729"
NETWORK_HOST = "blackbox.invalid"


PHASE_SOURCE = r'''
local runService = game:GetService("RunService")
local observed = {}
local firstFrameFinished = false

local function observe(name)
    if not firstFrameFinished then
        table.insert(observed, name)
        if name == "Heartbeat" then
            firstFrameFinished = true
        end
    end
end

for _, phase in ipairs({
    "PreRender",
    "RenderStepped",
    "PreAnimation",
    "PreSimulation",
    "Stepped",
    "PostSimulation",
    "Heartbeat",
}) do
    runService[phase]:Connect(function()
        observe(phase)
    end)
end

runService:BindToRenderStep("replacement", 50, function()
    observe("bind:old")
end)
runService:BindToRenderStep("replacement", 50, function()
    observe("bind:replacement")
end)
runService:BindToRenderStep("early", 100, function()
    observe("bind:early")
end)
runService:BindToRenderStep("late", 200, function()
    observe("bind:late")
end)

-- Four virtual frames plus one scheduler turn are ample for a first frame and
-- for deferred SignalBehavior callbacks to drain.
task.wait(4 / 60)
task.wait()

runService:UnbindFromRenderStep("replacement")
runService:UnbindFromRenderStep("early")
runService:UnbindFromRenderStep("late")
print("BLACKBOX_PHASE|" .. table.concat(observed, ","))
return table.concat(observed, ",")
'''


CANCELLATION_SOURCE = r'''
local event = Instance.new("BindableEvent")
local delayedFired = false
local scheduledSignalResumed = false
local manualTimerResumed = false
local manualSignalResumed = false

local delayed = task.delay(30, function()
    delayedFired = true
end)
task.cancel(delayed)

local scheduledSignal = task.spawn(function()
    event.Event:Wait()
    scheduledSignalResumed = true
end)

local manualTimer = coroutine.create(function()
    task.wait(30)
    manualTimerResumed = true
end)
assert(coroutine.resume(manualTimer))

local manualSignal = coroutine.create(function()
    event.Event:Wait()
    manualSignalResumed = true
end)
assert(coroutine.resume(manualSignal))

-- Let the task.spawn waiter register before cancelling it.  The two manually
-- created coroutines have already registered their native timer/signal waits.
task.wait()
task.cancel(scheduledSignal)
task.cancel(manualTimer)
task.cancel(manualSignal)

-- A stale signal waiter would be encountered here.  No cancelled coroutine is
-- allowed to resume, and no cancelled long timer may advance virtual time.
event:Fire("after-cancel")
task.wait(0.05)

local values = {
    tostring(delayedFired),
    tostring(scheduledSignalResumed),
    tostring(manualTimerResumed),
    tostring(manualSignalResumed),
    coroutine.status(manualTimer),
    coroutine.status(manualSignal),
}
print("BLACKBOX_CANCEL|" .. table.concat(values, "|"))
return delayedFired, scheduledSignalResumed, manualTimerResumed, manualSignalResumed
'''


MODULE_SOURCE = r'''
local modules = workspace.BlackboxModules
_G.blackbox_slow_loads = 0
_G.blackbox_multiple_loads = 0

local values = {}
local finished = 0
for index = 1, 8 do
    task.spawn(function()
        local ok, value = pcall(require, modules.Slow)
        values[index] = { ok = ok, value = value }
        finished += 1
    end)
end
while finished < 8 do
    task.wait()
end

local sameValue = true
local shared = values[1] and values[1].value
for index = 1, 8 do
    if not values[index] or not values[index].ok or values[index].value ~= shared then
        sameValue = false
    end
end
local cachedSame = require(modules.Slow) == shared

local falseOk, falseValue = pcall(require, modules.FalseValue)
local nilOk, nilValue = pcall(require, modules.NilValue)

local multipleOk1, multipleError1 = pcall(require, modules.Multiple)
local multipleOk2, multipleError2 = pcall(require, modules.Multiple)
local multipleCachedFailure = not multipleOk1 and not multipleOk2
    and string.find(tostring(multipleError1), "exactly one value", 1, true) ~= nil
    and string.find(tostring(multipleError2), "exactly one value", 1, true) ~= nil

local cycleOk, cycleError = pcall(require, modules.CycleA)
local cycleDetected = not cycleOk
    and string.find(tostring(cycleError), "required recursively", 1, true) ~= nil

local observations = {
    tostring(finished),
    tostring(_G.blackbox_slow_loads),
    tostring(sameValue),
    tostring(cachedSame),
    tostring(falseOk and falseValue == false),
    tostring(nilOk and nilValue == nil),
    tostring(multipleCachedFailure),
    tostring(_G.blackbox_multiple_loads),
    tostring(cycleDetected),
}
print("BLACKBOX_MODULE|" .. table.concat(observations, "|"))
return shared, falseValue, nilValue
'''


MODULE_SCENARIO: dict[str, Any] = {
    "version": 2,
    "instances": [
        {"id": "module-root", "class": "Folder", "name": "BlackboxModules", "parent": "workspace"},
        {"id": "slow", "class": "ModuleScript", "name": "Slow", "parent": "module-root"},
        {"id": "false", "class": "ModuleScript", "name": "FalseValue", "parent": "module-root"},
        {"id": "nil", "class": "ModuleScript", "name": "NilValue", "parent": "module-root"},
        {"id": "multiple", "class": "ModuleScript", "name": "Multiple", "parent": "module-root"},
        {"id": "cycle-a", "class": "ModuleScript", "name": "CycleA", "parent": "module-root"},
        {"id": "cycle-b", "class": "ModuleScript", "name": "CycleB", "parent": "module-root"},
    ],
    "module_sources": {
        "slow": (
            "_G.blackbox_slow_loads = (_G.blackbox_slow_loads or 0) + 1\n"
            "task.wait(0.05)\n"
            "return { token = 'one-shared-result' }"
        ),
        "false": "return false",
        "nil": "return nil",
        "multiple": (
            "_G.blackbox_multiple_loads = (_G.blackbox_multiple_loads or 0) + 1\n"
            "return 1, 2"
        ),
        "cycle-a": "return require(workspace.BlackboxModules.CycleB)",
        "cycle-b": "return require(workspace.BlackboxModules.CycleA)",
    },
}


MANUAL_BLOCK_SOURCE = r'''
print("BLACKBOX_MANUAL_BLOCK|before-yield")
return coroutine.yield("audit-manual-yield")
'''


SIGNAL_BLOCK_SOURCE = r'''
local event = Instance.new("BindableEvent")
print("BLACKBOX_SIGNAL_BLOCK|before-wait")
return event.Event:Wait()
'''


NETWORK_BLOCK_SOURCE = f'''
print("BLACKBOX_NETWORK_BLOCK|before-request")
return game:GetService("HttpService"):GetAsync("{NETWORK_URL}")
'''


@dataclass
class RunResult:
    name: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    report: dict[str, Any] | None


class Audit:
    def __init__(self, stale_binary: bool) -> None:
        self.failures: list[str] = []
        self.stale_binary = stale_binary

    def expect(self, group: str, condition: bool, message: str) -> None:
        if condition:
            return
        freshness = " [built binary is stale]" if self.stale_binary else ""
        self.failures.append(f"{group}: {message}{freshness}")

    def group_result(self, group: str, starting_failures: int) -> None:
        if len(self.failures) == starting_failures:
            print(f"PASS {group}")
        else:
            print(f"FAIL {group}")
            for failure in self.failures[starting_failures:]:
                print(f"  - {failure}")


def source_files_newer_than(runtime: pathlib.Path) -> list[pathlib.Path]:
    try:
        runtime_mtime = runtime.stat().st_mtime_ns
    except FileNotFoundError:
        return []
    candidates = [ROOT / "src" / "main.cpp", ROOT / "src" / "runtime_v2.cpp"]
    candidates.extend((ROOT / "src" / "runtime").glob("*.cpp"))
    candidates.extend((ROOT / "src" / "runtime").glob("*.hpp"))
    return sorted(path for path in candidates if path.is_file() and path.stat().st_mtime_ns > runtime_mtime)


def run_case(
    runtime: pathlib.Path,
    directory: pathlib.Path,
    name: str,
    source: str,
    *,
    scenario: dict[str, Any] | None = None,
    max_virtual_seconds: float = 2.0,
) -> RunResult:
    script_path = directory / f"{name}.luau"
    report_path = directory / f"{name}.report.json"
    output_path = directory / f"{name}.captures"
    script_path.write_text(source, encoding="utf-8")

    command = [
        str(runtime),
        "--profile", "roblox-client",
        "--execution-mode", "faithful",
        "--analysis-hooks", "off",
        "--network-policy", "offline",
        "--clock", "virtual",
        "--max-virtual-seconds", str(max_virtual_seconds),
        "--timeout", "8",
        "--memory-limit-mb", "128",
        "--no-native-codegen",
        "--report", str(report_path),
        "--out", str(output_path),
    ]
    if scenario is not None:
        scenario_path = directory / f"{name}.scenario.json"
        scenario_path.write_text(json.dumps(scenario, indent=2), encoding="utf-8")
        command.extend(("--scenario", str(scenario_path)))
    command.append(str(script_path))

    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        returncode = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as timeout:
        returncode = -1
        stdout = timeout.stdout.decode() if isinstance(timeout.stdout, bytes) else (timeout.stdout or "")
        stderr = timeout.stderr.decode() if isinstance(timeout.stderr, bytes) else (timeout.stderr or "")
        stderr += "\n[blackbox harness timeout]"

    report: dict[str, Any] | None = None
    if report_path.is_file():
        try:
            parsed = json.loads(report_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                report = parsed
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return RunResult(name, command, returncode, stdout, stderr, report)


def marker_payload(result: RunResult, marker: str) -> str | None:
    position = result.stdout.rfind(marker)
    if position < 0:
        return None
    value = result.stdout[position + len(marker):]
    return value.splitlines()[0].strip()


def mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def check_report_envelope(audit: Audit, group: str, result: RunResult) -> dict[str, Any]:
    report = result.report
    audit.expect(group, report is not None, f"CLI did not emit parseable report v3; stderr={result.stderr[-800:]!r}")
    if report is None:
        return {}
    release = mapping(report.get("release"))
    luau = mapping(release.get("luau"))
    api = mapping(release.get("api"))
    audit.expect(group, report.get("version") == 3, f"report version is {report.get('version')!r}, expected 3")
    audit.expect(group, report.get("schema") == "rbx-luau-runtime.report.v3", f"wrong schema {report.get('schema')!r}")
    audit.expect(group, report.get("engine_release") == "729", f"wrong engine release {report.get('engine_release')!r}")
    audit.expect(group, report.get("api_hash") == EXPECTED_API_SHA256, "top-level API hash does not match the pinned full dump")
    audit.expect(group, luau.get("commit") == EXPECTED_LUAU_COMMIT, "release manifest has the wrong Luau commit")
    audit.expect(group, api.get("sha256") == EXPECTED_API_SHA256, "release manifest has the wrong API dump hash")
    audit.expect(group, isinstance(report.get("dependency_requirements"), list), "dependency_requirements is not an array")
    audit.expect(group, isinstance(report.get("engine_effects"), dict), "engine_effects is not a typed object")
    native = mapping(report.get("native_runtime"))
    native_scheduler = mapping(native.get("scheduler"))
    tasks = sequence(native_scheduler.get("tasks"))
    for task in tasks:
        task_map = mapping(task)
        audit.expect(group, isinstance(task_map.get("state"), str), f"task is missing state: {task!r}")
        audit.expect(group, isinstance(task_map.get("queue"), str), f"task is missing queue: {task!r}")
        audit.expect(group, isinstance(task_map.get("security_identity"), str), f"task is missing security identity: {task!r}")
        audit.expect(group, isinstance(task_map.get("actor_lane"), str), f"task is missing actor lane: {task!r}")
    return report


def audit_phases(audit: Audit, runtime: pathlib.Path, directory: pathlib.Path) -> None:
    group = "RunService phase ordering and BindToRenderStep"
    start = len(audit.failures)
    result = run_case(runtime, directory, "blackbox_phases", PHASE_SOURCE)
    report = check_report_envelope(audit, group, result)
    audit.expect(group, result.returncode == 0, f"script failed with {result.returncode}: {result.stderr[-800:]!r}")
    audit.expect(group, report.get("execution_state") == "completed", f"execution state is {report.get('execution_state')!r}")

    observed = marker_payload(result, "BLACKBOX_PHASE|")
    expected = ",".join((
        "PreRender",
        "bind:replacement",
        "bind:early",
        "bind:late",
        "RenderStepped",
        "PreAnimation",
        "PreSimulation",
        "Stepped",
        "PostSimulation",
        "Heartbeat",
    ))
    audit.expect(group, observed is not None, f"phase observation marker is missing; stdout={result.stdout[-800:]!r}")
    audit.expect(group, observed == expected, f"first-frame order was {observed!r}, expected {expected!r}")
    if observed is not None:
        audit.expect(group, "bind:old" not in observed, "replaced BindToRenderStep callback still executed")

    events = sequence(mapping(report.get("scheduler")).get("events"))
    phase_details = {
        mapping(event).get("detail")
        for event in events
        if mapping(event).get("kind") == "phase_queue"
    }
    expected_phases = {
        "PreRender", "RenderStepped", "PreAnimation", "PreSimulation", "Stepped", "PostSimulation", "Heartbeat"
    }
    audit.expect(
        group,
        expected_phases.issubset(phase_details),
        f"native scheduler did not expose all RunService phase queues; observed {sorted(str(value) for value in phase_details)}",
    )
    audit.group_result(group, start)


def audit_cancellation(audit: Audit, runtime: pathlib.Path, directory: pathlib.Path) -> None:
    group = "timer/signal cancellation cleanup"
    start = len(audit.failures)
    result = run_case(runtime, directory, "blackbox_cancellation", CANCELLATION_SOURCE)
    report = check_report_envelope(audit, group, result)
    audit.expect(group, result.returncode == 0, f"script failed with {result.returncode}: {result.stderr[-800:]!r}")
    audit.expect(group, report.get("execution_state") == "completed", f"execution state is {report.get('execution_state')!r}")

    payload = marker_payload(result, "BLACKBOX_CANCEL|")
    fields = payload.split("|") if payload is not None else []
    audit.expect(group, payload is not None, f"cancellation marker is missing; stdout={result.stdout[-800:]!r}")
    audit.expect(
        group,
        len(fields) >= 4 and fields[:4] == ["false", "false", "false", "false"],
        f"a cancelled timer or signal waiter resumed: {payload!r}",
    )

    scheduler = mapping(report.get("scheduler"))
    pending = mapping(scheduler.get("pending"))
    audit.expect(group, pending.get("timers") == 0, f"cancelled timer remained queued: {pending!r}")
    audit.expect(group, pending.get("waiting") == 0, f"cancelled waiter remained in scheduler waiting state: {pending!r}")
    audit.expect(group, pending.get("suspended") == 0, f"cancelled coroutine remained suspended: {pending!r}")
    audit.expect(group, float(scheduler.get("virtual_time", 99)) < 1.0, "cancelled 30-second timer advanced virtual time")

    native_scheduler = mapping(mapping(report.get("native_runtime")).get("scheduler"))
    audit.expect(group, int(native_scheduler.get("cancelled", 0)) >= 4, f"expected four cancelled tasks: {native_scheduler!r}")
    audit.expect(group, int(native_scheduler.get("waiting", 0)) == 0, f"native waiters remain after cancellation: {native_scheduler!r}")
    tasks = sequence(native_scheduler.get("tasks"))
    cancelled_tasks = [mapping(task) for task in tasks if mapping(task).get("state") == "cancelled"]
    audit.expect(group, len(cancelled_tasks) >= 4, f"native task snapshots lost cancellations: {cancelled_tasks!r}")
    audit.expect(group, all(not task.get("wait_key") for task in cancelled_tasks), "a cancelled task retained its timer/signal wait key")

    events = [mapping(event) for event in sequence(scheduler.get("events"))]
    cancel_sequence: dict[Any, int] = {}
    for event in events:
        if event.get("kind") == "cancel":
            cancel_sequence[event.get("task")] = int(event.get("sequence", 0))
    audit.expect(group, len(cancel_sequence) >= 4, f"scheduler event log has fewer than four cancellations: {cancel_sequence!r}")
    post_cancel_resumes = [
        event
        for event in events
        if event.get("kind") == "resume"
        and event.get("task") in cancel_sequence
        and int(event.get("sequence", 0)) > cancel_sequence[event.get("task")]
    ]
    audit.expect(group, not post_cancel_resumes, f"cancelled task resumed later: {post_cancel_resumes!r}")
    audit.group_result(group, start)


def module_named(modules: Iterable[Any], suffix: str) -> dict[str, Any] | None:
    for raw in modules:
        module = mapping(raw)
        name = str(module.get("name", ""))
        if name == suffix or name.endswith("." + suffix) or name.endswith("/" + suffix):
            return module
    return None


def audit_modules(audit: Audit, runtime: pathlib.Path, directory: pathlib.Path) -> None:
    group = "ModuleScript exactly-once execution and native states"
    start = len(audit.failures)
    result = run_case(runtime, directory, "blackbox_modules", MODULE_SOURCE, scenario=MODULE_SCENARIO)
    report = check_report_envelope(audit, group, result)
    audit.expect(group, result.returncode == 0, f"script failed with {result.returncode}: {result.stderr[-1000:]!r}")
    audit.expect(group, report.get("execution_state") == "completed", f"execution state is {report.get('execution_state')!r}")

    payload = marker_payload(result, "BLACKBOX_MODULE|")
    expected = "8|1|true|true|true|true|true|1|true"
    audit.expect(group, payload is not None, f"module marker is missing; stdout={result.stdout[-1000:]!r}")
    audit.expect(group, payload == expected, f"module observations were {payload!r}, expected {expected!r}")

    native = mapping(report.get("native_runtime"))
    modules = sequence(native.get("modules"))
    audit.expect(
        group,
        len(modules) >= 6,
        f"Lua require completed, but native_runtime.modules has {len(modules)} entries; scenario ModuleScripts are not owned/reported by ModuleRegistry",
    )
    if modules:
        terminal = {"loaded", "failed", "unloaded"}
        audit.expect(group, all(mapping(module).get("state") in terminal for module in modules), f"module remained loading: {modules!r}")
        audit.expect(group, all(int(mapping(module).get("waiters", 0)) == 0 for module in modules), f"module waiter leaked: {modules!r}")
        audit.expect(group, all(bool(mapping(module).get("has_source")) for module in modules), f"host sidecar source was not registered: {modules!r}")

        slow = module_named(modules, "Slow")
        multiple = module_named(modules, "Multiple")
        audit.expect(group, slow is not None, f"Slow snapshot is missing: {modules!r}")
        if slow is not None:
            audit.expect(group, slow.get("state") == "loaded", f"Slow state is not loaded: {slow!r}")
            audit.expect(group, bool(slow.get("has_value")), f"Slow cached value is absent: {slow!r}")
            audit.expect(group, int(slow.get("loader_task", -1)) == 0, f"Slow retained its loader task: {slow!r}")
        audit.expect(group, multiple is not None, f"Multiple snapshot is missing: {modules!r}")
        if multiple is not None:
            audit.expect(group, multiple.get("state") == "failed", f"Multiple state is not failed: {multiple!r}")
            audit.expect(group, "exactly one value" in str(multiple.get("error", "")), f"Multiple cached the wrong error: {multiple!r}")

    tasks = sequence(mapping(native.get("scheduler")).get("tasks"))
    audit.expect(group, all(mapping(task).get("state") != "waiting-module" for task in tasks), "terminal run retained a waiting-module task")
    audit.group_result(group, start)


def validate_dependencies(audit: Audit, group: str, report: dict[str, Any]) -> list[dict[str, Any]]:
    raw = report.get("dependency_requirements")
    dependencies = [mapping(value) for value in sequence(raw)]
    for dependency in dependencies:
        audit.expect(group, isinstance(dependency.get("kind"), str), f"dependency kind is not typed: {dependency!r}")
        audit.expect(group, isinstance(dependency.get("name"), str), f"dependency name is not typed: {dependency!r}")
        audit.expect(group, dependency.get("required") is True, f"dependency required flag is not true: {dependency!r}")
    return dependencies


def audit_blocked_reports(audit: Audit, runtime: pathlib.Path, directory: pathlib.Path) -> None:
    group = "report v3 blocked states and dependency requirements"
    start = len(audit.failures)

    manual = run_case(runtime, directory, "blackbox_manual_block", MANUAL_BLOCK_SOURCE)
    manual_report = check_report_envelope(audit, group, manual)
    audit.expect(group, manual.returncode == 0, f"manual block returned {manual.returncode}: {manual.stderr[-800:]!r}")
    audit.expect(group, manual_report.get("execution_state") == "blocked", f"manual yield state is {manual_report.get('execution_state')!r}")
    audit.expect(group, manual_report.get("status") == "blocked", f"manual yield legacy status is {manual_report.get('status')!r}")
    audit.expect(group, manual_report.get("termination_reason") == "blocked", f"manual yield termination is {manual_report.get('termination_reason')!r}")
    manual_reason = mapping(manual_report.get("blocked_reason"))
    audit.expect(group, manual_reason.get("kind") == "caller_controlled_yield", f"manual blocked reason is inconsistent: {manual_reason!r}")
    audit.expect(group, manual_reason.get("state") == "suspended", f"manual task state is not suspended: {manual_reason!r}")
    audit.expect(group, manual_reason.get("wait_key") == "caller-controlled-yield", f"manual wait key is wrong: {manual_reason!r}")
    validate_dependencies(audit, group, manual_report)

    native_tasks = sequence(mapping(mapping(manual_report.get("native_runtime")).get("scheduler")).get("tasks"))
    blocked_task = next((mapping(task) for task in native_tasks if mapping(task).get("id") == manual_reason.get("task")), None)
    audit.expect(group, blocked_task is not None, f"blocked task {manual_reason.get('task')!r} is absent from native task states")
    if blocked_task is not None:
        audit.expect(group, blocked_task.get("state") == "suspended", f"blocked task snapshot disagrees: {blocked_task!r}")
        audit.expect(group, blocked_task.get("security_identity") == "local-script", f"blocked task lost LocalScript identity: {blocked_task!r}")

    signal = run_case(runtime, directory, "blackbox_signal_block", SIGNAL_BLOCK_SOURCE)
    signal_report = check_report_envelope(audit, group, signal)
    audit.expect(group, signal.returncode == 0, f"signal block returned {signal.returncode}: {signal.stderr[-800:]!r}")
    # An event wait is a healthy long-lived scheduler state, unlike arbitrary
    # coroutine.yield.  Report v3 should therefore expose steady_state while
    # retaining the precise native waiting-signal task state.
    audit.expect(group, signal_report.get("execution_state") == "steady_state", f"signal wait state is {signal_report.get('execution_state')!r}")
    audit.expect(
        group,
        isinstance(signal_report.get("steady_state_reason"), str) and bool(signal_report.get("steady_state_reason")),
        f"healthy signal steady state has no precise reason: {signal_report.get('steady_state_reason')!r}",
    )
    audit.expect(group, signal_report.get("blocked_reason") is None, f"healthy signal wait was also labeled blocked: {signal_report.get('blocked_reason')!r}")
    signal_native = mapping(mapping(signal_report.get("native_runtime")).get("scheduler"))
    signal_tasks = [mapping(task) for task in sequence(signal_native.get("tasks"))]
    signal_waiters = [task for task in signal_tasks if task.get("state") == "waiting-signal"]
    audit.expect(group, len(signal_waiters) == 1, f"signal waiter is absent from native task states: {signal_tasks!r}")
    if signal_waiters:
        audit.expect(group, signal_waiters[0].get("wait_key") == "BindableEvent.Event", f"signal wait key is imprecise: {signal_waiters[0]!r}")
        audit.expect(group, signal_waiters[0].get("security_identity") == "local-script", f"signal waiter lost LocalScript identity: {signal_waiters[0]!r}")
    validate_dependencies(audit, group, signal_report)

    network = run_case(runtime, directory, "blackbox_network_block", NETWORK_BLOCK_SOURCE)
    network_report = check_report_envelope(audit, group, network)
    audit.expect(group, network_report.get("execution_state") == "blocked", f"offline HTTP state is {network_report.get('execution_state')!r}")
    audit.expect(group, network_report.get("termination_reason") == "network_required", f"offline HTTP termination is {network_report.get('termination_reason')!r}")
    requirements = [mapping(value) for value in sequence(network_report.get("network_requirements"))]
    matching_requirements = [
        requirement
        for requirement in requirements
        if requirement.get("host") == NETWORK_HOST and requirement.get("url") == NETWORK_URL
    ]
    audit.expect(group, bool(matching_requirements), f"exact host/URL network requirement is missing: {requirements!r}")
    if matching_requirements:
        audit.expect(
            group,
            matching_requirements[0].get("policy") == "offline",
            f"offline requirement was mislabeled as {matching_requirements[0].get('policy')!r}: {matching_requirements[0]!r}",
        )
    dependencies = validate_dependencies(audit, group, network_report)
    matching_dependencies = [
        dependency
        for dependency in dependencies
        if dependency.get("kind") == "network_host"
        and dependency.get("name") == NETWORK_HOST
        and dependency.get("url") == NETWORK_URL
    ]
    audit.expect(group, bool(matching_dependencies), f"typed network dependency is missing: {dependencies!r}")
    network_reason = mapping(network_report.get("blocked_reason"))
    audit.expect(group, bool(network_reason), "execution_state=blocked but blocked_reason is null for an offline network stop")
    if network_reason:
        audit.expect(group, network_reason.get("kind") == "network_host", f"network blocked reason has wrong kind: {network_reason!r}")
        audit.expect(group, network_reason.get("name") == NETWORK_HOST, f"network blocked reason lost exact host: {network_reason!r}")
        audit.expect(group, network_reason.get("url") == NETWORK_URL, f"network blocked reason lost exact URL: {network_reason!r}")

    audit.group_result(group, start)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime",
        type=pathlib.Path,
        default=ROOT / "build-release729" / "rbx_luau_runtime",
        help="release-729 runner binary to audit",
    )
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    if not runtime.is_file():
        print(f"runtime binary does not exist: {runtime}", file=sys.stderr)
        return 2

    newer = source_files_newer_than(runtime)
    stale = bool(newer)
    if stale:
        print("STALE binary: these runtime sources are newer than the executable:")
        for path in newer:
            print(f"  - {path.relative_to(ROOT)}")
    else:
        print("FRESH binary: executable is newer than the audited runtime sources")

    audit = Audit(stale)
    with tempfile.TemporaryDirectory(prefix="release-729-blackbox-") as temporary:
        directory = pathlib.Path(temporary)
        audit_phases(audit, runtime, directory)
        audit_cancellation(audit, runtime, directory)
        audit_modules(audit, runtime, directory)
        audit_blocked_reports(audit, runtime, directory)

    if audit.failures:
        print(f"\nBLACKBOX AUDIT FAILED: {len(audit.failures)} contract gap(s)")
        for index, failure in enumerate(audit.failures, 1):
            print(f"{index}. {failure}")
        if stale:
            print("Rebuild build-release729 and rerun before treating source-sensitive failures as current.")
        return 1

    print("\nBLACKBOX AUDIT PASSED: phases, cancellation, modules, and report-v3 blocked/dependency contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
