#!/usr/bin/env python3
import argparse
import json
import math
import os
import pathlib
import random
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def runtime_timeout(seconds):
    raw_scale = os.environ.get("RBX_RUNTIME_TEST_TIMEOUT_SCALE", "1")
    try:
        scale = float(raw_scale)
    except ValueError as error:
        raise RuntimeError(f"RBX_RUNTIME_TEST_TIMEOUT_SCALE must be numeric, got {raw_scale!r}") from error
    if not math.isfinite(scale) or scale < 1:
        raise RuntimeError("RBX_RUNTIME_TEST_TIMEOUT_SCALE must be finite and at least 1")
    return f"{seconds * scale:g}"


def run(command):
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(map(str, command))}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
    return result


def run_raw(command):
    return subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def generated_lifecycle_program(operations, seed=0x728):
    rng = random.Random(seed)
    lines = [
        'local root = Instance.new("Folder", workspace)',
        'root.Name = "GeneratedLifecycle"',
        'local checksum = 0',
    ]
    for index in range(operations):
        value = rng.randint(-100000, 100000)
        lines.extend([
            "do",
            '  local part = Instance.new("Part", root)',
            f'  part.Name = "P{index}"',
            f'  part:SetAttribute("Value", {value})',
            '  part:AddTag("Generated")',
            '  assert(part:IsA("BasePart") and part.Parent == root)',
            '  assert(part:HasTag("Generated"))',
            f'  checksum += part:GetAttribute("Value") + {index}',
        ])
        if index % 25 == 0:
            lines.extend([
                "  local clone = part:Clone()",
                "  clone.Parent = root",
                "  assert(clone ~= part and clone:GetAttribute(\"Value\") == part:GetAttribute(\"Value\"))",
                "  clone:Destroy()",
            ])
        lines.extend(["  part:Destroy()", "end"])
    lines.extend([
        "task.wait()",
        "assert(#root:GetChildren() == 0)",
        'print("generated-lifecycle-ok", checksum)',
        "return checksum",
    ])
    return "\n".join(lines) + "\n"


def oracle_payload(stdout):
    marker = "RBX_ORACLE_JSON:"
    for line in stdout.splitlines():
        if marker in line:
            return json.loads(line.split(marker, 1)[1])
    raise RuntimeError("emulator oracle output did not contain the JSON marker")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    parser.add_argument("--operations", type=int, default=1000)
    parser.add_argument("--seeds", type=int, default=10)
    args = parser.parse_args()
    if args.operations < 0 or args.seeds <= 0:
        parser.error("--operations must be non-negative and --seeds must be positive")
    scenario = ROOT / "tests" / "fixtures" / "runtime_v2_scenario.json"
    contract = ROOT / "tests" / "roblox_fidelity_v2.luau"
    datatypes = ROOT / "tests" / "datatypes_v2.luau"

    with tempfile.TemporaryDirectory(prefix="rbx-fidelity-v2-") as temporary:
        temp = pathlib.Path(temporary)
        report = temp / "contract-report.json"
        result = run([
            str(args.runtime), "--profile", "roblox-client", "--execution-mode", "faithful", "--analysis-hooks", "off",
            "--network-policy", "offline", "--clock", "virtual", "--scenario", str(scenario),
            "--report", str(report), "--out", str(temp / "contract-captures"), str(contract),
        ])
        if "runtime-v2-contract-ok" not in result.stdout:
            raise RuntimeError(f"contract marker missing: {result.stdout!r}")
        payload = json.loads(report.read_text())
        if payload.get("version") != 3 or payload.get("engine_release") != "729" or payload.get("status") != "completed":
            raise RuntimeError(f"invalid fidelity report: {payload}")
        if payload.get("unsupported"):
            raise RuntimeError(f"unexpected unsupported APIs in contract: {payload['unsupported']}")
        scheduler = payload.get("scheduler") or {}
        if scheduler.get("timed_out") or scheduler.get("frames", 0) < 1:
            raise RuntimeError(f"scheduler did not advance correctly: {scheduler}")

        datatype_result = run([
            str(args.runtime), "--profile", "roblox-client", "--execution-mode", "faithful", "--analysis-hooks", "off",
            "--network-policy", "offline", "--clock", "virtual", "--out", str(temp / "datatype-captures"),
            str(datatypes),
        ])
        if "runtime-v2-datatypes-ok" not in datatype_result.stdout:
            raise RuntimeError(f"datatype marker missing: {datatype_result.stdout!r}")

        oracle = run([
            str(args.runtime), "--profile", "roblox-client", "--execution-mode", "faithful", "--analysis-hooks", "off",
            "--network-policy", "offline", "--clock", "virtual", "--out", str(temp / "oracle-captures"),
            str(ROOT / "tests" / "roblox_oracle" / "probes" / "core.luau"),
        ])
        actual_oracle = oracle_payload(oracle.stdout)
        fixture_path = ROOT / "tests" / "roblox_oracle" / "fixtures" / "release-729" / "core.json"
        if fixture_path.exists():
            expected_oracle = json.loads(fixture_path.read_text())
            expected_oracle.pop("oracle_release", None)
            if actual_oracle != expected_oracle:
                raise RuntimeError(f"Roblox Studio oracle mismatch:\nexpected={expected_oracle}\nactual={actual_oracle}")

        executor_source = temp / "executor.luau"
        executor_source.write_text(
            'local environment = getfenv(0)\n'
            'assert(environment ~= _G and getmetatable(_G) == nil)\n'
            'assert(type(getgenv)=="function" and getgenv() == environment)\n'
            'assert(type(getrenv)=="function" and getrenv() ~= environment)\n'
            'assert(type(getsenv)=="function" and getsenv(script) == environment)\n'
            'assert(type(request)=="function" and type(__rbx_execute)=="nil")\n'
            'environmentLoadMarker = 91\n'
            '_G.sharedLoadMarker = 92\n'
            'local loaded = assert(loadstring("return environmentLoadMarker == 91 and _G.sharedLoadMarker == 92 and getfenv(0) ~= _G"))\n'
            'assert(loaded() == true)\n'
            'local _ = ENVIRONMENT_CONTRACT_MISSING\n'
            'print("executor-profile-ok")\n'
        )
        executor_trace = temp / "executor-trace.jsonl"
        executor = run([
            str(args.runtime), "--profile", "executor-client", "--execution-mode", "diagnostic", "--analysis-hooks", "on",
            "--network-policy", "offline", "--clock", "virtual", "--trace-compat", str(executor_trace),
            "--out", str(temp / "executor-captures"), str(executor_source),
        ])
        if "executor-profile-ok" not in executor.stdout:
            raise RuntimeError("executor profile contract failed")
        trace_events = [json.loads(line) for line in executor_trace.read_text().splitlines() if line]
        if not any(event.get("kind") == "missing_global" and event.get("name") == "ENVIRONMENT_CONTRACT_MISSING" for event in trace_events):
            raise RuntimeError("missing-global tracing no longer observes the script environment")

        yielding_source = temp / "yielding-forever.luau"
        yielding_source.write_text("while true do task.wait() end\n")
        yielding_report = temp / "yielding-report.json"
        run([
            str(args.runtime), "--profile", "executor-client", "--execution-mode", "faithful", "--analysis-hooks", "off",
            "--network-policy", "offline", "--clock", "virtual", "--max-virtual-seconds", "0.05",
            "--timeout", runtime_timeout(3), "--report", str(yielding_report), "--out", str(temp / "yielding-captures"), str(yielding_source),
        ])
        yielding_payload = json.loads(yielding_report.read_text())
        if yielding_payload.get("status") != "virtual_budget" or yielding_payload.get("termination_reason") != "virtual_budget":
            raise RuntimeError(f"yielding script did not stop at a successful virtual budget: {yielding_payload}")

        busy_source = temp / "busy-forever.luau"
        busy_source.write_text("while true do end\n")
        busy_report = temp / "busy-report.json"
        busy = run_raw([
            str(args.runtime), "--profile", "executor-client", "--execution-mode", "faithful", "--analysis-hooks", "off",
            "--network-policy", "offline", "--clock", "virtual", "--timeout", runtime_timeout(1),
            "--report", str(busy_report), "--out", str(temp / "busy-captures"), str(busy_source),
        ])
        busy_payload = json.loads(busy_report.read_text())
        if busy.returncode == 0 or busy_payload.get("termination_reason") != "wall_timeout":
            raise RuntimeError(f"CPU-bound loop was not stopped by the wall watchdog: {busy_payload}")

        for seed_index in range(args.seeds):
            seed = 0x729000 + seed_index
            generated = temp / f"generated-lifecycle-{seed_index}.luau"
            generated.write_text(generated_lifecycle_program(args.operations, seed))
            lifecycle = run([
                str(args.runtime), "--profile", "roblox-client", "--execution-mode", "faithful", "--analysis-hooks", "off",
                "--network-policy", "offline", "--clock", "virtual", "--max-virtual-seconds", "10",
                "--out", str(temp / f"lifecycle-captures-{seed_index}"), str(generated),
            ])
            if "generated-lifecycle-ok" not in lifecycle.stdout:
                raise RuntimeError(f"generated lifecycle marker missing for seed {seed}")

    print(
        "Roblox fidelity release 729/report v3 OK: environments + scheduler + contract + datatypes + "
        f"{args.seeds} seeds x {args.operations} generated lifecycle operations"
    )


if __name__ == "__main__":
    main()
