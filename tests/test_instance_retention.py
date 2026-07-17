#!/usr/bin/env python3
"""Black-box Instance create/destroy retention and stale-userdata regression."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "tests" / "instance_retention_v3.luau"


def run_once(runtime: pathlib.Path, iterations: int, timeout: float, memory_limit_mb: int) -> tuple[dict, str]:
    with tempfile.TemporaryDirectory(prefix="rbx-instance-retention-") as temporary:
        directory = pathlib.Path(temporary)
        script = directory / f"instance_retention_{iterations}.luau"
        script.write_text(
            f"RETENTION_ITERATIONS = {iterations}\n" + TEMPLATE.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        report_path = directory / "report.json"
        completed = subprocess.run(
            [
                str(runtime),
                "--profile", "roblox-client",
                "--execution-mode", "faithful",
                "--analysis-hooks", "off",
                "--network-policy", "offline",
                "--clock", "virtual",
                "--no-native-codegen",
                "--memory-limit-mb", str(memory_limit_mb),
                "--timeout", str(timeout),
                "--report", str(report_path),
                "--out", str(directory / "captures"),
                str(script),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 15,
        )
        if completed.returncode:
            raise RuntimeError(
                f"retention run {iterations} failed ({completed.returncode}):\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )
        marker = f"instance-retention-v3-ok:{iterations}"
        if marker not in completed.stdout:
            raise RuntimeError(f"retention marker {marker!r} missing:\n{completed.stdout}\n{completed.stderr}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return report, completed.stdout


def validate_engine(engine: dict) -> None:
    live = engine.get("live_instances")
    retained = engine.get("retained_destroyed_instances")
    registry_nodes = engine.get("instance_registry_nodes")
    if engine.get("instances") != live or registry_nodes != live + retained:
        raise RuntimeError(f"live and weakly retained Instance counts are inconsistent: {engine}")
    if engine.get("instance_object_refs") != live or engine.get("instance_state_refs") != registry_nodes:
        raise RuntimeError(f"Instance registry reference counts are inconsistent: {engine}")
    if engine.get("released_object_refs") != engine.get("destroyed_instances"):
        raise RuntimeError(f"not every destroyed Instance released its object ref: {engine}")
    if engine.get("released_state_refs") != engine.get("destroyed_instances"):
        raise RuntimeError(f"not every destroyed Instance released its original state ref: {engine}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    parser.add_argument("--iterations", type=int, default=2500)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--memory-limit-mb", type=int, default=256)
    parser.add_argument("--max-current-delta-mb", type=float, default=32)
    args = parser.parse_args()
    if args.iterations < 0:
        parser.error("--iterations must be non-negative")

    baseline, _ = run_once(args.runtime, 0, args.timeout, args.memory_limit_mb)
    workload, _ = run_once(args.runtime, args.iterations, args.timeout, args.memory_limit_mb)
    if baseline.get("execution_state") != "completed" or workload.get("execution_state") != "completed":
        raise RuntimeError("retention workload did not complete")

    baseline_engine = baseline["engine"]
    workload_engine = workload["engine"]
    validate_engine(baseline_engine)
    validate_engine(workload_engine)
    if workload_engine["live_instances"] != baseline_engine["live_instances"]:
        raise RuntimeError(
            f"live Instance count grew from {baseline_engine['live_instances']} to {workload_engine['live_instances']}"
        )
    if workload_engine["instance_registry_nodes"] != baseline_engine["instance_registry_nodes"]:
        raise RuntimeError(
            "destroyed Instance tombstones grew from "
            f"{baseline_engine['instance_registry_nodes']} to {workload_engine['instance_registry_nodes']}"
        )
    destroyed_delta = workload_engine["destroyed_instances"] - baseline_engine["destroyed_instances"]
    if destroyed_delta != args.iterations:
        raise RuntimeError(f"destroyed count delta {destroyed_delta} != requested {args.iterations}")

    baseline_current = baseline["limits"]["memory_current_bytes"]
    workload_current = workload["limits"]["memory_current_bytes"]
    current_delta = workload_current - baseline_current
    maximum_delta = int(args.max_current_delta_mb * 1024 * 1024)
    if current_delta > maximum_delta:
        raise RuntimeError(
            f"post-GC VM memory grew by {current_delta} bytes; allowed {maximum_delta} bytes"
        )
    if workload["limits"].get("memory_limit_hit"):
        raise RuntimeError("retention workload hit the VM memory limit")

    print(
        "Instance retention OK: "
        f"iterations={args.iterations}, live={workload_engine['live_instances']}, "
        f"destroyed={workload_engine['destroyed_instances']}, "
        f"registry_nodes={workload_engine['instance_registry_nodes']}, "
        f"current_delta_bytes={current_delta}, "
        f"peak_bytes={workload['limits']['memory_peak_bytes']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
