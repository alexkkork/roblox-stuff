#!/usr/bin/env python3
import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def run(runtime: Path, source: Path, directory: Path, trace: bool) -> tuple[dict, list[dict]]:
    report_path = directory / "report.json"
    trace_path = directory / "environment.jsonl"
    command = [
        str(runtime),
        "--profile", "executor-client",
        "--execution-mode", "faithful",
        "--network-policy", "offline",
        "--clock", "virtual",
        "--timeout", "5",
        "--deterministic-seed", "729",
        "--no-native-codegen",
        "--analysis-hooks", "off",
        "--report", str(report_path),
    ]
    if trace:
        command.extend(
            [
                "--trace-environment", str(trace_path),
                "--trace-environment-after-clock-calls", "0",
                "--trace-environment-max-events", "10000",
            ]
        )
    command.append(str(source))
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if completed.returncode != 0:
        raise AssertionError(f"runtime exited {completed.returncode}: {completed.stderr}")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    events = []
    if trace:
        events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines() if line]
    return report, events


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).with_name("native_environment_trace.luau")

    with tempfile.TemporaryDirectory(prefix="rbx-native-environment-trace-") as temporary:
        root = Path(temporary)
        baseline_dir = root / "baseline"
        traced_dir = root / "traced"
        baseline_dir.mkdir()
        traced_dir.mkdir()
        baseline, _ = run(args.runtime.resolve(), source, baseline_dir, False)
        traced, events = run(args.runtime.resolve(), source, traced_dir, True)

    for field in ("status", "termination_reason", "returns", "typed_returns", "stdout", "stderr"):
        if baseline.get(field) != traced.get(field):
            raise AssertionError(f"trace changed {field}: {baseline.get(field)!r} != {traced.get(field)!r}")
    if traced.get("status") != "completed" or "native-environment-trace-ok" not in (traced.get("stdout") or []):
        raise AssertionError(f"trace fixture did not complete: {traced.get('status')} {traced.get('stdout')}")

    metadata = next((event for event in events if event.get("kind") == "trace_metadata"), None)
    accesses = [event for event in events if event.get("kind") == "environment_access"]
    if not metadata or not metadata.get("active") or metadata.get("activation_clock_calls") != 0:
        raise AssertionError(f"invalid trace metadata: {metadata}")
    if metadata.get("dropped") != 0:
        raise AssertionError(f"trace dropped events: {metadata}")
    if metadata.get("accesses") != sum(int(event.get("count", 1)) for event in accesses):
        raise AssertionError("trace metadata access count does not match aggregated events")

    scopes = {event.get("scope") for event in accesses}
    if not {"script_environment", "closure_environment", "shared_global"}.issubset(scopes):
        raise AssertionError(f"missing environment scopes: {scopes}")
    operations = {event.get("operation") for event in accesses}
    if not {"get_global", "get_import", "get_table", "set_global", "raw_get"}.issubset(operations):
        raise AssertionError(f"missing environment operations: {operations}")
    keys = {event.get("key") for event in accesses}
    required_keys = {"native_trace_missing", "native_trace_shared", "native_trace_written", "string", "table", "math"}
    if not required_keys.issubset(keys):
        raise AssertionError(f"missing traced keys: {required_keys - keys}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
