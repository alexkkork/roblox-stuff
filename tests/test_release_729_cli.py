#!/usr/bin/env python3
"""Release-729 CLI limits, modes, determinism, and CodeGen parity."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(
    runtime: pathlib.Path,
    script: pathlib.Path,
    *extra: str,
    timeout: float = 20,
    scenario: pathlib.Path | None = None,
):
    with tempfile.TemporaryDirectory(prefix="release-729-cli-") as temporary:
        temp = pathlib.Path(temporary)
        report_path = temp / "report.json"
        trace_path = temp / "trace.jsonl"
        command = [
            str(runtime),
            "--profile", "executor-client",
            "--network-policy", "offline",
            "--clock", "virtual",
            "--max-virtual-seconds", "3",
            "--timeout", str(timeout),
            "--report", str(report_path),
            "--trace-compat", str(trace_path),
            "--out", str(temp / "captures"),
        ]
        if scenario is not None:
            command.extend(("--scenario", str(scenario)))
        command.extend((*extra, str(script)))
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 10,
        )
        if not report_path.is_file():
            raise RuntimeError(f"runtime report is missing:\n{completed.stdout}\n{completed.stderr}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        trace = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines() if line] if trace_path.exists() else []
        return completed, report, trace


def require_release(report: dict) -> None:
    if report.get("version") != 3 or report.get("schema") != "rbx-luau-runtime.report.v3":
        raise RuntimeError(f"wrong report schema: {report.get('version')} / {report.get('schema')}")
    release = report.get("release") or {}
    if report.get("engine_release") != "729" or release.get("studio_version") != "0.729.0.7290838":
        raise RuntimeError("wrong engine or Studio release pin")
    if (release.get("luau") or {}).get("commit") != "6e9b580e2e24643214caf0f4bbbb3db911ca30f3":
        raise RuntimeError("wrong Luau release commit in report v3")
    if (release.get("api") or {}).get("sha256") != "88de6ce88153b2c7d226d7c2d22752e6e04d266c28b36809d9d61bf8256cf6bd":
        raise RuntimeError("wrong full API dump hash in report v3")
    if (release.get("oracle") or {}).get("probe_sha256") != "dbd2d32751a3666858edff70b6831e6a939aac1121dc645740a933c56a0c6aa6":
        raise RuntimeError("wrong Studio oracle probe hash in report v3")
    subject = release.get("subject") or {}
    if subject.get("sha256") != "ea93959c47e6ada393fdf3d5ad884b6fd713aa5d76ac7259e84bd18464153e15" or subject.get("bytes") != 368779:
        raise RuntimeError("wrong supplied-subject identity in report v3")
    if not isinstance(report.get("dependency_requirements"), list) or not isinstance(report.get("engine_effects"), dict):
        raise RuntimeError("report v3 is missing dependency requirements or typed engine effects")
    effects = report["engine_effects"]
    if not all(isinstance(effects.get(field), int) for field in ("instances_created", "instances_destroyed", "scheduler_resumes")):
        raise RuntimeError(f"report v3 engine effects are not typed counters: {effects}")


def mode_contract(runtime: pathlib.Path) -> None:
    script = ROOT / "tests" / "cli_execution_mode_v3.luau"
    # Faithful mode must reject this environment-altering diagnostic even when
    # an upstream caller explicitly requests it.
    faithful, faithful_report, faithful_trace = run(runtime, script, "--trace-pcall-errors")
    diagnostic, diagnostic_report, diagnostic_trace = run(
        runtime, script, "--execution-mode", "diagnostic", "--trace-pcall-errors"
    )
    for completed in (faithful, diagnostic):
        if completed.returncode or "cli-execution-mode-v3-ok" not in completed.stdout:
            raise RuntimeError(f"execution-mode program failed:\n{completed.stdout}\n{completed.stderr}")
    require_release(faithful_report)
    require_release(diagnostic_report)
    if faithful_report.get("execution_mode") != "faithful":
        raise RuntimeError("CLI default is no longer faithful")
    if diagnostic_report.get("execution_mode") != "diagnostic":
        raise RuntimeError("diagnostic CLI mode was not applied")
    faithful_missing = [event for event in faithful_trace if event.get("kind") == "missing_global"]
    diagnostic_missing = [event for event in diagnostic_trace if event.get("kind") == "missing_global"]
    if faithful_missing:
        raise RuntimeError(f"faithful mode unexpectedly enabled missing-global analysis hooks: {faithful_missing}")
    if not any(event.get("name") == "CLI_EXECUTION_MODE_MISSING_GLOBAL" for event in diagnostic_missing):
        raise RuntimeError("diagnostic mode did not enable its missing-global analysis hook")


def deterministic_codegen_contract(runtime: pathlib.Path) -> None:
    script = ROOT / "tests" / "cli_parity_v3.luau"
    native_a, report_a, _ = run(runtime, script, "--deterministic-seed", "424242", "--native-codegen")
    native_b, report_b, _ = run(runtime, script, "--deterministic-seed", "424242", "--native-codegen")
    interpreted, interpreted_report, _ = run(runtime, script, "--deterministic-seed", "424242", "--no-native-codegen")
    other_seed, other_report, _ = run(runtime, script, "--deterministic-seed", "424243", "--native-codegen")
    for completed, report in ((native_a, report_a), (native_b, report_b), (interpreted, interpreted_report), (other_seed, other_report)):
        require_release(report)
        if completed.returncode or report.get("execution_state") != "completed":
            raise RuntimeError(f"determinism/parity run failed:\n{completed.stdout}\n{completed.stderr}\n{report.get('error')}")
    if native_a.stdout != native_b.stdout or report_a.get("typed_returns") != report_b.get("typed_returns"):
        raise RuntimeError("identical deterministic seeds produced different output")
    if native_a.stdout != interpreted.stdout or report_a.get("typed_returns") != interpreted_report.get("typed_returns"):
        raise RuntimeError("interpreter and native CodeGen results diverged")
    if native_a.stdout == other_seed.stdout:
        raise RuntimeError("different deterministic seeds produced identical randomized output")
    if not (report_a.get("codegen") or {}).get("enabled"):
        raise RuntimeError("native CodeGen run did not report CodeGen enabled")
    if (report_a.get("codegen") or {}).get("budget_bytes", 0) > (report_a.get("limits") or {}).get("memory_limit_bytes", 0) // 2:
        raise RuntimeError("native CodeGen budget is not contained by the overall memory limit")
    if (interpreted_report.get("codegen") or {}).get("enabled"):
        raise RuntimeError("interpreter run did not report CodeGen disabled")

    module_script = ROOT / "tests" / "cli_module_codegen_parity_v3.luau"
    module_scenario = ROOT / "tests" / "fixtures" / "runtime_v2_scenario_v2.json"
    native_module, native_module_report, _ = run(
        runtime,
        module_script,
        "--deterministic-seed", "424242", "--native-codegen",
        scenario=module_scenario,
    )
    interpreted_module, interpreted_module_report, _ = run(
        runtime,
        module_script,
        "--deterministic-seed", "424242", "--no-native-codegen",
        scenario=module_scenario,
    )
    for completed, report in ((native_module, native_module_report), (interpreted_module, interpreted_module_report)):
        require_release(report)
        if completed.returncode or report.get("execution_state") != "completed":
            raise RuntimeError(f"ModuleScript parity run failed:\n{completed.stdout}\n{completed.stderr}\n{report.get('error')}")
    if native_module.stdout != interpreted_module.stdout or native_module_report.get("typed_returns") != interpreted_module_report.get("typed_returns"):
        raise RuntimeError("ModuleScript interpreter and native CodeGen results diverged")
    native_codegen = native_module_report.get("codegen") or {}
    if native_codegen.get("chunks_loaded", 0) < 2 or native_codegen.get("chunks_native_attempted", 0) < 2:
        raise RuntimeError(f"native CodeGen did not include the required ModuleScript: {native_codegen}")
    if (interpreted_module_report.get("codegen") or {}).get("chunks_native_attempted", 0) != 0:
        raise RuntimeError("interpreted ModuleScript run unexpectedly attempted native CodeGen")


def memory_contract(runtime: pathlib.Path) -> None:
    script = ROOT / "tests" / "cli_memory_limit_v3.luau"
    completed, report, _ = run(runtime, script, "--memory-limit-mb", "16", "--no-native-codegen", timeout=10)
    require_release(report)
    limits = report.get("limits") or {}
    if completed.returncode == 0 or report.get("execution_state") != "failed":
        raise RuntimeError("memory exhaustion unexpectedly completed successfully")
    if not limits.get("memory_limit_hit"):
        raise RuntimeError(f"memory allocation did not fail closed at the configured limit: {limits}")
    if limits.get("memory_peak_bytes", 0) > limits.get("memory_limit_bytes", 0):
        raise RuntimeError(f"reported peak exceeded the allocator's hard limit: {limits}")

    ordinary_error = ROOT / "tests" / "cli_error_classification_v3.luau"
    failed, failed_report, _ = run(runtime, ordinary_error, "--no-native-codegen")
    require_release(failed_report)
    if failed.returncode == 0 or failed_report.get("termination_reason") != "runtime_error":
        raise RuntimeError("an ordinary script error containing the word memory was misclassified as allocator exhaustion")
    if (failed_report.get("limits") or {}).get("memory_limit_hit"):
        raise RuntimeError("ordinary script error incorrectly marked the allocator limit as hit")


def cyclic_report_contract(runtime: pathlib.Path) -> None:
    script = ROOT / "tests" / "cli_report_cycles_v3.luau"
    completed, report, _ = run(runtime, script, "--no-native-codegen")
    require_release(report)
    if completed.returncode or report.get("execution_state") != "completed":
        raise RuntimeError(f"cyclic report run failed:\n{completed.stdout}\n{completed.stderr}\n{report.get('error')}")
    encoded = json.dumps(report, sort_keys=True)
    if "<cycle-or-reference>" not in encoded:
        raise RuntimeError("cyclic runtime values were not represented with a bounded reference marker")
    if "<value-limit>" in encoded:
        raise RuntimeError("small cyclic runtime values incorrectly exhausted the report value budget")
    if len(encoded) > 2 * 1024 * 1024:
        raise RuntimeError("small cyclic runtime values produced an unexpectedly large report")


def output_and_binary_contract(runtime: pathlib.Path) -> None:
    output_script = ROOT / "tests" / "cli_output_limit_v3.luau"
    completed, report, _ = run(runtime, output_script, "--no-native-codegen", timeout=10)
    require_release(report)
    limits = report.get("limits") or {}
    if completed.returncode == 0 or report.get("termination_reason") != "output_limit":
        raise RuntimeError("host output exhaustion did not fail closed")
    if not limits.get("output_limit_hit") or limits.get("output_captured_bytes", 0) > limits.get("output_limit_bytes", 0):
        raise RuntimeError(f"invalid output-limit accounting: {limits}")

    binary_script = ROOT / "tests" / "cli_binary_return_v3.luau"
    binary, binary_report, _ = run(runtime, binary_script, "--no-native-codegen")
    require_release(binary_report)
    if binary.returncode or binary_report.get("execution_state") != "completed":
        raise RuntimeError("binary-string report run failed")
    value = (binary_report.get("typed_returns") or [{}])[0].get("value") or {}
    if value.get("type") != "binary-string" or value.get("encoding") != "hex" or value.get("bytes") != 9:
        raise RuntimeError(f"binary string was not represented safely: {value}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    args = parser.parse_args()
    mode_contract(args.runtime)
    deterministic_codegen_contract(args.runtime)
    memory_contract(args.runtime)
    cyclic_report_contract(args.runtime)
    output_and_binary_contract(args.runtime)
    print("Release-729 CLI OK: faithful defaults, diagnostic hooks, deterministic seed, CodeGen parity, memory/output limits, safe reports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
