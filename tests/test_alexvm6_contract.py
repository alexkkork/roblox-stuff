#!/usr/bin/env python3
import argparse
import copy
import json
import pathlib
import re
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from alexfuscator_static_quality import validate_report  # noqa: E402


PROFILES = ("compatibility", "hardened", "maximum")
RUNTIME_MARKER = "ALEXVM6:"
OUTPUT_MARKER = "alexvm6-contract-ok"
SECRET = "VM6_CONTRACT_SECRET_6a1f3c9e"
FORBIDDEN_VM5_PATTERNS = (
    "LUAUVM5:",
    "register_vm_v5",
    "register-vm-v5",
    "register_bytecode_vm",
    "alex_ast_vm_vnext",
    "hardened_loader_fallback",
    "original_luau",
)
SOURCE = f'''local secret = "{SECRET}"
local folded = 2 + 3
if false then
    print("unreachable-vm6-contract")
end

local captured = 7
local function worker(value)
    return value + captured + folded, secret
end

local bytecode = getfunctionbytecode(worker)
print("{OUTPUT_MARKER}", worker(5), string.find(bytecode, "{RUNTIME_MARKER}", 1, true) ~= nil)
return worker(6)
'''


def run(command, *, check=True):
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(map(str, command))}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def assert_report_contract(descriptor, expected_profile=None):
    failures, warnings = validate_report(descriptor)
    if warnings:
        failures.extend(f"unexpected report warning: {warning}" for warning in warnings)
    if expected_profile is not None and descriptor.get("profile") != expected_profile:
        failures.append(
            f"profile is {descriptor.get('profile')!r}, expected {expected_profile!r}"
        )
    if descriptor.get("language") != "luau" or descriptor.get("frontend") != "luau":
        failures.append("Luau source was not reported through the Luau frontend")
    if descriptor.get("fallback_used") is not False:
        failures.append("fallback_used must be exactly false")
    if failures:
        raise RuntimeError("invalid AlexVM6 report:\n- " + "\n- ".join(failures))


def assert_artifact_contract(text, *, source_marker=SECRET):
    failures = []
    lowered = text.lower()
    if re.search(r"\b(?:loadstring|load)\s*\(", text):
        failures.append("source loader call is present")
    for marker in FORBIDDEN_VM5_PATTERNS:
        if marker.lower() in lowered:
            failures.append(f"legacy or fallback marker is present: {marker}")
    for marker in (source_marker, OUTPUT_MARKER, RUNTIME_MARKER, SOURCE.strip()):
        if marker and marker in text:
            failures.append(f"source-bearing plaintext is present: {marker[:48]!r}")
    if failures:
        raise RuntimeError("invalid AlexVM6 artifact:\n- " + "\n- ".join(failures))


def compile_artifact(compiler, source, output, report, profile, seed):
    run([
        str(compiler),
        str(source),
        "-o",
        str(output),
        "--report",
        str(report),
        "--unsafe-debug-map",
        "--profile",
        profile,
        "--runtime",
        "executor",
        "--environment-binding",
        "portable",
        "--seed",
        str(seed),
        "--format",
        "one-line",
        "--no-watermark",
    ])
    descriptor = json.loads(report.read_text(encoding="utf-8"))
    assert_report_contract(descriptor, profile)
    assert_artifact_contract(output.read_text(encoding="utf-8"))
    return descriptor


def execute(runtime, artifact, output_dir):
    return run([
        str(runtime),
        "--profile",
        "executor-client",
        "--luraph-mode",
        "off",
        "--analysis-hooks",
        "off",
        "--network-policy",
        "offline",
        "--out",
        str(output_dir),
        str(artifact),
    ], check=False)


def run_static_scanners(artifact, report, source):
    scanners = (
        ROOT / "tools" / "alexfuscator_static_quality.py",
        ROOT / "web" / "rbx-runtime-runner" / "tools" / "alexfuscator_static_quality.py",
    )
    for scanner in scanners:
        result = run([
            sys.executable,
            str(scanner),
            str(artifact),
            "--debug-map",
            str(report),
            "--original",
            str(source),
        ], check=False)
        if result.returncode:
            raise RuntimeError(f"static scanner rejected VM6 artifact: {scanner}\n{result.stdout}\n{result.stderr}")
        scan = json.loads(result.stdout)
        expected = {
            "failures": [],
            "warnings": [],
            "debug_mode": "alexvm6",
            "debug_backend": "alexvm6",
            "report_version": 4,
            "vm_version": 6,
            "ir_version": 2,
        }
        for key, value in expected.items():
            if scan.get(key) != value:
                raise RuntimeError(f"static scanner contract mismatch for {key}: {scan}")


def main():
    parser = argparse.ArgumentParser(description="Focused AlexVM6 production contract test.")
    parser.add_argument("--alexfuscator", type=pathlib.Path, default=ROOT / "build" / "alexfuscator")
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="alex-vm6-contract-") as directory:
        temporary = pathlib.Path(directory)
        source = temporary / "contract.luau"
        source.write_text(SOURCE, encoding="utf-8")

        descriptors = {}
        for index, profile in enumerate(PROFILES):
            artifact = temporary / f"{profile}.luau"
            report = temporary / f"{profile}.json"
            descriptor = compile_artifact(
                args.alexfuscator,
                source,
                artifact,
                report,
                profile,
                8600 + index,
            )
            descriptors[profile] = descriptor
            result = execute(args.runtime, artifact, temporary / f"{profile}-run")
            if result.returncode:
                raise RuntimeError(f"{profile} artifact failed at runtime: {result.stdout}\n{result.stderr}")
            if OUTPUT_MARKER not in result.stdout or not re.search(
                rf"{re.escape(OUTPUT_MARKER)}\s+17\s+true", result.stdout
            ):
                raise RuntimeError(
                    f"{profile} runtime did not expose the AlexVM6 synthetic marker: {result.stdout!r}"
                )
            run_static_scanners(artifact, report, source)

        maximum = descriptors["maximum"]
        if maximum.get("constant_fold_count", 0) < 1:
            raise RuntimeError("constant propagation did not report its source rewrite")
        if maximum.get("branch_fold_count", 0) < 1:
            raise RuntimeError("branch folding did not report its source rewrite")
        if maximum.get("unreachable_instruction_count", 0) < 1:
            raise RuntimeError("unreachable pruning did not report its source rewrite")

        fixed_a = temporary / "fixed-a.luau"
        fixed_b = temporary / "fixed-b.luau"
        fixed_a_report = temporary / "fixed-a.json"
        fixed_b_report = temporary / "fixed-b.json"
        fixed_a_descriptor = compile_artifact(
            args.alexfuscator, source, fixed_a, fixed_a_report, "maximum", 606060
        )
        fixed_b_descriptor = compile_artifact(
            args.alexfuscator, source, fixed_b, fixed_b_report, "maximum", 606060
        )
        if fixed_a.read_bytes() != fixed_b.read_bytes():
            raise RuntimeError("fixed seed did not produce byte-identical AlexVM6 artifacts")
        if fixed_a_descriptor != fixed_b_descriptor:
            raise RuntimeError("fixed seed did not produce byte-identical AlexVM6 reports")

        auto_a = temporary / "auto-a.luau"
        auto_b = temporary / "auto-b.luau"
        auto_a_report = temporary / "auto-a.json"
        auto_b_report = temporary / "auto-b.json"
        auto_a_descriptor = compile_artifact(
            args.alexfuscator, source, auto_a, auto_a_report, "maximum", "auto"
        )
        auto_b_descriptor = compile_artifact(
            args.alexfuscator, source, auto_b, auto_b_report, "maximum", "auto"
        )
        if auto_a_descriptor.get("seed") == auto_b_descriptor.get("seed"):
            raise RuntimeError("automatic seed generation repeated its reported seed")
        if auto_a.read_bytes() == auto_b.read_bytes():
            raise RuntimeError("automatic seeds produced identical AlexVM6 artifacts")

        dishonest = copy.deepcopy(maximum)
        dishonest["branch_fold_count"] += 1
        try:
            assert_report_contract(dishonest, "maximum")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("report validator accepted a dishonest pass count")

        dishonest_report = temporary / "dishonest.json"
        dishonest_report.write_text(json.dumps(dishonest), encoding="utf-8")
        scanner = ROOT / "tools" / "alexfuscator_static_quality.py"
        rejected = run([
            sys.executable,
            str(scanner),
            str(temporary / "maximum.luau"),
            "--debug-map",
            str(dishonest_report),
        ], check=False)
        if rejected.returncode == 0:
            raise RuntimeError("static scanner accepted a dishonest pass count")

        stale_report = copy.deepcopy(maximum)
        stale_report.update({
            "report_version": 3,
            "mode": "register_vm_v5",
            "backend": "register_vm_v5",
            "vm_version": 5,
            "fallback_used": True,
        })
        stale_report_path = temporary / "stale-vm5.json"
        stale_report_path.write_text(json.dumps(stale_report), encoding="utf-8")
        stale = run([
            sys.executable,
            str(scanner),
            str(temporary / "maximum.luau"),
            "--debug-map",
            str(stale_report_path),
        ], check=False)
        if stale.returncode == 0:
            raise RuntimeError("static scanner accepted a VM5/fallback report")

        weak_artifact = temporary / "legacy-loader.luau"
        weak_artifact.write_text(
            'return loadstring("source")() -- LUAUVM5: register_vm_v5\n',
            encoding="utf-8",
        )
        weak = run([
            sys.executable,
            str(scanner),
            str(weak_artifact),
            "--debug-map",
            str(temporary / "maximum.json"),
        ], check=False)
        if weak.returncode == 0:
            raise RuntimeError("static scanner accepted a VM5 loadstring artifact")

    print(
        "AlexVM6 contract OK: report v4, VM6 marker, no VM5/source fallback, "
        "truthful passes, deterministic fixed seeds, and diverse auto seeds"
    )


if __name__ == "__main__":
    main()
