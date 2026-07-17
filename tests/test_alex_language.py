#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILES = ("compatibility", "hardened", "maximum")


def run(command, *, input_text=None, check=True):
    result = subprocess.run(
        command,
        cwd=ROOT,
        input=input_text,
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


def normalize(value):
    if isinstance(value, str):
        return re.sub(r"(?:[^\s:]+[/\\])*[^\s:]+\.lua(?:u)?:\d+:\s*", "", value)
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {
            key: normalize(item)
            for key, item in value.items()
            if key not in {"path", "source", "thread"}
        }
    return value


def observe(runtime, source, directory, label):
    report_path = directory / f"{label}-runtime.json"
    capture_path = directory / f"{label}-captures"
    shutil.rmtree(capture_path, ignore_errors=True)
    result = run([
        str(runtime), "--luraph-mode", "off", "--analysis-hooks", "off",
        "--network-policy", "offline", "--report", str(report_path),
        "--out", str(capture_path), str(source),
    ], check=False)
    if not report_path.exists():
        raise RuntimeError(f"runtime report missing for {label}: {result.stderr}")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    scheduler = report.get("scheduler") or {}
    return {
        "exit_code": result.returncode,
        "status": report.get("status"),
        "termination_reason": report.get("termination_reason"),
        "returns": report.get("returns"),
        "stdout": report.get("stdout"),
        "stderr": normalize(report.get("stderr")),
        "error": normalize(report.get("error")),
        "unsupported": report.get("unsupported"),
        "scheduler": {
            "budget_reached": scheduler.get("budget_reached"),
            "stop_reason": scheduler.get("stop_reason"),
            "frames": scheduler.get("frames"),
            "virtual_time": scheduler.get("virtual_time"),
        },
    }


def compile_source(compiler, source, output, report, profile, seed, *extra):
    run([
        str(compiler), str(source), "-o", str(output), "--report", str(report),
        "--profile", profile, "--runtime", "universal",
        "--environment-binding", "portable", "--seed", str(seed),
        "--format", "one-line", "--no-watermark", *extra,
    ])
    return json.loads(report.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--alexfuscator", type=pathlib.Path, default=ROOT / "build" / "alexfuscator")
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    args = parser.parse_args()

    alex_source = ROOT / "tests" / "alex1_semantics.alex"
    luau_source = ROOT / "tests" / "alex1_semantics.luau"
    expected_source = alex_source.read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="alex-language-") as temporary_name:
        temporary = pathlib.Path(temporary_name)
        source_observation = observe(args.runtime, luau_source, temporary, "source")

        for profile in PROFILES:
            alex_output = temporary / f"alex-{profile}.luau"
            luau_output = temporary / f"luau-{profile}.luau"
            alex_report = temporary / f"alex-{profile}.json"
            luau_report = temporary / f"luau-{profile}.json"
            ir_dump = temporary / f"alex-{profile}.air"
            vm_dump = temporary / f"alex-{profile}.avm"

            descriptor = compile_source(
                args.alexfuscator, alex_source, alex_output, alex_report,
                profile, 6200, "--unsafe-debug-map", "--dump-ir", str(ir_dump),
                "--dump-vm", str(vm_dump),
            )
            luau_descriptor = compile_source(
                args.alexfuscator, luau_source, luau_output, luau_report,
                profile, 6200,
            )

            required = {
                "report_version": 4,
                "backend": "alexvm6",
                "vm_version": 6,
                "ir_version": 2,
                "language": "alex",
                "language_version": 1,
                "frontend": "alex1",
                "profile": profile,
                "fallback_used": False,
            }
            for key, expected in required.items():
                if descriptor.get(key) != expected:
                    raise RuntimeError(f"Alex report mismatch for {key}: {descriptor}")
            if luau_descriptor.get("language") != "luau" or luau_descriptor.get("frontend") != "luau":
                raise RuntimeError(f"Luau frontend report mismatch: {luau_descriptor}")
            flags = descriptor.get("feature_flags") or {}
            for flag in ("validated_control_flow", "declarative_instruction_set", "round_trip_debug_formats"):
                if flags.get(flag) is not True:
                    raise RuntimeError(f"missing VM 6 feature flag {flag}: {flags}")
            if not descriptor.get("passes"):
                raise RuntimeError("report omitted ordered compiler passes")

            ir = json.loads(ir_dump.read_text(encoding="utf-8"))
            vm = json.loads(vm_dump.read_text(encoding="utf-8"))
            if (ir.get("format"), ir.get("version")) != ("alex-ir", 2):
                raise RuntimeError(f"invalid AlexIR dump header: {ir}")
            if (vm.get("format"), vm.get("version")) != ("alex-vm", 6):
                raise RuntimeError(f"invalid AlexVM dump header: {vm}")

            alex_observation = observe(args.runtime, alex_output, temporary, f"alex-{profile}")
            luau_observation = observe(args.runtime, luau_output, temporary, f"luau-{profile}")
            if alex_observation != source_observation or luau_observation != source_observation:
                raise RuntimeError(
                    f"semantic mismatch for {profile}\n"
                    f"source={json.dumps(source_observation, sort_keys=True)}\n"
                    f"alex={json.dumps(alex_observation, sort_keys=True)}\n"
                    f"luau={json.dumps(luau_observation, sort_keys=True)}"
                )

            artifact = alex_output.read_text(encoding="utf-8")
            if "loadstring" in artifact or "alex1-semantics" in artifact or expected_source.strip() in artifact:
                raise RuntimeError(f"{profile} artifact exposed source-bearing content")

        fixed_a = temporary / "fixed-a.luau"
        fixed_b = temporary / "fixed-b.luau"
        report = temporary / "fixed.json"
        compile_source(args.alexfuscator, alex_source, fixed_a, report, "maximum", 9911)
        compile_source(args.alexfuscator, alex_source, fixed_b, report, "maximum", 9911)
        if fixed_a.read_bytes() != fixed_b.read_bytes():
            raise RuntimeError("fixed Alex seed was not byte-identical")

        folded_source = temporary / "folded.alex"
        folded_source.write_text(
            'let value = 2 + 3\n'
            'if false { print("never") }\n'
            'print("folded", value)\n',
            encoding="utf-8",
        )
        folded_output = temporary / "folded.luau"
        folded_report = temporary / "folded.json"
        folded = compile_source(
            args.alexfuscator, folded_source, folded_output, folded_report,
            "compatibility", 31337,
        )
        if folded.get("constant_fold_count", 0) < 1:
            raise RuntimeError(f"constant propagation did not report a change: {folded}")
        if folded.get("branch_fold_count", 0) < 1:
            raise RuntimeError(f"branch folding did not report a change: {folded}")
        if folded.get("unreachable_instruction_count", 0) < 1:
            raise RuntimeError(f"unreachable-code pruning did not report a change: {folded}")
        folded_stdout = observe(args.runtime, folded_output, temporary, "folded").get("stdout", "")
        if "folded\t5" not in folded_stdout or "never" in folded_stdout:
            raise RuntimeError(f"optimized Alex artifact changed behavior: {folded_stdout!r}")

        invalid = temporary / "invalid.alex"
        invalid.write_text("let = 3\n", encoding="utf-8")
        failed = run([str(args.alexfuscator), str(invalid), "-o", str(temporary / "invalid.luau"), "--diagnostics-json"], check=False)
        diagnostic = json.loads(failed.stderr)
        error = diagnostic.get("error") or {}
        if failed.returncode == 0 or error.get("stage") != "parse" or error.get("language") != "alex" or "location" not in error:
            raise RuntimeError(f"invalid Alex diagnostic: {diagnostic}")

        guarded = run([
            str(args.alexfuscator), str(alex_source), "-o", str(temporary / "guarded.luau"),
            "--dump-ir", str(temporary / "guarded.air"), "--diagnostics-json",
        ], check=False)
        if guarded.returncode == 0 or "require --unsafe-debug-map" not in guarded.stderr:
            raise RuntimeError("sensitive IR dump was accepted without --unsafe-debug-map")

        stdin_output = temporary / "stdin.luau"
        stdin_result = run([
            str(args.alexfuscator), "--stdin", "-o", str(stdin_output),
            "--profile", "compatibility", "--seed", "42", "--no-watermark",
        ], input_text='print("stdin-luau-default")\n')
        if stdin_result.returncode or "stdin-luau-default" not in observe(args.runtime, stdin_output, temporary, "stdin").get("stdout", ""):
            raise RuntimeError("stdin no longer defaults to Luau")

    print("Alex 1 language OK: parser, binder, IR/VM round-trip, three profiles, and Luau differential parity")


if __name__ == "__main__":
    main()
