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
        [str(part) for part in command],
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
        runtime,
        "--luraph-mode", "off",
        "--analysis-hooks", "off",
        "--network-policy", "offline",
        "--report", report_path,
        "--out", capture_path,
        source,
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


def output_contains(observation, expected):
    stdout = observation.get("stdout") or []
    if isinstance(stdout, str):
        return expected in stdout
    return any(expected in str(line) for line in stdout)


def compile_source(compiler, source, output, report, profile="compatibility", *extra):
    result = run([
        compiler,
        source,
        "-o", output,
        "--report", report,
        "--profile", profile,
        "--runtime", "universal",
        "--environment-binding", "portable",
        "--seed", "41027",
        "--format", "one-line",
        "--no-watermark",
        *extra,
    ])
    descriptor = json.loads(report.read_text(encoding="utf-8"))
    return result, descriptor


def assert_diagnostic(compiler, directory, name, source, stage, code):
    input_path = directory / f"diagnostic-{name}.alex"
    output_path = directory / f"diagnostic-{name}.luau"
    input_path.write_text(source, encoding="utf-8")
    result = run([
        compiler,
        input_path,
        "-o", output_path,
        "--language", "alex",
        "--diagnostics-json",
    ], check=False)
    if result.returncode == 0:
        raise RuntimeError(f"{name} unexpectedly compiled")
    try:
        payload = json.loads(result.stderr)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{name} did not emit JSON diagnostics: {result.stderr}") from error
    diagnostic = payload.get("error") or {}
    if payload.get("ok") is not False:
        raise RuntimeError(f"{name} diagnostic omitted ok=false: {payload}")
    if diagnostic.get("stage") != stage or diagnostic.get("code") != code:
        raise RuntimeError(f"{name} diagnostic mismatch: {payload}")
    if diagnostic.get("language") != "alex" or not diagnostic.get("kind"):
        raise RuntimeError(f"{name} diagnostic omitted frontend identity: {payload}")
    location = diagnostic.get("location") or {}
    if not isinstance(location.get("line"), int) or not isinstance(location.get("column"), int):
        raise RuntimeError(f"{name} diagnostic omitted source location: {payload}")
    if source.strip() in result.stderr or "source" in diagnostic:
        raise RuntimeError(f"{name} diagnostic exposed source text: {payload}")
    if output_path.exists():
        raise RuntimeError(f"{name} emitted output after a frontend failure")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--alexfuscator", type=pathlib.Path, default=ROOT / "build" / "alexfuscator")
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    args = parser.parse_args()

    alex_source = ROOT / "tests" / "alex1_edges.alex"
    luau_source = ROOT / "tests" / "alex1_edges.luau"

    with tempfile.TemporaryDirectory(prefix="alex-language-edges-") as temporary_name:
        temporary = pathlib.Path(temporary_name)
        oracle = observe(args.runtime, luau_source, temporary, "luau-source")
        expected_output = "alex1-edges\t1\t-4\t4\t5\t6\t6\t24\t15\tOKR\t30\t12\t13\tedge 1:120:OKR"
        if oracle.get("status") != "completed" or not output_contains(oracle, expected_output):
            raise RuntimeError(f"paired Luau fixture did not produce the expected result: {oracle}")

        for profile in PROFILES:
            output = temporary / f"edges-{profile}.luau"
            report = temporary / f"edges-{profile}.json"
            _, descriptor = compile_source(args.alexfuscator, alex_source, output, report, profile)
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
            mismatches = {
                key: (descriptor.get(key), value)
                for key, value in required.items()
                if descriptor.get(key) != value
            }
            if mismatches:
                raise RuntimeError(f"{profile} report mismatch: {mismatches}")
            actual = observe(args.runtime, output, temporary, f"edges-{profile}")
            if actual != oracle:
                raise RuntimeError(
                    f"Alex edge semantic mismatch for {profile}\n"
                    f"oracle={json.dumps(oracle, sort_keys=True)}\n"
                    f"actual={json.dumps(actual, sort_keys=True)}"
                )

        explicit_input = temporary / "explicit-language.txt"
        explicit_input.write_text('let value = 40 + 2\nprint("explicit-alex", value)\n', encoding="utf-8")
        explicit_output = temporary / "explicit-language.luau"
        explicit_report = temporary / "explicit-language.json"
        _, explicit_descriptor = compile_source(
            args.alexfuscator,
            explicit_input,
            explicit_output,
            explicit_report,
            "compatibility",
            "--language", "alex",
        )
        if explicit_descriptor.get("language") != "alex":
            raise RuntimeError(f"explicit Alex language was ignored: {explicit_descriptor}")
        if not output_contains(observe(args.runtime, explicit_output, temporary, "explicit"), "explicit-alex\t42"):
            raise RuntimeError("explicit Alex input did not execute")

        fallback_input = temporary / "unknown-extension.txt"
        fallback_input.write_text('local value = 6 * 7\nprint("fallback-luau", value)\n', encoding="utf-8")
        fallback_output = temporary / "unknown-extension.luau"
        fallback_report = temporary / "unknown-extension.json"
        _, fallback_descriptor = compile_source(
            args.alexfuscator,
            fallback_input,
            fallback_output,
            fallback_report,
        )
        if fallback_descriptor.get("language") != "luau" or fallback_descriptor.get("frontend") != "luau":
            raise RuntimeError(f"unknown extension no longer defaults to Luau: {fallback_descriptor}")
        if not output_contains(observe(args.runtime, fallback_output, temporary, "fallback"), "fallback-luau\t42"):
            raise RuntimeError("unknown-extension Luau input did not execute")

        assert_diagnostic(args.alexfuscator, temporary, "unterminated-comment", "/* never closed", "lex", "unterminated_comment")
        assert_diagnostic(args.alexfuscator, temporary, "missing-name", "let = 3\n", "parse", "expected_token")
        assert_diagnostic(args.alexfuscator, temporary, "duplicate-local", "let value = 1\nlet value = 2\n", "bind", "duplicate_local")
        assert_diagnostic(args.alexfuscator, temporary, "break-outside-loop", "break\n", "bind", "loop_control_outside_loop")
        assert_diagnostic(
            args.alexfuscator,
            temporary,
            "varargs-outside-function",
            "fn fixed(value) { return ... }\n",
            "bind",
            "varargs_outside_variadic_function",
        )

    print(
        "Alex 1 edge coverage OK: comments/floor division, interpolation, assignment order, "
        "closures/recursion, loops, varargs/multireturn, language selection, diagnostics"
    )


if __name__ == "__main__":
    main()
