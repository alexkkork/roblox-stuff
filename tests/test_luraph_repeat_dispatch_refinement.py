#!/usr/bin/env python3
"""Exercise bounded trace refinement for a repeat-until-false Luraph dispatcher."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
MARKER = "repeat-dispatch-ok"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def generated_interpreter() -> str:
    padding = "repeat_dispatch_padding_" * 16
    helpers = []
    for index in range(40):
        helpers.append(
            f"helper_{index}=function()"
            f"local text='{padding}{index:02d}';"
            "local slots={[1]=text,[2]=text};"
            "while true do break end;"
            "return slots[1],slots[2] end"
        )

    branches = []
    for opcode in range(3, 48):
        branches.append(f"elseif opcode=={opcode} then pc+=1")

    run = (
        "run=function(...)"
        "local registers={[1]=print,[2]='repeat-dispatch-ok',[3]=false,[4]=true};"
        "local opcode_table={[1]=1,[2]=2};"
        "local lane_a={[1]=1,[2]=3};"
        "local lane_b={[1]=2,[2]=2};"
        "local lane_c={[1]=3,[2]=3};"
        "local lane_d={[1]=4,[2]=4};"
        "local pc=1;"
        "repeat "
        "local opcode=opcode_table[pc];"
        "if opcode==1 then "
        "local keep_c=registers[lane_c[pc]];"
        "local keep_d=registers[lane_d[pc]];"
        "registers[lane_c[pc]]=keep_c;"
        "registers[lane_d[pc]]=keep_d;"
        "registers[lane_a[pc]](registers[lane_b[pc]]);"
        "pc+=1 "
        "elseif opcode==2 then return registers[lane_b[pc]] "
        + " ".join(branches)
        + " else return nil end "
        "until false end"
    )
    source = (
        "local V=...;return({"
        "yield=coroutine.yield,buffer=buffer,bit=bit32,"
        + run
        + ","
        + ",".join(helpers)
        + "}).run(V)"
    )
    require(len(source.encode("utf-8")) >= 16 * 1024,
            "synthetic interpreter must cross the generated-source size threshold")
    return source


def run_deobfuscator(
    deobfuscator: pathlib.Path,
    subject: pathlib.Path,
    output: pathlib.Path,
    report: pathlib.Path,
    trace: pathlib.Path | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        str(deobfuscator), str(subject),
        "--output-dir", str(output),
        "--mode", "reconstruct",
        "--report", str(report),
    ]
    if trace is not None:
        command.extend(("--trace", str(trace)))
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=25,
    )


def run_runtime(
    runtime: pathlib.Path,
    probe: pathlib.Path,
    report: pathlib.Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(runtime),
            "--profile", "executor-client",
            "--execution-mode", "faithful",
            "--analysis-hooks", "off",
            "--network-policy", "offline",
            "--clock", "virtual",
            "--timeout", "10",
            "--memory-limit-mb", "512",
            "--unsupported", "trace-nil",
            "--luraph-mode", "force",
            "--luraph-max-steps", "1000000",
            "--luraph-stall-steps", "0",
            "--no-native-codegen",
            "--report", str(report),
            str(probe),
        ],
        cwd=ROOT,
        text=True,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=20,
    )


def pass_for(report: dict[str, object], stage: str) -> dict[str, object]:
    return next(
        item for item in report.get("passes", [])
        if isinstance(item, dict) and item.get("stage") == stage
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-repeat-refine-") as temporary:
        root = pathlib.Path(temporary)
        subject = root / "repeat_dispatch.luau"
        subject.write_text(generated_interpreter(), encoding="utf-8")

        initial_output = root / "initial"
        initial_report_path = root / "initial-report.json"
        initial = run_deobfuscator(
            args.deobfuscator, subject, initial_output, initial_report_path)
        require(initial.returncode == 2,
                f"initial generated-interpreter analysis exited {initial.returncode}:\n"
                f"{initial.stdout}\n{initial.stderr}")
        initial_report = json.loads(initial_report_path.read_text(encoding="utf-8"))
        require(initial_report.get("adapter") == "luraph-runtime-interpreter",
                f"generated interpreter was misclassified: {initial_report.get('adapter')}")
        require(initial_report.get("status") == "blocked",
                "initial analysis must remain source-withheld")
        trace_probe_pass = pass_for(initial_report, "trace_probe")
        require(trace_probe_pass.get("ok") is True
                and trace_probe_pass.get("generator") == "structural-ast-v1",
                f"structural call probe was not generated: {trace_probe_pass}")

        handlers = json.loads((initial_output / "opcode_handlers.json").read_text(encoding="utf-8"))
        require(handlers.get("loop_kind") == "repeat-until-false",
                f"repeat dispatcher was not selected: {handlers.get('loop_kind')}")
        require(handlers.get("conditionals", 0) >= 40,
                f"dispatcher evidence threshold was not exercised: {handlers.get('conditionals')}")

        initial_probe_path = initial_output / "trace_probe.luau"
        initial_probe = initial_probe_path.read_text(encoding="utf-8")
        require("repeat" in initial_probe and "until false" in initial_probe,
                "call-only instrumentation did not preserve the repeat dispatcher")
        require("@@LPH_CALL_V2@@" in initial_probe,
                "initial probe omitted call discovery")
        for forbidden in ("@@LPH_VM@@", "@@LPH_STEP_V1@@", "@@LPH_RETURN_V1@@"):
            require(forbidden not in initial_probe,
                    f"initial call-only probe unexpectedly contains {forbidden}")

        initial_run = run_runtime(
            args.runtime, initial_probe_path, root / "initial-runtime-report.json")
        require(initial_run.returncode == 0,
                f"initial call-only probe failed:\n{initial_run.stdout}")
        require(initial_run.stdout.count("@@LPH_CALL_V2@@") == 1,
                f"initial probe did not report exactly one call candidate:\n{initial_run.stdout}")
        require(MARKER in initial_run.stdout,
                f"initial probe changed dispatcher behavior:\n{initial_run.stdout}")
        for forbidden in ("@@LPH_VM@@", "@@LPH_STEP_V1@@", "@@LPH_RETURN_V1@@"):
            require(forbidden not in initial_run.stdout,
                    f"call-only run unexpectedly emitted {forbidden}")

        initial_trace = root / "initial-trace.log"
        initial_trace.write_text(initial_run.stdout, encoding="utf-8")
        refined_output = root / "refined"
        refined_report_path = root / "refined-report.json"
        refined = run_deobfuscator(
            args.deobfuscator, subject, refined_output, refined_report_path, initial_trace)
        require(refined.returncode == 2,
                f"call-only evidence should request refinement, got {refined.returncode}:\n"
                f"{refined.stdout}\n{refined.stderr}")
        refined_report = json.loads(refined_report_path.read_text(encoding="utf-8"))
        diagnostics = refined_report.get("diagnostics", [])
        require(any(
            isinstance(item, dict)
            and item.get("code") == "luraph_trace_refinement_required"
            for item in diagnostics
        ), "call-only evidence did not report bounded refinement")
        refine_pass = pass_for(refined_report, "trace_refine")
        require(refine_pass.get("ok") is True
                and refine_pass.get("reason") == "payload_activation_boundary_required"
                and refine_pass.get("generator") == "structural-ast-v1",
                f"refinement metadata is incomplete: {refine_pass}")
        require(refine_pass.get("range_start") == 1
                and refine_pass.get("range_end") == 513,
                f"unexpected bounded trace window: {refine_pass}")
        require(refine_pass.get("evidence_mode") == "structure-and-dynamic",
                f"refinement did not request structural and dynamic evidence: {refine_pass}")

        refined_probe_path = refined_output / "trace_probe.luau"
        refined_probe = refined_probe_path.read_text(encoding="utf-8")
        require(refined_probe != initial_probe,
                "refinement did not replace the call-only probe")
        require("repeat" in refined_probe and "until false" in refined_probe,
                "refinement did not preserve repeat-until-false syntax")
        for marker in (
            "@@LPH_ACTIVATION@@",
            "@@LPH_ACT_PROTO_V1@@",
            "@@LPH_VM@@",
            "@@LPH_STEP_V1@@",
            "@@LPH_RETURN_V1@@",
        ):
            require(marker in refined_probe,
                    f"refined probe omitted {marker}")

        refined_run = run_runtime(
            args.runtime, refined_probe_path, root / "refined-runtime-report.json")
        require(refined_run.returncode == 0,
                f"refined repeat dispatcher failed:\n{refined_run.stdout}")
        require(MARKER in refined_run.stdout,
                f"refined probe changed dispatcher behavior:\n{refined_run.stdout}")
        for marker in (
            "@@LPH_ACTIVATION@@",
            "@@LPH_ACT_PROTO_V1@@",
            "@@LPH_VM@@",
            "@@LPH_STEP_V1@@",
            "@@LPH_RETURN_V1@@",
        ):
            require(marker in refined_run.stdout,
                    f"refined run omitted {marker}:\n{refined_run.stdout}")
        require("runtime_error" not in refined_run.stdout
                and "timed out" not in refined_run.stdout,
                f"refined run reported a runtime failure:\n{refined_run.stdout}")

        refined_trace = root / "refined-trace.log"
        refined_trace.write_text(refined_run.stdout, encoding="utf-8")
        converged_output = root / "converged"
        converged_report_path = root / "converged-report.json"
        converged = run_deobfuscator(
            args.deobfuscator, subject, converged_output,
            converged_report_path, refined_trace)
        require(converged.returncode in (0, 2),
                f"refined evidence produced an unexpected exit {converged.returncode}:\n"
                f"{converged.stdout}\n{converged.stderr}")
        converged_report = json.loads(converged_report_path.read_text(encoding="utf-8"))
        trace_pass = pass_for(converged_report, "trace")
        require(trace_pass.get("payload_activation_complete") is True,
                f"refined trace did not prove its activation boundary: {trace_pass}")
        require(not any(
            isinstance(item, dict) and item.get("stage") == "trace_refine"
            for item in converged_report.get("passes", [])
        ), "complete repeat-dispatch evidence requested another refinement")
        require(not any(
            isinstance(item, dict)
            and item.get("code") == "luraph_trace_refinement_required"
            for item in converged_report.get("diagnostics", [])
        ), "converged repeat-dispatch trace retained a refinement diagnostic")

    print("Luraph repeat-dispatch refinement OK: call-only, bounded dynamic, and convergence stages passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
