#!/usr/bin/env python3
"""Automatic Luraph probe generation and truthful staged semantic lifting."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"
def run_runtime(runtime: pathlib.Path, source: pathlib.Path, report: pathlib.Path, *, luraph: bool) -> subprocess.CompletedProcess[str]:
    arguments = [
        str(runtime),
        "--profile", "executor-client",
        "--execution-mode", "faithful",
        "--network-policy", "offline",
        "--clock", "virtual",
        "--timeout", "15",
        "--no-native-codegen",
        "--report", str(report),
    ]
    if luraph:
        arguments.extend([
            "--memory-limit-mb", "768",
            "--unsupported", "trace-nil",
            "--luraph-mode", "force",
            "--luraph-max-steps", "100000000",
            "--luraph-stall-steps", "0",
        ])
    arguments.append(str(source))
    return subprocess.run(arguments, text=True, errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-auto-trace-") as temporary:
        root = pathlib.Path(temporary)
        static_output = root / "static"
        static = subprocess.run([
            str(args.deobfuscator), str(SUBJECT),
            "--output-dir", str(static_output),
            "--mode", "reconstruct",
            "--report", "-",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if static.returncode != 2:
            raise RuntimeError(f"initial bounded analysis unexpectedly exited {static.returncode}:\n{static.stdout}\n{static.stderr}")
        probe = static_output / "trace_probe.luau"
        if not probe.is_file() or "@@LPH_CALL_V2@@" not in probe.read_text(encoding="utf-8"):
            raise RuntimeError("native adapter did not emit its call-focused Luraph probe")

        trace_run = run_runtime(args.runtime, probe, root / "probe-report.json", luraph=True)
        if trace_run.returncode != 0 or "@@LPH_CALL_V2@@" not in trace_run.stdout or "anti tamper BYPASSED" not in trace_run.stdout:
            raise RuntimeError(f"automatic Luraph probe failed:\n{trace_run.stdout}")
        trace = root / "payload-trace.log"
        trace.write_text(trace_run.stdout, encoding="utf-8")

        lifted_output = root / "lifted"
        lifted = subprocess.run([
            str(args.deobfuscator), str(SUBJECT),
            "--output-dir", str(lifted_output),
            "--mode", "reconstruct",
            "--trace", str(trace),
            "--report", "-",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if lifted.returncode != 2:
            raise RuntimeError(f"initial trace should request a payload-window refinement:\n{lifted.stdout}\n{lifted.stderr}")
        refined_probe = lifted_output / "trace_probe.luau"
        refined_run = run_runtime(args.runtime, refined_probe, root / "refined-probe-report.json", luraph=True)
        if (refined_run.returncode != 0 or "@@LPH_VM@@" not in refined_run.stdout
                or "@@LPH_STEP_V1@@" not in refined_run.stdout
                or "@@LPH_RETURN_V1@@" not in refined_run.stdout):
            raise RuntimeError(f"refined Luraph payload-window probe failed:\n{refined_run.stdout}")
        refined_trace = root / "refined-payload-trace.log"
        refined_trace.write_text(refined_run.stdout, encoding="utf-8")
        lifted = subprocess.run([
            str(args.deobfuscator), str(SUBJECT),
            "--output-dir", str(lifted_output),
            "--mode", "reconstruct",
            "--trace", str(refined_trace),
            "--report", "-",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if lifted.returncode != 0:
            raise RuntimeError(f"complete payload closure should reconstruct source:\n{lifted.stdout}\n{lifted.stderr}")
        reconstructed = lifted_output / "reconstructed.luau"
        if reconstructed.read_text(encoding="utf-8") != 'print("anti tamper BYPASSED")\n':
            raise RuntimeError("statement-level reconstruction did not emit the recovered root payload")
        report = json.loads((lifted_output / "deobfuscation_report.json").read_text(encoding="utf-8"))
        runtime_decode = report.get("coverage", {}).get("runtime_decode", {})
        payload_closure = report.get("coverage", {}).get("payload_closure", {})
        if (report.get("status") != "reconstructed"
                or runtime_decode.get("complete") is not True
                or runtime_decode.get("prototypes") != 29
                or runtime_decode.get("instructions") != 8548
                or runtime_decode.get("effect_classified") != 8548
                or runtime_decode.get("semantic_lifted", 0) <= 0
                or runtime_decode.get("semantic_unresolved", -1) < 0
                or runtime_decode.get("semantic_lifted", 0)
                    + runtime_decode.get("semantic_unresolved", 0) != 8548):
            raise RuntimeError(f"automatic semantic coverage is not truthful: {runtime_decode}")
        if (payload_closure.get("activations") != 5
                or payload_closure.get("prototypes") != 3
                or payload_closure.get("instructions") != 385
                or payload_closure.get("static_semantic_lifted", 0) <= 0
                or payload_closure.get("static_semantic_unresolved", -1) < 0
                or payload_closure.get("static_semantic_lifted", 0) + payload_closure.get("static_semantic_unresolved", 0) != 385
                or payload_closure.get("source_semantic_instructions", 0) + payload_closure.get("protector_internal_instructions", 0) != payload_closure.get("static_semantic_lifted", 0)
                or payload_closure.get("unresolved_observed_instructions", -1) < 0
                or payload_closure.get("unresolved_observed_instructions", 0) > payload_closure.get("static_semantic_unresolved", 0)
                or payload_closure.get("observed_returns", 0) <= 0
                or payload_closure.get("observed_steps", 0) <= 0):
            raise RuntimeError(f"payload closure evidence is incomplete: {payload_closure}")
        handlers = json.loads((lifted_output / "opcode_handlers.json").read_text(encoding="utf-8"))
        by_opcode = {handler.get("opcode"): handler for handler in handlers.get("handlers", [])}
        if (handlers.get("top_register_local") != "o"
                or handlers.get("environment_local") != "e"
                or handlers.get("upvalue_file_local") != "U"
                or handlers.get("helper_table_local") != "s"
                or any(
                by_opcode.get(opcode, {}).get("semantic_operation") is None
                for opcode in (2, 3, 13, 31, 32, 50, 52, 67, 73, 75, 79, 80, 87, 102, 108, 111, 116, 119, 130, 131, 137, 141, 146, 148, 157, 158))):
            raise RuntimeError("structural role inference did not lift the expected VM handlers")
        closure_path = lifted_output / "payload_closure_ir.json"
        closure = json.loads(closure_path.read_text(encoding="utf-8"))
        unresolved_instructions = [
            instruction
            for prototype in closure.get("prototypes", [])
            for instruction in prototype.get("instructions", [])
            if instruction.get("semantic_operation") is None
        ]
        if unresolved_instructions:
            raise RuntimeError(f"payload still contains unresolved instructions: {unresolved_instructions}")
        resolved_values = [
            instruction.get("semantic_operation", {}).get("runtime_resolution", {})
            for prototype in closure.get("prototypes", [])
            for instruction in prototype.get("instructions", [])
        ]
        if not any(value.get("register") == 1 and value.get("value", {}).get("name") == "print"
                   for value in resolved_values):
            raise RuntimeError(f"metatable-backed global load was not resolved at its real execution site: {resolved_values}")
        if not any(value.get("register") == 2
                   and value.get("value", {}).get("value") == "anti tamper BYPASSED"
                   for value in resolved_values):
            raise RuntimeError(f"metatable-backed constant load was not resolved at its real execution site: {resolved_values}")
        reconstruction_map = json.loads((lifted_output / "reconstruction_map.json").read_text(encoding="utf-8"))
        instruction_coverage = reconstruction_map.get("instruction_coverage", [])
        if (reconstruction_map.get("statement_coverage_complete") is not True
                or reconstruction_map.get("covered_instructions") != 385
                or len(instruction_coverage) != 385
                or {item.get("disposition") for item in instruction_coverage} != {
                    "emitted_statement", "implicit_terminal_return", "protector_control_elided",
                    "runtime_value_decoder_elided", "runtime_value_producer",
                }):
            raise RuntimeError("statement coverage did not account for every payload instruction")
        root_steps = [step for step in closure.get("observed_steps", []) if step.get("activation") == 6509]
        writes = [write for step in root_steps for write in step.get("register_writes", [])]
        if not any(write.get("register") == 1 and write.get("value", {}).get("name") == "print" for write in writes):
            raise RuntimeError(f"payload function producer was not resolved: {writes}")
        if not any(write.get("register") == 2
                   and write.get("value", {}).get("value") == "anti tamper BYPASSED" for write in writes):
            raise RuntimeError(f"payload string producer was not resolved: {writes}")

    print("Luraph automatic trace pipeline OK: complete statement coverage reconstructed and compiled the payload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
