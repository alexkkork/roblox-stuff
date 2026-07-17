#!/usr/bin/env python3
"""Recover reachable Luraph prototype lanes through the bounded runtime."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-runtime-structure-") as temporary:
        root = pathlib.Path(temporary)
        static_output = root / "static"
        static_report = root / "static-report.json"
        static = subprocess.run([
            str(args.deobfuscator), str(SUBJECT),
            "--output-dir", str(static_output),
            "--mode", "reconstruct",
            "--report", str(static_report),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if static.returncode != 2:
            raise RuntimeError(f"bounded static analysis unexpectedly exited {static.returncode}:\n{static.stderr}")
        report = json.loads(static_report.read_text(encoding="utf-8"))
        handler_pass = next(item for item in report["passes"] if item["stage"] == "opcode_handlers")
        structure_pass = next(item for item in report["passes"] if item["stage"] == "structure_probe")
        exact_handlers = handler_pass.get("exact_handlers", 0)
        ambiguous_handlers = handler_pass.get("ambiguous_handlers", 0)
        missing_handlers = handler_pass.get("missing_handlers", 0)
        if (handler_pass["resolved_opcodes"] != exact_handlers
                or exact_handlers + ambiguous_handlers + missing_handlers != 256
                or exact_handlers < 200 or missing_handlers != 0
                or not structure_pass["ok"]):
            raise RuntimeError(f"static handler/probe recovery incomplete: {handler_pass} {structure_pass}")

        probe = static_output / "structure_probe.luau"
        probe_source = probe.read_text(encoding="utf-8")
        if any(marker in probe_source for marker in (
                "@@LPH_CALL_V2@@", "@@LPH_ACT_PROTO_V1@@", "@@LPH_STEP_V1@@")):
            raise RuntimeError("pure structure probe contains payload-window instrumentation")
        runtime_report = root / "runtime-report.json"
        run = subprocess.run([
            str(args.runtime),
            "--profile", "executor-client",
            "--execution-mode", "faithful",
            "--network-policy", "offline",
            "--clock", "virtual",
            "--timeout", "15",
            "--no-native-codegen",
            "--memory-limit-mb", "768",
            "--unsupported", "trace-nil",
            "--luraph-mode", "force",
            "--luraph-max-steps", "30000000",
            "--luraph-stall-steps", "0",
            "--report", str(runtime_report),
            str(probe),
        ], text=True, errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        if run.returncode != 0 or "anti tamper BYPASSED" not in run.stdout:
            raise RuntimeError(f"structure probe did not preserve payload execution:\n{run.stdout[-4000:]}")
        if run.stdout.count("@@LPH_PROTO_V1@@") != 29 or run.stdout.count("@@LPH_INSN_V1@@") != 8548:
            raise RuntimeError("structure probe did not recover the locked reachable prototype corpus")

        trace = root / "structure-trace.log"
        trace.write_text(run.stdout, encoding="utf-8")
        lifted_output = root / "lifted"
        lifted_report = root / "lifted-report.json"
        lifted = subprocess.run([
            str(args.deobfuscator), str(SUBJECT),
            "--output-dir", str(lifted_output),
            "--mode", "reconstruct",
            "--trace", str(trace),
            "--report", str(lifted_report),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        if lifted.returncode != 2:
            raise RuntimeError(f"structure-only trace must not claim source recovery: {lifted.returncode}")
        runtime_ir = json.loads((lifted_output / "runtime_prototypes.json").read_text(encoding="utf-8"))
        if (not runtime_ir["complete"] or runtime_ir["malformed_rows"] != 0
                or runtime_ir["prototype_count"] != 29 or runtime_ir["instruction_count"] != 8548
                or not all(prototype["complete"] for prototype in runtime_ir["prototypes"])):
            raise RuntimeError(f"runtime prototype IR failed validation: {runtime_ir}")
        lifted_data = json.loads(lifted_report.read_text(encoding="utf-8"))
        decode_pass = next(item for item in lifted_data["passes"] if item["stage"] == "runtime_decode")
        if not decode_pass["ok"] or lifted_data["artifacts"]["runtime_prototypes"] != "runtime_prototypes.json":
            raise RuntimeError(f"runtime decode was not reported truthfully: {decode_pass}")

    print("Luraph runtime structure pipeline OK: 29 prototypes and 8548 instructions validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
