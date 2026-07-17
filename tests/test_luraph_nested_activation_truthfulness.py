#!/usr/bin/env python3
"""Nested Luraph payload prototypes must prevent output-replay source claims."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"
PAYLOAD_TEXT = "anti tamper BYPASSED"


def combined_trace() -> str:
    encoded_payload = PAYLOAD_TEXT.encode("utf-8").hex()
    return "\n".join((
        "@@LPH_PROTO_V1@@\t27\t1\tQ,t,u",
        "@@LPH_PROTO_V1@@\t28\t1\tQ,t,u",
        "@@LPH_PROTO_V1@@\t29\t1\tQ,t,u",
        "@@LPH_INSN_V1@@\t27\t1\t80\tQ=n:1|t=z:|u=z:",
        "@@LPH_INSN_V1@@\t28\t1\t87\tQ=n:2|t=n:1|u=n:2",
        "@@LPH_INSN_V1@@\t29\t1\t31\tQ=z:|t=z:|u=z:",
        "@@LPH_ACT_PROTO_V1@@\t6509\t27\t2\t77\t6\t0",
        "@@LPH_ACT_PROTO_V1@@\t6510\t28\t6509\t5\t87\t2",
        "@@LPH_ACT_PROTO_V1@@\t6511\t29\t6510\t26\t80\t1",
        "@@LPH_ACTIVATION@@\t422200\t6509\t2\t77\t6\t0\t",
        f"@@LPH_CALL_V2@@\t422262\t6509\t2\t77\t6\t7\t80\t1\tprint\t1\ts:{encoded_payload}\tQ",
        PAYLOAD_TEXT,
        "@@LPH_VM@@\t422263\t6509\t2\t77\t6\t8\t31",
        "",
    ))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-nested-truth-") as temporary:
        root = pathlib.Path(temporary)
        trace = root / "combined-trace.log"
        output = root / "output"
        report_path = root / "report.json"
        trace.write_text(combined_trace(), encoding="utf-8")

        completed = subprocess.run(
            [
                str(args.deobfuscator), str(SUBJECT),
                "--output-dir", str(output),
                "--mode", "reconstruct",
                "--trace", str(trace),
                "--report", str(report_path),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        require(report_path.is_file(),
                f"deobfuscator omitted its report (exit={completed.returncode}): {completed.stderr}")
        report = json.loads(report_path.read_text(encoding="utf-8"))

        runtime_decode = next(item for item in report.get("passes", [])
                              if item.get("stage") == "runtime_decode")
        trace_pass = next(item for item in report.get("passes", [])
                          if item.get("stage") == "trace")
        require(runtime_decode.get("complete") is True
                and runtime_decode.get("prototypes") == 3,
                f"nested runtime structure evidence was not accepted: {runtime_decode}")
        require(trace_pass.get("payload_calls") == 1
                and trace_pass.get("payload_activation_complete") is True,
                f"the confirmed print/activation premise was not exercised: {trace_pass}")

        prototypes_path = output / "runtime_prototypes.json"
        require(prototypes_path.is_file(), "runtime prototype evidence was not retained")
        prototypes = json.loads(prototypes_path.read_text(encoding="utf-8"))
        activations = {item["activation"]: item for item in prototypes.get("activations", [])}
        require(activations[6510]["caller_activation"] == 6509
                and activations[6511]["caller_activation"] == 6510,
                f"nested activation ancestry was not preserved: {activations}")

        require(completed.returncode == 2,
                f"nested unlifted prototypes were falsely reported as recovered (exit={completed.returncode})")
        require(report.get("status") == "blocked",
                f"nested unlifted prototypes produced status {report.get('status')!r}")
        require(report.get("exact_source") is False,
                "nested activation evidence was falsely claimed as exact source")
        require(report.get("artifacts", {}).get("source") is None,
                f"report exposed a source artifact: {report.get('artifacts')}")
        require(not (output / "reconstructed.luau").exists(),
                "a confirmed print was replayed as reconstructed source despite nested payload prototypes")
        require(report.get("verification", {}).get("compiled") is False,
                f"withheld source was falsely reported as compiled: {report.get('verification')}")

    print("Luraph nested activation truthfulness OK: confirmed output did not replace unlifted payload logic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
