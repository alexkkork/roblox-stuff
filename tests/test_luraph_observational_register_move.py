#!/usr/bin/env python3
"""Regression coverage for path-specific observational register moves."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"
SPECIALIZED_OPCODES = {8, 28, 89, 161, 193}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def read_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_deobfuscator(
    deobfuscator: pathlib.Path,
    root: pathlib.Path,
    *,
    trace: pathlib.Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], pathlib.Path, dict]:
    output = root / "output"
    report_path = root / "report.json"
    command = [
        str(deobfuscator),
        str(SUBJECT),
        "--output-dir",
        str(output),
        "--mode",
        "reconstruct",
        "--report",
        str(report_path),
    ]
    if trace is not None:
        command.extend(("--trace", str(trace)))
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    require(
        report_path.is_file(),
        f"deobfuscator omitted its report (exit={completed.returncode}): {completed.stderr[-2000:]}",
    )
    return completed, output, read_json(report_path)


def select_trace_only_opcodes(output: pathlib.Path) -> list[int]:
    handlers = read_json(output / "opcode_handlers.json").get("handlers") or []
    opcodes = [
        int(row["opcode"])
        for row in handlers
        if row.get("opcode") not in SPECIALIZED_OPCODES
        and row.get("semantic_operation") is None
        and row.get("selection_status") == "ambiguous"
        and row.get("vm_state_independent") is False
    ]
    require(len(opcodes) >= 3, "locked fixture has fewer than three unpromotable handler opcodes")
    return opcodes[:3]


def guard_path(vm_count: int, pc: int, opcode: int) -> str:
    return f"@@LPH_GUARD_PATH_V1@@\t{vm_count}\t1\t{pc}\t{opcode}\t0\t0\t"


def step(
    vm_count: int,
    pc: int,
    opcode: int,
    next_pc: int,
    destination: int,
    origins: str,
) -> str:
    return (
        f"@@LPH_STEP_V1@@\t{vm_count}\t1\t{pc}\t{opcode}\t{next_pc}"
        f"\t1\t{destination}=n:42\tR=n:2|D=n:{destination}\t{destination}={origins}"
    )


def build_trace(opcodes: list[int]) -> str:
    positive, ambiguous, non_fallthrough = opcodes
    return "\n".join(
        (
            "@@LPH_PROTO_V1@@\t1\t3\tR,D",
            "@@LPH_PROTO_OBJECT_V1@@\t1\t1001",
            f"@@LPH_INSN_V1@@\t1\t1\t{positive}\tR=n:2|D=n:6",
            f"@@LPH_INSN_V1@@\t1\t2\t{ambiguous}\tR=n:2|D=n:8",
            f"@@LPH_INSN_V1@@\t1\t3\t{non_fallthrough}\tR=n:2|D=n:9",
            "@@LPH_ACT_PROTO_V1@@\t1\t1\tnil\tnil\tnil\t2\t1\tn:11|n:42\t0",
            guard_path(1, 1, positive),
            step(1, 1, positive, 2, 6, "a:2,r:2"),
            guard_path(2, 2, ambiguous),
            step(2, 2, ambiguous, 3, 8, "r:2,r:3"),
            guard_path(3, 3, non_fallthrough),
            step(3, 3, non_fallthrough, 1, 9, "a:2,r:2"),
            "",
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    args = parser.parse_args()
    deobfuscator = args.deobfuscator.resolve()

    with tempfile.TemporaryDirectory(prefix="luraph-observational-move-") as temporary:
        root = pathlib.Path(temporary)
        static_completed, static_output, _ = run_deobfuscator(deobfuscator, root / "static")
        require(static_completed.returncode == 2, f"static analysis exited {static_completed.returncode}")
        opcodes = select_trace_only_opcodes(static_output)

        trace = root / "trace.log"
        trace.write_text(build_trace(opcodes), encoding="utf-8")
        completed, output, _ = run_deobfuscator(deobfuscator, root / "traced", trace=trace)
        require(completed.returncode == 2, f"trace analysis exited {completed.returncode}: {completed.stderr}")

        semantic = read_json(output / "runtime_semantic_ir.json")
        rows = {
            int(row["pc"]): row
            for prototype in semantic.get("prototypes") or []
            if prototype.get("runtime_id") == 1
            for row in prototype.get("instructions") or []
        }
        require(set(rows) == {1, 2, 3}, f"synthetic instruction rows drifted: {sorted(rows)}")

        operation = rows[1].get("observational_semantic_operation")
        require(isinstance(operation, dict), "proven observational register move was not emitted")
        require(operation.get("kind") == "register_write", f"unexpected operation: {operation}")
        require(
            operation.get("register") == {"kind": "constant", "value": 6},
            f"destination register was not preserved: {operation}",
        )
        require(
            operation.get("value")
            == {"kind": "register_read", "index": {"kind": "constant", "value": 2}},
            f"source register was not preserved: {operation}",
        )
        require(
            operation.get("proof") == "complete_observation_set_and_unique_register_origin",
            f"observational move proof drifted: {operation}",
        )
        require(
            rows[1].get("semantic_coverage_class")
            == "runtime_validated_observational_semantic",
            f"proven move has the wrong coverage class: {rows[1]}",
        )

        for pc, reason in ((2, "ambiguous register origins"), (3, "non-fallthrough edge")):
            require(
                rows[pc].get("observational_semantic_operation") is None,
                f"{reason} was incorrectly promoted: {rows[pc]}",
            )
            require(
                rows[pc].get("semantic_coverage_class") == "trace_evidence_only",
                f"{reason} did not remain trace-only: {rows[pc]}",
            )
            require(
                isinstance(rows[pc].get("trace_specialized_operation"), dict),
                f"{reason} lost its trace evidence: {rows[pc]}",
            )

    print("Luraph observational register move regression OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
