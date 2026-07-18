#!/usr/bin/env python3
"""Exact evidence boundaries for Luraph capture opcodes 136 and 186."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
LUAUTH_BODY = ROOT / "tests" / "fixtures" / "luraph" / "subject_ea93959c47e6.luau"
OTHER_FAMILY = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"
LUAUTH_HEADER = (
    "la_code=1;la_script_id='capture-opcode-regression'\n"
    "--[[ LuaAuth launcher: https://luaauth.com ]]\n"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def read_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def encoded_lanes(**overrides: int) -> str:
    values: dict[str, str] = {
        "S": "n:0",
        "V": "n:0",
        "Z": "n:0",
        "g": "z:",
        "r": "n:0",
        "v": "z:",
    }
    values.update({name: f"n:{value}" for name, value in overrides.items()})
    return "|".join(f"{name}={value}" for name, value in values.items())


def guard_path(vm_count: int, pc: int, opcode: int) -> str:
    return f"@@LPH_GUARD_PATH_V1@@\t{vm_count}\t1\t{pc}\t{opcode}\t0\t0\t"


def step(
    vm_count: int,
    pc: int,
    opcode: int,
    lanes: str,
    writes: str,
    write_count: int,
    origins: str = "",
) -> str:
    return (
        f"@@LPH_STEP_V1@@\t{vm_count}\t1\t{pc}\t{opcode}\t{pc + 1}"
        f"\t{write_count}\t{writes}\t{lanes}\t{origins}"
    )


def build_trace() -> str:
    sites = (
        (1, 136, encoded_lanes(S=4, Z=9)),
        (2, 136, encoded_lanes(S=6, Z=10)),
        (3, 186, encoded_lanes(S=8, r=8, V=187)),
        (4, 186, encoded_lanes(S=10, r=10, V=188)),
        (5, 186, encoded_lanes(S=12, r=12, V=189)),
        (6, 186, encoded_lanes(S=14, r=14, V=190)),
        (7, 61, encoded_lanes(r=3)),
        (8, 161, encoded_lanes(S=20)),
        (9, 59, encoded_lanes(Z=56, r=11)),
        (10, 59, encoded_lanes(Z=56, r=11)),
    )
    return "\n".join(
        (
            "@@LPH_PROTO_V1@@\t1\t10\tS,V,Z,g,r,v",
            "@@LPH_PROTO_OBJECT_V1@@\t1\t1001",
            "@@LPH_PROTO_V1@@\t98\t0\tS,V,Z,g,r,v",
            "@@LPH_PROTO_OBJECT_V1@@\t98\t1098",
            *(f"@@LPH_INSN_V1@@\t1\t{pc}\t{opcode}\t{lanes}" for pc, opcode, lanes in sites),
            "@@LPH_ACT_PROTO_V1@@\t1\t1\tnil\tnil\tnil\t0\t1\t\t0",
            # The call frame is proven by child entry even though the parent did not return.
            "@@LPH_ACT_PROTO_V1@@\t2\t98\t1\t9\t59\t10\t1\t"
            + "|".join(["n:1"] * 10)
            + "\t10",
            # A child activation with the wrong arity must not validate the same handler candidate.
            "@@LPH_ACT_PROTO_V1@@\t3\t98\t1\t10\t59\t9\t1\t"
            + "|".join(["n:1"] * 9)
            + "\t11",
            # Enter opcode 61 but end capture before its yielding call completes.
            "@@LPH_VM@@\t9\t1\tnil\tnil\tnil\t7\t61",
            guard_path(1, 1, 136),
            step(1, 1, 136, sites[0][2], "4=s:6361707475726564", 1),
            # Missing guard-path evidence must reject an otherwise matching capture load.
            step(2, 2, 136, sites[1][2], "6=s:6361707475726564", 1),
            guard_path(3, 3, 186),
            step(3, 3, 186, sites[2][2], "8=f:|9=x:table", 2, "9=r:8"),
            guard_path(6, 3, 186),
            # A repeated visit may omit the unchanged preserved-table write.
            step(6, 3, 186, sites[2][2], "8=f:", 1),
            guard_path(4, 4, 186),
            # The preserved table claims the wrong register origin.
            step(4, 4, 186, sites[3][2], "10=f:|11=x:table", 2, "11=r:9"),
            guard_path(5, 5, 186),
            # The preserved S+1 value must remain a capture table, not another function.
            step(5, 5, 186, sites[4][2], "12=f:|13=f:", 2, "13=r:12"),
            guard_path(7, 6, 186),
            step(7, 6, 186, sites[5][2], "14=f:|15=x:table", 2, "15=r:14"),
            guard_path(8, 6, 186),
            # Sparse observations still reject writes outside S and S+1.
            step(8, 6, 186, sites[5][2], "16=f:", 1),
            guard_path(10, 8, 161),
            step(10, 8, 161, sites[7][2], "20=x:thread", 1),
            "",
        )
    )


def run_deobfuscator(
    deobfuscator: pathlib.Path,
    source: pathlib.Path,
    trace: pathlib.Path,
    root: pathlib.Path,
) -> tuple[subprocess.CompletedProcess[str], pathlib.Path, dict]:
    output = root / "output"
    report_path = root / "report.json"
    completed = subprocess.run(
        (
            str(deobfuscator),
            str(source),
            "--output-dir",
            str(output),
            "--mode",
            "reconstruct",
            "--trace",
            str(trace),
            "--report",
            str(report_path),
        ),
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=45,
    )
    require(
        report_path.is_file(),
        f"deobfuscator omitted its report (exit={completed.returncode}): {completed.stderr[-2000:]}",
    )
    return completed, output, read_json(report_path)


def instruction_rows(output: pathlib.Path) -> dict[int, dict]:
    semantic = read_json(output / "runtime_semantic_ir.json")
    rows = {
        int(row["pc"]): row
        for prototype in semantic.get("prototypes") or []
        if prototype.get("runtime_id") == 1
        for row in prototype.get("instructions") or []
    }
    require(
        set(rows) == {1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
        f"synthetic instruction rows drifted: {sorted(rows)}",
    )
    return rows


def assert_runtime_validated(
    row: dict, recognition_key: str, expected_observations: int = 1
) -> dict:
    recognition = row.get(recognition_key)
    require(
        recognition
        == {"status": "runtime_validated", "validated_observations": expected_observations},
        f"exact recognizer status drifted: {recognition}",
    )
    operation = row.get("observational_semantic_operation")
    require(isinstance(operation, dict), f"exact recognizer emitted no operation: {row}")
    require(operation.get("path_specific") is True, f"operation lost path specificity: {operation}")
    require(operation.get("static_semantic") is False, f"operation became static semantics: {operation}")
    require(operation.get("source_claim") is False, f"operation made a source claim: {operation}")
    require(
        row.get("semantic_coverage_class") == "runtime_validated_observational_semantic",
        f"validated operation has the wrong coverage class: {row}",
    )
    return operation


def assert_evidence_mismatch(row: dict, recognition_key: str, label: str) -> None:
    require(
        row.get(recognition_key) == {"status": "evidence_mismatch", "validated_observations": 0},
        f"{label} did not fail closed: {row.get(recognition_key)}",
    )
    require(
        row.get("observational_semantic_operation") is None,
        f"{label} was incorrectly promoted: {row}",
    )
    require(
        row.get("semantic_coverage_class") == "trace_evidence_only",
        f"{label} did not remain trace-only: {row}",
    )
    require(
        isinstance(row.get("trace_specialized_operation"), dict),
        f"{label} lost its non-semantic trace evidence: {row}",
    )


def audit_exact_capture_semantics(output: pathlib.Path, report: dict) -> None:
    rows = instruction_rows(output)

    capture_load = assert_runtime_validated(rows[1], "opcode136_capture_load_recognition")
    require(capture_load.get("kind") == "register_write", f"opcode 136 shape drifted: {capture_load}")
    require(capture_load.get("semantic_family") == "capture_load", f"opcode 136 family drifted: {capture_load}")
    require(
        capture_load.get("proof") == "locked_opcode136_capture_load_and_runtime_write_validated",
        f"opcode 136 proof drifted: {capture_load}",
    )
    require(
        capture_load.get("register") == {"kind": "constant", "value": 4},
        f"opcode 136 destination drifted: {capture_load}",
    )
    require(
        capture_load.get("value")
        == {
            "kind": "index_read",
            "table": {"kind": "upvalue_file"},
            "index": {"kind": "constant", "value": 9},
        },
        f"opcode 136 capture index was not preserved: {capture_load}",
    )
    assert_evidence_mismatch(
        rows[2], "opcode136_capture_load_recognition", "opcode 136 incomplete guard path"
    )

    lookup = assert_runtime_validated(rows[3], "opcode186_lookup_preserve_recognition", 2)
    require(lookup.get("kind") == "operation_sequence", f"opcode 186 shape drifted: {lookup}")
    require(lookup.get("semantic_family") == "lookup_and_preserve", f"opcode 186 family drifted: {lookup}")
    require(
        lookup.get("proof")
        == "locked_opcode186_lookup_preserve_branch_and_runtime_origins_validated",
        f"opcode 186 proof drifted: {lookup}",
    )
    operations = lookup.get("operations") or []
    require(len(operations) == 2, f"opcode 186 did not preserve both writes: {operations}")
    require(
        operations[0]
        == {
            "kind": "register_write",
            "register": {"kind": "constant", "value": 9},
            "value": {"kind": "register_read", "index": {"kind": "constant", "value": 8}},
        },
        f"opcode 186 did not preserve the source table before lookup: {operations}",
    )
    require(
        operations[1]
        == {
            "kind": "register_write",
            "register": {"kind": "constant", "value": 8},
            "value": {
                "kind": "index_read",
                "table": {"kind": "register_read", "index": {"kind": "constant", "value": 9}},
                "index": {"kind": "constant", "value": 187},
            },
        },
        f"opcode 186 lookup order or index drifted: {operations}",
    )
    assert_evidence_mismatch(
        rows[4], "opcode186_lookup_preserve_recognition", "opcode 186 wrong write origin"
    )
    assert_evidence_mismatch(
        rows[5], "opcode186_lookup_preserve_recognition", "opcode 186 non-table preservation"
    )
    assert_evidence_mismatch(
        rows[6], "opcode186_lookup_preserve_recognition", "opcode 186 contradictory sparse write"
    )

    discard_call = rows[7].get("semantic_operation")
    require(
        rows[7].get("opcode61_one_argument_discard_call_recognition")
        == {"status": "static_validated", "validated_observations": 0},
        f"opcode 61 exact handler was not statically recognized: {rows[7]}",
    )
    require(
        isinstance(discard_call, dict)
        and discard_call.get("semantic_family") == "call"
        and discard_call.get("static_semantic") is True
        and discard_call.get("path_specific") is False
        and discard_call.get("source_claim") is False,
        f"opcode 61 source boundary drifted: {discard_call}",
    )
    require(
        discard_call.get("proof")
        == "locked_opcode61_body_and_vm_state_independence_validated",
        f"opcode 61 proof drifted: {discard_call}",
    )
    require(
        discard_call.get("operations")
        == [
            {
                "kind": "call",
                "method": False,
                "function": {"kind": "register_read", "index": {"kind": "constant", "value": 3}},
                "arguments": [
                    {"kind": "register_read", "index": {"kind": "constant", "value": 4}}
                ],
            },
            {"kind": "set_top", "value": {"kind": "constant", "value": 2}},
        ],
        f"opcode 61 call layout drifted: {discard_call}",
    )

    two_argument_call = assert_runtime_validated(
        rows[8], "opcode161_two_argument_call_recognition"
    )
    require(
        two_argument_call.get("proof")
        == "locked_opcode161_two_argument_call_body_and_runtime_result_validated",
        f"opcode 161 proof drifted: {two_argument_call}",
    )
    require(
        two_argument_call.get("operations")
        == [
            {
                "kind": "register_write",
                "register": {"kind": "constant", "value": 20},
                "value": {
                    "kind": "call",
                    "method": False,
                    "function": {
                        "kind": "register_read",
                        "index": {"kind": "constant", "value": 20},
                    },
                    "arguments": [
                        {
                            "kind": "register_read",
                            "index": {"kind": "constant", "value": 21},
                        },
                        {
                            "kind": "register_read",
                            "index": {"kind": "constant", "value": 22},
                        },
                    ],
                },
            },
            {"kind": "set_top", "value": {"kind": "constant", "value": 20}},
        ],
        f"opcode 161 call layout drifted: {two_argument_call}",
    )

    entered_call = rows[9].get("observational_semantic_operation")
    require(
        isinstance(entered_call, dict)
        and entered_call.get("kind") == "operation_sequence"
        and entered_call.get("proof") == "runtime_validated_incomplete_call_handler_candidate",
        f"entered child call was not promoted from the exact handler: {rows[9]}",
    )
    validation = entered_call.get("runtime_validation") or {}
    require(
        validation.get("proof") == "observed_child_call_entry_without_parent_return"
        and validation.get("parent_return_observed") is False
        and validation.get("callee_prototype") == 98
        and validation.get("argument_count") == 10
        and validation.get("function_register") == 56
        and validation.get("argument_register_range") == {"from": 57, "to": 66}
        and validation.get("result_register") is None,
        f"entered child call proof overclaimed or lost its frame: {validation}",
    )
    require(
        validation.get("validated_fields")
        == ["callee_prototype", "argument_count", "function_register", "argument_register_range"],
        f"entered child call claimed unobserved parent effects: {validation}",
    )

    wrong_arity = rows[10]
    require(
        wrong_arity.get("incomplete_call_candidate_validated") is not True
        and not isinstance(wrong_arity.get("guarded_candidate_validation"), dict),
        f"wrong-arity child call incorrectly validated the handler: {wrong_arity}",
    )
    weak_call = wrong_arity.get("observational_semantic_operation") or {}
    require(
        weak_call.get("kind") == "call" and "function" not in weak_call,
        f"wrong-arity child call was not kept as evidence-only call telemetry: {weak_call}",
    )

    partition = (report.get("coverage") or {}).get("semantic_coverage_partition") or {}
    require(
        partition.get("runtime_validated_observational_semantic") == 5
        and partition.get("trace_evidence_only") == 4
        and partition.get("static_semantic") == 1
        and partition.get("total") == 10,
        f"capture opcode coverage partition drifted: {partition}",
    )


def audit_locked_handler_ranges(output: pathlib.Path) -> None:
    rows = instruction_rows(output)
    for pc, opcode, key, family, proof in (
        (
            1,
            136,
            "opcode136_capture_load_recognition",
            "capture_load",
            "locked_opcode136_capture_load_and_runtime_write_validated",
        ),
        (
            3,
            186,
            "opcode186_lookup_preserve_recognition",
            "lookup_and_preserve",
            "locked_opcode186_lookup_preserve_branch_and_runtime_origins_validated",
        ),
        (
            7,
            61,
            "opcode61_one_argument_discard_call_recognition",
            "call",
            "locked_opcode61_body_and_vm_state_independence_validated",
        ),
        (
            8,
            161,
            "opcode161_two_argument_call_recognition",
            "call",
            "locked_opcode161_two_argument_call_body_and_runtime_result_validated",
        ),
    ):
        handler_range = rows[pc].get("handler_range") or {}
        locked_range = {
            136: (326066, 326084),
            186: (307936, 323136),
            61: (351789, 351819),
            161: (307936, 323136),
        }[opcode]
        require(
            (handler_range.get("begin"), handler_range.get("end")) != locked_range,
            f"alternate family unexpectedly reused the locked opcode-{opcode} handler range",
        )
        require(
            rows[pc].get(key) == {"status": "evidence_mismatch", "validated_observations": 0},
            f"opcode {opcode} wrong handler range did not reject exact recognition: {rows[pc].get(key)}",
        )
        operation = rows[pc].get("observational_semantic_operation")
        if isinstance(operation, dict):
            require(
                operation.get("semantic_family") != family and operation.get("proof") != proof,
                f"opcode {opcode} wrong handler range escaped as exact semantics: {operation}",
            )
            require(
                operation.get("static_semantic") is False and operation.get("source_claim") is False,
                f"opcode {opcode} fallback telemetry crossed the source boundary: {operation}",
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    args = parser.parse_args()
    deobfuscator = args.deobfuscator.resolve()

    with tempfile.TemporaryDirectory(prefix="luraph-capture-opcodes-") as temporary:
        root = pathlib.Path(temporary)
        source = root / "luaauth-subject.luau"
        source.write_text(LUAUTH_HEADER + LUAUTH_BODY.read_text(encoding="utf-8"), encoding="utf-8")
        trace = root / "capture-opcodes.log"
        trace.write_text(build_trace(), encoding="utf-8")

        completed, output, report = run_deobfuscator(deobfuscator, source, trace, root / "exact")
        require(completed.returncode == 2, f"partial exact-family trace exited {completed.returncode}")
        audit_exact_capture_semantics(output, report)

        completed, output, _ = run_deobfuscator(deobfuscator, OTHER_FAMILY, trace, root / "wrong-range")
        require(completed.returncode == 2, f"wrong-range trace exited {completed.returncode}")
        audit_locked_handler_ranges(output)

    print("Luraph capture opcode 136/186 regression OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
