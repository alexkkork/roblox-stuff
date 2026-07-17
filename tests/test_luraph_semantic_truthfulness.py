#!/usr/bin/env python3
"""Truthfulness boundaries for Luraph opcode and payload evidence."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"
SOURCE_CANDIDATES = (
    "reconstructed.luau",
    "source_exact.luau",
    "payload_candidate.luau",
    "semantic_state_machine_candidate.luau",
    "semantic_readable_candidate.luau",
)


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


def handler_partition(report: dict, output: pathlib.Path) -> tuple[dict, list[dict]]:
    handler_pass = next(
        (row for row in report.get("passes") or [] if row.get("stage") == "opcode_handlers"),
        None,
    )
    require(handler_pass is not None, "opcode handler pass is missing")
    artifact = read_json(output / "opcode_handlers.json")
    handlers = artifact.get("handlers") or []
    require(len(handlers) == 256, f"handler catalog has {len(handlers)} rows instead of 256")
    require(
        {row.get("opcode") for row in handlers} == set(range(256)),
        "handler catalog does not contain each opcode exactly once",
    )

    statuses = Counter(row.get("selection_status") for row in handlers)
    require(
        not (set(statuses) - {"exact", "ambiguous", "missing"}),
        f"handler catalog contains unknown evidence tiers: {statuses}",
    )
    expected = {
        "exact": statuses["exact"],
        "ambiguous": statuses["ambiguous"],
        "missing": statuses["missing"],
    }
    reported = {
        "exact": handler_pass.get("exact_handlers"),
        "ambiguous": handler_pass.get("ambiguous_handlers"),
        "missing": handler_pass.get("missing_handlers"),
    }
    require(reported == expected, f"report collapsed handler evidence tiers: {reported} != {expected}")
    require(
        artifact.get("exact_handlers") == expected["exact"]
        and artifact.get("ambiguous_handlers") == expected["ambiguous"]
        and artifact.get("missing_handlers") == expected["missing"],
        "opcode artifact totals disagree with its handler rows",
    )
    require(
        handler_pass.get("resolved_opcodes") == expected["exact"]
        and artifact.get("resolved_opcodes") == expected["exact"],
        "resolved_opcodes includes ambiguous or missing handlers",
    )
    require(sum(expected.values()) == 256, f"handler evidence partition is incomplete: {expected}")
    require(
        artifact.get("leaf_selection_complete") is (expected["exact"] == 256),
        "leaf_selection_complete does not describe exact static selection",
    )
    return artifact, handlers


def audit_handler_partition(deobfuscator: pathlib.Path) -> None:
    with tempfile.TemporaryDirectory(prefix="luraph-handler-truth-") as temporary:
        completed, output, report = run_deobfuscator(deobfuscator, pathlib.Path(temporary))
        require(completed.returncode == 2, f"incomplete static recovery exited {completed.returncode}")
        _, handlers = handler_partition(report, output)

        ambiguous = [row for row in handlers if row.get("selection_status") == "ambiguous"]
        require(ambiguous, "locked fixture no longer exercises ambiguous handler selection")
        promoted = [row.get("opcode") for row in ambiguous if row.get("semantic_operation") is not None]
        require(
            not promoted,
            "guarded handler candidates were promoted to static semantics for opcodes "
            + ", ".join(map(str, promoted)),
        )
        path_promoted = [
            row.get("opcode") for row in handlers
            if row.get("semantic_operation") is not None
        ]
        require(
            not path_promoted,
            "branch-path results were promoted to general semantics for opcodes "
            + ", ".join(map(str, path_promoted)),
        )
        for row in ambiguous:
            require(row.get("unresolved_guard_path") is True,
                    f"ambiguous opcode {row.get('opcode')} lost its guard-path label")
        for row in (item for item in handlers if item.get("selection_status") == "missing"):
            require(row.get("semantic_operation") is None,
                    f"missing opcode {row.get('opcode')} carries static semantics")
            require(row.get("candidate_semantic_operation") is None,
                    f"missing opcode {row.get('opcode')} carries a candidate operation")

        continuation = handlers[186]
        require(continuation.get("executed_path_complete") is True,
                "opcode 186 no longer has a complete executed-statement path")
        require(continuation.get("executed_statement_count") == 2,
                "opcode 186 did not retain both executed writes")
        require(continuation.get("dispatcher_statement_count") == 1
                and continuation.get("continuation_statement_count") == 1,
                "opcode 186 did not distinguish its enclosing continuation")
        effects = continuation.get("effects") or {}
        require(effects.get("register_writes") == 1 and effects.get("pc_writes") == 1,
                f"opcode 186 effects dropped a write: {effects}")
        require(continuation.get("semantic_operation") is None,
                "opcode 186 path result was promoted to general semantics")
        operation = continuation.get("candidate_semantic_operation")
        require(isinstance(operation, dict) and operation.get("kind") == "operation_sequence",
                "opcode 186 candidate was collapsed back to a one-write operation")
        operations = operation.get("operations") or []
        require([item.get("kind") for item in operations] == ["register_write", "compound_write"],
                f"opcode 186 operation order is incomplete: {operations}")
        require((operations[1].get("target") or {}).get("kind") == "program_counter",
                "opcode 186 continuation is not represented as a PC write")
        require(continuation.get("full_effect_normalization") is True,
                "opcode 186 complete sequence did not normalize as a whole")
        require(continuation.get("full_effect_validation") is False
                and operation.get("candidate_only") is True
                and operation.get("static_semantic") is False,
                "opcode 186 path evidence crossed the static semantic boundary")


def build_guarded_trace(opcode: int, lanes: list[str]) -> str:
    encoded_lanes = "|".join(f"{lane}=n:0" for lane in lanes)
    return "\n".join((
        f"@@LPH_PROTO_V1@@\t1\t1\t{','.join(lanes)}",
        "@@LPH_PROTO_OBJECT_V1@@\t1\t1001",
        "@@LPH_ACT_PROTO_V1@@\t1\t1\tnil\tnil\tnil\t0\t1\t\t0",
        f"@@LPH_INSN_V1@@\t1\t1\t{opcode}\t{encoded_lanes}",
        f"@@LPH_STEP_V1@@\t1\t1\t1\t{opcode}\t2\t0\t\t{encoded_lanes}",
        "@@LPH_RETURN_V1@@\t2\t1\t1\t1\t0\t0\t",
        "",
    ))


def build_semantic_partition_trace(
    static_opcode: int,
    observational_opcode: int,
    lanes: list[str],
) -> str:
    encoded_lanes = "|".join(f"{lane}=n:0" for lane in lanes)
    instructions = (
        (1, static_opcode),
        (2, observational_opcode),
        (3, observational_opcode),
        (4, observational_opcode),
    )
    return "\n".join((
        f"@@LPH_PROTO_V1@@\t1\t4\t{','.join(lanes)}",
        "@@LPH_PROTO_OBJECT_V1@@\t1\t1001",
        "@@LPH_ACT_PROTO_V1@@\t1\t1\tnil\tnil\tnil\t0\t1\t\t0",
        *(f"@@LPH_INSN_V1@@\t1\t{pc}\t{opcode}\t{encoded_lanes}" for pc, opcode in instructions),
        f"@@LPH_STEP_V1@@\t1\t1\t2\t{observational_opcode}\t3\t0\t\t{encoded_lanes}",
        f"@@LPH_RETURN_V1@@\t2\t1\t2\t{observational_opcode}\t0\t0\t",
        f"@@LPH_STEP_V1@@\t3\t1\t3\t{observational_opcode}\t4\t0\t\t{encoded_lanes}",
        "",
    ))


def semantic_coverage_partition(report: dict) -> dict:
    partition = (report.get("coverage") or {}).get("semantic_coverage_partition")
    require(isinstance(partition, dict), "semantic coverage partition is missing")
    require(partition.get("available") is True, f"semantic coverage partition is unavailable: {partition}")
    categories = (
        "static_semantic",
        "runtime_validated_observational_semantic",
        "trace_evidence_only",
        "unresolved",
    )
    counts = {category: partition.get(category) for category in categories}
    require(
        all(isinstance(value, int) and value >= 0 for value in counts.values()),
        f"semantic coverage categories are not non-negative integer counts: {counts}",
    )
    require(
        sum(counts.values()) == partition.get("total") == partition.get("partition_sum"),
        f"semantic coverage categories are not a disjoint total: {partition}",
    )
    require(partition.get("disjoint") is True, "semantic coverage partition lost its disjoint contract")
    require(partition.get("partition_complete") is True, "semantic coverage partition is marked incomplete")
    require(
        partition.get("runtime_validated_observational_semantic_is_path_specific") is True,
        "runtime-validated observational semantics lost their path-specific qualification",
    )
    require(
        partition.get("trace_evidence_only_is_semantic") is False,
        "trace-only evidence was mislabeled as semantic coverage",
    )
    return partition


def audit_guarded_runtime_candidate(deobfuscator: pathlib.Path) -> None:
    with tempfile.TemporaryDirectory(prefix="luraph-guarded-runtime-truth-") as temporary:
        root = pathlib.Path(temporary)
        static_root = root / "static"
        _, static_output, static_report = run_deobfuscator(deobfuscator, static_root)
        artifact, handlers = handler_partition(static_report, static_output)
        candidate = next(
            (
                row for row in handlers
                if row.get("selection_status") == "ambiguous"
                and row.get("vm_state_independent") is True
                and isinstance(row.get("candidate_semantic_operation"), dict)
                and row.get("semantic_operation") is None
            ),
            None,
        )
        require(candidate is not None, "locked fixture has no guarded runtime candidate")

        trace = root / "guarded-trace.log"
        lanes = [str(lane) for lane in artifact.get("operand_lane_locals") or []]
        require(lanes, "opcode catalog omitted operand lane names")
        trace.write_text(build_guarded_trace(int(candidate["opcode"]), lanes), encoding="utf-8")
        completed, output, report = run_deobfuscator(deobfuscator, root / "traced", trace=trace)
        require(completed.returncode == 2, f"guarded trace crossed the recovery boundary: {completed.returncode}")

        semantic = read_json(output / "runtime_semantic_ir.json")
        instructions = [
            instruction
            for prototype in semantic.get("prototypes") or []
            for instruction in prototype.get("instructions") or []
        ]
        require(len(instructions) == 1, f"guarded trace produced {len(instructions)} semantic rows")
        instruction = instructions[0]
        require(instruction.get("opcode") == candidate["opcode"], "runtime opcode evidence drifted")
        require(
            instruction.get("semantic_operation") is None,
            "an ambiguous guarded candidate became a static semantic operation",
        )
        observational = instruction.get("observational_semantic_operation")
        if isinstance(observational, dict):
            require(observational.get("static_semantic") is False,
                    "observational candidate lost static_semantic=false")
            require(observational.get("path_specific") is True,
                    "observational candidate lost path_specific=true")
            require(observational.get("proof") != "runtime_validated_ambiguous_handler_candidate",
                    "an incomplete ambiguous path was accepted by partial effect validation")
        require(instruction.get("candidate_rejection_reason") == "incomplete_executed_statement_path",
                "incomplete ambiguous path was not preserved as rejected evidence")
        require(semantic.get("semantic_lifted_instructions") == 0,
                "ambiguous runtime evidence increased the static semantic count")

        semantic_pass = next(
            row for row in report.get("passes") or [] if row.get("stage") == "semantic_classify"
        )
        require(semantic_pass.get("semantic_lifted_instructions") == 0,
                "report counted guarded runtime evidence as static semantics")

        partition = semantic_coverage_partition(report)
        require(
            partition.get("static_semantic") == 0
            and partition.get("runtime_validated_observational_semantic") == 1
            and partition.get("trace_evidence_only") == 0
            and partition.get("unresolved") == 0,
            f"guarded runtime evidence was assigned to the wrong semantic class: {partition}",
        )

        exact_path = next(
            (
                row for row in handlers
                if row.get("selection_status") == "exact"
                and row.get("semantic_operation") is None
                and isinstance(row.get("candidate_semantic_operation"), dict)
            ),
            None,
        )
        require(exact_path is not None, "locked fixture has no exact path candidate")
        partition_trace = root / "semantic-partition-trace.log"
        partition_trace.write_text(
            build_semantic_partition_trace(int(exact_path["opcode"]), int(candidate["opcode"]), lanes),
            encoding="utf-8",
        )
        completed, output, report = run_deobfuscator(
            deobfuscator, root / "partitioned", trace=partition_trace
        )
        require(completed.returncode == 2, f"partition trace crossed the recovery boundary: {completed.returncode}")
        partition = semantic_coverage_partition(report)
        expected = {
            "static_semantic": 0,
            "runtime_validated_observational_semantic": 1,
            "trace_evidence_only": 1,
            "unresolved": 2,
        }
        require(
            {name: partition.get(name) for name in expected} == expected,
            f"semantic coverage partition double-counted or omitted a site: {partition}",
        )
        require(
            partition.get("total") == partition.get("declared_total") == partition.get("materialized_total") == 4,
            f"semantic coverage total does not match its independent instruction universe: {partition}",
        )

        semantic = read_json(output / "runtime_semantic_ir.json")
        require(
            semantic.get("semantic_coverage_partition") == partition,
            "runtime semantic IR and report expose different semantic partitions",
        )
        instructions = [
            instruction
            for prototype in semantic.get("prototypes") or []
            for instruction in prototype.get("instructions") or []
        ]
        classes = Counter(row.get("semantic_coverage_class") for row in instructions)
        require(classes == Counter(expected), f"instruction classes disagree with report totals: {classes}")
        overlapping = next(row for row in instructions if row.get("pc") == 2)
        require(
            isinstance(overlapping.get("observational_semantic_operation"), dict)
            and isinstance(overlapping.get("trace_specialized_operation"), dict),
            "partition fixture no longer carries overlapping observational and trace telemetry",
        )
        require(
            overlapping.get("semantic_coverage_class") == "runtime_validated_observational_semantic",
            "overlapping telemetry was counted in more than its strongest semantic class",
        )


def audit_incomplete_payload_root(deobfuscator: pathlib.Path) -> None:
    with tempfile.TemporaryDirectory(prefix="luraph-payload-root-truth-") as temporary:
        completed, output, report = run_deobfuscator(deobfuscator, pathlib.Path(temporary))
        require(completed.returncode == 2, f"incomplete payload-root evidence exited {completed.returncode}")
        require(report.get("status") == "blocked", "incomplete payload-root evidence was not blocked")
        require(report.get("exact_source") is False, "incomplete payload-root evidence claimed exact source")
        require((report.get("coverage") or {}).get("payload_root") == {"available": False},
                "missing payload-root evidence was not reported explicitly")
        require((report.get("artifacts") or {}).get("source") is None,
                "report exposed a source artifact without a payload root")
        require((report.get("verification") or {}).get("source_claim_accepted") is False,
                "source claim was accepted without a payload root")
        for name in SOURCE_CANDIDATES:
            require(not (output / name).exists(), f"unproven source artifact was emitted: {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    parser.add_argument("--case", choices=("handlers", "runtime", "payload-root"), required=True)
    args = parser.parse_args()
    deobfuscator = args.deobfuscator.resolve()

    if args.case == "handlers":
        audit_handler_partition(deobfuscator)
    elif args.case == "runtime":
        audit_guarded_runtime_candidate(deobfuscator)
    else:
        audit_incomplete_payload_root(deobfuscator)
    print(f"Luraph semantic truthfulness OK: {args.case}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
