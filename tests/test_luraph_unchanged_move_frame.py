#!/usr/bin/env python3
"""Validate unchanged Luraph register moves with explicit operand frames."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
LUAUTH_BODY = ROOT / "tests" / "fixtures" / "luraph" / "subject_ea93959c47e6.luau"
LUAUTH_HEADER = (
    "la_code=1;la_script_id='unchanged-move-frame-regression'\n"
    "--[[ LuaAuth launcher: https://luaauth.com ]]\n"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def trace(operand_frame: str | None) -> str:
    rows = [
        "@@LPH_PROTO_V1@@\t1\t1\tS,V,Z,g,r,v",
        "@@LPH_PROTO_OBJECT_V1@@\t1\t1001",
        "@@LPH_INSN_V1@@\t1\t1\t72\tS=n:19|V=z:|Z=n:0|g=z:|r=n:12|v=z:",
        "@@LPH_ACT_PROTO_V1@@\t1\t1\tnil\tnil\tnil\t0\t1\t\t1",
    ]
    if operand_frame is not None:
        rows.append(
            "@@LPH_OPERAND_FRAME_V1@@\t1\t1\t1\t72\t3\t"
            f"S@19={operand_frame.split('|')[0]}|Z@0=z:|r@12={operand_frame.split('|')[1]}"
        )
    rows.extend(
        (
            "@@LPH_GUARD_PATH_V1@@\t1\t1\t1\t72\t0\t0\t",
            "@@LPH_STEP_V1@@\t1\t1\t1\t72\t2\t0\t\t"
            "S=n:19|V=z:|Z=n:0|g=z:|r=n:12|v=z:\t",
            "",
        )
    )
    return "\n".join(rows)


def ambiguous_object_trace(include_frame: bool) -> str:
    rows = [
        "@@LPH_PROTO_V1@@\t1\t1\tS,V,Z,g,r,v",
        "@@LPH_PROTO_OBJECT_V1@@\t1\t1001",
        "@@LPH_INSN_V1@@\t1\t1\t72\tS=n:19|V=z:|Z=n:0|g=z:|r=n:12|v=z:",
        "@@LPH_ACT_PROTO_V1@@\t1\t1\tnil\tnil\tnil\t0\t1\t\t1",
    ]
    if include_frame:
        rows.append(
            "@@LPH_OPERAND_FRAME_V1@@\t1\t1\t1\t72\t3\t"
            "S@19=f:73656c656374|Z@0=z:|r@12=x:table"
        )
    rows.extend(
        (
            "@@LPH_GUARD_PATH_V1@@\t1\t1\t1\t72\t0\t0\t",
            "@@LPH_STEP_V1@@\t1\t1\t1\t72\t2\t1\t19=x:table\t"
            "S=n:19|V=z:|Z=n:0|g=z:|r=n:12|v=z:\t19=r:12,r:55",
            "",
        )
    )
    return "\n".join(rows)


def run_case(
    deobfuscator: pathlib.Path,
    source: pathlib.Path,
    root: pathlib.Path,
    name: str,
    operand_frame: str | None,
) -> dict:
    return run_trace_case(deobfuscator, source, root, name, trace(operand_frame))


def run_trace_case(
    deobfuscator: pathlib.Path,
    source: pathlib.Path,
    root: pathlib.Path,
    name: str,
    trace_text: str,
) -> dict:
    case = root / name
    case.mkdir()
    trace_path = case / "trace.log"
    trace_path.write_text(trace_text, encoding="utf-8")
    output = case / "output"
    report = case / "report.json"
    completed = subprocess.run(
        (
            str(deobfuscator),
            str(source),
            "--output-dir",
            str(output),
            "--mode",
            "reconstruct",
            "--trace",
            str(trace_path),
            "--report",
            str(report),
        ),
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=45,
    )
    require(completed.returncode == 2, f"{name} exited {completed.returncode}: {completed.stderr}")
    semantic = json.loads((output / "runtime_semantic_ir.json").read_text(encoding="utf-8"))
    rows = [
        row
        for prototype in semantic.get("prototypes") or []
        if prototype.get("runtime_id") == 1
        for row in prototype.get("instructions") or []
        if row.get("pc") == 1
    ]
    require(len(rows) == 1, f"{name} did not retain its instruction: {rows}")
    return rows[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-unchanged-move-") as temporary:
        root = pathlib.Path(temporary)
        source = root / "subject.luau"
        source.write_text(LUAUTH_HEADER + LUAUTH_BODY.read_text(encoding="utf-8"), encoding="utf-8")

        accepted = run_case(args.deobfuscator.resolve(), source, root, "accepted", "z:|z:")
        operation = accepted.get("observational_semantic_operation") or {}
        validation = operation.get("runtime_validation") or {}
        require(
            operation.get("kind") == "register_write"
            and operation.get("proof") == "runtime_validated_incomplete_register_move_candidate",
            f"equal nil operand frame did not recover the move: {accepted}",
        )
        require(
            validation.get("proof") == "observed_unchanged_destination_and_source_operand_frame"
            and validation.get("changed_write_observations") == 0
            and validation.get("unchanged_write_observations") == 1
            and validation.get("operand_frame_validated_unchanged_observations") == 1,
            f"unchanged move proof drifted: {validation}",
        )

        table_accepted = run_case(
            args.deobfuscator.resolve(), source, root, "table-accepted", "t:42|t:42"
        )
        require(
            (table_accepted.get("observational_semantic_operation") or {}).get("kind") == "register_write",
            f"same-object table operand frame did not recover the move: {table_accepted}",
        )

        for name, frame in (
            ("contradictory", "z:|n:1"),
            ("table-identity-mismatch", "t:42|t:43"),
            ("missing", None),
        ):
            rejected = run_case(args.deobfuscator.resolve(), source, root, name, frame)
            require(
                rejected.get("observational_semantic_operation") is None
                and rejected.get("semantic_coverage_class") == "trace_evidence_only",
                f"{name} unchanged move evidence was incorrectly accepted: {rejected}",
            )

        ambiguous = run_trace_case(
            args.deobfuscator.resolve(), source, root, "ambiguous-object", ambiguous_object_trace(True)
        )
        ambiguous_operation = ambiguous.get("observational_semantic_operation") or {}
        require(
            ambiguous_operation.get("kind") == "register_write"
            and ambiguous_operation.get("proof") == "runtime_validated_incomplete_register_move_candidate",
            f"operand-framed ambiguous object move was not recovered: {ambiguous}",
        )

        ambiguous_unframed = run_trace_case(
            args.deobfuscator.resolve(), source, root, "ambiguous-object-unframed", ambiguous_object_trace(False)
        )
        require(
            ambiguous_unframed.get("observational_semantic_operation") is None,
            f"unframed ambiguous object move was incorrectly accepted: {ambiguous_unframed}",
        )

    print("Luraph unchanged move operand-frame regression OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
