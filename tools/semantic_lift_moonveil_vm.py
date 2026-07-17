#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a semantic MoonVeil VM fallback decompile.")
    parser.add_argument("--ir", type=Path, default=Path("outputs/moonveil_v2_devirtualized_ir.json"))
    parser.add_argument("--lifted-summary", type=Path, default=Path("outputs/moonveil_v2_lifted_summary.json"))
    parser.add_argument("--json-out", type=Path, default=Path("outputs/moonveil_v2_semantic_ir.json"))
    parser.add_argument("--lua-out", type=Path, default=Path("outputs/moonveil_v2_semantic_decompile.lua"))
    parser.add_argument("--max-comment-lines", type=int, default=2200)
    return parser.parse_args()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def coerce_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    text = str(value).strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        return None
    return int(number) if number.is_integer() else None


def lua_quote(value: Any) -> str:
    text = str(value)
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 32 <= code < 127:
            out.append(ch)
        elif code <= 255:
            out.append(f"\\x{code:02X}")
        else:
            out.append("?")
    out.append('"')
    return "".join(out)


def safe_comment(value: Any, limit: int = 220) -> str:
    text = str(value)
    out = []
    for ch in text:
        code = ord(ch)
        if ch in "\r\n\t":
            out.append(" ")
        elif 32 <= code < 127:
            out.append(ch)
        elif code <= 255:
            out.append(f"\\x{code:02X}")
        else:
            out.append("?")
    result = "".join(out)
    return result if len(result) <= limit else result[: limit - 3] + "..."


def field(fields: dict[str, Any], name: str) -> dict[str, Any]:
    value = fields.get(name)
    return value if isinstance(value, dict) else {}


def field_value(fields: dict[str, Any], name: str) -> Any:
    return field(fields, name).get("value")


def field_int(fields: dict[str, Any], name: str) -> int | None:
    return coerce_int(field_value(fields, name))


def reg(index: int | None) -> str:
    return "r?" if index is None else f"r{index}"


def biased(fields: dict[str, Any], name: str, bias: int) -> str:
    value = field_int(fields, name)
    return reg(None if value is None else value - bias)


def literal_expr(literal: dict[str, Any]) -> str:
    hex_value = literal.get("hex")
    if isinstance(hex_value, str) and hex_value:
        return f"hex({hex_value})"
    value = literal.get("value")
    if value is None:
        return "nil"
    return repr(str(value))


def literal_summary(literal: dict[str, Any]) -> dict[str, Any] | None:
    if not literal:
        return None
    out = {
        "bytes": literal.get("bytes"),
        "preview": literal.get("preview") or literal.get("value_preview") or literal.get("value"),
        "hex": literal.get("hex"),
        "sha256": literal.get("sha256"),
        "printable_ratio": literal.get("printable_ratio"),
    }
    return {key: value for key, value in out.items() if value is not None}


def normalize_observed_writes(ins: dict[str, Any]) -> list[dict[str, Any]]:
    writes = []
    for write in ((ins.get("observed_effect") or {}).get("writes") or []):
        values = write.get("values") or []
        top = values[0] if values else {}
        writes.append(
            {
                "register": write.get("register"),
                "top": top.get("value"),
                "count": top.get("count", 0),
                "alternatives": values[1:5],
            }
        )
    return writes


def observed_pseudo(writes: list[dict[str, Any]]) -> list[str]:
    lines = []
    for write in writes:
        register = str(write.get("register") or "r?")
        top = str(write.get("top") or "unknown")
        lines.append(f"{register} := observed({safe_comment(top, 120)})")
    return lines


def decode_semantics(opcode: int | None, fields: dict[str, Any], lifted_text: str) -> dict[str, Any]:
    literal = field(fields, "literal")
    number = field_value(fields, "number")
    a = field_int(fields, "a_or_dst")
    b = field_int(fields, "b_or_src")
    c = field_int(fields, "c_or_rhs")
    branch_target = field_int(fields, "branch_target")
    jump_target = field_int(fields, "jump_target")
    branch_aux = field_value(fields, "branch_aux")
    aux = field_int(fields, "aux_0xd37c")

    result: dict[str, Any] = {
        "static": lifted_text,
        "reads": [],
        "writes": [],
        "effects": [],
        "confidence": "medium",
        "notes": [],
    }

    def set_pseudo(text: str, confidence: str = "high") -> None:
        result["pseudo"] = text
        result["confidence"] = confidence

    if opcode == 12:
        set_pseudo(f"iterator_next_or_index({biased(fields, 'a_or_dst', 0)}, {biased(fields, 'b_or_src', 0)})", "medium")
        result["effects"].append("iterator")
        result["notes"].append("Observed in string/byte iteration loops; exact bias is still partial.")
    elif opcode == 32:
        set_pseudo(f"metamethod_or_call({biased(fields, 'a_or_dst', 0)}, target_pc={branch_target})", "low")
        result["effects"].append("call_or_branch")
    elif opcode == 39:
        set_pseudo(f"goto pc_{jump_target}", "high")
        result["effects"].append("jump")
        result["target_pc"] = jump_target
    elif opcode == 42:
        set_pseudo(f"string_key_context = {literal_expr(literal)}", "medium")
        result["effects"].append("string_key_context")
    elif opcode == 44:
        set_pseudo(f"compare_or_test({biased(fields, 'a_or_dst', 0)}, {biased(fields, 'b_or_src', 0)}) -> pc_{branch_target}", "low")
        result["effects"].append("branch")
        result["target_pc"] = branch_target
    elif opcode == 45:
        dst = None if a is None else a - 0x3B
        left = None if b is None else b - 0x2C
        right = None if c is None else c - 0x1F
        set_pseudo(f"{reg(dst)} = ({reg(left)} == {reg(right)})", "medium")
        result["reads"].extend([reg(left), reg(right)])
        result["writes"].append(reg(dst))
    elif opcode == 48:
        set_pseudo(f"load_const_or_global(dst_raw={a}, key={literal_expr(literal)})", "medium")
        result["notes"].append("Destination is computed by VM hidden state; observed writes are authoritative when present.")
    elif opcode == 58:
        set_pseudo(f"{reg(a)} = not {reg(b)}", "high")
        result["reads"].append(reg(b))
        result["writes"].append(reg(a))
    elif opcode == 78:
        set_pseudo(f"call_or_branch(raw_a={a}, raw_b={b}, raw_c={c})", "low")
        result["effects"].append("call_or_branch")
    elif opcode == 79:
        set_pseudo(f"iterator_init_or_index(raw_a={a}, raw_b={b}, target_pc={branch_target})", "medium")
        result["effects"].append("iterator")
        result["target_pc"] = branch_target
    elif opcode == 91:
        set_pseudo(f"{reg(a)} = {number}", "high")
        result["writes"].append(reg(a))
    elif opcode == 97:
        dst = None if a is None else a - 0x29
        src = None if b is None else b - 0x1E
        set_pseudo(f"{reg(dst)} = upvalue[{src}]", "high")
        result["reads"].append(f"u{src}")
        result["writes"].append(reg(dst))
    elif opcode == 105:
        start = None if a is None else a - 2
        set_pseudo(f"call_frame_prepare(start={reg(start)}, raw_b={b})", "medium")
        result["effects"].append("call_frame")
    elif opcode == 106:
        base = None if a is None else a - 0x17
        argc = None if b is None else b - 0x28
        retctl = None if c is None else c - 0x3D
        set_pseudo(f"call {reg(base)} argc={argc} retctl={retctl}", "high")
        result["reads"].append(reg(base))
        result["effects"].append("call")
    elif opcode == 113:
        set_pseudo(f"{reg(a)} = {reg(b)} * {reg(c)}", "medium")
        result["reads"].extend([reg(b), reg(c)])
        result["writes"].append(reg(a))
    elif opcode == 133:
        set_pseudo(f"{reg(a)} = nil", "high")
        result["writes"].append(reg(a))
    elif opcode == 137:
        dst = None if a is None else a - 0x14
        set_pseudo(f"{reg(dst)} = newclosure(selector={aux})", "high")
        result["writes"].append(reg(dst))
        result["effects"].append("closure")
    elif opcode == 153:
        dst = None if a is None else a - 0x0E
        src = None if b is None else b - 0x24
        set_pseudo(f"{reg(dst)} = {reg(src)}[{literal_expr(literal)}]", "high")
        result["reads"].append(reg(src))
        result["writes"].append(reg(dst))
    elif opcode == 158:
        set_pseudo(f"call_or_branch(raw_a={a}, raw_b={b}, raw_c={c})", "low")
        result["effects"].append("call_or_branch")
    elif opcode == 161:
        set_pseudo(f"mul_add_accumulate(raw_a={a}, raw_b={b}, raw_c={c})", "medium")
        result["effects"].append("numeric_accumulator")
    elif opcode == 170:
        dst = None if a is None else a - 0x2A
        src = None if b is None else b - 0x3B
        set_pseudo(f"{reg(dst)} = #{reg(src)}", "high")
        result["reads"].append(reg(src))
        result["writes"].append(reg(dst))
    elif opcode == 176:
        set_pseudo(f"{reg(a)} = {reg(b)}[{literal_expr(literal)}]", "medium")
        result["reads"].append(reg(b))
        result["writes"].append(reg(a))
    elif opcode == 180:
        set_pseudo(f"string_block_finalize(raw_a={a}, raw_b={b}, raw_c={c})", "low")
        result["effects"].append("string_builder")
    elif opcode == 182:
        set_pseudo(f"return_pack_setup(raw_a={a})", "medium")
        result["effects"].append("return")
    elif opcode == 189:
        set_pseudo(f"if {reg(a)} then goto pc_{branch_target} end -- aux={branch_aux}", "medium")
        result["reads"].append(reg(a))
        result["effects"].append("branch")
        result["target_pc"] = branch_target
    elif opcode == 201:
        set_pseudo(f"{reg(a)} = {reg(b)} - {reg(c)}", "medium")
        result["reads"].extend([reg(b), reg(c)])
        result["writes"].append(reg(a))
    elif opcode == 207:
        dst = None if a is None else a - 0x25
        right = None if c is None else c - 0x2E
        set_pseudo(f"{reg(dst)} = {reg(b)} .. {reg(right)}", "high")
        result["reads"].extend([reg(b), reg(right)])
        result["writes"].append(reg(dst))
    elif opcode == 209:
        set_pseudo(f"return_or_trampoline(raw_a={a}, raw_b={b})", "medium")
        result["effects"].append("return")
    elif opcode == 210:
        dst = None if a is None else a - 0x13
        src = None if b is None else b - 0x24
        set_pseudo(f"{reg(dst)} = {reg(src)}", "high")
        result["reads"].append(reg(src))
        result["writes"].append(reg(dst))
    elif opcode == 224:
        dst = None if a is None else a - 0x14
        proto = None if aux is None else aux - 0x3F
        set_pseudo(f"{reg(dst)} = newclosure(proto[{proto}])", "high")
        result["writes"].append(reg(dst))
        result["effects"].append("closure")
    elif opcode == 226:
        set_pseudo(f"{reg(a)} = {literal_expr(literal)}", "high")
        result["writes"].append(reg(a))
    elif opcode == 227:
        set_pseudo(f"capture_descriptor(raw_a={a}, raw_b={b})", "high")
        result["effects"].append("closure_capture")
    else:
        set_pseudo(lifted_text or f"opcode_{opcode}", "low")
        result["notes"].append("No semantic decoder is available for this opcode.")

    literal_info = literal_summary(literal)
    if literal_info:
        result["literal"] = literal_info
    return result


def build_lifted_index(lifted: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
    index: dict[tuple[str, int], dict[str, Any]] = {}
    for program in lifted.get("programs", []):
        program_id = str(program.get("program_id") or "")
        for row in program.get("rows", []):
            pc = coerce_int(row.get("pc"))
            if program_id and pc is not None:
                index[(program_id, pc)] = row
    return index


def merge_literal_from_ir(lifted_fields: dict[str, Any], ins: dict[str, Any]) -> dict[str, Any]:
    fields = json.loads(json.dumps(lifted_fields))
    literal = ins.get("literal")
    if isinstance(literal, dict):
        target = fields.setdefault("literal", {})
        if isinstance(target, dict):
            target.update({key: value for key, value in literal.items() if value is not None})
    return fields


def build_semantic(ir: dict[str, Any], lifted: dict[str, Any]) -> dict[str, Any]:
    lifted_index = build_lifted_index(lifted)
    programs = []
    confidence_counts: dict[str, int] = {}
    opcode_counts: dict[str, int] = {}
    observed_instruction_count = 0

    for program in ir.get("programs", []):
        program_id = str(program.get("program_id") or "unknown")
        semantic_blocks = []
        for block in program.get("blocks", []):
            semantic_instructions = []
            for ins in block.get("instructions", []):
                pc = int(ins.get("pc") or 0)
                opcode = coerce_int(ins.get("opcode"))
                lifted_row = lifted_index.get((program_id, pc), {})
                lifted_fields = lifted_row.get("fields") if isinstance(lifted_row.get("fields"), dict) else {}
                fields = merge_literal_from_ir(lifted_fields, ins)
                decoded = decode_semantics(opcode, fields, str(lifted_row.get("text") or ins.get("text") or ""))
                writes = normalize_observed_writes(ins)
                if writes:
                    observed_instruction_count += 1
                    decoded["observed_writes"] = writes
                    decoded["observed_pseudo"] = observed_pseudo(writes)
                confidence_counts[str(decoded.get("confidence"))] = confidence_counts.get(str(decoded.get("confidence")), 0) + 1
                opcode_counts[str(opcode)] = opcode_counts.get(str(opcode), 0) + 1
                semantic_instructions.append(
                    {
                        "pc": pc,
                        "opcode": opcode,
                        "opcode_name": ins.get("opcode_name"),
                        "dynamic_traces": ins.get("dynamic_traces") or [],
                        "semantic": decoded,
                    }
                )
            semantic_blocks.append(
                {
                    "block_id": block.get("block_id"),
                    "start_pc": block.get("start_pc"),
                    "end_pc": block.get("end_pc"),
                    "dynamic_hit_count": block.get("dynamic_hit_count"),
                    "successors": block.get("successors") or [],
                    "successor_blocks": block.get("successor_blocks") or [],
                    "instructions": semantic_instructions,
                }
            )
        programs.append(
            {
                "program_id": program_id,
                "sha256": program.get("sha256"),
                "instruction_count": program.get("instruction_count"),
                "coverage": program.get("coverage"),
                "blocks": semantic_blocks,
            }
        )

    return {
        "schema": "moonveil_semantic_lift_v1",
        "exact_recovery_status": "not_original_source_semantic_fallback",
        "exact_recovery_note": (
            "This artifact is a VM semantic lift. It improves readability and opcode coverage, "
            "but it is not byte-exact original Luau source."
        ),
        "source_ir": ir.get("inputs"),
        "program_count": len(programs),
        "trace_count": ir.get("trace_count"),
        "raw_literal_metadata_count": ir.get("raw_literal_metadata_count"),
        "instruction_count": sum(int(p.get("instruction_count") or 0) for p in programs),
        "observed_instruction_count": observed_instruction_count,
        "confidence_counts": confidence_counts,
        "opcode_counts": opcode_counts,
        "strict_source_candidates": len((ir.get("blob_classification") or {}).get("strict_source_candidates") or []),
        "programs": programs,
    }


def render_lua(semantic: dict[str, Any], max_comment_lines: int) -> str:
    lines: list[str] = []
    lines.append("-- MoonVeil v2 semantic VM fallback decompile.")
    lines.append("-- This is not byte-exact original source.")
    lines.append("-- It is generated from lifted VM operands, dynamic traces, observed register writes, and exact literal hex.")
    lines.append("")
    lines.append("local MoonVeilSemantic = {}")
    lines.append('MoonVeilSemantic.exact_recovery_status = "not_original_source_semantic_fallback"')
    lines.append("MoonVeilSemantic.summary = {")
    lines.append("    program_count = " + str(semantic.get("program_count")) + ",")
    lines.append("    instruction_count = " + str(semantic.get("instruction_count")) + ",")
    lines.append("    observed_instruction_count = " + str(semantic.get("observed_instruction_count")) + ",")
    lines.append("    raw_literal_metadata_count = " + str(semantic.get("raw_literal_metadata_count")) + ",")
    lines.append("    strict_source_candidates = " + str(semantic.get("strict_source_candidates")) + ",")
    lines.append("}")
    lines.append("")
    lines.append("MoonVeilSemantic.programs = {")
    for program in semantic.get("programs", []):
        coverage = program.get("coverage") or {}
        lines.append("    {")
        lines.append("        id = " + lua_quote(program.get("program_id")) + ",")
        lines.append("        sha256 = " + lua_quote(program.get("sha256")) + ",")
        lines.append("        instructions = " + str(program.get("instruction_count") or 0) + ",")
        lines.append("        dynamic_pc_percent = " + str(coverage.get("dynamic_pc_percent") or 0) + ",")
        lines.append("    },")
    lines.append("}")
    lines.append("")
    lines.append("-- Source-shaped semantic listing:")
    emitted = 0
    for program in semantic.get("programs", []):
        lines.append("--")
        lines.append("-- program " + str(program.get("program_id")) + " instructions=" + str(program.get("instruction_count")))
        for block in program.get("blocks", []):
            if emitted >= max_comment_lines:
                lines.append("-- semantic listing truncated")
                break
            lines.append(
                "--   block "
                + str(block.get("block_id"))
                + " pc "
                + str(block.get("start_pc"))
                + ".."
                + str(block.get("end_pc"))
                + " hits="
                + str(block.get("dynamic_hit_count"))
                + " successors="
                + ",".join(str(x) for x in block.get("successors", []))
            )
            emitted += 1
            for ins in block.get("instructions", []):
                if emitted >= max_comment_lines:
                    lines.append("-- semantic listing truncated")
                    break
                sem = ins.get("semantic") or {}
                lines.append(
                    "--     pc "
                    + str(ins.get("pc"))
                    + " op "
                    + str(ins.get("opcode"))
                    + " "
                    + safe_comment(sem.get("pseudo", sem.get("static", "")), 260)
                    + " ["
                    + str(sem.get("confidence"))
                    + "]"
                )
                emitted += 1
                literal = sem.get("literal") or {}
                if literal.get("hex"):
                    lines.append(
                        "--       literal bytes="
                        + str(literal.get("bytes"))
                        + " hex="
                        + str(literal.get("hex"))
                        + " sha256="
                        + str(literal.get("sha256", ""))[:16]
                    )
                    emitted += 1
                for observed in sem.get("observed_pseudo") or []:
                    if emitted >= max_comment_lines:
                        break
                    lines.append("--       observed " + safe_comment(observed, 260))
                    emitted += 1
            if emitted >= max_comment_lines:
                break
        if emitted >= max_comment_lines:
            break
    lines.append("")
    lines.append("return MoonVeilSemantic")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    ir = load_json(args.ir)
    lifted = load_json(args.lifted_summary)
    semantic = build_semantic(ir, lifted)
    write_text(args.json_out, json.dumps(semantic, indent=2, sort_keys=True))
    write_text(args.lua_out, render_lua(semantic, args.max_comment_lines))
    print(
        json.dumps(
            {
                "json_out": str(args.json_out),
                "lua_out": str(args.lua_out),
                "program_count": semantic["program_count"],
                "instruction_count": semantic["instruction_count"],
                "observed_instruction_count": semantic["observed_instruction_count"],
                "confidence_counts": semantic["confidence_counts"],
                "strict_source_candidates": semantic["strict_source_candidates"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
