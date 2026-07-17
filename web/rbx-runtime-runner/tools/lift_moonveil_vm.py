#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_INPUT = Path("work/mv-deobf-trace-op48/moonveil_vm_programs.json")

FIELD_DEFS = [
    ("6731", "f_0x1a4b", "branch_aux"),
    ("10389", "f_0x2895", "a_or_dst"),
    ("15394", "f_0x3c22", "op"),
    ("25137", "f_0x6231", "aux_0x6231"),
    ("36629", "f_0x8f15", "number"),
    ("41102", "f_0xa08e", "literal"),
    ("45043", "f_0xaff3", "branch_target"),
    ("46251", "f_0xb4ab", "c_or_rhs"),
    ("50066", "f_0xc392", "b_or_src"),
    ("51755", "f_0xca2b", "jump_target"),
    ("54140", "f_0xd37c", "aux_0xd37c"),
]

RAW_TO_ALIAS = {raw: alias for raw, alias, _role in FIELD_DEFS}
ALIAS_TO_RAW = {alias: raw for raw, alias, _role in FIELD_DEFS}
ALIAS_TO_ROLE = {alias: role for _raw, alias, role in FIELD_DEFS}
ROLE_TO_ALIAS = {role: alias for _raw, alias, role in FIELD_DEFS}

OPCODES = {
    12: "iter_next_or_index",
    32: "metamethod_or_call",
    39: "jump",
    42: "string_meta",
    44: "compare_or_test",
    45: "equals",
    48: "load_const_global",
    58: "not",
    78: "call_or_branch",
    79: "iter_init_or_index",
    91: "load_number",
    97: "load_upvalue",
    105: "callprep_proto_bind",
    106: "call_enter_closure",
    113: "mul",
    133: "nil",
    137: "newclosure",
    153: "getkey",
    158: "call_or_branch",
    161: "mul_add_accumulate",
    170: "len",
    176: "gettable",
    180: "string_block_finalize",
    182: "return_pack_setup",
    189: "branch",
    201: "sub",
    207: "concat",
    209: "return_pack_or_trampoline",
    210: "move",
    224: "newclosure_load_proto",
    226: "literal",
    227: "closure_capture_descriptor",
}

PARTIAL_OPCODE_NOTES = {
    12: "Observed in byte/string iteration loop; advances an index and loads the next single-character string.",
    45: "Observed writing booleans from equality-style tests; exact operand bias is not fully proven.",
    79: "Observed as iterator/bootstrap for the single-character string loop.",
    97: "Loads a captured/upvalue value. Dynamic trace supports R[a-0x29] = U[b-0x1e].",
    105: "Observed before CALL in MoonVeil wrapper; prepares/binds call frame state.",
    106: "CALL/ENTER_CLOSURE. Decoded call base is a_or_dst - 0x17; b/c encode argc and return/control.",
    137: "Creates a closure and consumes following opcode-227 capture descriptor rows.",
    153: "Keyed lookup. Dynamic trace supports R[a-0xe] = R[b-0x24][literal].",
    161: "Observed numeric accumulator update in a string/byte loop.",
    170: "Length operator. Dynamic trace supports R[a-0x2a] = #R[b-0x3b].",
    180: "Observed statically after concat repair blocks; not dispatched on the successful traced route.",
    182: "Observed immediately before return packing; prepares hidden return-pack state.",
    207: "String concatenation. Dynamic trace supports R[a-0x25] = R[b] .. R[c-0x2e].",
    209: "Return/continuation trampoline. Exact return packing still needs more dynamic tracing.",
    224: "NEWCLOSURE/LOAD_PROTO. Decoded destination is a_or_dst - 0x14; proto index is aux_0xd37c - 0x3f.",
    227: "Inline closure capture descriptor consumed by opcode 137; not independently dispatched.",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Statically lift a MoonVeil VM program table into readable Lua "
            "pseudocode plus a JSON summary."
        )
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"moonveil_vm_programs.json path (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--lua-out",
        type=Path,
        default=None,
        help="Lua/pseudocode output path (default: beside input)",
    )
    parser.add_argument(
        "--summary-out",
        type=Path,
        default=None,
        help="JSON summary output path (default: beside input)",
    )
    parser.add_argument(
        "--max-literal",
        type=int,
        default=96,
        help="maximum literal preview length in the Lua/pseudocode output",
    )
    return parser.parse_args()


def default_lua_path(input_path: Path) -> Path:
    return input_path.with_name(f"{input_path.stem}_lifted.lua")


def default_summary_path(input_path: Path) -> Path:
    return input_path.with_name(f"{input_path.stem}_lift_summary.json")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return json.load(handle)


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
    if number.is_integer():
        return int(number)
    return None


def coerce_number(value: Any) -> int | float | None:
    integer = coerce_int(value)
    if integer is not None:
        return integer
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def raw_from_key(key: Any) -> str | None:
    text = str(key)
    if text in RAW_TO_ALIAS:
        return text
    if text in ALIAS_TO_RAW:
        return ALIAS_TO_RAW[text]
    if text.startswith("0x"):
        try:
            raw = str(int(text, 16))
        except ValueError:
            return None
        return raw if raw in RAW_TO_ALIAS else None
    return None


def canonical_alias(key: Any, field: Any) -> tuple[str, str | None]:
    raw = raw_from_key(key)
    if isinstance(field, dict):
        raw = raw or raw_from_key(field.get("raw_key"))
    if raw is not None:
        return RAW_TO_ALIAS[raw], raw
    return str(key), None


def normalize_field(key: Any, field: Any) -> dict[str, Any]:
    alias, raw = canonical_alias(key, field)
    if isinstance(field, dict):
        field_type = field.get("type", field.get("value_type"))
        value = field.get("value")
        byte_count = field.get("bytes")
        hex_value = field.get("hex")
        key_hex = field.get("key_hex")
        entries = field.get("entries", field.get("table_entries_seen"))
        raw = raw or raw_from_key(field.get("raw_key")) or field.get("raw_key")
    else:
        field_type = type(field).__name__
        value = field
        byte_count = None
        hex_value = None
        key_hex = None
        entries = None
    return {
        "alias": alias,
        "role": ALIAS_TO_ROLE.get(alias, alias),
        "raw_key": str(raw) if raw is not None else None,
        "type": field_type,
        "value": value,
        "bytes": byte_count,
        "hex": hex_value,
        "key_hex": key_hex,
        "entries": entries,
    }


def normalize_row(row: Any, index: int) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ValueError(f"instruction row {index} is not an object")
    pc = coerce_int(row.get("pc", row.get("numeric_key", row.get("key", index + 1))))
    if pc is None:
        pc = index + 1
    fields_raw = row.get("fields", row)
    if not isinstance(fields_raw, dict):
        raise ValueError(f"instruction row {pc} has non-object fields")
    fields = {}
    for key, field in fields_raw.items():
        if key in {"pc", "numeric_key", "key", "fields"}:
            continue
        normalized = normalize_field(key, field)
        fields[normalized["alias"]] = normalized
    return {"pc": pc, "fields": fields}


def iter_program_objects(data: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    metadata: dict[str, Any] = {}
    if isinstance(data, dict):
        metadata = {key: value for key, value in data.items() if key != "programs"}
        raw_programs = data.get("programs")
        if raw_programs is None and ("instructions" in data or "rows" in data):
            raw_programs = [data]
    else:
        raw_programs = data

    if isinstance(raw_programs, dict):
        out = []
        for program_id, program in raw_programs.items():
            if isinstance(program, dict):
                item = dict(program)
                item.setdefault("program_id", str(program_id))
                out.append(item)
        return out, metadata
    if isinstance(raw_programs, list):
        return [item for item in raw_programs if isinstance(item, dict)], metadata
    raise ValueError("input JSON must contain a programs array/dict or an instructions object")


def normalize_programs(data: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_programs, metadata = iter_program_objects(data)
    programs = []
    for index, program in enumerate(raw_programs, start=1):
        instructions = program.get("instructions", program.get("rows", []))
        if not isinstance(instructions, list):
            raise ValueError(f"program {index} instructions must be an array")
        rows = [normalize_row(row, row_index) for row_index, row in enumerate(instructions)]
        program_id = str(program.get("program_id", f"prog_{index:03d}"))
        occurrences = program.get("occurrences", [])
        if occurrences is None:
            occurrences = []
        if not isinstance(occurrences, list):
            occurrences = [occurrences]
        programs.append(
            {
                "program_id": program_id,
                "sha256": program.get("sha256"),
                "occurrences": occurrences,
                "declared_instruction_count": program.get("instruction_count"),
                "instructions": sorted(rows, key=lambda item: item["pc"]),
            }
        )
    return programs, metadata


def field(fields: dict[str, dict[str, Any]], role: str) -> dict[str, Any] | None:
    return fields.get(ROLE_TO_ALIAS[role])


def field_value(fields: dict[str, dict[str, Any]], role: str) -> Any:
    item = field(fields, role)
    return item.get("value") if item else None


def field_int(fields: dict[str, dict[str, Any]], role: str) -> int | None:
    return coerce_int(field_value(fields, role))


def reg(value: Any) -> str:
    number = coerce_int(value)
    if number is not None:
        return f"R{number}"
    if value is None:
        return "R?"
    return f"R[{format_atom(value)}]"


def biased_reg(value: Any, bias: int) -> str:
    number = coerce_int(value)
    if number is not None:
        return f"R{number - bias}"
    return reg(value)


def pc_label(value: Any) -> str:
    number = coerce_int(value)
    if number is None:
        return f"pc_{format_atom(value)}"
    return f"pc_{number:03d}"


def shorten(text: str, limit: int) -> str:
    if limit < 8:
        limit = 8
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def format_atom(value: Any, max_literal: int = 96) -> str:
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = shorten(str(value), max_literal)
    return json.dumps(text, ensure_ascii=True)


def format_field_value(item: dict[str, Any], max_literal: int) -> str:
    value = item.get("value")
    if item.get("type") == "string":
        suffix = ""
        if item.get("bytes") is not None:
            suffix = f" bytes={item['bytes']}"
        if item.get("hex"):
            suffix += f" hex={shorten(str(item['hex']), max_literal)}"
        return f"{format_atom(value, max_literal)}{suffix}"
    if value is None and item.get("entries") is not None:
        return f"<table entries={item['entries']}>"
    return str(value)


def sorted_fields(fields: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    def sort_key(item: dict[str, Any]) -> tuple[int, str]:
        raw = coerce_int(item.get("raw_key"))
        if raw is None:
            return (10**9, item["alias"])
        return (raw, item["alias"])

    return sorted(fields.values(), key=sort_key)


def opcode_for_row(row: dict[str, Any]) -> int | None:
    return field_int(row["fields"], "op")


def opcode_name(opcode: int | None) -> str:
    if opcode is None:
        return "missing_opcode"
    return OPCODES.get(opcode, f"unknown_{opcode}")


def render_operands(fields: dict[str, dict[str, Any]], max_literal: int) -> str:
    parts = []
    for item in sorted_fields(fields):
        role = item["role"]
        if role == "op":
            continue
        value = format_field_value(item, max_literal)
        if value in {"0", "None", "nil"}:
            continue
        parts.append(f"{role}={value}")
    return ", ".join(parts)


def render_known_pseudocode(opcode: int | None, fields: dict[str, dict[str, Any]], max_literal: int) -> str:
    a = field_value(fields, "a_or_dst")
    b = field_value(fields, "b_or_src")
    c = field_value(fields, "c_or_rhs")
    literal = field_value(fields, "literal")
    number = field_value(fields, "number")
    jump_target = field_value(fields, "jump_target")
    branch_target = field_value(fields, "branch_target")
    branch_aux = field_value(fields, "branch_aux")

    if opcode == 12:
        return f"ITER_NEXT_OR_INDEX({render_operands(fields, max_literal)})"
    if opcode == 32:
        return f"METAMETHOD_OR_CALL({render_operands(fields, max_literal)})"
    if opcode == 39:
        return f"goto {pc_label(jump_target)}"
    if opcode == 42:
        return f"string_meta {format_atom(literal, max_literal)}"
    if opcode == 44:
        return f"COMPARE_OR_TEST({render_operands(fields, max_literal)})"
    if opcode == 45:
        left = coerce_int(b)
        right = coerce_int(c)
        dst = coerce_int(a)
        if dst is not None and left is not None and right is not None:
            return f"R{dst - 0x3b} = (R{left - 0x2c} == R{right - 0x1f})"
        return f"EQUALS({render_operands(fields, max_literal)})"
    if opcode == 48:
        return f"{reg(a)} = CONST_OR_GLOBAL[{format_atom(literal, max_literal)}]"
    if opcode == 58:
        return f"{reg(a)} = not {reg(b)}"
    if opcode == 78:
        return f"CALL_OR_BRANCH({render_operands(fields, max_literal)})"
    if opcode == 79:
        return f"ITER_INIT_OR_INDEX({render_operands(fields, max_literal)})"
    if opcode == 91:
        return f"{reg(a)} = {format_atom(number if number is not None else literal, max_literal)}"
    if opcode == 97:
        dst = coerce_int(a)
        src = coerce_int(b)
        if dst is not None and src is not None:
            return f"R{dst - 0x29} = U{src - 0x1e}"
        return f"LOAD_UPVALUE({render_operands(fields, max_literal)})"
    if opcode == 105:
        start = coerce_int(a)
        start_text = f"R{start - 2}" if start is not None else reg(a)
        return f"CALLPREP start={start_text} raw=({render_operands(fields, max_literal)})"
    if opcode == 106:
        base = coerce_int(a)
        argc = coerce_int(b)
        retctl = coerce_int(c)
        return (
            f"CALL {('R' + str(base - 0x17)) if base is not None else reg(a)} "
            f"argc={argc - 0x28 if argc is not None else '?'} "
            f"retctl={retctl - 0x3d if retctl is not None else '?'}"
        )
    if opcode == 113:
        return f"{reg(a)} = {reg(b)} * {reg(c)}"
    if opcode == 133:
        return f"{reg(a)} = nil"
    if opcode == 137:
        dst = coerce_int(a)
        selector = coerce_int(field_value(fields, "aux_0xd37c"))
        base = f"R{dst - 0x14}" if dst is not None else reg(a)
        selector_text = str(selector) if selector is not None else "?"
        return f"{base} = NEWCLOSURE selector={selector_text} (captures follow as op227 rows)"
    if opcode == 153:
        dst = coerce_int(a)
        src = coerce_int(b)
        if dst is not None and src is not None:
            return f"R{dst - 0xe} = R{src - 0x24}[{format_atom(literal, max_literal)}]"
        return f"GETKEY({render_operands(fields, max_literal)})"
    if opcode == 158:
        return f"CALL_OR_BRANCH({render_operands(fields, max_literal)})"
    if opcode == 161:
        return f"MUL_ADD_ACCUMULATE({render_operands(fields, max_literal)})"
    if opcode == 170:
        dst = coerce_int(a)
        src = coerce_int(b)
        if dst is not None and src is not None:
            return f"R{dst - 0x2a} = #R{src - 0x3b}"
        return f"LEN({render_operands(fields, max_literal)})"
    if opcode == 176:
        return f"{reg(a)} = {reg(b)}[{format_atom(literal, max_literal)}]"
    if opcode == 180:
        return f"STRING_BLOCK_FINALIZE({render_operands(fields, max_literal)})"
    if opcode == 182:
        return f"RETURN_PACK_SETUP({render_operands(fields, max_literal)})"
    if opcode == 189:
        return f"branch {reg(a)} -> {pc_label(branch_target)} / aux={format_atom(branch_aux, max_literal)}"
    if opcode == 201:
        return f"{reg(a)} = {reg(b)} - {reg(c)}"
    if opcode == 207:
        dst = coerce_int(a)
        left = coerce_int(b)
        right = coerce_int(c)
        if dst is not None and left is not None and right is not None:
            return f"R{dst - 0x25} = R{left} .. R{right - 0x2e}"
        return f"CONCAT({render_operands(fields, max_literal)})"
    if opcode == 209:
        return f"RETURN_OR_TRAMPOLINE({render_operands(fields, max_literal)})"
    if opcode == 210:
        return f"{biased_reg(a, 0x13)} = {biased_reg(b, 0x24)}"
    if opcode == 224:
        proto = coerce_int(field_value(fields, "aux_0xd37c"))
        return f"{biased_reg(a, 0x14)} = NEWCLOSURE proto[{proto - 0x3f if proto is not None else '?'}]"
    if opcode == 226:
        return f"{reg(a)} = literal({format_atom(literal, max_literal)})"
    if opcode == 227:
        return f"CAPTURE_DESCRIPTOR({render_operands(fields, max_literal)})"

    operands = render_operands(fields, max_literal)
    if operands:
        return f"{opcode_name(opcode)}({operands})"
    return opcode_name(opcode)


def histogram(rows: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in rows:
        opcode = opcode_for_row(row)
        counts[str(opcode) if opcode is not None else "<missing>"] += 1
    return counts


def sort_histogram(counter: Counter[str]) -> dict[str, int]:
    def key(item: tuple[str, int]) -> tuple[int, str]:
        number = coerce_int(item[0])
        if number is None:
            return (10**9, item[0])
        return (number, item[0])

    return {op: count for op, count in sorted(counter.items(), key=key)}


def row_summary(row: dict[str, Any], max_literal: int) -> dict[str, Any]:
    opcode = opcode_for_row(row)
    fields = row["fields"]
    text = render_known_pseudocode(opcode, fields, max_literal)
    return {
        "pc": row["pc"],
        "opcode": opcode,
        "opcode_name": opcode_name(opcode),
        "known_opcode": opcode in OPCODES if opcode is not None else False,
        "text": text,
        "fields": {item["role"]: item for item in sorted_fields(fields)},
    }


def build_summary(
    input_path: Path,
    metadata: dict[str, Any],
    programs: list[dict[str, Any]],
    max_literal: int,
) -> dict[str, Any]:
    total_histogram: Counter[str] = Counter()
    program_summaries = []
    for program in programs:
        rows = [row_summary(row, max_literal) for row in program["instructions"]]
        op_histogram = histogram(program["instructions"])
        total_histogram.update(op_histogram)
        program_summaries.append(
            {
                "program_id": program["program_id"],
                "sha256": program["sha256"],
                "instruction_count": len(program["instructions"]),
                "declared_instruction_count": program["declared_instruction_count"],
                "occurrence_count": len(program["occurrences"]),
                "occurrences": program["occurrences"],
                "opcode_histogram": sort_histogram(op_histogram),
                "rows": rows,
            }
        )

    return {
        "source": str(input_path),
        "source_dump": metadata.get("source_dump"),
        "program_count": len(programs),
        "total_instruction_count": sum(len(program["instructions"]) for program in programs),
        "program_sizes": {
            program["program_id"]: len(program["instructions"]) for program in programs
        },
        "field_aliases": {
            raw: {"alias": alias, "role": role} for raw, alias, role in FIELD_DEFS
        },
        "opcodes": {str(opcode): name for opcode, name in sorted(OPCODES.items())},
        "partial_opcode_notes": {str(opcode): note for opcode, note in sorted(PARTIAL_OPCODE_NOTES.items())},
        "total_opcode_histogram": sort_histogram(total_histogram),
        "programs": program_summaries,
    }


def render_histogram_line(counter: dict[str, int]) -> str:
    return ", ".join(f"{opcode}:{count}" for opcode, count in counter.items())


def render_lua(summary: dict[str, Any]) -> str:
    lines = [
        "-- MoonVeil VM static lift fallback.",
        "-- This is not original source; it is a cautious disassembly of recovered VM rows.",
        f"-- source: {summary['source']}",
        f"-- program_count: {summary['program_count']}",
        f"-- total_instruction_count: {summary['total_instruction_count']}",
        "--",
        "-- Field aliases:",
    ]
    for raw, info in summary["field_aliases"].items():
        lines.append(f"--   {info['role']}: {info['alias']} raw={raw}")
    lines.extend(
        [
            "--",
            "-- Known opcode names:",
            "--   "
            + ", ".join(
                f"{opcode}={name}" for opcode, name in summary["opcodes"].items()
            ),
            "--",
            "-- Partial opcode notes:",
        ]
    )
    for opcode, note in summary.get("partial_opcode_notes", {}).items():
        lines.append(f"--   {opcode}: {note}")
    lines.extend(
        [
            "--",
        ]
    )

    for program in summary["programs"]:
        sha = program["sha256"] or "<unknown>"
        lines.append(
            f"-- ## {program['program_id']} rows={program['instruction_count']} "
            f"occurrences={program['occurrence_count']} sha256={sha}"
        )
        lines.append(f"-- opcode_histogram: {render_histogram_line(program['opcode_histogram'])}")
        for row in program["rows"]:
            opcode = row["opcode"]
            opcode_text = "???" if opcode is None else f"{opcode:03d}"
            operands = []
            for item in row["fields"].values():
                if item["role"] == "op":
                    continue
                value = format_field_value(item, 96)
                if value in {"0", "None", "nil"}:
                    continue
                operands.append(f"{item['role']}={value}")
            suffix = ""
            if operands:
                suffix = " | " + ", ".join(operands)
            lines.append(
                f"--   pc {row['pc']:03d}: op {opcode_text} {row['opcode_name']} | "
                f"{row['text']}{suffix}"
            )
        lines.append("--")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    input_path = args.input
    lua_path = args.lua_out or default_lua_path(input_path)
    summary_path = args.summary_out or default_summary_path(input_path)

    data = load_json(input_path)
    programs, metadata = normalize_programs(data)
    summary = build_summary(input_path, metadata, programs, args.max_literal)
    lua_text = render_lua(summary)
    summary_text = json.dumps(summary, indent=2, ensure_ascii=True) + "\n"

    write_text(lua_path, lua_text)
    write_text(summary_path, summary_text)

    print(f"wrote {lua_path}")
    print(f"wrote {summary_path}")
    print(
        f"programs={summary['program_count']} "
        f"rows={summary['total_instruction_count']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
