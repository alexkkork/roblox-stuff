#!/usr/bin/env python3
"""Analyze and partially lift old Luraph v14 VM state dumps.

This consumes the JSON snapshot produced from the old LuaJIT probe/final-state
dumper.  It does not claim exact source recovery.  Its job is to turn the
captured VM tables into stable, inspectable artifacts: opcode inventory,
strings/constants, a control-flow-aware pseudo listing, and an honest recovery
report.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


Instruction = list[Any]


@dataclass(frozen=True)
class Proto:
    name: str
    path: str
    instructions: list[Instruction]
    captures: Any
    constants: Any
    header: Any
    seed: Any


def lua_field(value: Any, index: int) -> Any:
    if isinstance(value, list):
        pos = index - 1
        return value[pos] if 0 <= pos < len(value) else None
    if isinstance(value, dict):
        return value.get(str(index))
    return None


def normalize_instruction(value: Any) -> Instruction:
    return [lua_field(value, i) for i in range(1, 8)]


def is_instruction_like(value: Any) -> bool:
    if not isinstance(value, (list, dict)):
        return False
    op = lua_field(value, 1)
    if not isinstance(op, int):
        return False
    # Most Luraph v14 instructions use at least one of these fields.
    return any(lua_field(value, i) is not None for i in range(2, 8))


def is_proto_like(value: Any) -> bool:
    if not isinstance(value, list) or len(value) < 5:
        return False
    ins = value[0]
    return isinstance(ins, list) and bool(ins) and all(is_instruction_like(x) for x in ins[: min(len(ins), 8)])


def value_repr(value: Any, max_len: int = 80) -> str:
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "nan"
        if math.isinf(value):
            return "inf" if value > 0 else "-inf"
        return repr(value)
    if isinstance(value, str):
        escaped = value.encode("unicode_escape").decode("ascii")
        if len(escaped) > max_len:
            escaped = escaped[: max_len - 3] + "..."
        return '"' + escaped.replace('"', '\\"') + '"'
    if is_proto_like(value):
        return f"<proto len={len(value[0])} seed={value[4] if len(value) > 4 else '?'}>"
    if isinstance(value, list):
        return f"<list len={len(value)}>"
    if isinstance(value, dict):
        return f"<table keys={len(value)}>"
    return repr(value)


def r(index: Any) -> str:
    return f"r{index}" if isinstance(index, int) else f"r[{value_repr(index)}]"


def c(value: Any) -> str:
    return value_repr(value)


def instr_parts(instr: Instruction) -> tuple[Any, Any, Any, Any, Any, Any, Any]:
    return tuple(instr)  # type: ignore[return-value]


def semantic_for(instr: Instruction) -> tuple[str, str]:
    """Return (mnemonic, pseudo).  Field names match the VM table:

    op = [1], a = [2], b = [3], k1 = [4], c = [5], k2 = [6], k3 = [7].
    The names are intentionally generic because Luraph reuses fields per op.
    """

    op, a, b, k1, dst, k2, k3 = instr_parts(instr)

    known: dict[int, tuple[str, str]] = {
        1: ("BXOR", f"{r(a)} = bit.bxor({r(b)}, {r(dst)})"),
        2: ("TAILCALL_RANGE", f"return {r(b)}(...range {r(b)}..{r(b)}+{value_repr(a)}-1)"),
        3: ("LE_REG", f"{r(b)} = {r(a)} <= {r(dst)}"),
        4: ("ADD_REG", f"{r(b)} = {r(dst)} + {r(a)}"),
        5: ("JMP_IF_NOT_LT", f"if not ({r(dst)} < {r(a)}) then pc = {value_repr(b)} end"),
        6: ("EQ_CONST_CONST", f"{r(a)} = {c(k2)} == {c(k1)}"),
        7: ("JMP_IF_FALSE", f"if not {r(dst)} then pc = {value_repr(a)} end"),
        8: ("VARARG_SLICE", f"{r(dst)}.. = varargs[{r(dst)}..]"),
        9: ("RESTORE_FOR_STATE", "restore saved loop state"),
        10: ("CALL_ONE_ARG_NORET", f"{r(b)}({r(b + 1) if isinstance(b, int) else 'next'})"),
        11: ("SUB_CONST_CONST", f"{r(dst)} = {c(k3)} - {c(k1)}"),
        12: ("CLEAR_RANGE", f"for i = {value_repr(b)}, {value_repr(dst)} do r[i] = nil end"),
        13: ("GE_REG", f"{r(dst)} = {r(b)} >= {r(a)}"),
        14: ("CONCAT_CONST_REG", f"{r(b)} = {c(k3)} .. {r(dst)}"),
        15: ("SET_UPVALUE_TABLE_REG", f"up[{value_repr(dst)}][{r(a)}] = {r(b)}"),
        16: ("RETURN_RANGE", f"return r[{value_repr(dst)}..last_call]"),
        17: ("DIV_REG_CONST", f"{r(b)} = {r(a)} / {c(k2)}"),
        18: ("LOAD_VARARGS", f"load first {value_repr(b)} varargs into registers"),
        19: ("JMP_IF_NOT_LE", f"if not ({r(a)} <= {r(b)}) then pc = {value_repr(dst)} end"),
        20: ("NE_REG", f"{r(dst)} = {r(a)} ~= {r(b)}"),
        21: ("LOAD_VARARG_SLOT", f"{r(b)} = varargs[next]"),
        22: ("MUL_REG_CONST", f"{r(dst)} = {r(b)} * {c(k3)}"),
        23: ("FOR_PREP_B", f"save numeric for state at {r(a)}; pc = {value_repr(dst)}"),
        24: ("TABLE_MOVE_TAIL", f"append call tail from {r(b)} into {r(b)}[{value_repr(dst)}..]"),
        25: ("SET_UPVALUE", f"up[{value_repr(a)}] = {r(b)}"),
        26: ("LT_CONST_REG", f"{r(a)} = {c(k1)} < {r(dst)}"),
        27: ("CONCAT_REG_CONST", f"{r(dst)} = {r(a)} .. {c(k1)}"),
        28: ("GT_REG_CONST", f"{r(a)} = {r(b)} > {c(k2)}"),
        29: ("SUB_CONST_REG", f"{r(b)} = {c(k2)} - {r(a)}"),
        30: ("JMP", f"pc = {value_repr(b)}"),
        31: ("RETURN_CALL0", f"return {r(a)}()"),
        32: ("LOADK", f"{r(b)} = {c(k2)}"),
        33: ("CALL_2ARGS_1RET", f"{r(b)} = {r(b)}({r(b + 1) if isinstance(b, int) else 'next'}, {r(b + 2) if isinstance(b, int) else 'next2'})"),
        34: ("CALL_RANGE_NORET", f"{r(dst)}(...range {r(dst)}..last_call)"),
        35: ("RETURN_REG", f"return {r(dst)}"),
        36: ("EQ_REG_CONST", f"{r(b)} = {r(a)} == {c(k2)}"),
        37: ("LOADK_ALIAS", f"{r(b)} = {c(dst if dst is not None else k2)}"),
        38: ("GENERIC_FOR_NEXT", f"if next({r(a)}) then pc = {value_repr(b)} end"),
        39: ("JMP_IF_TRUE", f"if {r(b)} then pc = {value_repr(dst)} end"),
        40: ("LE_REG_CONST", f"{r(dst)} = {r(b)} <= {c(k3)}"),
        41: ("SET_GLOBAL", f"_ENV[{c(dst)}] = {r(b)}"),
        42: ("GE_REG_CONST", f"{r(b)} = {r(dst)} >= {c(k3)}"),
        43: ("NE_REG_CONST", f"{r(a)} = {r(b)} ~= {c(k2)}"),
        44: ("NEWTABLE", f"{r(dst)} = {{}}"),
        45: ("GE_CONST_CONST", f"{r(a)} = {c(k2)} >= {c(k1)}"),
        46: ("SETTABLE_CONST", f"{r(b)}[{r(a)}] = {c(k2)}"),
        47: ("CALL_1ARG_1RET", f"{r(dst)} = {r(dst)}({r(dst + 1) if isinstance(dst, int) else 'next'})"),
        48: ("GET_UPVALUE", f"{r(b)} = up[{value_repr(a)}]"),
        49: ("SETTABLE_REG", f"{r(a)}[{r(b)}] = {r(dst)}"),
        50: ("POW_REG_CONST", f"{r(dst)} = {r(a)} ^ {c(k1)}"),
        51: ("MOD_REG_REG", f"{r(a)} = {r(b)} % {r(dst)}"),
        52: ("GET_UPVALUE_FIELD", f"{r(b)} = up[{value_repr(a)}][{c(k2)}]"),
        53: ("CALL_RANGE_1RET", f"{r(a)} = {r(a)}(...range {r(a)}..{r(a)}+{value_repr(b)}-1)"),
        54: ("ADD_REG_CONST", f"{r(a)} = {r(b)} + {c(k2)}"),
        55: ("RETURN_VOID", "return"),
        56: ("DIV_REG_REG", f"{r(a)} = {r(b)} / {r(dst)}"),
        57: ("GETTABLE_REG", f"{r(b)} = {r(a)}[{r(dst)}]"),
        58: ("GT_CONST_REG", f"{r(b)} = {c(k2)} > {r(a)}"),
        59: ("CALL_RANGE_1RET_B", f"{r(b)} = {r(b)}(...range {r(b)}..last_call)"),
        60: ("SELF_CONST", f"{r(a)} = {r(dst)}; {r(a)} = {r(a)}[{c(k1)}]"),
        61: ("GET_GLOBAL_NAME_ALIAS", f"{r(dst)} = _ENV[{c(k3 if k3 is not None else b)}]"),
        62: ("MUL_CONST_CONST", f"{r(b)} = {c(k3)} * {c(k2)}"),
        63: ("CALL0_NORET", f"{r(dst)}()"),
        64: ("LT_CONST_CONST", f"{r(b)} = {c(k3)} < {c(k2)}"),
        65: ("GET_UPVALUE_TABLE_REG", f"{r(dst)} = up[{value_repr(b)}][{r(a)}]"),
        66: ("JMP_IF_NOT_EQ_REG", f"if {r(b)} ~= {r(a)} then pc = {value_repr(dst)} end"),
        67: ("JMP_IF_NOT_EQ_CONST", f"if {r(dst)} ~= {c(k3)} then pc = {value_repr(b)} end"),
        68: ("GT_REG_REG", f"{r(dst)} = {r(b)} > {r(a)}"),
        69: ("RETURN_RANGE_FROM", f"return r[{value_repr(dst)}..{value_repr(dst)}+{value_repr(a)}-2]"),
        70: ("GET_GLOBAL", f"{r(dst)} = _ENV[{c(b)}]"),
        71: ("MOD_REG_CONST", f"{r(b)} = {r(dst)} % {c(k3)}"),
        72: ("CLOSURE", f"{r(dst)} = closure({value_repr(k3)})"),
        73: ("SUB_REG_CONST", f"{r(dst)} = {r(b)} - {c(k3)}"),
        74: ("LE_CONST_CONST", f"{r(a)} = {c(k1)} <= {c(k2)}"),
        75: ("SUB_REG_REG", f"{r(b)} = {r(dst)} - {r(a)}"),
        76: ("LOADNIL", f"{r(a)} = nil"),
        77: ("RETURN_CALL_RANGE", f"return {r(b)}(...range {r(b)}..last_call)"),
        78: ("CONCAT_REG_REG", f"{r(b)} = {r(dst)} .. {r(a)}"),
        79: ("LEN", f"{r(b)} = #{r(dst)}"),
        80: ("LT_REG_REG", f"{r(b)} = {r(a)} < {r(dst)}"),
        81: ("GET_UPVALUE_DIRECT", f"{r(a)} = up[{value_repr(dst)}]"),
        83: ("FOR_PREP", f"prepare numeric for at {r(a)}; pc = {value_repr(b)}"),
        84: ("GT_CONST_CONST", f"{r(b)} = {c(k2)} > {c(k3)}"),
        85: ("MOVE", f"{r(dst)} = {r(b)}"),
        86: ("CALL_MULTI_ASSIGN", f"call {r(b)} and store returns from {r(b)}"),
        87: ("CALL_2ARGS_NORET", f"{r(a)}({r(a + 1) if isinstance(a, int) else 'next'}, {r(a + 2) if isinstance(a, int) else 'next2'})"),
        88: ("POW_REG_REG", f"{r(b)} = {r(dst)} ^ {r(a)}"),
        89: ("JMP_IF_NOT_LT_CONST_REG", f"if not ({c(k1)} < {r(a)}) then pc = {value_repr(dst)} end"),
        90: ("MUL_REG_REG", f"{r(dst)} = {r(a)} * {r(b)}"),
        91: ("POW_CONST_REG", f"{r(dst)} = {c(k3)} ^ {r(b)}"),
        92: ("CAPTURE_VARARGS", "capture current varargs"),
        93: ("UNM", f"{r(b)} = -{r(dst)}"),
        94: ("CALL0_1RET", f"{r(dst)} = {r(dst)}()"),
        95: ("LOAD_P", f"{r(a)} = P({value_repr(dst)})"),
        96: ("ADD_CONST_REG", f"{r(a)} = {c(k1)} + {r(dst)}"),
        97: ("LOAD_VARARG_PACK", f"copy {value_repr(dst)} varargs into registers"),
        98: ("NOT", f"{r(dst)} = not {r(a)}"),
        99: ("JMP_IF_EQ_REG", f"if {r(a)} == {r(b)} then pc = {value_repr(dst)} end"),
        100: ("EQ_REG_REG", f"{r(dst)} = {r(a)} == {r(b)}"),
        101: ("SETTABLE_CONST_CONST", f"{r(dst)}[{c(k3)}] = {c(k1)}"),
        102: ("GETTABLE_CONST", f"{r(a)} = {r(dst)}[{c(k1)}]"),
        103: ("SETTABLE_REG_CONSTKEY", f"{r(b)}[{c(k3)}] = {r(dst)}"),
        104: ("ADD_CONST_CONST", f"{r(a)} = {c(k2)} + {c(k1)}"),
        105: ("CALL_RANGE_NORET_B", f"{r(dst)}(...range {r(dst)}..{r(dst)}+{value_repr(b)}-1)"),
        106: ("TABLE_COPY_REGS", f"copy {value_repr(b)} regs from {r(a)} into {r(a)}[{value_repr(dst)}..]"),
        107: ("GET_ENV_SLOT", f"{r(b)} = env_slot[{c(k3)}]"),
        108: ("FOR_LOOP", f"advance numeric for; if active then pc = {value_repr(dst)} end"),
        109: ("GET_CONST_POOL", f"{r(b)} = const_pool[{value_repr(dst)}]"),
    }
    if isinstance(op, int) and op in known:
        return known[op]
    if isinstance(op, int) and op >= 108 and op != 109:
        return ("FOR_LOOP_ALIAS", f"advance numeric for alias op {op}; if active then pc = {value_repr(dst)} end")
    return (f"OP_{op}", f"op_{op} a={value_repr(a)} b={value_repr(b)} k1={value_repr(k1)} c={value_repr(dst)} k2={value_repr(k2)} k3={value_repr(k3)}")


RETURN_OPS = {2, 16, 31, 35, 55, 69, 77}
UNCOND_JUMP_OPS = {30}
COND_JUMP_FIELDS = {
    5: 3,
    7: 2,
    19: 5,
    38: 3,
    39: 5,
    66: 5,
    67: 3,
    83: 3,
    89: 5,
    99: 5,
    108: 5,
}


def instruction_successors(pc: int, instr: Instruction, count: int) -> list[int]:
    op, a, b, k1, dst, k2, k3 = instr_parts(instr)
    out: list[int] = []
    if op in RETURN_OPS:
        return out
    if op in UNCOND_JUMP_OPS:
        if isinstance(b, int) and 1 <= b <= count:
            return [b]
        return out
    jump_field = COND_JUMP_FIELDS.get(op)
    if isinstance(op, int) and op >= 108 and op != 109:
        jump_field = 5
    if jump_field is not None:
        target = instr[jump_field - 1]
        if isinstance(target, int) and 1 <= target <= count:
            out.append(target)
    if pc + 1 <= count:
        out.append(pc + 1)
    return list(dict.fromkeys(out))


def reachable_pcs(instructions: list[Instruction], start_pc: int = 1) -> set[int]:
    todo = [start_pc]
    seen: set[int] = set()
    while todo:
        pc = todo.pop()
        if pc in seen or pc < 1 or pc > len(instructions):
            continue
        seen.add(pc)
        todo.extend(instruction_successors(pc, instructions[pc - 1], len(instructions)))
    return seen


def extract_upvalues(data: dict[str, Any]) -> dict[str, Any]:
    upvalues = {}
    for item in data.get("upvalues", []):
        if isinstance(item, dict) and "name" in item:
            upvalues[str(item["name"])] = item.get("value")
    return upvalues


def collect_protos(root_value: Any) -> list[Proto]:
    protos: list[Proto] = []
    seen: set[int] = set()

    def walk(value: Any, name: str, path: str) -> None:
        if is_proto_like(value):
            ident = id(value)
            if ident in seen:
                return
            seen.add(ident)
            instrs = [normalize_instruction(x) for x in value[0]]
            protos.append(
                Proto(
                    name=name,
                    path=path,
                    instructions=instrs,
                    captures=value[1] if len(value) > 1 else None,
                    constants=value[2] if len(value) > 2 else None,
                    header=value[3] if len(value) > 3 else None,
                    seed=value[4] if len(value) > 4 else None,
                )
            )
            for pc, instr in enumerate(instrs, 1):
                for idx, part in enumerate(instr, 1):
                    if is_proto_like(part):
                        walk(part, f"{name}_pc{pc}_f{idx}", f"{path}[0][{pc - 1}][{idx}]")
            return
        if isinstance(value, list):
            for i, child in enumerate(value):
                walk(child, f"{name}_{i}", f"{path}[{i}]")
        elif isinstance(value, dict):
            for key, child in value.items():
                walk(child, f"{name}_{key}", f"{path}.{key}")

    walk(root_value, "root", "$")
    return protos


def printable_score(text: str) -> float:
    if not text:
        return 1.0
    ok = 0
    for ch in text:
        o = ord(ch)
        if ch in "\n\r\t" or 32 <= o < 127:
            ok += 1
    return ok / len(text)


SOURCE_TOKENS = (
    "local ",
    "function",
    "return ",
    "game:",
    "game.",
    "loadstring",
    "HttpGet",
    "require",
    "getgenv",
    "--[[",
)


def collect_strings(data: Any) -> list[dict[str, Any]]:
    found: list[tuple[str, str]] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, str):
            if not value.startswith("function:function:"):
                found.append((path, value))
        elif isinstance(value, list):
            for i, child in enumerate(value):
                walk(child, f"{path}[{i}]")
        elif isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str) and not key.isdigit():
                    found.append((f"{path}.<key>", key))
                walk(child, f"{path}.{key}")

    walk(data, "$")
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for path, text in found:
        if text in seen:
            continue
        seen.add(text)
        b = text.encode("utf-8", "surrogatepass")
        unique.append(
            {
                "path": path,
                "bytes": len(b),
                "chars": len(text),
                "sha256": hashlib.sha256(b).hexdigest(),
                "printable_score": round(printable_score(text), 3),
                "source_like": any(token in text for token in SOURCE_TOKENS),
                "preview": text[:1000],
            }
        )
    unique.sort(key=lambda x: (-int(x["bytes"]), str(x["path"])))
    return unique


def write_strings(path: Path, strings: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for item in strings:
            fh.write(f"--- bytes={item['bytes']} printable={item['printable_score']} source_like={item['source_like']} path={item['path']}\n")
            fh.write(item["preview"].encode("unicode_escape").decode("ascii"))
            fh.write("\n\n")


def write_pseudocode(path: Path, protos: list[Proto], limit: int | None) -> None:
    with path.open("w", encoding="utf-8") as fh:
        fh.write("-- Partial old Luraph v14 VM lift.\n")
        fh.write("-- This is not exact original source. It is a pseudo listing of the recovered VM instructions.\n\n")
        for proto in protos:
            start_pc = proto.seed if isinstance(proto.seed, int) and proto.seed > 0 else 1
            reachable = reachable_pcs(proto.instructions, start_pc)
            fh.write(f"-- proto {proto.name} path={proto.path} instructions={len(proto.instructions)} reachable_from_seed={len(reachable)} seed={value_repr(proto.seed)}\n")
            fh.write(f"local function {re.sub(r'[^A-Za-z0-9_]', '_', proto.name)}(...)\n")
            count = len(proto.instructions) if limit is None else min(len(proto.instructions), limit)
            for pc, instr in enumerate(proto.instructions[:count], 1):
                mnemonic, pseudo = semantic_for(instr)
                mark = "" if pc in reachable else " -- unreachable-from-pc1?"
                raw = ", ".join(value_repr(x, 42) for x in instr)
                fh.write(f"    -- [{pc:04d}] {mnemonic:<22} raw={{ {raw} }}{mark}\n")
                fh.write(f"    --      {pseudo}\n")
            if limit is not None and len(proto.instructions) > limit:
                fh.write(f"    -- ... truncated {len(proto.instructions) - limit} instructions; rerun with --limit 0 for all\n")
            fh.write("end\n\n")


def build_report(protos: list[Proto], strings: list[dict[str, Any]], state_path: Path) -> dict[str, Any]:
    all_ops: collections.Counter[int] = collections.Counter()
    proto_reports = []
    unknown_ops: collections.Counter[int] = collections.Counter()
    reachable_unknown_ops: collections.Counter[int] = collections.Counter()
    known_ops = set()
    for proto in protos:
        ops = collections.Counter()
        start_pc = proto.seed if isinstance(proto.seed, int) and proto.seed > 0 else 1
        reach = reachable_pcs(proto.instructions, start_pc)
        for instr in proto.instructions:
            op = instr[0]
            if isinstance(op, int):
                ops[op] += 1
                all_ops[op] += 1
                mnemonic, _ = semantic_for(instr)
                if mnemonic.startswith("OP_"):
                    unknown_ops[op] += 1
                else:
                    known_ops.add(op)
        for pc, instr in enumerate(proto.instructions, 1):
            op = instr[0]
            if isinstance(op, int) and pc in reach:
                mnemonic, _ = semantic_for(instr)
                if mnemonic.startswith("OP_"):
                    reachable_unknown_ops[op] += 1
        proto_reports.append(
            {
                "name": proto.name,
                "path": proto.path,
                "instructions": len(proto.instructions),
                "entry_pc": start_pc,
                "reachable_from_entry": len(reach),
                "captures": len(proto.captures) if isinstance(proto.captures, list) else None,
                "seed": proto.seed,
                "opcode_histogram": dict(sorted(ops.items())),
            }
        )
    return {
        "input_state": str(state_path),
        "exact_recovery_status": "not_recovered",
        "exact_recovery_reason": "final state contains virtualized bytecode/prototypes, not exact source text",
        "artifact_kind": "partial_vm_lift",
        "proto_count": len(protos),
        "total_instructions": sum(len(p.instructions) for p in protos),
        "known_opcode_count": len(known_ops),
        "unknown_opcode_histogram": dict(sorted(unknown_ops.items())),
        "reachable_unknown_opcode_histogram": dict(sorted(reachable_unknown_ops.items())),
        "opcode_histogram_all_protos": dict(sorted(all_ops.items())),
        "string_count": len(strings),
        "source_like_string_count": sum(1 for item in strings if item["source_like"]),
        "source_like_strings": [
            {k: item[k] for k in ("path", "bytes", "sha256", "preview")}
            for item in strings
            if item["source_like"]
        ][:50],
        "protos": proto_reports,
    }


def write_markdown(path: Path, report: dict[str, Any], artifacts: dict[str, Path]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        fh.write("# Old Luraph VM Lift Report\n\n")
        fh.write(f"- Exact recovery status: `{report['exact_recovery_status']}`\n")
        fh.write(f"- Reason: {report['exact_recovery_reason']}\n")
        fh.write(f"- Proto count: `{report['proto_count']}`\n")
        fh.write(f"- Total instructions: `{report['total_instructions']}`\n")
        fh.write(f"- Known opcode count: `{report['known_opcode_count']}`\n")
        fh.write(f"- Unique strings: `{report['string_count']}`\n")
        fh.write(f"- Source-like strings: `{report['source_like_string_count']}`\n\n")
        fh.write("## Artifacts\n\n")
        for name, artifact in artifacts.items():
            fh.write(f"- `{name}`: `{artifact}`\n")
        fh.write("\n## Unknown Opcodes\n\n")
        unknown = report.get("unknown_opcode_histogram", {})
        if unknown:
            for op, count in unknown.items():
                fh.write(f"- `{op}`: `{count}`\n")
        else:
            fh.write("- None in the current opcode map.\n")
        fh.write("\n## Reachable Unknown Opcodes\n\n")
        reachable_unknown = report.get("reachable_unknown_opcode_histogram", {})
        if reachable_unknown:
            for op, count in reachable_unknown.items():
                fh.write(f"- `{op}`: `{count}`\n")
        else:
            fh.write("- None from the recovered entry PCs.\n")
        fh.write("\n## Source-like Strings\n\n")
        for item in report.get("source_like_strings", [])[:20]:
            preview = str(item["preview"]).replace("\n", "\\n")
            if len(preview) > 240:
                preview = preview[:237] + "..."
            fh.write(f"- bytes `{item['bytes']}` at `{item['path']}`: `{preview}`\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path, help="final VM state JSON")
    parser.add_argument("--out", type=Path, default=Path("work/old-luraph-lift"), help="output directory")
    parser.add_argument("--limit", type=int, default=0, help="instructions per proto in pseudo output; 0 means all")
    args = parser.parse_args(argv)

    data = json.loads(args.state.read_text(errors="replace"))
    upvalues = extract_upvalues(data)
    root = upvalues.get("I")
    if not is_proto_like(root):
        root = [upvalues.get("Z"), [], [], 0, upvalues.get("J")]
    protos = collect_protos(root)
    if not protos:
        print("no Luraph proto-like tables found", file=sys.stderr)
        return 2

    args.out.mkdir(parents=True, exist_ok=True)
    strings = collect_strings(data)

    pseudo_path = args.out / "old_luraph_decompiled_fallback.luau"
    strings_path = args.out / "old_luraph_strings.txt"
    report_path = args.out / "old_luraph_opcode_report.json"
    md_path = args.out / "old_luraph_lift_report.md"

    write_pseudocode(pseudo_path, protos, None if args.limit == 0 else args.limit)
    write_strings(strings_path, strings)
    report = build_report(protos, strings, args.state)
    artifacts = {
        "pseudo_luau": pseudo_path,
        "strings": strings_path,
        "json_report": report_path,
        "markdown_report": md_path,
    }
    report["artifacts"] = {k: str(v) for k, v in artifacts.items()}
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    write_markdown(md_path, report, artifacts)

    print(f"Wrote {pseudo_path}")
    print(f"Wrote {strings_path}")
    print(f"Wrote {report_path}")
    print(f"Wrote {md_path}")
    print(f"Protos: {report['proto_count']}  instructions: {report['total_instructions']}  strings: {report['string_count']}")
    print(f"Exact status: {report['exact_recovery_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
