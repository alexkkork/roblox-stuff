#!/usr/bin/env python3
"""Lift decoded KeyForge/Goofyscator VM chunks into Lua-like pseudocode."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


MODE_REG = 3935
MODE_IMM = 31988
MODE_CONST_A = 15639
MODE_CONST_B = 6166


BINOPS = {
    25985: "==",
    4108: "~=",
    23981: ">",
    21597: ">=",
    32270: "<",
    501: "<=",
    14808: "+",
    18562: "-",
    31748: "*",
    7605: "/",
    21670: "%",
    19815: "^",
    1193: "..",
    26184: "and",
    10168: "or",
}


def lua_string(value: str) -> str:
    out = ['"']
    for ch in value:
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
        elif 32 <= code <= 126:
            out.append(ch)
        elif code <= 255:
            out.append(f"\\{code:03d}")
        else:
            out.append(f"\\u{{{code:x}}}")
    out.append('"')
    return "".join(out)


def lua_value(value: Any) -> str:
    if value is None:
        return "nil"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return lua_string(value)
    if isinstance(value, dict):
        if "12453" in value:
            proto = value.get("12453")
            captures = value.get("15193") or ""
            suffix = f", captures={lua_string(captures)}" if captures else ""
            return f"<proto {proto}{suffix}>"
        return "{...}"
    if isinstance(value, list):
        return "{...}"
    return repr(value)


def reg(value: Any) -> str:
    try:
        return f"r{int(value)}"
    except (TypeError, ValueError):
        return "r_unknown"


def dst(ins: dict[str, Any]) -> str:
    return reg(int(ins.get("8", 5)) - 5)


def raw_dst(ins: dict[str, Any]) -> int:
    return int(ins.get("8", 5)) - 5


def op_index(op: Any) -> int:
    if isinstance(op, dict):
        return int(op.get("17753", 0))
    if isinstance(op, int):
        return op
    return 0


def operand(op: Any) -> str:
    if not isinstance(op, dict):
        return lua_value(op)
    if "__constant_value" in op:
        return lua_value(op["__constant_value"])
    if "15711" in op:
        return lua_value(op["15711"])
    mode = int(op.get("22900", 5388))
    value = int(op.get("17753", 0))
    if mode == MODE_REG:
        return f"r{value}"
    if mode == MODE_IMM:
        return str(value)
    if mode in (MODE_CONST_A, MODE_CONST_B):
        return f"K[{value}]"
    if mode == 5388:
        return "nil"
    return f"<op mode={mode} value={value}>"


def ops(ins: dict[str, Any]) -> list[Any]:
    value = ins.get("3")
    return value if isinstance(value, list) else []


def op1(ins: dict[str, Any]) -> str:
    value = ops(ins)
    return operand(value[0]) if len(value) > 0 else "nil"


def op2(ins: dict[str, Any]) -> str:
    value = ops(ins)
    return operand(value[1]) if len(value) > 1 else "nil"


def op1_index(ins: dict[str, Any]) -> int:
    value = ops(ins)
    return op_index(value[0]) if len(value) > 0 else 0


def op2_index(ins: dict[str, Any]) -> int:
    value = ops(ins)
    return op_index(value[1]) if len(value) > 1 else 0


def jump_target(ins: dict[str, Any]) -> int:
    return op2_index(ins)


def call_args(base: int, count: int) -> str:
    if count < 0:
        return f"{reg(base + 1)}, ..."
    return ", ".join(reg(base + i) for i in range(1, count + 1))


def call_returns(base: int, count: int) -> str:
    if count < 0:
        return f"{reg(base)}, ..."
    return ", ".join(reg(base + i) for i in range(count))


def lift_instruction(ins: dict[str, Any], indent: str = "") -> list[str]:
    name = ins.get("__handler_name", "<unknown>")
    d = dst(ins)
    dnum = raw_dst(ins)
    a = op1(ins)
    b = op2(ins)
    a_i = op1_index(ins)
    b_i = op2_index(ins)
    lines: list[str] = []

    if name == "gQSlX":
        lines.append(f"{indent}do")
        for sub in ins.get("2") or []:
            if isinstance(sub, dict):
                lines.extend(lift_instruction(sub, indent + "    "))
        lines.append(f"{indent}end")
    elif name == "gHsX":
        lines.append(f"{indent}-- noop")
    elif name == "aBJLT":
        lines.append(f"{indent}{d} = {b}")
    elif name in {"HizZR", "JXZK"}:
        lines.append(f"{indent}{d} = _ENV[{b}]")
    elif name == "LE":
        lines.append(f"{indent}{d} = {d}[{b}]")
    elif name in {"RKh", "hhJSn"}:
        lines.append(f"{indent}{d}[{b}] = {a}")
    elif name == "pG":
        code = ins.get("6")
        op = BINOPS.get(code, f"<binop {code}>")
        lines.append(f"{indent}{d} = {b} {op} {a}")
    elif name == "uQ":
        lines.append(f"{indent}{d} = {reg(b_i)} * {a_i}")
    elif name == "DwJ":
        lines.append(f"{indent}{d} = {reg(b_i)} + {a_i}")
    elif name == "qda":
        lines.append(f"{indent}{d} = {reg(b_i)} - {a_i}")
    elif name == "HHgh":
        lines.append(f"{indent}{d} = {reg(b_i)} / {a_i}")
    elif name in {"fF", "Oqu"}:
        lines.append(f"{indent}{d} = {b}")
    elif name == "XUOG":
        extra = ins.get("6")
        lines.append(f"{indent}{d} = {b}")
        lines.append(f"{indent}{reg(a_i)} = {reg(extra)}")
    elif name == "P":
        lines.append(f"{indent}{d} = {{}}")
    elif name == "BcY":
        lines.append(f"{indent}{d} = nil")
    elif name in {"en", "n"}:
        lines.append(f"{indent}{d} = true")
    elif name == "MX":
        lines.append(f"{indent}{d} = not {d}")
    elif name == "IEb":
        lines.append(f"{indent}{d} = #{d}")
    elif name == "Lvt":
        lines.append(f"{indent}{d} = {b_i}")
    elif name == "Dk":
        lines.append(f"{indent}{d}, ... = ...")
    elif name == "uftj":
        lines.append(f"{indent}-- fill {d} from register range r{a_i}..r{b_i}")
    elif name == "BHsCD":
        proto = ins.get("6", {})
        lines.append(f"{indent}{d} = function(...) -- {lua_value(proto)}")
        lines.append(f"{indent}    return proto_{proto.get('12453') if isinstance(proto, dict) else 'unknown'}(...)")
        lines.append(f"{indent}end")
    elif name == "se":
        extra = ins.get("6")
        arg_count = b_i
        ret_count = a_i
        args = call_args(dnum, arg_count)
        if ret_count == 0:
            lines.append(f"{indent}{d}({args})")
        else:
            lines.append(f"{indent}{call_returns(dnum, ret_count)} = {d}({args})")
    elif name == "FFTv":
        lines.append(f"{indent}return {d}, ...")
    elif name == "bHv":
        lines.append(f"{indent}goto pc_{jump_target(ins)}")
    elif name in {"O", "EWj", "JqmZA", "rx"}:
        lines.append(f"{indent}-- jump relative {jump_target(ins)}")
    elif name == "cDSx":
        lines.append(f"{indent}if not {d} then goto pc_{jump_target(ins)} end")
    elif name == "Lvsqy":
        lines.append(f"{indent}-- numeric-for prepare {d}; if done goto pc_{jump_target(ins)}")
    elif name == "ryj":
        lines.append(f"{indent}{d} = {d} + {reg(ins.get('6'))}; if loop continues then goto pc_{jump_target(ins)} end")
    elif name == "z":
        lines.append(f"{indent}-- close/upvalue sync {d}")
    elif name == "mJu":
        lines.append(f"{indent}{d} = {d}[{b}] -- method lookup")
    else:
        raw = json.dumps(ins, ensure_ascii=False, sort_keys=True)
        if len(raw) > 240:
            raw = raw[:237] + "..."
        lines.append(f"{indent}-- {name}: {raw}")

    if "__decode_error" in ins:
        lines.append(f"{indent}-- decoder side-effect stopped: {lua_string(str(ins['__decode_error']))}")
    return lines


def proto_label(key: str, proto: dict[str, Any], chunk_no: int) -> str:
    if key == "__root__":
        return f"chunk_{chunk_no}_root"
    return f"proto_{key}"


def lift_proto(label: str, proto: dict[str, Any]) -> list[str]:
    ins = proto.get("23709") if isinstance(proto, dict) else None
    if not isinstance(ins, dict):
        return [f"-- {label}: no decoded instructions"]
    count = int(ins.get("0", 0))
    lines = [f"local function {label}(...)", "    local r = {}", "    -- registers are shown as r0, r1, ...; labels preserve VM program counters."]
    for pc in range(1, count + 1):
        item = ins.get(str(pc))
        lines.append(f"    ::pc_{pc}::")
        if isinstance(item, dict):
            lines.extend(lift_instruction(item, "    "))
        else:
            lines.append(f"    -- missing instruction {pc}")
    lines.append("end")
    return lines


def collect_protos(chunk: Any, chunk_no: int) -> list[tuple[str, dict[str, Any]]]:
    protos: list[tuple[str, dict[str, Any]]] = []
    if not isinstance(chunk, list) or len(chunk) < 1:
        return protos
    if isinstance(chunk[0], dict):
        protos.append((proto_label("__root__", chunk[0], chunk_no), chunk[0]))
    if len(chunk) > 1 and isinstance(chunk[1], dict):
        for key in sorted(chunk[1], key=str):
            value = chunk[1][key]
            if isinstance(value, dict) and "23709" in value:
                protos.append((proto_label(str(key), value, chunk_no), value))
    return protos


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decoded_dir", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    files = sorted(args.decoded_dir.glob("full_chunk_*.json"))
    if not files:
        raise SystemExit(f"no full_chunk_*.json files in {args.decoded_dir}")

    output: list[str] = [
        "-- Devirtualized KeyForge/Goofyscator VM listing",
        "-- This is lifted semantic Luau, not a byte-for-byte original-source recovery.",
        "",
    ]
    for idx, path in enumerate(files, 1):
        data = json.loads(path.read_text(errors="replace"))
        output.append(f"-- ===== {path.name} =====")
        for label, proto in collect_protos(data.get("chunk"), idx):
            output.extend(lift_proto(label, proto))
            output.append("")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(output), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
