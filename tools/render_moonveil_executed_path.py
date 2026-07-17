#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


OPNAMES = {
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render MoonVeil VM dispatch traces as executed-path pseudocode.")
    parser.add_argument("trace_dir", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-change", type=int, default=160)
    return parser.parse_args()


def coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value))
    except ValueError:
        return None


def parse_trace_file(path: Path) -> dict[str, str]:
    item = {"path": str(path)}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        item[key] = value
    return item


def load_traces(trace_dir: Path) -> list[dict[str, str]]:
    return [parse_trace_file(path) for path in sorted(trace_dir.glob("moonveil_dispatch_trace_*.txt"))]


def load_diffs(trace_dir: Path) -> dict[str, dict[str, Any]]:
    path = trace_dir / "moonveil_dispatch_diff.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    return {str(item.get("after_trace")): item for item in data.get("diffs", [])}


def q(text: Any, limit: int = 96) -> str:
    if text is None:
        return "?"
    raw = str(text)
    if len(raw) > limit:
        raw = raw[: limit - 3] + "..."
    return json.dumps(raw, ensure_ascii=True)


def reg_from(value: Any, bias: int = 0) -> str:
    number = coerce_int(value)
    if number is None:
        return "R?"
    return f"R{number - bias}"


def pc_label(value: Any) -> str:
    number = coerce_int(value)
    if number is None:
        return "pc_?"
    return f"pc_{number:03d}"


def render_op(row: dict[str, str]) -> str:
    op = coerce_int(row.get("op"))
    a = row.get("a")
    b = row.get("b")
    c = row.get("c")
    lit = row.get("lit")
    d37c = row.get("d37c")
    i1 = row.get("i1")
    i2 = row.get("i2")
    name = OPNAMES.get(op, f"unknown_{op}") if op is not None else "missing_op"

    if op == 39:
        return f"goto {pc_label(row.get('jump_target') or i2)}"
    if op == 42:
        return f"-- string metadata literal {q(lit)}"
    if op == 45:
        return f"{reg_from(a, 0x3b)} = ({reg_from(b, 0x2c)} == {reg_from(c, 0x1f)})"
    if op == 48:
        return f"{reg_from(a)} = ENV[{q(lit)}]"
    if op == 58:
        return f"{reg_from(a)} = not {reg_from(b)}"
    if op == 91:
        return f"{reg_from(a)} = {q(row.get('number') or lit)}"
    if op == 97:
        return f"{reg_from(a, 0x29)} = U{(coerce_int(b) or 0) - 0x1e}"
    if op == 105:
        return f"CALLPREP target={reg_from(a, 2)} raw_b={b}"
    if op == 106:
        argc = coerce_int(b)
        retctl = coerce_int(c)
        return f"CALL {reg_from(a, 0x17)} argc={argc - 0x28 if argc is not None else '?'} retctl={retctl - 0x3d if retctl is not None else '?'}"
    if op == 113:
        return f"{reg_from(a)} = {reg_from(b)} * {reg_from(c)}"
    if op == 133:
        return f"{reg_from(a)} = nil"
    if op == 137:
        return f"{reg_from(a, 0x14)} = NEWCLOSURE selector={d37c}; consume following capture descriptors"
    if op == 153:
        return f"{reg_from(a, 0xe)} = {reg_from(b, 0x24)}[{q(lit)}]"
    if op == 170:
        return f"{reg_from(a, 0x2a)} = #{reg_from(b, 0x3b)}"
    if op == 176:
        return f"{reg_from(a)} = {reg_from(b)}[{q(lit)}]"
    if op == 180:
        return f"STRING_BLOCK_FINALIZE raw_a={a} raw_b={b}"
    if op == 182:
        return f"RETURN_PACK_SETUP raw_a={a}"
    if op == 189:
        return f"BRANCH {reg_from(a)} -> {pc_label(i2)} aux={q(i1)}"
    if op == 201:
        return f"{reg_from(a)} = {reg_from(b)} - {reg_from(c)}"
    if op == 207:
        return f"{reg_from(a, 0x25)} = {reg_from(b)} .. {reg_from(c, 0x2e)}"
    if op == 209:
        return f"RETURN_OR_TRAMPOLINE raw_a={a} raw_b={b}"
    if op == 210:
        return f"{reg_from(a, 0x13)} = {reg_from(b, 0x24)}"
    if op == 224:
        proto = coerce_int(d37c)
        return f"{reg_from(a, 0x14)} = NEWCLOSURE proto[{proto - 0x3f if proto is not None else '?'}]"
    if op == 226:
        return f"{reg_from(a)} = literal({q(lit)})"
    if op == 227:
        return f"CAPTURE_DESCRIPTOR raw_a={a} raw_b={b}"
    return f"{name}(raw_a={a}, raw_b={b}, raw_c={c}, lit={q(lit)})"


def simplify_value(value: Any, limit: int) -> str:
    if value is None:
        return "nil"
    text = str(value)
    text = text.replace("\n", "\\n")
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def interesting_change(key: str, change: dict[str, Any]) -> bool:
    if key.startswith("r"):
        return True
    before = str(change.get("from"))
    after = str(change.get("to"))
    return "string(" in before or "string(" in after or "function:" in before or "function:" in after


def extract_string_payloads(trace_dir: Path) -> list[dict[str, Any]]:
    rows = []
    index_path = trace_dir / "capture_index.jsonl"
    if not index_path.exists():
        return rows
    seen = set()
    for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = str(item.get("kind", ""))
        if not kind.startswith(("moonveil_vm_string", "moonveil_return_frame_string", "moonveil_return_string")):
            continue
        path = Path(str(item.get("path", "")))
        if not path.exists():
            path = trace_dir / path.name
        if not path.exists():
            continue
        data = path.read_bytes()
        sig = (len(data), data)
        if sig in seen:
            continue
        seen.add(sig)
        printable = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13)) / len(data) if data else 1.0
        rows.append(
            {
                "kind": kind,
                "bytes": len(data),
                "printable_ratio": round(printable, 4),
                "hex": data.hex(),
                "preview": data[:80].decode("utf-8", errors="replace").replace("\n", "\\n"),
            }
        )
    rows.sort(key=lambda item: (-item["bytes"], item["hex"]))
    return rows


def main() -> int:
    args = parse_args()
    traces = load_traces(args.trace_dir)
    diffs = load_diffs(args.trace_dir)
    payloads = extract_string_payloads(args.trace_dir)

    lines = [
        "-- MoonVeil executed-path deobfuscation.",
        "-- This is not exact original source; it is the traced VM path rendered as readable pseudocode.",
        f"-- trace_dir: {args.trace_dir}",
        f"-- dispatches: {len(traces)}",
        f"-- unique_vm_payload_strings: {len(payloads)}",
        "",
        "-- Unique VM strings seen on the executed path:",
    ]
    for item in payloads[:80]:
        lines.append(
            f"--   bytes={item['bytes']} printable={item['printable_ratio']} kind={item['kind']} "
            f"hex={item['hex'][:160]} preview={q(item['preview'], 80)}"
        )
    if len(payloads) > 80:
        lines.append(f"--   ... {len(payloads) - 80} more omitted")

    lines.extend(["", "local R = {}", "local U = {}", ""])
    for row in traces:
        trace = row.get("trace", "?")
        op = coerce_int(row.get("op"))
        op_text = "???" if op is None else f"{op:03d}"
        name = OPNAMES.get(op, f"unknown_{op}") if op is not None else "missing_op"
        lines.append(f"-- trace {trace} pc {row.get('pc', '?')} op {op_text} {name}")
        lines.append("-- " + render_op(row))
        diff = diffs.get(str(trace))
        if diff:
            changes = [
                (key, change)
                for key, change in diff.get("changed", {}).items()
                if interesting_change(key, change)
            ]
            for key, change in changes[:12]:
                before = simplify_value(change.get("from"), args.max_change)
                after = simplify_value(change.get("to"), args.max_change)
                lines.append(f"--   {key}: {before} -> {after}")
            if len(changes) > 12:
                lines.append(f"--   ... {len(changes) - 12} more register/hidden changes")
        lines.append("")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    print(f"dispatches={len(traces)} payload_strings={len(payloads)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
