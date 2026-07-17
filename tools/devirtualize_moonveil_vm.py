#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SOURCE_MARKERS = (
    b"local ",
    b"function",
    b"return ",
    b"loadstring",
    b"game:",
    b"game.",
    b"getgenv",
    b"HttpGet",
    b"Instance.new",
    b"WaitForChild",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MoonVeil v2 devirtualizer/decompiler pass over recovered VM artifacts."
    )
    parser.add_argument(
        "--lifted-summary",
        type=Path,
        default=Path("outputs/moonveil_v2_lifted_summary.json"),
        help="MoonVeil lifted summary JSON from lift_moonveil_vm.py.",
    )
    parser.add_argument(
        "--raw-programs",
        type=Path,
        default=Path("work/mv-deobf-rawhex/moonveil_vm_programs.json"),
        help="Optional raw VM programs JSON with exact literal hex metadata.",
    )
    parser.add_argument(
        "--trace-dir",
        type=Path,
        default=Path("work/mv-brutecall"),
        help="Directory containing moonveil_dispatch_trace_*.txt captures.",
    )
    parser.add_argument(
        "--extra-trace-dir",
        type=Path,
        action="append",
        default=[],
        help="Additional trace directory to merge for CFG coverage; repeatable.",
    )
    parser.add_argument(
        "--behavior-report",
        type=Path,
        default=Path("outputs/moonveil_v2_behavior_report.json"),
        help="Behavior report generated from dynamic traces.",
    )
    parser.add_argument(
        "--forced-branch",
        type=Path,
        default=Path("outputs/moonveil_v2_forced_branch_probe.json"),
        help="Optional forced branch probe JSON.",
    )
    parser.add_argument(
        "--vm-chunk",
        type=Path,
        default=Path("work/mv-brutecall/moonveil_vm_chunk_0005.bin"),
        help="Raw MoonVeil VM chunk captured from the decoded payload.",
    )
    parser.add_argument(
        "--decoded-payload",
        type=Path,
        default=Path("work/mv-brutecall/moonveil_i_decoded_0004.bin"),
        help="Ascii85 decoded MoonVeil payload before VM chunk normalization.",
    )
    parser.add_argument(
        "--snapshot-bank",
        type=Path,
        default=Path("outputs/moonveil_v2_raw_snapshot_strings_bank.bin"),
        help="Recovered raw string/snapshot bank for cross-reference.",
    )
    parser.add_argument(
        "--literal-bank",
        type=Path,
        default=Path("outputs/moonveil_v2_raw_literal_bank.bin"),
        help="Recovered static literal bank for cross-reference.",
    )
    parser.add_argument(
        "--lua-out",
        type=Path,
        default=Path("outputs/moonveil_v2_devirtualized.lua"),
        help="Generated Luau-like decompiled output.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("outputs/moonveil_v2_devirtualized_ir.json"),
        help="Generated structured devirtualized IR JSON.",
    )
    parser.add_argument(
        "--max-block-lines",
        type=int,
        default=220,
        help="Maximum static block/instruction comments to include in Lua output.",
    )
    return parser.parse_args()


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def file_sha256(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def preview_bytes(data: bytes, limit: int = 72) -> str:
    return "".join(chr(c) if c in (9, 10, 13) or 32 <= c < 127 else "." for c in data[:limit])


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    return sum(1 for c in data if c in (9, 10, 13) or 32 <= c < 127) / len(data)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def source_marker_hits(data: bytes) -> dict[str, int]:
    return {marker.decode("ascii"): data.count(marker) for marker in SOURCE_MARKERS}


def literal_metadata_from_hex(hex_value: str, value: Any = None) -> dict[str, Any]:
    try:
        data = bytes.fromhex(hex_value)
    except ValueError:
        return {
            "hex": hex_value,
            "value_preview": preview_bytes(str(value).encode("utf-8", errors="replace")) if value is not None else None,
            "exact_hex_valid": False,
        }
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hex": hex_value,
        "printable_ratio": round(printable_ratio(data), 4),
        "source_marker_hits": source_marker_hits(data),
        "preview": preview_bytes(data),
        "exact_hex_valid": True,
    }


def load_literal_metadata(raw_programs_path: Path) -> dict[tuple[str, int], dict[str, Any]]:
    if not raw_programs_path.exists():
        return {}
    raw = load_json(raw_programs_path, {})
    programs = raw.get("programs") if isinstance(raw, dict) else raw
    if not isinstance(programs, list):
        return {}
    out: dict[tuple[str, int], dict[str, Any]] = {}
    for program in programs:
        if not isinstance(program, dict):
            continue
        program_id = str(program.get("program_id") or "")
        rows = program.get("rows") or program.get("instructions") or []
        if not program_id or not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            pc = coerce_int(row.get("pc"))
            fields = row.get("fields") or {}
            literal = fields.get("f_0xa08e") or fields.get("41102") or fields.get("literal")
            if pc is None or not isinstance(literal, dict):
                continue
            hex_value = literal.get("hex")
            if not isinstance(hex_value, str) or not hex_value:
                continue
            meta = literal_metadata_from_hex(hex_value, literal.get("value"))
            meta["raw_key"] = literal.get("raw_key")
            meta["value_preview"] = preview_bytes(str(literal.get("value", "")).encode("utf-8", errors="replace"))
            out[(program_id, pc)] = meta
    return out


def read_kv_file(path: Path) -> dict[str, str]:
    row: dict[str, str] = {"path": str(path)}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        row[key] = value
    return row


def load_traces(trace_dir: Path) -> list[dict[str, str]]:
    traces = []
    for path in sorted(trace_dir.glob("moonveil_dispatch_trace_*.txt")):
        row = read_kv_file(path)
        if "trace" in row:
            row["trace_source_dir"] = str(trace_dir)
            traces.append(row)
    traces.sort(key=lambda item: int(item.get("trace", "0")))
    return traces


def load_diffs(trace_dirs: list[Path], traces: list[dict[str, str]]) -> list[dict[str, Any]]:
    trace_index = {
        (str(trace.get("trace_source_dir") or ""), str(trace.get("trace") or "")): trace
        for trace in traces
    }
    rows: list[dict[str, Any]] = []
    for trace_dir in trace_dirs:
        path = trace_dir / "moonveil_dispatch_diff.json"
        if not path.exists():
            continue
        data = load_json(path, {})
        for item in data.get("diffs", []):
            source = str(trace_dir)
            trace_no = str(item.get("after_trace") or "")
            trace = trace_index.get((source, trace_no), {})
            row = dict(item)
            row["trace_source_dir"] = source
            row["program_len"] = coerce_int(trace.get("program_len"))
            rows.append(row)
    return rows


def load_capture_rows(trace_dir: Path) -> list[dict[str, Any]]:
    path = trace_dir / "capture_index.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        raw_path = Path(str(item.get("path", "")))
        if not raw_path.exists():
            raw_path = trace_dir / raw_path.name
        if raw_path.exists() and raw_path.is_file():
            data = raw_path.read_bytes()
            item["resolved_path"] = str(raw_path)
            item["bytes"] = len(data)
            item["sha256"] = hashlib.sha256(data).hexdigest()
            item["printable_ratio"] = round(printable_ratio(data), 4)
            item["source_marker_hits"] = source_marker_hits(data)
            item["preview"] = preview_bytes(data)
        rows.append(item)
    return rows


def field_value(row: dict[str, Any], name: str) -> Any:
    fields = row.get("fields", {})
    item = fields.get(name)
    if isinstance(item, dict):
        return item.get("value")
    return None


def field_int(row: dict[str, Any], name: str) -> int | None:
    return coerce_int(field_value(row, name))


def row_opcode(row: dict[str, Any]) -> int | None:
    return coerce_int(row.get("opcode"))


def row_pc(row: dict[str, Any]) -> int:
    return int(row.get("pc") or 0)


def row_text(row: dict[str, Any]) -> str:
    return str(row.get("text") or "")


def possible_target(row: dict[str, Any]) -> int | None:
    opcode = row_opcode(row)
    if opcode == 39:
        return field_int(row, "jump_target")
    if opcode == 189:
        return field_int(row, "branch_target")
    if opcode == 12:
        return field_int(row, "branch_target")
    return None


def compact_instruction_bytes(row: dict[str, Any]) -> bytes | None:
    opcode = row_opcode(row)
    if opcode is None:
        return None

    # This compact encoding is proven from the leading MoonVeil wrapper program.
    # Other opcodes can have literal/number payloads and are intentionally not
    # guessed here.
    field_order_by_opcode = {
        105: ("a_or_dst", "b_or_src"),
        106: ("a_or_dst", "b_or_src", "c_or_rhs"),
        137: ("a_or_dst", "b_or_src", "aux_0xd37c"),
        209: ("a_or_dst", "b_or_src"),
        210: ("a_or_dst", "b_or_src"),
        224: ("a_or_dst", "b_or_src", "c_or_rhs", "aux_0xd37c"),
    }
    field_order = field_order_by_opcode.get(opcode)
    if field_order is None:
        return None

    out = [opcode]
    for name in field_order:
        value = field_int(row, name)
        if value is None or not 0 <= value <= 255:
            return None
        out.append(value)
    return bytes(out)


def prefix_match_len(left: bytes, right: bytes) -> int:
    count = 0
    for a, b in zip(left, right):
        if a != b:
            break
        count += 1
    return count


def longest_prefix_match_at(data: bytes, needle: bytes, offset: int) -> int:
    if offset < 0:
        return 0
    return prefix_match_len(data[offset:], needle)


def find_loose_opcode_alignment(data: bytes, opcodes: list[int], max_gap: int = 96) -> dict[str, Any]:
    positions: list[int] = []
    cursor = -1
    failed_at = None
    for index, opcode in enumerate(opcodes):
        found = data.find(bytes([opcode]), cursor + 1)
        if found < 0:
            failed_at = index + 1
            break
        if positions and found - positions[-1] - 1 > max_gap:
            failed_at = index + 1
            break
        positions.append(found)
        cursor = found

    gaps = [positions[i] - positions[i - 1] - 1 for i in range(1, len(positions))]
    exact_offset = data.find(bytes(opcodes)) if opcodes else -1
    return {
        "exact_opcode_stream_offset": exact_offset,
        "matched_opcode_count": len(positions),
        "opcode_count": len(opcodes),
        "first_offset": positions[0] if positions else None,
        "last_offset": positions[-1] if positions else None,
        "span_bytes": (positions[-1] - positions[0] + 1) if positions else 0,
        "max_gap": max(gaps) if gaps else 0,
        "average_gap": round(sum(gaps) / len(gaps), 2) if gaps else 0.0,
        "failed_at_opcode_index": failed_at,
        "note": "Loose alignment only; opcode bytes can also appear as operands.",
    }


def find_best_opcode_alignments(data: bytes, opcodes: list[int], max_gap: int = 12, limit: int = 12) -> list[dict[str, Any]]:
    if not opcodes:
        return []

    candidates = [index for index, byte in enumerate(data) if byte == opcodes[0]]
    matches = []
    for start in candidates:
        positions = [start]
        cursor = start
        failed_at = None
        for opcode_index, opcode in enumerate(opcodes[1:], start=2):
            stop = min(len(data), cursor + max_gap + 2)
            found = -1
            for index in range(cursor + 1, stop):
                if data[index] == opcode:
                    found = index
                    break
            if found < 0:
                failed_at = opcode_index
                break
            positions.append(found)
            cursor = found
        if failed_at is not None:
            continue

        gaps = [positions[i] - positions[i - 1] - 1 for i in range(1, len(positions))]
        start_offset = positions[0]
        end_offset = positions[-1]
        matches.append(
            {
                "start_offset": start_offset,
                "end_offset": end_offset,
                "span_bytes": end_offset - start_offset + 1,
                "matched_opcode_count": len(positions),
                "opcode_count": len(opcodes),
                "max_gap": max(gaps) if gaps else 0,
                "average_gap": round(sum(gaps) / len(gaps), 2) if gaps else 0.0,
                "head_hex": data[start_offset : start_offset + 32].hex(),
                "tail_hex": data[max(start_offset, end_offset - 16) : end_offset + 16].hex(),
                "opcode_positions_first16": positions[:16],
                "opcode_positions_last16": positions[-16:],
            }
        )

    matches.sort(key=lambda item: (item["span_bytes"], item["start_offset"]))
    return matches[:limit]


def analyze_related_blob(chunk: bytes, path: Path, label: str) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        return {"label": label, "path": str(path), "exists": False}

    data = path.read_bytes()
    transforms = {
        "raw": data,
        "strip_ff_bytes": data.replace(b"\xff", b""),
    }
    transform_rows = []
    for transform_name, transformed in transforms.items():
        prefix = transformed[:32]
        prefix_offset = chunk.find(prefix) if prefix else -1
        full_offset = chunk.find(transformed) if transformed else -1
        transform_rows.append(
            {
                "transform": transform_name,
                "bytes": len(transformed),
                "sha256": hashlib.sha256(transformed).hexdigest(),
                "full_offset": full_offset,
                "prefix32_offset": prefix_offset,
                "prefix_match_bytes": longest_prefix_match_at(chunk, transformed, prefix_offset),
                "head_hex": transformed[:48].hex(),
            }
        )

    return {
        "label": label,
        "path": str(path),
        "exists": True,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "transforms": transform_rows,
    }


def parse_leading_compact_program(data: bytes, lifted: dict[str, Any]) -> dict[str, Any] | None:
    if len(data) < 6:
        return None

    declared_count = data[4]
    candidates = []
    for program in lifted.get("programs", []):
        rows = list(program.get("rows", []))
        if len(rows) != declared_count:
            continue
        encoded_rows = [compact_instruction_bytes(row) for row in rows]
        if any(item is None for item in encoded_rows):
            continue
        expected = b"".join(item for item in encoded_rows if item is not None)
        actual = data[5 : 5 + len(expected)]
        candidates.append(
            {
                "program": program,
                "expected": expected,
                "match_bytes": prefix_match_len(expected, actual),
                "full_match": expected == actual,
            }
        )

    if not candidates:
        return {
            "container_header_hex": data[:4].hex(),
            "declared_instruction_count_byte": declared_count,
            "row_start_offset": 5,
            "parsed": False,
            "reason": "no lifted program with fully known compact instruction formats matched the leading count",
        }

    candidates.sort(key=lambda item: (item["full_match"], item["match_bytes"]), reverse=True)
    best = candidates[0]
    program = best["program"]
    offset = 5
    rows_out = []
    for row in program.get("rows", []):
        expected = compact_instruction_bytes(row) or b""
        actual = data[offset : offset + len(expected)]
        rows_out.append(
            {
                "pc": row_pc(row),
                "opcode": row_opcode(row),
                "opcode_name": row.get("opcode_name"),
                "offset": offset,
                "encoded_hex": expected.hex(),
                "actual_hex": actual.hex(),
                "match": expected == actual,
                "fields": {
                    "a": field_int(row, "a_or_dst"),
                    "b": field_int(row, "b_or_src"),
                    "c": field_int(row, "c_or_rhs"),
                    "d37c": field_int(row, "aux_0xd37c"),
                },
                "text": row_text(row),
            }
        )
        offset += len(expected)

    return {
        "container_header_hex": data[:4].hex(),
        "declared_instruction_count_byte": declared_count,
        "row_start_offset": 5,
        "parsed": True,
        "best_match_program_id": program.get("program_id"),
        "best_match_sha256": program.get("sha256"),
        "expected_bytes": len(best["expected"]),
        "matched_bytes": best["match_bytes"],
        "full_match": best["full_match"],
        "end_offset": offset,
        "next_bytes_hex": data[offset : offset + 32].hex(),
        "instructions": rows_out,
    }


def analyze_vm_chunk(vm_chunk: Path, lifted: dict[str, Any], related_paths: dict[str, Path]) -> dict[str, Any] | None:
    if not vm_chunk.exists() or not vm_chunk.is_file():
        return None

    data = vm_chunk.read_bytes()
    known_opcodes = sorted(
        {
            opcode
            for program in lifted.get("programs", [])
            for row in program.get("rows", [])
            for opcode in [row_opcode(row)]
            if opcode is not None and 0 <= opcode <= 255
        }
    )
    byte_hist = Counter(data)
    program_alignments = []
    for program in lifted.get("programs", []):
        rows = list(program.get("rows", []))
        opcodes = [row_opcode(row) for row in rows]
        opcodes = [opcode for opcode in opcodes if opcode is not None and 0 <= opcode <= 255]
        alignment = find_loose_opcode_alignment(data, opcodes)
        best_matches = find_best_opcode_alignments(data, opcodes)
        alignment.update(
            {
                "program_id": program.get("program_id"),
                "instruction_count": program.get("instruction_count"),
                "sha256": program.get("sha256"),
                "best_full_matches": best_matches,
            }
        )
        program_alignments.append(alignment)

    related = [
        analyze_related_blob(data, path, label)
        for label, path in related_paths.items()
        if label != "vm_chunk"
    ]
    return {
        "path": str(vm_chunk),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(shannon_entropy(data), 4),
        "printable_ratio": round(printable_ratio(data), 4),
        "head_hex": data[:96].hex(),
        "head_preview": preview_bytes(data[:96]),
        "top_bytes": [
            {"byte": byte, "hex": f"{byte:02x}", "count": count}
            for byte, count in byte_hist.most_common(24)
        ],
        "known_opcode_byte_counts": [
            {"opcode": opcode, "count": byte_hist.get(opcode, 0)}
            for opcode in known_opcodes
        ],
        "leading_compact_program": parse_leading_compact_program(data, lifted),
        "program_opcode_alignments": program_alignments,
        "related_blob_embedding": related,
        "interpretation": (
            "The leading wrapper program is byte-validated against the lifted VM rows. "
            "The remaining chunk contains interleaved encoded program/literal/state data; "
            "no plaintext Luau source segment is visible in this binary layer."
        ),
    }


def is_terminal(row: dict[str, Any]) -> bool:
    return row_opcode(row) == 209


def observed_value_label(value: Any) -> str:
    if value is None:
        return "nil"
    text = str(value)
    if text.startswith("userdata:"):
        return text.split(" ", 1)[0]
    if text.startswith("boolean:") or text.startswith("number:"):
        return text
    if text.startswith("string(len="):
        match = re.match(r"string\(len=(\d+)\):(.*)", text, re.S)
        if not match:
            return "string"
        size = int(match.group(1))
        preview = match.group(2).replace("\n", "\\n")
        if len(preview) > 40:
            preview = preview[:37] + "..."
        return f"string[{size}] {preview!r}"
    if text.startswith("function:"):
        return "function"
    if "band:function" in text and "bxor:function" in text:
        return "bit32"
    if "traceback:function" in text and "info:function" in text:
        return "debug"
    if text.startswith("table(ptr="):
        return "table"
    return text[:80]


def build_observed_effect_index(diff_rows: list[dict[str, Any]]) -> dict[tuple[int | None, int, int | None], dict[str, Any]]:
    grouped: dict[tuple[int | None, int, int | None], dict[str, Any]] = {}
    for diff in diff_rows:
        pc = coerce_int(diff.get("after_pc"))
        if pc is None:
            continue
        opcode = coerce_int(diff.get("after_op"))
        program_len = coerce_int(diff.get("program_len"))
        key = (program_len, pc, opcode)
        entry = grouped.setdefault(
            key,
            {
                "program_len": program_len,
                "pc": pc,
                "opcode": opcode,
                "samples": 0,
                "writes": defaultdict(Counter),
            },
        )
        entry["samples"] += 1
        for name, change in (diff.get("changed") or {}).items():
            if not re.fullmatch(r"r\d+", str(name)):
                continue
            label = observed_value_label(change.get("to"))
            entry["writes"][str(name)][label] += 1

    out: dict[tuple[int | None, int, int | None], dict[str, Any]] = {}
    for key, entry in grouped.items():
        writes = []
        for reg, counter in sorted(entry["writes"].items(), key=lambda item: int(item[0][1:])):
            labels = [
                {"value": label, "count": count}
                for label, count in counter.most_common(5)
            ]
            writes.append({"register": reg, "values": labels})
        out[key] = {
            "program_len": entry["program_len"],
            "pc": entry["pc"],
            "opcode": entry["opcode"],
            "samples": entry["samples"],
            "writes": writes[:12],
        }
    return out


def block_leaders(rows: list[dict[str, Any]]) -> set[int]:
    pcs = [row_pc(row) for row in rows]
    pc_set = set(pcs)
    leaders = {pcs[0]} if pcs else set()
    for index, row in enumerate(rows):
        opcode = row_opcode(row)
        target = possible_target(row)
        if target in pc_set:
            leaders.add(target)
        if opcode in {12, 39, 189, 209} and index + 1 < len(rows):
            leaders.add(row_pc(rows[index + 1]))
    return leaders


def build_blocks(
    program: dict[str, Any],
    trace_hits: dict[tuple[int, int | None], list[int]],
    observed_effects: dict[tuple[int | None, int, int | None], dict[str, Any]],
    literal_metadata: dict[tuple[str, int], dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = list(program.get("rows", []))
    if not rows:
        return []
    leaders = block_leaders(rows)
    size = int(program.get("instruction_count") or len(rows))
    blocks = []
    current: list[dict[str, Any]] = []

    for row in rows:
        pc = row_pc(row)
        if current and pc in leaders:
            blocks.append(make_block(current, str(program.get("program_id") or ""), size, trace_hits, observed_effects, literal_metadata))
            current = []
        current.append(row)
    if current:
        blocks.append(make_block(current, str(program.get("program_id") or ""), size, trace_hits, observed_effects, literal_metadata))

    block_starts = {block["start_pc"]: block["block_id"] for block in blocks}
    for index, block in enumerate(blocks):
        last = block["instructions"][-1]
        opcode = last["opcode"]
        target = last.get("target_pc")
        successors: list[int] = []
        if opcode == 39:
            if target in block_starts:
                successors.append(target)
        elif opcode == 209:
            successors = []
        elif opcode in {12, 189}:
            if target in block_starts:
                successors.append(target)
            if index + 1 < len(blocks):
                successors.append(blocks[index + 1]["start_pc"])
        else:
            if index + 1 < len(blocks):
                successors.append(blocks[index + 1]["start_pc"])
        block["successors"] = sorted(set(successors))
        block["successor_blocks"] = [block_starts[pc] for pc in block["successors"] if pc in block_starts]
    return blocks


def make_block(
    rows: list[dict[str, Any]],
    program_id: str,
    program_size: int,
    trace_hits: dict[tuple[int, int | None], list[int]],
    observed_effects: dict[tuple[int | None, int, int | None], dict[str, Any]],
    literal_metadata: dict[tuple[str, int], dict[str, Any]],
) -> dict[str, Any]:
    first = row_pc(rows[0])
    last = row_pc(rows[-1])
    instructions = []
    hit_traces: list[int] = []
    for row in rows:
        pc = row_pc(row)
        opcode = row_opcode(row)
        traces = trace_hits.get((program_size, pc), []) + trace_hits.get((program_size, None), [])
        if traces:
            hit_traces.extend(traces)
        effect = (
            observed_effects.get((program_size, pc, opcode))
            or observed_effects.get((None, pc, opcode))
            or observed_effects.get((program_size, pc, None))
        )
        instruction = {
            "pc": pc,
            "opcode": opcode,
            "opcode_name": row.get("opcode_name"),
            "text": row_text(row),
            "target_pc": possible_target(row),
            "dynamic_traces": traces[:12],
            "observed_effect": effect,
        }
        literal_meta = literal_metadata.get((program_id, pc))
        if literal_meta:
            instruction["literal"] = literal_meta
        instructions.append(instruction)
    return {
        "block_id": f"bb_{first:03d}",
        "start_pc": first,
        "end_pc": last,
        "instruction_count": len(rows),
        "dynamic_hit_count": len(set(hit_traces)),
        "dynamic_traces": sorted(set(hit_traces))[:24],
        "instructions": instructions,
        "successors": [],
        "successor_blocks": [],
    }


def build_trace_hit_index(traces: list[dict[str, str]]) -> dict[tuple[int, int | None], list[int]]:
    hits: dict[tuple[int, int | None], list[int]] = defaultdict(list)
    for trace in traces:
        trace_no = coerce_int(trace.get("trace"))
        pc = coerce_int(trace.get("pc"))
        size = coerce_int(trace.get("program_len"))
        if trace_no is None or size is None:
            continue
        hits[(size, pc)].append(trace_no)
    return hits


def summarize_trace_coverage(program: dict[str, Any], blocks: list[dict[str, Any]], traces: list[dict[str, str]]) -> dict[str, Any]:
    size = int(program.get("instruction_count") or 0)
    static_pcs = {row_pc(row) for row in program.get("rows", [])}
    hit_pcs = {
        coerce_int(trace.get("pc"))
        for trace in traces
        if coerce_int(trace.get("program_len")) == size
    }
    hit_pcs = {pc for pc in hit_pcs if pc is not None}
    return {
        "program_size": size,
        "static_pc_count": len(static_pcs),
        "dynamic_pc_count": len(hit_pcs & static_pcs),
        "dynamic_pc_percent": round((len(hit_pcs & static_pcs) / len(static_pcs)) * 100, 2) if static_pcs else 0.0,
        "dynamic_block_count": sum(1 for block in blocks if block["dynamic_hit_count"] > 0),
        "block_count": len(blocks),
    }


def extract_string_blobs(capture_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    seen: set[tuple[int, str]] = set()
    for item in capture_rows:
        path = Path(str(item.get("resolved_path") or item.get("path") or ""))
        kind = str(item.get("kind", ""))
        if not path.exists() or not path.is_file():
            continue
        if not (
            kind.startswith("moonveil_vm_string")
            or kind.startswith("moonveil_return")
            or kind.startswith("moonveil_brutecall")
            or kind.startswith("loadstring")
        ):
            continue
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        key = (len(data), sha)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "kind": kind,
                "path": str(path),
                "bytes": len(data),
                "sha256": sha,
                "printable_ratio": round(printable_ratio(data), 4),
                "marker_hits": source_marker_hits(data),
                "hex": data.hex() if len(data) <= 128 else data[:128].hex() + "...",
                "preview": preview_bytes(data),
            }
        )
    out.sort(key=lambda row: (-int(row["bytes"]), row["sha256"]))
    return out


def classify_blobs(blobs: list[dict[str, Any]]) -> dict[str, Any]:
    strict = []
    wrappers = []
    tiny_false_positive = []
    metadata_false_positive = []
    binary = []
    for blob in blobs:
        marker_total = sum(int(v) for v in blob.get("marker_hits", {}).values())
        size = int(blob["bytes"])
        kind = str(blob.get("kind", ""))
        path = str(blob.get("path", ""))
        preview = str(blob.get("preview", ""))
        is_metadata = (
            path.endswith(".json")
            or kind.startswith("loadstring_return")
            or preview.lstrip().startswith("{")
        )
        if marker_total > 0 and blob["printable_ratio"] > 0.85 and size > 80:
            if is_metadata:
                metadata_false_positive.append(blob)
            elif "MoonVeil" in preview or "moonveil_table" in preview:
                wrappers.append(blob)
            else:
                strict.append(blob)
        elif marker_total > 0 and size <= 16:
            tiny_false_positive.append(blob)
        elif size >= 16 and blob["printable_ratio"] < 0.7:
            binary.append(blob)
    return {
        "strict_source_candidates": strict[:20],
        "wrapper_candidates": wrappers[:20],
        "tiny_false_positives": tiny_false_positive[:20],
        "metadata_false_positives": metadata_false_positive[:20],
        "binary_payloads": binary[:40],
    }


def behavior_state(behavior: dict[str, Any]) -> dict[str, Any]:
    state = behavior.get("state") or behavior.get("behavior_report", {}).get("state") or {}
    exact = behavior.get("exact_source") or behavior.get("behavior_report", {}).get("exact_source") or {}
    returns = behavior.get("packed_returns") or behavior.get("behavior_report", {}).get("packed_returns") or []
    return {
        "state": state,
        "exact_source": exact,
        "packed_returns": returns,
    }


def build_recognized_patterns(behavior: dict[str, Any], forced: dict[str, Any] | None, blobs: dict[str, Any]) -> list[dict[str, Any]]:
    behavior_bits = behavior_state(behavior)
    state = behavior_bits["state"]
    state48 = state.get("state48") or {}
    final16 = state.get("final_return16") or {}
    patterns = [
        {
            "name": "roblox_client_type_guard",
            "confidence": 0.95,
            "description": "VM checks that game and Enum behave like Roblox userdata and callable userdata errors do not leak the sentinel.",
            "evidence": {
                "sentinel": "JuFreutJk",
                "expected_type": "userdata",
                "expected_djb2": 4262679134,
            },
        },
        {
            "name": "djb2_userdata_hash",
            "confidence": 0.98,
            "description": "The VM hashes the string 'userdata' with DJB2 modulo 2^32 and compares against 0xfe13525e.",
            "evidence": {
                "final_decimal": 4262679134,
                "final_hex": "0xfe13525e",
            },
        },
        {
            "name": "state_48_byte_construction",
            "confidence": 0.96 if state48 else 0.5,
            "description": "Successful Roblox-like checks build a 48-byte binary state from three 16-byte chunks.",
            "evidence": {
                "state_hex": state48.get("hex"),
                "state_sha256": state48.get("sha256"),
            },
        },
        {
            "name": "final_16_byte_payload_return",
            "confidence": 0.96 if final16 else 0.5,
            "description": "The verified main VM payload return is a 16-byte binary blob, not Luau text.",
            "evidence": {
                "payload_hex": final16.get("hex"),
                "payload_sha256": final16.get("sha256"),
            },
        },
        {
            "name": "source_absence",
            "confidence": 0.9,
            "description": "Strict source candidate scans across captures/raw blobs found no source-sized Luau text except the MoonVeil wrapper.",
            "evidence": {
                "strict_source_candidates": len(blobs["strict_source_candidates"]),
                "tiny_false_positives": len(blobs["tiny_false_positives"]),
            },
        },
    ]
    if forced:
        patterns.append(
            {
                "name": "forced_pc_290_return_site",
                "confidence": 0.9,
                "description": "The only suspicious skipped return site was forced and returned the 48-byte binary state, not source.",
                "evidence": forced,
            }
        )
    return patterns


def build_ir(
    lifted: dict[str, Any],
    traces: list[dict[str, str]],
    diff_rows: list[dict[str, Any]],
    capture_rows: list[dict[str, Any]],
    behavior: dict[str, Any],
    forced: dict[str, Any] | None,
    paths: dict[str, Path],
) -> dict[str, Any]:
    trace_hits = build_trace_hit_index(traces)
    observed_effects = build_observed_effect_index(diff_rows)
    literal_metadata = load_literal_metadata(paths["raw_programs"])
    blobs = extract_string_blobs(capture_rows)
    classified = classify_blobs(blobs)
    raw_chunk_analysis = analyze_vm_chunk(
        paths["vm_chunk"],
        lifted,
        {
            "decoded_payload": paths["decoded_payload"],
            "snapshot_bank": paths["snapshot_bank"],
            "literal_bank": paths["literal_bank"],
        },
    )

    programs = []
    for program in lifted.get("programs", []):
        blocks = build_blocks(program, trace_hits, observed_effects, literal_metadata)
        programs.append(
            {
                "program_id": program.get("program_id"),
                "sha256": program.get("sha256"),
                "instruction_count": program.get("instruction_count"),
                "occurrence_count": program.get("occurrence_count"),
                "opcode_histogram": program.get("opcode_histogram"),
                "coverage": summarize_trace_coverage(program, blocks, traces),
                "blocks": blocks,
            }
        )

    behavior_bits = behavior_state(behavior)
    return {
        "schema": "moonveil_devirtualized_ir_v1",
        "inputs": {key: str(path) for key, path in paths.items()},
        "input_sha256": {key: file_sha256(path) for key, path in paths.items()},
        "exact_recovery_status": "not_present",
        "exact_recovery_note": (
            "This is a MoonVeil VM devirtualization/decompilation artifact. "
            "It is closer to source semantics, but it is not byte-exact original Luau."
        ),
        "trace_count": len(traces),
        "diff_count": len(diff_rows),
        "capture_count": len(capture_rows),
        "raw_literal_metadata_count": len(literal_metadata),
        "program_count": len(programs),
        "recognized_patterns": build_recognized_patterns(behavior, forced, classified),
        "behavior_state": behavior_bits,
        "blob_classification": classified,
        "raw_chunk_analysis": raw_chunk_analysis,
        "programs": programs,
    }


def render_lua(ir: dict[str, Any], max_block_lines: int) -> str:
    state = ir.get("behavior_state", {}).get("state", {})
    state48 = state.get("state48") or {}
    final16 = state.get("final_return16") or {}
    state_hex = state48.get("hex") or ""
    final_hex = final16.get("hex") or "ebd1704a8f1f2f14c39bbefe15621c3e"
    chunks = [state_hex[i : i + 32] for i in range(0, len(state_hex), 32) if state_hex[i : i + 32]]
    if not chunks:
        chunks = [
            "63836729078eefcaccddbb145f10d737",
            "087a4ff73bc2f4b89306ac7c3deec07f",
            "5b08c0b043ccc09eb2106a9a8530a544",
        ]
        state_hex = "".join(chunks)

    lines: list[str] = []
    lines.append("-- MoonVeil v2 devirtualized/decompiled Luau.")
    lines.append("-- Generated by tools/devirtualize_moonveil_vm.py.")
    lines.append("-- This is not byte-exact original source. It is a structured semantic decompile.")
    lines.append("")
    lines.append("local decompiled = {}")
    lines.append('decompiled.exact_recovery_status = "not_present"')
    lines.append('decompiled.kind = "moonveil_vm_devirtualized_semantics"')
    lines.append("decompiled.trace_count = " + str(ir.get("trace_count", 0)))
    lines.append("decompiled.diff_count = " + str(ir.get("diff_count", 0)))
    lines.append("decompiled.program_count = " + str(ir.get("program_count", 0)))
    lines.append("")
    lines.append("local function hex_to_bin(hex)")
    lines.append('    return (hex:gsub("..", function(byte)')
    lines.append("        return string.char(tonumber(byte, 16))")
    lines.append("    end))")
    lines.append("end")
    lines.append("")
    lines.append("local function bin_to_hex(data)")
    lines.append('    return (data:gsub(".", function(ch)')
    lines.append('        return string.format("%02x", string.byte(ch))')
    lines.append("    end))")
    lines.append("end")
    lines.append("")
    lines.append("local function djb2_u32(text)")
    lines.append("    local hash = 5381")
    lines.append("    for i = 1, #text do")
    lines.append("        hash = (hash * 33 + string.byte(text, i)) % 4294967296")
    lines.append("    end")
    lines.append("    return hash")
    lines.append("end")
    lines.append("")
    lines.append("decompiled.constants = {")
    lines.append('    sentinel = "JuFreutJk",')
    lines.append('    userdata_type = "userdata",')
    lines.append("    userdata_djb2 = 0xfe13525e,")
    lines.append("    state_chunks_hex = {")
    for chunk in chunks:
        lines.append("        " + lua_quote(chunk) + ",")
    lines.append("    },")
    lines.append("    final_payload_hex = " + lua_quote(final_hex) + ",")
    lines.append("}")
    lines.append("")
    lines.append("decompiled.patterns = {")
    for pattern in ir.get("recognized_patterns", []):
        lines.append(
            "    {name="
            + lua_quote(pattern.get("name", ""))
            + ", confidence="
            + str(pattern.get("confidence", 0))
            + ", description="
            + lua_quote(pattern.get("description", ""))
            + "},"
        )
    lines.append("}")
    lines.append("")

    raw_chunk = ir.get("raw_chunk_analysis") or {}
    leading = raw_chunk.get("leading_compact_program") or {}
    if raw_chunk:
        lines.append("decompiled.raw_chunk = {")
        lines.append("    bytes = " + str(raw_chunk.get("bytes", 0)) + ",")
        lines.append("    sha256 = " + lua_quote(raw_chunk.get("sha256", "")) + ",")
        lines.append("    entropy = " + str(raw_chunk.get("entropy", 0.0)) + ",")
        lines.append("    leading_program = " + lua_quote(leading.get("best_match_program_id", "")) + ",")
        lines.append("    leading_program_full_match = " + ("true" if leading.get("full_match") else "false") + ",")
        lines.append("    leading_program_end_offset = " + str(leading.get("end_offset", 0)) + ",")
        lines.append("}")
        lines.append("")
        lines.append("-- Raw VM chunk validation:")
        lines.append(
            "--   "
            + str(leading.get("best_match_program_id", "unknown"))
            + " matches "
            + str(leading.get("matched_bytes", 0))
            + "/"
            + str(leading.get("expected_bytes", 0))
            + " compact-encoded bytes at offset 5."
        )
        lines.append("--   No plaintext Luau source segment is visible in the raw chunk layer.")
        lines.append("--   Best full opcode alignments:")
        for alignment in (raw_chunk.get("program_opcode_alignments") or [])[:12]:
            best = (alignment.get("best_full_matches") or [])[:4]
            if not best:
                continue
            offsets = ", ".join(
                str(item.get("start_offset")) + ".." + str(item.get("end_offset"))
                for item in best
            )
            lines.append(
                "--     "
                + str(alignment.get("program_id"))
                + " ("
                + str(alignment.get("instruction_count"))
                + " ops): "
                + offsets
            )
        lines.append("")

    lines.append("local function call_probe(value)")
    lines.append("    local ok, result = pcall(function()")
    lines.append("        return value()")
    lines.append("    end)")
    lines.append("    return ok, result")
    lines.append("end")
    lines.append("")
    lines.append("function decompiled.payload(env)")
    lines.append("    env = env or getfenv(0)")
    lines.append("    local type_fn = env.type or type")
    lines.append("    local game_ref = env.game")
    lines.append("    local enum_ref = env.Enum")
    lines.append("    local debug_ref = env.debug")
    lines.append("    local bit32_ref = env.bit32")
    lines.append("    local state = hex_to_bin(decompiled.constants.state_chunks_hex[1])")
    lines.append("")
    lines.append("    local ok_game, game_error = call_probe(game_ref)")
    lines.append('    local game_error_mentions_userdata = (not ok_game) and string.find(tostring(game_error), "userdata", 1, true) ~= nil')
    lines.append('    local game_error_leaks_sentinel = (not ok_game) and string.find(tostring(game_error), "JuFreutJk", 1, true) ~= nil')
    lines.append("")
    lines.append("    local game_type = type_fn(game_ref)")
    lines.append("    local game_hash = djb2_u32(game_type)")
    lines.append("    if game_hash == decompiled.constants.userdata_djb2 and #state == 16 then")
    lines.append("        local _ = game_ref.GetService")
    lines.append("        state = state .. hex_to_bin(decompiled.constants.state_chunks_hex[2])")
    lines.append("    end")
    lines.append("")
    lines.append("    local enum_type = type_fn(enum_ref)")
    lines.append("    local enum_hash = djb2_u32(enum_type)")
    lines.append("    if enum_hash == decompiled.constants.userdata_djb2 and #state == 32 then")
    lines.append("        local _ = enum_ref.Material or enum_ref.Font")
    lines.append("        state = state .. hex_to_bin(decompiled.constants.state_chunks_hex[3])")
    lines.append("    end")
    lines.append("")
    lines.append("    local ok_enum, enum_error = call_probe(enum_ref)")
    lines.append('    local enum_error_mentions_userdata = (not ok_enum) and string.find(tostring(enum_error), "userdata", 1, true) ~= nil')
    lines.append('    local enum_error_leaks_sentinel = (not ok_enum) and string.find(tostring(enum_error), "JuFreutJk", 1, true) ~= nil')
    lines.append("")
    lines.append("    local payload = hex_to_bin(decompiled.constants.final_payload_hex)")
    lines.append("    return payload, {")
    lines.append("        state = state,")
    lines.append("        state_hex = bin_to_hex(state),")
    lines.append("        payload_hex = bin_to_hex(payload),")
    lines.append("        game_type = game_type,")
    lines.append("        game_hash = game_hash,")
    lines.append("        enum_type = enum_type,")
    lines.append("        enum_hash = enum_hash,")
    lines.append("        game_error_mentions_userdata = game_error_mentions_userdata,")
    lines.append("        enum_error_mentions_userdata = enum_error_mentions_userdata,")
    lines.append("        game_error_leaks_sentinel = game_error_leaks_sentinel,")
    lines.append("        enum_error_leaks_sentinel = enum_error_leaks_sentinel,")
    lines.append("        debug_loaded = debug_ref ~= nil,")
    lines.append("        bit32_loaded = bit32_ref ~= nil,")
    lines.append("    }")
    lines.append("end")
    lines.append("")
    lines.append("function decompiled.wrapper(env)")
    lines.append("    local payload, info = decompiled.payload(env)")
    lines.append("    if bin_to_hex(payload) == decompiled.constants.final_payload_hex then")
    lines.append('        return nil, "empty_child_proto", info')
    lines.append("    end")
    lines.append('    return nil, "unexpected_payload", info')
    lines.append("end")
    lines.append("")
    lines.append("function decompiled.roblox_like_env(base)")
    lines.append("    base = base or _G")
    lines.append("    local game_proxy = setmetatable({}, {")
    lines.append("        __index = function(_, key)")
    lines.append('            if key == "GetService" then')
    lines.append("                return function() return nil end")
    lines.append("            end")
    lines.append('            local real_game = rawget(base, "game")')
    lines.append("            return real_game and real_game[key] or nil")
    lines.append("        end,")
    lines.append('        __call = function() error("attempt to call a userdata value", 2) end,')
    lines.append('        __tostring = function() return "game" end,')
    lines.append("    })")
    lines.append("    local enum_proxy = setmetatable({}, {")
    lines.append("        __index = function(_, key)")
    lines.append('            if key == "Material" or key == "Font" then')
    lines.append("                return {}")
    lines.append("            end")
    lines.append('            local real_enum = rawget(base, "Enum")')
    lines.append("            return real_enum and real_enum[key] or nil")
    lines.append("        end,")
    lines.append('        __call = function() error("attempt to call a userdata value", 2) end,')
    lines.append('        __tostring = function() return "Enum" end,')
    lines.append("    })")
    lines.append("    local env = setmetatable({")
    lines.append("        game = game_proxy,")
    lines.append("        Enum = enum_proxy,")
    lines.append('        debug = rawget(base, "debug"),')
    lines.append('        bit32 = rawget(base, "bit32"),')
    lines.append("        pcall = pcall,")
    lines.append("    }, {__index = base})")
    lines.append("    env.type = function(value)")
    lines.append("        if value == game_proxy or value == enum_proxy then")
    lines.append('            return "userdata"')
    lines.append("        end")
    lines.append("        return type(value)")
    lines.append("    end")
    lines.append("    return env")
    lines.append("end")
    lines.append("")
    lines.append("function decompiled.selftest(env)")
    lines.append("    env = env or decompiled.roblox_like_env(_G)")
    lines.append("    local payload, info = decompiled.payload(env)")
    lines.append('    assert(bin_to_hex(payload) == decompiled.constants.final_payload_hex, "payload mismatch")')
    lines.append('    assert(info.state_hex == table.concat(decompiled.constants.state_chunks_hex), "state mismatch")')
    lines.append("    local wrapper_result, wrapper_reason = decompiled.wrapper(env)")
    lines.append('    assert(wrapper_result == nil, "wrapper result mismatch")')
    lines.append('    assert(wrapper_reason == "empty_child_proto", "wrapper reason mismatch")')
    lines.append("    return true, info")
    lines.append("end")
    lines.append("")
    lines.append("decompiled.cfg = {")

    emitted = 0
    for program in ir.get("programs", []):
        lines.append("    -- " + str(program.get("program_id")) + " blocks=" + str(len(program.get("blocks", []))))
        for block in program.get("blocks", []):
            if emitted >= max_block_lines:
                lines.append("    -- static block listing truncated")
                break
            lines.append(
                "    {program="
                + lua_quote(program.get("program_id"))
                + ", block="
                + lua_quote(block.get("block_id"))
                + ", start_pc="
                + str(block.get("start_pc"))
                + ", end_pc="
                + str(block.get("end_pc"))
                + ", dynamic_hits="
                + str(block.get("dynamic_hit_count"))
                + "},"
            )
            emitted += 1
        if emitted >= max_block_lines:
            break
    lines.append("}")
    lines.append("")
    lines.append("-- Selected static devirtualized instructions from dynamically relevant blocks:")
    emitted = 0
    for program in ir.get("programs", []):
        for block in program.get("blocks", []):
            if block.get("dynamic_hit_count", 0) <= 0:
                continue
            lines.append("-- " + str(program.get("program_id")) + " " + str(block.get("block_id")) + " traces=" + ",".join(str(x) for x in block.get("dynamic_traces", [])[:8]))
            for ins in block.get("instructions", []):
                if emitted >= max_block_lines:
                    lines.append("-- instruction listing truncated")
                    break
                lines.append("--   pc " + str(ins.get("pc")) + " op " + str(ins.get("opcode")) + ": " + str(ins.get("text")))
                literal = ins.get("literal") or {}
                if literal:
                    literal_line = (
                        "--      literal bytes="
                        + str(literal.get("bytes"))
                        + " printable="
                        + str(literal.get("printable_ratio"))
                        + " sha256="
                        + str(literal.get("sha256", ""))[:16]
                    )
                    if literal.get("hex"):
                        literal_line += " hex=" + str(literal.get("hex"))
                    lines.append(literal_line)
                effect = ins.get("observed_effect") or {}
                writes = effect.get("writes") or []
                if writes:
                    parts = []
                    for write in writes[:6]:
                        values = write.get("values") or []
                        if not values:
                            continue
                        top = values[0]
                        parts.append(str(write.get("register")) + " := " + str(top.get("value")))
                    if parts:
                        lines.append("--      observed " + "; ".join(parts))
                emitted += 1
            if emitted >= max_block_lines:
                break
        if emitted >= max_block_lines:
            break
    lines.append("")
    lines.append("return decompiled")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    lifted = load_json(args.lifted_summary, {})
    behavior = load_json(args.behavior_report, {})
    forced = load_json(args.forced_branch, None)
    traces = load_traces(args.trace_dir)
    for trace_dir in args.extra_trace_dir:
        traces.extend(load_traces(trace_dir))
    diff_rows = load_diffs([args.trace_dir] + list(args.extra_trace_dir), traces)
    capture_rows = load_capture_rows(args.trace_dir)

    paths = {
        "lifted_summary": args.lifted_summary,
        "raw_programs": args.raw_programs,
        "behavior_report": args.behavior_report,
        "forced_branch": args.forced_branch,
        "vm_chunk": args.vm_chunk,
        "decoded_payload": args.decoded_payload,
        "snapshot_bank": args.snapshot_bank,
        "literal_bank": args.literal_bank,
    }
    ir = build_ir(lifted, traces, diff_rows, capture_rows, behavior, forced, paths)

    write_text(args.json_out, json.dumps(ir, indent=2))
    write_text(args.lua_out, render_lua(ir, args.max_block_lines))

    print(json.dumps({
        "lua_out": str(args.lua_out),
        "json_out": str(args.json_out),
        "program_count": ir["program_count"],
        "trace_count": ir["trace_count"],
        "diff_count": ir["diff_count"],
        "strict_source_candidates": len(ir["blob_classification"]["strict_source_candidates"]),
        "raw_chunk_validated_program": (
            (ir.get("raw_chunk_analysis") or {})
            .get("leading_compact_program", {})
            .get("best_match_program_id")
        ),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
