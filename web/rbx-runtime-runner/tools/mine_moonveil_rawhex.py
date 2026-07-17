#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import bz2
import gzip
import hashlib
import json
import lzma
import re
import zlib
from pathlib import Path
from typing import Any


SOURCE_MARKERS = (
    b"local ",
    b"function",
    b"return ",
    b"game:",
    b"game.",
    b"script",
    b"Instance.new",
    b"HttpGet",
    b"loadstring",
    b"getgenv",
    b"task.",
)

WRAPPER_MARKERS = (b"MoonVeil", b"moonveil_table", b"return({")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mine byte-exact MoonVeil raw-hex artifacts for source-bearing data.")
    parser.add_argument("trace_dir", type=Path)
    parser.add_argument("--extra-trace-dir", type=Path, action="append", default=[], help="Additional trace/capture directory to merge; repeatable.")
    parser.add_argument("--extra-captures-only", action="store_true", help="For extra trace dirs, merge capture_index files only and skip VM/function dump JSON.")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--max-candidates", type=int, default=80)
    parser.add_argument("--max-xor-bytes", type=int, default=8192)
    return parser.parse_args()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    return sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13)) / len(data)


def preview(data: bytes, limit: int = 160) -> str:
    shown = data[:limit]
    return "".join(chr(byte) if 32 <= byte < 127 or byte in (9, 10, 13) else "." for byte in shown)


def source_score(data: bytes) -> int:
    marker_hits = sum(data.count(marker) for marker in SOURCE_MARKERS)
    wrapper_penalty = sum(data.count(marker) for marker in WRAPPER_MARKERS) * 4
    printable_bonus = 2 if len(data) >= 40 and printable_ratio(data) >= 0.82 else 0
    structure_bonus = 0
    if re.search(rb"\b(local|function|return|if|for|while)\b", data):
        structure_bonus += 2
    if b"\n" in data and (b"=" in data or b"(" in data):
        structure_bonus += 1
    return marker_hits * 3 + printable_bonus + structure_bonus - wrapper_penalty


def decode_hex(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def collect_vm_program_strings(trace_dir: Path) -> list[dict[str, Any]]:
    data = load_json(trace_dir / "moonveil_vm_programs.json")
    rows: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return rows

    for program in data.get("programs", []):
        if not isinstance(program, dict):
            continue
        program_id = program.get("program_id")
        for instruction in program.get("instructions", []):
            if not isinstance(instruction, dict):
                continue
            pc = instruction.get("pc")
            fields = instruction.get("fields", {})
            if not isinstance(fields, dict):
                continue
            opcode = None
            op_field = fields.get("f_0x3c22")
            if isinstance(op_field, dict):
                opcode = op_field.get("value")
            for alias, field in fields.items():
                if not isinstance(field, dict) or field.get("type") != "string":
                    continue
                data_bytes = decode_hex(field.get("hex"))
                if data_bytes is None:
                    value = field.get("value")
                    if not isinstance(value, str):
                        continue
                    data_bytes = value.encode("utf-8", errors="surrogatepass")
                rows.append(
                    {
                        "origin": "vm_program",
                        "program_id": program_id,
                        "pc": pc,
                        "opcode": opcode,
                        "field": alias,
                        "bytes": len(data_bytes),
                        "sha256": sha256(data_bytes),
                        "hex": data_bytes.hex(),
                        "printable_ratio": round(printable_ratio(data_bytes), 4),
                        "source_score": source_score(data_bytes),
                        "preview": preview(data_bytes),
                    }
                )
    return rows


def collect_function_dump_strings(trace_dir: Path) -> list[dict[str, Any]]:
    data = load_json(trace_dir / "luraph_function_dump.json")
    rows: list[dict[str, Any]] = []
    if data is None:
        return rows

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            kind = value.get("value_type", value.get("type"))
            data_bytes = decode_hex(value.get("hex"))
            if kind == "string" and data_bytes is not None:
                rows.append(
                    {
                        "origin": "function_dump",
                        "path": path,
                        "bytes": len(data_bytes),
                        "sha256": sha256(data_bytes),
                        "hex": data_bytes.hex(),
                        "printable_ratio": round(printable_ratio(data_bytes), 4),
                        "source_score": source_score(data_bytes),
                        "preview": preview(data_bytes),
                    }
                )
            for key, child in value.items():
                walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")

    walk(data, "root")
    return rows


def collect_capture_strings(trace_dir: Path) -> list[dict[str, Any]]:
    index_path = trace_dir / "capture_index.jsonl"
    rows: list[dict[str, Any]] = []
    if not index_path.exists():
        return rows

    for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = str(item.get("kind", ""))
        if kind == "luraph_function_dump":
            continue
        path = Path(str(item.get("path", "")))
        if not path.exists():
            path = trace_dir / path.name
        if not path.exists() or not path.is_file():
            continue
        data = path.read_bytes()
        rows.append(
            {
                "origin": "capture",
                "kind": item.get("kind"),
                "path": str(path),
                "bytes": len(data),
                "sha256": sha256(data),
                "hex": data.hex(),
                "printable_ratio": round(printable_ratio(data), 4),
                "source_score": source_score(data),
                "preview": preview(data),
            }
        )
    return rows


def dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[tuple[int, str], dict[str, Any]] = {}
    for row in rows:
        key = (int(row["bytes"]), str(row["sha256"]))
        if key not in seen:
            seen[key] = dict(row)
            seen[key]["occurrences"] = 1
            seen[key]["origins"] = [row.get("origin")]
        else:
            seen[key]["occurrences"] += 1
            origin = row.get("origin")
            if origin not in seen[key]["origins"]:
                seen[key]["origins"].append(origin)
    return sorted(seen.values(), key=lambda row: (-int(row["bytes"]), -int(row["source_score"]), str(row["sha256"])))


def write_bank(path: Path, chunks: list[bytes]) -> dict[str, Any]:
    data = b"".join(chunks)
    path.write_bytes(data)
    return {
        "path": str(path),
        "bytes": len(data),
        "sha256": sha256(data),
        "printable_ratio": round(printable_ratio(data), 4),
        "source_score": source_score(data),
        "preview": preview(data),
    }


def try_decompress(label: str, data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    codecs = [
        ("zlib", lambda raw: zlib.decompress(raw)),
        ("raw_zlib", lambda raw: zlib.decompress(raw, -15)),
        ("gzip", lambda raw: gzip.decompress(raw)),
        ("bz2", lambda raw: bz2.decompress(raw)),
        ("lzma", lambda raw: lzma.decompress(raw)),
    ]
    for name, func in codecs:
        try:
            decoded = func(data)
        except Exception:
            continue
        out.append((f"{label}.{name}", decoded))
    return out


def try_ascii_decodes(label: str, data: bytes) -> list[tuple[str, bytes]]:
    if printable_ratio(data) < 0.92:
        return []
    compact = re.sub(rb"\s+", b"", data)
    out: list[tuple[str, bytes]] = []
    attempts = [
        ("base64", lambda raw: base64.b64decode(raw, validate=True)),
        ("base32", lambda raw: base64.b32decode(raw, casefold=True)),
        ("base85", lambda raw: base64.b85decode(raw)),
        ("ascii85", lambda raw: base64.a85decode(raw)),
    ]
    for name, func in attempts:
        try:
            decoded = func(compact)
        except Exception:
            continue
        if decoded and decoded != data:
            out.append((f"{label}.{name}", decoded))
    return out


def transformed_candidates(named_blobs: list[tuple[str, bytes]], max_candidates: int, max_xor_bytes: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()

    def add(label: str, data: bytes, transform: str) -> None:
        if len(data) < 8:
            return
        digest = sha256(data)
        key = (len(data), digest, transform)
        if key in seen:
            return
        seen.add(key)
        score = source_score(data)
        marker_counts = [(marker, data.count(marker)) for marker in SOURCE_MARKERS]
        marker_hits = {marker.decode("ascii"): count for marker, count in marker_counts if count}
        debug_text = (
            b"moonveil_table" in data
            or b"roblox_high_fidelity_setup" in data
            or b"function invoke" in data
            or data == b"function"
        )
        if debug_text or len(data) < 40 or score < 6:
            return
        candidates.append(
            {
                "label": label,
                "transform": transform,
                "bytes": len(data),
                "sha256": digest,
                "printable_ratio": round(printable_ratio(data), 4),
                "source_score": score,
                "marker_hits": marker_hits,
                "hex": data.hex(),
                "preview": preview(data, 300),
            }
        )

    for label, data in named_blobs:
        add(label, data, "identity")
        add(label, data[::-1], "reverse")
        add(label, bytes((~byte) & 0xff for byte in data), "bitnot")
        for bits in range(1, 8):
            add(
                f"{label}.rotl{bits}",
                bytes(((byte << bits) | (byte >> (8 - bits))) & 0xff for byte in data),
                f"rotl{bits}",
            )
            add(
                f"{label}.rotr{bits}",
                bytes(((byte >> bits) | (byte << (8 - bits))) & 0xff for byte in data),
                f"rotr{bits}",
            )
        for child_label, child in try_decompress(label, data):
            add(child_label, child, "decompress")
        for child_label, child in try_ascii_decodes(label, data):
            add(child_label, child, "ascii_decode")
            for nested_label, nested in try_decompress(child_label, child):
                add(nested_label, nested, "ascii_decode.decompress")

        # Exhaustive single-byte XOR is cheap for these banks and catches the
        # common "one more mask" layer without assuming text is aligned.
        if len(data) <= max_xor_bytes:
            for key in range(256):
                if key == 0:
                    continue
                xored = bytes(byte ^ key for byte in data)
                if printable_ratio(xored) >= 0.78:
                    add(f"{label}.xor_{key:02x}", xored, f"xor_{key:02x}")
                added = bytes((byte + key) & 0xff for byte in data)
                if printable_ratio(added) >= 0.78:
                    add(f"{label}.add_{key:02x}", added, f"add_{key:02x}")
                subbed = bytes((byte - key) & 0xff for byte in data)
                if printable_ratio(subbed) >= 0.78:
                    add(f"{label}.sub_{key:02x}", subbed, f"sub_{key:02x}")

    candidates.sort(key=lambda row: (-int(row["source_score"]), -float(row["printable_ratio"]), -int(row["bytes"])))
    return candidates[:max_candidates]


def write_candidate_files(out_dir: Path, candidates: list[dict[str, Any]]) -> None:
    cand_dir = out_dir / "exact_source_candidates"
    cand_dir.mkdir(parents=True, exist_ok=True)
    for index, row in enumerate(candidates[:50], start=1):
        data = bytes.fromhex(str(row["hex"]))
        suffix = ".lua" if printable_ratio(data) >= 0.8 else ".bin"
        path = cand_dir / f"candidate_{index:03d}{suffix}"
        path.write_bytes(data)
        row["path"] = str(path)


def main() -> int:
    args = parse_args()
    trace_dir = args.trace_dir
    trace_dirs = [trace_dir] + list(args.extra_trace_dir)
    out_dir = args.out_dir or trace_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    vm_rows: list[dict[str, Any]] = []
    dump_rows: list[dict[str, Any]] = []
    capture_rows: list[dict[str, Any]] = []
    capture_rows_by_dir: dict[str, list[dict[str, Any]]] = {}
    for current_dir in trace_dirs:
        if args.extra_captures_only and current_dir != trace_dir:
            current_vm_rows = []
            current_dump_rows = []
        else:
            current_vm_rows = collect_vm_program_strings(current_dir)
            current_dump_rows = collect_function_dump_strings(current_dir)
        current_capture_rows = collect_capture_strings(current_dir)
        for row in current_vm_rows + current_dump_rows + current_capture_rows:
            row["trace_dir"] = str(current_dir)
        vm_rows.extend(current_vm_rows)
        dump_rows.extend(current_dump_rows)
        capture_rows.extend(current_capture_rows)
        capture_rows_by_dir[str(current_dir)] = current_capture_rows
    all_rows = dedupe_rows(vm_rows + dump_rows + capture_rows)

    literal_rows = [row for row in vm_rows if row.get("field") == "f_0xa08e"]
    op226_rows = [row for row in literal_rows if str(row.get("opcode")) == "226"]
    all_vm_rows = [row for row in vm_rows]
    dump_unique = dedupe_rows(dump_rows)
    capture_unique = dedupe_rows(capture_rows)

    banks = {
        "raw_literal_bank": write_bank(out_dir / "raw_literal_bank.bin", [bytes.fromhex(row["hex"]) for row in literal_rows]),
        "raw_literal_bank_op226": write_bank(out_dir / "raw_literal_bank_op226.bin", [bytes.fromhex(row["hex"]) for row in op226_rows]),
        "raw_all_vm_strings_bank": write_bank(out_dir / "raw_all_vm_strings_bank.bin", [bytes.fromhex(row["hex"]) for row in all_vm_rows]),
        "raw_snapshot_strings_bank": write_bank(out_dir / "raw_snapshot_strings_bank.bin", [bytes.fromhex(row["hex"]) for row in dump_unique]),
        "raw_capture_bank": write_bank(out_dir / "raw_capture_bank.bin", [bytes.fromhex(row["hex"]) for row in capture_unique]),
    }

    named_blobs: list[tuple[str, bytes]] = []
    for name, bank in banks.items():
        if name == "raw_capture_bank":
            continue
        named_blobs.append((name, (out_dir / Path(bank["path"]).name).read_bytes()))
    for row in all_rows:
        if int(row["bytes"]) >= 8:
            if row.get("origin") == "capture":
                kind = str(row.get("kind", ""))
                path = str(row.get("path", ""))
                interesting_capture = (
                    kind.startswith("moonveil_return")
                    or kind.startswith("moonveil_vm_string")
                    or kind.startswith("function_snapshot_string")
                    or kind.startswith("moonveil_i")
                    or kind.startswith("moonveil_vm_chunk")
                    or path.endswith(".bin")
                )
                if not interesting_capture:
                    continue
                if int(row["bytes"]) > 4096:
                    continue
            label = f"{row.get('origin')}:{row.get('program_id', '')}:{row.get('pc', '')}:{row.get('field', row.get('kind', row.get('path', '')))}"
            named_blobs.append((label, bytes.fromhex(row["hex"])))

    candidates = transformed_candidates(named_blobs, args.max_candidates, args.max_xor_bytes)
    write_candidate_files(out_dir, candidates)

    trace_frames = []
    for current_dir in trace_dirs:
        current_frame = {
            "trace_dir": str(current_dir),
            "packed_return_trace_382": None,
            "empty_proto_trace": None,
            "raw_return_frame_strings": [],
            "trace_386_snapshot_strings": [],
        }
        for path in sorted(current_dir.glob("moonveil_packed_return_*.txt")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if "trace=382" in text:
                current_frame["packed_return_trace_382"] = {"path": str(path), "text": text}
        for path in sorted(current_dir.glob("moonveil_empty_proto_return_*.txt")):
            current_frame["empty_proto_trace"] = {"path": str(path), "text": path.read_text(encoding="utf-8", errors="replace")}
        for row in capture_rows_by_dir.get(str(current_dir), []):
            kind = str(row.get("kind", ""))
            path = str(row.get("path", ""))
            if kind.startswith("moonveil_return_frame_string") or kind == "moonveil_return_string":
                current_frame["raw_return_frame_strings"].append(row)
            if "trace=386" in path or "trace=386" in str(row.get("preview", "")):
                current_frame["trace_386_snapshot_strings"].append(row)
        trace_frames.append(current_frame)

    report = {
        "trace_dir": str(trace_dir),
        "trace_dirs": [str(path) for path in trace_dirs],
        "string_counts": {
            "vm_program_strings": len(vm_rows),
            "vm_literal_strings": len(literal_rows),
            "vm_opcode226_literal_strings": len(op226_rows),
            "function_dump_strings": len(dump_rows),
            "capture_strings": len(capture_rows),
            "unique_all_strings": len(all_rows),
        },
        "banks": banks,
        "source_marker_counts": {
            name: {marker.decode("ascii"): (out_dir / Path(bank["path"]).name).read_bytes().count(marker) for marker in SOURCE_MARKERS}
            for name, bank in banks.items()
        },
        "top_raw_rows": all_rows[:120],
        "candidate_count": len(candidates),
        "candidates": candidates,
        "trace_frames": trace_frames,
        "exact_recovery_status": "unknown" if candidates else "not_present_in_rawhex_scan",
        "reason": (
            "raw hex banks and common reversible transforms produced source-like candidates"
            if candidates
            else "no individual raw string, ordered literal bank, snapshot bank, capture bank, or simple transform contained Luau source markers"
        ),
    }

    (out_dir / "exact_source_candidates_rawhex.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({k: report[k] for k in ("string_counts", "candidate_count", "exact_recovery_status", "reason")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
