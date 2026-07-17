#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SOURCE_MARKERS = (
    b"local ",
    b"function",
    b"return ",
    b"game",
    b"script",
    b"Instance.new",
    b"HttpGet",
    b"loadstring",
    b"getgenv",
    b"task.",
)

NON_ORIGINAL_MARKERS = (
    b"This script was generated using MoonVeil",
    b"return({",
    b"moonveil_",
    b"MoonVeil v2 behavior-level",
    b"dispatch_trace",
    b"function_snapshot",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a strict exact-source recovery report for the MoonVeil sample.")
    parser.add_argument("--source", type=Path, default=Path("/Users/alexkkork/Downloads/mv.lua"))
    parser.add_argument("--primary-dir", type=Path, default=Path("work/mv-deobf-rawhex"))
    parser.add_argument("--high-capture-dir", type=Path, default=Path("work/mv-high-capture"))
    parser.add_argument("--empty-explore-dir", type=Path, default=Path("work/mv-empty-explore"))
    parser.add_argument("--brutecall-dir", type=Path, default=Path("work/mv-brutecall"))
    parser.add_argument("--force-matrix-dir", type=Path, default=Path("work/mv-force-matrix"))
    parser.add_argument("--expanded-rawhex-report", type=Path, default=Path("work/mv-rawhex-matrix/exact_source_candidates_rawhex.json"))
    parser.add_argument("--semantic-ir", type=Path, default=Path("outputs/moonveil_v2_semantic_ir.json"))
    parser.add_argument("--semantic-lua", type=Path, default=Path("outputs/moonveil_v2_semantic_decompile.lua"))
    parser.add_argument("--out", type=Path, default=Path("outputs/moonveil_v2_exact_recovery_report.json"))
    parser.add_argument("--copy-artifacts", action="store_true")
    return parser.parse_args()


def read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_summary(path: Path) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file():
        return None
    data = path.read_bytes()
    return {
        "path": str(path),
        "bytes": len(data),
        "sha256": sha256_bytes(data),
    }


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(data)


def source_score(data: bytes) -> int:
    score = 0
    score += sum(data.count(marker) for marker in SOURCE_MARKERS) * 3
    if re.search(rb"\b(local|function|return|if|for|while)\b", data):
        score += 3
    if len(data) >= 40 and printable_ratio(data) >= 0.82:
        score += 2
    score -= sum(data.count(marker) for marker in NON_ORIGINAL_MARKERS) * 12
    return score


def preview(data: bytes, limit: int = 180) -> str:
    shown = data[:limit]
    return "".join(chr(byte) if 32 <= byte < 127 or byte in (9, 10, 13) else "." for byte in shown)


def count_markers(data: bytes) -> dict[str, int]:
    return {marker.decode("ascii", errors="replace"): data.count(marker) for marker in SOURCE_MARKERS}


def encoded_payload_summary(source_path: Path) -> dict[str, Any]:
    if not source_path.exists():
        return {"present": False}
    text = source_path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r'\{\{aL([^"]+)', text)
    payload = match.group(1).encode("utf-8") if match else b""
    return {
        "present": bool(match),
        "encoded_bytes": len(payload),
        "encoded_sha256": sha256_bytes(payload) if payload else None,
        "source_file": file_summary(source_path),
        "wrapper_marker_counts": {
            "MoonVeil": text.count("MoonVeil"),
            "loadstring": text.count("loadstring"),
            "HttpGet": text.count("HttpGet"),
            "LPH": text.count("LPH"),
        },
    }


def summarize_bank(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    data = path.read_bytes()
    return {
        "path": str(path),
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "printable_ratio": round(printable_ratio(data), 4),
        "source_marker_counts": count_markers(data),
        "preview": preview(data),
    }


def summarize_rawhex(primary_dir: Path) -> dict[str, Any]:
    rawhex = read_json(primary_dir / "exact_source_candidates_rawhex.json")
    banks = {}
    for name in (
        "raw_literal_bank.bin",
        "raw_literal_bank_op226.bin",
        "raw_snapshot_strings_bank.bin",
        "raw_all_vm_strings_bank.bin",
        "raw_capture_bank.bin",
    ):
        summary = summarize_bank(primary_dir / name)
        if summary:
            banks[name] = summary
    return {
        "report_path": str(primary_dir / "exact_source_candidates_rawhex.json"),
        "status": rawhex.get("exact_recovery_status") if isinstance(rawhex, dict) else None,
        "reason": rawhex.get("reason") if isinstance(rawhex, dict) else None,
        "string_counts": rawhex.get("string_counts") if isinstance(rawhex, dict) else None,
        "candidate_count": rawhex.get("candidate_count") if isinstance(rawhex, dict) else None,
        "banks": banks,
    }


def summarize_behavior(primary_dir: Path) -> dict[str, Any]:
    behavior = read_json(primary_dir / "moonveil_v2_behavior_report.json")
    if not isinstance(behavior, dict):
        return {"present": False}
    exact = behavior.get("exact_source", {})
    return {
        "present": True,
        "exact_source": exact,
        "state": behavior.get("state"),
        "largest_blobs": behavior.get("largest_blobs", [])[:8],
        "empty_proto_returns": behavior.get("empty_proto_returns", []),
        "static_literal_audit": behavior.get("static_literal_audit"),
        "program_count": len(behavior.get("programs", [])),
        "trace_count": behavior.get("trace_count"),
    }


def summarize_branch_runs(work_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(work_root.glob("mv-arg-*/moonveil_recovery_report.json")):
        report = read_json(path)
        if not isinstance(report, dict):
            continue
        trace_dir = path.parent
        status_file = trace_dir / "moonveil_vm_execute_status_0014.txt"
        return_file = trace_dir / "moonveil_vm_return_1_0015.lua"
        rows.append(
            {
                "mode": trace_dir.name.removeprefix("mv-arg-"),
                "report_status": report.get("exact_recovery_status"),
                "status_file": status_file.read_text(encoding="utf-8", errors="replace").strip() if status_file.exists() else None,
                "return_file": file_summary(return_file),
                "return_preview": preview(return_file.read_bytes()) if return_file.exists() else None,
            }
        )
    return rows


def capture_index_rows(trace_dir: Path) -> list[dict[str, Any]]:
    path = trace_dir / "capture_index.jsonl"
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        capture_path = Path(str(item.get("path", "")))
        if not capture_path.exists():
            capture_path = trace_dir / capture_path.name
        rows.append(
            {
                "kind": item.get("kind"),
                "path": str(capture_path),
                "bytes": int(item.get("bytes", -1)) if str(item.get("bytes", "")).lstrip("-").isdigit() else None,
            }
        )
    return rows


def scan_source_candidates(trace_dirs: list[Path]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    blocked_names = (
        "dispatch_trace",
        "function_snapshot",
        "execute_vm",
        "extract_layers",
        "wrapper",
        "loadstring_input",
        "loadstring_seen",
        "loadstring_return",
        "op48_lookup",
        "table_concat",
        "pcall_error",
        "x_status",
        "vm_execute_status",
        "behavior",
        "compat_trace",
        "capture_index",
        "recovery_report",
        "rawhex",
    )
    for trace_dir in trace_dirs:
        for row in capture_index_rows(trace_dir):
            path = Path(row["path"])
            if not path.exists() or not path.is_file():
                continue
            if any(name in path.name for name in blocked_names):
                continue
            if path.stat().st_size > 2_000_000:
                continue
            data = path.read_bytes()
            if b"This script was generated using MoonVeil" in data:
                continue
            if data.startswith(b"pc=") or data.startswith(b"trace="):
                continue
            score = source_score(data)
            if score <= 0:
                continue
            candidates.append(
                {
                    "path": str(path),
                    "kind": row.get("kind"),
                    "bytes": len(data),
                    "sha256": sha256_bytes(data),
                    "score": score,
                    "printable_ratio": round(printable_ratio(data), 4),
                    "marker_counts": count_markers(data),
                    "preview": preview(data),
                }
            )
    candidates.sort(key=lambda item: (-int(item["score"]), -int(item["bytes"]), str(item["path"])))
    return {
        "candidate_count_after_excluding_wrappers_and_traces": len(candidates),
        "top_candidates": candidates[:20],
    }


def summarize_high_capture(high_capture_dir: Path) -> dict[str, Any]:
    rows = capture_index_rows(high_capture_dir)
    existing = [row for row in rows if Path(str(row["path"])).exists()]
    largest = sorted(existing, key=lambda row: int(row.get("bytes") or 0), reverse=True)[:12]
    return {
        "path": str(high_capture_dir),
        "capture_count": len(rows),
        "existing_capture_count": len(existing),
        "largest_captures": largest,
    }


def summarize_empty_explore(empty_explore_dir: Path) -> dict[str, Any]:
    report = read_json(empty_explore_dir / "moonveil_recovery_report.json")
    rawhex = read_json(empty_explore_dir / "exact_source_candidates_rawhex.json")
    empty_files = []
    for path in sorted(empty_explore_dir.glob("moonveil_empty_proto_return_*.txt")):
        empty_files.append(
            {
                "path": str(path),
                "bytes": path.stat().st_size,
                "sha256": sha256_bytes(path.read_bytes()),
                "text": path.read_text(encoding="utf-8", errors="replace"),
            }
        )
    return {
        "path": str(empty_explore_dir),
        "present": empty_explore_dir.exists(),
        "exact_recovery_status": report.get("exact_recovery_status") if isinstance(report, dict) else None,
        "exact_recovery_reason": report.get("exact_recovery_reason") if isinstance(report, dict) else None,
        "enabled": report.get("moonveil_empty_proto_explore") if isinstance(report, dict) else None,
        "source_candidates": len(report.get("analysis", {}).get("source_candidates", [])) if isinstance(report, dict) else None,
        "rawhex_status": rawhex.get("exact_recovery_status") if isinstance(rawhex, dict) else None,
        "rawhex_candidate_count": rawhex.get("candidate_count") if isinstance(rawhex, dict) else None,
        "empty_proto_files": empty_files,
    }


def summarize_brutecall(brutecall_dir: Path) -> dict[str, Any]:
    report = read_json(brutecall_dir / "moonveil_recovery_report.json")
    rawhex = read_json(brutecall_dir / "exact_source_candidates_rawhex.json")
    brute_files = []
    for path in sorted(brutecall_dir.glob("moonveil_brutecall_return_*")):
        data = path.read_bytes()
        brute_files.append(
            {
                "path": str(path),
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "hex": data.hex(),
                "source_score": source_score(data),
                "preview": preview(data),
            }
        )
    packed_tail = []
    for path in sorted(brutecall_dir.glob("moonveil_packed_return_*.txt"))[-8:]:
        packed_tail.append(
            {
                "path": str(path),
                "bytes": path.stat().st_size,
                "text": path.read_text(encoding="utf-8", errors="replace")[:2000],
            }
        )
    return {
        "path": str(brutecall_dir),
        "present": brutecall_dir.exists(),
        "enabled": report.get("moonveil_brutecall_return_frame") if isinstance(report, dict) else None,
        "min_trace": report.get("moonveil_brutecall_min_trace") if isinstance(report, dict) else None,
        "exact_recovery_status": report.get("exact_recovery_status") if isinstance(report, dict) else None,
        "exact_recovery_reason": report.get("exact_recovery_reason") if isinstance(report, dict) else None,
        "source_candidates": len(report.get("analysis", {}).get("source_candidates", [])) if isinstance(report, dict) else None,
        "rawhex_status": rawhex.get("exact_recovery_status") if isinstance(rawhex, dict) else None,
        "rawhex_candidate_count": rawhex.get("candidate_count") if isinstance(rawhex, dict) else None,
        "note": "rawhex candidates here were 8-byte trace/debug tokens, not source, when manually inspected",
        "brutecall_returns": brute_files,
        "packed_return_tail": packed_tail,
    }


def summarize_force_matrix(force_matrix_dir: Path) -> dict[str, Any]:
    matrix = read_json(force_matrix_dir / "summary.json")
    aggregate = read_json(Path("outputs/moonveil_v2_forced_branch_matrix_report.json"))
    if not isinstance(matrix, list):
        matrix = []
    if not isinstance(aggregate, dict):
        aggregate = {}
    statuses: dict[str, int] = {}
    source_counts = 0
    for item in matrix:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status"))
        statuses[status] = statuses.get(status, 0) + 1
        source_counts += int(item.get("source_count") or 0)
    largest = []
    for item in aggregate.get("largest_unique", [])[:20]:
        if not isinstance(item, dict):
            continue
        largest.append(
            {
                "bytes": item.get("bytes"),
                "sha256": item.get("sha256"),
                "printable_ratio": item.get("printable_ratio"),
                "markers": item.get("markers"),
                "head": item.get("head"),
                "examples": item.get("examples", [])[:3],
            }
        )
    return {
        "path": str(force_matrix_dir),
        "present": force_matrix_dir.exists(),
        "summary_path": str(force_matrix_dir / "summary.json"),
        "aggregate_report_path": "outputs/moonveil_v2_forced_branch_matrix_report.json",
        "run_count": len(matrix),
        "status_counts": statuses,
        "source_candidate_count": source_counts,
        "aggregate_sourceish_nonwrapper_count": aggregate.get("sourceish_nonwrapper_count"),
        "aggregate_sourceish_note": (
            "Non-wrapper marker hits in the aggregate report are trace/debug text containing words such as "
            "'function', not strict source candidates."
        ),
        "largest_unique_captures": largest,
    }


def summarize_expanded_rawhex(path: Path) -> dict[str, Any]:
    report = read_json(path)
    if not isinstance(report, dict):
        return {"present": False, "path": str(path)}
    return {
        "present": True,
        "path": str(path),
        "trace_dir_count": len(report.get("trace_dirs", [])),
        "string_counts": report.get("string_counts"),
        "candidate_count": report.get("candidate_count"),
        "exact_recovery_status": report.get("exact_recovery_status"),
        "reason": report.get("reason"),
        "transform_scope": (
            "identity, reverse, bit-not, bit rotations, zlib/raw-zlib/gzip/bz2/lzma, "
            "base32/base64/ascii85/base85, single-byte XOR, and add/sub byte masks"
        ),
        "top_candidates": report.get("candidates", [])[:8],
    }


def summarize_semantic_fallback(ir_path: Path, lua_path: Path) -> dict[str, Any]:
    semantic = read_json(ir_path)
    if not isinstance(semantic, dict):
        return {"present": False, "ir_path": str(ir_path), "lua_path": str(lua_path)}
    return {
        "present": True,
        "ir": file_summary(ir_path),
        "lua": file_summary(lua_path),
        "exact_recovery_status": semantic.get("exact_recovery_status"),
        "program_count": semantic.get("program_count"),
        "instruction_count": semantic.get("instruction_count"),
        "observed_instruction_count": semantic.get("observed_instruction_count"),
        "raw_literal_metadata_count": semantic.get("raw_literal_metadata_count"),
        "confidence_counts": semantic.get("confidence_counts"),
        "strict_source_candidates": semantic.get("strict_source_candidates"),
        "note": "Readable semantic VM fallback only; not exact original Luau source.",
    }


def write_artifact_copies(primary_dir: Path, output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    copied: dict[str, str] = {}
    for src_name, dst_name in (
        ("moonveil_v2_deobfuscated_behavior.lua", "moonveil_v2_deobfuscated_behavior.lua"),
        ("moonveil_v2_behavior_report.json", "moonveil_v2_behavior_report.json"),
        ("exact_source_candidates_rawhex.json", "moonveil_v2_rawhex_scan_report.json"),
        ("raw_literal_bank.bin", "moonveil_v2_raw_literal_bank.bin"),
        ("raw_literal_bank_op226.bin", "moonveil_v2_raw_literal_bank_op226.bin"),
        ("raw_snapshot_strings_bank.bin", "moonveil_v2_raw_snapshot_strings_bank.bin"),
    ):
        src = primary_dir / src_name
        if not src.exists():
            continue
        dst = output_dir / dst_name
        dst.write_bytes(src.read_bytes())
        copied[src_name] = str(dst)
    return copied


def main() -> int:
    args = parse_args()
    primary_dir = args.primary_dir
    output_dir = args.out.parent

    report: dict[str, Any] = {
        "sample": encoded_payload_summary(args.source),
        "runtime_artifacts": {
            "decoded_payload": file_summary(primary_dir / "moonveil_i_decoded_0004.bin"),
            "vm_chunk": file_summary(primary_dir / "moonveil_vm_chunk_0005.bin"),
            "vm_programs": file_summary(primary_dir / "moonveil_vm_programs.json"),
            "function_dump": file_summary(primary_dir / "luraph_function_dump.json"),
        },
        "behavior_report": summarize_behavior(primary_dir),
        "rawhex_scan": summarize_rawhex(primary_dir),
        "branch_runs": summarize_branch_runs(primary_dir.parent),
        "high_capture": summarize_high_capture(args.high_capture_dir),
        "empty_proto_explore": summarize_empty_explore(args.empty_explore_dir),
        "brutecall_probe": summarize_brutecall(args.brutecall_dir),
        "forced_branch_matrix": summarize_force_matrix(args.force_matrix_dir),
        "expanded_transform_scan": summarize_expanded_rawhex(args.expanded_rawhex_report),
        "semantic_fallback": summarize_semantic_fallback(args.semantic_ir, args.semantic_lua),
        "strict_capture_candidate_scan": scan_source_candidates([primary_dir, args.high_capture_dir]),
        "superseded_false_positives": [
            {
                "path": str(primary_dir / "luraph_recovery_report.json"),
                "reason": "older report counted the MoonVeil wrapper/loadstring input as exact source; this is not the original protected payload source",
            }
        ],
        "verdict": {
            "exact_recovery_status": "not_present_in_observed_runtime_and_static_data",
            "original_luau_exact_written": False,
            "reason": (
                "The decoded VM chunk, VM literals, recursive function dumps, high-capture string hooks, "
                "main returns, branch-mode runs, forced skipped-branch probes, and simple/raw byte transforms "
                "including the expanded forced-branch transform scan did not contain a source-like payload "
                "string. The only large Luau-looking text is the MoonVeil-generated wrapper, which is not "
                "the original Luau source."
            ),
        },
    }

    if args.copy_artifacts:
        report["copied_artifacts"] = write_artifact_copies(primary_dir, output_dir)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"wrote": str(args.out), "verdict": report["verdict"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
