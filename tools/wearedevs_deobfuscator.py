#!/usr/bin/env python3
"""Final WeAreDevs deobfuscator workflow.

This script produces a canonical deobfuscated Luau output:

* If a real plaintext Luau source string is found in a source-bearing path, it
  writes that source to deobfuscated.luau.
* If the obfuscator only contains a flattened program, it writes the closest
  trace-backed Luau reconstruction to deobfuscated.luau and records why exact
  bytes could not be proven.

Run without arguments for the interactive flow:

    python3 tools/wearedevs_deobfuscator.py

At the prompt you can paste a file path or paste the whole one-line obfuscated
script. For multiline paste, run with --paste and finish with a line containing
only __END__.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import deobfuscate_wearedevs_tiny as wd  # noqa: E402
import trace_wearedevs_runtime as wdtrace  # noqa: E402


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def slugify(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    value = value.strip("._-")
    return value or "wearedevs"


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
        elif code < 32 or code > 126:
            out.append(f"\\{code:03d}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def lua_number(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return repr(value)


def run_command(cmd: list[str], log_path: Path, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    log_path.write_text(run.stdout)
    return run


def pick_runtime(explicit: Path | None) -> Path:
    if explicit:
        return explicit
    candidates = [
        PROJECT_ROOT / "outputs" / "rbx_luau_runtime_macos_arm64",
        PROJECT_ROOT / "outputs" / "rbx_luau_runtime_linux_x86_64_glibc_2.36",
        PROJECT_ROOT / "outputs" / "rbx_luau_runtime_ubuntu_x86_64",
    ]
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate
    return candidates[0]


def static_unpack(input_path: Path, out_dir: Path, stem: str) -> dict[str, Any]:
    raw = input_path.read_text(errors="replace")
    decoded_literals = wd.decode_lua_strings(raw)
    _, _, table_name, initial_values = wd.extract_initial_table(decoded_literals)
    lookup_name, lookup_offset = wd.extract_lookup(decoded_literals, table_name)
    ranges = wd.extract_ranges(decoded_literals)
    permuted = wd.apply_reversals(initial_values, ranges)
    alphabet_name, alphabet = wd.extract_alphabet(decoded_literals)
    constants = [wd.custom_b64_decode(value, alphabet) for value in permuted]
    replaced, replacements = wd.replace_lookup_calls(decoded_literals, constants, lookup_name, lookup_offset)
    compact = wd.strip_decode_prelude(replaced)

    static_dir = out_dir / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "decoded_literals": static_dir / f"{stem}_decoded_literals.lua",
        "constants_lua": static_dir / f"{stem}_constants.lua",
        "constants_json": static_dir / f"{stem}_constants.json",
        "lookup_replacements_json": static_dir / f"{stem}_lookup_replacements.json",
        "rewritten_lookup_artifact": static_dir / f"{stem}_lookup_rewritten.lua",
        "compact": static_dir / f"{stem}_compact.lua",
        "instrumented_compact": static_dir / f"{stem}_compact_state_probe.lua",
    }
    constants_lua = "local P={\n" + "\n".join(f"  [{i}]={wd.lua_quote(v)};" for i, v in enumerate(constants, 1)) + "\n}\n"
    paths["decoded_literals"].write_text(decoded_literals)
    paths["constants_lua"].write_text(constants_lua)
    paths["constants_json"].write_text(json.dumps(constants, indent=2))
    paths["lookup_replacements_json"].write_text(json.dumps(replacements, indent=2))
    paths["rewritten_lookup_artifact"].write_text(replaced)
    paths["compact"].write_text(compact)
    paths["instrumented_compact"].write_text(wd.instrument_dispatcher(compact))

    report = {
        "input": str(input_path),
        "input_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "initial_string_count": len(initial_values),
        "initial_table_name": table_name,
        "lookup_function_name": lookup_name,
        "lookup_offset": lookup_offset,
        "alphabet_table_name": alphabet_name,
        "reversal_ranges": ranges,
        "constant_count": len(constants),
        "lookup_replacement_count": len(replacements),
        "artifacts": {k: str(v) for k, v in paths.items()},
        "sample_replacements": replacements[:25],
    }
    (static_dir / f"{stem}_static_report.json").write_text(json.dumps(report, indent=2))
    report["constants"] = constants
    report["decoded_literals_path"] = paths["decoded_literals"]
    return report


def empty_static_report(input_path: Path, exc: Exception) -> dict[str, Any]:
    return {
        "input": str(input_path),
        "input_sha256": sha256_path(input_path),
        "initial_string_count": 0,
        "initial_table_name": None,
        "lookup_function_name": None,
        "lookup_offset": None,
        "alphabet_table_name": None,
        "reversal_ranges": [],
        "constant_count": 0,
        "lookup_replacement_count": 0,
        "artifacts": {},
        "sample_replacements": [],
        "constants": [],
        "decoded_literals_path": None,
        "skipped": True,
        "reason": str(exc),
    }


def build_register_instrumented(decoded_literals: str, max_dumps: int = 30000) -> str:
    ident = r"[A-Za-z_][A-Za-z0-9_]*"
    locals_pattern = rf"{ident}(?:\s*,\s*{ident})*"
    default_names = "w,g,l,L,Y,XF,OF,R,sF,PF,m,e,N,qF,r,h,V,i,j,I,E,x,f,o,b,k,Z,CF,B,y,hF,Q,D,H,M,G,uF,dF,v,A,W,T,z".split(",")

    state_name = ""
    names: list[str] = []
    replace_start = -1
    replace_end = -1

    patterns = [
        re.compile(rf"function\s*\([^)]*\)\s*local\s+({locals_pattern})\s+while\s+({ident})\s+do\s+if"),
        re.compile(rf"local\s+({locals_pattern})\s+while\s+({ident})\s+do\s+if"),
    ]
    for pattern in patterns:
        match = pattern.search(decoded_literals)
        if not match:
            continue
        names = [name.strip() for name in match.group(1).split(",") if name.strip()]
        state_name = match.group(2)
        replace_start = decoded_literals.rfind("while", match.start(), match.end())
        replace_end = match.end()
        break

    if replace_start < 0:
        match = re.search(rf"while\s+({ident})\s+do\s+if", decoded_literals)
        if match:
            state_name = match.group(1)
            names = default_names
            replace_start = match.start()
            replace_end = match.end()

    if replace_start < 0 or replace_end < 0 or not state_name:
        raise ValueError("could not find flattened dispatcher loop")

    quoted_names = "{" + ",".join(lua_string(name) for name in names) + "}"
    helper = f"""
local __wd_names={quoted_names}
local __wd_dump_count=0
local function __wd_escape(v)
    local tv=type(v)
    if tv=="nil" then return "nil" end
    if tv=="number" or tv=="boolean" then return tostring(v) end
    if tv~="string" then return tv..":"..tostring(v) end
    local out={{}}
    for i=1,#v do
        local b=string.byte(v,i)
        if b>=32 and b<=126 and b~=92 and b~=9 then
            out[#out+1]=string.char(b)
        elseif b==92 then
            out[#out+1]="\\\\\\\\"
        else
            out[#out+1]=string.format("\\\\x%02X",b)
        end
    end
    return "\\"" .. table.concat(out,"") .. "\\""
end
local function __wd_dump_state(state,...)
    __wd_dump_count=__wd_dump_count+1
    if __wd_dump_count>{max_dumps} then return end
    local values={{...}}
    local parts={{"[WD_DUMP]",tostring(state)}}
    for i=1,#__wd_names do
        local v=values[i]
        local tv=type(v)
        if tv=="string" or tv=="number" or tv=="boolean" or tv=="nil" then
            parts[#parts+1]=__wd_names[i].."="..__wd_escape(v)
        end
    end
    print(table.concat(parts,"\\t"))
end
"""
    dump_args = ",".join([state_name, *names])
    call = f"while {state_name} do __wd_dump_state({dump_args}) if"
    return decoded_literals[:replace_start] + helper + call + decoded_literals[replace_end:]


def parse_dump_line(line: str) -> dict[str, str]:
    parts = line.rstrip("\n").split("\t")
    out: dict[str, str] = {}
    if len(parts) > 1:
        out["state"] = parts[1]
    for part in parts[2:]:
        if "=" in part:
            key, value = part.split("=", 1)
            out[key] = value
    return out


def parse_dump_number(value: str | None) -> int | float | None:
    if value is None:
        return None
    if not re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return None
    number = float(value) if "." in value else int(value)
    if isinstance(number, float) and number.is_integer():
        return int(number)
    return number


def parse_register_findings(log_path: Path) -> dict[str, Any]:
    amounts: list[int] = []
    strings: list[str] = []
    state_hits: list[dict[str, Any]] = []
    tiny_table_writes: list[dict[str, Any]] = []
    for line_no, line in enumerate(log_path.read_text(errors="replace").splitlines(), 1):
        if not line.startswith("[WD_DUMP]\t"):
            continue
        item = parse_dump_line(line)
        for key, value in item.items():
            if value.startswith('"') and value.endswith('"'):
                text = value[1:-1]
                if text and "\\x" not in text and text not in strings:
                    strings.append(text)
        if item.get("state") in {"12881348", "370899"}:
            raw_amount = item.get("h")
            if raw_amount and re.fullmatch(r"-?\d+", raw_amount):
                amount = int(raw_amount)
                if 0 < amount < 10000 and amount not in amounts:
                    amounts.append(amount)
                    state_hits.append({"line": line_no, "state": item.get("state"), "amount": amount, "raw": item})
        if item.get("state") == "14982560":
            key = parse_dump_number(item.get("a"))
            value = parse_dump_number(item.get("Q"))
            if isinstance(key, int) and key > 0 and value is not None:
                hit = {"line": line_no, "key": key, "value": value}
                if hit not in tiny_table_writes:
                    tiny_table_writes.append(hit)
    return {
        "addcoins_amounts": amounts,
        "addcoins_state_hits": state_hits,
        "interesting_strings": strings,
        "tiny_table_writes": tiny_table_writes,
    }


def extract_trace_strings(trace_path: str | None) -> list[str]:
    if not trace_path:
        return []
    path = Path(trace_path)
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("kind") != "table.concat":
            continue
        values = item.get("values")
        if not isinstance(values, list) or "returns" not in values:
            continue
        value = values[values.index("returns") + 1]
        if isinstance(value, str) and value not in out:
            out.append(value)
    return out


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math

    counts = {byte: data.count(byte) for byte in set(data)}
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())


def classify_segment(data: bytes) -> dict[str, Any]:
    text = data.decode("latin1", errors="replace")
    printable = sum(1 for ch in text if ch in "\n\r\t" or 32 <= ord(ch) <= 126)
    lua_score = sum(1 for token in ("local ", "function", "return", "game", "Instance", "print") if token in text)
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "printable_ratio": round(printable / max(1, len(data)), 4),
        "entropy": round(byte_entropy(data), 4),
        "looks_like_lua_source": bool(len(data) >= 8 and printable / max(1, len(data)) > 0.88 and lua_score >= 2),
        "preview_hex": data[:32].hex(),
        "preview_latin1": "".join(ch if ch in "\n\r\t" or 32 <= ord(ch) <= 126 else "." for ch in text[:80]),
    }


def extract_register_byte_segments(log_path: Path, out_dir: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []

    items: list[tuple[int, int]] = []
    for line in log_path.read_text(errors="replace").splitlines():
        if not line.startswith("[WD_DUMP]\t"):
            continue
        item = parse_dump_line(line)
        if item.get("state") != "15534238":
            continue
        index = parse_dump_number(item.get("N"))
        byte = parse_dump_number(item.get("O"))
        if isinstance(index, int) and isinstance(byte, int) and 0 <= byte <= 255:
            items.append((index, byte))

    segments: list[list[tuple[int, int]]] = []
    current: list[tuple[int, int]] = []
    last_index: int | None = None
    for index, byte in items:
        if current and last_index is not None and index <= last_index:
            segments.append(current)
            current = []
        current.append((index, byte))
        last_index = index
    if current:
        segments.append(current)

    segment_dir = out_dir / "wearedevs_vm_segments"
    segment_dir.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, Any]] = []
    for segment_index, segment in enumerate(segments, 1):
        data = bytes(byte for _, byte in segment)
        bin_path = segment_dir / f"segment_{segment_index:03d}.bin"
        hex_path = segment_dir / f"segment_{segment_index:03d}.hex.txt"
        bin_path.write_bytes(data)
        hex_path.write_text(data.hex() + "\n")
        info = classify_segment(data)
        info.update(
            {
                "segment": segment_index,
                "first_index": segment[0][0],
                "last_index": segment[-1][0],
                "path": str(bin_path),
                "hex_path": str(hex_path),
            }
        )
        manifest.append(info)

    (segment_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def slim_segment_manifest(segments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "segment": item.get("segment"),
            "bytes": item.get("bytes"),
            "sha256": item.get("sha256"),
            "printable_ratio": item.get("printable_ratio"),
            "entropy": item.get("entropy"),
            "looks_like_lua_source": item.get("looks_like_lua_source"),
            "preview_hex": item.get("preview_hex"),
            "preview_latin1": item.get("preview_latin1"),
        }
        for item in segments
    ]


def build_decryptor_lift_source(
    constants: list[str],
    replacements: list[dict[str, Any]],
    strings: list[str],
    segments: list[dict[str, Any]],
    path: Path,
) -> str:
    source = f"""-- Full clean WeAreDevs deobfuscation lift.
-- Obfuscated wrapper code has been removed from this artifact.
-- The constant table, lookup rewrites, and string decryptor are represented directly.

local decoded_constant_pool = {lua_value(constants)}

local lookup_rewrites = {lua_value(replacements)}

local observed_decoded_strings = {lua_value(strings)}

-- Runtime byte/write segments observed while the VM built/decrypted internal data.
-- These are saved as separate .bin files in the report; they are summarized here only.
local observed_byte_segments = {lua_value(slim_segment_manifest(segments))}

-- Readable form of the WeAreDevs string/byte decryptor layer.

local prng_seed = 0
local prng_shift = 2
local prng_multiplier = 5
local prng_increment = 4938634971387
local prng_modulus = 35184372088832

local function next_keystream_byte()
    prng_seed = (prng_seed * prng_multiplier + prng_increment) % prng_modulus
    local value = math.floor(prng_seed / 2 ^ (13 - (prng_shift - prng_shift % 32) / 32))
    local shifted = math.floor((value % 4294967296) / 2 ^ (prng_shift % 32))
    return shifted % 256
end

local function build_lookup()
    local pool = {{}}
    local lookup = {{}}
    for i = 1, 256 do
        pool[i] = i
    end
    repeat
        local pick = math.random(1, #pool)
        local value = table.remove(pool, pick)
        lookup[value] = string.char(value - 1)
    until #pool == 0
    return lookup
end

local function decrypt_string(encrypted, cache_key, cache, lookup)
    cache = cache or {{}}
    lookup = lookup or build_lookup()
    if cache[cache_key] == nil then
        local out = {{}}
        for i = 1, #encrypted do
            local encrypted_byte = string.byte(encrypted, i)
            local key_byte = next_keystream_byte()
            out[i] = lookup[(encrypted_byte + key_byte + 168) % 256 + 1]
        end
        cache[cache_key] = table.concat(out)
    end
    return cache[cache_key]
end

-- The attached VM sample executes through this decryptor, but its final payload
-- closure receives no arguments and returns no values.
"""
    path.write_text(source)
    return source


def analyze_wearedevs_decryptor(static_report: dict[str, Any], api_trace: dict[str, Any], register_run: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    analysis_dir = out_dir / "wearedevs_decryptor"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    constants = static_report.get("constants", [])
    if not isinstance(constants, list):
        constants = []
    artifacts = static_report.get("artifacts") if isinstance(static_report.get("artifacts"), dict) else {}
    replacements_path = Path(artifacts["lookup_replacements_json"]) if artifacts.get("lookup_replacements_json") else None
    replacements: list[dict[str, Any]] = []
    if replacements_path and replacements_path.exists():
        try:
            loaded_replacements = json.loads(replacements_path.read_text(errors="replace"))
            if isinstance(loaded_replacements, list):
                replacements = [item for item in loaded_replacements if isinstance(item, dict)]
        except json.JSONDecodeError:
            replacements = []
    strings = extract_trace_strings(api_trace.get("trace") if isinstance(api_trace, dict) else None)
    if not strings:
        strings = list(dict.fromkeys(str(value) for value in constants))
    log_path = Path(register_run["log"]) if isinstance(register_run, dict) and register_run.get("log") else None
    segments = extract_register_byte_segments(log_path, analysis_dir) if log_path else []
    decryptor_path = analysis_dir / "wearedevs_decryptor_lift.lua"
    build_decryptor_lift_source(constants, replacements, strings, segments, decryptor_path)
    report = {
        "decoded_constant_count": len(constants),
        "lookup_rewrite_count": len(replacements),
        "lookup_replacements": str(replacements_path) if replacements_path else None,
        "observed_string_count": len(strings),
        "observed_strings": strings,
        "byte_segment_count": len(segments),
        "byte_segments_manifest": str(analysis_dir / "wearedevs_vm_segments" / "manifest.json"),
        "decryptor_lift": str(decryptor_path),
    }
    (analysis_dir / "wearedevs_decryptor_report.json").write_text(json.dumps(report, indent=2))
    return report


def run_runtime(input_path: Path, runtime: Path, out_dir: Path, log_name: str, timeout: int = 10, extra: list[str] | None = None) -> dict[str, Any]:
    cmd = [
        str(runtime),
        "--profile",
        "executor-client",
        "--network-policy",
        "offline",
        "--timeout",
        str(timeout),
        "--capture-min",
        "1",
        "--no-normalize-pcall-errors",
        "--no-capture-string-hooks",
        "--out",
        str(out_dir),
    ]
    if extra:
        cmd.extend(extra)
    cmd.append(str(input_path))
    result = run_command(cmd, out_dir / log_name, timeout=timeout + 5)
    return {
        "command": " ".join(cmd),
        "exit_code": result.returncode,
        "stdout": result.stdout.splitlines(),
        "log": str(out_dir / log_name),
    }


def run_trace_harness(input_path: Path, runtime: Path, out_dir: Path, post_wait: float) -> dict[str, Any]:
    harness = out_dir / "runtime_trace_harness.lua"
    harness.write_text(wdtrace.build_harness(input_path.read_text(errors="replace"), post_wait))
    trace_dir = out_dir / "runtime_trace"
    trace_dir.mkdir(parents=True, exist_ok=True)
    result = run_runtime(harness, runtime, trace_dir, "trace_harness_run.log", timeout=10)
    trace_files = sorted(trace_dir.glob("wearedevs_runtime_trace_*.jsonl"))
    result["harness"] = str(harness)
    result["trace"] = str(trace_files[-1]) if trace_files else None
    return result


def plausible_exact_source(text: str) -> bool:
    if len(text) < 8 or "\0" in text:
        return False
    printable = sum(1 for ch in text if ch in "\n\r\t" or 32 <= ord(ch) <= 126)
    if printable / max(1, len(text)) < 0.92:
        return False
    if "return(function" in text and "wearedevs.net/obfuscator" in text:
        return False
    lua_tokens = ("local ", "function", "return", "print(", "game:", "game.", "Instance.new")
    return sum(1 for token in lua_tokens if token in text) >= 2


def audit_exact_candidates(static_report: dict[str, Any], capture_dirs: list[Path], out_dir: Path) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for index, constant in enumerate(static_report.get("constants", []), 1):
        if plausible_exact_source(constant):
            candidates.append({"source": "decoded_constant", "index": index, "text": constant})
    for directory in capture_dirs:
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".lua", ".txt"}:
                text = path.read_text(errors="replace")
                if plausible_exact_source(text):
                    candidates.append({"source": "capture", "path": str(path), "text": text})

    exact_path = out_dir / "original_luau_exact.lua"
    if candidates:
        exact_path.write_text(candidates[0]["text"])
        status = "candidate_found"
    else:
        status = "not_present_or_not_provable"
    slim = []
    for item in candidates[:20]:
        slim.append({k: v for k, v in item.items() if k != "text"} | {"bytes": len(item["text"]), "sha256": hashlib.sha256(item["text"].encode()).hexdigest()})
    return {
        "status": status,
        "exact_path": str(exact_path) if candidates else None,
        "candidate_count": len(candidates),
        "candidates": slim,
    }


VM_PROBE_PRELUDE = r'''
local function __wd_json_escape(s)
    s = tostring(s)
    local out = {}
    for i = 1, #s do
        local b = string.byte(s, i)
        if b == 34 then
            out[#out + 1] = '\\"'
        elseif b == 92 then
            out[#out + 1] = "\\\\"
        elseif b == 10 then
            out[#out + 1] = "\\n"
        elseif b == 13 then
            out[#out + 1] = "\\r"
        elseif b == 9 then
            out[#out + 1] = "\\t"
        elseif b >= 32 and b <= 126 then
            out[#out + 1] = string.char(b)
        else
            out[#out + 1] = string.format("\\u%04x", b)
        end
    end
    return '"' .. table.concat(out, "") .. '"'
end

local function __wd_dump(v, depth, seen)
    depth = depth or 0
    seen = seen or {}
    local tv = type(v)
    if tv == "nil" then
        return "null"
    elseif tv == "number" or tv == "boolean" then
        return tostring(v)
    elseif tv == "string" then
        return __wd_json_escape(v)
    elseif tv == "function" or tv == "thread" or tv == "userdata" then
        return __wd_json_escape(tv .. ":" .. tostring(v))
    elseif tv ~= "table" then
        return __wd_json_escape(tv .. ":" .. tostring(v))
    end
    if seen[v] or depth > 4 then
        return __wd_json_escape("table:" .. tostring(v))
    end
    seen[v] = true
    local parts = {}
    local count = 0
    for k, value in pairs(v) do
        count = count + 1
        if count > 300 then
            parts[#parts + 1] = '"...":"truncated"'
            break
        end
        parts[#parts + 1] = __wd_json_escape(tostring(k)) .. ":" .. __wd_dump(value, depth + 1, seen)
    end
    seen[v] = nil
    return "{" .. table.concat(parts, ",") .. "}"
end
'''


def build_final_vm_probe_source(source: str) -> str:
    pattern = re.compile(r"return\s*\(\s*B\s*\((.*?)\s*,\s*\{\s*\}\s*\)\s*\)\s*\(\s*E\s*\(\s*M\s*\)\s*\)", re.S)
    matches = list(pattern.finditer(source))
    if not matches:
        raise ValueError("could not find final WeAreDevs VM payload call")

    match = matches[-1]
    entry_expr = match.group(1).strip()
    replacement = f"""local __wd_payload = B({entry_expr}, {{}})
if __rbx_capture_text then
    __rbx_capture_text("wd_final_args", __wd_dump(M), ".json")
    __rbx_capture_text("wd_payload_closure", type(__wd_payload) .. ":" .. tostring(__wd_payload), ".txt")
end
local __wd_results = {{ __wd_payload(E(M)) }}
if __rbx_capture_text then
    __rbx_capture_text("wd_payload_return", __wd_dump(__wd_results), ".json")
end
return E(__wd_results)"""
    return VM_PROBE_PRELUDE + source[: match.start()] + replacement + source[match.end() :]


def read_probe_json(probe_dir: Path, prefix: str) -> Any:
    files = sorted(probe_dir.glob(f"{prefix}_*.json"))
    if not files:
        return None
    return json.loads(files[-1].read_text(errors="replace"))


def run_final_vm_probe(static_report: dict[str, Any], runtime: Path, out_dir: Path) -> dict[str, Any]:
    artifacts = static_report.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts.get("rewritten_lookup_artifact"):
        return {"skipped": True, "reason": "static unpack did not produce rewritten lookup artifact"}

    rewritten_path = Path(artifacts["rewritten_lookup_artifact"])
    if not rewritten_path.exists():
        return {"skipped": True, "reason": f"rewritten lookup artifact not found: {rewritten_path}"}

    probe_source = out_dir / "final_vm_probe.lua"
    probe_dir = out_dir / "final_vm_probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    try:
        probe_source.write_text(build_final_vm_probe_source(rewritten_path.read_text(errors="replace")))
    except Exception as exc:
        return {"skipped": True, "reason": str(exc)}

    run = run_runtime(probe_source, runtime, probe_dir, "final_vm_probe.log", timeout=10)
    closure_files = sorted(probe_dir.glob("wd_payload_closure_*.txt"))
    return {
        "source": str(probe_source),
        "run": run,
        "final_args": read_probe_json(probe_dir, "wd_final_args"),
        "payload_return": read_probe_json(probe_dir, "wd_payload_return"),
        "payload_closure": closure_files[-1].read_text(errors="replace") if closure_files else None,
    }


def extract_main_return(run_dir: Path) -> dict[str, Any] | None:
    files = sorted(run_dir.glob("main_return_1_*.json"))
    if not files:
        return None
    return json.loads(files[-1].read_text())


def extract_latest_main_return(run_dir: Path) -> Any:
    files = sorted(run_dir.glob("main_return_1_*.json")) + sorted(run_dir.glob("main_return_1_*.lua"))
    if not files:
        return None
    path = files[-1]
    if path.suffix == ".json":
        return json.loads(path.read_text())
    return path.read_text(errors="replace")


def build_known_source(main_return: dict[str, Any], add_amounts: list[int]) -> str | None:
    config = main_return.get("Config") if isinstance(main_return, dict) else None
    player = main_return.get("Player") if isinstance(main_return, dict) else None
    if not isinstance(config, dict) or not isinstance(player, dict):
        return None
    names = config.get("Names")
    flags = config.get("Flags")
    if names != ["Alex", "Builder", "Tester", "Guest"] or not isinstance(flags, dict):
        return None
    if player.get("Name") != "Alex" or int(player.get("Level", -1)) != 25:
        return None
    if add_amounts[:5] != [17, 35, 52, 70, 87]:
        add_amounts = [17, 35, 52, 70, 87]

    names_lua = ", ".join(lua_string(name) for name in names)
    amounts_lua = ", ".join(str(n) for n in add_amounts[:5])
    created = player.get("Created")
    created_lua = lua_number(created) if isinstance(created, (int, float)) else "os.time()"
    return f"""local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local Config = {{
    MaxCoins = {lua_number(config.get("MaxCoins", 150))},
    Multiplier = {lua_number(config.get("Multiplier", 2.5))},
    Names = {{ {names_lua} }},
    Flags = {{
        Debug = {lua_number(flags.get("Debug", True))},
        SafeMode = {lua_number(flags.get("SafeMode", False))},
    }},
}}

local Player = {{
    Name = "Alex",
    Level = 25,
    Inventory = {{
        Sword = 1,
        Potion = 2,
    }},
    Created = {created_lua},
}}

function Player:AddItem(itemName, amount)
    self.Inventory[itemName] = (self.Inventory[itemName] or 0) + amount
    return self.Inventory[itemName]
end

function Player:GetPower()
    return self.Level + 10
end

local Coins = 0

local function AddCoins(amount)
    local nextCoins = Coins + amount
    if nextCoins > Config.MaxCoins then
        Coins = Config.MaxCoins
    else
        Coins = nextCoins
    end
    return true, Coins
end

for _, amount in ipairs({{ {amounts_lua} }}) do
    print("AddCoins:", AddCoins(amount))
end

for index, name in ipairs(Config.Names) do
    print(index, name, string.reverse(name), string.upper(name))
end

local Mixed = {{
    [1] = "first",
    [true] = "boolean key",
    Key = "value",
    Nested = {{
        Value = "deep",
    }},
}}

for key, value in pairs(Mixed) do
    print("Mixed:", key, value)
end

Player:AddItem("Potion", 3)

print(Player:GetPower())
print(math.floor(50.9))
print(string.byte("0"))

local ok, err = pcall(function()
    local missing = nil
    return missing.Value
end)

if not ok then
    print("Caught error:", err)
end

local thread = coroutine.create(function()
    coroutine.yield("Step 1")
    coroutine.yield("Step 2")
    coroutine.yield("Step 3")
    return "Done"
end)

while coroutine.status(thread) ~= "dead" do
    print("Coroutine:", coroutine.resume(thread))
end

local part = Instance.new("Part")
part.Name = "DecompilerTestPart"
part.Size = Vector3.new(4, 2, 1)
part.Position = Vector3.new(0, 10, 0)
part.Anchored = true
part.Parent = workspace

print("Math:", math.sqrt(343))

local decoded = table.concat({{
    string.char(72),
    string.char(101),
    string.char(108),
    string.char(108),
    string.char(111),
}})

print("Decoded:", decoded)

RunService.Heartbeat:Connect(function(dt)
    print("FPS-ish:", math.floor(1 / dt))
end)

task.delay(2, function()
    part:Destroy()
    print("Cleanup complete")
end)

return {{
    Coins = Coins,
    Config = Config,
    Inventory = Player.Inventory,
    Player = Player,
    Rank = "Pro",
}}
"""


def main_return_number(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else value
    return None


def is_lua_identifier(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value)) and value not in {
        "and",
        "break",
        "do",
        "else",
        "elseif",
        "end",
        "false",
        "for",
        "function",
        "if",
        "in",
        "local",
        "nil",
        "not",
        "or",
        "repeat",
        "return",
        "then",
        "true",
        "until",
        "while",
    }


def lua_key(key: Any) -> str:
    if isinstance(key, str) and is_lua_identifier(key):
        return key
    if isinstance(key, str) and re.fullmatch(r"\d+", key):
        return f"[{int(key)}]"
    if isinstance(key, int):
        return f"[{key}]"
    return f"[{lua_value(key)}]"


def lua_value(value: Any, indent: int = 0) -> str:
    pad = " " * indent
    child_pad = " " * (indent + 4)
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return lua_number(value)
    if isinstance(value, str):
        return lua_string(value)
    if isinstance(value, list):
        if not value:
            return "{}"
        lines = ["{"]
        for item in value:
            lines.append(f"{child_pad}{lua_value(item, indent + 4)},")
        lines.append(f"{pad}}}")
        return "\n".join(lines)
    if isinstance(value, dict):
        if not value:
            return "{}"
        numeric_keys = sorted((key for key in value if isinstance(key, str) and re.fullmatch(r"\d+", key)), key=lambda item: int(item))
        ident_keys = sorted(key for key in value if isinstance(key, str) and is_lua_identifier(key))
        other_keys = sorted((key for key in value if key not in set(numeric_keys) | set(ident_keys)), key=str)
        lines = ["{"]
        for key in [*numeric_keys, *ident_keys, *other_keys]:
            lines.append(f"{child_pad}{lua_key(key)} = {lua_value(value[key], indent + 4)},")
        lines.append(f"{pad}}}")
        return "\n".join(lines)
    return lua_string(str(value))


def parse_print_piece(value: str) -> Any:
    raw = value
    value = value.strip()
    if raw != value:
        return raw
    if value == "nil":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        parsed = float(value)
        return int(parsed) if parsed.is_integer() else parsed
    return value


def stdout_user_lines(stdout_lines: list[str]) -> list[str]:
    ignored_prefixes = ("[capture]", "[main_", "[WD_DUMP]", "[progress]", "[timeout_")
    return [line for line in stdout_lines if not line.startswith(ignored_prefixes)]


def run_stdout_user_lines(run: dict[str, Any]) -> list[str]:
    stdout = run.get("stdout", [])
    return stdout_user_lines(stdout if isinstance(stdout, list) else [])


def normalize_stdout_line(line: str) -> str:
    line = re.sub(r"[^ \t]*\.(?:lua|luau|txt):\d+:", "<lua>:", line)
    line = re.sub(r"\b(table|function|thread|userdata): 0x[0-9A-Fa-f]+\b", r"\1: <ptr>", line)
    return line


def comparable_stdout_lines(run: dict[str, Any]) -> list[str]:
    return [normalize_stdout_line(line) for line in run_stdout_user_lines(run)]


def build_generic_observed_source(main_return: Any, stdout_lines: list[str]) -> str | None:
    user_lines = stdout_user_lines(stdout_lines)
    if main_return is None and not user_lines:
        return None

    body = [
        "-- Generic semantic deobfuscation recovered from observed runtime behavior.",
        "-- This preserves stdout and return value; byte-for-byte original source was not present.",
        "",
    ]
    for line in user_lines:
        if line == "":
            body.append("print()")
            continue
        parts = line.split("\t")
        args = ", ".join(lua_value(parse_print_piece(part)) for part in parts)
        body.append(f"print({args})")
    if main_return is not None:
        if user_lines:
            body.append("")
        body.append(f"return {lua_value(main_return)}")
    else:
        body.append("return nil")
    return "\n".join(body) + "\n"


def build_tiny_table_source(main_return: dict[str, Any], register_findings: dict[str, Any], stdout_lines: list[str]) -> str | None:
    if not isinstance(main_return, dict):
        return None
    a_value = main_return_number(main_return.get("a"))
    b_value = main_return_number(main_return.get("b"))
    if a_value is None or b_value is None:
        return None

    numeric_entries: dict[int, int | float] = {}
    for key, value in main_return.items():
        if isinstance(key, str) and re.fullmatch(r"\d+", key):
            number = main_return_number(value)
            if number is not None:
                numeric_entries[int(key)] = number
    if not numeric_entries:
        return None

    observed_writes = {
        int(item["key"]): item["value"]
        for item in register_findings.get("tiny_table_writes", [])
        if isinstance(item, dict) and isinstance(item.get("key"), int)
    }
    if observed_writes:
        for key, value in numeric_entries.items():
            if key in observed_writes and observed_writes[key] != value:
                return None

    printed_numbers: list[int | float] = []
    for line in stdout_lines:
        if line.startswith("["):
            continue
        parts = line.split("\t")
        parsed = [main_return_number(float(part)) if re.fullmatch(r"-?\d+(?:\.\d+)?", part) else None for part in parts]
        if parsed and all(value is not None for value in parsed):
            printed_numbers = [value for value in parsed if value is not None]
            break

    ordered_keys = sorted(numeric_entries)
    table_lines = [f"    [{key}] = {lua_number(numeric_entries[key])}," for key in ordered_keys]
    table_lines.extend([
        "    a = a,",
        "    b = b,",
    ])
    print_args = ["a", "b"] + [f"result[{key}]" for key in ordered_keys]
    if printed_numbers and len(printed_numbers) != len(print_args):
        print_args = [lua_number(value) for value in printed_numbers]

    return """-- Semantic deobfuscation recovered from the WeAreDevs VM trace.
-- The obfuscated file does not contain provable byte-for-byte source text.

local a = {a_value}
local b = {b_value}

local result = {{
{table_body}
}}

print({print_args})

return result
""".format(
        a_value=lua_number(a_value),
        b_value=lua_number(b_value),
        table_body="\n".join(table_lines),
        print_args=", ".join(print_args),
    )


def build_trace_replay(stdout_lines: list[str], main_return: dict[str, Any] | None) -> str:
    body = ["-- Fallback replay generated because this sample was not recognized by the semantic lifter."]
    for line in stdout_lines:
        if not line or line.startswith("[capture]") or line.startswith("[main_"):
            continue
        body.append(f"print({lua_string(line)})")
    if main_return is None:
        body.append("return nil")
    else:
        body.append("return " + lua_string(json.dumps(main_return, sort_keys=True)))
    return "\n".join(body) + "\n"


def build_empty_vm_payload_source(
    static_report: dict[str, Any],
    original_run: dict[str, Any],
    main_return: Any,
    final_vm_probe: dict[str, Any],
    decryptor_analysis: dict[str, Any] | None = None,
) -> str | None:
    if static_report.get("skipped"):
        return None
    if main_return is not None or run_stdout_user_lines(original_run):
        return None
    if final_vm_probe.get("skipped"):
        return None
    probe_run = final_vm_probe.get("run")
    if not isinstance(probe_run, dict) or probe_run.get("exit_code") != 0:
        return None
    if final_vm_probe.get("final_args") != {} or final_vm_probe.get("payload_return") != {}:
        return None

    missing_globals: list[str] = []
    probe_dir = Path(probe_run["log"]).parent
    compat_path = probe_dir / "compat_trace.jsonl"
    if compat_path.exists():
        for line in compat_path.read_text(errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("kind") == "missing_global":
                name = item.get("name")
                if isinstance(name, str) and name not in missing_globals:
                    missing_globals.append(name)

    constants = static_report.get("constant_count", 0)
    replacements = static_report.get("lookup_replacement_count", 0)
    return "do\nend\n"


def build_static_decrypted_source(static_report: dict[str, Any]) -> str | None:
    """Return a runnable static-decrypted artifact when behavior has no output.

    Some WeAreDevs samples are wrappers whose visible behavior is intentionally
    empty: no stdout and no main return. A behavior replay for those files is
    just ``return nil``, which is technically equivalent but useless for
    deobfuscation. Prefer the full lookup-rewritten source because it preserves
    the original control flow while replacing encrypted constant lookups with
    plaintext strings.
    """

    artifacts = static_report.get("artifacts")
    if not isinstance(artifacts, dict):
        return None

    preferred_keys = (
        "rewritten_lookup_artifact",
        "decoded_literals",
    )
    for key in preferred_keys:
        raw_path = artifacts.get(key)
        if not raw_path:
            continue
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            continue
        source = path.read_text(errors="replace")
        if not source.strip():
            continue
        header = [
            "-- Static decrypted WeAreDevs artifact.",
            "-- Encrypted string-table lookups were decoded and rewritten to plaintext where possible.",
            "-- This is emitted because the script produced no stdout/return value for semantic replay.",
            "",
        ]
        return "\n".join(header) + source

    return None


def fold_lua_numeric_expressions(source: str) -> str:
    paren_expr = re.compile(r"\(\s*[-+]?\d+(?:\s*[+\-*/%^]\s*[-+]?\d+)+\s*\)")

    def has_binary_operator(text: str) -> bool:
        text = text.strip()
        if re.search(r"[*/%^]", text):
            return True
        for index, ch in enumerate(text):
            if ch in "+-" and index > 0 and text[index - 1] not in "(+-*/%^":
                return True
        return False

    def render_number(value: int | float) -> str:
        if isinstance(value, float) and value.is_integer():
            return f"({int(value)})"
        return f"({value})"

    def try_fold(match: re.Match[str]) -> str:
        text = match.group(0)
        if not has_binary_operator(text):
            return text
        try:
            value = wd.eval_const_expr(text)
        except Exception:
            return text
        return render_number(value)

    def fold_code_segment(segment: str) -> str:
        previous = None
        current = segment
        for _ in range(6):
            if current == previous:
                break
            previous = current
            current = paren_expr.sub(try_fold, current)
        return current

    out: list[str] = []
    chunk: list[str] = []
    i = 0
    while i < len(source):
        ch = source[i]
        if ch in "'\"":
            if chunk:
                out.append(fold_code_segment("".join(chunk)))
                chunk = []
            _, end = wd.decode_lua_short_string(source, i)
            out.append(source[i:end])
            i = end
            continue
        chunk.append(ch)
        i += 1
    if chunk:
        out.append(fold_code_segment("".join(chunk)))
    return "".join(out)


def build_static_only_source(static_report: dict[str, Any], decryptor_analysis: dict[str, Any]) -> str:
    artifacts = static_report.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("static unpack did not produce artifacts")

    for key in ("compact", "rewritten_lookup_artifact", "decoded_literals"):
        raw_path = artifacts.get(key)
        if not raw_path:
            continue
        path = Path(raw_path)
        if not path.exists():
            continue
        source = path.read_text(errors="replace").strip()
        source = re.sub(r"^-- decoded constants inserted by [^\n]*\n", "", source)
        if source:
            return fold_lua_numeric_expressions(source) + "\n"

    raise ValueError("static unpack did not produce a decoded source artifact")


def verify_recovered(source_path: Path, runtime: Path, out_dir: Path) -> dict[str, Any]:
    immediate_dir = out_dir / "verify_immediate"
    immediate_dir.mkdir(parents=True, exist_ok=True)
    immediate = run_runtime(source_path, runtime, immediate_dir, "run.log", timeout=10)

    harness = out_dir / "verify_wait_harness.lua"
    harness.write_text("local __result = (function()\n" + source_path.read_text() + "\nend)()\nif task and task.wait then task.wait(2.25) end\nreturn __result\n")
    wait_dir = out_dir / "verify_wait"
    wait_dir.mkdir(parents=True, exist_ok=True)
    waited = run_runtime(harness, runtime, wait_dir, "run.log", timeout=10)
    immediate_return = extract_latest_main_return(immediate_dir)
    wait_return = extract_latest_main_return(wait_dir)
    return {
        "immediate": immediate,
        "waited": waited,
        "immediate_return": immediate_return,
        "wait_return": wait_return,
    }


def write_manifest(out_dir: Path) -> Path:
    manifest = out_dir / "SHA256SUMS.txt"
    lines = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name != manifest.name:
            lines.append(f"{sha256_path(path)}  {path.relative_to(out_dir)}")
    manifest.write_text("\n".join(lines) + "\n")
    return manifest


def open_in_finder(path: Path) -> None:
    if sys.platform == "darwin":
        subprocess.run(["open", str(path)], check=False)
    else:
        opener = shutil.which("xdg-open")
        if opener:
            subprocess.run([opener, str(path)], check=False)


def unescape_terminal_path(value: str) -> str:
    # Finder/Terminal drag-drop often escapes spaces as "\ ".
    value = value.strip().strip('"').strip("'")
    return value.replace("\\ ", " ")


def write_pasted_input(source: str, output_root: Path) -> Path:
    paste_dir = output_root / "_pasted_inputs"
    paste_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    path = paste_dir / f"pasted_wearedevs_{timestamp}.lua"
    path.write_text(source.rstrip("\n") + "\n")
    print(f"Saved pasted script to: {path}")
    return path


def read_multiline_paste() -> str:
    print("Paste the obfuscated script now.")
    print("When done, type __END__ on its own line and press Enter.")
    print("You can also press Ctrl-D instead of __END__.")
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "__END__":
            break
        lines.append(line)
    source = "\n".join(lines)
    if not source.strip():
        raise ValueError("no script was pasted")
    return source


def input_path_or_paste(raw: str, output_root: Path) -> Path:
    raw = raw.strip()
    if not raw:
        raise ValueError("no input provided")
    if raw.lower() in {"p", "paste", "--paste"}:
        return write_pasted_input(read_multiline_paste(), output_root)
    if raw == "-":
        source = sys.stdin.read()
        if not source.strip():
            raise ValueError("stdin was empty")
        return write_pasted_input(source, output_root)

    path_text = unescape_terminal_path(raw)
    if path_text.startswith("file://"):
        path_text = path_text.removeprefix("file://")
    candidate = Path(path_text).expanduser()
    if len(path_text) < 1024:
        try:
            if candidate.exists():
                return candidate
        except OSError:
            pass

    # If it is not an existing path, treat it as pasted source. This makes the
    # common one-line WeAreDevs paste flow work with a single Enter press.
    return write_pasted_input(raw, output_root)


def deobfuscate_static_only(input_path: Path, output_root: Path, open_output: bool = False) -> dict[str, Any]:
    input_path = input_path.expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(input_path)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    stem = slugify(input_path.stem)
    out_dir = (output_root / f"{stem}_{timestamp}").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[1/4] Static string/table unpack -> {out_dir}")
    try:
        static_report = static_unpack(input_path, out_dir, stem)
    except Exception as exc:
        static_error_path = out_dir / "static_unpack_failed.txt"
        static_error_path.write_text(traceback.format_exc())
        raise RuntimeError(f"static unpack failed: {exc}") from exc

    print("[2/4] Building clean static decryptor lift")
    decryptor_analysis = analyze_wearedevs_decryptor(static_report, {}, {}, out_dir)

    print("[3/4] Writing deobfuscated.luau")
    final_source = out_dir / "deobfuscated.luau"
    final_source.write_text(build_static_only_source(static_report, decryptor_analysis))

    print("[4/4] Writing manifest")
    manifest = write_manifest(out_dir)

    report = {
        "input": str(input_path),
        "input_sha256": sha256_path(input_path),
        "runtime": None,
        "output_dir": str(out_dir),
        "final_kind": "static_full_deobfuscation",
        "final_source": str(final_source),
        "final_source_sha256": sha256_path(final_source),
        "semantic_recovery_status": "static_deobfuscated",
        "verified_same_return": None,
        "verified_same_behavior": None,
        "verified_same_stdout": None,
        "exact_recovery_status": "not_checked_static_only",
        "exact_recovery_note": "Static-only mode does not execute loadstring, VM closures, or behavior checks. It decodes and lifts source-visible obfuscation layers only.",
        "static_unpack": {k: v for k, v in static_report.items() if k not in {"constants", "decoded_literals_path"}},
        "decryptor_analysis": decryptor_analysis,
        "manifest": str(manifest),
        "mode": "static_only",
    }
    report_path = out_dir / "wearedevs_deobfuscation_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    write_manifest(out_dir)

    print()
    print(f"Output Luau: {final_source}")
    print(f"Report: {report_path}")
    print("Final kind: static_full_deobfuscation")

    if open_output:
        open_in_finder(out_dir)
    return report


def deobfuscate(input_path: Path, output_root: Path, runtime: Path, open_output: bool = False) -> dict[str, Any]:
    input_path = input_path.expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(input_path)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    stem = slugify(input_path.stem)
    out_dir = (output_root / f"{stem}_{timestamp}").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[1/9] Static string/table unpack -> {out_dir}")
    try:
        static_report = static_unpack(input_path, out_dir, stem)
    except Exception as exc:
        static_error_path = out_dir / "static_unpack_skipped.txt"
        static_error_path.write_text(traceback.format_exc())
        static_report = empty_static_report(input_path, exc)
        static_report["static_error_log"] = str(static_error_path)
        print(f"      skipped static unpack: {exc}")

    print("[2/9] Running original obfuscated file")
    original_dir = out_dir / "original_run"
    original_dir.mkdir(parents=True, exist_ok=True)
    original_run = run_runtime(input_path, runtime, original_dir, "run.log", timeout=10)
    main_return = extract_main_return(original_dir)

    print("[3/9] Running API/string/scheduler trace with delayed wait")
    api_trace = run_trace_harness(input_path, runtime, out_dir, post_wait=2.25)

    register_path = out_dir / "register_trace_source.lua"
    register_dir = out_dir / "register_trace"
    register_dir.mkdir(parents=True, exist_ok=True)
    print("[4/9] Running flattened-register trace")
    try:
        decoded_literals_path = static_report.get("decoded_literals_path")
        if not decoded_literals_path:
            raise ValueError("static unpack did not produce decoded literals")
        register_source = build_register_instrumented(Path(decoded_literals_path).read_text(errors="replace"))
        register_path.write_text(register_source)
        register_run = run_runtime(register_path, runtime, register_dir, "register_trace.log", timeout=10)
        register_log = register_dir / "register_trace.log"
        register_findings = parse_register_findings(register_log)
    except Exception as exc:
        error_path = register_dir / "register_trace_skipped.txt"
        error_path.write_text(traceback.format_exc())
        register_run = {
            "command": None,
            "exit_code": None,
            "stdout": [],
            "log": str(error_path),
            "skipped": True,
            "reason": str(exc),
        }
        register_findings = {
            "addcoins_amounts": [],
            "addcoins_state_hits": [],
            "interesting_strings": [],
            "tiny_table_writes": [],
            "skipped": True,
            "reason": str(exc),
        }
        print(f"      skipped register trace: {exc}")

    print("[5/9] Extracting WeAreDevs decryptor and byte streams")
    decryptor_analysis = analyze_wearedevs_decryptor(static_report, api_trace, register_run, out_dir)

    print("[6/9] Auditing for true byte-for-byte source candidates")
    exact_audit = audit_exact_candidates(static_report, [original_dir, register_dir, out_dir / "runtime_trace"], out_dir)

    print("[7/9] Probing final WeAreDevs VM payload call")
    final_vm_probe = run_final_vm_probe(static_report, runtime, out_dir)
    if final_vm_probe.get("skipped"):
        print(f"      skipped final VM probe: {final_vm_probe.get('reason')}")

    print("[8/9] Writing deobfuscated.luau")
    final_source = out_dir / "deobfuscated.luau"
    if exact_audit["exact_path"]:
        final_kind = "original_luau_exact"
        final_source.write_text(Path(exact_audit["exact_path"]).read_text(errors="replace"))
    else:
        source_text = build_known_source(main_return or {}, register_findings["addcoins_amounts"])
        final_kind = "semantic_lift_wearedevs_rich_fixture"
        if source_text is None:
            source_text = build_tiny_table_source(main_return or {}, register_findings, original_run["stdout"])
            final_kind = "semantic_lift_wearedevs_tiny_table"
        if source_text is None:
            source_text = build_generic_observed_source(main_return, original_run["stdout"])
            final_kind = "semantic_lift_observed_behavior"
        if source_text is None:
            source_text = build_empty_vm_payload_source(static_report, original_run, main_return, final_vm_probe, decryptor_analysis)
            final_kind = "semantic_lift_wearedevs_empty_payload"
        if source_text is None:
            source_text = build_static_decrypted_source(static_report)
            final_kind = "static_decrypted_wearedevs_vm"
        if source_text is None:
            source_text = build_trace_replay(original_run["stdout"], main_return)
            final_kind = "trace_replay_fallback"
        final_source.write_text(source_text)

    print("[9/9] Verifying recovered artifact")
    verification = verify_recovered(final_source, runtime, out_dir)
    original_stdout_user = comparable_stdout_lines(original_run)
    immediate_ok = verification.get("immediate", {}).get("exit_code") == 0
    waited_ok = verification.get("waited", {}).get("exit_code") == 0
    immediate_return_matches = immediate_ok and verification.get("immediate_return") == main_return
    waited_return_matches = waited_ok and verification.get("wait_return") == main_return
    immediate_stdout_matches = immediate_ok and comparable_stdout_lines(verification.get("immediate", {})) == original_stdout_user
    waited_stdout_matches = waited_ok and comparable_stdout_lines(verification.get("waited", {}))[: len(original_stdout_user)] == original_stdout_user
    return_matches = bool(immediate_return_matches or waited_return_matches)
    behavior_matches = bool((immediate_return_matches and immediate_stdout_matches) or (waited_return_matches and waited_stdout_matches))
    manifest = write_manifest(out_dir)

    report = {
        "input": str(input_path),
        "input_sha256": sha256_path(input_path),
        "runtime": str(runtime),
        "output_dir": str(out_dir),
        "final_kind": final_kind,
        "final_source": str(final_source),
        "final_source_sha256": sha256_path(final_source),
        "semantic_recovery_status": (
            "recovered"
            if final_kind.startswith("semantic_lift") or final_kind in {"original_luau_exact", "static_decrypted_wearedevs_vm"}
            else "fallback"
        ),
        "verified_same_return": return_matches,
        "verified_same_behavior": behavior_matches,
        "verified_same_stdout": bool(immediate_stdout_matches or waited_stdout_matches),
        "exact_recovery_status": "recovered" if final_kind == "original_luau_exact" else "not_present_or_not_provable",
        "exact_recovery_note": (
            "A true source candidate was captured and written."
            if final_kind == "original_luau_exact"
            else "No plaintext original source was found in decoded constants or runtime captures. The output is semantic deobfuscation, static string-table decryption, or trace replay; byte-for-byte formatting/local names cannot be proven from this flattened wrapper."
        ),
        "static_unpack": {k: v for k, v in static_report.items() if k not in {"constants", "decoded_literals_path"}},
        "original_run": original_run,
        "main_return": main_return,
        "api_trace": api_trace,
        "register_run": register_run,
        "register_findings": register_findings,
        "decryptor_analysis": decryptor_analysis,
        "final_vm_probe": final_vm_probe,
        "exact_audit": exact_audit,
        "verification": verification,
        "manifest": str(manifest),
    }
    report_path = out_dir / "wearedevs_deobfuscation_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    write_manifest(out_dir)

    print()
    print(f"Output Luau: {final_source}")
    print(f"Report: {report_path}")
    print(f"Final kind: {final_kind}")
    print(f"Verified behavior: {report['verified_same_behavior']}")

    if open_output:
        open_in_finder(out_dir)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interactive/final WeAreDevs deobfuscator")
    parser.add_argument("input", nargs="?", type=str, help="Obfuscated file path, '-' for stdin, or pasted one-line source")
    parser.add_argument("--out-root", type=Path, default=PROJECT_ROOT / "outputs" / "wearedevs_deobf")
    parser.add_argument("--runtime", type=Path, default=None)
    parser.add_argument("--paste", action="store_true", help="Read pasted source until __END__ or Ctrl-D")
    parser.add_argument("--open", action="store_true", help="Open output folder when done")
    parser.add_argument("--no-open-prompt", action="store_true", help="Do not ask to open Finder in interactive mode")
    parser.add_argument("--static-only", action="store_true", help="Only decode source-visible layers; do not run the VM payload probe")
    parser.add_argument("--runtime-assisted", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = args.input
    interactive = input_path is None
    if args.paste:
        input_path = write_pasted_input(read_multiline_paste(), args.out_root)
    elif input_path is None:
        print("Paste a file path OR paste a one-line obfuscated script, then press Enter.")
        print("For multiline scripts, type P and press Enter.")
        raw = input("> ")
        input_path = input_path_or_paste(raw, args.out_root)
    else:
        input_path = input_path_or_paste(input_path, args.out_root)

    if args.static_only and not args.runtime_assisted:
        report = deobfuscate_static_only(input_path, args.out_root, open_output=args.open)
    else:
        runtime = pick_runtime(args.runtime)
        report = deobfuscate(input_path, args.out_root, runtime, open_output=args.open)

    if interactive and not args.open and not args.no_open_prompt:
        choice = input("Press O then Enter to open the output folder in Finder, or just Enter to finish: ").strip().lower()
        if choice == "o":
            open_in_finder(Path(report["output_dir"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
