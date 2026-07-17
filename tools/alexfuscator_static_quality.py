#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path


DEFAULT_NEEDLES = [
    "Alexfuscator",
    "RunService",
    "HttpService",
    "Vector3",
    "Enum.KeyCode",
    "Instance.new",
    "GetService",
    "stage2_decoy_",
    "decoy_",
    "register_bytecode_vm",
    "hardened_loader_fallback",
    "original_luau",
]

WEAK_PATTERNS = {
    "sequential_layer_table": re.compile(r"\{\s*\{[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80},[^{}]{0,80}\s*\}", re.S),
    "loadstring_loader": re.compile(r"\b(loadstring|load)\s*\("),
    "plain_roblox_global": re.compile(r'["\'](?:game|workspace|typeof|Instance|Enum|RunService|Vector3)["\']'),
    "readable_string_pool_label": re.compile(r"stage2_decoy_|decoy_|string_pool|constant_array", re.I),
    "patchable_stage2_runtime_function": re.compile(r"local\s+[A-Za-z_]\w*\s*=\s*function\(\)\s*local\s+val,\s*salts\s*=.*?local\s+function\s+step\s*\(\s*flag,\s*idx\s*\).*?return\s+val\s+end", re.S),
    "plain_stage2_salt_vector": re.compile(r"local\s+val,\s*salts\s*=\s*[^,\n]+,\s*\{\d+(?:,\d+){6,}\}"),
}


def load_debug(path):
    if not path:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return {"_debug_error": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Static quality scan for Alexfuscator artifacts.")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--debug-map", type=Path)
    parser.add_argument("--original", type=Path, help="Optional source file; strings >= min length are searched in output.")
    parser.add_argument("--needle", action="append", default=[], help="Extra forbidden plaintext needle.")
    parser.add_argument("--min-original-string", type=int, default=8)
    args = parser.parse_args()

    text = args.artifact.read_text(encoding="utf-8", errors="replace")
    debug = load_debug(args.debug_map)
    failures = []
    warnings = []

    for needle in DEFAULT_NEEDLES + args.needle:
        if needle and needle in text:
            failures.append(f"plaintext needle present: {needle!r}")

    for name, pattern in WEAK_PATTERNS.items():
        if pattern.search(text):
            if name == "loadstring_loader" and debug.get("mode", "").startswith("register_bytecode_vm"):
                failures.append(f"weak pattern present in VM output: {name}")
            elif name != "loadstring_loader":
                failures.append(f"weak pattern present: {name}")

    if args.original and args.original.exists():
        source = args.original.read_text(encoding="utf-8", errors="replace")
        literals = set()
        for match in re.finditer(r'"((?:\\.|[^"\\])*)"', source):
            raw = match.group(1)
            if len(raw) >= args.min_original_string:
                literals.add(raw)
        for literal in sorted(literals):
            if literal in text:
                failures.append(f"original string literal present: {literal!r}")

    if debug:
        if debug.get("fallback_used"):
            failures.append("debug map reports fallback_used=true")
        if debug.get("mode") != "alexvm6" or debug.get("vm_version") != 6:
            warnings.append(f"debug map mode is {debug.get('mode')!r}, expected alexvm6")
        for key in ("stage2_key_len", "stage2_runtime_fingerprint_expected", "stage2_header_hash", "stage2_mac"):
            if key in debug:
                failures.append(f"redacted debug field leaked: {key}")
        for key in ("per_prototype_opcode_maps", "per_prototype_operand_codecs", "register_liveness_reuse"):
            if debug.get(key) is not True:
                warnings.append(f"debug flag not true: {key}")

    result = {
        "artifact": str(args.artifact),
        "bytes": len(text.encode("utf-8", errors="replace")),
        "lines": text.count("\n") + 1,
        "failures": failures,
        "warnings": warnings,
        "debug_mode": debug.get("mode"),
    }
    print(json.dumps(result, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
