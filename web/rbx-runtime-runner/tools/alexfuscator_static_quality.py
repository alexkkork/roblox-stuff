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
    "register_vm_v5",
    "register-vm-v5",
    "LUAUVM5:",
    "alex_ast_vm_vnext",
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
    "legacy_vm5_marker": re.compile(r"(?:LUAUVM5:|register[_-]?vm[_-]?v?5|register[_-]?bytecode[_-]?vm)", re.I),
}

REPORT_CONTRACT = {
    "report_version": 4,
    "mode": "alexvm6",
    "backend": "alexvm6",
    "vm_version": 6,
    "ir_version": 2,
    "fallback_used": False,
}

PASS_ORDER = (
    "frontend_lowering",
    "ir_validation",
    "cfg_construction",
    "constant_propagation",
    "branch_folding",
    "unreachable_pruning",
    "redundant_move_cleanup",
    "constant_placement",
    "register_liveness",
    "opaque_edges",
    "instruction_substitution",
    "block_layout",
    "prototype_polymorphism",
    "decoy_prototypes",
    "authenticated_container",
)

PASS_COUNT_FIELDS = {
    "frontend_lowering": "instruction_count",
    "cfg_construction": "basic_block_count",
    "constant_propagation": "constant_fold_count",
    "branch_folding": "branch_fold_count",
    "unreachable_pruning": "unreachable_instruction_count",
    "redundant_move_cleanup": "redundant_move_count",
    "opaque_edges": "opaque_branch_count",
    "instruction_substitution": "instruction_substitution_count",
    "decoy_prototypes": "decoy_prototype_count",
}

COUNT_FLAG_PAIRS = (
    ("opaque_branch_count", "opaque_branches"),
    ("instruction_substitution_count", "instruction_substitution"),
    ("decoy_prototype_count", "safe_decoy_prototypes"),
    ("lazy_encrypted_block_count", "per_block_lazy_decryption"),
    ("encrypted_constant_fragment_count", "encrypted_constant_fragments"),
)

CORE_FLAGS = (
    "register_vm",
    "typed_semantic_ir",
    "validated_control_flow",
    "declarative_instruction_set",
    "round_trip_debug_formats",
    "explicit_result_arity",
    "lexical_upvalue_cells",
    "per_prototype_opcode_maps",
    "per_prototype_operand_codecs",
)


def load_debug(path):
    if not path:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return {"_debug_error": str(exc)}


def is_count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_report(debug):
    failures = []
    warnings = []

    if "_debug_error" in debug:
        return [f"could not parse debug map: {debug['_debug_error']}"], warnings

    for key, expected in REPORT_CONTRACT.items():
        if debug.get(key) != expected:
            failures.append(f"debug map {key} is {debug.get(key)!r}, expected {expected!r}")

    flags = debug.get("feature_flags")
    if not isinstance(flags, dict):
        failures.append("debug map omitted feature_flags")
        flags = {}
    for name in CORE_FLAGS:
        if flags.get(name) is not True:
            failures.append(f"required AlexVM6 feature flag is not true: {name}")

    count_fields = set(PASS_COUNT_FIELDS.values())
    count_fields.update(name for name, _ in COUNT_FLAG_PAIRS)
    count_fields.update((
        "prototype_count",
        "virtual_register_count",
        "physical_register_count",
        "constant_count",
    ))
    for name in sorted(count_fields):
        if not is_count(debug.get(name)):
            failures.append(f"debug map count is missing or invalid: {name}={debug.get(name)!r}")

    passes = debug.get("passes")
    if not isinstance(passes, list):
        failures.append("debug map omitted ordered passes")
        passes = []
    pass_names = [entry.get("name") for entry in passes if isinstance(entry, dict)]
    if tuple(pass_names) != PASS_ORDER:
        failures.append(f"compiler pass order mismatch: {pass_names!r}")
    pass_counts = {}
    for entry in passes:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            failures.append(f"invalid pass descriptor: {entry!r}")
            continue
        changes = entry.get("changes")
        if not is_count(changes):
            failures.append(f"pass {entry['name']} has invalid change count: {changes!r}")
            continue
        pass_counts[entry["name"]] = changes

    for pass_name, field_name in PASS_COUNT_FIELDS.items():
        if pass_name in pass_counts and is_count(debug.get(field_name)) and pass_counts[pass_name] != debug[field_name]:
            failures.append(
                f"pass {pass_name} reports {pass_counts[pass_name]} changes, "
                f"but {field_name} is {debug[field_name]}"
            )
    if pass_counts.get("ir_validation") not in (None, 0):
        failures.append("ir_validation must not claim source-changing rewrites")

    if all(is_count(debug.get(name)) for name in ("virtual_register_count", "physical_register_count")):
        expected_reuse = debug["virtual_register_count"] - debug["physical_register_count"]
        if expected_reuse < 0:
            failures.append("physical register count exceeds virtual register count")
        elif pass_counts.get("register_liveness") not in (None, expected_reuse):
            failures.append(
                f"register_liveness reports {pass_counts.get('register_liveness')} changes, "
                f"expected {expected_reuse}"
            )
        if flags.get("register_liveness_reuse") is not (expected_reuse > 0):
            failures.append("register_liveness_reuse flag disagrees with register counts")

    if all(is_count(debug.get(name)) for name in ("prototype_count", "decoy_prototype_count")):
        expected_prototypes = debug["prototype_count"] + debug["decoy_prototype_count"]
        if pass_counts.get("prototype_polymorphism") not in (None, expected_prototypes):
            failures.append(
                f"prototype_polymorphism reports {pass_counts.get('prototype_polymorphism')} changes, "
                f"expected {expected_prototypes}"
            )

    expected_container_changes = 1 if debug.get("encrypted_vm_container") is True else 0
    if pass_counts.get("authenticated_container") not in (None, expected_container_changes):
        failures.append("authenticated_container pass disagrees with encrypted_vm_container")

    for count_name, flag_name in COUNT_FLAG_PAIRS:
        count = debug.get(count_name)
        if is_count(count) and flags.get(flag_name) is not (count > 0):
            failures.append(f"feature flag {flag_name} disagrees with {count_name}={count}")

    if debug.get("constant_placement_randomized") is False and pass_counts.get("constant_placement") not in (None, 0):
        failures.append("constant_placement claimed changes while randomization was disabled")
    if debug.get("physical_block_shuffle") is False and pass_counts.get("block_layout") not in (None, 0):
        failures.append("block_layout claimed changes while block shuffling was disabled")

    return failures, warnings


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
        report_failures, report_warnings = validate_report(debug)
        failures.extend(report_failures)
        warnings.extend(report_warnings)
        for key in ("stage2_key_len", "stage2_runtime_fingerprint_expected", "stage2_header_hash", "stage2_mac"):
            if key in debug:
                failures.append(f"redacted debug field leaked: {key}")

    result = {
        "artifact": str(args.artifact),
        "bytes": len(text.encode("utf-8", errors="replace")),
        "lines": text.count("\n") + 1,
        "failures": failures,
        "warnings": warnings,
        "debug_mode": debug.get("mode"),
        "debug_backend": debug.get("backend"),
        "report_version": debug.get("report_version"),
        "vm_version": debug.get("vm_version"),
        "ir_version": debug.get("ir_version"),
    }
    print(json.dumps(result, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
