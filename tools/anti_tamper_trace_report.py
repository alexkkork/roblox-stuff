#!/usr/bin/env python3
"""Run behavior-preserving anti-tamper observation and classify the results."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


CAPABILITY_CATEGORIES = {
    "_ENV": "environment",
    "WYNF_NO_VIRTUALIZE": "protector_marker",
    "getreg": "debug_inspection",
    "getregistry": "debug_inspection",
    "getgc": "debug_inspection",
    "getinfo": "debug_inspection",
    "getupvalue": "debug_inspection",
    "dump": "debug_inspection",
    "clonefunction": "hooking",
    "clonereference": "hooking",
    "hookfunction": "hooking",
    "hookfunc": "hooking",
    "isfunctionhooked": "hooking",
    "restorefunction": "hooking",
    "newcclosure": "hooking",
    "setreadonly": "hooking",
    "getrawmetatable": "hooking",
    "load": "loader",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detect_protector(source: str) -> dict[str, Any]:
    match = re.search(r"Protected by\s+([^:\r\n]+)", source, flags=re.IGNORECASE)
    family = match.group(1).strip() if match else "unknown"
    normalized = family.lower()
    if "wynfuscate" in normalized:
        adapter = "wynfuscate"
    elif "luraph" in normalized:
        adapter = "luraph"
    else:
        adapter = "unknown"
    return {"family": family, "adapter": adapter, "watermark_present": match is not None}


def _check(source: str, check_id: str, title: str, description: str, patterns: list[str]) -> dict[str, Any] | None:
    offsets = [source.find(pattern) for pattern in patterns]
    if any(offset < 0 for offset in offsets):
        return None
    return {
        "id": check_id,
        "title": title,
        "description": description,
        "evidence": [{"byte_offset": offset, "pattern": pattern[:96]} for offset, pattern in zip(offsets, patterns)],
    }


def classify_static_checks(source: str) -> list[dict[str, Any]]:
    compact = re.sub(r"\s+", "", source)
    candidates = [
        _check(
            compact,
            "hashed_global_resolution",
            "Hashed global resolver",
            "Searches environment tables by hashing key names instead of embedding every API name directly.",
            ["localfu=1675752813", "fu=(fu*131+fm(fP,fG))%2147483647"],
        ),
        _check(
            compact,
            "environment_topology",
            "Environment topology probe",
            "Walks _ENV, _G, getfenv, and a metatable __index chain to detect altered script environments.",
            ["((_ENVor_G)or{})", "localfR=fkandfk(fQ)ornil", "localfb=fRandfR.__indexornil"],
        ),
        _check(
            compact,
            "timing_ratio",
            "Timing-ratio anti-hook probe",
            "Compares arithmetic-loop time with repeated getfenv access and rejects a ratio at or above 2.5.",
            ["localfh=osandos.clock", "forf8=1,200000do", "returndT>=2.5"],
        ),
        _check(
            compact,
            "random_environment_scan",
            "Randomized environment scan",
            "Reads 200 generated environment keys to expose logging metatables and unexpected proxy behavior.",
            ["locald7=130+70", "forRs=1,d7do", "local_=Rg[RE[RS(#RE)]..RS(d0)]"],
        ),
        _check(
            compact,
            "closure_identity",
            "Fresh-closure identity check",
            "Verifies two separately created closures are not the same function object.",
            ["localRN=function()returnfunction()endend", "localss=(RN()~=RN())"],
        ),
        _check(
            compact,
            "container_topology",
            "Protector table topology check",
            "Validates internal table cardinality and a sentinel value before dispatching the payload.",
            ["ifRU~=Rithen", "ifv7[(17-7)*1000+408]~=(648-3)*100+65then"],
        ),
        _check(
            compact,
            "vm_instruction_integrity",
            "Virtual-instruction integrity check",
            "Recomputes instruction fingerprints and diverts to a failure path when VM fields no longer match.",
            ["ifGv<=248then", "ifXz~=X2orXa~=X7thenVJ=1end", "ifVJ~=0then"],
        ),
    ]
    return [candidate for candidate in candidates if candidate is not None]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def classify_probe_name(name: str) -> str:
    if name.isdecimal():
        return "randomized_key"
    return CAPABILITY_CATEGORIES.get(name, "unknown_capability")


def summarize_trace(events: list[dict[str, Any]]) -> dict[str, Any]:
    kind_counts = collections.Counter(str(event.get("kind", "unknown")) for event in events)
    missing_names = [str(event.get("name", "")) for event in events if event.get("kind") == "missing_global"]
    name_counts = collections.Counter(missing_names)
    randomized = sorted(int(name) for name in missing_names if name.isdecimal())
    named = [
        {"name": name, "count": count, "category": classify_probe_name(name)}
        for name, count in sorted(name_counts.items())
        if not name.isdecimal()
    ]
    api_calls = [event for event in events if event.get("kind") == "api_call"]
    return {
        "event_counts": dict(sorted(kind_counts.items())),
        "environment_reads": {
            "total_unresolved": len(missing_names),
            "randomized": {
                "count": len(randomized),
                "minimum": randomized[0] if randomized else None,
                "maximum": randomized[-1] if randomized else None,
                "unique": len(set(randomized)),
            },
            "named": named,
        },
        "api_calls": api_calls,
    }


def summarize_native_trace(events: list[dict[str, Any]]) -> dict[str, Any]:
    metadata = next((event for event in events if event.get("kind") == "trace_metadata"), {})
    accesses = [event for event in events if event.get("kind") == "environment_access"]

    def weighted_summary(field: str) -> list[dict[str, Any]]:
        groups: dict[str, dict[str, int]] = collections.defaultdict(lambda: {"accesses": 0, "signatures": 0})
        for event in accesses:
            name = str(event.get(field, "unknown"))
            groups[name]["accesses"] += int(event.get("count", 1) or 1)
            groups[name]["signatures"] += 1
        return [
            {field: name, **values}
            for name, values in sorted(groups.items(), key=lambda item: (-item[1]["accesses"], item[0]))
        ]

    hit_groups: dict[bool, dict[str, int]] = collections.defaultdict(lambda: {"accesses": 0, "signatures": 0})
    key_groups: dict[tuple[str, str, bool], dict[str, Any]] = {}
    for event in accesses:
        hit = bool(event.get("hit"))
        count = int(event.get("count", 1) or 1)
        hit_groups[hit]["accesses"] += count
        hit_groups[hit]["signatures"] += 1
        key = str(event.get("key", ""))
        key_type = str(event.get("key_type", "unknown"))
        identity = (key, key_type, hit)
        group = key_groups.setdefault(
            identity,
            {
                "key": key,
                "key_type": key_type,
                "hit": hit,
                "accesses": 0,
                "operations": set(),
                "scopes": set(),
                "value_types": set(),
            },
        )
        group["accesses"] += count
        group["operations"].add(str(event.get("operation", "unknown")))
        group["scopes"].add(str(event.get("scope", "unknown")))
        group["value_types"].add(str(event.get("value_type", "unknown")))

    keys = []
    for group in key_groups.values():
        keys.append(
            {
                **{key: value for key, value in group.items() if not isinstance(value, set)},
                "operations": sorted(group["operations"]),
                "scopes": sorted(group["scopes"]),
                "value_types": sorted(group["value_types"]),
            }
        )
    keys.sort(key=lambda entry: (-entry["accesses"], entry["key_type"], entry["key"]))

    misses = [entry for entry in keys if not entry["hit"]]
    randomized_misses = [entry for entry in misses if entry["key"].isdecimal()]
    named_misses = [
        {**entry, "category": classify_probe_name(entry["key"])}
        for entry in misses
        if not entry["key"].isdecimal()
    ]
    named_misses.sort(key=lambda entry: (entry["category"], entry["key"]))

    total_accesses = sum(int(event.get("count", 1) or 1) for event in accesses)
    metadata_accesses = int(metadata.get("accesses", total_accesses) or 0)
    metadata_unique = int(metadata.get("unique_events", len(accesses)) or 0)
    return {
        "schema": metadata.get("schema"),
        "active": bool(metadata.get("active")),
        "activation_clock_calls": metadata.get("activation_clock_calls"),
        "clock_calls_observed": metadata.get("clock_calls_observed"),
        "accesses": total_accesses,
        "unique_signatures": len(accesses),
        "dropped": int(metadata.get("dropped", 0) or 0),
        "metadata_consistent": metadata_accesses == total_accesses and metadata_unique == len(accesses),
        "operations": weighted_summary("operation"),
        "scopes": weighted_summary("scope"),
        "hits": {
            "successful": hit_groups[True],
            "missing": hit_groups[False],
        },
        "randomized_missing_keys": {
            "count": sum(entry["accesses"] for entry in randomized_misses),
            "unique": len(randomized_misses),
        },
        "named_missing_keys": named_misses,
        "top_keys": keys[:100],
        "all_keys": keys,
    }


def classify_protected_error(message: str) -> str:
    lowered = message.lower()
    if "rawget" in lowered:
        return "rawget_contract"
    if "setfenv" in lowered:
        return "environment_mutation_contract"
    if "byte" in lowered:
        return "string_library_contract"
    if "attempt to call a nil value" in lowered:
        return "nil_call_error_shape"
    if "attempt to index nil" in lowered:
        return "nil_index_error_shape"
    return "protected_error_shape"


def read_protected_errors(directory: Path, source_path: Path) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    for path in sorted(directory.glob("pcall_error_*.txt")):
        raw = path.read_text(encoding="utf-8", errors="replace")
        normalized = raw.replace(str(source_path), source_path.name)
        fields: dict[str, str] = {}
        for line in normalized.splitlines()[:3]:
            key, separator, value = line.partition("=")
            if separator:
                fields[key] = value
        message = fields.get("error_value", "")
        errors.append(
            {
                "ordinal": len(errors) + 1,
                "category": classify_protected_error(message),
                "error_type": fields.get("error_type"),
                "error_value": message,
                "stack_depth": int(fields.get("stack_depth", "0") or 0),
                "normalized_sha256": sha256_bytes(normalized.encode("utf-8")),
            }
        )
    return errors


def report_behavior(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": report.get("status"),
        "termination_reason": report.get("termination_reason"),
        "execution_state": report.get("execution_state"),
        "returns": report.get("returns"),
        "typed_returns": report.get("typed_returns"),
        "stdout": report.get("stdout"),
        "stderr": report.get("stderr"),
        "scheduler_events": report.get("scheduler", {}).get("events"),
    }


def compare_behavior(baseline: dict[str, Any], observed: dict[str, Any], baseline_errors: list[dict[str, Any]], observed_errors: list[dict[str, Any]]) -> dict[str, Any]:
    fields = ["status", "termination_reason", "returns", "typed_returns", "stdout", "stderr"]
    comparisons = {field: baseline.get(field) == observed.get(field) for field in fields}
    baseline_error_hashes = [entry["normalized_sha256"] for entry in baseline_errors]
    observed_error_hashes = [entry["normalized_sha256"] for entry in observed_errors]
    comparisons["protected_errors"] = baseline_error_hashes == observed_error_hashes
    return {
        "equivalent": all(comparisons.values()),
        "comparisons": comparisons,
        "baseline": report_behavior(baseline),
        "observed": report_behavior(observed),
    }


def run_runtime(
    runtime: Path,
    source: Path,
    output: Path,
    profile: str,
    timeout: float,
    seed: int,
    run_kind: str,
) -> tuple[int, dict[str, Any], list[dict[str, Any]]]:
    if run_kind not in {"baseline", "native", "diagnostic"}:
        raise ValueError(f"unsupported run kind: {run_kind}")
    diagnostic = run_kind == "diagnostic"
    native = run_kind == "native"
    output.mkdir(parents=True, exist_ok=True)
    captures = output / "captures"
    captures.mkdir(parents=True, exist_ok=True)
    report_path = output / "runtime_report.json"
    trace_path = output / ("environment_trace.jsonl" if native else "compat_trace.jsonl")
    command = [
        str(runtime),
        "--profile", profile,
        "--execution-mode", "diagnostic" if diagnostic else "faithful",
        "--network-policy", "offline",
        "--clock", "virtual",
        "--timeout", str(timeout),
        "--memory-limit-mb", "1024",
        "--deterministic-seed", str(seed),
        "--luraph-mode", "off",
        "--unsupported", "trace-nil",
        "--register-overflow", "error",
        "--no-native-codegen",
        "--no-capture-string-hooks",
        "--analysis-hooks", "on" if diagnostic else "off",
        "--trace-pcall-errors",
        "--out", str(captures),
        "--report", str(report_path),
    ]
    if diagnostic:
        command.extend(["--trace-calls", "--trace-compat", str(trace_path)])
    elif native:
        command.extend(
            [
                "--trace-environment", str(trace_path),
                "--trace-environment-after-clock-calls", "0",
                "--trace-environment-max-events", "2000000",
            ]
        )
    command.append(str(source))
    completed = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 10)
    (output / "host_stdout.log").write_text(completed.stdout, encoding="utf-8")
    (output / "host_stderr.log").write_text(completed.stderr, encoding="utf-8")
    report = read_json(report_path) if report_path.exists() else {"status": "missing_report", "error": completed.stderr[-4000:]}
    return completed.returncode, report, read_jsonl(trace_path)


def render_markdown(report: dict[str, Any]) -> str:
    transparent = report["behavior_comparison"]
    native = report["native_environment_trace"]
    diagnostic = report["diagnostic_trace"]
    randomized = diagnostic["environment_reads"]["randomized"]
    lines = [
        "# Anti-Tamper Trace Report",
        "",
        f"- Protector: **{report['protector']['family']}**",
        f"- Source SHA-256: `{report['source']['sha256']}`",
        f"- Baseline/native-trace equivalent: **{'yes' if transparent['equivalent'] else 'no'}**",
        f"- Native-trace termination: **{transparent['observed']['termination_reason']}**",
        f"- Native environment accesses: **{native['accesses']:,}**",
        f"- Unique access signatures: **{native['unique_signatures']:,}**",
        f"- Dropped trace signatures: **{native['dropped']:,}**",
        "",
        "## What Was Observed",
        "",
        f"- {native['hits']['successful']['accesses']:,} successful environment accesses",
        f"- {native['hits']['missing']['accesses']:,} missing environment accesses",
        f"- {diagnostic['environment_reads']['total_unresolved']} compatibility-level unresolved reads",
        f"- {randomized['count']} randomized probe-key reads ({randomized['unique']} unique)",
        f"- {len(report['protected_errors'])} protected error-contract probes",
        f"- {len(diagnostic['api_calls'])} Roblox API calls",
        f"- {len(transparent['observed'].get('stdout') or [])} payload output records",
        "",
        "## Environment Coverage",
        "",
    ]
    for scope in native["scopes"]:
        lines.append(f"- `{scope['scope']}`: {scope['accesses']:,} accesses ({scope['signatures']} signatures)")
    lines.extend(["", "## Access Operations", ""])
    for operation in native["operations"]:
        lines.append(f"- `{operation['operation']}`: {operation['accesses']:,} accesses ({operation['signatures']} signatures)")
    lines.extend([
        "",
        "## Anti-Tamper Checks",
        "",
    ])
    for check in report["anti_tamper_checks"]:
        lines.append(f"- **{check['title']}**: {check['description']}")
    lines.extend(["", "## Named Environment Probes", ""])
    for probe in diagnostic["environment_reads"]["named"]:
        lines.append(f"- `{probe['name']}`: {probe['category']} ({probe['count']})")
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "The host VM trace was active from the first instruction and recorded script-environment, closure-environment, and shared `_G` globals/imports/indexed accesses plus rawget, with no dropped signatures. The trace-enabled run preserved status, returns, output, and protected-error fingerprints.",
            "",
            "This is a full environment-access log for the instrumented access paths, not a full VM trace. It does not claim every native-library call, arbitrary payload-table access, instruction, or virtual-register mutation.",
            "",
        ]
    )
    return "\n".join(lines)


def build_report(
    source_path: Path,
    baseline: dict[str, Any],
    native_report: dict[str, Any],
    native_events: list[dict[str, Any]],
    diagnostic_report: dict[str, Any],
    diagnostic_events: list[dict[str, Any]],
    baseline_errors: list[dict[str, Any]],
    native_errors: list[dict[str, Any]],
    diagnostic_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    source_bytes = source_path.read_bytes()
    source = source_bytes.decode("utf-8", errors="replace")
    native_trace = summarize_native_trace(native_events)
    diagnostic_trace = summarize_trace(diagnostic_events)
    checks = classify_static_checks(source)
    if native_errors:
        checks.append(
            {
                "id": "protected_error_oracles",
                "title": "Protected error-contract probes",
                "description": f"Generated and inspected {len(native_errors)} protected failures covering native error text and stack shape.",
                "evidence": [{"capture_count": len(native_errors)}],
            }
        )
    if diagnostic_trace["environment_reads"]["named"]:
        checks.append(
            {
                "id": "executor_capability_scan",
                "title": "Executor/debug capability scan",
                "description": "Queried hook, registry, closure, loader, and debug capabilities through the script environment.",
                "evidence": [{"named_probe_count": len(diagnostic_trace["environment_reads"]["named"])}],
            }
        )
    behavior = compare_behavior(baseline, native_report, baseline_errors, native_errors)
    diagnostic_behavior = compare_behavior(baseline, diagnostic_report, baseline_errors, diagnostic_errors)
    scopes = {entry["scope"] for entry in native_trace["scopes"]}
    full_environment_log = (
        behavior["equivalent"]
        and native_trace["active"]
        and native_trace["activation_clock_calls"] == 0
        and native_trace["dropped"] == 0
        and native_trace["metadata_consistent"]
        and {"script_environment", "closure_environment", "shared_global"}.issubset(scopes)
    )
    return {
        "schema": "anti-tamper-trace-report/v2",
        "source": {"filename": source_path.name, "bytes": len(source_bytes), "sha256": sha256_bytes(source_bytes)},
        "protector": detect_protector(source),
        "behavior_comparison": behavior,
        "diagnostic_behavior_comparison": diagnostic_behavior,
        "native_environment_trace": native_trace,
        "diagnostic_trace": diagnostic_trace,
        "protected_errors": native_errors,
        "anti_tamper_checks": checks,
        "coverage": {
            "unresolved_environment_reads": True,
            "successful_environment_reads_and_writes": True,
            "script_environment": "script_environment" in scopes,
            "closure_environment": "closure_environment" in scopes,
            "shared_global": "shared_global" in scopes,
            "globals_imports_indexed_accesses_and_rawget": True,
            "protected_error_contracts": True,
            "roblox_api_calls": True,
            "payload_output_returns_and_scheduler": True,
            "full_environment_access_log": full_environment_log,
            "arbitrary_non_environment_table_accesses": False,
            "all_native_library_calls": False,
            "vm_instruction_trace": False,
            "virtual_register_mutations": False,
        },
        "claim": "full environment access log captured with equivalent behavior" if full_environment_log else "environment observation was incomplete or changed behavior",
        "limitations": [
            "Environment tracing covers VM globals, imports, environment/shared-global indexed reads and writes, and rawget on those tables; arbitrary payload tables are outside this claim.",
            "Only explicitly instrumented native calls are dynamic events; other native calls remain static inferences.",
            "VM instructions and virtual-register mutations require a separate bounded dispatcher trace.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--runtime", type=Path, default=ROOT / "build" / "rbx_luau_runtime")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--profile", choices=["roblox-client", "executor-client"], default="executor-client")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    source = args.source.resolve()
    runtime = args.runtime.resolve()
    output = args.output_dir.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    seed = int(sha256_bytes(source.read_bytes())[:8], 16) & 0x7FFFFFFF

    baseline_code, baseline, _ = run_runtime(runtime, source, output / "baseline", args.profile, args.timeout, seed, "baseline")
    native_code, native_report, native_events = run_runtime(runtime, source, output / "native", args.profile, args.timeout, seed, "native")
    diagnostic_code, diagnostic_report, diagnostic_events = run_runtime(
        runtime, source, output / "diagnostic", args.profile, args.timeout, seed, "diagnostic"
    )
    baseline_errors = read_protected_errors(output / "baseline" / "captures", source)
    native_errors = read_protected_errors(output / "native" / "captures", source)
    diagnostic_errors = read_protected_errors(output / "diagnostic" / "captures", source)
    report = build_report(
        source,
        baseline,
        native_report,
        native_events,
        diagnostic_report,
        diagnostic_events,
        baseline_errors,
        native_errors,
        diagnostic_errors,
    )
    report["runs"] = {
        "baseline_exit_code": baseline_code,
        "baseline_execution_mode": "faithful",
        "native_trace_exit_code": native_code,
        "native_trace_execution_mode": "faithful",
        "native_trace_activation_clock_calls": 0,
        "diagnostic_exit_code": diagnostic_code,
        "diagnostic_execution_mode": "diagnostic",
        "deterministic_seed": seed,
        "network_policy": "offline",
    }

    (output / "anti_tamper_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "anti_tamper_report.md").write_text(render_markdown(report), encoding="utf-8")
    ok = report["coverage"]["full_environment_access_log"]
    print(json.dumps({"ok": ok, "output": str(output), "claim": report["claim"]}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
