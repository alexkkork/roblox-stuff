#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(command: list[str], *, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != expected:
        raise RuntimeError(
            f"command returned {result.returncode}, expected {expected}: {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def invoke(
    tool: pathlib.Path,
    runtime: pathlib.Path,
    compiler: pathlib.Path,
    source: pathlib.Path,
    output: pathlib.Path,
    *extra: str,
    expected: int = 0,
) -> dict:
    run([
        "python3", str(tool), str(source), "--runtime", str(runtime), "--alexfuscator", str(compiler),
        "--output-dir", str(output), "--adapter", "generic", "--max-passes", "3",
        "--wall-timeout", "5", "--instruction-budget", "500000", "--no-progress", *extra,
    ], expected=expected)
    report = output / "deobfuscation_report.json"
    if not report.exists():
        raise RuntimeError(f"deobfuscator omitted report: {report}")
    return json.loads(report.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", type=pathlib.Path, default=ROOT / "tools" / "auto_deobfuscator.py")
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    parser.add_argument("--alexfuscator", type=pathlib.Path, default=ROOT / "build" / "alexfuscator")
    args = parser.parse_args()

    spec = importlib.util.spec_from_file_location("alex_auto_deobfuscator_under_test", args.tool)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not import deobfuscator: {args.tool}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    luaauth_fixture = (
        "la_code=123;la_script_id='sanitized'\n"
        "-- luaauth.com\n"
        "return({payload='LPH$abc'}):O()()\n"
    )
    adapter, scores = module.detect_adapter(luaauth_fixture)
    if adapter != "luraph" or not any(row.get("adapter") == "luraph" and row.get("score", 0) > 0 for row in scores):
        raise RuntimeError(f"LuaAuth LPH$ source was not routed to the native Luraph adapter: {adapter} {scores}")

    with tempfile.TemporaryDirectory(prefix="alex-auto-deobf-test-") as temporary:
        root = pathlib.Path(temporary)

        exact_dir = root / "exact"
        exact = invoke(
            args.tool, args.runtime, args.alexfuscator,
            ROOT / "tests" / "exact_source_recovery_smoke.lua", exact_dir,
        )
        exact_source = exact_dir / "source_exact.luau"
        expected_exact = 'local message = "exact source smoke"\nreturn message\n'
        if exact.get("status") != "recovered_exact" or exact.get("exact_source") is not True:
            raise RuntimeError(f"exact source fixture was not recovered honestly: {exact}")
        if exact_source.read_text(encoding="utf-8") != expected_exact:
            raise RuntimeError("exact source output did not match the source-bearing payload")
        differential = exact.get("selected_candidate", {}).get("verification", {}).get("differential", {})
        if differential.get("equivalent") is not True:
            raise RuntimeError(f"exact source failed differential verification: {differential}")

        reconstructed_dir = root / "reconstructed"
        reconstructed = invoke(
            args.tool, args.runtime, args.alexfuscator,
            ROOT / "tests" / "alexfuscator_smoke.luau", reconstructed_dir,
        )
        reconstructed_source = reconstructed_dir / "reconstructed.luau"
        if reconstructed.get("status") != "reconstructed" or reconstructed.get("exact_source") is not False:
            raise RuntimeError(f"static reconstruction was mislabeled: {reconstructed}")
        text = reconstructed_source.read_text(encoding="utf-8")
        if 'local message = "alex-fuscator-smoke"' not in text or "    local shifted = value + 7" not in text:
            raise RuntimeError("reconstruction did not fold constants while preserving indentation")
        differential = reconstructed.get("selected_candidate", {}).get("verification", {}).get("differential", {})
        if differential.get("equivalent") is not True:
            raise RuntimeError(f"reconstruction failed differential verification: {differential}")

        packed_dir = root / "packed"
        packed = invoke(
            args.tool, args.runtime, args.alexfuscator,
            ROOT / "tests" / "packed_blob_recovery_smoke.lua", packed_dir,
        )
        if packed.get("status") != "disassembled" or packed.get("source_output") is not None:
            raise RuntimeError(f"source-free packed data was promoted to source: {packed}")
        if (packed_dir / "source_exact.luau").exists() or (packed_dir / "reconstructed.luau").exists():
            raise RuntimeError("packed data emitted a false source artifact")

        exact_only_dir = root / "exact-only"
        exact_only = invoke(
            args.tool, args.runtime, args.alexfuscator,
            ROOT / "tests" / "alexfuscator_smoke.luau", exact_only_dir,
            "--mode", "exact", expected=2,
        )
        if exact_only.get("status") != "blocked" or exact_only.get("source_output") is not None:
            raise RuntimeError(f"exact-only mode silently downgraded: {exact_only}")

        disassembly_dir = root / "disassembly-only"
        disassembly = invoke(
            args.tool, args.runtime, args.alexfuscator,
            ROOT / "tests" / "exact_source_recovery_smoke.lua", disassembly_dir,
            "--mode", "disassemble",
        )
        if disassembly.get("status") != "disassembled" or disassembly.get("source_output") is not None:
            raise RuntimeError(f"disassembly mode emitted source: {disassembly}")

        graph = json.loads((exact_dir / "artifact_graph.json").read_text(encoding="utf-8"))
        node_ids = [node["id"] for node in graph.get("nodes", [])]
        if len(node_ids) != len(set(node_ids)) or not graph.get("edges"):
            raise RuntimeError("artifact graph was not content-addressed or linked")
        if any(report.get("network_policy") != "offline" for report in (exact, reconstructed, packed)):
            raise RuntimeError("automatic deobfuscation did not default to offline networking")

    print("Auto deobfuscator OK: LPH$ routing, exact gate, reconstruction, disassembly, blocked mode, artifact graph, offline runtime")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
