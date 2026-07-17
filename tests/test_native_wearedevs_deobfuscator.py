#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
import time
import unittest
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build"
DEOBFUSCATOR = BUILD_DIR / "alex_deobfuscator"
RUNTIME = BUILD_DIR / "rbx_luau_runtime"
CORPUS_DIR = ROOT / "tests" / "deobfuscation_corpus" / "wearedevs_obfuscated"
SOURCE_DIR = ROOT / "tests" / "deobfuscation_corpus" / "source"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
REFERENCE_SAMPLE = CORPUS_DIR / "001_arithmetic.luau"
SYNTHETIC_REGISTER_CAPTURE = ROOT / "tests" / "fixtures" / "wearedevs_empty_register_capture.luau"
SYNTHETIC_PARTIAL_REGISTER_TABLE = (
    ROOT / "tests" / "fixtures" / "wearedevs_partial_register_scalarization.luau"
)
SYNTHETIC_ADJACENT_TEMPORARIES = ROOT / "tests" / "fixtures" / "wearedevs_adjacent_temporary_inlining.luau"
SYNTHETIC_ADJACENT_CAPTURED_RELOAD = (
    ROOT / "tests" / "fixtures" / "wearedevs_adjacent_captured_reload.luau"
)
READABLE_REWRITER_HARNESS = ROOT / "tests" / "helpers" / "flow_harness.cpp"
BALENCI_LIKE_ANALYSIS_BUDGET_SECONDS = 25.0
FOCUSED_STRUCTURED_FAMILY_SAMPLES = (
    ("array_reduce", "003_array_reduce.luau"),
    ("coroutine", "015_coroutine.luau"),
    ("iterator", "016_iterator.luau"),
)
TRACE_MARKER = re.compile(r"^\[ALEX_WD_STATE:[0-9a-f]{16}\]\s+-?\d+", re.MULTILINE)
RESIDUAL_VM_OR_PROTECTOR = re.compile(
    r"https://wearedevs\.net/obfuscator"
    r"|getfenv\s+and\s+getfenv"
    r"|Tamper Detected!"
    r"|\[ALEX_WD_STATE:"
    r"|\b__(?:state|states|dispatch|dispatcher|pc|program_counter|instructions)\b"
    r"|\bstate_[0-9]+\b"
    r"|return\s*\(\s*function\s*\(\.\.\.\)\s*local\s+[A-Za-z_]",
    re.IGNORECASE,
)

ACCEPTED_STATUSES = {"cached", "fetched"}
MAX_INPUT_BYTES = 1536 * 1024
JSON_ARTIFACTS = (
    "deobfuscation_report.json",
    "semantic_ir.json",
    "cfg.json",
    "constants.json",
    "artifact_graph.json",
    "reconstruction_map.json",
)
REPORT_ARTIFACTS = {
    "semantic_ir": "semantic_ir.json",
    "cfg": "cfg.json",
    "constants": "constants.json",
    "graph": "artifact_graph.json",
    "reconstruction_map": "reconstruction_map.json",
}
DETERMINISTIC_RECONSTRUCTION_ARTIFACTS = (
    "cfg.json",
    "constants.json",
    "reconstruction_map.json",
)
NON_SOURCE_LUA_ARTIFACTS = {
    "decoded_wrapper.luau",
    "trace_probe.luau",
    "reconstructed_candidate.luau",
    "semantic_state_machine_candidate.luau",
}


def reconstruction_structure_counts(source: str) -> dict[str, int]:
    return {
        "empty_table_allocations": len(
            re.findall(r"(?m)^\s*(?:local\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{\s*\}\s*$", source)
        ),
        "constant_index_accesses": len(
            re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\[\s*[0-9]+\s*\]", source)
        ),
        "closure_literals": len(re.findall(r"\bfunction(?:\s+[A-Za-z_][A-Za-z0-9_]*)?\s*\(", source)),
        "state_dispatchers": len(re.findall(r"while\s+__state\s*~=\s*nil\s+do", source)),
    }


def balenci_like_reconstruction_source() -> str:
    """Build a stable 10k-line lifted payload shaped like the Balenci regression."""
    lines = ["-- Synthetic large Prometheus reconstruction used only for native analysis timing."]
    function_count = 80
    operations_per_function = 72
    for function_index in range(1, function_count + 1):
        lines.extend(
            [
                f"local function function_{function_index}(argument_1)",
                "    local temporary, local_1",
                "    local_1 = argument_1",
            ]
        )
        for operation in range(1, operations_per_function + 1):
            literal = function_index * 1000 + operation
            lines.append(f"    temporary = math.abs(argument_1 + {literal})")
            lines.append("    local_1 += temporary")
        lines.extend(["    return local_1", "end"])
    lines.append(f"return function_1(1), function_{function_count}({function_count})")
    return "\n".join(lines) + "\n"


def run_command(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def invoke(
    source: pathlib.Path,
    output_dir: pathlib.Path,
    *,
    mode: str = "auto",
    trace: pathlib.Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    command = [
        str(DEOBFUSCATOR),
        str(source),
        "--output-dir",
        str(output_dir),
        "--mode",
        mode,
        "--report",
        "-",
    ]
    if trace is not None:
        command.extend(["--trace", str(trace)])
    result = run_command(
        command,
        timeout=15,
    )
    report_path = output_dir / "deobfuscation_report.json"
    if not report_path.is_file():
        raise AssertionError(
            f"native deobfuscator omitted {report_path}\n"
            f"exit: {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    try:
        stdout_report = json.loads(result.stdout)
        disk_report = json.loads(report_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError(
            f"native deobfuscator emitted an invalid report: {error}\n"
            f"exit: {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        ) from error
    if stdout_report != disk_report:
        raise AssertionError("--report - did not match deobfuscation_report.json")
    return result, disk_report


def normalize_runtime_value(value: Any, chunk_paths: tuple[pathlib.Path, ...]) -> Any:
    if isinstance(value, list):
        return [normalize_runtime_value(item, chunk_paths) for item in value]
    if isinstance(value, dict):
        return {key: normalize_runtime_value(item, chunk_paths) for key, item in value.items()}
    if not isinstance(value, str):
        return value
    normalized = value
    for chunk_path in chunk_paths:
        normalized = normalized.replace(str(chunk_path), "<chunk>")
    normalized = re.sub(r"<chunk>:\d+", "<chunk>:<line>", normalized)
    return re.sub(r"loadstring:\d+", "loadstring:<line>", normalized)


def runtime_projection(report: dict[str, Any], chunk_paths: tuple[pathlib.Path, ...]) -> dict[str, Any]:
    scheduler = report.get("scheduler") or {}
    projection = {
        "status": report.get("status"),
        "termination_reason": report.get("termination_reason"),
        "returns": report.get("returns", []),
        "stdout": report.get("stdout", []),
        "stderr": report.get("stderr", []),
        "error": report.get("error"),
        "engine": report.get("engine"),
        "network_requirements": report.get("network_requirements", []),
        "scheduler": {
            "budget_reached": scheduler.get("budget_reached", False),
            "errors": scheduler.get("errors", []),
            "events": [
                {key: event.get(key) for key in ("kind", "frame", "time")}
                for event in scheduler.get("events", [])
            ],
            "frames": scheduler.get("frames", 0),
            "pending": scheduler.get("pending"),
            "stop_reason": scheduler.get("stop_reason"),
            "timed_out": scheduler.get("timed_out", False),
            "virtual_time": scheduler.get("virtual_time", 0),
        },
    }
    return normalize_runtime_value(projection, chunk_paths)


class NativeWeAreDevsDeobfuscatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        build = run_command(
            [
                "cmake",
                "--build",
                str(BUILD_DIR),
                "--target",
                "alex_deobfuscator",
                "rbx_luau_runtime",
                "--parallel",
                "2",
            ],
            timeout=180,
        )
        if build.returncode != 0:
            raise RuntimeError(
                f"failed to build alex_deobfuscator ({build.returncode})\n"
                f"stdout:\n{build.stdout}\nstderr:\n{build.stderr}"
            )
        if not DEOBFUSCATOR.is_file():
            raise RuntimeError(f"build did not produce {DEOBFUSCATOR}")
        if not RUNTIME.is_file():
            raise RuntimeError(f"build did not produce {RUNTIME}")

    @classmethod
    def readable_rewriter_harness(cls) -> pathlib.Path:
        existing = getattr(cls, "_readable_rewriter_harness", None)
        if existing is not None:
            return existing

        temporary = tempfile.TemporaryDirectory(prefix="alex-readable-rewriter-harness-")
        cls.addClassCleanup(temporary.cleanup)
        harness = pathlib.Path(temporary.name) / "readable_rewriter_harness"
        nlohmann_include = BUILD_DIR / "_deps" / "nlohmann_json-src" / "include"
        build = run_command(
            [
                "c++",
                "-std=c++20",
                "-O2",
                "-DNDEBUG",
                f"-I{ROOT / 'src' / 'deobfuscator'}",
                f"-I{nlohmann_include}",
                str(READABLE_REWRITER_HARNESS),
                str(ROOT / "src" / "deobfuscator" / "passes" / "flow.cpp"),
                str(ROOT / "src" / "deobfuscator" / "passes" / "names.cpp"),
                f"-I{ROOT / 'vendor' / 'luau' / 'Ast' / 'include'}",
                f"-I{ROOT / 'vendor' / 'luau' / 'Common' / 'include'}",
                str(BUILD_DIR / "vendor" / "luau" / "libLuau.Ast.a"),
                str(BUILD_DIR / "vendor" / "luau" / "libLuau.Common.a"),
                "-o",
                str(harness),
            ],
            timeout=180,
        )
        if build.returncode != 0:
            raise RuntimeError(
                "failed to build readable rewriter harness\n"
                f"stdout:\n{build.stdout}\nstderr:\n{build.stderr}"
            )
        cls._readable_rewriter_harness = harness
        return harness

    @classmethod
    def state_field_refiner_harness(cls) -> pathlib.Path:
        existing = getattr(cls, "_state_field_refiner_harness", None)
        if existing is not None:
            return existing

        temporary = tempfile.TemporaryDirectory(prefix="alex-state-field-refiner-harness-")
        cls.addClassCleanup(temporary.cleanup)
        harness_source = pathlib.Path(temporary.name) / "state_field_refiner_harness.cpp"
        harness_source.write_text(
            r'''#include "passes/fields.hpp"
#include "register_overflow.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include <nlohmann/json.hpp>

int main(int argc, char** argv)
{
    if (argc != 2 && argc != 3)
        return 2;
    std::ifstream input(argv[1], std::ios::binary);
    if (!input)
        return 3;
    const std::string source((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    rbx::runtime::RegisterOverflowRewrite spill;
    if (argc == 3 && std::string(argv[2]) == "--spill")
        spill = rbx::runtime::spillRegisterOverflow(source, 0);
    else
        spill.source = source;
    const alex::deobfuscator::state_fields::RefinementResult result =
        alex::deobfuscator::state_fields::refineGeneratedCallbackFields(spill.source);
    std::cout << nlohmann::json{
        {"source", result.source},
        {"spill_applied", spill.applied},
        {"bindings_spilled", spill.bindingsSpilled},
        {"parse_succeeded", result.parse_succeeded},
        {"compile_attempted", result.compile_attempted},
        {"candidate_compiled", result.candidate_compiled},
        {"committed", result.committed},
        {"generated_callback_fields_found", result.generated_callback_fields_found},
        {"fields_proposed", result.fields_proposed},
        {"fields_renamed", result.fields_renamed},
        {"references_proposed", result.references_proposed},
        {"references_renamed", result.references_renamed},
        {"ambiguous_fields", result.ambiguous_fields},
        {"unproven_fields", result.unproven_fields},
        {"unsafe_state_tables", result.unsafe_state_tables},
        {"unsafe_fields", result.unsafe_fields},
        {"name_collisions_detected", result.name_collisions_detected},
        {"name_collisions_avoided", result.name_collisions_avoided},
        {"diagnostics", result.diagnostics},
    }.dump();
}
''',
            encoding="utf-8",
        )
        harness = pathlib.Path(temporary.name) / "state_field_refiner_harness"
        nlohmann_include = BUILD_DIR / "_deps" / "nlohmann_json-src" / "include"
        build = run_command(
            [
                "c++",
                "-std=c++20",
                "-O2",
                "-DNDEBUG",
                f"-I{ROOT / 'src' / 'deobfuscator'}",
                f"-I{ROOT / 'src' / 'runtime'}",
                f"-I{nlohmann_include}",
                f"-I{ROOT / 'vendor' / 'luau' / 'Ast' / 'include'}",
                f"-I{ROOT / 'vendor' / 'luau' / 'Common' / 'include'}",
                f"-I{ROOT / 'vendor' / 'luau' / 'Compiler' / 'include'}",
                str(harness_source),
                str(ROOT / "src" / "deobfuscator" / "passes" / "fields.cpp"),
                str(ROOT / "src" / "runtime" / "register_overflow.cpp"),
                str(BUILD_DIR / "vendor" / "luau" / "libLuau.Compiler.a"),
                str(BUILD_DIR / "vendor" / "luau" / "libLuau.Bytecode.a"),
                str(BUILD_DIR / "vendor" / "luau" / "libLuau.Ast.a"),
                str(BUILD_DIR / "vendor" / "luau" / "libLuau.Common.a"),
                "-o",
                str(harness),
            ],
            timeout=180,
        )
        if build.returncode != 0:
            raise RuntimeError(
                "failed to build state field refiner harness\n"
                f"stdout:\n{build.stdout}\nstderr:\n{build.stderr}"
            )
        cls._state_field_refiner_harness = harness
        return harness

    def refine_state_fields(self, source: pathlib.Path, *, spill: bool = False) -> dict[str, Any]:
        command = [str(self.state_field_refiner_harness()), str(source)]
        if spill:
            command.append("--spill")
        result = run_command(command, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            self.fail(f"state field refiner harness emitted invalid JSON for {source}: {error}")

    def rewrite_fixture(
        self,
        source: pathlib.Path,
        *,
        timeout: float = 15,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any], float]:
        harness = self.readable_rewriter_harness()
        started = time.monotonic()
        result = run_command([str(harness), str(source)], timeout=timeout)
        elapsed = time.monotonic() - started
        self.assertEqual(
            result.returncode,
            0,
            f"readable rewriter harness failed for {source}\n{result.stdout}{result.stderr}",
        )
        try:
            artifact = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            self.fail(f"readable rewriter harness emitted invalid JSON for {source}: {error}")
        return result, artifact, elapsed

    def assert_runtime_equivalent_rewrite(
        self,
        source: pathlib.Path,
        rewritten_source: str,
        root: pathlib.Path,
        label: str,
        expected_returns: list[Any],
    ) -> None:
        rewritten = root / f"{label}-rewritten.luau"
        rewritten.write_text(rewritten_source, encoding="utf-8")
        source_result, source_report = self.execute_runtime(source, root, f"{label}-source")
        rewritten_result, rewritten_report = self.execute_runtime(rewritten, root, f"{label}-rewritten")

        self.assertEqual(source_result.returncode, 0, source_result.stderr)
        self.assertEqual(rewritten_result.returncode, 0, rewritten_result.stderr)
        self.assertEqual(source_report.get("returns"), expected_returns)
        chunk_paths = (source, rewritten)
        self.assertEqual(
            runtime_projection(rewritten_report, chunk_paths),
            runtime_projection(source_report, chunk_paths),
        )

    def assert_capture_factory_lowered(self, rewritten_source: str) -> None:
        self.assertNotRegex(
            rewritten_source,
            r"(?s)\(\s*function\s*\([^)]*\)\s*\n\s*return\s+function\s*\(",
        )
        self.assertNotRegex(rewritten_source, r"(?m)^\s*end\)\s*\(")

    def local_function_parts(
        self,
        source: str,
        name: str,
        following_declaration: str,
    ) -> tuple[list[str], str]:
        match = re.search(
            rf"(?ms)^local function {re.escape(name)}\((?P<parameters>[^)]*)\)[ \t]*$\n"
            rf"(?P<body>.*?)^end[ \t]*$\n(?:[ \t]*\n)*(?={following_declaration})",
            source,
        )
        if match is None:
            self.fail(f"missing rewritten local function {name}")
        parameters = [item.strip() for item in match.group("parameters").split(",") if item.strip()]
        return parameters, match.group("body")

    def assert_returncode(
        self,
        result: subprocess.CompletedProcess[str],
        expected: int,
    ) -> None:
        self.assertEqual(
            result.returncode,
            expected,
            f"unexpected native deobfuscator exit\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

    def assert_common_report(self, report: dict[str, Any]) -> None:
        self.assertEqual(report.get("report_version"), 2)
        self.assertEqual(report.get("tool"), "alex-native-deobfuscator")
        self.assertEqual(report.get("backend"), "native-cpp")
        self.assertEqual(report.get("network_policy"), "offline")
        self.assertIs(report.get("fallback_used"), False)
        self.assertIsInstance(report.get("diagnostics"), list)
        self.assertIsInstance(report.get("passes"), list)

    def trace_candidate(
        self,
        source: pathlib.Path,
        output_dir: pathlib.Path,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any], pathlib.Path]:
        result, report = invoke(source, output_dir, mode="reconstruct")
        for probe_pass in range(1, 3):
            probe = output_dir / "trace_probe.luau"
            self.assertTrue(probe.is_file(), f"missing trace probe after pass {probe_pass}: {source.name}")
            trace_result = run_command(
                [
                    str(RUNTIME),
                    "--profile",
                    "executor-client",
                    "--network-policy",
                    "offline",
                    "--clock",
                    "virtual",
                    "--timeout",
                    "5",
                    "--capture-min",
                    "1",
                    "--no-normalize-pcall-errors",
                    "--no-capture-string-hooks",
                    "--out",
                    str(output_dir / f"trace-captures-{probe_pass}"),
                    str(probe),
                ],
                timeout=12,
            )
            self.assertEqual(
                trace_result.returncode,
                0,
                f"trace probe failed for {source.name}\nstdout:\n{trace_result.stdout}\nstderr:\n{trace_result.stderr}",
            )
            self.assertRegex(trace_result.stdout, TRACE_MARKER)
            trace_path = output_dir / f"state-trace-{probe_pass}.txt"
            trace_path.write_text(trace_result.stdout, encoding="utf-8")
            result, report = invoke(source, output_dir, mode="reconstruct", trace=trace_path)

        candidate = output_dir / "reconstructed_candidate.luau"
        self.assertTrue(candidate.is_file(), f"native lifter withheld a candidate for {source.name}: {report.get('diagnostics')}")
        return result, report, candidate

    def execute_runtime(
        self,
        source: pathlib.Path,
        output_dir: pathlib.Path,
        label: str,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        report_path = output_dir / f"verify-{label}.json"
        result = run_command(
            [
                str(RUNTIME),
                "--profile",
                "executor-client",
                "--network-policy",
                "offline",
                "--clock",
                "virtual",
                "--timeout",
                "5",
                "--capture-min",
                "1",
                "--analysis-hooks",
                "off",
                "--no-normalize-pcall-errors",
                "--no-capture-string-hooks",
                "--report",
                str(report_path),
                "--out",
                str(output_dir / f"verify-{label}-captures"),
                str(source),
            ],
            timeout=12,
        )
        self.assertTrue(report_path.is_file(), f"runtime omitted report for {source}")
        return result, json.loads(report_path.read_text(encoding="utf-8"))

    def load_json_artifacts(
        self,
        output_dir: pathlib.Path,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, bytes]]:
        documents: dict[str, dict[str, Any]] = {}
        raw: dict[str, bytes] = {}
        for filename in JSON_ARTIFACTS:
            path = output_dir / filename
            self.assertTrue(path.is_file(), f"missing JSON artifact: {path}")
            payload = path.read_bytes()
            try:
                document = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                self.fail(f"invalid JSON artifact {path}: {error}")
            self.assertIsInstance(document, dict, f"JSON artifact is not an object: {path}")
            documents[filename] = document
            raw[filename] = payload

        self.assertEqual(documents["deobfuscation_report.json"].get("report_version"), 2)
        for filename in JSON_ARTIFACTS[1:]:
            self.assertEqual(documents[filename].get("version"), 2, filename)
        return documents, raw

    def assert_no_recovered_source(
        self,
        output_dir: pathlib.Path,
        report: dict[str, Any],
        documents: dict[str, dict[str, Any]],
    ) -> None:
        self.assertIs(report.get("exact_source"), False)
        self.assertIsNone(report.get("source_output"))
        self.assertIsNone((report.get("artifacts") or {}).get("source"))
        self.assertIsNone(documents["reconstruction_map.json"].get("output"))

        emitted_source = sorted(
            path.name
            for path in output_dir.iterdir()
            if path.is_file()
            and path.suffix in {".lua", ".luau"}
            and path.name not in NON_SOURCE_LUA_ARTIFACTS
        )
        self.assertEqual(emitted_source, [], f"unexpected recovered source artifacts: {emitted_source}")

        graph = documents["artifact_graph.json"]
        promoted = [
            node
            for node in graph.get("nodes", [])
            if node.get("source_bearing") is True and node.get("provenance") != "input"
        ]
        self.assertEqual(promoted, [], f"non-input graph nodes were promoted to source: {promoted}")

    def assert_diagnostic(
        self,
        report: dict[str, Any],
        *,
        code: str,
        stage: str,
        message: str | None = None,
    ) -> dict[str, Any]:
        matches = [
            diagnostic
            for diagnostic in report.get("diagnostics", [])
            if diagnostic.get("code") == code and diagnostic.get("stage") == stage
        ]
        self.assertTrue(matches, f"missing {stage}/{code} diagnostic: {report.get('diagnostics')}")
        diagnostic = matches[0]
        if message is not None:
            self.assertIn(message, diagnostic.get("message", ""))
        return diagnostic

    def assert_control_flow_semantics(
        self,
        report: dict[str, Any],
        documents: dict[str, dict[str, Any]],
    ) -> None:
        coverage = report.get("coverage") or {}
        dynamic_transitions = coverage.get("dynamic_transitions")
        return_sentinels = coverage.get("return_sentinels")
        unresolved_control_edges = coverage.get("unresolved_control_edges")
        self.assertIsInstance(dynamic_transitions, int)
        self.assertGreater(dynamic_transitions, 0)
        self.assertEqual(dynamic_transitions, return_sentinels)
        self.assertEqual(unresolved_control_edges, 0)

        cfg = documents["cfg.json"]
        root_entry_states = cfg.get("root_entry_states")
        entry_states = cfg.get("entry_states")
        self.assertIsInstance(root_entry_states, list)
        self.assertEqual(len(root_entry_states), 1)
        self.assertIsInstance(entry_states, list)
        self.assertIn(root_entry_states[0], entry_states)

        nodes = cfg.get("nodes") or []
        reachable_nodes = {node.get("id"): node for node in nodes if node.get("reachable") is True}
        root_node = reachable_nodes.get(str(root_entry_states[0]))
        self.assertIsNotNone(root_node, "root entry state is not a reachable CFG node")

        reachable_dynamic_nodes = {
            node_id: node
            for node_id, node in reachable_nodes.items()
            if node.get("dynamic_transitions", 0) > 0
        }
        self.assertTrue(reachable_dynamic_nodes)
        self.assertEqual(
            sum(node["dynamic_transitions"] for node in reachable_dynamic_nodes.values()),
            dynamic_transitions,
        )
        for node in reachable_dynamic_nodes.values():
            self.assertIs(node.get("return_sentinel"), True)

        dynamic_edge_kinds = {"return_sentinel", "dynamic_state_assignment"}
        reachable_dynamic_edges = [
            edge
            for edge in cfg.get("edges", [])
            if edge.get("from") in reachable_dynamic_nodes and edge.get("kind") in dynamic_edge_kinds
        ]
        self.assertEqual(len(reachable_dynamic_edges), len(reachable_dynamic_nodes))
        self.assertEqual(
            {edge.get("from") for edge in reachable_dynamic_edges},
            set(reachable_dynamic_nodes),
        )
        for edge in reachable_dynamic_edges:
            self.assertEqual(edge.get("kind"), "return_sentinel")
            self.assertIs(edge.get("resolved"), True)
            self.assertIsNone(edge.get("to"))

        basic_blocks = {
            block.get("id"): block
            for block in documents["semantic_ir.json"].get("basic_blocks", [])
        }
        for node_id in reachable_dynamic_nodes:
            self.assertIn(node_id, basic_blocks)
            terminator = basic_blocks[node_id].get("terminator") or {}
            targets = terminator.get("targets")
            self.assertIsInstance(targets, list)
            self.assertEqual(terminator.get("kind"), "branch_return" if targets else "return")
            self.assertNotEqual(terminator.get("kind"), "jump")
            self.assertIs(terminator.get("protector_return_sentinel"), True)
            self.assertEqual(terminator.get("unresolved_targets"), 0)

        source_searches = [item for item in report.get("passes", []) if item.get("stage") == "source_search"]
        self.assertEqual(len(source_searches), 1)
        source_search = source_searches[0]
        self.assertIs(source_search.get("ok"), True)
        self.assertIsInstance(source_search.get("compilable_candidates"), int)
        self.assertGreaterEqual(source_search["compilable_candidates"], 0)
        self.assertEqual(source_search.get("vm_structure_matches"), 0)
        self.assertIs(source_search.get("promoted"), False)
        self.assertIs(report.get("verification", {}).get("compiled"), False)

    def assert_clean_compilable_reconstruction(
        self,
        candidate_text: str,
        report: dict[str, Any],
        sample: str,
    ) -> None:
        candidate_report = report.get("reconstruction_candidate") or {}
        readability = candidate_report.get("readability") or {}
        passes = {item.get("stage"): item for item in report.get("passes", [])}
        diagnostics = json.dumps(
            {
                "representation": candidate_report.get("representation"),
                "compiled": candidate_report.get("compiled"),
                "readability": readability,
                "residual_reasons": readability.get("residual_reasons", {}),
                "lift": passes.get("lift", {}),
            },
            indent=2,
            sort_keys=True,
        )
        failure_context = f"{sample}: reconstruction quality regression\n{diagnostics}"

        self.assertIs(candidate_report.get("available"), True, failure_context)
        self.assertIs(candidate_report.get("compiled"), True, failure_context)
        self.assertEqual(
            candidate_report.get("representation"),
            "structured_control_flow",
            failure_context,
        )
        self.assertIs(readability.get("applied"), True, failure_context)
        self.assertEqual(readability.get("residual_state_machines"), 0, failure_context)
        self.assertEqual(
            readability.get("regions_structured"),
            readability.get("regions_found"),
            failure_context,
        )
        self.assertIs(
            passes.get("lift", {}).get("candidate_compiled"),
            True,
            failure_context,
        )
        self.assertNotRegex(
            candidate_text,
            RESIDUAL_VM_OR_PROTECTOR,
            f"{sample}: reconstructed source retained VM state or protector wrapper machinery\n{diagnostics}",
        )

    def test_all_90_accepted_samples_reconstruct_and_match_runtime(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        accepted = [entry for entry in manifest["files"] if entry.get("status") in ACCEPTED_STATUSES]
        rejected = [entry for entry in manifest["files"] if entry.get("status") == "rejected"]
        self.assertEqual(len(accepted), 90)
        self.assertEqual(len(rejected), 10)

        expected_files = {entry["filename"] for entry in accepted}
        actual_files = {path.name for path in CORPUS_DIR.glob("*.luau")}
        self.assertEqual(actual_files, expected_files)

        with tempfile.TemporaryDirectory(prefix="alex-native-corpus-") as temporary:
            root = pathlib.Path(temporary)
            for entry in accepted:
                filename = entry["filename"]
                with self.subTest(sample=filename):
                    obfuscated = CORPUS_DIR / filename
                    source = SOURCE_DIR / filename
                    self.assertTrue(source.is_file(), f"missing unobfuscated oracle: {source}")
                    payload = obfuscated.read_bytes()
                    source_payload = source.read_bytes()
                    self.assertEqual(len(payload), entry["output_bytes"])
                    self.assertEqual(hashlib.sha256(payload).hexdigest(), entry["output_sha256"])
                    self.assertEqual(hashlib.sha256(source_payload).hexdigest(), entry["source_sha256"])

                    output_dir = root / obfuscated.stem
                    result, report, candidate = self.trace_candidate(obfuscated, output_dir)
                    self.assert_returncode(result, 2)
                    self.assert_common_report(report)
                    self.assertEqual(report.get("adapter"), "wearedevs-v1")
                    self.assertEqual(report.get("mode"), "reconstruct")
                    self.assertEqual(report.get("status"), "blocked")
                    self.assertEqual(report.get("input", {}).get("sha256"), entry["output_sha256"])
                    self.assertGreaterEqual(report.get("detection", {}).get("confidence", 0), 0.75)

                    passes = {item.get("stage"): item for item in report["passes"]}
                    for stage in ("parse", "detect", "decode", "trace", "cfg"):
                        self.assertIs(passes.get(stage, {}).get("ok"), True, f"{filename}: {stage}")
                    self.assertIs(passes.get("prometheus_inverse", {}).get("ok"), True)
                    self.assertRegex(
                        passes["prometheus_inverse"].get("reason", ""),
                        r"^complete_(?:straight_line|semantic_state_machine)_payload$",
                    )
                    self.assertIs(passes.get("lift", {}).get("candidate_compiled"), True)
                    self.assertEqual(passes.get("lift", {}).get("unresolved"), 0)

                    candidate_report = report.get("reconstruction_candidate") or {}
                    self.assertIs(candidate_report.get("available"), True)
                    self.assertIs(candidate_report.get("compiled"), True)
                    self.assertIs(candidate_report.get("source_claim_eligible"), True)
                    self.assertEqual(candidate_report.get("kind"), "structured_luau")
                    self.assertGreater(candidate_report.get("lifted_instructions", 0), 0)
                    self.assertGreater(candidate_report.get("statements", 0), 0)
                    self.assertIn(candidate_report.get("representation"), {"structured_control_flow", "straight_line_lift", "semantic_state_machine"})
                    readability = candidate_report.get("readability") or {}
                    self.assertIsInstance(readability.get("applied"), bool)
                    self.assertGreaterEqual(readability.get("regions_structured", 0), 0)
                    self.assertGreaterEqual(readability.get("dead_assignments_removed", 0), 0)

                    candidate_text = candidate.read_text(encoding="utf-8")
                    self.assertNotEqual(candidate_text.strip(), obfuscated.read_text(encoding="utf-8").strip())
                    self.assert_clean_compilable_reconstruction(
                        candidate_text,
                        report,
                        filename,
                    )

                    artifacts = report.get("artifacts") or {}
                    for key, filename_value in REPORT_ARTIFACTS.items():
                        self.assertEqual(artifacts.get(key), filename_value)
                    self.assertEqual(artifacts.get("disassembly"), "vm_disassembly.txt")
                    self.assertEqual(artifacts.get("semantic_candidate"), "semantic_state_machine_candidate.luau")

                    documents, _ = self.load_json_artifacts(output_dir)
                    semantic_ir = documents["semantic_ir.json"]
                    cfg = documents["cfg.json"]
                    constants = documents["constants.json"]
                    graph = documents["artifact_graph.json"]
                    self.assertEqual(semantic_ir.get("status"), "payload_isolated")
                    self.assertTrue(semantic_ir.get("basic_blocks"))
                    self.assertTrue(cfg.get("nodes"))
                    self.assertTrue(constants.get("constants"))
                    self.assertTrue(graph.get("edges"))
                    reconstruction_map = documents["reconstruction_map.json"]
                    self.assertEqual(reconstruction_map.get("output"), "reconstructed_candidate.luau")
                    self.assertIs(reconstruction_map.get("verified"), False)
                    self.assertTrue(reconstruction_map.get("statements"))
                    mapped_states = {item.get("state") for item in reconstruction_map["statements"]}
                    self.assertGreaterEqual(len(mapped_states), candidate_report.get("root_blocks", 0))

                    node_ids = [node.get("id") for node in graph.get("nodes", [])]
                    self.assertEqual(len(node_ids), len(set(node_ids)))
                    self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", node_id or "") for node_id in node_ids))

                    source_result, source_report = self.execute_runtime(source, output_dir, "source")
                    candidate_result, candidate_runtime_report = self.execute_runtime(candidate, output_dir, "candidate")
                    self.assertEqual(
                        source_result.returncode,
                        0,
                        f"source oracle did not compile and execute for {filename}: {source_result.stderr}",
                    )
                    self.assertEqual(
                        candidate_result.returncode,
                        0,
                        f"candidate did not compile and execute for {filename}: {candidate_result.stderr}",
                    )
                    self.assertEqual(
                        candidate_result.returncode,
                        source_result.returncode,
                        f"runtime exit mismatch for {filename}\nsource:\n{source_result.stdout}{source_result.stderr}"
                        f"candidate:\n{candidate_result.stdout}{candidate_result.stderr}",
                    )
                    chunk_paths = (source, candidate)
                    self.assertEqual(
                        runtime_projection(candidate_runtime_report, chunk_paths),
                        runtime_projection(source_report, chunk_paths),
                        f"runtime behavior mismatch for {filename}",
                    )

    def test_focused_structured_families_are_deterministic_and_runtime_equivalent(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        statuses = {entry["filename"]: entry.get("status") for entry in manifest["files"]}

        with tempfile.TemporaryDirectory(prefix="alex-native-focused-families-") as temporary:
            root = pathlib.Path(temporary)
            for family, filename in FOCUSED_STRUCTURED_FAMILY_SAMPLES:
                with self.subTest(family=family, sample=filename):
                    self.assertIn(statuses.get(filename), ACCEPTED_STATUSES)
                    obfuscated = CORPUS_DIR / filename
                    source = SOURCE_DIR / filename
                    self.assertTrue(obfuscated.is_file(), f"missing obfuscated fixture: {obfuscated}")
                    self.assertTrue(source.is_file(), f"missing source oracle: {source}")

                    first_dir = root / family / "first"
                    second_dir = root / family / "second"
                    first_result, first_report, first_candidate = self.trace_candidate(
                        obfuscated,
                        first_dir,
                    )
                    second_result, second_report, second_candidate = self.trace_candidate(
                        obfuscated,
                        second_dir,
                    )

                    self.assert_returncode(first_result, 2)
                    self.assert_returncode(second_result, 2)
                    for reconstruction, report, candidate in (
                        ("first_quality", first_report, first_candidate),
                        ("second_quality", second_report, second_candidate),
                    ):
                        with self.subTest(check=reconstruction):
                            self.assert_common_report(report)
                            self.assertEqual(report.get("adapter"), "wearedevs-v1")
                            self.assert_clean_compilable_reconstruction(
                                candidate.read_text(encoding="utf-8"),
                                report,
                                filename,
                            )

                    with self.subTest(check="determinism"):
                        self.assertEqual(
                            first_candidate.read_bytes(),
                            second_candidate.read_bytes(),
                            f"{filename}: reconstructed source was nondeterministic",
                        )
                        for artifact in DETERMINISTIC_RECONSTRUCTION_ARTIFACTS:
                            self.assertEqual(
                                (first_dir / artifact).read_bytes(),
                                (second_dir / artifact).read_bytes(),
                                f"{filename}: {artifact} was nondeterministic",
                            )

                    source_result, source_report = self.execute_runtime(source, first_dir, "source")
                    candidate_result, candidate_report = self.execute_runtime(
                        first_candidate,
                        first_dir,
                        "candidate",
                    )
                    with self.subTest(check="runtime_equivalence"):
                        self.assertEqual(
                            source_result.returncode,
                            0,
                            f"{filename}: source oracle failed\n{source_result.stdout}{source_result.stderr}",
                        )
                        self.assertEqual(
                            candidate_result.returncode,
                            0,
                            f"{filename}: candidate failed\n{candidate_result.stdout}{candidate_result.stderr}",
                        )
                        chunk_paths = (source, first_candidate)
                        self.assertEqual(
                            runtime_projection(candidate_report, chunk_paths),
                            runtime_projection(source_report, chunk_paths),
                            f"{filename}: reconstructed runtime behavior diverged from source",
                        )

    def test_empty_register_table_scalarization_preserves_nested_captures(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-scalarization-") as temporary:
            root = pathlib.Path(temporary)
            _, artifact, _ = self.rewrite_fixture(SYNTHETIC_REGISTER_CAPTURE)
            rewritten = artifact["source"]
            metrics = artifact["metrics"]
            input_counts = reconstruction_structure_counts(
                SYNTHETIC_REGISTER_CAPTURE.read_text(encoding="utf-8")
            )
            output_counts = reconstruction_structure_counts(rewritten)

            self.assertIs(artifact.get("changed"), True)
            self.assertEqual(metrics.get("regions_found"), 0)
            self.assertEqual(metrics.get("regions_structured"), 0)
            self.assertEqual(metrics.get("residual_state_machines"), 0)
            self.assertEqual(metrics.get("residual_reasons"), {})
            self.assertEqual(metrics.get("register_tables_scalarized"), 1)
            self.assertEqual(metrics.get("register_tables_fully_scalarized"), 1)
            self.assertEqual(metrics.get("register_tables_partially_scalarized"), 0)
            self.assertEqual(metrics.get("register_table_slots_scalarized"), 2)
            self.assertEqual(metrics.get("register_table_accesses_scalarized"), 9)
            self.assertEqual(input_counts["empty_table_allocations"], 1)
            self.assertEqual(input_counts["constant_index_accesses"], 9)
            self.assertEqual(input_counts["closure_literals"], 2)
            self.assertEqual(input_counts["state_dispatchers"], 0)
            self.assertEqual(output_counts["empty_table_allocations"], 0)
            self.assertEqual(output_counts["constant_index_accesses"], 0)
            self.assertEqual(output_counts["closure_literals"], 2)
            self.assertEqual(output_counts["state_dispatchers"], 0)
            self.assertNotRegex(rewritten, RESIDUAL_VM_OR_PROTECTOR)

            rewritten_path = root / "rewritten.luau"
            rewritten_path.write_text(rewritten, encoding="utf-8")
            source_result, source_report = self.execute_runtime(
                SYNTHETIC_REGISTER_CAPTURE,
                root,
                "synthetic-source",
            )
            rewritten_result, rewritten_report = self.execute_runtime(
                rewritten_path,
                root,
                "synthetic-rewritten",
            )
            self.assertEqual(source_result.returncode, 0, source_result.stderr)
            self.assertEqual(rewritten_result.returncode, 0, rewritten_result.stderr)
            self.assertEqual(source_report.get("returns"), [22, 18, 4])
            chunk_paths = (SYNTHETIC_REGISTER_CAPTURE, rewritten_path)
            self.assertEqual(
                runtime_projection(rewritten_report, chunk_paths),
                runtime_projection(source_report, chunk_paths),
            )

    def test_register_table_scalarization_respects_the_luau_local_limit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-partial-scalarization-") as temporary:
            root = pathlib.Path(temporary)
            _, artifact, _ = self.rewrite_fixture(SYNTHETIC_PARTIAL_REGISTER_TABLE)
            rewritten = artifact["source"]
            metrics = artifact["metrics"]
            input_counts = reconstruction_structure_counts(
                SYNTHETIC_PARTIAL_REGISTER_TABLE.read_text(encoding="utf-8")
            )
            output_counts = reconstruction_structure_counts(rewritten)

            with self.subTest(check="bounded_partial_scalarization"):
                self.assertIs(artifact.get("changed"), True)
                self.assertEqual(metrics.get("register_tables_scalarized"), 1)
                self.assertEqual(metrics.get("register_tables_fully_scalarized"), 0)
                self.assertEqual(metrics.get("register_tables_partially_scalarized"), 1)
                scalarized_slots = metrics.get("register_table_slots_scalarized", 0)
                scalarized_accesses = metrics.get("register_table_accesses_scalarized", 0)
                self.assertGreater(scalarized_slots, 0)
                self.assertLess(scalarized_slots, 189)
                self.assertEqual(scalarized_accesses, scalarized_slots * 2)
                self.assertEqual(input_counts["empty_table_allocations"], 1)
                self.assertEqual(input_counts["constant_index_accesses"], 410)
                self.assertEqual(output_counts["empty_table_allocations"], 1)
                self.assertEqual(output_counts["constant_index_accesses"], 410 - scalarized_accesses)
                self.assertNotRegex(rewritten, r"\b(?:local|registers)_\d+\s*\[\s*1\s*\]")
                self.assertRegex(
                    rewritten,
                    rf"\b[A-Za-z_]\w*\s*\[\s*{scalarized_slots + 1}\s*\]",
                )

            with self.subTest(check="deterministic_slot_selection"):
                _, repeated, _ = self.rewrite_fixture(SYNTHETIC_PARTIAL_REGISTER_TABLE)
                self.assertEqual(repeated, artifact)

            rewritten_path = root / "rewritten.luau"
            rewritten_path.write_text(rewritten, encoding="utf-8")
            source_result, source_report = self.execute_runtime(
                SYNTHETIC_PARTIAL_REGISTER_TABLE,
                root,
                "partial-scalar-source",
            )
            rewritten_result, rewritten_report = self.execute_runtime(
                rewritten_path,
                root,
                "partial-scalar-rewritten",
            )
            with self.subTest(check="runtime_equivalence"):
                self.assertEqual(source_result.returncode, 0, source_result.stderr)
                self.assertEqual(rewritten_result.returncode, 0, rewritten_result.stderr)
                self.assertEqual(source_report.get("returns"), [*range(1, 206), 0])
                chunk_paths = (SYNTHETIC_PARTIAL_REGISTER_TABLE, rewritten_path)
                self.assertEqual(
                    runtime_projection(rewritten_report, chunk_paths),
                    runtime_projection(source_report, chunk_paths),
                )

    def test_private_register_dead_stores_cross_only_unobserving_closures(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-private-slot-dse-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "private-slot-dse.luau"
            source.write_text(
                '''local trace = {}
local function keep(value)
    table.insert(trace, value)
end

local function probe()
    local local_1, local_2
    local_1 = {}
    local_1[1] = "dead-before-function"
    local function unrelated()
        return "unrelated"
    end
    local_1[1] = "dead-before-call"
    keep(unrelated())
    local_1[1] = "live"
    local observed = local_1[1]

    local_2 = {}
    local_2[1] = "captured"
    local function observer()
        keep(local_2[1])
    end
    observer()
    local_2[1] = "after"
    return observed, local_2[1], table.concat(trace, ",")
end

return probe()
''',
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertNotIn('"dead-before-function"', rewritten)
            self.assertNotIn('"dead-before-call"', rewritten)
            self.assertIn('"captured"', rewritten)
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "private-slot-dse",
                ["live", "after", "unrelated,captured"],
            )

    def test_adjacent_single_use_temporaries_inline_without_semantic_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-adjacent-inline-") as temporary:
            root = pathlib.Path(temporary)
            _, artifact, _ = self.rewrite_fixture(SYNTHETIC_ADJACENT_TEMPORARIES)
            rewritten = artifact["source"]
            metrics = artifact["metrics"]
            identifier = r"[A-Za-z_][A-Za-z0-9_]*"

            with self.subTest(check="metrics"):
                self.assertIs(artifact.get("changed"), True)
                self.assertEqual(metrics.get("regions_found"), 0)
                self.assertEqual(metrics.get("residual_state_machines"), 0)
                self.assertEqual(metrics.get("residual_reasons"), {})
                self.assertGreaterEqual(
                    metrics.get("single_use_temporaries_inlined", 0)
                    + metrics.get("single_use_expressions_inlined", 0)
                    + metrics.get("semantic_lifetimes_split", 0),
                    5,
                )
                self.assertEqual(metrics.get("callback_aliases_promoted"), 1)
                self.assertNotRegex(rewritten, RESIDUAL_VM_OR_PROTECTOR)

            with self.subTest(check="multi_result_parentheses"):
                assignment = re.search(
                    rf"(?m)^[ \t]*(?P<first>{identifier})\s*,\s*"
                    rf"(?P<second>{identifier})\s*=\s*\(many\(\)\)[ \t]*$",
                    rewritten,
                )
                self.assertIsNotNone(
                    assignment,
                    "the grouped call must remain a two-target assignment with one produced value",
                )

            with self.subTest(check="side_effect_order"):
                self.assertRegex(
                    rewritten,
                    rf'''(?m)^[ \t]*(?:local\s+)?{identifier}\s*=\s*'''
                    r'''\(mark\("A",\s*4\)\)\s*\+\s*mark\("B",\s*6\)[ \t]*$''',
                )

            with self.subTest(check="branch_condition"):
                self.assertRegex(
                    rewritten,
                    r'''(?m)^[ \t]*if\s+\(?mark\("C",\s*true\)\)?\s+then[ \t]*$''',
                )

            with self.subTest(check="named_callback"):
                callback = re.search(
                    rf"(?s)local function (?P<callback>{identifier})\(value\)\s*"
                    r'''return\s+mark\("D",\s*value\s*\*\s*3\)\s*'''
                    r"end.*?\bconsume\((?P=callback)\)",
                    rewritten,
                )
                self.assertIsNotNone(callback, "the promoted callback must be passed by its declared name")

            with self.subTest(check="multi_result_call_argument"):
                grouped_call = re.search(
                    rf"(?m)^[ \t]*(?:local\s+)?{identifier}\s*,\s*{identifier}\s*,\s*"
                    rf"{identifier}\s*=\s*countValues\(\(many\(\)\)\)[ \t]*$",
                    rewritten,
                )
                bound_call = re.search(
                    rf"(?m)^[ \t]*(?:local\s+)?(?P<argument>{identifier})\s*=\s*many\(\)[ \t]*\n"
                    rf"(?:[ \t]*\n)*[ \t]*(?:local\s+)?{identifier}\s*,\s*{identifier}\s*,\s*"
                    rf"{identifier}\s*=\s*countValues\((?P=argument)\)[ \t]*$",
                    rewritten,
                )
                self.assertTrue(
                    grouped_call is not None or bound_call is not None,
                    "countValues must receive exactly one value and assign its three results",
                )

            with self.subTest(check="multi_result_table_tail"):
                grouped_table = re.search(
                    rf"(?m)^[ \t]*(?:local\s+)?(?P<table>{identifier})\s*=\s*"
                    r"\{\s*\(many\(\)\)\s*\}[ \t]*$",
                    rewritten,
                )
                bound_table = re.search(
                    rf"(?m)^[ \t]*(?:local\s+)?(?P<element>{identifier})\s*=\s*many\(\)[ \t]*\n"
                    rf"(?:[ \t]*\n)*[ \t]*(?:local\s+)?(?P<table>{identifier})\s*=\s*"
                    r"\{\s*(?P=element)\s*\}[ \t]*$",
                    rewritten,
                )
                self.assertTrue(
                    grouped_table is not None or bound_table is not None,
                    "the table must contain exactly the first result from many()",
                )
                table_name = (
                    grouped_table.group("table") if grouped_table is not None else bound_table.group("table")
                )
                self.assertRegex(
                    rewritten,
                    rf"(?s)\breturn\b.*?#\s*{re.escape(table_name)}\s*,\s*"
                    rf"{re.escape(table_name)}\s*\[\s*1\s*\]\s*,\s*"
                    rf"{re.escape(table_name)}\s*\[\s*2\s*\]",
                )

            with self.subTest(check="negative_multiple_uses"):
                reused_value = re.search(
                    rf'''(?m)^[ \t]*(?:local\s+)?(?P<value>{identifier})\s*=\s*'''
                    r'''mark\("M",\s*7\)[ \t]*$\n(?:[ \t]*\n)*'''
                    rf'''[ \t]*(?:local\s+)?{identifier}\s*=\s*'''
                    r'''(?P=value)\s*\+\s*(?P=value)[ \t]*$''',
                    rewritten,
                )
                self.assertIsNotNone(reused_value, "a multiply-used effectful value must stay materialized")
                self.assertEqual(len(re.findall(r'''mark\("M",\s*7\)''', rewritten)), 1)

            with self.subTest(check="negative_intervening_statement"):
                barrier_value = re.search(
                    rf'''(?m)^[ \t]*(?:local\s+)?(?P<value>{identifier})\s*=\s*'''
                    r'''mark\("I",\s*8\)[ \t]*$\n(?:[ \t]*\n)*'''
                    rf'''[ \t]*{identifier}\s*\.\.=\s*"\|gap\|"[ \t]*$\n(?:[ \t]*\n)*'''
                    rf'''[ \t]*(?:local\s+)?{identifier}\s*=\s*'''
                    r'''(?P=value)\s*\+\s*1[ \t]*$''',
                    rewritten,
                )
                self.assertIsNotNone(
                    barrier_value,
                    "the marked value must remain materialized across the intervening trace write",
                )

            rewritten_path = root / "rewritten.luau"
            rewritten_path.write_text(rewritten, encoding="utf-8")
            source_result, source_report = self.execute_runtime(
                SYNTHETIC_ADJACENT_TEMPORARIES,
                root,
                "adjacent-source",
            )
            rewritten_result, rewritten_report = self.execute_runtime(
                rewritten_path,
                root,
                "adjacent-rewritten",
            )
            with self.subTest(check="runtime_equivalence"):
                self.assertEqual(source_result.returncode, 0, source_result.stderr)
                self.assertEqual(rewritten_result.returncode, 0, rewritten_result.stderr)
                self.assertEqual(
                    source_report.get("returns"),
                    [
                        11,
                        None,
                        10,
                        "A1B2C3M4I5|gap|D6",
                        "hit",
                        15,
                        14,
                        9,
                        6,
                        1,
                        11,
                        None,
                        1,
                        11,
                        None,
                    ],
                )
                chunk_paths = (SYNTHETIC_ADJACENT_TEMPORARIES, rewritten_path)
                self.assertEqual(
                    runtime_projection(rewritten_report, chunk_paths),
                    runtime_projection(source_report, chunk_paths),
                )

            with self.subTest(check="deterministic_rewrite"):
                _, repeated, _ = self.rewrite_fixture(SYNTHETIC_ADJACENT_TEMPORARIES)
                self.assertEqual(repeated, artifact)

    def test_semantic_lifetime_splitting_preserves_conditional_block_shadows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-lifetime-shadow-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "lifetime-shadow.luau"
            source.write_text(
                """local function choose(condition)
    local local_4, local_16

    local_16 = condition
    if condition then
        local local_16 = "hot"
    end
    local_4 = local_16
    if not local_16 then
        local local_4 = "cold"
    end
    local first = local_4

    local_16 = not condition
    if not condition then
        local local_16 = "second-hot"
    end
    local_4 = local_16
    if not local_16 then
        local local_4 = "second-cold"
    end
    return first, local_4
end

local first, second = choose(true)
local third, fourth = choose(false)
return first, second, third, fourth
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertNotRegex(rewritten, r'''\bor\s+"(?:second-)?cold"''')
            self.assertNotRegex(rewritten, r'''\band\s*\(?"(?:second-)?hot"''')
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "lifetime-shadow",
                [True, False, False, True],
            )

    def test_semantic_lifetime_splitting_promotes_nested_definition_webs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-definition-web-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "definition-web.luau"
            source.write_text(
                """local function choose(condition, producer)
    local local_1, local_2, local_3

    local_1 = condition
    local before = local_1
    if condition then
        local_1 = producer()
        local_2 = local_1.Name
        local_3 = local_1.Value
        print(local_2, local_3)
    end
    return before
end

local first = choose(true, function() return {Name = "inner", Value = 1} end)
local second = choose(false, function() return {Name = "unused", Value = 2} end)
return first, second
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact["metrics"].get("semantic_lifetimes_split", 0), 1)
            self.assertRegex(rewritten, r"(?m)^\s+local\s+\w+\s*=\s*producer\(\)$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "definition-web",
                [True, False],
            )

    def test_semantic_lifetime_splitting_preserves_live_branch_joins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-live-definition-web-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "live-definition-web.luau"
            source.write_text(
                """local function choose(condition, producer)
    local local_1

    local_1 = condition
    if condition then
        local_1 = producer()
        print(local_1)
    end
    return local_1
end

local first = choose(true, function() return "inner" end)
local second = choose(false, function() return "unused" end)
return first, second
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertNotRegex(rewritten, r"(?m)^\s+local\s+\w+\s*=\s*producer\(\)$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "live-definition-web",
                ["inner", False],
            )

    def test_semantic_lifetime_splitting_preserves_self_update_input_versions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-self-update-web-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "self-update-web.luau"
            source.write_text(
                """local trace = ""
local function produce()
    trace ..= "P"
    return 12
end

local function transform(value)
    trace ..= "T"
    return value + 5
end

local local_1
local_1 = produce()
local snapshot = local_1
local_1 = transform(local_1)
return snapshot, local_1, trace
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            producer = re.search(r"(?m)^local\s+(\w+)\s*=\s*produce\(\)$", rewritten)
            self.assertIsNotNone(producer)
            self.assertRegex(rewritten, rf"transform\(\s*{re.escape(producer.group(1))}\s*\)")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "self-update-web",
                [12, 17, "PT"],
            )

    def test_residual_ssa_splits_post_rename_vm_value_versions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-residual-ssa-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "residual-ssa.luau"
            source.write_text(
                """local trace = ""
local function produce()
    trace ..= "P"
    return 12
end
local function transform(value)
    trace ..= "T"
    return value + 5
end

local vm_value_1
vm_value_1 = produce()
local snapshot = vm_value_1
vm_value_1 = transform(vm_value_1)
return snapshot, vm_value_1, trace
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r"(?m)^local\s+\w+\s*=\s*produce\(\)$")
            self.assertNotRegex(rewritten, r"(?m)^vm_value_1\s*=\s*produce\(\)$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "residual-ssa",
                [12, 17, "PT"],
            )

    def test_numeric_loop_recovery_absorbs_synthetic_exit_break(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-numeric-loop-break-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "numeric-loop-break.luau"
            source.write_text(
                """local local_5, local_9, local_17, local_18, local_19, local_20
local __results
local __state = 1
while __state ~= nil do
    if __state == 1 then
        local_20 = 1
        local_5 = 5
        local_19 = local_5
        local_5 = 1
        local_17 = local_5
        local_5 = 0
        local_18 = (local_17 < local_5)
        local_5 = (local_20 - local_17)
        __state = 2
    elseif __state == 2 then
        local_5 = (local_5 + local_17)
        local_9 = (not local_18)
        local_20 = (local_5 <= local_19)
        local_20 = (local_9 and local_20)
        local_9 = (local_5 >= local_19)
        local_9 = (local_18 and local_9)
        local_20 = (local_9 or local_20)
        __state = ((local_20 and 3) or 4)
    elseif __state == 3 then
        print(local_5)
        __state = 2
    elseif __state == 4 then
        __results = {}
        __state = nil
    else
        __state = nil
    end
end
if __results ~= nil then
    return table.unpack(__results)
end
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertIn("for index_1 = 1, 5 do", rewritten)
            self.assertNotRegex(rewritten, r"(?m)^\s*break\s*$")
            self.assert_runtime_equivalent_rewrite(source, rewritten, root, "numeric-loop-break", [])

    def test_generic_loop_recovery_accepts_implicit_exit_and_indexed_state(self) -> None:
        fixtures = {
            "plain": "local iterator, state, control = ipairs({10, 20})",
            "indexed": "local registers_1 = {}\nlocal iterator, control\niterator, registers_1[39], control = ipairs({10, 20})",
        }
        states = {"plain": "state", "indexed": "registers_1[39]"}
        with tempfile.TemporaryDirectory(prefix="alex-native-implicit-generic-") as temporary:
            root = pathlib.Path(temporary)
            for label, setup in fixtures.items():
                with self.subTest(label=label):
                    source = root / f"implicit-generic-{label}.luau"
                    source.write_text(
                        f"""{setup}
local total = 0
while true do
    control, value = iterator({states[label]}, control)
    if control then
        total += value
        continue
    end
end
return total
""",
                        encoding="utf-8",
                    )
                    _, artifact, _ = self.rewrite_fixture(source)
                    rewritten = artifact["source"]
                    self.assertRegex(rewritten, r"for key_1, value_1 in iterator,")
                    self.assertNotIn("while true do", rewritten)
                    rewritten_path = root / f"implicit-generic-{label}-rewritten.luau"
                    rewritten_path.write_text(rewritten, encoding="utf-8")
                    result, report = self.execute_runtime(rewritten_path, root, f"implicit-generic-{label}")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(report.get("returns"), [30.0])

    def test_literal_prefix_propagation_remains_compilable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-literal-prefix-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "literal-prefix.luau"
            source.write_text(
                """local function readMissing()
    local local_1
    local_1 = nil
    local local_2 = (local_1)["Value"]
    return local_2
end

local ok, message = pcall(readMissing)
return ok, string.find(message, "Value", 1, true) ~= nil
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertIn("(nil).Value", rewritten)
            self.assertNotIn("nil.Value", rewritten.replace("(nil).Value", ""))
            self.assert_runtime_equivalent_rewrite(source, rewritten, root, "literal-prefix", [False, True])

    def test_unused_command_result_can_die_across_an_unrelated_callback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-command-result-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "command-result.luau"
            source.write_text(
                """local local_1, local_2
local_1 = print("side effect")
local function callback()
    return true
end
local_1, local_2 = pcall(callback)
return local_1, local_2
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertIn('print("side effect")', rewritten)
            self.assertNotRegex(rewritten, r'(?m)^\s*\w+\s*=\s*print\("side effect"\)\s*$')
            self.assert_runtime_equivalent_rewrite(source, rewritten, root, "command-result", [True, True])

    def test_semantic_lifetime_splitting_keeps_captured_nested_definitions_shared(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-captured-definition-web-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "captured-definition-web.luau"
            source.write_text(
                """local function choose()
    local local_1

    local_1 = "outer"
    if true then
        local_1 = "inner"
        local read = function()
            return local_1
        end
        return read()
    end
end

return choose()
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertNotRegex(rewritten, r'(?m)^\s+local\s+\w+\s*=\s*"inner"$')
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "captured-definition-web",
                ["inner"],
            )

    def test_readable_alias_propagation_requires_branch_dominance(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-alias-dominance-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "alias-dominance.luau"
            source.write_text(
                """local function choose(condition)
    local local_1, local_2, local_3, local_4

    local_1 = condition
    if condition then
        local_2 = "hot"
        local_1 = local_2
    end
    local_3 = local_1
    if not local_1 then
        local_4 = "cold"
        local_3 = local_4
    end
    return local_3
end

return choose(true), choose(false)
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            self.assert_runtime_equivalent_rewrite(
                source,
                artifact["source"],
                root,
                "alias-dominance",
                ["hot", "cold"],
            )

    def test_adjacent_generated_expression_chains_inline_without_reordering_effects(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-generated-expression-chain-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "generated-expression-chain.luau"
            source.write_text(
                """local trace = ""
local function mark(label, value)
    trace ..= label
    return value
end

local function pure_chain(argument_1)
    local local_1, local_2, local_3
    local_1 = argument_1 + 2
    local_2 = local_1 * 3
    local_3 = local_2 >= 24
    if local_3 then
        return "high"
    end
    return "low"
end

local function effect_first_rhs()
    local local_4, local_5
    local_4 = mark("A", 4)
    local_5 = local_4 + mark("B", 6)
    return local_5
end

local receiver = {}
function receiver.apply(self, value)
    return value * 2
end
local function make_receiver()
    mark("C", 0)
    return receiver
end
local function effect_first_receiver()
    local local_6, local_7
    local_6 = make_receiver()
    local_7 = local_6:apply(mark("D", 5))
    return local_7
end

local arithmetic = pure_chain(6)
local rhs = effect_first_rhs()
local receiver_result = effect_first_receiver()
return arithmetic, rhs, receiver_result, trace
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]

            with self.subTest(check="pure_arithmetic_condition_chain"):
                for name in ("local_1", "local_2", "local_3"):
                    self.assertNotRegex(rewritten, rf"(?m)^\s*{name}\s*=")
                self.assertRegex(
                    rewritten,
                    r"(?m)^\s*if\s+.*argument_1\s*\+\s*2.*\*\s*3.*>=\s*24.*then\s*$",
                )

            with self.subTest(check="effectful_first_rhs"):
                self.assertNotRegex(rewritten, r'''(?m)^\s*local_4\s*=\s*mark\("A",\s*4\)\s*$''')
                self.assertRegex(
                    rewritten,
                    r'''(?m)^.*\(mark\("A",\s*4\)\)\s*\+\s*mark\("B",\s*6\).*$''',
                )

            with self.subTest(check="effectful_first_receiver"):
                self.assertNotRegex(rewritten, r"(?m)^\s*local_6\s*=\s*make_receiver\(\)\s*$")
                self.assertRegex(
                    rewritten,
                    r'''(?m)^.*\(make_receiver\(\)\):apply\(mark\("D",\s*5\)\).*$''',
                )

            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "generated-expression-chain",
                ["high", 10, 10, "ABCD"],
            )

    def test_adjacent_pure_roblox_value_constructors_inline_only_when_order_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-roblox-constructor-inline-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "roblox-constructor-inline.luau"
            source.write_text(
                """local trace = ""
local function mark(label, value)
    trace ..= label
    return value
end

local function safe_table_field()
    local local_1, local_2
    local_1 = Color3.fromRGB(10, 20, 30)
    local_2 = { kind = "safe", color = local_1, after = mark("A", 7) }
    return local_2.color == Color3.fromRGB(10, 20, 30) and local_2.after == 7
end

local function effectful_constructor()
    local local_3, local_4
    local_3 = Color3.fromRGB(mark("C", 40), 50, 60)
    local_4 = { before = mark("D", 1), color = local_3 }
    return local_4.color == Color3.fromRGB(40, 50, 60) and local_4.before == 1
end

local function multiply_used_constructor()
    local local_5, local_6
    local_5 = Color3.fromRGB(70, 80, 90)
    local_6 = { first = local_5, second = local_5 }
    return local_6.first == local_6.second
        and local_6.first == Color3.fromRGB(70, 80, 90)
end

return safe_table_field(), effectful_constructor(), multiply_used_constructor(), trace
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            identifier = r"[A-Za-z_][A-Za-z0-9_]*"

            with self.subTest(check="table_field_inlined"):
                self.assertNotRegex(
                    rewritten,
                    r"(?m)^\s*(?:local\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*"
                    r"Color3\.fromRGB\(10,\s*20,\s*30\)\s*$",
                )
                self.assertRegex(
                    rewritten,
                    r'''(?m)^\s*(?:local\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{\s*'''
                    r'''kind\s*=\s*"safe"\s*,\s*color\s*=\s*\(?Color3\.fromRGB'''
                    r'''\(10,\s*20,\s*30\)\)?\s*,\s*after\s*=\s*mark\("A",\s*7\)\s*\}\s*$''',
                )

            with self.subTest(check="effectful_constructor_remains_materialized"):
                effectful = re.search(
                    rf'''(?m)^\s*(?:local\s+)?(?P<color>{identifier})\s*=\s*'''
                    r'''Color3\.fromRGB\(mark\("C",\s*40\),\s*50,\s*60\)\s*$''',
                    rewritten,
                )
                self.assertIsNotNone(
                    effectful,
                    "an effectful constructor must stay before the table's earlier effectful field",
                )
                self.assertRegex(
                    rewritten,
                    rf'''(?m)^\s*(?:local\s+)?{identifier}\s*=\s*\{{\s*'''
                    rf'''before\s*=\s*mark\("D",\s*1\)\s*,\s*color\s*=\s*'''
                    rf'''{re.escape(effectful.group("color"))}\s*\}}\s*$''',
                )

            with self.subTest(check="multiply_used_constructor_remains_materialized"):
                multiply_used = re.search(
                    rf'''(?m)^\s*(?:local\s+)?(?P<color>{identifier})\s*=\s*'''
                    r'''Color3\.fromRGB\(70,\s*80,\s*90\)\s*$''',
                    rewritten,
                )
                self.assertIsNotNone(
                    multiply_used,
                    "a constructor value referenced twice must not be duplicated",
                )
                color = re.escape(multiply_used.group("color"))
                self.assertRegex(
                    rewritten,
                    rf'''(?m)^\s*(?:local\s+)?{identifier}\s*=\s*\{{\s*'''
                    rf'''first\s*=\s*{color}\s*,\s*second\s*=\s*{color}\s*\}}\s*$''',
                )
                self.assertEqual(len(re.findall(r"Color3\.fromRGB\(70,\s*80,\s*90\)", rewritten)), 2)

            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "roblox-constructor-inline",
                [True, True, True, "ACD"],
            )

    def test_prometheus_or_ladder_recovers_after_semantic_lifetime_naming(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-prometheus-or-ladder-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "prometheus-or-ladder.luau"
            source.write_text(
                """local trace = ""
local function fallback()
    trace ..= "F"
    return "fallback"
end

local function mark(label, value)
    trace ..= label
    return value
end

local function choose(left)
    local condition_1
    condition_1 = left
    if not (left) then
        condition_1 = fallback()
    end
    return condition_1
end

local function guarded(left)
    local condition_2, observed
    condition_2 = left
    if not (left) then
        observed = fallback()
        condition_2 = observed
    end
    return condition_2, observed
end

local function choose_color(condition)
    local local_1, local_2
    local_1 = condition
    if condition then
        local color_1 = mark("C", "hot")
        local_1 = color_1
    end
    local_2 = local_1
    if not (local_1) then
        local color_2 = mark("D", "cold")
        local_2 = color_2
    end
    return local_2
end

local first = choose("ready")
local first_trace = trace
local second = choose(false)
local second_trace = trace
local third, observed = guarded(false)
local hot = choose_color(true)
local cold = choose_color(false)
return first, first_trace, second, second_trace, third, observed, hot, cold, trace
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r"\bleft\s+or\s+\(+fallback\(\)\)+")
            self.assertRegex(rewritten, r"(?m)^\s*if\s+not\s+\(?left\)?\s+then\s*$")
            self.assertRegex(rewritten, r'''(?s)condition\s+and\s+\(+mark\("C",\s*"hot"\)\)+''')
            self.assertRegex(rewritten, r'''(?s)\bor\s+\(+mark\("D",\s*"cold"\)\)+''')
            self.assertNotRegex(rewritten, r"\bcolor_[12]\b")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "prometheus-or-ladder",
                ["ready", "", "fallback", "F", "fallback", "fallback", "hot", "cold", "FFCD"],
            )

    def test_adjacent_generated_expression_inlining_respects_liveness_capture_and_effect_order(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-generated-expression-barriers-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "generated-expression-barriers.luau"
            source.write_text(
                """local trace = ""
local function mark(label, value)
    trace ..= label
    return value
end

local function later_use(argument_1)
    local local_1, local_2, local_3
    local_1 = argument_1 + 1
    local_2 = local_1 * 2
    local_3 = local_1 * 3
    local_1 = 0
    return local_2, local_3, local_1
end

local function captured(argument_1)
    local local_4, local_5
    local_4 = argument_1 + 5
    local_5 = local_4 * 2
    local function read()
        return local_4
    end
    return local_5, read()
end

local function effect_before_result()
    local local_6, local_7
    local_6 = mark("E", 4)
    local_7 = mark("F", 6) + local_6
    return local_7
end

local first, second, overwritten = later_use(4)
local doubled, captured_value = captured(7)
local effect_total = effect_before_result()
return first, second, overwritten, doubled, captured_value, effect_total, trace
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            identifier = r"[A-Za-z_][A-Za-z0-9_]*"

            with self.subTest(check="later_use_before_overwrite"):
                self.assertRegex(
                    rewritten,
                    rf"(?s)(?:local\s+)?({identifier})\s*=\s*argument_1\s*\+\s*1.*?"
                    rf"(?:local\s+)?{identifier}\s*=\s*\1\s*\*\s*2.*?"
                    rf"(?:local\s+)?{identifier}\s*=\s*\1\s*\*\s*3",
                )

            with self.subTest(check="nested_closure_capture"):
                self.assertRegex(
                    rewritten,
                    rf"(?s)(?:local\s+)?({identifier})\s*=\s*argument_1\s*\+\s*5.*?"
                    rf"(?:local\s+)?{identifier}\s*=\s*\1\s*\*\s*2.*?"
                    r"local function read\(\).*?return\s+\1",
                )

            with self.subTest(check="earlier_effectful_rhs"):
                self.assertRegex(
                    rewritten,
                    rf'''(?s)(?:local\s+)?({identifier})\s*=\s*mark\("E",\s*4\).*?'''
                    r'''mark\("F",\s*6\)\s*\+\s*\1''',
                )
                self.assertNotRegex(
                    rewritten,
                    r'''(?m)^.*mark\("F",\s*6\).*mark\("E",\s*4\).*$''',
                )

            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "generated-expression-barriers",
                [10, 15, 0, 24, 12, 10, "EF"],
            )

    def test_redundant_parentheses_cleanup_preserves_multi_result_call_arity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-redundant-parentheses-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "redundant-parentheses.luau"
            source.write_text(
                """local function many()
    return 11, 29
end

local function count_values(...)
    return select("#", ...), ...
end

local record = { value = 7 }
local scalar = ((record.value))
local first, second = (many())
local argument_count, only_value = count_values((many()))
return scalar, first, second, argument_count, only_value
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            metrics = artifact["metrics"]

            with self.subTest(check="metrics"):
                self.assertIs(artifact.get("changed"), True)
                self.assertEqual(metrics.get("redundant_parentheses_removed"), 2)
                self.assertEqual(metrics.get("guard_clauses_flattened"), 0)

            with self.subTest(check="safe_cleanup"):
                self.assertRegex(rewritten, r"(?m)^local scalar = record\.value$")
                self.assertNotIn("((record.value))", rewritten)

            with self.subTest(check="multi_result_arity"):
                self.assertRegex(rewritten, r"(?m)^local first, second = \(many\(\)\)$")
                self.assertRegex(
                    rewritten,
                    r"(?m)^local argument_count, only_value = count_values\(\(many\(\)\)\)$",
                )

            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "redundant-parentheses",
                [7, 11, None, 1, 11],
            )

    def test_nil_only_literal_unpack_return_preserves_zero_result_arity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-empty-unpack-return-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "empty-unpack-return.luau"
            source.write_text(
                """local function empty_results()
    return table.unpack({nil})
end

local function count_results(...)
    return select("#", ...)
end

return count_results(empty_results())
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            parameters, body = self.local_function_parts(
                rewritten,
                "empty_results",
                r"local function count_results\(",
            )

            self.assertIs(artifact.get("changed"), True)
            self.assertEqual(parameters, [])
            self.assertRegex(body, r"(?m)^[ \t]*return[ \t]*$")
            self.assertNotRegex(body, r"(?m)table\.unpack|^[ \t]*return\s+nil[ \t]*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "empty-unpack-return",
                [0],
            )

    def test_write_only_result_packs_preserve_discarded_call_effects(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-write-only-results-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "write-only-results.luau"
            source.write_text(
                '''local trace = ""
local function emit()
    trace ..= "E"
    return 1, 2
end

local function run()
    local __results
    __results = {"discarded", [3] = true}
    __results = {emit()}
    return "done"
end

return run(), trace
''',
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertEqual(artifact["metrics"].get("write_only_result_packs_removed"), 2)
            self.assertNotIn("__results", rewritten)
            self.assertRegex(rewritten, r"(?m)^\s*emit\(\)\s*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "write-only-results",
                ["done", "E"],
            )

    def test_terminating_else_branches_flatten_into_nested_guard_clauses(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-guard-clauses-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "guard-clauses.luau"
            source.write_text(
                """local function classify(value)
    if value < 0 then
        return "negative"
    else
        if value == 0 then
            return "zero"
        else
            return "positive"
        end
    end
end

return classify(-3), classify(0), classify(4)
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            metrics = artifact["metrics"]

            with self.subTest(check="metrics"):
                self.assertIs(artifact.get("changed"), True)
                self.assertEqual(metrics.get("guard_clauses_flattened"), 2)
                self.assertEqual(metrics.get("redundant_parentheses_removed"), 0)

            with self.subTest(check="guard_shape"):
                self.assertNotRegex(rewritten, r"(?m)^\s*else\s*$")
                self.assertRegex(
                    rewritten,
                    r'''(?s)if value < 0 then\s+return "negative"\s+end\s+'''
                    r'''if value == 0 then\s+return "zero"\s+end\s+return "positive"''',
                )

            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "guard-clauses",
                ["negative", "zero", "positive"],
            )

    def test_balenci_like_native_readable_analysis_stays_bounded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-balenci-like-") as temporary:
            source = pathlib.Path(temporary) / "balenci-like-reconstruction.luau"
            payload = balenci_like_reconstruction_source()
            source.write_text(payload, encoding="utf-8")
            self.assertGreaterEqual(payload.count("\n"), 11_500)
            self.assertGreaterEqual(len(payload.encode("utf-8")), 400_000)

            try:
                _, artifact, elapsed = self.rewrite_fixture(source, timeout=30)
            except subprocess.TimeoutExpired as error:
                self.fail(
                    "native readable analysis exceeded the 30-second hard timeout for the "
                    f"Balenci-like fixture: {error}"
                )

            metrics = artifact.get("metrics") or {}
            self.assertIs(artifact.get("changed"), True)
            self.assertEqual(
                metrics.get("single_use_temporaries_inlined", 0)
                + metrics.get("semantic_lifetimes_split", 0),
                5_760,
            )
            self.assertLess(
                elapsed,
                BALENCI_LIKE_ANALYSIS_BUDGET_SECONDS,
                "native readable analysis regressed toward the prior 30+ second Balenci path: "
                f"{elapsed:.2f}s >= {BALENCI_LIKE_ANALYSIS_BUDGET_SECONDS:.2f}s",
            )

    def test_adjacent_captured_reload_is_removed_only_without_an_intervening_call(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-captured-reload-") as temporary:
            root = pathlib.Path(temporary)
            _, artifact, _ = self.rewrite_fixture(SYNTHETIC_ADJACENT_CAPTURED_RELOAD)
            rewritten = artifact["source"]
            identifier = r"[A-Za-z_][A-Za-z0-9_]*"

            self.assertIs(artifact.get("changed"), True)
            adjacent_write = re.search(
                rf"(?m)^[ \t]*(?:local\s+)?(?P<receiver>{identifier})\s*=\s*"
                r"\{\s*Value\s*=\s*3\s*\}[ \t]*$\n(?:[ \t]*\n)*"
                r"[ \t]*(?P=receiver)\.Value\s*=\s*9[ \t]*$",
                rewritten,
            )
            self.assertIsNotNone(
                adjacent_write,
                "the adjacent reload must collapse to a direct write on the captured receiver",
            )
            receiver = adjacent_write.group("receiver")

            call_barrier = re.search(
                rf"(?m)^[ \t]*(?:local\s+)?(?P<alias>{identifier})\s*=\s*"
                rf"{re.escape(receiver)}[ \t]*$\n(?:[ \t]*\n)*"
                r"[ \t]*task\.wait\(\)[ \t]*$\n(?:[ \t]*\n)*"
                r"[ \t]*(?P=alias)\.Value\s*=\s*12[ \t]*$",
                rewritten,
            )
            self.assertIsNotNone(
                call_barrier,
                "the receiver snapshot must remain materialized across task.wait()",
            )
            self.assertNotEqual(call_barrier.group("alias"), receiver)
            self.assertRegex(
                rewritten,
                rf"(?m)^[ \t]*{re.escape(receiver)}\s*=\s*"
                rf"\{{\s*Value\s*=\s*{re.escape(receiver)}\.Value\s*\}}[ \t]*$\n"
                rf"[ \t]*return\s+{re.escape(receiver)}\.Value[ \t]*$",
            )

            rewritten_path = root / "rewritten.luau"
            rewritten_path.write_text(rewritten, encoding="utf-8")
            source_result, source_report = self.execute_runtime(
                SYNTHETIC_ADJACENT_CAPTURED_RELOAD,
                root,
                "captured-reload-source",
            )
            rewritten_result, rewritten_report = self.execute_runtime(
                rewritten_path,
                root,
                "captured-reload-rewritten",
            )
            self.assertEqual(source_result.returncode, 0, source_result.stderr)
            self.assertEqual(rewritten_result.returncode, 0, rewritten_result.stderr)
            self.assertEqual(source_report.get("returns"), [12])
            chunk_paths = (SYNTHETIC_ADJACENT_CAPTURED_RELOAD, rewritten_path)
            self.assertEqual(
                runtime_projection(rewritten_report, chunk_paths),
                runtime_projection(source_report, chunk_paths),
            )

    def test_dead_temporary_assignments_remove_overwritten_pure_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-dead-temporary-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "dead-temporary.luau"
            source.write_text(
                """local trace = ""
local function mark(value)
    trace ..= value
    return 99
end
local function dead_temporaries()
    local temporary
    temporary = 10
    temporary = 20
    local observed = temporary
    temporary = mark("K")
    temporary = 30
    return observed, trace
end
return dead_temporaries()
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact["metrics"].get("dead_assignments_removed", 0), 2)
            self.assertNotRegex(
                rewritten,
                r"(?m)^\s*temporary\s*=\s*(?:10|20|30)\s*$",
            )
            self.assertRegex(rewritten, r"(?m)^\s*local observed\s*=\s*20\s*$")
            self.assertRegex(
                rewritten,
                r'''(?m)^\s*(?:temporary|vm_temporary_\d+)\s*=\s*mark\("K"\)\s*$''',
            )
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "dead-temporary",
                [20, "K"],
            )

    def test_dead_temporary_analysis_preserves_semicolons_and_nested_captures(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-temporary-barriers-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "temporary-barriers.luau"
            source.write_text(
                """local events = ""
local function semicolon_barrier(callback)
    local temporary
    temporary = callback
    ;(function()
        callback("S")
    end)()
    return events
end

local function make_reader()
    local temporary
    temporary = 41
    local function read()
        return temporary
    end
    temporary = 42
    return read()
end

local semicolon_result = semicolon_barrier(function(value)
    events ..= value
end)
return semicolon_result, make_reader()
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r"(?m)^\s*(?:temporary|vm_temporary_\d+)\s*=\s*callback\s*$")
            self.assertRegex(rewritten, r"(?m)^\s*;\(function\(\)\s*$")
            self.assertRegex(
                rewritten,
                r"(?s)local function read\(\).*?return (?:temporary|vm_temporary_\d+).*?"
                r"end\s+(?:temporary|vm_temporary_\d+)\s*=\s*42",
            )
            self.assertRegex(rewritten, r"(?m)^\s*(?:temporary|vm_temporary_\d+)\s*=\s*41\s*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "temporary-barriers",
                ["S", 42],
            )

    def test_straight_line_alias_coalescing_respects_effect_barriers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-alias-coalescing-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "alias-coalescing.luau"
            source.write_text(
                """local function straight_line(captured_value_1)
    local local_1, local_2, local_3
    local_1 = captured_value_1
    local_2 = local_1.first
    local_3 = local_1.second
    local_1 = nil
    return local_2, local_3
end

local function call_barrier()
    local captured_value_2, local_4, before, after
    captured_value_2 = { value = 1 }
    local function mutate()
        captured_value_2 = { value = 2 }
    end
    local_4 = captured_value_2
    before = local_4.value
    mutate()
    after = local_4.value
    local_4 = nil
    return before, after
end

local function control_barrier(flag)
    local captured_value_3, local_7, after
    captured_value_3 = { value = 3 }
    local_7 = captured_value_3
    if flag then
        captured_value_3 = { value = 4 }
    end
    after = local_7.value
    local_7 = nil
    return after
end

local function capture_barrier()
    local captured_value_4, local_10
    captured_value_4 = { value = 5 }
    local_10 = captured_value_4
    local function read()
        return local_10.value
    end
    local_10 = { value = 6 }
    return read()
end

local safe_first, safe_second = straight_line({ first = 7, second = 8 })
local call_before, call_after = call_barrier()
local control_value = control_barrier(true)
local captured_result = capture_barrier()
return safe_first, safe_second, call_before, call_after, control_value, captured_result
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            identifier = r"[A-Za-z_][A-Za-z0-9_]*"
            self.assertIs(artifact.get("changed"), True)

            with self.subTest(check="straight_line"):
                parameters, body = self.local_function_parts(
                    rewritten,
                    "straight_line",
                    r"local function call_barrier\(",
                )
                self.assertEqual(len(parameters), 1)
                receiver = re.escape(parameters[0])
                self.assertNotRegex(
                    body,
                    rf"(?m)^[ \t]*(?:local\s+)?{identifier}\s*=\s*{receiver}[ \t]*$",
                )
                direct_return = re.search(
                    rf"(?m)^[ \t]*return\s+{receiver}\.first\s*,\s*"
                    rf"{receiver}\.second[ \t]*$",
                    body,
                )
                if direct_return is None:
                    returned_values = re.search(
                        rf"(?m)^[ \t]*return\s+(?P<first>{identifier})\s*,\s*"
                        rf"(?P<second>{identifier})[ \t]*$",
                        body,
                    )
                    self.assertIsNotNone(returned_values, "straight_line must return exactly two values")
                    first = returned_values.group("first")
                    second = returned_values.group("second")
                    self.assertNotEqual(first, second)
                    self.assertRegex(
                        body,
                        rf"(?m)^[ \t]*(?:local\s+)?{re.escape(first)}\s*=\s*"
                        rf"{receiver}\.first[ \t]*$",
                    )
                    self.assertRegex(
                        body,
                        rf"(?m)^[ \t]*(?:local\s+)?{re.escape(second)}\s*=\s*"
                        rf"{receiver}\.second[ \t]*$",
                    )

            with self.subTest(check="call_barrier"):
                parameters, body = self.local_function_parts(
                    rewritten,
                    "call_barrier",
                    r"local function control_barrier\(",
                )
                self.assertEqual(parameters, [])
                initial = re.search(
                    rf"(?m)^[ \t]*(?:local\s+)?(?P<captured>{identifier})\s*=\s*"
                    r"\{\s*value\s*=\s*1\s*\}[ \t]*$",
                    body,
                )
                self.assertIsNotNone(initial, "call_barrier must create the mutable captured receiver")
                captured = initial.group("captured")
                mutator = re.search(
                    rf"(?ms)^[ \t]*local function (?P<mutator>{identifier})\(\)[ \t]*$.*?"
                    rf"^[ \t]*{re.escape(captured)}\s*=\s*"
                    r"\{\s*value\s*=\s*2\s*\}[ \t]*$.*?^[ \t]*end[ \t]*$",
                    body,
                )
                self.assertIsNotNone(mutator, "the nested call must be able to replace the captured receiver")
                remainder = body[mutator.end() :]
                snapshot = re.search(
                    rf"(?m)^[ \t]*(?:local\s+)?(?P<snapshot>{identifier})\s*=\s*"
                    rf"{re.escape(captured)}[ \t]*$",
                    remainder,
                )
                self.assertIsNotNone(snapshot, "the pre-call receiver snapshot must remain materialized")
                snapshot_name = snapshot.group("snapshot")
                self.assertNotEqual(snapshot_name, captured)
                observations = re.search(
                    rf"(?ms)^[ \t]*(?:local\s+)?(?P<before>{identifier})\s*=\s*"
                    rf"{re.escape(snapshot_name)}\.value[ \t]*$.*?"
                    rf"^[ \t]*{re.escape(mutator.group('mutator'))}\(\)[ \t]*$.*?"
                    rf"^[ \t]*(?:local\s+)?(?P<after>{identifier})\s*=\s*"
                    rf"{re.escape(snapshot_name)}\.value[ \t]*$.*?"
                    r"^[ \t]*return\s+(?P=before)\s*,\s*(?P=after)[ \t]*$",
                    remainder,
                )
                self.assertIsNotNone(
                    observations,
                    "the same snapshot must be observed before and after the call barrier",
                )

            with self.subTest(check="control_barrier"):
                parameters, body = self.local_function_parts(
                    rewritten,
                    "control_barrier",
                    r"local function capture_barrier\(",
                )
                self.assertEqual(len(parameters), 1)
                flag = re.escape(parameters[0])
                control_flow = re.search(
                    rf"(?ms)^[ \t]*(?:local\s+)?(?P<captured>{identifier})\s*=\s*"
                    r"\{\s*value\s*=\s*3\s*\}[ \t]*$.*?"
                    rf"^[ \t]*(?:local\s+)?(?P<snapshot>{identifier})\s*=\s*"
                    r"(?P=captured)[ \t]*$.*?"
                    rf"^[ \t]*if\s+{flag}\s+then[ \t]*$.*?"
                    r"^[ \t]*(?P=captured)\s*=\s*\{\s*value\s*=\s*4\s*\}[ \t]*$.*?"
                    r"^[ \t]*end[ \t]*$.*?"
                    rf"^[ \t]*(?:local\s+)?(?P<after>{identifier})\s*=\s*"
                    r"(?P=snapshot)\.value[ \t]*$.*?"
                    r"^[ \t]*return\s+(?P=after)[ \t]*$",
                    body,
                )
                self.assertIsNotNone(
                    control_flow,
                    "the original receiver snapshot must survive the conditional reassignment",
                )
                self.assertNotEqual(control_flow.group("snapshot"), control_flow.group("captured"))

            with self.subTest(check="capture_barrier"):
                parameters, body = self.local_function_parts(
                    rewritten,
                    "capture_barrier",
                    r"local\s+safe_first\b",
                )
                self.assertEqual(parameters, [])
                read_closure = re.search(
                    rf"(?ms)^[ \t]*local function (?P<reader>{identifier})\(\)[ \t]*$.*?"
                    rf"^[ \t]*return\s+(?P<captured>{identifier})\.value[ \t]*$.*?"
                    r"^[ \t]*end[ \t]*$\n(?:[ \t]*\n)*"
                    r"[ \t]*(?P=captured)\s*=\s*\{\s*value\s*=\s*6\s*\}[ \t]*$"
                    r"(?:\n[ \t]*)*return\s+(?P=reader)\(\)[ \t]*$",
                    body,
                )
                self.assertIsNotNone(
                    read_closure,
                    "the closure must observe the binding after its post-capture reassignment",
                )
                captured = read_closure.group("captured")
                initialization = body[: read_closure.start()]
                direct_initialization = re.search(
                    rf"(?m)^[ \t]*(?:local\s+)?{re.escape(captured)}\s*=\s*"
                    r"\{\s*value\s*=\s*5\s*\}[ \t]*$",
                    initialization,
                )
                aliased_initialization = re.search(
                    rf"(?ms)^[ \t]*(?:local\s+)?(?P<source>{identifier})\s*=\s*"
                    r"\{\s*value\s*=\s*5\s*\}[ \t]*$.*?"
                    rf"^[ \t]*(?:local\s+)?{re.escape(captured)}\s*=\s*(?P=source)[ \t]*$",
                    initialization,
                )
                self.assertTrue(
                    direct_initialization is not None or aliased_initialization is not None,
                    "the captured binding must be initialized from the value-5 receiver",
                )
                if aliased_initialization is not None:
                    self.assertNotEqual(aliased_initialization.group("source"), captured)

            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "alias-coalescing",
                [7, 8, 1, 1, 3, 6],
            )

    def test_readable_alias_propagation_does_not_assume_globals_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-rebound-global-alias-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "rebound-global-alias.luau"
            source.write_text(
                """game = {Name = "old"}
local local_1 = game
local before = local_1.Name
game = {Name = "new"}
local after = local_1.Name
return before, after, game.Name
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r"(?m)^\s*(?:local\s+)?[A-Za-z_]\w*\s*=\s*game\s*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "rebound-global-alias",
                ["old", "old", "new"],
            )

    def test_lexical_alias_name_promotion_respects_snapshot_lifetimes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-lexical-alias-versions-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "lexical-alias-versions.luau"
            source.write_text(
                """local local_1 = {value = "old"}
local final_snapshot = local_1
local before_rebind = final_snapshot.value
local_1 = {value = "new"}
local after_rebind = local_1.value

local local_2 = {value = "kept"}
local preserved_snapshot = local_2
local_2 = {value = "replacement"}
local preserved_value = preserved_snapshot.value

return before_rebind, after_rebind, preserved_value, local_2.value
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact.get("lexical_alias_versions_eliminated", 0), 1)
            self.assertRegex(rewritten, r'(?m)^local final_snapshot\s*=\s*\{value = "old"\}$')
            self.assertNotRegex(rewritten, r"(?m)^local final_snapshot\s*=\s*[A-Za-z_]\w*$")
            self.assertRegex(rewritten, r"(?m)^local preserved_snapshot\s*=\s*[A-Za-z_]\w*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "lexical-alias-versions",
                ["old", "new", "kept", "replacement"],
            )

    def test_lexical_alias_name_promotion_accepts_snapshot_reads_in_rebind_rhs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-rebind-rhs-alias-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "rebind-rhs-alias.luau"
            source.write_text(
                """local local_1 = {value = 7}
local receiver = local_1
if local_1 then
    local_1 = {value = receiver.value + 4}
end
return local_1.value
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact.get("lexical_alias_versions_eliminated", 0), 1)
            self.assertNotRegex(rewritten, r"(?m)^local receiver\s*=\s*[A-Za-z_]\w*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "rebind-rhs-alias",
                [11],
            )

    def test_lexical_alias_versions_coalesce_callback_producer_transport(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-producer-transport-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "producer-transport.luau"
            source.write_text(
                """local local_1, callback
local_1 = function(value)
    return value + 1
end
callback = local_1
local_1 = false
return callback(4), local_1
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact.get("lexical_alias_versions_eliminated", 0), 1)
            self.assertRegex(rewritten, r"(?m)^callback\s*=\s*function\(value\)$")
            self.assertNotRegex(rewritten, r"(?m)^callback\s*=\s*[A-Za-z_]\w*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "producer-transport",
                [5, False],
            )

    def test_lexical_alias_versions_ignore_unread_conditional_producer_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-conditional-producer-write-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "conditional-producer-write.luau"
            source.write_text(
                """local local_1
local_1 = function(value)
    return value + 1
end
local callback = local_1
for _, value in ipairs({}) do
    local_1 = value
end
local_1 = false
return callback(6), local_1
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact.get("lexical_alias_versions_eliminated", 0), 1)
            self.assertRegex(rewritten, r"(?m)^local callback\s*=\s*function\(value\)$")
            self.assertNotRegex(rewritten, r"(?m)^local callback\s*=\s*[A-Za-z_]\w*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "conditional-producer-write",
                [7, False],
            )

    def test_lexical_alias_versions_preserve_recursive_producer_cells(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-recursive-producer-cell-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "recursive-producer-cell.luau"
            source.write_text(
                """local local_1, callback
local_1 = function(value)
    if value <= 0 then
        return 0
    end
    return local_1(value - 1) + 1
end
callback = local_1
local_1 = false
return callback
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r"(?m)^callback\s*=\s*[A-Za-z_]\w*$")
            self.assertRegex(rewritten, r"(?m)^\s*return\s+[A-Za-z_]\w*\(value - 1\) \+ 1$")

    def test_lexical_alias_versions_coalesce_values_across_deferred_callbacks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-deferred-value-transport-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "deferred-value-transport.luau"
            source.write_text(
                """local local_1, color, callback
local local_calls = 0
local_1 = 10
callback = function()
    local_calls += 1
    return color
end
color = local_1
local_1 = false
return callback(), local_1, local_calls
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact.get("lexical_alias_versions_eliminated", 0), 1)
            self.assertRegex(rewritten, r"(?m)^color\s*=\s*10$")
            self.assertNotRegex(rewritten, r"(?m)^color\s*=\s*[A-Za-z_]\w*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "deferred-value-transport",
                [10, False, 1],
            )

    def test_identifier_inference_ranks_corroborated_semantic_names(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-name-inference-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "name-inference.luau"
            source.write_text(
                """local local_1, local_2
local_1 = unknown_value()
local_1 = character:FindFirstChildOfClass("Humanoid")
print(local_1.Health)

local_2 = unknown_value()
print(local_2.Health, local_2.UserId)
return local_1, local_2
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r"(?m)^humanoid\s*=\s*unknown_value\(\)$")
            self.assertRegex(rewritten, r"(?m)^humanoid\s*=\s*character:FindFirstChildOfClass\(\"Humanoid\"\)$")
            self.assertRegex(rewritten, r"(?m)^vm_value_\d+\s*=\s*unknown_value\(\)$")

    def test_identifier_inference_uses_call_sites_and_operators(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-name-context-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "name-context.luau"
            source.write_text(
                """local local_1, local_2
local_1 = unknown_callback()
signal:Connect(local_1)
pcall(local_1)

local_2 = unknown_number()
print(local_2 + 1, local_2 * 2, local_2 - 3)
return local_1, local_2
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r"(?m)^callback\s*=\s*unknown_callback\(\)$")
            self.assertRegex(rewritten, r"(?m)^number\s*=\s*unknown_number\(\)$")

    def test_identifier_inference_rejects_mixed_callback_lifetimes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-mixed-callback-name-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "mixed-callback-name.luau"
            source.write_text(
                """local local_1
local_1 = function()
    return 1
end
pcall(local_1)
local_1 = condition and 560
return local_1
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r"(?m)^vm_value_\d+\s*=\s*function\(\)$")
            self.assertNotRegex(rewritten, r"(?m)^callback(?:_\d+)?\s*=\s*function\(\)$")

    def test_post_split_identifier_refinement_names_only_proven_residual_roles(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-post-split-names-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "post-split-names.luau"
            source.write_text(
                """local vm_value_1, vm_value_2, vm_value_3, vm_value_4, vm_value_5
vm_value_1 = game:GetService("Players")
vm_value_2 = pcall(function()
    return true
end)
vm_value_3 = CFrame.new()
vm_value_4 = unknown_value()
print(vm_value_4.Health, vm_value_4.UserId)
return vm_value_1, vm_value_2, vm_value_3, vm_value_4
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--refine-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r'(?m)^players\s*=\s*game:GetService\("Players"\)$')
            self.assertRegex(rewritten, r"(?m)^success\s*=\s*pcall\(function\(\)$")
            self.assertRegex(rewritten, r"(?m)^cframe\s*=\s*CFrame\.new\(\)$")
            self.assertRegex(rewritten, r"(?m)^vm_value_4\s*=\s*unknown_value\(\)$")
            self.assertNotIn("vm_value_5", rewritten)
            self.assertEqual(artifact.get("semantic_role_names"), 3)
            self.assertEqual(artifact.get("unused_declarations_removed"), 1)

    def test_final_stabilization_labels_ambiguous_values_without_claiming_recovered_names(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-stable-generated-names-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "ambiguous-value.luau"
            source.write_text(
                """local vm_value_1
vm_value_1 = unknown_value()
if vm_value_1 then
    print(vm_value_1.Name)
end
return vm_value_1
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--stabilize-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertIs(artifact.get("committed"), True)
            self.assertEqual(artifact.get("generated_merge_names"), 1)
            self.assertNotIn("vm_value_1", rewritten)
            self.assertRegex(rewritten, r"(?m)^(?:working|merged)_\w+(?:_\d+)?\s*=\s*unknown_value\(\)$")

    def test_straight_line_residual_versions_receive_distinct_semantic_locals(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-straight-residual-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "straight-residual.luau"
            source.write_text(
                """local vm_value_1
vm_value_1 = {Name = "first"}
local first = vm_value_1.Name
vm_value_1 = {Name = "second"}
local second = vm_value_1.Name
return first, second
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--split-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r'(?m)^local values\s*=\s*\{Name = "first"\}$')
            self.assertRegex(rewritten, r'(?m)^local values_2\s*=\s*\{Name = "second"\}$')
            self.assertNotRegex(rewritten, r"(?m)^vm_value_1\s*=")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "straight-residual",
                ["first", "second"],
            )

    def test_straight_line_residual_versions_reject_captured_cells(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-captured-residual-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "captured-residual.luau"
            source.write_text(
                """local vm_value_1
vm_value_1 = {Name = "old"}
local function read()
    return vm_value_1.Name
end
vm_value_1 = {Name = "new"}
return read(), vm_value_1.Name
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--split-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            self.assertFalse(artifact["changed"])
            self.assertEqual(artifact["source"], source.read_text(encoding="utf-8"))

    def test_guarded_receiver_snapshots_collapse_to_optional_chains(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-guarded-receiver-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "guarded-receiver.luau"
            source.write_text(
                """local calls = 0
local function nextValue(receiver)
    calls += 1
    return receiver.child
end

local function resolve(value)
    local local_1
    local_1 = value
    local receiver = local_1
    if local_1 then
        local_1 = nextValue(receiver)
    end
    return local_1
end

local missing = resolve(false)
local found = resolve({child = "ok"})
return missing, found, calls
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertNotRegex(rewritten, r"(?m)^\s*local receiver\s*=")
            self.assertRegex(rewritten, r"\bvalue\s+and\s+\(nextValue\(value\)\)")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "guarded-receiver",
                [False, "ok", 1],
            )

    def test_guarded_receiver_aliases_cross_unrelated_straight_line_statements(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-guarded-receiver-alias-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "guarded-receiver-alias.luau"
            source.write_text(
                """local function nextValue(receiver)
    return receiver.child
end

local function resolve(value)
    local local_1
    local_1 = value
    local receiver = local_1
    if local_1 then
        local marker = local_1.tag
        local_1 = nextValue(receiver)
        print(marker)
    end
    return local_1
end

return resolve({child = "ok", tag = "seen"})
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertNotRegex(rewritten, r"(?m)^\s*local receiver\s*=")
            self.assertRegex(rewritten, r"nextValue\([A-Za-z_]\w*\)")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "guarded-receiver-alias",
                ["ok"],
            )

    def test_linear_short_circuit_phi_producers_collapse_without_eager_calls(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-linear-short-circuit-phi-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "linear-short-circuit-phi.luau"
            source.write_text(
                """local calls = 0
local function rhs(value)
    calls += 1
    return value
end

local function and_phi(gate, value)
    local local_1, local_2
    local_1 = gate
    if gate then
        local_2 = rhs(value)
        local_1 = local_2
    end
    return local_1
end

local function or_phi(gate, value)
    local local_3, local_4
    local_3 = gate
    if not gate then
        local_4 = rhs(value)
        local_3 = local_4
    end
    return local_3
end

return and_phi(false, "unused"), and_phi(true, nil), or_phi("kept", "unused"), or_phi(false, "fallback"), calls
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertRegex(rewritten, r"gate\s+and\s+\(.*rhs\(value\).*")
            self.assertRegex(rewritten, r"gate\s+or\s+\(.*rhs\(value\).*")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "linear-short-circuit-phi",
                [False, None, "kept", "fallback", 2],
            )

    def test_nested_short_circuit_phi_chain_collapses_recursively(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-nested-short-circuit-phi-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "nested-short-circuit-phi.luau"
            source.write_text(
                """local known = {walk = true}

local function lookup(argument)
    local local_1, local_2, local_3, local_4
    local_1 = argument
    if argument then
        local_2 = argument.Animation
        if local_2 then
            local_3 = local_2.AnimationId
            local_4 = tostring(local_3)
            local_2 = known[local_4]
        end
        local_1 = local_2
    end
    return local_1
end

return lookup(nil), lookup({}), lookup({Animation = {AnimationId = "walk"}})
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertEqual(len(re.findall(r"(?m)^\s*if\s+", rewritten)), 1)
            self.assertRegex(rewritten, r"\band\s+\(known\[")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "nested-short-circuit-phi",
                [None, None, True],
            )

    def test_detached_method_call_reconstruction_crosses_unrelated_declarations_and_calls(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-detached-method-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "detached-method.luau"
            source.write_text(
                """local trace = ""
local function mark(label)
    trace ..= label
    return label
end

local receiver = { prefix = "R" }
function receiver.render(self, suffix)
    return self.prefix .. suffix .. ":" .. trace
end

local function invoke(argument_1)
    local local_1, local_2
    local_1 = argument_1.render
    local local_3 = mark("A")
    mark("B")
    local local_4 = { local_3 }
    local_2 = local_1(argument_1, local_4[1])
    return local_2
end

return invoke(receiver), trace
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertNotRegex(rewritten, r"(?m)^\s*local_1\s*=\s*argument_1\.render\s*$")
            self.assertRegex(
                rewritten,
                r'''(?s)mark\("A"\).*?mark\("B"\).*?argument_1:render\([^)]*\)''',
            )
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "detached-method",
                ["RA:AB", "AB"],
            )

    def test_detached_method_call_reconstruction_stops_after_function_or_receiver_reassignment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-detached-method-mutation-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "detached-method-mutation.luau"
            source.write_text(
                """local function original(self, value)
    return "original:" .. self.label .. ":" .. value
end

local function replacement(self, value)
    return "replacement:" .. self.label .. ":" .. value
end

local function function_reassigned(argument_1)
    local local_1, local_2
    local_1 = argument_1.method
    local_1 = replacement
    local_2 = local_1(argument_1, "function")
    return local_2
end

local function receiver_reassigned(argument_1, argument_2)
    local local_3, local_4
    local_3 = argument_1.method
    argument_1 = argument_2
    local_4 = local_3(argument_1, "receiver")
    return local_4
end

local first = { label = "first", method = original }
local second = { label = "second", method = replacement }
return function_reassigned(first), receiver_reassigned(first, second)
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            identifier = r"[A-Za-z_][A-Za-z0-9_]*"
            self.assertIs(artifact.get("changed"), True)

            function_parameters, function_body = self.local_function_parts(
                rewritten,
                "function_reassigned",
                r"local function receiver_reassigned\(",
            )
            self.assertEqual(len(function_parameters), 1)
            function_receiver = function_parameters[0]
            self.assertNotRegex(function_body, rf"\b{re.escape(function_receiver)}:method\(")
            function_call = re.search(
                rf'''\b(?P<callee>{identifier})\(\s*{re.escape(function_receiver)}\s*,\s*'''
                r'''"function"\s*\)''',
                function_body,
            )
            self.assertIsNotNone(
                function_call,
                "the reassigned function must be called with receiver and value as two explicit arguments",
            )
            if function_call.group("callee") != "replacement":
                self.assertRegex(
                    function_body[: function_call.start()],
                    rf"(?m)^[ \t]*(?:local\s+)?{re.escape(function_call.group('callee'))}\s*=\s*"
                    r"replacement[ \t]*$",
                )

            receiver_parameters, receiver_body = self.local_function_parts(
                rewritten,
                "receiver_reassigned",
                r"local\s+first\b",
            )
            self.assertEqual(len(receiver_parameters), 2)
            original_receiver, replacement_receiver = receiver_parameters
            self.assertNotRegex(receiver_body, rf"\b{identifier}:method\(")
            receiver_flow = re.search(
                rf"(?ms)^[ \t]*(?:local\s+)?(?P<callback>{identifier})\s*=\s*"
                rf"{re.escape(original_receiver)}\.method[ \t]*$.*?"
                rf"^[ \t]*{re.escape(original_receiver)}\s*=\s*"
                rf"{re.escape(replacement_receiver)}[ \t]*$.*?"
                rf'''\b(?P=callback)\(\s*{re.escape(original_receiver)}\s*,\s*'''
                r'''"receiver"\s*\)''',
                receiver_body,
            )
            self.assertIsNotNone(
                receiver_flow,
                "the detached callback snapshot must cross receiver reassignment and keep two-argument arity",
            )
            self.assertNotIn(
                receiver_flow.group("callback"),
                {original_receiver, replacement_receiver},
            )
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "detached-method-mutation",
                ["replacement:first:function", "original:second:receiver"],
            )

    def test_semantic_local_promotion_applies_inside_nested_closures(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-nested-local-promotion-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "nested-local-promotion.luau"
            source.write_text(
                """local function outer(factory)
    local function inner()
        local result
        result = factory()
        return result
    end
    return inner()
end
return outer(function()
    return 73
end)
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertEqual(artifact["metrics"].get("semantic_locals_promoted"), 1)
            self.assertNotRegex(rewritten, r"(?m)^\s*local result\s*$")
            self.assertRegex(
                rewritten,
                r"(?s)local function inner\(\).*?local result\s*=\s*factory\(\).*?return result",
            )
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "nested-local-promotion",
                [73],
            )

    def test_initialized_function_locals_become_idiomatic_without_changing_outer_binding_resolution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-initialized-function-local-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "initialized-function-local.luau"
            source.write_text(
                """local worker = function(value)
    return value * 2
end

local observed
local shadowed = "outer"
do
    local shadowed = function()
        return shadowed
    end
    observed = shadowed()
end

return worker(21), observed
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact["metrics"].get("function_locals_promoted", 0), 1)
            self.assertRegex(rewritten, r"(?m)^local function worker\(value\)$")
            self.assertRegex(rewritten, r"(?m)^\s*local shadowed = function\(\)$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "initialized-function-local",
                [42, "outer"],
            )

    def test_residual_binding_renamer_uses_ast_identity_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-residual-binding-renamer-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "residual-binding-renamer.luau"
            source.write_text(
                """local local_1 = {}
local_1[1] = 3
local_1[2] = 4
local local_2 = {nil}
local_2[1] = 9
local temporary
temporary = function(value)
    return value + local_2[1]
end
local unused_alias = local_2

local function make_reader()
    local local_1 = 5
    return function()
        return local_1
    end
end

return local_1[1] + local_1[2], temporary(1), make_reader()()
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            first = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(first.returncode, 0, first.stderr)
            artifact = json.loads(first.stdout)
            renamed = artifact["source"]
            self.assertIs(artifact.get("committed"), True)
            self.assertGreaterEqual(artifact.get("renamed", 0), 3)
            self.assertGreaterEqual(
                artifact.get("unused_declarations_removed", 0)
                + artifact.get("lexical_alias_versions_eliminated", 0),
                1,
            )
            self.assertGreaterEqual(artifact.get("roles", {}).get("registers", 0), 1)
            self.assertGreaterEqual(artifact.get("roles", {}).get("mutable_cells", 0), 1)
            self.assertGreaterEqual(artifact.get("roles", {}).get("callbacks", 0), 1)
            self.assertNotRegex(renamed, r"\b(?:local|function)_\d+\b|\btemporary\b")

            renamed_path = root / "residual-binding-renamer-rewritten.luau"
            renamed_path.write_text(renamed, encoding="utf-8")
            second = run_command([str(harness), str(renamed_path), "--rename-only"], timeout=15)
            self.assertEqual(second.returncode, 0, second.stderr)
            second_artifact = json.loads(second.stdout)
            self.assertIs(second_artifact.get("committed"), True)
            self.assertIs(second_artifact.get("changed"), False)
            self.assertEqual(second_artifact.get("source"), renamed)
            self.assert_runtime_equivalent_rewrite(
                source,
                renamed,
                root,
                "residual-binding-renamer",
                [7, 10, 5],
            )

    def test_residual_binding_renamer_recovers_ast_proven_semantic_roles(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-semantic-binding-renamer-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "semantic-binding-renamer.luau"
            source.write_text(
                """local player = {
    Character = {
        Position = {Magnitude = 8, X = 42},
    },
}

function player.Character:FindFirstChild(name)
    assert(name == "HumanoidRootPart")
    return self
end

local players = {11, 22}
local local_1, local_2, local_3, local_4, local_5, local_6, local_7
local_1 = player.Character
local_2 = local_1:FindFirstChild("HumanoidRootPart")
local_3 = local_2.Position
local_4 = local_3.Magnitude > 5
local_5 = function(value)
    return value
end
local_6 = {local_3.X, 1, 2}
local_7 = players

if local_4 then
    return local_5(local_6[1]), local_7[2]
end
return 0
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            renamed = artifact["source"]
            self.assertIs(artifact.get("committed"), True)
            self.assertGreaterEqual(artifact.get("semantic_role_names", 0), 6)
            self.assertGreaterEqual(artifact.get("lexical_alias_versions_eliminated", 0), 1)
            self.assertGreaterEqual(artifact.get("roles", {}).get("semantic_values", 0), 5)
            self.assertGreaterEqual(artifact.get("roles", {}).get("callbacks", 0), 1)
            self.assertRegex(renamed, r"(?m)^character\s*=\s*player\.Character$")
            self.assertRegex(renamed, r'(?m)^humanoid_root_part\s*=\s*character:FindFirstChild\("HumanoidRootPart"\)$')
            self.assertRegex(renamed, r"(?m)^position\s*=\s*humanoid_root_part\.Position$")
            self.assertRegex(renamed, r"(?m)^condition\s*=\s*position\.Magnitude > 5$")
            self.assertRegex(renamed, r"(?m)^callback_1\s*=\s*function\(value\)$")
            self.assertRegex(renamed, r"(?m)^values\s*=\s*\{position\.X, 1, 2\}$")
            self.assertNotRegex(renamed, r"(?m)^registers_\d+\s*=\s*\{position\.X, 1, 2\}$")
            self.assertNotRegex(renamed, r"(?m)^players_2\s*=\s*players$")
            self.assertRegex(renamed, r"return callback_1\(values\[1\]\), players\[2\]")
            self.assertNotRegex(renamed, r"\blocal_\d+\b|\bvm_(?:value|temporary)_\d+\b")
            self.assert_runtime_equivalent_rewrite(
                source,
                renamed,
                root,
                "semantic-binding-renamer",
                [42, 22],
            )

    def test_generated_callbacks_receive_purpose_names_from_their_destinations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-callback-purpose-renamer-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "callback-purpose-renamer.luau"
            source.write_text(
                """local callback_1 = function(delta_time)
    print(delta_time)
end
local callback_2 = function()
    return 42
end
local callback_3 = function(...)
    return ...
end
render_stepped_signal:Connect(callback_1)
pcall(callback_2)
remote_event.FireServer = callback_3
""",
                encoding="utf-8",
            )

            result = run_command(
                [str(self.readable_rewriter_harness()), str(source), "--callback-only"],
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            renamed = artifact["source"]
            self.assertIs(artifact.get("committed"), True)
            self.assertIn("local on_render_stepped = function(delta_time)", renamed)
            self.assertIn("pcall(protected_action)", renamed)
            self.assertIn("remote_event.FireServer = fire_server_hook", renamed)
            self.assertNotRegex(renamed, r"\bcallback_[123]\b")

    def test_post_spill_state_fields_receive_proven_callback_purpose_names(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-state-field-purpose-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "state-field-purpose.luau"
            source.write_text(
                """local script_state = {}
script_state.callback_1 = function() end
script_state.event_handler_2 = function() end
script_state.callback_3 = function() end
script_state.callback_4 = function() end
script_state.event_handler_5 = function() end
script_state.callback_6 = function() end
script_state.callback_7 = function() end
script_state.callback_8 = function() end
script_state.callback_9 = function() end
script_state.callback_10 = function() end
script_state.callback_11 = function() end

render_stepped_signal:Connect(script_state.callback_1)
changed_signal:Once(script_state.event_handler_2)
pcall(script_state.callback_3)
xpcall(script_state.callback_4, script_state.event_handler_5)
task.spawn(script_state.callback_6)
task.defer(script_state.callback_7)
task.delay(0, script_state.callback_8)
remote_event.FireServer = script_state.callback_9
hookfunction(remote_event.FireClient, script_state.callback_10)
hookmetamethod(remote_event, "__namecall", script_state.callback_11)
""",
                encoding="utf-8",
            )

            artifact = self.refine_state_fields(source)
            refined = artifact["source"]
            self.assertIs(artifact.get("parse_succeeded"), True)
            self.assertIs(artifact.get("compile_attempted"), True)
            self.assertIs(artifact.get("candidate_compiled"), True)
            self.assertIs(artifact.get("committed"), True)
            self.assertEqual(artifact.get("generated_callback_fields_found"), 11)
            self.assertEqual(artifact.get("fields_proposed"), 11)
            self.assertEqual(artifact.get("fields_renamed"), 11)
            self.assertEqual(artifact.get("references_proposed"), 22)
            self.assertEqual(artifact.get("references_renamed"), 22)
            self.assertEqual(artifact.get("name_collisions_detected"), 1)
            self.assertEqual(artifact.get("name_collisions_avoided"), 1)
            for expected in (
                "script_state.on_render_stepped",
                "script_state.on_changed",
                "script_state.protected_action",
                "script_state.protected_action_2",
                "script_state.error_handler",
                "script_state.background_task",
                "script_state.deferred_task",
                "script_state.delayed_task",
                "script_state.fire_server_hook",
                "script_state.fire_client_hook",
                "script_state.__namecall_hook",
            ):
                self.assertIn(expected, refined)
            self.assertNotRegex(refined, r"script_state\.(?:callback|event_handler)_\d+")

    def test_state_field_refiner_accepts_actual_register_spill_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-state-field-spill-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "state-field-spill.luau"
            source.write_text(
                """do
    local callback_1 = function(delta_time)
        print(delta_time)
    end
    render_stepped_signal:Connect(callback_1)
end
do
    local callback_1 = function()
        return 42
    end
    pcall(callback_1)
end
""",
                encoding="utf-8",
            )

            artifact = self.refine_state_fields(source, spill=True)
            refined = artifact["source"]
            self.assertIs(artifact.get("spill_applied"), True)
            self.assertEqual(artifact.get("bindings_spilled"), 2)
            self.assertIs(artifact.get("committed"), True)
            self.assertEqual(artifact.get("fields_renamed"), 2)
            self.assertIn("local script_state = {}", refined)
            self.assertIn("script_state.on_render_stepped = function(delta_time)", refined)
            self.assertIn("render_stepped_signal:Connect(script_state.on_render_stepped)", refined)
            self.assertIn("script_state.protected_action = function()", refined)
            self.assertIn("pcall(script_state.protected_action)", refined)
            self.assertNotRegex(refined, r"script_state\.callback_\d+(?:_\d+)*")

    def test_post_spill_state_field_refiner_rejects_unproven_or_unsafe_names(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-state-field-conservative-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "state-field-conservative.luau"
            source.write_text(
                """local script_state = {}
script_state.callback_1 = function() end
signal:Connect(script_state.callback_1)
pcall(script_state.callback_1)
script_state.callback_2 = 1
pcall(script_state.callback_2)
script_state.callback_3 = function() end
local retained_callback = script_state.callback_3

local script_state_2 = {}
script_state_2.callback_4 = function() end
consume(script_state_2)
pcall(script_state_2.callback_4)

local script_state_3 = {}
script_state_3.protected_action = function() end
script_state_3.callback_5 = function() end
pcall(script_state_3.callback_5)
""",
                encoding="utf-8",
            )

            artifact = self.refine_state_fields(source)
            refined = artifact["source"]
            self.assertIs(artifact.get("committed"), True)
            self.assertEqual(artifact.get("generated_callback_fields_found"), 5)
            self.assertEqual(artifact.get("fields_renamed"), 1)
            self.assertEqual(artifact.get("ambiguous_fields"), 1)
            self.assertEqual(artifact.get("unproven_fields"), 2)
            self.assertEqual(artifact.get("unsafe_state_tables"), 1)
            self.assertEqual(artifact.get("unsafe_fields"), 1)
            self.assertEqual(artifact.get("name_collisions_detected"), 1)
            self.assertEqual(artifact.get("name_collisions_avoided"), 1)
            for unchanged in (
                "script_state.callback_1",
                "script_state.callback_2",
                "script_state.callback_3",
                "script_state_2.callback_4",
            ):
                self.assertIn(unchanged, refined)
            self.assertIn("pcall(script_state_3.protected_action_2)", refined)
            self.assertNotIn("script_state_3.callback_5", refined)

    def test_post_spill_state_field_refinement_preserves_runtime_behavior(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-state-field-equivalence-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "state-field-equivalence.luau"
            source.write_text(
                """local script_state = {}
local signal = {callback = nil}
function signal:Connect(callback)
    self.callback = callback
end

script_state.callback_1 = function(value)
    return value + 1
end
signal:Connect(script_state.callback_1)

script_state.callback_2 = function()
    return 17
end
local ok, protected_result = pcall(script_state.callback_2)

local target = {}
script_state.event_handler_3 = function(value)
    return value * 2
end
target.Invoke = script_state.event_handler_3

return signal.callback(4), ok, protected_result, target.Invoke(6)
""",
                encoding="utf-8",
            )

            artifact = self.refine_state_fields(source)
            self.assertIs(artifact.get("committed"), True)
            self.assertEqual(artifact.get("fields_renamed"), 3)
            self.assertNotRegex(artifact["source"], r"script_state\.(?:callback|event_handler)_\d+")
            self.assert_runtime_equivalent_rewrite(
                source,
                artifact["source"],
                root,
                "state-field-equivalence",
                [5, True, 17, 12],
            )

    def test_residual_binding_roles_reject_mixed_lifetimes_and_truthiness_guesses(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-conservative-binding-renamer-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "conservative-binding-renamer.luau"
            source.write_text(
                """local object = {Name = "object"}
local local_1, local_2, local_3, local_4, local_5, local_6, local_7

local_1 = function(value)
    return value + 1
end
local first = local_1(2)
local_1 = {Name = "table"}

local_2 = object
local truthy_name = "missing"
if local_2 then
    truthy_name = local_2.Name
end

local_3, local_4 = pcall(function()
    return object
end)
local payload_name = local_4 and local_4.Name or "missing"

local_5 = {}
local_5[1] = 7
local_5[2] = 8

local_6 = {}
local_6[1] = 9
local_6 = object

return first, local_1.Name, truthy_name, local_3, payload_name, local_5[1] + local_5[2], local_6.Name
""",
                encoding="utf-8",
            )

            harness = self.readable_rewriter_harness()
            result = run_command([str(harness), str(source), "--rename-only"], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            artifact = json.loads(result.stdout)
            renamed = artifact["source"]
            self.assertIs(artifact.get("committed"), True)
            self.assertGreaterEqual(artifact.get("unused_declarations_removed", 0), 1)
            self.assertEqual(artifact.get("roles", {}).get("callbacks"), 0)
            self.assertEqual(artifact.get("roles", {}).get("registers"), 1)
            self.assertNotRegex(renamed, r"(?m)^condition(?:_\d+)?\s*=\s*object$")
            self.assertNotRegex(renamed, r"(?m)^callback_\d+\s*=\s*function\(value\)$")
            self.assertRegex(renamed, r"(?m)^registers(?:_\d+)?\s*=\s*\{\}$")
            self.assertNotRegex(renamed, r"(?m)^registers_\d+\s*=\s*object$")
            self.assert_runtime_equivalent_rewrite(
                source,
                renamed,
                root,
                "conservative-binding-renamer",
                [3, "table", "object", True, "object", 15, "object"],
            )

    def test_single_allocation_register_capture_unboxes_local_1(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-register-capture-cell-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "register-capture-cell.luau"
            source.write_text(
                """local local_1
local_1 = {nil}
local_1[1] = 73
local closure
closure = (function(upvalue_1)
    return function()
        return upvalue_1[1]
    end
end)(local_1)

return closure(), local_1[1]
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]

            with self.subTest(check="single_allocation_unboxed"):
                self.assertEqual(
                    artifact["metrics"].get("captured_cells_unboxed", 0)
                    + artifact["metrics"].get("stable_capture_cells_scalarized", 0),
                    1,
                )
                self.assertNotIn("{nil}", rewritten)
                self.assertNotRegex(rewritten, r"\blocal_1\s*\[\s*1\s*\]")

            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "register-capture-cell",
                [73, 73],
            )

    def test_dead_indexed_cell_capture_factory_is_removed_only_before_first_observation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-dead-indexed-capture-factory-") as temporary:
            root = pathlib.Path(temporary)
            dead_source = root / "dead-indexed-capture-factory.luau"
            dead_source.write_text(
                """local cell_1, source_cell
cell_1 = {nil}
source_cell = {nil}
source_cell[1] = 41
cell_1[1] = (function(captured)
    return function()
        return captured[1] + 1
    end
end)(source_cell)
cell_1 = {nil}
cell_1[1] = 73
return cell_1[1]
""",
                encoding="utf-8",
            )

            _, dead_artifact, _ = self.rewrite_fixture(dead_source)
            dead_rewritten = dead_artifact["source"]
            self.assertGreaterEqual(dead_artifact["metrics"].get("dead_capture_factories_removed", 0), 1)
            self.assertNotIn("captured[1] + 1", dead_rewritten)
            self.assert_runtime_equivalent_rewrite(
                dead_source,
                dead_rewritten,
                root,
                "dead-indexed-capture-factory",
                [73],
            )

            observed_source = root / "observed-indexed-capture-factory.luau"
            observed_source.write_text(
                """local cell_1, source_cell
cell_1 = {nil}
source_cell = {nil}
source_cell[1] = 41
cell_1[1] = (function(captured)
    return function()
        return captured[1] + 1
    end
end)(source_cell)
local observed = cell_1[1]()
cell_1 = {nil}
cell_1[1] = 73
return observed, cell_1[1]
""",
                encoding="utf-8",
            )

            _, observed_artifact, _ = self.rewrite_fixture(observed_source)
            observed_rewritten = observed_artifact["source"]
            self.assertIn("+ 1", observed_rewritten)
            self.assert_runtime_equivalent_rewrite(
                observed_source,
                observed_rewritten,
                root,
                "observed-indexed-capture-factory",
                [42, 73],
            )

    def test_loop_allocated_cell_keeps_per_iteration_nil_reset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-loop-cell-reset-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "loop-cell-reset.luau"
            source.write_text(
                """local local_1
local values = {}
for index = 1, 2 do
    local_1 = {nil}
    if index == 1 then
        local_1[1] = 9
    end
    values[index] = local_1[1]
end
return values[1], values[2]
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertEqual(artifact["metrics"].get("stable_capture_cells_scalarized"), 0)
            self.assertIn("{nil}", rewritten)
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "loop-cell-reset",
                [9, None],
            )

    def test_shadowed_cell_initialization_removes_only_unobserved_pure_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-shadowed-cell-initialization-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "shadowed-cell-initialization.luau"
            source.write_text(
                """local trace = ""
local function mark()
    trace ..= "M"
    return {}
end

local cell_1
cell_1 = {nil}
cell_1[1] = {}
cell_1 = {nil}
cell_1[1] = 11

local cell_2
cell_2 = {nil}
cell_2[1] = mark()
cell_2 = {nil}
cell_2[1] = 22
return cell_1[1], cell_2[1], trace
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact["metrics"].get("unused_cell_allocations_removed", 0), 2)
            self.assertEqual(len(re.findall(r"(?m)^\s*[A-Za-z_]\w*\s*=\s*\{nil\}\s*$", rewritten)), 3)
            self.assertNotRegex(rewritten, r"(?m)^\s*[A-Za-z_]\w*\[1\]\s*=\s*\{\}\s*$")
            self.assertRegex(rewritten, r"(?m)^\s*[A-Za-z_]\w*\[1\]\s*=\s*mark\(\)\s*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "shadowed-cell-initialization",
                [11, 22, "M"],
            )

    def test_cell_reallocation_preserves_distinct_closure_snapshots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-cell-reallocation-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "cell-reallocation.luau"
            source.write_text(
                """local cell_1
cell_1 = {nil}
cell_1[1] = 1
local first
first = (function(upvalue_1)
    return function()
        return upvalue_1[1]
    end
end)(cell_1)

cell_1 = {nil}
cell_1[1] = 2
local second
second = (function(upvalue_1)
    return function()
        return upvalue_1[1]
    end
end)(cell_1)

return first(), second()
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]

            box_allocations = re.findall(
                r"(?m)^\s*(?:local\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{nil\}\s*$",
                rewritten,
            )

            def scalar_capture(closure: str) -> str | None:
                match = re.search(
                    rf"(?s)(?:local\s+)?(?:function\s+{closure}\(\)|{closure}\s*=\s*function\(\))"
                    r".*?\n\s*return\s+\(?([A-Za-z_][A-Za-z0-9_]*)\)?\s*\n\s*end",
                    rewritten,
                )
                return match.group(1) if match is not None else None

            first_scalar = scalar_capture("first")
            second_scalar = scalar_capture("second")
            boxes_preserved = len(box_allocations) >= 2
            scalar_generations_split = (
                first_scalar is not None
                and second_scalar is not None
                and first_scalar != second_scalar
            )
            with self.subTest(check="distinct_representations"):
                self.assertTrue(
                    boxes_preserved or scalar_generations_split,
                    "cell reallocations collapsed into one closure-visible generation:\n" + rewritten,
                )

            with self.subTest(check="runtime_equivalence"):
                self.assert_runtime_equivalent_rewrite(
                    source,
                    rewritten,
                    root,
                    "cell-reallocation",
                    [1, 2],
                )

    def test_reused_register_stable_cell_segments_scalarize_independently(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-stable-cell-segments-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "stable-cell-segments.luau"
            source.write_text(
                """local trace = ""
local function seed(label, value)
    trace ..= label
    return value
end

local local_1
local_1 = {nil}
local_1[1] = seed("A", 11)
local first = local_1[1]

local_1 = {nil}
local_1[1] = seed("B", 22)
local second = local_1[1]

return first, second, trace
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]

            with self.subTest(check="each_generation_scalarized"):
                self.assertNotIn("{nil}", rewritten)
                self.assertNotRegex(rewritten, r"\b(?:local|registers)_\d+\s*\[\s*1\s*\]")

            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "stable-cell-segments",
                [11, 22, "AB"],
            )

    def test_reused_register_mutable_cell_segments_become_distinct_lexical_upvalues(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-mutable-cell-segments-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "mutable-cell-segments.luau"
            source.write_text(
                """local local_1
local_1 = {nil}
local_1[1] = 10
local increment
increment = (function(upvalue_1)
    return function(amount)
        upvalue_1[1] += amount
        return upvalue_1[1]
    end
end)(local_1)
local first = increment(2)

local_1 = {nil}
local_1[1] = 40
local decrement
decrement = (function(upvalue_2)
    return function(amount)
        upvalue_2[1] -= amount
        return upvalue_2[1]
    end
end)(local_1)

return first, increment(3), decrement(5), decrement(1)
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]

            with self.subTest(check="boxes_replaced_by_lexical_upvalues"):
                self.assertNotIn("{nil}", rewritten)
                self.assertNotRegex(rewritten, r"[A-Za-z_][A-Za-z0-9_]*\s*\[\s*1\s*\]")
                updates = re.findall(
                    r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*([+-])=\s*(?:amount|argument_\d+)\s*$",
                    rewritten,
                )
                self.assertEqual({operator for _, operator in updates}, {"+", "-"})
                self.assertEqual(len({target for target, _ in updates}), 2)

            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "mutable-cell-segments",
                [12, 15, 35, 34],
            )

    def test_reused_register_cell_segments_reject_identity_escape_and_dynamic_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-unsafe-cell-segments-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "unsafe-cell-segments.luau"
            source.write_text(
                """local escaped_box
local function retain(box)
    escaped_box = box
    return box[1]
end

local local_1
local_1 = {nil}
local_1[1] = 7
local escaped_value = retain(local_1)

local_1 = {nil}
local slot = 1
local_1[slot] = 19
local dynamic_value = local_1[slot]

local_1 = {nil}
local_1[1] = 23
local safe_value = local_1[1]

return escaped_value, dynamic_value, safe_value, escaped_box[1], type(escaped_box)
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]

            with self.subTest(check="unsafe_generations_remain_boxed"):
                allocations = re.findall(
                    r"(?m)^\s*(?:local\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{nil\}\s*$",
                    rewritten,
                )
                self.assertEqual(len(allocations), 2)
                self.assertRegex(rewritten, r"\[\s*slot\s*\]")
                self.assertRegex(rewritten, r"escaped_box\s*=\s*[A-Za-z_][A-Za-z0-9_]*")

            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "unsafe-cell-segments",
                [7, 19, 23, 7, "table"],
            )

    def test_capture_factory_lowering_snapshots_before_source_reassignment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-capture-snapshot-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "capture-snapshot.luau"
            source.write_text(
                """local source_value = { value = 11 }
local closure
closure = (function(upvalue_1)
    return function()
        return upvalue_1.value
    end
end)(source_value)
source_value = { value = 22 }
return closure(), source_value.value
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "capture-snapshot",
                [11, 22],
            )
            self.assert_capture_factory_lowered(rewritten)
            snapshot = re.search(
                r"(?m)^\s*local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(?source_value\)?\s*$",
                rewritten,
            )
            self.assertIsNotNone(snapshot, rewritten)
            self.assertRegex(rewritten, rf"\b{re.escape(snapshot.group(1))}\.value\b")

    def test_single_use_snapshot_callbacks_receive_lexical_function_scopes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-snapshot-callback-scope-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "snapshot-callback-scope.luau"
            source.write_text(
                """local trace = ""
local signal = { handlers = {} }
function signal:Connect(callback)
    table.insert(self.handlers, callback)
end

local function safe(captured)
    local local_1
    do
        local snapshot_1 = captured
        local_1 = function(value)
            snapshot_1(value)
        end
    end
    signal:Connect(local_1)
    captured = function()
        trace ..= "wrong"
    end
    local_1 = "later"
    return local_1
end

local function guarded(captured)
    local local_2
    local observed_during_connect
    local function observe()
        return local_2
    end
    local receiver = {}
    function receiver:Connect(callback)
        observed_during_connect = observe()
        self.callback = callback
    end
    do
        local snapshot_2 = captured
        local_2 = function(value)
            snapshot_2(value)
        end
    end
    receiver:Connect(local_2)
    return observed_during_connect == local_2
end

local safe_result = safe(function(value)
    trace ..= value
end)
signal.handlers[1]("A")
local guarded_result = guarded(function(value)
    trace ..= value
end)
return safe_result, trace, guarded_result
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact["metrics"].get("callback_aliases_promoted", 0), 1)
            self.assertRegex(
                rewritten,
                r"(?s)do\s+local snapshot_1\s*=\s*captured\s+"
                r"local function event_handler\(value\).*?signal:Connect\(event_handler\)\s+end",
            )
            self.assertRegex(rewritten, r"(?m)^\s*(?:callback|vm_value|registers)_\d+\s*=\s*function\(value\)\s*$")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "snapshot-callback-scope",
                ["later", "A", True],
            )

    def test_capture_factory_lowering_preserves_ordered_multireturn_arguments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-capture-multireturn-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "capture-multireturn.luau"
            source.write_text(
                """local trace = ""
local function capture(label, ...)
    trace ..= label
    return ...
end
local closure
closure = (function(upvalue_1, upvalue_2, upvalue_3)
    return function()
        return upvalue_1, upvalue_2, upvalue_3, trace
    end
end)(capture("A", 10, 99), capture("B", 20, 30))
return closure()
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "capture-multireturn",
                [10, 20, 30, "AB"],
            )
            self.assert_capture_factory_lowered(rewritten)
            identifier = r"[A-Za-z_][A-Za-z0-9_]*"
            self.assertRegex(
                rewritten,
                rf'''(?m)^\s*local\s+{identifier}\s*,\s*{identifier}\s*,\s*{identifier}\s*=\s*'''
                rf'''capture\("A",\s*10,\s*99\),\s*capture\("B",\s*20,\s*30\)\s*$''',
            )

    def test_capture_factory_lowering_avoids_identifier_collisions_and_shadowing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-capture-collision-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "capture-collision.luau"
            source.write_text(
                """local upvalue_1 = "source"
local upvalue_1_snapshot = "occupied"
local closure
closure = (function(upvalue_1)
    return function(argument)
        local upvalue_1 = upvalue_1 .. "-local"
        return upvalue_1, argument
    end
end)(upvalue_1)
upvalue_1 = "reassigned"
local closure_value, closure_argument = closure("inner")
return closure_value, closure_argument, upvalue_1, upvalue_1_snapshot
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "capture-collision",
                ["source-local", "inner", "reassigned", "occupied"],
            )
            self.assert_capture_factory_lowered(rewritten)
            snapshot = re.search(
                r"(?m)^\s*local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(?upvalue_1\)?\s*$",
                rewritten,
            )
            self.assertIsNotNone(snapshot, rewritten)
            self.assertNotIn(snapshot.group(1), {"upvalue_1", "upvalue_1_snapshot"})

    def test_private_register_slot_cleanup_preserves_observable_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-register-slot-cleanup-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "register-slot-cleanup.luau"
            source.write_text(
                """local local_38
local_38 = {}
local_38[1] = (function(_, seed) return seed end)
local_38[2] = "keep"
local_38[1] = "final"
local local_1 = local_38[1]

local_38[3] = "before"
local function observe()
    return local_38[3]
end
local observed = observe()
local_38[3] = "after"

return local_1, local_38[2], observed, local_38[3]
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertNotIn("(function(_, seed) return seed end)", rewritten)
            self.assertRegex(
                rewritten,
                r'(?m)^\s*(?:local\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*"before"\s*$',
            )
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "register-slot-cleanup",
                ["final", "keep", "before", "after"],
            )

    def test_contiguous_result_packs_lower_to_multiple_assignment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-result-pack-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "result-pack.luau"
            source.write_text(
                """local function many()
    return 11, nil, 29
end

local local_38 = {many()}
local local_1 = local_38[1]
local local_2 = local_38[2]
local local_3 = local_38[3]

local local_39 = {many()}
local local_4 = local_39[1]
local local_5 = local_39[2]
local observed_length = #local_39

return local_1, local_2, local_3, local_4, local_5, observed_length
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact["metrics"].get("result_packs_collapsed", 0), 1)
            self.assertRegex(
                rewritten,
                r"(?m)^\s*local\s+[A-Za-z_]\w*\s*,\s*[A-Za-z_]\w*\s*,\s*[A-Za-z_]\w*\s*=\s*many\(\)\s*$",
            )
            self.assertNotRegex(rewritten, r"\blocal_38\s*\[")
            self.assertEqual(len(re.findall(r"\{\s*many\(\)\s*\}", rewritten)), 1)
            self.assertRegex(rewritten, r"\b(?:local|registers)_\d+\s*\[\s*1\s*\]")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "result-pack",
                [11, None, 29, 11, None, 3],
            )

    def test_sparse_result_packs_preserve_nil_slots_and_reject_table_escape(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-sparse-result-pack-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "sparse-result-pack.luau"
            source.write_text(
                '''local trace = ""
local function many()
    trace ..= "C"
    return 11, nil, 29, 41
end

local local_38 = {many()}
trace ..= "X"
local local_3 = local_38[3]
local local_1 = local_38[1]

local local_39 = {many()}
local escaped = local_39
local dynamic = local_39[1]

return local_1, local_3, escaped[4], dynamic, type(escaped), trace
''',
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact["metrics"].get("result_packs_collapsed", 0), 1)
            self.assertRegex(
                rewritten,
                r"(?m)^\s*local\s+call_result(?:_\d+)?\s*,\s*call_result_\d+\s*,\s*"
                r"call_result_\d+\s*=\s*many\(\)\s*$",
            )
            self.assertEqual(len(re.findall(r"\{\s*many\(\)\s*\}", rewritten)), 1)
            self.assertRegex(
                rewritten,
                r"(?m)^\s*(?:local\s+)?escaped\s*=\s*(?:[A-Za-z_]\w*|\{\s*many\(\)\s*\})\s*$",
            )
            self.assertRegex(rewritten, r"\bescaped\s*\[\s*(?:1|4)\s*\]")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "sparse-result-pack",
                [11, 29, 41, 11, "table", "CXC"],
            )

    def test_result_packs_collapse_into_private_constant_lvalues_without_new_locals(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-lvalue-result-pack-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "lvalue-result-pack.luau"
            filler = ", ".join(f"keep_{index}" for index in range(1, 185))
            source.write_text(
                f"""local function many()
    return 11, nil, 29, 41
end

local {filler}
local local_38
local local_1, local_2, local_3
local_38 = {{}}
do
    local_38[9] = {{many()}}
end
local_1 = local_38[9][1]
local_38[2] = local_38[9][3]
local_2 = local_38[9][2]
local_3 = local_38[9][4]

return local_1, local_2, local_38[2], local_3
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source, timeout=30)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact["metrics"].get("result_packs_collapsed", 0), 1)
            self.assertNotRegex(rewritten, r"\{\s*many\(\)\s*\}")
            self.assertNotRegex(rewritten, r"\[\s*9\s*\]\s*\[\s*[1-4]\s*\]")
            self.assertRegex(
                rewritten,
                r"(?m)^\s*[A-Za-z_]\w*\s*,\s*[A-Za-z_]\w*\s*,\s*"
                r"[A-Za-z_]\w*(?:\s*\[\s*2\s*\])?\s*,\s*[A-Za-z_]\w*\s*=\s*many\(\)\s*$",
            )
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "lvalue-result-pack",
                [11, None, 29, 41],
            )

    def test_result_pack_collapse_crosses_proven_alias_and_multiassignment_kill(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-result-pack-alias-") as temporary:
            root = pathlib.Path(temporary)
            source = root / "result-pack-alias.luau"
            source.write_text(
                """local function many()
    return 11, nil, 29
end

local local_38, local_1, local_2, local_3, local_4, local_5
local_38 = {many()}
local_1 = local_38[3]
local_2 = local_1
local_3 = local_38[1]
local_4 = local_38[2]
local_5, local_38 = local_2, "replaced"

return local_3, local_4, local_1, local_2, local_5, local_38
""",
                encoding="utf-8",
            )

            _, artifact, _ = self.rewrite_fixture(source)
            rewritten = artifact["source"]
            self.assertGreaterEqual(artifact["metrics"].get("result_packs_collapsed", 0), 1)
            self.assertNotRegex(rewritten, r"\{\s*many\(\)\s*\}")
            self.assertNotRegex(rewritten, r"\blocal_38\s*\[")
            self.assert_runtime_equivalent_rewrite(
                source,
                rewritten,
                root,
                "result-pack-alias",
                [11, None, 29, 29, 29, "replaced"],
            )

    def test_traced_reconstruction_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-determinism-") as temporary:
            root = pathlib.Path(temporary)
            _, _, first_candidate = self.trace_candidate(REFERENCE_SAMPLE, root / "first")
            _, _, second_candidate = self.trace_candidate(REFERENCE_SAMPLE, root / "second")
            self.assertEqual(first_candidate.read_bytes(), second_candidate.read_bytes())
            for filename in DETERMINISTIC_RECONSTRUCTION_ARTIFACTS:
                with self.subTest(artifact=filename):
                    self.assertEqual(
                        (root / "first" / filename).read_bytes(),
                        (root / "second" / filename).read_bytes(),
                    )

    def test_reference_reconstruction_is_clean_and_compiles(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-clean-") as temporary:
            output_dir = pathlib.Path(temporary) / "output"
            result, report, candidate = self.trace_candidate(REFERENCE_SAMPLE, output_dir)
            self.assert_returncode(result, 2)
            self.assert_common_report(report)
            self.assert_clean_compilable_reconstruction(
                candidate.read_text(encoding="utf-8"),
                report,
                REFERENCE_SAMPLE.name,
            )

            runtime_result, _ = self.execute_runtime(candidate, output_dir, "candidate")
            self.assertEqual(runtime_result.returncode, 0, runtime_result.stderr)

    def test_disassemble_mode_succeeds_without_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-disassemble-") as temporary:
            output_dir = pathlib.Path(temporary) / "output"
            result, report = invoke(REFERENCE_SAMPLE, output_dir, mode="disassemble")
            self.assert_returncode(result, 0)
            self.assert_common_report(report)
            self.assertEqual(report.get("adapter"), "wearedevs-v1")
            self.assertEqual(report.get("status"), "disassembled")
            self.assertEqual(report.get("mode"), "disassemble")

            documents, _ = self.load_json_artifacts(output_dir)
            self.assert_no_recovered_source(output_dir, report, documents)
            disassembly = (output_dir / "vm_disassembly.txt").read_text(encoding="utf-8")
            self.assertTrue(disassembly.startswith("Alex native WeAreDevs v1 structural disassembly\n"))
            self.assertRegex(disassembly, r"(?m)^state -?\d+")
            self.assertTrue(documents["cfg.json"].get("nodes"))

    def test_malformed_recognized_envelope_has_decode_diagnostic(self) -> None:
        source = REFERENCE_SAMPLE.read_text(encoding="utf-8")
        malformed, replacements = re.subn(
            r"return\(function\(\.\.\.\)local\s+([A-Za-z_][A-Za-z0-9_]*)=",
            r"return(function(...)\1=",
            source,
            count=1,
        )
        self.assertEqual(replacements, 1)

        with tempfile.TemporaryDirectory(prefix="alex-native-envelope-") as temporary:
            root = pathlib.Path(temporary)
            input_path = root / "malformed-envelope.luau"
            input_path.write_text(malformed, encoding="utf-8")
            output_dir = root / "output"
            result, report = invoke(input_path, output_dir)
            self.assert_returncode(result, 2)
            self.assert_common_report(report)
            self.assertEqual(report.get("adapter"), "wearedevs-v1")
            self.assertEqual(report.get("status"), "blocked")
            self.assertIs(report.get("passes", [])[1].get("ok"), True)
            self.assert_diagnostic(
                report,
                code="native_analysis_failed",
                stage="decode",
                message="initial encoded table was not found",
            )
            documents, _ = self.load_json_artifacts(output_dir)
            self.assert_no_recovered_source(output_dir, report, documents)

    def test_bannerless_reformatted_envelope_is_detected_structurally(self) -> None:
        source = REFERENCE_SAMPLE.read_text(encoding="utf-8")
        bannerless, banner_replacements = re.subn(
            r"^\s*--\[\[.*?\]\]\s*",
            "",
            source,
            count=1,
        )
        self.assertEqual(banner_replacements, 1)
        reformatted, wrapper_replacements = re.subn(
            r"^return\(function\(\.\.\.\)local\s+",
            "return ( function ( ... )\nlocal ",
            bannerless,
            count=1,
        )
        self.assertEqual(wrapper_replacements, 1)

        with tempfile.TemporaryDirectory(prefix="alex-native-structural-envelope-") as temporary:
            root = pathlib.Path(temporary)
            input_path = root / "bannerless-reformatted.luau"
            input_path.write_text(reformatted, encoding="utf-8")
            output_dir = root / "output"
            result, report = invoke(input_path, output_dir, mode="disassemble")
            self.assert_returncode(result, 0)
            self.assert_common_report(report)
            self.assertEqual(report.get("adapter"), "wearedevs-v1")
            self.assertEqual(report.get("status"), "disassembled")
            self.assertGreaterEqual(report.get("detection", {}).get("confidence", 0), 0.75)
            evidence = report.get("detection", {}).get("evidence", {})
            self.assertIs(evidence.get("header"), False)
            self.assertIs(evidence.get("vararg_iife"), True)
            self.assertIs(evidence.get("flattened_dispatcher"), True)
            self.assertIs(evidence.get("executor_environment_tail"), True)
            passes = {item.get("stage"): item for item in report.get("passes", [])}
            self.assertIs(passes.get("detect", {}).get("ok"), True)
            self.assertIs(passes.get("decode", {}).get("ok"), True)

    def test_corrupt_alphabet_has_decode_diagnostic(self) -> None:
        source = REFERENCE_SAMPLE.read_text(encoding="utf-8")
        alphabet_zero = r'["\056"]=-176517-(-176517)'
        self.assertEqual(source.count(alphabet_zero), 1)
        corrupt = source.replace(alphabet_zero, r'["\056"]=1', 1)

        with tempfile.TemporaryDirectory(prefix="alex-native-alphabet-") as temporary:
            root = pathlib.Path(temporary)
            input_path = root / "corrupt-alphabet.luau"
            input_path.write_text(corrupt, encoding="utf-8")
            output_dir = root / "output"
            result, report = invoke(input_path, output_dir)
            self.assert_returncode(result, 2)
            self.assert_common_report(report)
            self.assertEqual(report.get("adapter"), "wearedevs-v1")
            self.assertEqual(report.get("status"), "blocked")
            self.assert_diagnostic(
                report,
                code="native_analysis_failed",
                stage="decode",
                message="custom 64-character alphabet was not found",
            )
            documents, _ = self.load_json_artifacts(output_dir)
            self.assert_no_recovered_source(output_dir, report, documents)

    def test_oversize_input_has_structured_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-oversize-") as temporary:
            root = pathlib.Path(temporary)
            input_path = root / "oversize.luau"
            input_path.write_bytes(b" " * (MAX_INPUT_BYTES + 1))
            output_dir = root / "output"
            result, report = invoke(input_path, output_dir)
            self.assert_returncode(result, 2)
            self.assert_common_report(report)
            self.assertEqual(report.get("status"), "blocked")
            self.assertEqual(report.get("input", {}).get("bytes"), MAX_INPUT_BYTES + 1)
            self.assert_diagnostic(
                report,
                code="source_too_large",
                stage="input",
                message="1.5 MiB limit",
            )
            documents, _ = self.load_json_artifacts(output_dir)
            self.assert_no_recovered_source(output_dir, report, documents)

    def test_parse_errors_have_locations_and_no_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-parse-") as temporary:
            root = pathlib.Path(temporary)
            input_path = root / "parse-error.luau"
            input_path.write_text("local function broken(\n    return )\nend\n", encoding="utf-8")
            output_dir = root / "output"
            result, report = invoke(input_path, output_dir)
            self.assert_returncode(result, 2)
            self.assert_common_report(report)
            self.assertEqual(report.get("status"), "blocked")
            diagnostic = self.assert_diagnostic(
                report,
                code="luau_parse_error",
                stage="parse",
            )
            self.assertIsInstance(diagnostic.get("message"), str)
            self.assertGreaterEqual(diagnostic.get("line", 0), 1)
            self.assertGreaterEqual(diagnostic.get("column", 0), 1)
            documents, _ = self.load_json_artifacts(output_dir)
            self.assert_no_recovered_source(output_dir, report, documents)

    def test_unrecognized_family_is_rejected_without_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alex-native-family-") as temporary:
            root = pathlib.Path(temporary)
            input_path = root / "plain.luau"
            input_path.write_text("local value = 21 * 2\nreturn value\n", encoding="utf-8")
            output_dir = root / "output"
            result, report = invoke(input_path, output_dir)
            self.assert_returncode(result, 4)
            self.assert_common_report(report)
            self.assertEqual(report.get("adapter"), "unsupported")
            self.assertEqual(report.get("status"), "blocked")
            self.assert_diagnostic(
                report,
                code="unsupported_family",
                stage="detect",
                message="WeAreDevs v1 structural envelope",
            )
            documents, _ = self.load_json_artifacts(output_dir)
            self.assert_no_recovered_source(output_dir, report, documents)


if __name__ == "__main__":
    unittest.main(verbosity=2)
