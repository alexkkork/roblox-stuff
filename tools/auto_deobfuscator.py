#!/usr/bin/env python3
"""Offline-first automatic Luau deobfuscation orchestrator.

The tool combines conservative source-visible transforms with the local Roblox
runtime's capture hooks. Exact recovery is provenance-gated: behavior, traces,
and decompiler output can produce a reconstruction, but never exact source.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from local_luau_deobfuscator import deobfuscate_text  # noqa: E402
from wearedevs_deobfuscator import deobfuscate_static_only as deobfuscate_wearedevs_static  # noqa: E402


SOURCE_MARKERS = (
    "local ", "function", "return ", "game:", "game.", "Instance.new",
    "WaitForChild", "getgenv", "task.",
)
EXACT_CAPTURE_KINDS = {
    "loadstring_input", "captured_script", "original_luau_exact",
    "httpget", "captured_httpget",
}
RECONSTRUCTION_NAMES = (
    "reconstructed.luau", "deobfuscated.luau", "luraph_decompiled_fallback.lua",
    "moonveil_v2_devirtualized.lua", "wearedevs_deobfuscated.lua", "deobfuscated.luau",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return value or "script"


def now_stamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S") + f"_{time.time_ns() % 1_000_000_000:09d}"


def looks_like_source(data: bytes) -> bool:
    if not data or b"\0" in data[:4096]:
        return False
    text = data.decode("utf-8", errors="replace")
    printable = sum(ch in "\t\n\r" or 32 <= ord(ch) < 127 for ch in text)
    if printable / max(1, len(text)) < 0.82:
        return False
    return sum(marker in text for marker in SOURCE_MARKERS) >= 1


def classify_bytes(data: bytes, filename: str = "") -> str:
    lower = filename.lower()
    if lower.endswith(".json"):
        return "json"
    if lower.endswith(".jsonl"):
        return "trace"
    if data.startswith(b"LPH@"):
        return "packed_blob"
    if data.startswith(b"\x1b") or b"LUAU" in data[:32]:
        return "bytecode"
    if looks_like_source(data):
        return "luau_source"
    try:
        data.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "binary"


def detect_adapter(source: str) -> tuple[str, list[dict[str, Any]]]:
    lower = source[:250000].lower()
    scores = {
        "luraph": (
            3 * ("lph$" in lower)
            + 2 * ("luaauth" in lower)
            + ("la_script_id" in lower)
            + ("do not modify this script" in lower and "return({" in lower)
        ),
        "wynfuscate": sum(token in lower for token in ("wynfuscate", "local md=", "local md =", "keytxt_auth")),
        "moonveil": sum(token in lower for token in ("moonveil", "mv2", "ascii85", "z85")),
        "wearedevs": sum(token in lower for token in ("wearedevs.net/obfuscator", "wearedevs", "return(function(...)")),
        "alexfuscator": sum(token in lower for token in ("alexfuscator", "alexvm6:", "luauvm5:", "register vm v5")),
    }
    ranked = sorted(({"adapter": name, "score": score} for name, score in scores.items()), key=lambda item: (-item["score"], item["adapter"]))
    selected = ranked[0]["adapter"] if ranked and ranked[0]["score"] > 0 else "generic"
    return selected, ranked


@dataclass
class Artifact:
    id: str
    kind: str
    bytes: int
    path: str
    provenance: str
    parents: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    source_bearing: bool = False
    compile_verified: bool | None = None


class ArtifactGraph:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.artifact_dir = output_dir / "artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.nodes: dict[str, Artifact] = {}
        self.edges: list[dict[str, str]] = []

    def add(
        self,
        data: bytes,
        *,
        kind: str | None = None,
        provenance: str,
        parent: str | None = None,
        label: str = "",
        source_bearing: bool = False,
    ) -> tuple[Artifact, bool]:
        digest = sha256_bytes(data)
        if digest in self.nodes:
            node = self.nodes[digest]
            if parent and parent not in node.parents:
                node.parents.append(parent)
                self.edges.append({"from": parent, "to": digest, "relation": provenance})
            if label and label not in node.labels:
                node.labels.append(label)
            node.source_bearing = node.source_bearing or source_bearing
            return node, False
        actual_kind = kind or classify_bytes(data, label)
        extension = {
            "luau_source": ".luau", "json": ".json", "trace": ".jsonl",
            "text": ".txt", "packed_blob": ".bin", "bytecode": ".bin",
            "binary": ".bin",
        }.get(actual_kind, ".bin")
        path = self.artifact_dir / f"{digest[:16]}_{safe_name(actual_kind)}{extension}"
        path.write_bytes(data)
        node = Artifact(
            id=digest,
            kind=actual_kind,
            bytes=len(data),
            path=str(path.relative_to(self.output_dir)),
            provenance=provenance,
            parents=[parent] if parent else [],
            labels=[label] if label else [],
            source_bearing=source_bearing,
        )
        self.nodes[digest] = node
        if parent:
            self.edges.append({"from": parent, "to": digest, "relation": provenance})
        return node, True

    def add_file(self, path: Path, **kwargs: Any) -> tuple[Artifact, bool] | None:
        try:
            if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
                return None
            return self.add(path.read_bytes(), label=path.name, **kwargs)
        except OSError:
            return None

    def write(self) -> Path:
        path = self.output_dir / "artifact_graph.json"
        payload = {
            "version": 1,
            "nodes": [vars(node) for node in sorted(self.nodes.values(), key=lambda item: item.id)],
            "edges": self.edges,
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path


@dataclass
class Candidate:
    artifact_id: str
    text: str
    provenance: str
    exact_eligible: bool
    compile_verified: bool = False
    verification: dict[str, Any] = field(default_factory=dict)


class AutoDeobfuscator:
    def __init__(self, args: argparse.Namespace, input_path: Path, output_dir: Path):
        self.args = args
        self.input_path = input_path
        self.output_dir = output_dir
        self.graph = ArtifactGraph(output_dir)
        self.candidates: dict[str, Candidate] = {}
        self.pass_log: list[dict[str, Any]] = []
        self.runtime_runs: list[dict[str, Any]] = []
        self.adapter_runs: list[dict[str, Any]] = []
        self.errors: list[dict[str, Any]] = []
        self.input_node: Artifact | None = None
        self.adapter = "generic"
        self.adapter_scores: list[dict[str, Any]] = []
        self.started = time.monotonic()

    def log(self, stage: str, **details: Any) -> None:
        self.pass_log.append({"stage": stage, "elapsed_ms": round((time.monotonic() - self.started) * 1000), **details})
        if self.args.progress:
            print(f"[{stage}] " + " ".join(f"{key}={value}" for key, value in details.items()), file=sys.stderr, flush=True)

    def add_candidate(self, node: Artifact, text: str, provenance: str, exact_eligible: bool) -> None:
        existing = self.candidates.get(node.id)
        if existing:
            existing.exact_eligible = existing.exact_eligible or exact_eligible
            return
        self.candidates[node.id] = Candidate(node.id, text, provenance, exact_eligible)

    def verify_compile(self, candidate: Candidate) -> bool:
        if candidate.compile_verified:
            return True
        compiler = self.args.alexfuscator
        if not compiler.exists():
            candidate.verification = {"available": False, "reason": "alexfuscator_missing"}
            return False
        with tempfile.TemporaryDirectory(prefix="alex-auto-deobf-verify-") as temporary:
            root = Path(temporary)
            source = root / "candidate.luau"
            output = root / "candidate.obf.luau"
            source.write_text(candidate.text, encoding="utf-8")
            command = [
                str(compiler), str(source), "-o", str(output), "--profile", "compatibility",
                "--control-flow", "off", "--constant-protection", "off", "--vm-diversity", "off",
                "--tamper-density", "off", "--no-integrity", "--no-bytecode-trampoline",
                "--environment-binding", "portable", "--seed", "deobf-verify", "--no-watermark",
                "--diagnostics-json",
            ]
            result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            candidate.compile_verified = result.returncode == 0
            candidate.verification = {
                "available": True,
                "compiled": candidate.compile_verified,
                "exit_code": result.returncode,
            }
            if result.returncode:
                try:
                    candidate.verification["diagnostic"] = json.loads(result.stderr).get("error", {})
                except json.JSONDecodeError:
                    candidate.verification["diagnostic"] = {"code": "compile_failed"}
        node = self.graph.nodes.get(candidate.artifact_id)
        if node:
            node.compile_verified = candidate.compile_verified
        return candidate.compile_verified

    def static_pass(self, node: Artifact, text: str, pass_index: int) -> list[Artifact]:
        result = deobfuscate_text(text)
        self.log("static", pass_index=pass_index, artifact=node.id[:12], changes=len(result["changes"]), unwrapped=result["unwrapped_loadstrings"])
        if not result["changed"]:
            return []
        output = result["output"]
        source_bearing = result["unwrapped_loadstrings"] > 0
        child, created = self.graph.add(
            output.encode(), kind="luau_source", provenance="static_transform", parent=node.id,
            label=f"static-pass-{pass_index}.luau", source_bearing=source_bearing,
        )
        self.add_candidate(child, output, "decoded" if source_bearing else "statically_proven", source_bearing)
        return [child] if created else []

    def run_runtime(self, node: Artifact, text: str, pass_index: int) -> list[Artifact]:
        if not self.args.runtime.exists() or self.args.mode == "disassemble":
            return []
        run_dir = self.output_dir / "runtime" / f"pass_{pass_index:02d}_{node.id[:10]}"
        captures = run_dir / "captures"
        run_dir.mkdir(parents=True, exist_ok=True)
        source_path = run_dir / "input.luau"
        report_path = run_dir / "runtime_report.json"
        trace_path = run_dir / "compat_trace.jsonl"
        source_path.write_text(text, encoding="utf-8")
        command = [
            str(self.args.runtime), "--profile", self.args.profile, "--clock", "virtual",
            "--max-virtual-seconds", str(self.args.max_virtual_seconds), "--unsupported", "trace-nil",
            "--network-policy", self.args.network, "--timeout", str(self.args.wall_timeout),
            "--capture-min", "1", "--capture-string-hooks", "--luraph-mode", "auto",
            "--luraph-max-steps", str(self.args.instruction_budget), "--luraph-stall-steps", str(max(10000, self.args.instruction_budget // 5)),
            "--trace-compat", str(trace_path), "--report", str(report_path), "--out", str(captures),
        ]
        if self.args.scenario:
            command.extend(["--scenario", str(self.args.scenario)])
        for fixture in self.args.fixture:
            command.extend(["--fixture", fixture])
        command.append(str(source_path))
        started = time.monotonic()
        try:
            result = subprocess.run(
                command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.args.wall_timeout + 10,
            )
        except subprocess.TimeoutExpired:
            self.runtime_runs.append({"pass": pass_index, "artifact": node.id, "termination_reason": "wall_timeout", "host_timeout": True})
            self.log("runtime", pass_index=pass_index, artifact=node.id[:12], termination="wall_timeout")
            return []
        runtime_report: dict[str, Any] = {}
        if report_path.exists():
            try:
                runtime_report = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                pass
        run_summary = {
            "pass": pass_index,
            "artifact": node.id,
            "exit_code": result.returncode,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "termination_reason": runtime_report.get("termination_reason", "runtime_error" if result.returncode else "completed"),
            "report": str(report_path.relative_to(self.output_dir)) if report_path.exists() else None,
            "trace": str(trace_path.relative_to(self.output_dir)) if trace_path.exists() else None,
            "network_requirements": runtime_report.get("network_requirements", []),
        }
        self.runtime_runs.append(run_summary)
        self.log("runtime", pass_index=pass_index, artifact=node.id[:12], termination=run_summary["termination_reason"])

        discovered: list[Artifact] = []
        if captures.exists():
            for path in sorted(captures.rglob("*")):
                if not path.is_file() or path.name in {"capture_index.jsonl", "luraph_recovery_report.json"}:
                    continue
                capture_kind = path.stem.rsplit("_", 1)[0]
                exact = capture_kind in EXACT_CAPTURE_KINDS or path.name in {"original_luau_exact.lua", "captured_script.lua", "captured_httpget.lua"}
                added = self.graph.add_file(
                    path, provenance="runtime_capture", parent=node.id, source_bearing=exact,
                )
                if not added:
                    continue
                child, created = added
                if child.kind == "luau_source":
                    candidate_text = path.read_text(encoding="utf-8", errors="replace")
                    self.add_candidate(child, candidate_text, "exact" if exact else "trace_observed", exact)
                    if created:
                        discovered.append(child)
        return discovered

    def run_adapter(self, source: str) -> None:
        if self.adapter == "generic" or self.args.adapter == "generic":
            return
        adapter_dir = self.output_dir / "adapters" / self.adapter
        adapter_dir.mkdir(parents=True, exist_ok=True)
        if self.adapter == "wearedevs":
            output = []
            try:
                capture = __import__("io").StringIO()
                with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
                    adapter_report = deobfuscate_wearedevs_static(self.input_path, adapter_dir, open_output=False)
                output.append(capture.getvalue())
                self.adapter_runs.append({
                    "adapter": self.adapter,
                    "exit_code": 0,
                    "output_dir": str(adapter_dir.relative_to(self.output_dir)),
                    "final_kind": adapter_report.get("final_kind"),
                    "semantic_recovery_status": adapter_report.get("semantic_recovery_status"),
                })
            except Exception as error:
                self.adapter_runs.append({
                    "adapter": self.adapter,
                    "exit_code": 1,
                    "output_dir": str(adapter_dir.relative_to(self.output_dir)),
                    "diagnostic": f"{type(error).__name__}: {error}"[:500],
                })
            self.ingest_adapter_artifacts(adapter_dir)
            return
        command: list[str] | None = None
        native_report = adapter_dir / "native-report.json"
        if self.adapter == "luraph":
            if not self.args.deobfuscator.is_file():
                self.adapter_runs.append({
                    "adapter": self.adapter,
                    "exit_code": None,
                    "diagnostic": "native_deobfuscator_missing",
                })
                return
            command = [
                str(self.args.deobfuscator), str(self.input_path),
                "--output-dir", str(adapter_dir),
                "--mode", self.args.mode,
                "--report", str(native_report),
            ]
        elif self.adapter == "wynfuscate":
            command = [sys.executable, str(ROOT / "tools" / "wynfuscate_deobfuscator.py"), str(self.input_path), "--out-root", str(adapter_dir)]
        elif self.adapter == "moonveil":
            command = [
                sys.executable, str(ROOT / "tools" / "deobfuscate_moonveil_v2.py"), str(self.input_path),
                "--out", str(adapter_dir), "--runtime", str(self.args.runtime), "--timeout", str(self.args.wall_timeout),
                "--trace-vm-dispatch", "--capture-vm-strings",
            ]
        if not command:
            return
        try:
            result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.args.wall_timeout + 20)
            summary: dict[str, Any] = {
                "adapter": self.adapter,
                "exit_code": result.returncode,
                "output_dir": str(adapter_dir.relative_to(self.output_dir)),
            }
            if native_report.is_file():
                try:
                    native = json.loads(native_report.read_text(encoding="utf-8"))
                    summary.update({
                        "native_adapter": native.get("adapter"),
                        "native_status": native.get("status"),
                        "native_backend": native.get("backend"),
                        "coverage": native.get("coverage"),
                        "diagnostics": native.get("diagnostics", []),
                    })
                except json.JSONDecodeError:
                    summary["diagnostic"] = "native_report_invalid"
            self.adapter_runs.append(summary)
        except subprocess.TimeoutExpired:
            self.adapter_runs.append({"adapter": self.adapter, "exit_code": None, "timed_out": True})
            return
        self.ingest_adapter_artifacts(adapter_dir)

    def ingest_adapter_artifacts(self, adapter_dir: Path) -> None:
        parent = self.input_node.id if self.input_node else None
        for path in sorted(adapter_dir.rglob("*")):
            if not path.is_file():
                continue
            added = self.graph.add_file(path, provenance=f"adapter:{self.adapter}", parent=parent, source_bearing=False)
            if not added:
                continue
            node, _ = added
            if node.kind == "luau_source" and path.name in RECONSTRUCTION_NAMES:
                self.add_candidate(node, path.read_text(encoding="utf-8", errors="replace"), "inferred", False)

    def differential_verify(self, candidate: Candidate) -> dict[str, Any]:
        if not candidate.compile_verified or not self.args.runtime.exists():
            return {"attempted": False}
        verify_dir = self.output_dir / "verification" / candidate.artifact_id[:12]
        verify_dir.mkdir(parents=True, exist_ok=True)
        candidate_path = verify_dir / "candidate.luau"
        candidate_path.write_text(candidate.text, encoding="utf-8")

        def execute(label: str, path: Path) -> dict[str, Any]:
            report = verify_dir / f"{label}.json"
            captures = verify_dir / f"{label}-captures"
            command = [
                str(self.args.runtime), "--profile", self.args.profile, "--clock", "virtual", "--unsupported", "trace-nil",
                "--network-policy", self.args.network, "--timeout", str(self.args.wall_timeout),
                "--max-virtual-seconds", str(self.args.max_virtual_seconds), "--report", str(report), "--out", str(captures),
            ]
            if self.args.scenario:
                command.extend(["--scenario", str(self.args.scenario)])
            for fixture in self.args.fixture:
                command.extend(["--fixture", fixture])
            command.append(str(path))
            result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.args.wall_timeout + 10)
            payload: dict[str, Any] = {}
            if report.exists():
                try:
                    payload = json.loads(report.read_text(encoding="utf-8", errors="replace"))
                except json.JSONDecodeError:
                    pass
            scheduler = payload.get("scheduler") or {}
            scheduler_events = [
                {key: event.get(key) for key in ("kind", "frame", "time")}
                for event in scheduler.get("events", [])
            ]
            return {
                "exit_code": result.returncode,
                "stdout": payload.get("stdout", result.stdout),
                "stderr": payload.get("stderr", result.stderr),
                "termination_reason": payload.get("termination_reason"),
                "returns": payload.get("returns"),
                "errors": payload.get("errors", scheduler.get("errors")),
                "unsupported_calls": payload.get("unsupported_calls", payload.get("unsupported")),
                "scheduler_events": scheduler_events,
                "network_requirements": payload.get("network_requirements"),
            }

        try:
            original = execute("original", self.input_path)
            reconstructed = execute("reconstructed", candidate_path)
        except subprocess.TimeoutExpired:
            return {"attempted": True, "equivalent": False, "reason": "wall_timeout"}
        keys = ("exit_code", "stdout", "termination_reason", "returns", "errors", "unsupported_calls", "scheduler_events", "network_requirements")
        differences = [key for key in keys if original.get(key) != reconstructed.get(key)]
        return {"attempted": True, "equivalent": not differences, "differences": differences, "original": original, "reconstructed": reconstructed}

    def write_disassembly(self) -> Path:
        path = self.output_dir / "vm_disassembly.txt"
        lines = ["Alex Auto-Deobfuscator artifact inventory", ""]
        for node in sorted(self.graph.nodes.values(), key=lambda item: (item.kind, item.id)):
            lines.append(f"{node.id[:16]}  {node.kind:14} {node.bytes:9} bytes  {node.provenance}  {','.join(node.labels)}")
        if self.runtime_runs:
            lines.extend(["", "Runtime passes:"])
            for run in self.runtime_runs:
                lines.append(f"pass={run['pass']} artifact={run['artifact'][:12]} termination={run['termination_reason']}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def write_ir(self, selected: Candidate | None) -> tuple[Path, Path, Path]:
        semantic = self.output_dir / "semantic_ir.json"
        cfg = self.output_dir / "cfg.json"
        constants = self.output_dir / "constants.json"
        semantic.write_text(json.dumps({
            "version": 1,
            "status": "source_candidate" if selected else "artifact_only",
            "selected_artifact": selected.artifact_id if selected else None,
            "provenance": selected.provenance if selected else None,
            "compile_verified": selected.compile_verified if selected else False,
            "prototypes": [], "registers": [], "upvalue_cells": [], "basic_blocks": [],
            "notes": ["Generic typed VM lifting is emitted by family adapters when a VM layout is recovered."],
        }, indent=2) + "\n", encoding="utf-8")
        cfg.write_text(json.dumps({"version": 1, "nodes": [], "edges": [], "coverage": {"known": 0, "total": None}}, indent=2) + "\n", encoding="utf-8")
        literal_rows = []
        if selected:
            for match in re.finditer(r"(['\"])(.*?)(?<!\\)\1", selected.text, re.S):
                value = match.group(2)
                literal_rows.append({"index": len(literal_rows) + 1, "value": value[:4096], "provenance": selected.provenance})
        constants.write_text(json.dumps({"version": 1, "constants": literal_rows}, indent=2) + "\n", encoding="utf-8")
        return semantic, cfg, constants

    def run(self) -> dict[str, Any]:
        source_bytes = self.input_path.read_bytes()
        source = source_bytes.decode("utf-8", errors="replace")
        self.input_node, _ = self.graph.add(source_bytes, kind="luau_source", provenance="input", label=self.input_path.name, source_bearing=True)
        self.adapter, self.adapter_scores = detect_adapter(source)
        if self.args.adapter != "auto":
            self.adapter = self.args.adapter
        self.log("classify", adapter=self.adapter, bytes=len(source_bytes))
        self.run_adapter(source)

        frontier: list[tuple[Artifact, str]] = [(self.input_node, source)]
        seen: set[str] = set()
        for pass_index in range(1, self.args.max_passes + 1):
            if not frontier:
                break
            node, text = frontier.pop(0)
            if node.id in seen:
                continue
            seen.add(node.id)
            discovered = self.static_pass(node, text, pass_index)
            discovered.extend(self.run_runtime(node, text, pass_index))
            for child in discovered:
                try:
                    child_text = (self.output_dir / child.path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if child.id not in seen:
                    frontier.append((child, child_text))

        for candidate in self.candidates.values():
            self.verify_compile(candidate)
        exact_candidates = [candidate for candidate in self.candidates.values() if candidate.exact_eligible and candidate.compile_verified]
        reconstructed_candidates = [candidate for candidate in self.candidates.values() if candidate.compile_verified]
        exact_candidates.sort(key=lambda item: (-len(item.text), item.artifact_id))
        reconstructed_candidates.sort(key=lambda item: (item.provenance == "inferred", -len(item.text), item.artifact_id))

        selected: Candidate | None = None
        status = "blocked"
        if self.args.mode == "disassemble":
            status = "disassembled"
        elif self.args.mode in {"auto", "exact"} and exact_candidates:
            selected = exact_candidates[0]
            status = "recovered_exact"
        elif self.args.mode in {"auto", "reconstruct"} and reconstructed_candidates:
            selected = reconstructed_candidates[0]
            status = "reconstructed"
        elif self.args.mode != "exact" and self.graph.nodes:
            status = "disassembled"

        output_source: Path | None = None
        if selected:
            output_source = self.output_dir / ("source_exact.luau" if status == "recovered_exact" else "reconstructed.luau")
            output_source.write_text(selected.text.rstrip() + "\n", encoding="utf-8")
            selected.verification["differential"] = self.differential_verify(selected)

        disassembly = self.write_disassembly()
        semantic, cfg, constants = self.write_ir(selected)
        graph_path = self.graph.write()
        reconstruction_map = self.output_dir / "reconstruction_map.json"
        reconstruction_map.write_text(json.dumps({
            "version": 1,
            "output": output_source.name if output_source else None,
            "statements": [],
            "default_provenance": selected.provenance if selected else None,
        }, indent=2) + "\n", encoding="utf-8")

        report = {
            "report_version": 1,
            "tool": "alex-auto-deobfuscator",
            "status": status,
            "mode": self.args.mode,
            "adapter": self.adapter,
            "adapter_scores": self.adapter_scores,
            "input": {"path": str(self.input_path), "sha256": sha256_bytes(source_bytes), "bytes": len(source_bytes)},
            "output_dir": str(self.output_dir),
            "source_output": str(output_source) if output_source else None,
            "exact_source": status == "recovered_exact",
            "selected_candidate": {
                "artifact_id": selected.artifact_id,
                "provenance": selected.provenance,
                "compile_verified": selected.compile_verified,
                "verification": selected.verification,
            } if selected else None,
            "recovery_guidance": (
                "Exact source was not present in source-bearing captures. Run Auto or Readable mode to emit the best verified reconstruction."
                if status == "blocked" and reconstructed_candidates else
                "No compilable source candidate was recovered; inspect VM and provenance artifacts."
                if status == "blocked" else None
            ),
            "readable_candidate_available": bool(reconstructed_candidates),
            "artifact_counts": {
                "total": len(self.graph.nodes),
                "source": sum(node.kind == "luau_source" for node in self.graph.nodes.values()),
                "binary": sum(node.kind in {"binary", "bytecode", "packed_blob"} for node in self.graph.nodes.values()),
            },
            "passes": self.pass_log,
            "runtime_runs": self.runtime_runs,
            "adapter_runs": self.adapter_runs,
            "errors": self.errors,
            "artifacts": {
                "graph": str(graph_path), "semantic_ir": str(semantic), "cfg": str(cfg),
                "constants": str(constants), "disassembly": str(disassembly),
                "reconstruction_map": str(reconstruction_map),
            },
            "network_policy": self.args.network,
            "notes": [
                "Exact status requires directly captured or decoded source-bearing bytes plus successful compilation.",
                "Generated names, inferred control flow, and decompiler output are never labeled exact.",
            ],
        }
        report_path = self.output_dir / "deobfuscation_report.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if self.args.report == "-":
            print(json.dumps(report))
        elif self.args.report:
            target = Path(self.args.report)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(report_path, target)
        return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline runtime-assisted automatic Luau deobfuscator")
    parser.add_argument("input", help="Luau file path or '-' for stdin")
    parser.add_argument("--mode", choices=("auto", "exact", "reconstruct", "disassemble"), default="auto")
    parser.add_argument("--runtime", type=Path, default=ROOT / "build" / "rbx_luau_runtime")
    parser.add_argument("--alexfuscator", type=Path, default=ROOT / "build" / "alexfuscator")
    parser.add_argument("--deobfuscator", type=Path, default=ROOT / "build" / "alex_deobfuscator")
    parser.add_argument("--profile", choices=("roblox-client", "executor-client"), default="executor-client")
    parser.add_argument("--scenario", type=Path)
    parser.add_argument("--adapter", choices=("auto", "generic", "alexfuscator", "luraph", "moonveil", "wynfuscate", "wearedevs"), default="auto")
    parser.add_argument("--max-passes", type=int, default=6)
    parser.add_argument("--wall-timeout", type=float, default=10.0)
    parser.add_argument("--instruction-budget", type=int, default=10_000_000)
    parser.add_argument("--max-virtual-seconds", type=float, default=30.0)
    parser.add_argument("--network", choices=("offline", "allowlist"), default="offline")
    parser.add_argument("--fixture", action="append", default=[], metavar="URL=PATH")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--output-root", type=Path, default=ROOT / "outputs" / "auto_deobfuscator")
    parser.add_argument("--report", help="Copy report to PATH or write compact JSON to '-'")
    parser.add_argument("--progress", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    if not 1 <= args.max_passes <= 64:
        parser.error("--max-passes must be from 1 to 64")
    if args.wall_timeout <= 0 or args.instruction_budget < 1000 or args.max_virtual_seconds <= 0:
        parser.error("analysis budgets must be positive")
    return args


def materialize_input(raw: str, output_root: Path) -> Path:
    if raw != "-":
        path = Path(raw).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"input file does not exist: {path}")
        return path
    data = sys.stdin.buffer.read()
    if not data.strip():
        raise ValueError("stdin was empty")
    incoming = output_root / "_stdin"
    incoming.mkdir(parents=True, exist_ok=True)
    path = incoming / f"stdin_{now_stamp()}.luau"
    path.write_bytes(data)
    return path


def main() -> int:
    args = parse_args()
    try:
        input_path = materialize_input(args.input, args.output_root)
        output_dir = args.output_dir or args.output_root / f"{safe_name(input_path.stem)}_{now_stamp()}"
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=False)
        report = AutoDeobfuscator(args, input_path, output_dir).run()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"auto-deobfuscator: {error}", file=sys.stderr)
        return 1
    if args.report != "-":
        print(f"Status: {report['status']}")
        print(f"Output: {report['source_output'] or report['artifacts']['disassembly']}")
        print(f"Report: {Path(report['output_dir']) / 'deobfuscation_report.json'}")
    return 0 if report["status"] != "blocked" else 2


if __name__ == "__main__":
    raise SystemExit(main())
