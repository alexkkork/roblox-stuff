#!/usr/bin/env python3
"""End-to-end truthfulness checks for guarded Luraph path replay."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
import pathlib
import re
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"
SOURCE_CANDIDATES = (
    "reconstructed.luau",
    "source_exact.luau",
    "payload_candidate.luau",
    "semantic_state_machine_candidate.luau",
    "semantic_readable_candidate.luau",
)
GUARD_PATH_MARKER = "@@LPH_GUARD_PATH_V1@@"
GUARD_RANGE_PATTERN = re.compile(r"__alex_lph_guard_eval\((\d+),(\d+),")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run(
    command: list[str],
    *,
    timeout: int = 30,
    accepted: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    require(
        completed.returncode in accepted,
        f"command exited {completed.returncode}: {' '.join(command)}\n"
        f"stdout:\n{completed.stdout[-4000:]}\nstderr:\n{completed.stderr[-4000:]}",
    )
    return completed


def run_runtime(runtime: pathlib.Path, probe: pathlib.Path, report: pathlib.Path) -> str:
    completed = run(
        [
            str(runtime),
            "--profile", "executor-client",
            "--execution-mode", "faithful",
            "--network-policy", "offline",
            "--clock", "virtual",
            "--timeout", "15",
            "--no-native-codegen",
            "--memory-limit-mb", "768",
            "--unsupported", "trace-nil",
            "--luraph-mode", "force",
            "--luraph-max-steps", "100000000",
            "--luraph-stall-steps", "0",
            "--report", str(report),
            str(probe),
        ],
        timeout=25,
    )
    require("anti tamper BYPASSED" in completed.stdout, "offline probe did not reach the locked payload")
    return completed.stdout


def run_deobfuscator(
    deobfuscator: pathlib.Path,
    root: pathlib.Path,
    name: str,
    *,
    trace: pathlib.Path | None = None,
) -> tuple[pathlib.Path, dict]:
    output = root / name
    report_path = root / f"{name}-report.json"
    command = [
        str(deobfuscator),
        str(SUBJECT),
        "--output-dir", str(output),
        "--mode", "reconstruct",
        "--report", str(report_path),
    ]
    if trace is not None:
        command.extend(("--trace", str(trace)))
    run(command, accepted=(2,))
    require(report_path.is_file(), f"{name} did not emit a report")
    return output, json.loads(report_path.read_text(encoding="utf-8"))


def assert_source_withheld(output: pathlib.Path, report: dict, name: str) -> None:
    require(report.get("status") == "blocked", f"{name} crossed the recovery boundary")
    require(report.get("exact_source") in (None, False), f"{name} claimed exact source")
    artifacts = report.get("artifacts") or {}
    require(artifacts.get("source") is None, f"{name} advertised a source artifact")
    verification = report.get("verification") or {}
    require(
        verification.get("source_claim_accepted") in (None, False),
        f"{name} accepted an unproven source claim",
    )
    for candidate in SOURCE_CANDIDATES:
        require(not (output / candidate).exists(), f"{name} emitted unproven source: {candidate}")


def read_runtime_artifacts(output: pathlib.Path) -> tuple[dict, dict]:
    structure_path = output / "runtime_prototypes.json"
    semantic_path = output / "runtime_semantic_ir.json"
    require(structure_path.is_file(), "runtime structure artifact is missing")
    require(semantic_path.is_file(), "runtime semantic artifact is missing")
    return (
        json.loads(structure_path.read_text(encoding="utf-8")),
        json.loads(semantic_path.read_text(encoding="utf-8")),
    )


def semantic_rows(semantic: dict) -> list[dict]:
    return [
        instruction
        for prototype in semantic.get("prototypes") or []
        for instruction in prototype.get("instructions") or []
    ]


def source_without_guard_paths(source: str) -> str:
    return "\n".join(
        line for line in source.splitlines() if not line.startswith(f"{GUARD_PATH_MARKER}\t")
    ) + "\n"


def choose_replayed_site(semantic: dict, trace_source: str) -> tuple[int, int]:
    available = {
        (int(fields[3]), int(fields[4]))
        for line in trace_source.splitlines()
        if line.startswith(f"{GUARD_PATH_MARKER}\t")
        for fields in (line.split("\t"),)
        if len(fields) == 8 and int(fields[5]) > 0
    }
    for row in semantic_rows(semantic):
        site = (int(row.get("pc", -1)), int(row.get("opcode", -1)))
        if row.get("guard_path_replayed") is True and site in available:
            return site
    raise AssertionError("no validated replay site has a non-empty recorded guard path")


def mutate_guard_path(
    source: str,
    site: tuple[int, int],
    *,
    mutation: str,
    known_ranges: set[tuple[int, int]],
) -> str:
    lines = source.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith(f"{GUARD_PATH_MARKER}\t"):
            continue
        fields = line.split("\t")
        if len(fields) != 8 or (int(fields[3]), int(fields[4])) != site or int(fields[5]) == 0:
            continue
        if mutation == "missing_field":
            fields.pop()
        elif mutation == "count_mismatch":
            fields[5] = str(int(fields[5]) + 1)
        else:
            decisions = fields[7].split("|")
            begin, end, decision = (int(value) for value in decisions[0].split(":"))
            if mutation == "malformed":
                end = begin
            elif mutation == "unknown":
                begin = max((range_end for _, range_end in known_ranges), default=end) + 100
                end = begin + 1
                require((begin, end) not in known_ranges, "unknown guard range accidentally exists")
            elif mutation == "invalid_decision":
                decision = 2
            else:
                raise AssertionError(f"unknown mutation: {mutation}")
            decisions[0] = f"{begin}:{end}:{decision}"
            fields[7] = "|".join(decisions)
        lines[index] = "\t".join(fields)
        return "\n".join(lines) + "\n"
    raise AssertionError(f"could not find a non-empty guard path for site {site}")


def guard_path_malformed_count(structure: dict) -> int:
    return int((structure.get("malformed_row_kinds") or {}).get(GUARD_PATH_MARKER, 0))


def assert_replay_labels(semantic: dict) -> list[dict]:
    replayed = [row for row in semantic_rows(semantic) if row.get("guard_path_replayed") is True]
    require(replayed, "valid guard paths did not produce replayed semantic rows")
    for row in replayed:
        require(row.get("semantic_operation") is None, "guard replay was promoted to static semantics")
        operation = row.get("observational_semantic_operation")
        require(isinstance(operation, dict), "guard replay omitted its observational operation")
        require(operation.get("path_specific") is True, "guard replay lost path_specific=true")
        require(operation.get("static_semantic") is False, "guard replay lost static_semantic=false")
        require(
            operation.get("proof") == "recorded_guard_path_replayed_through_original_ast",
            "guard replay lost its proof boundary",
        )
    return replayed


def assert_divergent_paths_not_merged(structure: dict, semantic: dict) -> None:
    operations_by_site: dict[tuple[int, int, int], set[str]] = defaultdict(set)
    for step in structure.get("steps") or []:
        operation = step.get("guard_replayed_semantic_operation")
        if isinstance(operation, dict):
            site = (int(step["prototype"]), int(step["pc"]), int(step["opcode"]))
            operations_by_site[site].add(json.dumps(operation, sort_keys=True, separators=(",", ":")))
    divergent = {site for site, operations in operations_by_site.items() if len(operations) > 1}
    require(divergent, "locked trace no longer exercises divergent guard paths")
    require(
        semantic.get("guard_replay_sites_divergent") == len(divergent),
        "divergent guard-path count does not match the recorded operations",
    )
    rows = {
        (int(prototype["runtime_id"]), int(row["pc"]), int(row["opcode"])): row
        for prototype in semantic.get("prototypes") or []
        for row in prototype.get("instructions") or []
    }
    for site in divergent:
        row = rows.get(site)
        require(row is not None, f"divergent site is missing from semantic IR: {site}")
        require(row.get("guard_path_replayed") is not True, f"divergent site was merged: {site}")
        operation = row.get("observational_semantic_operation") or {}
        require(
            operation.get("proof") != "recorded_guard_path_replayed_through_original_ast",
            f"divergent site retained a single replayed operation: {site}",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-guard-path-replay-") as temporary:
        root = pathlib.Path(temporary)

        static_output, static_report = run_deobfuscator(args.deobfuscator, root, "static")
        assert_source_withheld(static_output, static_report, "static analysis")
        initial_trace = root / "initial-trace.log"
        initial_trace.write_text(
            run_runtime(args.runtime, static_output / "trace_probe.luau", root / "initial-runtime-report.json"),
            encoding="utf-8",
        )

        window_output, window_report = run_deobfuscator(
            args.deobfuscator, root, "window", trace=initial_trace
        )
        assert_source_withheld(window_output, window_report, "window selection")
        refined_source = run_runtime(
            args.runtime, window_output / "trace_probe.luau", root / "refined-runtime-report.json"
        )
        require(GUARD_PATH_MARKER in refined_source, "refined probe emitted no guard paths")
        refined_trace = root / "refined-trace.log"
        refined_trace.write_text(refined_source, encoding="utf-8")

        control_trace = root / "control-trace.log"
        control_trace.write_text(source_without_guard_paths(refined_source), encoding="utf-8")
        control_output, control_report = run_deobfuscator(
            args.deobfuscator, root, "control", trace=control_trace
        )
        assert_source_withheld(control_output, control_report, "guard-free control")
        control_structure, control_semantic = read_runtime_artifacts(control_output)

        valid_output, valid_report = run_deobfuscator(
            args.deobfuscator, root, "valid", trace=refined_trace
        )
        assert_source_withheld(valid_output, valid_report, "valid guard replay")
        valid_structure, valid_semantic = read_runtime_artifacts(valid_output)
        replayed = assert_replay_labels(valid_semantic)
        assert_divergent_paths_not_merged(valid_structure, valid_semantic)
        require(guard_path_malformed_count(valid_structure) == 0, "valid guard ranges were rejected")
        require(valid_semantic.get("guard_replay_sites_validated") == len(replayed),
                "validated replay count does not match replayed semantic rows")
        require(valid_semantic.get("guard_replay_sites_validated", 0) > 0,
                "valid guard rows did not improve replay coverage")
        require(control_semantic.get("guard_replay_sites_validated") == 0,
                "guard-free control reported replayed paths")
        require(
            valid_semantic.get("semantic_lifted_instructions")
            == control_semantic.get("semantic_lifted_instructions"),
            "guard replay changed the static semantic count",
        )
        require(
            valid_semantic.get("observational_semantic_lifted", 0)
            > control_semantic.get("observational_semantic_lifted", 0),
            "valid guard rows did not improve observational coverage",
        )
        require(
            valid_semantic.get("observational_semantic_lifted", 0)
            - control_semantic.get("observational_semantic_lifted", 0)
            == valid_semantic.get("guard_replay_sites_validated"),
            "guard replay and observational coverage changed by different amounts",
        )

        known_ranges = {
            (int(begin), int(end))
            for begin, end in GUARD_RANGE_PATTERN.findall(
                (window_output / "trace_probe.luau").read_text(encoding="utf-8")
            )
        }
        require(known_ranges, "probe contains no guard-condition manifest")
        target_site = choose_replayed_site(valid_semantic, refined_source)
        for mutation in (
            "missing_field",
            "count_mismatch",
            "invalid_decision",
            "malformed",
            "unknown",
        ):
            mutated_trace = root / f"{mutation}-trace.log"
            mutated_trace.write_text(
                mutate_guard_path(
                    refined_source,
                    target_site,
                    mutation=mutation,
                    known_ranges=known_ranges,
                ),
                encoding="utf-8",
            )
            output, report = run_deobfuscator(
                args.deobfuscator, root, mutation, trace=mutated_trace
            )
            assert_source_withheld(output, report, f"{mutation} guard range")
            structure, semantic = read_runtime_artifacts(output)
            surviving_replayed = assert_replay_labels(semantic)
            require(
                guard_path_malformed_count(structure) == guard_path_malformed_count(valid_structure) + 1,
                f"{mutation} guard range was not rejected by the trace parser",
            )
            require(
                semantic.get("guard_replay_sites_validated")
                == valid_semantic.get("guard_replay_sites_validated") - 1,
                f"{mutation} guard range still contributed replay semantics",
            )
            require(
                semantic.get("semantic_lifted_instructions")
                == valid_semantic.get("semantic_lifted_instructions"),
                f"{mutation} guard range changed static semantic coverage",
            )
            require(
                semantic.get("guard_replay_sites_validated") == len(surviving_replayed),
                f"{mutation} guard range left an unlabeled accepted replay fact",
            )

    print(
        "Luraph guard-path replay OK: malformed rows rejected, divergent paths separated, "
        "and valid replay improved observational coverage only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
