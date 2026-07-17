#!/usr/bin/env python3
"""Validate generated guard-state rows across the offline trace boundary."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"
GUARD_MARKER = "@@LPH_GUARD_V1@@"
GUARD_PATH_MARKER = "@@LPH_GUARD_PATH_V1@@"
BINDING_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}=(?:[snbzfx]:.*)$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run(
    command: list[str],
    *,
    accepted: tuple[int, ...] = (0,),
    timeout: int = 30,
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


def run_deobfuscator(
    deobfuscator: pathlib.Path,
    root: pathlib.Path,
    name: str,
    *,
    trace: pathlib.Path | None = None,
) -> pathlib.Path:
    output = root / name
    command = [
        str(deobfuscator),
        str(SUBJECT),
        "--output-dir", str(output),
        "--mode", "reconstruct",
        "--report", str(root / f"{name}-report.json"),
    ]
    if trace is not None:
        command.extend(("--trace", str(trace)))
    run(command, accepted=(2,))
    return output


def run_runtime(runtime: pathlib.Path, root: pathlib.Path, name: str, probe: pathlib.Path) -> str:
    return run(
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
            "--report", str(root / f"{name}-runtime-report.json"),
            str(probe),
        ],
        timeout=25,
    ).stdout


def marker_rows(trace: str, marker: str) -> list[list[str]]:
    return [
        line.split("\t")
        for line in trace.splitlines()
        if line.startswith(f"{marker}\t")
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    parser.add_argument("--runtime", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-guard-state-trace-") as temporary:
        root = pathlib.Path(temporary)
        static_output = run_deobfuscator(args.deobfuscator, root, "static")
        initial_trace = root / "initial-trace.log"
        initial_trace.write_text(
            run_runtime(args.runtime, root, "initial", static_output / "trace_probe.luau"),
            encoding="utf-8",
        )

        refined_output = run_deobfuscator(
            args.deobfuscator, root, "refined", trace=initial_trace
        )
        refined_probe = refined_output / "trace_probe.luau"
        probe_source = refined_probe.read_text(encoding="utf-8")
        require(
            'print("@@LPH_GUARD_V1@@",_G.__vmc,__aid,__alex_lph_pre_pc,'
            '__alex_lph_pre_op,table.concat(__alex_lph_pre_guards,"|"))' in probe_source,
            "guard-state probe did not emit the packed V1 payload",
        )

        refined_trace_source = run_runtime(args.runtime, root, "refined", refined_probe)
        guard_rows = marker_rows(refined_trace_source, GUARD_MARKER)
        guard_path_rows = marker_rows(refined_trace_source, GUARD_PATH_MARKER)
        require(guard_rows, "refined probe emitted no guard-state rows")
        require(guard_path_rows, "refined probe emitted no guard-path rows")
        for fields in guard_rows:
            require(len(fields) == 6, f"guard-state row has {len(fields)} fields instead of 6")
            bindings = fields[5].split("|")
            require(bindings and all(BINDING_PATTERN.fullmatch(item) for item in bindings),
                    f"guard-state row contains an invalid binding payload: {fields[5]!r}")
            require(len(bindings) == len(set(item.split("=", 1)[0] for item in bindings)),
                    "guard-state row contains duplicate bindings")
        require(all(len(fields) == 8 for fields in guard_path_rows),
                "generated guard-path row no longer matches its V1 field shape")

        refined_trace = root / "refined-trace.log"
        refined_trace.write_text(refined_trace_source, encoding="utf-8")
        parsed_output = run_deobfuscator(
            args.deobfuscator, root, "parsed", trace=refined_trace
        )
        structure = json.loads(
            (parsed_output / "runtime_prototypes.json").read_text(encoding="utf-8")
        )
        malformed = structure.get("malformed_row_kinds") or {}
        require(int(malformed.get(GUARD_MARKER, 0)) == 0,
                f"generated guard-state rows were counted malformed: {malformed}")
        require(int(malformed.get(GUARD_PATH_MARKER, 0)) == 0,
                f"generated guard-path rows were counted malformed: {malformed}")
        observed_states = [
            step.get("guard_state")
            for step in structure.get("steps") or []
            if step.get("guard_state")
        ]
        require(observed_states, "parsed steps retained no generated guard state")

    print(
        "Luraph guard-state trace OK: "
        f"{len(guard_rows)} packed rows parsed without malformed guard events"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
