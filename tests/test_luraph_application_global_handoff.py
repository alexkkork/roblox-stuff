#!/usr/bin/env python3
"""Regression coverage for Luraph application-global payload handoffs."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"
APPLICATION_GLOBALS = (
    "game",
    "workspace",
    "Instance.new",
    "UDim.new",
    "Vector2.new",
    "task",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def encoded_global(path: str) -> str:
    return "g:" + path.encode("utf-8").hex()


def activation_trace(*, include_application_child: bool) -> str:
    rows = [
        "@@LPH_PROTO_V1@@\t1\t1\tQ,t,u",
        "@@LPH_PROTO_V1@@\t2\t1\tQ,t,u",
        "@@LPH_PROTO_V1@@\t3\t1\tQ,t,u",
        "@@LPH_PROTO_V1@@\t4\t1\tQ,t,u",
        "@@LPH_INSN_V1@@\t1\t1\t255\tQ=n:0|t=n:0|u=n:0",
        "@@LPH_INSN_V1@@\t2\t1\t255\tQ=n:0|t=n:0|u=n:0",
        "@@LPH_INSN_V1@@\t3\t1\t255\tQ=n:0|t=n:0|u=n:0",
        "@@LPH_INSN_V1@@\t4\t1\t255\tQ=n:0|t=n:0|u=n:0",
        "@@LPH_ACT_PROTO_V1@@\t1\t1\tnil\tnil\tnil\t0\t1\t\t1",
        "@@LPH_ACT_PROTO_V1@@\t2\t2\t1\t1\t255\t0\t1\t\t2",
    ]
    if include_application_child:
        arguments = "|".join(encoded_global(path) for path in APPLICATION_GLOBALS)
        rows.append(
            f"@@LPH_ACT_PROTO_V1@@\t3\t3\t2\t1\t255\t{len(APPLICATION_GLOBALS)}\t1\t{arguments}\t3"
        )
    rows.extend((
        "@@LPH_ACT_PROTO_V1@@\t4\t4\t2\t1\t255\t1\t1\t"
        + encoded_global("debug") + "\t4",
        "@@LPH_STEP_V1@@\t5\t1\t1\t255\t1\t0\t\tQ=n:0|t=n:0|u=n:0",
        "@@LPH_STEP_V1@@\t6\t2\t1\t255\t1\t0\t\tQ=n:0|t=n:0|u=n:0",
        "@@LPH_STEP_V1@@\t7\t4\t1\t255\t1\t0\t\tQ=n:0|t=n:0|u=n:0",
        "",
    ))
    return "\n".join(rows)


def run_case(
    deobfuscator: pathlib.Path,
    root: pathlib.Path,
    *,
    include_application_child: bool,
) -> tuple[pathlib.Path, dict]:
    root.mkdir(parents=True)
    trace = root / "trace.log"
    output = root / "output"
    report_path = root / "report.json"
    trace.write_text(
        activation_trace(include_application_child=include_application_child),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            str(deobfuscator),
            str(SUBJECT),
            "--output-dir",
            str(output),
            "--mode",
            "reconstruct",
            "--trace",
            str(trace),
            "--report",
            str(report_path),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=25,
    )
    require(
        report_path.is_file(),
        f"deobfuscator omitted its report (exit={completed.returncode}): {completed.stderr[-2000:]}",
    )
    require(
        completed.returncode == 2,
        f"bounded handoff evidence unexpectedly crossed the recovery boundary: {completed.returncode}",
    )
    return output, json.loads(report_path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-app-handoff-") as temporary:
        root = pathlib.Path(temporary)

        positive_output, positive = run_case(
            args.deobfuscator,
            root / "positive",
            include_application_child=True,
        )
        coverage = positive.get("coverage") or {}
        payload_root = coverage.get("payload_root") or {}
        require(payload_root.get("available") is True, f"payload root was not detected: {payload_root}")
        require(
            payload_root.get("evidence") == "runtime_application_global_handoff",
            f"application handoff used the wrong evidence tier: {payload_root}",
        )
        require(
            payload_root.get("bootstrap_activation") == 2
            and payload_root.get("bootstrap_prototype") == 2
            and payload_root.get("payload_activation") == 3
            and payload_root.get("payload_prototype") == 3,
            f"the debug-only sibling displaced the application payload: {payload_root}",
        )
        require(
            set(payload_root.get("application_globals") or []) == set(APPLICATION_GLOBALS),
            f"application-global evidence was not retained: {payload_root}",
        )
        require(
            (coverage.get("guard_hotspot") or {}).get("available") is False,
            f"a proven application handoff was still reported as a guard hotspot: {coverage.get('guard_hotspot')}",
        )
        require(
            not (positive_output / "guard_hotspot.json").exists(),
            "a guard-hotspot artifact was emitted for a proven application handoff",
        )

        _, debug_only = run_case(
            args.deobfuscator,
            root / "debug-only",
            include_application_child=False,
        )
        debug_coverage = debug_only.get("coverage") or {}
        require(
            (debug_coverage.get("payload_root") or {}).get("available") is False,
            f"a debug-only child was misclassified as payload: {debug_coverage.get('payload_root')}",
        )
        require(
            (debug_coverage.get("guard_hotspot") or {}).get("available") is True,
            f"debug-only evidence did not remain a guard hotspot: {debug_coverage.get('guard_hotspot')}",
        )

    print("Luraph application-global handoff OK: payload selected and debug-only child rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
