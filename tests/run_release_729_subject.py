#!/usr/bin/env python3
"""Hash-pinned, bounded execution harness for the supplied Luraph workload."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT_MANIFEST = ROOT / "tests" / "fixtures" / "luraph" / "subject_manifest.json"


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def subject() -> tuple[pathlib.Path, dict]:
    manifest = json.loads(SUBJECT_MANIFEST.read_text(encoding="utf-8"))
    path = SUBJECT_MANIFEST.parent / manifest["filename"]
    if not path.is_file():
        raise RuntimeError(f"subject is missing: {path}")
    if path.stat().st_size != manifest["bytes"]:
        raise RuntimeError("subject byte size does not match its manifest")
    if sha256_file(path) != manifest["sha256"]:
        raise RuntimeError("subject SHA-256 does not match its manifest")
    return path, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the release-729 Luraph subject without requiring source recovery")
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    parser.add_argument("--acceptance", action="store_true", help="require a completed, steady, or explicitly network-blocked run")
    parser.add_argument("--network-policy", choices=("offline", "allowlist", "live"), default="offline")
    parser.add_argument("--allow-host", action="append", default=[])
    parser.add_argument("--timeout", type=float)
    args = parser.parse_args()

    subject_path, manifest = subject()
    timeout = args.timeout if args.timeout is not None else (280 if args.acceptance else 15)
    max_steps = 2_000_000_000 if args.acceptance else 2_000_000
    stall_steps = 0 if args.acceptance else 500_000

    with tempfile.TemporaryDirectory(prefix="release-729-subject-") as temporary:
        temp = pathlib.Path(temporary)
        report_path = temp / "report.json"
        command = [
            str(args.runtime),
            "--profile", "executor-client",
            "--execution-mode", "faithful",
            "--analysis-hooks", "off",
            "--executor-preset", "generic",
            "--filesystem", "memory",
            "--memory-limit-mb", "512",
            "--network-policy", args.network_policy,
            "--clock", "virtual",
            "--max-virtual-seconds", "30" if args.acceptance else "3",
            "--timeout", str(timeout),
            "--luraph-mode", "force",
            "--luraph-max-steps", str(max_steps),
            "--luraph-stall-steps", str(stall_steps),
            "--native-codegen",
            "--report", str(report_path),
            "--out", str(temp / "captures"),
        ]
        for host in args.allow_host:
            command.extend(("--allow-host", host))
        command.append(str(subject_path))
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 20,
        )
        if not report_path.is_file():
            raise RuntimeError(
                f"runtime did not emit a report (exit {completed.returncode})\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )
        report = json.loads(report_path.read_text(encoding="utf-8"))

    if report.get("version") != 3 or report.get("engine_release") != "729":
        raise RuntimeError(f"subject used the wrong report/release contract: {report.get('version')}/{report.get('engine_release')}")
    if report.get("profile") != "executor-client" or report.get("execution_mode") != "faithful":
        raise RuntimeError("subject did not run in the faithful executor-client profile")
    if report.get("status") == "compile_error":
        raise RuntimeError(f"release-729 Luau compiler rejected the unchanged subject: {report.get('error')}")
    workload = report.get("workload") or {}
    if workload.get("input_sha256") != manifest["sha256"] or workload.get("input_bytes") != manifest["bytes"]:
        raise RuntimeError("runtime report did not preserve the subject identity")
    if workload.get("family") != "luraph" or workload.get("phase") not in {"executing", "payload_activity", "source_observed"}:
        raise RuntimeError(f"Luraph workload did not begin execution: {workload}")
    if (report.get("limits") or {}).get("memory_limit_hit"):
        raise RuntimeError("subject exceeded the configured memory sandbox")
    if (report.get("security") or {}).get("allow_private_network"):
        raise RuntimeError("subject unexpectedly received private-network access")

    execution_state = report.get("execution_state")
    if args.acceptance:
        allowed = {"completed", "steady_state"}
        if args.network_policy == "offline" and report.get("network_requirements"):
            allowed.add("blocked")
        if execution_state not in allowed:
            raise RuntimeError(f"subject acceptance did not reach a healthy terminal state: {execution_state}: {report.get('error')}")
        unexpected = [
            item for item in (report.get("unsupported") or [])
            if item.get("kind") in {"missing_global", "missing_member", "stub_method", "missing_fixture"}
        ]
        if unexpected:
            raise RuntimeError(f"subject encountered unexpected runtime API gaps: {unexpected[:5]}")
        workload_evidence = workload.get("activity_evidence") or []
        has_return = bool(report.get("typed_returns") or report.get("returns"))
        healthy_wait = execution_state == "steady_state" and isinstance(report.get("steady_state_reason"), str)
        if not (workload_evidence or has_return or healthy_wait):
            raise RuntimeError("subject reached a terminal state without payload-side activity, a return value, or a healthy scheduler wait")

    if completed.returncode != 0:
        if not args.acceptance and report.get("status") == "instruction_budget":
            print(
                "release-729 subject bounded probe: "
                f"{manifest['bytes']} bytes, phase={workload.get('phase')}, "
                f"classification={workload.get('classification')}, status=instruction_budget"
            )
            return 0
        raise RuntimeError(
            f"subject process failed (exit {completed.returncode}): "
            f"{report.get('termination_reason')}: {report.get('error')}"
        )

    print(
        "release-729 subject OK: "
        f"{manifest['bytes']} bytes, phase={workload.get('phase')}, state={execution_state}, "
        "source recovery not required"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
