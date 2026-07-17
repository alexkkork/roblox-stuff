#!/usr/bin/env python3
"""Fail-closed verification for the release-729 runtime inputs.

This checker never starts Roblox Studio and never updates a fixture. Oracle
refresh is a separate, explicit operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "tests" / "release_729_manifest.json"


class VerificationError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def verify_artifact(record: dict[str, Any], label: str) -> pathlib.Path:
    path = ROOT / record["path"]
    require(path.is_file(), f"{label} is missing: {record['path']}")
    size = path.stat().st_size
    require(size == int(record["bytes"]), f"{label} size mismatch: expected {record['bytes']}, got {size}")
    actual = sha256_file(path)
    require(actual == record["sha256"], f"{label} SHA-256 mismatch: expected {record['sha256']}, got {actual}")
    return path


def git_output(*arguments: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(ROOT / "vendor" / "luau"), *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip()


def verify_luau(manifest: dict[str, Any]) -> None:
    luau = manifest["luau"]
    for index, sentinel in enumerate(luau.get("sentinels", []), 1):
        verify_artifact(sentinel, f"Luau sentinel {index}")

    commit = git_output("rev-parse", "HEAD")
    if commit is not None:
        require(commit == luau["commit"], f"Luau commit mismatch: expected {luau['commit']}, got {commit}")
        tag = git_output("describe", "--tags", "--exact-match")
        require(tag == luau["tag"], f"Luau tag mismatch: expected {luau['tag']}, got {tag or 'no exact tag'}")

    root_cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    require(luau["commit"] in root_cmake, "root CMake fallback is not pinned to the release Luau commit")


def verify_declared_release(manifest: dict[str, Any]) -> None:
    header = (ROOT / "src" / "runtime" / "release_manifest.hpp").read_text(encoding="utf-8")
    declarations = {
        "engine release": manifest["engine_release"],
        "Studio build": manifest["studio_build"],
        "Luau tag": manifest["luau"]["tag"],
        "Luau commit": manifest["luau"]["commit"],
        "API hash": manifest["api_dump"]["sha256"],
        "oracle hash": manifest["oracle"]["fixture"]["sha256"],
    }
    for label, value in declarations.items():
        require(str(value) in header, f"compiled release manifest does not declare {label} {value}")
    require(
        re.search(r"kReportSchemaVersion\s*=\s*3\s*;", header) is not None,
        "compiled report schema is not version 3",
    )
    require(
        re.search(r"kScenarioSchemaVersion\s*=\s*2\s*;", header) is not None,
        "compiled scenario schema is not version 2",
    )


def verify_subject(manifest: dict[str, Any]) -> None:
    subject = manifest["subject"]
    verify_artifact(subject, "Luraph subject")
    sidecar_path = ROOT / subject["manifest_path"]
    require(sidecar_path.is_file(), f"subject sidecar is missing: {subject['manifest_path']}")
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    require(sidecar.get("sha256") == subject["sha256"], "subject sidecar SHA-256 disagrees with release manifest")
    require(sidecar.get("bytes") == subject["bytes"], "subject sidecar size disagrees with release manifest")
    require("source recovery is not required" in str(sidecar.get("acceptance", "")), "subject acceptance must not require source recovery")


def verify(manifest_path: pathlib.Path, subject_only: bool = False) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("schema") == "rbx-luau-runtime.release-test-manifest.v1", "unsupported release manifest schema")
    require(manifest.get("engine_release") == "729", "release manifest must target engine release 729")
    verify_subject(manifest)
    if subject_only:
        return manifest

    verify_luau(manifest)
    verify_artifact(manifest["api_dump"], "Full API dump")
    probe = verify_artifact(manifest["oracle"]["probe"], "oracle probe")
    fixture = verify_artifact(manifest["oracle"]["fixture"], "oracle fixture")
    require(probe.suffix == ".luau", "oracle probe must remain Luau source")
    fixture_payload = json.loads(fixture.read_text(encoding="utf-8"))
    require(fixture_payload.get("oracle_release") == "729", "oracle fixture release marker is not 729")
    require(manifest["oracle"].get("capture_repetitions_required", 0) >= 2, "oracle refresh policy must require two captures")
    require(manifest["oracle"].get("refresh_requires_identical_normalized_results") is True, "oracle refresh must require stable captures")
    verify_declared_release(manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify all release-729 pins without starting Studio")
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--subject-only", action="store_true")
    args = parser.parse_args()
    try:
        manifest = verify(args.manifest.resolve(), args.subject_only)
    except (OSError, ValueError, KeyError, VerificationError) as error:
        print(f"release-729 verification failed: {error}", file=sys.stderr)
        return 1
    if args.subject_only:
        print(f"release-729 subject OK: {manifest['subject']['sha256']} ({manifest['subject']['bytes']} bytes)")
    else:
        print(f"release-729 pins OK: Luau {manifest['luau']['tag']} @ {manifest['luau']['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
