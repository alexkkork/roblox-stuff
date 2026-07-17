#!/usr/bin/env python3
"""Explicit, two-capture Roblox Studio oracle refresh for release 729.

Nothing imports or invokes this module from builds or tests. The confirmation
flag is intentionally required because running it starts Studio in command-line
mode and replaces pinned fixture files only after two normalized captures agree.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import plistlib
import re
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_STUDIO = pathlib.Path("/Applications/RobloxStudio.app/Contents/MacOS/RobloxStudio")
DEFAULT_PLIST = pathlib.Path("/Applications/RobloxStudio.app/Contents/Info.plist")
EXPECTED_BUILD = "0.729.0.7290838"
MARKER = "RBX_ORACLE_JSON:"


def normalize(value):
    if isinstance(value, dict):
        return {key: normalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"(?:[A-Za-z]:)?[^\s:]+\.luau:\d+", "<script>:<line>", value)
    return value


def extract_payload(text: str):
    for line in reversed(text.splitlines()):
        if MARKER in line:
            return normalize(json.loads(line.split(MARKER, 1)[1].strip()))
    raise RuntimeError("Studio output did not contain an RBX_ORACLE_JSON marker")


def studio_build(plist: pathlib.Path) -> str:
    with plist.open("rb") as handle:
        info = plistlib.load(handle)
    return str(info.get("CFBundleShortVersionString", "unknown"))


def capture(studio: pathlib.Path, probe: pathlib.Path, output: pathlib.Path):
    completed = subprocess.run(
        [
            str(studio),
            "--task", "RunScript",
            "--runScriptFile", str(probe),
            "--outputFile", str(output),
            "--quitAfterExecution",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
    if completed.returncode:
        raise RuntimeError(f"Studio probe failed with exit {completed.returncode}:\n{completed.stdout}")
    log = output.read_text(errors="replace") if output.exists() else ""
    return extract_payload(f"{completed.stdout}\n{log}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Explicitly refresh stable release-729 Studio oracle fixtures")
    parser.add_argument("--studio", type=pathlib.Path, default=DEFAULT_STUDIO)
    parser.add_argument("--info-plist", type=pathlib.Path, default=DEFAULT_PLIST)
    parser.add_argument("--confirm-studio-refresh", action="store_true", required=True)
    args = parser.parse_args()

    if not args.studio.is_file() or not args.info_plist.is_file():
        raise SystemExit("the requested Roblox Studio installation is unavailable")
    actual_build = studio_build(args.info_plist)
    if actual_build != EXPECTED_BUILD:
        raise SystemExit(f"Studio build mismatch: expected {EXPECTED_BUILD}, got {actual_build}")

    probes = sorted((ROOT / "tests" / "roblox_oracle" / "probes").glob("*.luau"))
    if not probes:
        raise SystemExit("no oracle probes were found")
    destination = ROOT / "tests" / "roblox_oracle" / "fixtures" / "release-729"
    pending = {}
    with tempfile.TemporaryDirectory(prefix="rbx-oracle-729-") as temporary:
        temp = pathlib.Path(temporary)
        for probe in probes:
            first = capture(args.studio, probe, temp / f"{probe.stem}-capture-1.log")
            second = capture(args.studio, probe, temp / f"{probe.stem}-capture-2.log")
            if first != second:
                raise SystemExit(f"unstable Studio oracle for {probe.name}; no fixtures were changed")
            first["oracle_release"] = "729"
            pending[probe.stem] = first

    destination.mkdir(parents=True, exist_ok=True)
    for stem, payload in pending.items():
        target = destination / f"{stem}.json"
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"updated {target.relative_to(ROOT)} from two identical captures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
