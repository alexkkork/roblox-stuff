#!/usr/bin/env python3
import argparse
import json
import plistlib
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STUDIO = Path("/Applications/RobloxStudio.app/Contents/MacOS/RobloxStudio")
INFO_PLIST = Path("/Applications/RobloxStudio.app/Contents/Info.plist")
MARKER = "RBX_ORACLE_JSON:"


def run(command, timeout=180):
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(map(str, command))}\n{result.stdout}")
    return result.stdout


def export_api(studio, flag, output):
    for attempt in range(2):
        run([str(studio), flag, str(output)])
        if output.exists() and output.stat().st_size > 1024:
            return
    raise RuntimeError(f"Studio did not produce {flag} output at {output}")


def studio_release():
    if not INFO_PLIST.exists():
        return "unknown"
    with INFO_PLIST.open("rb") as handle:
        info = plistlib.load(handle)
    version = str(info.get("CFBundleShortVersionString", "unknown"))
    match = re.match(r"0\.(\d+)\.", version)
    return match.group(1) if match else version


def extract_payload(text):
    for line in reversed(text.splitlines()):
        if MARKER in line:
            payload = line.split(MARKER, 1)[1].strip()
            return json.loads(payload)
    raise RuntimeError("Studio output did not contain an RBX_ORACLE_JSON marker")


def normalize(value):
    if isinstance(value, dict):
        return {key: normalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?:[A-Za-z]:)?[^\s:]+\.luau:\d+", "<script>:<line>", value)
    return value


def main():
    parser = argparse.ArgumentParser(description="Refresh release-pinned Roblox Studio oracle fixtures and API metadata")
    parser.add_argument("--studio", type=Path, default=DEFAULT_STUDIO)
    parser.add_argument("--release", default="auto")
    parser.add_argument("--skip-api", action="store_true")
    args = parser.parse_args()
    if not args.studio.exists():
        raise SystemExit(f"Roblox Studio executable not found: {args.studio}")
    release = studio_release() if args.release == "auto" else args.release
    fixture_dir = ROOT / "tests" / "roblox_oracle" / "fixtures" / f"release-{release}"
    fixture_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="rbx-oracle-") as temporary:
        temp = Path(temporary)
        if not args.skip_api:
            api_v1_path = temp / "Full-API-Dump.json"
            api_v2_path = temp / "Full-API-Dump-v2.json"
            export_api(args.studio, "--fullApi", api_v1_path)
            export_api(args.studio, "--apiV2", api_v2_path)
            run(["python3", "tools/generate_api_summary.py", str(api_v1_path), "src/generated/RobloxApiDumpSummary.inc"])

        for probe in sorted((ROOT / "tests" / "roblox_oracle" / "probes").glob("*.luau")):
            output = temp / f"{probe.stem}.log"
            stdout = run([
                str(args.studio), "--task", "RunScript", "--runScriptFile", str(probe),
                "--outputFile", str(output), "--quitAfterExecution",
            ])
            combined = stdout + "\n" + (output.read_text(errors="replace") if output.exists() else "")
            payload = normalize(extract_payload(combined))
            payload["oracle_release"] = release
            (fixture_dir / f"{probe.stem}.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            print(f"updated {fixture_dir / (probe.stem + '.json')}")


if __name__ == "__main__":
    main()
