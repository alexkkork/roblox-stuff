#!/usr/bin/env python3
import argparse
import json
import plistlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def run(cmd):
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=15)
        return {
            "ok": proc.returncode == 0,
            "code": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except Exception as exc:
        return {"ok": False, "code": None, "stdout": "", "stderr": str(exc)}


def read_plist(path):
    with path.open("rb") as fh:
        return plistlib.load(fh)


def find_app_root(path, temp_root):
    path = Path(path).expanduser().resolve()
    if path.suffix.lower() == ".ipa":
        extract_dir = temp_root / "ipa"
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path) as zf:
            zf.extractall(extract_dir)
        apps = sorted((extract_dir / "Payload").glob("*.app"))
        if not apps:
            raise SystemExit(f"No Payload/*.app found inside {path}")
        return apps[0], "ipa"

    if path.is_dir() and path.suffix == ".app":
        nested = sorted(path.glob("Contents/Resources/iOSApp/*.app"))
        if nested:
            return nested[0], "ipa-installer-wrapper"
        return path, "app"

    raise SystemExit(f"Expected .ipa or .app path, got {path}")


def parse_codesign(app):
    detail = run(["/usr/bin/codesign", "-dv", "--verbose=4", str(app)])
    ent = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(app)])
    text = "\n".join(x for x in [detail["stderr"], detail["stdout"]] if x)
    fields = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip()
    return {
        "raw": text,
        "fields": fields,
        "entitlements_raw": ent["stdout"] or ent["stderr"],
    }


def executable_path(app, info):
    exe_name = info.get("CFBundleExecutable")
    if not exe_name:
        return None
    p = app / exe_name
    return p if p.exists() else None


def classify(info, codesign, file_info, lipo_info, app):
    platform = str(info.get("DTPlatformName") or "")
    supported = info.get("CFBundleSupportedPlatforms") or []
    requires_iphone = bool(info.get("LSRequiresIPhoneOS"))
    min_os = str(info.get("MinimumOSVersion") or "")
    signature = codesign.get("fields", {}).get("Signature", "")
    team = codesign.get("fields", {}).get("TeamIdentifier", "")
    version_platform = codesign.get("fields", {}).get("VersionPlatform", "")
    raw = "\n".join([file_info, lipo_info, codesign.get("raw", ""), codesign.get("entitlements_raw", "")])

    reasons = []
    possible = []
    impossible = []

    if "iphonesimulator" in platform or "iPhoneSimulator" in supported:
        possible.append("Built for Xcode iOS Simulator. It may run in Simulator if launched by simctl/Xcode and dependencies are present.")
    elif platform == "iphoneos" or "iPhoneOS" in supported or requires_iphone or version_platform == "2":
        impossible.append("This is an iPhoneOS device build, not an iOS Simulator build.")
        impossible.append("macOS cannot directly exec ordinary iPhoneOS app bundles as normal Mac apps.")
        if signature == "adhoc" or team in {"", "not set"}:
            impossible.append("The bundle is ad-hoc signed and has no Apple team identity, so App Store/iOS-on-Mac receipt and entitlement checks will fail.")
        if "arm64" in file_info and "x86_64" not in file_info:
            reasons.append("The executable is arm64, but architecture alone is not enough; it still needs the iOS runtime and services.")
        if min_os:
            reasons.append(f"Minimum iOS version is {min_os}.")
    elif platform in {"macosx", "maccatalyst"} or "MacOSX" in supported:
        possible.append("This appears to target macOS/Mac Catalyst and should be launched as a normal Mac app if signing and dependencies are valid.")
    else:
        reasons.append("Could not confidently identify the target platform from Info.plist.")

    if "FairPlay" in raw or "SC_Info" in raw:
        reasons.append("FairPlay/App Store metadata appears to be referenced; that requires Apple-managed installation.")

    receipt = app / "Contents" / "_MASReceipt" / "receipt"
    if not receipt.exists() and (platform == "iphoneos" or requires_iphone):
        reasons.append("No Mac App Store receipt was found in the app bundle.")

    if impossible:
        verdict = "not_runnable_here"
    elif possible:
        verdict = "maybe_runnable_with_supported_launcher"
    else:
        verdict = "unknown"

    return {"verdict": verdict, "possible": possible, "blockers": impossible, "notes": reasons}


def inspect(path):
    with tempfile.TemporaryDirectory(prefix="iphone-os-app-check-") as tmp:
        app, source_kind = find_app_root(path, Path(tmp))
        info_path = app / "Info.plist"
        if not info_path.exists():
            raise SystemExit(f"No Info.plist found at {info_path}")
        info = read_plist(info_path)
        exe = executable_path(app, info)
        file_info = run(["file", str(exe)])["stdout"] if exe else ""
        lipo_info = run(["lipo", "-info", str(exe)])["stdout"] if exe else ""
        codesign = parse_codesign(app)
        classification = classify(info, codesign, file_info, lipo_info, app)
        return {
            "input": str(Path(path).expanduser().resolve()),
            "source_kind": source_kind,
            "app": str(app),
            "bundle_id": info.get("CFBundleIdentifier"),
            "bundle_name": info.get("CFBundleName") or info.get("CFBundleDisplayName"),
            "executable": str(exe) if exe else None,
            "info": {
                "CFBundleExecutable": info.get("CFBundleExecutable"),
                "MinimumOSVersion": info.get("MinimumOSVersion"),
                "DTPlatformName": info.get("DTPlatformName"),
                "CFBundleSupportedPlatforms": info.get("CFBundleSupportedPlatforms"),
                "UIDeviceFamily": info.get("UIDeviceFamily"),
                "LSRequiresIPhoneOS": info.get("LSRequiresIPhoneOS"),
            },
            "mach_o": {"file": file_info, "lipo": lipo_info},
            "codesign": {
                "Identifier": codesign["fields"].get("Identifier"),
                "Signature": codesign["fields"].get("Signature"),
                "TeamIdentifier": codesign["fields"].get("TeamIdentifier"),
                "VersionPlatform": codesign["fields"].get("VersionPlatform"),
                "VersionMin": codesign["fields"].get("VersionMin"),
                "VersionSDK": codesign["fields"].get("VersionSDK"),
            },
            "classification": classification,
        }


def print_human(report):
    c = report["classification"]
    print(f"App: {report.get('bundle_name') or '(unknown)'}")
    print(f"Bundle ID: {report.get('bundle_id') or '(unknown)'}")
    print(f"Source: {report['source_kind']}")
    print(f"Executable: {report.get('executable') or '(missing)'}")
    print(f"Target platform: {report['info'].get('DTPlatformName') or report['info'].get('CFBundleSupportedPlatforms') or '(unknown)'}")
    print(f"Minimum OS: {report['info'].get('MinimumOSVersion') or '(unknown)'}")
    print(f"Signature: {report['codesign'].get('Signature') or '(unknown)'}")
    print(f"Team: {report['codesign'].get('TeamIdentifier') or '(unknown)'}")
    print(f"Mach-O: {report['mach_o'].get('file') or '(unknown)'}")
    print()
    print(f"Verdict: {c['verdict']}")
    for item in c["blockers"]:
        print(f"- Blocker: {item}")
    for item in c["possible"]:
        print(f"- Possible: {item}")
    for item in c["notes"]:
        print(f"- Note: {item}")


def main():
    parser = argparse.ArgumentParser(description="Inspect whether an iPhoneOS .ipa/.app can run on this Mac without private Apple runtime bypasses.")
    parser.add_argument("path", help="Path to .ipa or .app")
    parser.add_argument("--json", action="store_true", help="Print JSON report")
    parser.add_argument("--save", help="Save JSON report to this path")
    args = parser.parse_args()

    report = inspect(args.path)
    if args.save:
        out = Path(args.save).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human(report)
        if args.save:
            print(f"\nSaved JSON: {Path(args.save).expanduser().resolve()}")


if __name__ == "__main__":
    raise SystemExit(main())
