#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


def fixture(version: str = "14.7") -> str:
    fields = [
        "P=function(self)return function(...)return ... end end",
        "readu8=function(s,i)return string.byte(s,i)end",
        "readu32=function(s,i)return bit32.band(string.byte(s,i),255)end",
        'secret=function()return "LURAPH_TEST_SECRET_MUST_NOT_LEAK" end',
    ]
    fields.extend(
        f"f{index}=function(x)for i=1,2 do x=(x or 0)+i end return x end"
        for index in range(18)
    )
    carrier = "LPH@" + "".join(chr(33 + (index % 80)) for index in range(1400))
    fields.append(f"payload=[=[{carrier}]=]")
    return (
        f"-- This file was protected using Luraph Obfuscator v{version} [https://lura.ph/]\n"
        f"return({{{','.join(fields)}}}):P()(...);\n"
    )


def invoke(binary: pathlib.Path, source: str, directory: pathlib.Path, mode: str = "auto") -> tuple[subprocess.CompletedProcess[str], dict]:
    directory.mkdir(parents=True, exist_ok=True)
    input_path = directory / "input.luau"
    output_path = directory / "output"
    input_path.write_text(source, encoding="utf-8")
    completed = subprocess.run(
        [
            str(binary),
            str(input_path),
            "--output-dir",
            str(output_path),
            "--mode",
            mode,
            "--report",
            "-",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    report_path = output_path / "deobfuscation_report.json"
    if not report_path.is_file():
        raise AssertionError(f"report missing: exit={completed.returncode}\n{completed.stderr}")
    stdout_report = json.loads(completed.stdout)
    disk_report = json.loads(report_path.read_text(encoding="utf-8"))
    if stdout_report != disk_report:
        raise AssertionError("--report - differs from deobfuscation_report.json")
    return completed, disk_report


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def audit_supported(binary: pathlib.Path, root: pathlib.Path) -> None:
    completed, report = invoke(binary, fixture(), root / "supported")
    output = root / "supported" / "output"
    require(completed.returncode == 2, f"bounded envelope analysis exit was {completed.returncode}")
    require(report.get("backend") == "native-cpp", f"wrong backend: {report.get('backend')!r}")
    require(report.get("adapter") == "luraph-v14.7", f"wrong adapter: {report.get('adapter')!r}")
    require(report.get("status") == "blocked", f"wrong status: {report.get('status')!r}")
    require(report.get("exact_source") is False, "adapter claimed exact source")
    require(report.get("fallback_used") is False, "adapter used a fallback")
    require(report.get("analysis_scope") == "source-envelope-only", "analysis scope is ambiguous")
    require(report.get("coverage", {}).get("payload_decoded") is False, "coverage claimed a decoded payload")
    require(report.get("coverage", {}).get("stages", {}).get("identified", 0) >= 4, "stage coverage is missing")
    require(report.get("verification", {}).get("source_claim_accepted") is False, "source claim was accepted")
    require(report.get("artifacts", {}).get("source") is None, "source artifact was exposed")
    require(report.get("artifacts", {}).get("candidate") is None, "candidate source artifact was exposed")
    codes = {item.get("code") for item in report.get("diagnostics", [])}
    require("luraph_payload_decode_unimplemented" in codes, f"decode boundary diagnostic missing: {codes}")

    expected = {
        "luraph_envelope_analysis.json",
        "semantic_ir.json",
        "cfg.json",
        "constants.json",
        "vm_disassembly.txt",
        "reconstruction_map.json",
        "artifact_graph.json",
        "deobfuscation_report.json",
    }
    require(expected.issubset({path.name for path in output.iterdir()}), "one or more bounded artifacts are missing")
    require(not list(output.glob("*.luau")), "Luraph adapter emitted a Luau source artifact")
    envelope = json.loads((output / "luraph_envelope_analysis.json").read_text(encoding="utf-8"))
    require(envelope.get("source_recovery_attempted") is False, "envelope artifact claimed source recovery")
    require(envelope.get("payload_decoded") is False, "envelope artifact claimed payload decoding")
    require(envelope.get("version_supported") is True, "v14.7 was not accepted")
    require(envelope.get("wrapper", {}).get("kind") == "returned_table_method_dispatch", "wrapper metadata is missing")
    require(all(blob.get("content_included") is False for blob in envelope.get("blobs", [])), "blob content was included")
    cfg = json.loads((output / "cfg.json").read_text(encoding="utf-8"))
    require(cfg.get("payload_cfg_recovered") is False, "stage graph was mislabeled as a payload CFG")
    ir = json.loads((output / "semantic_ir.json").read_text(encoding="utf-8"))
    require(ir.get("status") == "unavailable" and not ir.get("prototypes"), "semantic IR was fabricated")
    require("No VM instruction disassembly was produced" in (output / "vm_disassembly.txt").read_text(encoding="utf-8"), "disassembly boundary is unclear")
    for artifact in output.iterdir():
        require("LURAPH_TEST_SECRET_MUST_NOT_LEAK" not in artifact.read_text(encoding="utf-8"), f"secret leaked into {artifact.name}")


def audit_unsupported_version(binary: pathlib.Path, root: pathlib.Path) -> None:
    completed, report = invoke(binary, fixture("15.0"), root / "unsupported")
    require(completed.returncode == 2, f"unsupported version exit was {completed.returncode}")
    require(report.get("adapter") == "luraph-v14.7", "unsupported Luraph input fell through to another adapter")
    require(report.get("status") == "blocked" and report.get("exact_source") is False, "unsupported version made a recovery claim")
    codes = {item.get("code") for item in report.get("diagnostics", [])}
    require("UNSUPPORTED_VERSION" in codes and "unsupported_luraph_version" in codes, f"version diagnostics missing: {codes}")


def audit_modes_never_claim_source(binary: pathlib.Path, root: pathlib.Path) -> None:
    for mode in ("exact", "reconstruct", "disassemble"):
        completed, report = invoke(binary, fixture(), root / f"mode-{mode}", mode=mode)
        output = root / f"mode-{mode}" / "output"
        require(completed.returncode == 2, f"{mode} mode exited {completed.returncode}")
        require(report.get("adapter") == "luraph-v14.7", f"{mode} mode changed adapters")
        require(report.get("status") == "blocked", f"{mode} mode overstated status: {report.get('status')!r}")
        require(report.get("exact_source") is False, f"{mode} mode claimed exact source")
        require(report.get("artifacts", {}).get("source") is None, f"{mode} mode exposed source")
        require(not list(output.glob("*.luau")), f"{mode} mode emitted a Luau artifact")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    args = parser.parse_args()
    binary = args.deobfuscator.resolve()
    with tempfile.TemporaryDirectory(prefix="luraph-adapter-integration-") as temporary:
        root = pathlib.Path(temporary)
        audit_supported(binary, root)
        audit_unsupported_version(binary, root)
        audit_modes_never_claim_source(binary, root)
    print("luraph-adapter-integration-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
