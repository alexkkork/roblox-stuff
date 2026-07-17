#!/usr/bin/env python3
import argparse
import json
import math
import pathlib
import re
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SECRET = "V5_SECRET_LITERAL_9f4d21b63a"
MARKER = "v5-structure-ok"
SOURCE = f'''local secret = "{SECRET}"
local captured = 7
local function noargs() return captured, secret end
local function branch(value)
    if value % 3 == 0 then return value + captured end
    if value % 2 == 0 then return value * 2 end
    return value - 1
end
local total = 0
for value = 1, 8 do
    if value == 4 then continue end
    total += branch(value)
end
local first, second = noargs()
print("{MARKER}", total, first, #second)
return total, first
'''


def run(command, *, check=True):
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(map(str, command))}\n{result.stderr}")
    return result


def compile_artifact(binary, source, output, report, profile, seed, *extra):
    run([
        str(binary), str(source), "-o", str(output), "--report", str(report), "--unsafe-debug-map",
        "--profile", profile, "--runtime", "universal", "--environment-binding", "portable",
        "--seed", str(seed), "--format", "one-line", "--no-watermark", *extra,
    ])
    return json.loads(report.read_text(encoding="utf-8"))


def execute(runtime, artifact, output_dir):
    return run([
        str(runtime), "--luraph-mode", "off", "--analysis-hooks", "off", "--network-policy", "offline",
        "--out", str(output_dir), str(artifact),
    ], check=False)


def mutate_payload(artifact):
    text = artifact.read_text(encoding="utf-8")
    candidates = list(re.finditer(r'\{\d+(?:,\d+){28,}\}', text))
    if not candidates:
        raise RuntimeError("could not locate a syntax-preserving encrypted payload shard")
    match = max(candidates, key=lambda item: len(item.group(0)))
    numbers = list(re.finditer(r'\d+', match.group(0)))
    number = numbers[len(numbers) // 2]
    start = match.start() + number.start()
    end = match.start() + number.end()
    replacement = str((int(number.group(0)) + 1) % 256)
    return text[:start] + replacement + text[end:]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--alexfuscator", type=pathlib.Path, default=ROOT / "build" / "alexfuscator")
    parser.add_argument("--runtime", type=pathlib.Path, default=ROOT / "build" / "rbx_luau_runtime")
    parser.add_argument("--seeds", type=int, default=100)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="alex-v5-structure-") as directory:
        temporary = pathlib.Path(directory)
        source = temporary / "source.luau"
        output = temporary / "artifact.luau"
        report = temporary / "report.json"
        source.write_text(SOURCE, encoding="utf-8")

        fingerprints = {name: set() for name in (
            "opcode_map_fingerprint", "block_order_fingerprint", "constant_layout_fingerprint",
            "handler_topology_fingerprint", "complete_structural_fingerprint",
        )}
        for seed in range(1, args.seeds + 1):
            descriptor = compile_artifact(args.alexfuscator, source, output, report, "maximum", 700000 + seed)
            for name in fingerprints:
                value = descriptor.get(name)
                if not value:
                    raise RuntimeError(f"unsafe v5 report omitted {name}")
                fingerprints[name].add(value)
            flags = descriptor.get("feature_flags") or {}
            required = (
                "register_vm", "typed_semantic_ir", "explicit_result_arity", "lexical_upvalue_cells",
                "per_prototype_opcode_maps", "per_prototype_operand_codecs", "physical_block_shuffle",
                "control_flow_flattening", "opaque_branches", "instruction_substitution",
                "handler_topology_randomized", "safe_decoy_prototypes", "encrypted_vm_container",
                "encrypted_constant_fragments", "chained_integrity_checks", "per_block_lazy_decryption",
                "hkdf_sha256", "chacha20_poly1305",
            )
            missing = [name for name in required if flags.get(name) is not True]
            if missing:
                raise RuntimeError(f"Maximum report omitted active v5 features: {missing}")

        for name in ("opcode_map_fingerprint", "block_order_fingerprint", "constant_layout_fingerprint", "complete_structural_fingerprint"):
            if len(fingerprints[name]) != args.seeds:
                raise RuntimeError(f"{name} repeated across Maximum seeds: {len(fingerprints[name])}/{args.seeds}")
        required_topologies = math.ceil(args.seeds * 0.9)
        if len(fingerprints["handler_topology_fingerprint"]) < required_topologies:
            raise RuntimeError(f"handler topology diversity is too low: {len(fingerprints['handler_topology_fingerprint'])}/{args.seeds}")

        fixed_a = temporary / "fixed-a.luau"
        fixed_b = temporary / "fixed-b.luau"
        compile_artifact(args.alexfuscator, source, fixed_a, report, "maximum", 777)
        compile_artifact(args.alexfuscator, source, fixed_b, report, "maximum", 777)
        if fixed_a.read_bytes() != fixed_b.read_bytes():
            raise RuntimeError("fixed seed did not produce byte-identical output")

        auto_a = temporary / "auto-a.luau"
        auto_b = temporary / "auto-b.luau"
        compile_artifact(args.alexfuscator, source, auto_a, report, "maximum", "auto")
        compile_artifact(args.alexfuscator, source, auto_b, report, "maximum", "auto")
        if auto_a.read_bytes() == auto_b.read_bytes():
            raise RuntimeError("automatic seeds produced identical output")

        artifact_text = fixed_a.read_text(encoding="utf-8")
        forbidden = ("loadstring", SECRET, "local captured = 7", "alex_ast_vm_vnext", "hardened_loader_fallback")
        visible = [value for value in forbidden if value in artifact_text]
        if visible:
            raise RuntimeError(f"v5 artifact exposed forbidden plaintext: {visible}")
        baseline = execute(args.runtime, fixed_a, temporary / "baseline-run")
        if baseline.returncode or MARKER not in baseline.stdout:
            raise RuntimeError(f"baseline v5 artifact failed: {baseline.stderr}")

        mutated = temporary / "mutated.luau"
        mutated.write_text(mutate_payload(fixed_a), encoding="utf-8")
        tampered = execute(args.runtime, mutated, temporary / "mutated-run")
        if MARKER in tampered.stdout or tampered.stderr.strip():
            raise RuntimeError(f"authenticated payload mutation was not a harmless decoy: {tampered.stdout!r} {tampered.stderr!r}")

        for profile in ("compatibility", "hardened", "maximum"):
            descriptor = compile_artifact(args.alexfuscator, source, output, report, profile, 991)
            if descriptor.get("profile") != profile or descriptor.get("backend") != "register_vm_v5" or descriptor.get("fallback_used") is not False:
                raise RuntimeError(f"profile contract mismatch: {descriptor}")
            if profile != "maximum" and descriptor.get("per_block_lazy_decryption") is not False:
                raise RuntimeError(f"{profile} unexpectedly enabled Maximum lazy blocks")

        disabled = compile_artifact(
            args.alexfuscator, source, output, report, "compatibility", 992,
            "--control-flow", "off", "--constant-protection", "off", "--vm-diversity", "off",
            "--tamper-density", "off", "--no-integrity", "--no-bytecode-trampoline",
        )
        disabled_flags = disabled.get("feature_flags") or {}
        unexpected = [name for name in (
            "physical_block_shuffle", "control_flow_flattening", "opaque_branches", "instruction_substitution",
            "handler_topology_randomized", "safe_decoy_prototypes", "encrypted_constant_fragments",
            "chained_integrity_checks", "per_block_lazy_decryption",
        ) if disabled_flags.get(name) is not False]
        if unexpected or disabled.get("integrity_checks") is not False or disabled.get("bytecode_trampoline") is not False:
            raise RuntimeError(f"disabled controls were reported as active: {unexpected} {disabled}")
        disabled_text = output.read_text(encoding="utf-8")
        if "loadstring" in disabled_text or SECRET in disabled_text:
            raise RuntimeError("disabled controls exposed source-bearing output")
        disabled_result = execute(args.runtime, output, temporary / "disabled-run")
        if disabled_result.returncode or MARKER not in disabled_result.stdout:
            raise RuntimeError(f"disabled-control artifact changed semantics: {disabled_result.stderr}")

        no_stage2 = compile_artifact(args.alexfuscator, source, output, report, "maximum", 993, "--no-stage2")
        no_stage2_flags = no_stage2.get("feature_flags") or {}
        if no_stage2_flags.get("per_block_lazy_decryption") is not False or no_stage2_flags.get("encrypted_constant_fragments") is not False:
            raise RuntimeError(f"--no-stage2 report claimed lazy encrypted structures: {no_stage2_flags}")

        notice = compile_artifact(
            args.alexfuscator, source, output, report, "maximum", 994, "--analysis-notice", "authorized analysis only",
        )
        if notice.get("analysis_notice") is not True or notice.get("analysis_notice_key_bound") is not False:
            raise RuntimeError(f"analysis notice was incorrectly security-bound: {notice}")

        owner_prefix = temporary / "owner-v5"
        run([
            str(args.alexfuscator), "--owner-keygen", str(owner_prefix), "--owner-id", "v5-test-owner", "--seed", "5151",
        ])
        owner_artifact = temporary / "owner-locked.luau"
        owner_descriptor = compile_artifact(
            args.alexfuscator, source, owner_artifact, report, "maximum", 5152,
            "--owner-protect", "sign-and-lock", "--owner-private-key", str(owner_prefix) + ".private",
            "--owner-id", "v5-test-owner",
        )
        if owner_descriptor.get("owner_protect") != "sign-and-lock" or owner_descriptor.get("owner_locked") is not True:
            raise RuntimeError(f"owner protection was not reported accurately: {owner_descriptor}")
        owner_result = execute(args.runtime, owner_artifact, temporary / "owner-run")
        if owner_result.returncode or MARKER not in owner_result.stdout:
            raise RuntimeError(f"owner-locked artifact changed semantics: {owner_result.stderr}")

        online_material = "fixture-online-material-v5"
        online = temporary / "online.luau"
        run([
            str(args.alexfuscator), str(source), "-o", str(online), "--profile", "maximum", "--runtime", "executor",
            "--environment-binding", "portable", "--key-mode", "online", "--online-key-url", "https://key.example/v2/value",
            "--online-key-material", online_material, "--seed", "7171", "--no-watermark",
        ])
        good_online = temporary / "online-good.luau"
        bad_online = temporary / "online-bad.luau"
        good_online.write_text(f'request=function(_) return {{Body="{online_material}"}} end\n' + online.read_text(encoding="utf-8"), encoding="utf-8")
        bad_online.write_text('request=function(_) return {Body="wrong-online-material-v5"} end\n' + online.read_text(encoding="utf-8"), encoding="utf-8")
        good = run([
            str(args.runtime), "--profile", "executor-client", "--luraph-mode", "off", "--analysis-hooks", "off",
            "--network-policy", "offline", "--out", str(temporary / "online-good-run"), str(good_online),
        ], check=False)
        bad = run([
            str(args.runtime), "--profile", "executor-client", "--luraph-mode", "off", "--analysis-hooks", "off",
            "--network-policy", "offline", "--out", str(temporary / "online-bad-run"), str(bad_online),
        ], check=False)
        if good.returncode or MARKER not in good.stdout:
            raise RuntimeError(f"online-key v5 success path failed: {good.stderr}")
        if MARKER in bad.stdout or bad.stderr.strip():
            raise RuntimeError(f"wrong online material did not produce a harmless decoy: {bad.stdout!r} {bad.stderr!r}")

        contract = temporary / "opiumware-contract.luau"
        run([
            str(args.alexfuscator), str(ROOT / "tests" / "opiumware_executor_contract.luau"), "-o", str(contract),
            "--profile", "maximum", "--runtime", "executor", "--environment-binding", "portable",
            "--seed", "991", "--no-watermark",
        ])
        contract_result = run([
            str(args.runtime), "--profile", "executor-client", "--luraph-mode", "off", "--analysis-hooks", "off",
            "--network-policy", "offline", "--out", str(temporary / "contract-run"), str(contract),
        ], check=False)
        if contract_result.returncode or "opiumware-contract-ok" not in contract_result.stdout:
            raise RuntimeError(f"Opiumware executor contract failed: {contract_result.stdout} {contract_result.stderr}")

        invalid = temporary / "invalid.luau"
        invalid.write_text("local =\n", encoding="utf-8")
        failed = run([str(args.alexfuscator), str(invalid), "-o", str(output), "--diagnostics-json"], check=False)
        diagnostic = json.loads(failed.stderr)
        if failed.returncode == 0 or diagnostic.get("error", {}).get("code") != "parse_error" or "location" not in diagnostic.get("error", {}):
            raise RuntimeError(f"structured parse diagnostic is invalid: {diagnostic}")
        removed = run([str(args.alexfuscator), str(source), "-o", str(output), "--legacy-vm", "--diagnostics-json"], check=False)
        removed_diagnostic = json.loads(removed.stderr)
        if removed.returncode == 0 or removed_diagnostic.get("error", {}).get("code") != "removed_option":
            raise RuntimeError(f"removed backend selector was accepted: {removed_diagnostic}")

    print(f"Register VM v5 structure OK: {args.seeds} Maximum seeds, authenticated tamper decoy, deterministic fixed seeds")


if __name__ == "__main__":
    main()
