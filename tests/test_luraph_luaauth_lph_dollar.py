#!/usr/bin/env python3
"""Regression coverage for the sanitized LuaAuth-wrapped LPH$ generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "luraph_luaauth" / "lph_dollar_generation.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def read_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_sanitized_subject(spec: dict) -> str:
    carrier = spec["carrier"]
    groups = int(carrier["radix85_group_count"])
    zero_groups = int(carrier["radix85_zero_group_count"])
    require(groups > zero_groups >= 0, "fixture carrier group counts are invalid")

    # Both encodings decode to four zero bytes. Mixing them preserves the
    # captured generation's exact radix-85 and zero-shorthand dimensions.
    encoded = "LPH$" + ("z" * zero_groups) + ("!!!!!" * (groups - zero_groups))
    require(len(encoded) == carrier["encoded_carrier_bytes"], "generated carrier length drifted")

    launcher = spec["launcher"]
    code = "1" * int(launcher["code_digit_count"])
    script_id = "sanitized_fixture_script_id_0000"
    require(len(script_id) == launcher["script_id_byte_count"], "sanitized script id length drifted")
    return (
        f"la_code={code};la_script_id='{script_id}'\n"
        "--[[ LuaAuth protected loader. https://luaauth.com ]]\n\n"
        "return({"
        "P=function(self)return function(...)return ... end end,"
        "readu8=function(s,i)return string.byte(s,i)end,"
        "readu32=function(s,i)return bit32.band(string.byte(s,i),255)end,"
        f"payload=[==[{encoded}]==]"
        "}):P()(...);"
    )


def sanitize_reference_subject(source: str, spec: dict) -> str:
    launcher = re.match(r"\Ala_code=(\d+);la_script_id='([^']*)'", source)
    require(launcher is not None, "reference subject is missing the expected LuaAuth launcher")
    require(
        len(launcher.group(1)) == spec["launcher"]["code_digit_count"],
        "reference launcher code length drifted",
    )
    require(
        len(launcher.group(2).encode("utf-8")) == spec["launcher"]["script_id_byte_count"],
        "reference launcher script id length drifted",
    )
    sanitized = (
        "la_code="
        + ("0" * len(launcher.group(1)))
        + ";la_script_id='"
        + ("x" * len(launcher.group(2)))
        + "'"
    )
    return sanitized + source[launcher.end() :]


def build_partial_trace(spec: dict) -> str:
    partial = spec["partial_trace"]
    declared = int(partial["declared_instruction_count"])
    observed = int(partial["observed_instruction_count"])
    require(0 < observed < declared, "partial trace must remain incomplete")

    lines = [
        f"@@LPH_PROTO_V1@@\t1\t{declared}\tD,G,p",
        "@@LPH_PROTO_OBJECT_V1@@\t1\t1001",
        "@@LPH_ACT_PROTO_V1@@\t1\t1\tnil\tnil\tnil\t0\t1\t\t0",
    ]
    for pc in range(1, observed + 1):
        opcode = (pc - 1) % 256
        next_pc = pc + 1
        lanes = f"D=n:{pc}|G=n:0|p=n:{next_pc}"
        lines.append(f"@@LPH_INSN_V1@@\t1\t{pc}\t{opcode}\t{lanes}")
        lines.append(
            f"@@LPH_STEP_V1@@\t{pc}\t1\t{pc}\t{opcode}\t{next_pc}\t0\t\t{lanes}"
        )
    return "\n".join(lines) + "\n"


def append_uleb(output: bytearray, value: int) -> None:
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        output.append(byte)
        if not value:
            return


def append_little(output: bytearray, value: int, width: int) -> None:
    output.extend(value.to_bytes(width, byteorder="little"))


def signed_fold(value: int) -> int:
    return (1 << 53) + value if value < 0 else value


def radix85_dollar_carrier(decoded: bytes) -> str:
    require(len(decoded) % 4 == 0, "structural carrier must contain complete radix-85 groups")
    encoded = []
    for offset in range(0, len(decoded), 4):
        value = int.from_bytes(decoded[offset : offset + 4], byteorder="little")
        digits = ["!"] * 5
        for index in range(4, -1, -1):
            digits[index] = chr(value % 85 + 33)
            value //= 85
        encoded.extend(digits)
    return "LPH$" + "".join(encoded)


def build_ambiguous_structural_subject() -> str:
    decoded = bytearray()
    append_uleb(decoded, 101 + 2)
    decoded.extend((0x5A, 0x21, 0xA1, 0x42, 0xB2))
    append_uleb(decoded, 203 + 2)

    append_uleb(decoded, 1)
    append_uleb(decoded, 4)
    append_uleb(decoded, 7)
    append_uleb(decoded, 8)
    for value in (1, 1, 10, 20):
        append_little(decoded, value, 4)
    append_uleb(decoded, 307 + 1)
    for word in (5, 1, -2, 3):
        append_uleb(decoded, signed_fold(word))

    append_uleb(decoded, 0)
    append_uleb(decoded, 9)
    append_uleb(decoded, 10)
    append_little(decoded, 0, 4)
    append_uleb(decoded, 307 + 1)
    for word in (112, -8, 9, 10):
        append_uleb(decoded, signed_fold(word))

    append_uleb(decoded, 2)
    decoded.extend((0xDE, 0xAD, 0xBE))
    while len(decoded) % 4:
        decoded.append(0xEF)
    carrier = radix85_dollar_carrier(decoded)
    return (
        "la_code=271828182;la_script_id='structural_schema_fixture'\n"
        "--[[ LuaAuth protected loader. https://luaauth.com ]]\n\n"
        "return({P=function(self)local state={} local runtime=buffer local words={1,2,3,4,5,6,7,8,9} "
        "state[7]=buffer.readu8 state[8]=buffer.readi16 state[11]=buffer.readu16 "
        "state[12]=buffer.readi32 state[13]=buffer.readu32 state[14]=buffer.readf32 "
        "state[15]=buffer.readf64 state[49]=buffer.readstring "
        "state[42]=function()return 0 end "
        "state[50]=function()local byte,total,factor=0,0,1 repeat byte=state[42]() "
        "total+=(byte>127 and byte-128 or byte)*factor factor*=128 until byte<=127 return total end "
        "local function constants()local count=state[50]()-101 if state[42]()~=0 then return end "
        "for index=1,count do local tag=state[42]() if tag<=12 then elseif tag<=34 then elseif tag<=56 then "
        "elseif tag<=78 then elseif tag<=90 then elseif tag<=123 then elseif tag<=210 then end end end "
        "local function prototypes()local count=state[50]()-203 local instructionCount=state[50]()-307 "
        "return count+instructionCount end local prototypeTable={} local root=prototypeTable[state[50]()] "
        f"constants() prototypes() return function(...)return root,... end end,payload=[========[{carrier}]========]"
        "}):P()(...);"
    )


def build_ambiguous_correspondence_trace() -> str:
    return "\n".join(
        (
            "@@LPH_PROTO_V1@@\t11\t1\tD,G,p",
            "@@LPH_PROTO_OBJECT_V1@@\t11\t1011",
            "@@LPH_PROTO_V1@@\t12\t1\tD,G,p",
            "@@LPH_PROTO_OBJECT_V1@@\t12\t1012",
            "",
        )
    )


def run_deobfuscator(
    deobfuscator: pathlib.Path,
    subject: pathlib.Path,
    output: pathlib.Path,
    report: pathlib.Path,
    trace: pathlib.Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict]:
    command = [
        str(deobfuscator),
        str(subject),
        "--output-dir",
        str(output),
        "--mode",
        "reconstruct",
        "--report",
        str(report),
    ]
    if trace is not None:
        command.extend(("--trace", str(trace)))
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    require(report.is_file(), f"deobfuscator did not write a report: {completed.stderr[-2000:]}")
    return completed, read_json(report)


def assert_source_withheld(report: dict, output: pathlib.Path, label: str) -> None:
    verification = report.get("verification") or {}
    artifacts = report.get("artifacts") or {}
    require(report.get("status") == "blocked", f"{label}: incomplete evidence was not blocked")
    require(report.get("exact_source") is False, f"{label}: exact source was falsely claimed")
    require(report.get("fallback_used") is False, f"{label}: a fallback was silently used")
    require(artifacts.get("source") is None, f"{label}: report exposed a source artifact")
    require(verification.get("source_claim_accepted") is False, f"{label}: source claim was accepted")
    require(not (output / "reconstructed.luau").exists(), f"{label}: reconstructed source was emitted")
    for candidate in (
        "payload_candidate.luau",
        "semantic_state_machine_candidate.luau",
        "semantic_readable_candidate.luau",
    ):
        require(not (output / candidate).exists(), f"{label}: unproven candidate {candidate} was emitted")


def assert_carrier_invariants(
    spec: dict,
    report: dict,
    output: pathlib.Path,
    *,
    decoded_sha256: str | None = None,
    expect_zero_stream: bool = True,
) -> None:
    expected = spec["carrier"]
    expected_hash = decoded_sha256 or expected["sanitized_decoded_sha256"]
    require(report.get("adapter") == "luraph-luaauth-lph-dollar", "LuaAuth LPH$ adapter was not selected")
    require(report.get("backend") == "native-cpp", "native deobfuscator backend was not used")

    envelope = read_json(output / "luraph_envelope_analysis.json")
    launcher = envelope.get("luaauth_launcher") or {}
    require(launcher.get("present") is True, "LuaAuth launcher was not detected")
    require(launcher.get("exact_assignment_shape") is True, "launcher assignment shape was not retained")
    require(launcher.get("metadata_removed_from_body") is True, "launcher metadata was not separated")
    require(launcher.get("values_retained") is False, "launcher identity leaked into analysis")
    require(launcher.get("code_digit_count") == spec["launcher"]["code_digit_count"], "code length drifted")
    require(
        launcher.get("script_id_byte_count") == spec["launcher"]["script_id_byte_count"],
        "script id length drifted",
    )

    static = envelope.get("static_decode") or {}
    require(static.get("eligible") is True and static.get("attempted") is True, "carrier decode was skipped")
    require(static.get("complete") is True, "carrier literal extraction was incomplete")
    require(static.get("carrier_candidates") == 1, "carrier candidate count drifted")
    require(static.get("carrier_attempts") == 1, "carrier attempt count drifted")
    require(static.get("carriers_decoded") == 1, "carrier decode count drifted")
    require(static.get("carrier_failures") == 0, "carrier decode unexpectedly failed")
    require(
        static.get("decoded_carrier_bytes") == expected["encoded_carrier_bytes"],
        "retained carrier byte count drifted",
    )

    metrics = envelope.get("container_metrics") or {}
    exact_metrics = {
        "candidate_count": 1,
        "attempt_count": 1,
        "decoded_count": 1,
        "parsed_count": 0,
        "failure_count": 0,
        "encoded_body_bytes": expected["encoded_body_bytes"],
        "radix85_group_count": expected["radix85_group_count"],
        "radix85_zero_group_count": expected["radix85_zero_group_count"],
        "decoded_bytes": expected["decoded_bytes"],
    }
    for key, value in exact_metrics.items():
        require(metrics.get(key) == value, f"container metric {key} drifted: {metrics.get(key)!r}")

    carriers = envelope.get("carriers") or []
    require(len(carriers) == 1, "decoded carrier record is missing")
    require(carriers[0].get("kind") == "lph_dollar", "carrier kind is not LPH$")
    require(carriers[0].get("literal_kind") == "long_bracket_string", "carrier literal kind drifted")
    require(carriers[0].get("decode_status") == "decoded_literal", "carrier literal did not decode")
    require(carriers[0].get("lph_marker_offset") == 0, "LPH$ marker offset drifted")

    containers = envelope.get("containers") or []
    require(len(containers) == 1, "decoded container record is missing")
    container = containers[0]
    require(container.get("marker") == "$", "decoded container marker drifted")
    require(container.get("decode_status") == "decoded", "container did not decode")
    expected_parse_status = "unsupported_schema" if expect_zero_stream else "structural_metadata_recovered"
    require(
        container.get("parse_status") == expected_parse_status,
        f"LPH$ parse status drifted: expected {expected_parse_status}",
    )
    require(
        container.get("decoded_sha256") == expected_hash,
        "decoded carrier content changed",
    )

    decoded = (output / "decoded_lph_container.bin").read_bytes()
    require(len(decoded) == expected["decoded_bytes"], "decoded artifact length drifted")
    require(hashlib.sha256(decoded).hexdigest() == expected_hash, "artifact hash drifted")
    if expect_zero_stream:
        require(not any(decoded), "sanitized carrier no longer decodes to the expected zero stream")


def assert_strict_partial_reporting(spec: dict, report: dict) -> None:
    expected = spec["partial_trace"]
    instructions = (report.get("coverage") or {}).get("instructions") or {}
    gaps = []
    if instructions.get("declared") != expected["declared_instruction_count"]:
        gaps.append(
            "coverage.instructions.declared does not retain the 25,215-instruction denominator"
        )
    if instructions.get("observed") != expected["observed_instruction_count"]:
        gaps.append("coverage.instructions.observed does not report the 268 captured rows")
    if instructions.get("total") != expected["declared_instruction_count"]:
        gaps.append("coverage.instructions.total reports observed rows instead of declared rows")
    if (report.get("coverage") or {}).get("semantic_lifting_complete") is not False:
        gaps.append("coverage.semantic_lifting_complete is absent or not explicitly false")

    schema_diagnostic = next(
        (
            item
            for item in report.get("diagnostics") or []
            if item.get("code") == "luraph_runtime_schema_bypass"
        ),
        {},
    )
    if "complete prototype objects" in schema_diagnostic.get("message", ""):
        gaps.append("partial runtime-schema diagnostic describes incomplete objects as complete")
    require(not gaps, "strict partial-coverage reporting gaps:\n- " + "\n- ".join(gaps))


def assert_ambiguous_prototype_correspondence(report: dict, output: pathlib.Path) -> None:
    envelope = read_json(output / "luraph_envelope_analysis.json")
    containers = envelope.get("containers") or []
    require(len(containers) == 1, "structural LPH$ fixture did not retain exactly one container")
    require(
        containers[0].get("parse_status") == "structural_metadata_recovered",
        "prototype correspondence fixture did not reach StructuralMetadataRecovered",
    )

    artifacts = report.get("artifacts") or {}
    require(
        artifacts.get("prototype_correspondence") == "prototype_correspondence.json",
        "structural metadata was not accepted for prototype correspondence",
    )
    correspondence = read_json(output / "prototype_correspondence.json")
    require(correspondence.get("status") == "partial", "ambiguous correspondence was not partial")
    require(correspondence.get("complete") is False, "ambiguous correspondence was falsely complete")
    require(
        correspondence.get("selected_container_index") is None,
        "an incomplete correspondence selected a static container",
    )
    require(
        correspondence.get("complete_container_match_count") == 0,
        "incomplete runtime evidence produced a complete container match",
    )

    container_reports = correspondence.get("containers") or []
    require(len(container_reports) == 1, "structural correspondence report omitted its container")
    container = container_reports[0]
    require(container.get("container_index") == 0, "structural correspondence index drifted")
    require(container.get("static_evidence_valid") is True, "structural static evidence was rejected")
    require(container.get("runtime_evidence_valid") is True, "bounded runtime evidence was rejected")
    require(container.get("complete") is False, "ambiguous container was falsely complete")
    require(container.get("matched") == 0, "incomplete evidence produced a prototype mapping")
    require(container.get("ambiguous") == 2, "ambiguous prototype count was not preserved")
    require(container.get("unmatched") == 0, "compatible ambiguous prototypes were marked unmatched")
    require(container.get("ambiguity_preserved") is True, "ambiguity preservation was not reported")

    matches = container.get("matches") or []
    require(len(matches) == 2, "runtime prototype correspondence rows are missing")
    for match in matches:
        runtime_id = match.get("runtime_id")
        require(match.get("status") == "ambiguous", f"runtime prototype {runtime_id} was guessed")
        require(
            match.get("static_metadata_index") is None and match.get("static_wrapper_index") is None,
            f"runtime prototype {runtime_id} exposed an unproven mapping",
        )
        require(match.get("proof") == [], f"runtime prototype {runtime_id} exposed a mapping proof")
        require(
            [candidate.get("metadata_index") for candidate in match.get("candidates") or []] == [0, 1],
            f"runtime prototype {runtime_id} did not retain both static candidates",
        )

    correspondence_pass = next(
        (item for item in report.get("passes") or [] if item.get("stage") == "prototype_correspondence"),
        {},
    )
    require(correspondence_pass.get("ok") is False, "partial correspondence pass was marked successful")
    require(correspondence_pass.get("ambiguity_preserved") is True, "report pass hid ambiguity")
    require(correspondence_pass.get("selected_container_index") is None, "report pass claimed a mapping")


def assert_partial_trace(
    spec: dict,
    static_report: dict,
    report: dict,
    output: pathlib.Path,
    *,
    strict_reporting: bool,
) -> None:
    expected = spec["partial_trace"]
    observed = expected["observed_instruction_count"]
    declared = expected["declared_instruction_count"]
    coverage = report.get("coverage") or {}
    runtime = coverage.get("runtime_decode") or {}
    static_runtime = (static_report.get("coverage") or {}).get("runtime_decode") or {}

    require(static_runtime.get("available") is False, "static run fabricated runtime evidence")
    require(runtime.get("available") is True, "semantic trace did not enable runtime evidence")
    require(runtime.get("complete") is False, "268/25,215 evidence was falsely marked complete")
    require(runtime.get("prototypes") == expected["prototype_count"], "partial prototype count drifted")
    require(runtime.get("instructions") == observed, "partial instruction count drifted")
    require(runtime.get("observed_steps") == expected["observed_step_count"], "partial step count drifted")
    require(runtime.get("semantic_lifted") == 0, "unresolved opcode handlers were falsely lifted")
    require(runtime.get("semantic_unresolved") == declared, "declared unresolved semantic count drifted")
    require(runtime.get("trace_specialized_sites") == observed, "trace specialization did not retain every site")
    require(runtime.get("trace_specialized_is_path_specific") is True, "path-specific evidence lost its label")
    require(coverage.get("runtime_prototype_schema_recovered") is True, "runtime schema evidence was discarded")
    require(coverage.get("static_serialized_schema_recovered") is False, "static LPH$ schema was falsely recovered")

    observed_cfg = coverage.get("observed_cfg") or {}
    require(observed_cfg.get("available") is True, "observed CFG was not built")
    require(observed_cfg.get("complete") is False, "partial observed CFG was falsely marked complete")
    require(observed_cfg.get("nodes") == observed, "observed CFG node count drifted")
    require(observed_cfg.get("observed_steps") == observed, "observed CFG step count drifted")

    prototypes = read_json(output / "runtime_prototypes.json")
    require(prototypes.get("complete") is False, "partial prototype artifact was falsely complete")
    require(prototypes.get("malformed_rows") == 0, "valid trace rows were marked malformed")
    require(prototypes.get("prototype_count") == 1, "runtime prototype artifact count drifted")
    require(prototypes.get("instruction_count") == observed, "runtime artifact instruction count drifted")
    require(prototypes.get("step_count") == observed, "runtime artifact step count drifted")
    prototype = prototypes["prototypes"][0]
    require(prototype.get("declared_instruction_count") == declared, "declared instruction total was lost")
    require(prototype.get("observed_instruction_count") == observed, "observed instruction total was lost")
    require(prototype.get("complete") is False, "partial prototype row was falsely complete")

    semantic = read_json(output / "runtime_semantic_ir.json")
    require(semantic.get("instruction_count") == observed, "semantic IR instruction count drifted")
    require(semantic.get("observed_step_count") == observed, "semantic IR step count drifted")
    require(semantic.get("trace_specialized_instructions") == observed, "semantic trace evidence was dropped")
    require(semantic.get("trace_effect_classified_instructions") == observed, "observed effects were not classified")
    require(semantic.get("observed_semantic_coverage") == observed, "observed semantic coverage drifted")
    require(semantic.get("unresolved_instructions") == observed, "static uncertainty was hidden")
    require(semantic.get("semantic_lifted_instructions") == 0, "path evidence was mislabeled static semantics")

    diagnostics = {item.get("code") for item in report.get("diagnostics") or []}
    for code in (
        "luraph_runtime_prototypes_partial",
        "luraph_runtime_schema_bypass",
        "luraph_semantic_lift_incomplete",
    ):
        require(code in diagnostics, f"missing partial-evidence diagnostic {code}")

    semantic_pass = next(
        (item for item in report.get("passes") or [] if item.get("stage") == "semantic_classify"),
        {},
    )
    require(semantic_pass.get("ok") is True, "trace-specialized semantic evidence was not acknowledged")
    require(semantic_pass.get("trace_specialized_sites") == observed, "semantic pass specialization count drifted")
    if strict_reporting:
        assert_strict_partial_reporting(spec, report)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    parser.add_argument(
        "--reference-subject",
        type=pathlib.Path,
        help="optional local sample; launcher values are replaced before analysis",
    )
    parser.add_argument(
        "--require-complete-reporting",
        action="store_true",
        help="fail on known top-level 268/25,215 coverage-reporting gaps",
    )
    args = parser.parse_args()
    spec = read_json(FIXTURE)

    with tempfile.TemporaryDirectory(prefix="luraph-luaauth-lph-dollar-") as temporary:
        root = pathlib.Path(temporary)
        subject = root / "sanitized_subject.luau"
        trace = root / "partial_semantic_trace.log"
        subject.write_text(build_sanitized_subject(spec), encoding="utf-8")
        trace.write_text(build_partial_trace(spec), encoding="utf-8")

        static_output = root / "static"
        static_completed, static_report = run_deobfuscator(
            args.deobfuscator.resolve(), subject, static_output, root / "static-report.json"
        )
        require(static_completed.returncode == 2, f"static boundary returned {static_completed.returncode}")
        assert_source_withheld(static_report, static_output, "static carrier")
        assert_carrier_invariants(spec, static_report, static_output)

        if args.reference_subject is not None:
            reference_spec = spec["local_reference"]
            reference_source = args.reference_subject.read_text(encoding="utf-8")
            require(
                len(reference_source.encode("utf-8")) == reference_spec["source_bytes"],
                "local reference source length drifted",
            )
            sanitized_reference = sanitize_reference_subject(reference_source, spec)
            require(len(sanitized_reference) == len(reference_source), "launcher sanitization changed offsets")
            reference_subject = root / "sanitized_local_reference.luau"
            reference_subject.write_text(sanitized_reference, encoding="utf-8")
            reference_output = root / "reference"
            reference_completed, reference_report = run_deobfuscator(
                args.deobfuscator.resolve(),
                reference_subject,
                reference_output,
                root / "reference-report.json",
            )
            require(reference_completed.returncode == 2, "local reference crossed the recovery boundary")
            assert_source_withheld(reference_report, reference_output, "sanitized local reference")
            assert_carrier_invariants(
                spec,
                reference_report,
                reference_output,
                decoded_sha256=reference_spec["decoded_sha256"],
                expect_zero_stream=False,
            )
            require(
                (reference_report.get("launcher") or {}).get("protected_body_bytes")
                == reference_spec["protected_body_bytes"],
                "local reference protected-body length drifted",
            )

        traced_output = root / "traced"
        traced_completed, traced_report = run_deobfuscator(
            args.deobfuscator.resolve(), subject, traced_output, root / "traced-report.json", trace
        )
        require(traced_completed.returncode == 2, f"partial trace boundary returned {traced_completed.returncode}")
        assert_source_withheld(traced_report, traced_output, "partial runtime trace")
        assert_carrier_invariants(spec, traced_report, traced_output)
        assert_partial_trace(
            spec,
            static_report,
            traced_report,
            traced_output,
            strict_reporting=args.require_complete_reporting,
        )

        correspondence_subject = root / "ambiguous_structural_subject.luau"
        correspondence_trace = root / "ambiguous_correspondence_trace.log"
        correspondence_subject.write_text(build_ambiguous_structural_subject(), encoding="utf-8")
        correspondence_trace.write_text(build_ambiguous_correspondence_trace(), encoding="utf-8")
        correspondence_output = root / "prototype-correspondence"
        correspondence_completed, correspondence_report = run_deobfuscator(
            args.deobfuscator.resolve(),
            correspondence_subject,
            correspondence_output,
            root / "prototype-correspondence-report.json",
            correspondence_trace,
        )
        require(
            correspondence_completed.returncode == 2,
            f"prototype correspondence boundary returned {correspondence_completed.returncode}",
        )
        assert_source_withheld(
            correspondence_report, correspondence_output, "ambiguous prototype correspondence"
        )
        assert_ambiguous_prototype_correspondence(correspondence_report, correspondence_output)

    print(
        "LuaAuth LPH$ regression OK: exact carrier framing decoded; "
        "268/25,215 runtime evidence retained as partial, and ambiguous prototype correspondence withheld"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
