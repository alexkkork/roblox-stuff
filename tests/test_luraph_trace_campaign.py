#!/usr/bin/env python3
"""Regression checks for the offline Luraph trace campaign utility."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "luraph_trace_campaign.py"
sys.path.insert(0, str(ROOT / "tools"))

from luraph_trace_campaign import CampaignError, run_campaign  # noqa: E402


def marker(marker_name: str, *fields: object) -> str:
    return "\t".join((marker_name, *(str(field) for field in fields)))


def structure(opcode_at_two: int = 16) -> list[str]:
    return [
        marker("@@LPH_PROTO_V1@@", 1, 3, "D,G,p"),
        marker("@@LPH_PROTO_OBJECT_V1@@", 1, 1001),
        marker("@@LPH_INSN_V1@@", 1, 1, 80, "D=n:1|G=n:0|p=n:2"),
        marker("@@LPH_INSN_V1@@", 1, 2, opcode_at_two, "D=n:2|G=n:0|p=n:3"),
        marker("@@LPH_INSN_V1@@", 1, 3, 188, "D=n:3|G=n:0|p=z:"),
        marker("@@LPH_PROTO_V1@@", 2, 1, "D,G,p"),
        marker("@@LPH_INSN_V1@@", 2, 1, 72, "D=n:1|G=n:0|p=z:"),
    ]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    source = TOOL.read_text(encoding="utf-8")
    for forbidden in ("requests", "urllib", "socket", "http.client"):
        require(forbidden not in source, f"network dependency leaked into tool: {forbidden}")

    with tempfile.TemporaryDirectory(prefix="luraph-trace-campaign-") as temporary:
        temp = pathlib.Path(temporary)
        first = temp / "first.log"
        second = temp / "second.jsonl"
        merged = temp / "merged.log"
        report_path = temp / "report.json"

        duplicate_step = marker("@@LPH_STEP_V1@@", 2, 1, 2, 16, 3, 0, "", "D=n:2")
        first.write_text(
            "runtime prelude ignored\n"
            + "\n".join(
                structure()
                + [
                    marker("@@LPH_STEP_V1@@", 1, 1, 1, 80, 2, 0, "", "D=n:1"),
                    duplicate_step,
                    duplicate_step,
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        json_records = [
            {"marker": line.split("\t", 1)[0], "fields": line.split("\t")[1:]}
            for line in structure()
        ]
        json_records.extend(
            (
                {"line": duplicate_step},
                {
                    "marker": "@@LPH_STEP_V1@@",
                    "fields": [3, 1, 3, 188, 4, 0, "", "D=n:3"],
                },
                {
                    "marker": "@@LPH_CALL_V2@@",
                    "fields": [3, 1, 0, 0, 0, 3, 188, 1, "print", 1, "s:6869"],
                },
            )
        )
        second.write_text(
            "\n".join(json.dumps(record, separators=(",", ":")) for record in json_records) + "\n",
            encoding="utf-8",
        )

        report = run_campaign(
            [first, second],
            merged,
            report_path,
            window_size=2,
        )
        merged_lines = merged.read_text(encoding="utf-8").splitlines()
        require(merged_lines[0].startswith("@@LPH_PROTO_V1@@"), "structure was not emitted first")
        require(merged_lines.count(duplicate_step) == 1, "duplicate marker survived the merge")
        require(report["merge"]["duplicates_removed"] == 9, "duplicate count drifted")
        require(report["structure"]["complete"] is True, "complete structure was not recognized")
        require(report["structure"]["consistent"] is True, "matching structure was rejected")
        require(report["structure"]["all_inputs_independently_validated"] is True, "full traces were not validated")
        require(report["structure"]["exact_shape_inputs"] == 2, "matching input hashes were not retained")
        require(report["structure"]["compatible_subset_inputs"] == 0, "full inputs were mislabeled as subsets")
        require(report["structure"]["prototypes"] == 2, "prototype coverage drifted")
        require(report["structure"]["instructions"] == 4, "instruction coverage drifted")
        require(len(report["structure"]["sha256"]) == 64, "structure hash is missing")
        require(report["guards"]["available"] is False, "old trace unexpectedly reported guard evidence")
        require(report["guards"]["records"] == 0, "empty guard summary is not backward compatible")
        require(report["guards"]["conflicts"]["count"] == 0, "empty guard summary reported conflicts")
        require(report["guard_paths"]["available"] is False, "old trace unexpectedly reported guard paths")
        require(report["guard_paths"]["records"] == 0, "empty guard-path summary is not backward compatible")
        require(
            report["guard_paths"]["conflicts"]["count"] == 0,
            "empty guard-path summary reported conflicts",
        )
        require(len(report["vm_windows"]["windows"]) == 2, "VM window count drifted")
        first_window = report["vm_windows"]["windows"][0]
        require(first_window["start"] == 1 and first_window["end"] == 2, "window alignment drifted")
        require(first_window["execution_vm_counts"] == 2, "execution coverage drifted")
        require(first_window["execution_coverage_ratio"] == 1.0, "window ratio drifted")
        require(json.loads(report_path.read_text(encoding="utf-8"))["offline"] is True, "offline claim missing")

        checked = temp / "checked.log"
        checked_report = temp / "checked.json"
        checked_result = run_campaign(
            [first],
            checked,
            checked_report,
            expected_structure_hash=report["structure"]["sha256"],
        )
        require(checked_result["structure"]["validated"] is True, "expected hash was not validated")

        partial = temp / "partial.log"
        partial.write_text(
            "\n".join(structure()[:3] + [marker("@@LPH_STEP_V1@@", 8, 1, 1, 80, 2, 0)]) + "\n",
            encoding="utf-8",
        )
        partial_result = run_campaign(
            [partial],
            temp / "partial-merged.log",
            temp / "partial-report.json",
        )
        require(partial_result["structure"]["complete"] is False, "partial structure was called complete")
        require(partial_result["structure"]["validated"] is False, "partial structure was called validated")

        subset = temp / "subset.log"
        subset.write_text(
            "\n".join(
                [
                    marker("@@LPH_PROTO_V1@@", 2, 1, "D,G,p"),
                    marker("@@LPH_INSN_V1@@", 2, 1, 72, "D=n:1"),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        subset_result = run_campaign(
            [first, subset],
            temp / "subset-merged.log",
            temp / "subset-report.json",
        )
        require(subset_result["structure"]["consistent"] is True, "compatible subset was rejected")
        require(subset_result["structure"]["compatible_subset_inputs"] == 1, "subset hash was not reported")
        require(
            subset_result["structure"]["all_inputs_independently_validated"] is False,
            "subset was claimed as an exact independent match",
        )

        conflicting = temp / "conflicting.log"
        conflicting.write_text("\n".join(structure(72)) + "\n", encoding="utf-8")
        try:
            run_campaign(
                [first, conflicting],
                temp / "bad.log",
                temp / "bad.json",
            )
        except CampaignError as error:
            require("conflicting opcodes" in str(error), "conflict error was not specific")
        else:
            raise AssertionError("conflicting structures were merged")

        jsonl_output = temp / "merged.jsonl"
        run_campaign([first], jsonl_output, temp / "jsonl-report.json", output_format="jsonl")
        decoded = [json.loads(line) for line in jsonl_output.read_text(encoding="utf-8").splitlines()]
        require(decoded[0]["marker"] == "@@LPH_PROTO_V1@@", "JSONL output is not normalized")

        guard_first = temp / "guard-first.log"
        guard_second = temp / "guard-second.jsonl"
        guard_merged = temp / "guard-merged.log"
        guard_report_path = temp / "guard-report.json"
        first_guard = marker(
            "@@LPH_GUARD_V1@@",
            10,
            3,
            51,
            149,
            "J=n:66",
            "O=s:token=value",
        )
        guard_first.write_text(
            "\n".join(
                [
                    marker("@@LPH_STEP_V1@@", 10, 3, 51, 149, 52, 0, "", "D=n:1"),
                    marker("@@LPH_STEP_V1@@", 11, 3, 51, 149, 52, 0, "", "D=n:1"),
                    first_guard,
                    first_guard,
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        guard_second_records = [
            {
                "marker": "@@LPH_GUARD_V1@@",
                "fields": [10, 3, 51, 149, "O=s:token=value", "J=n:66"],
            },
            {"marker": "@@LPH_GUARD_V1@@", "fields": [10, 3, 51, 149, "J=n:66"]},
            {"marker": "@@LPH_GUARD_V1@@", "fields": [10, 3, 51, 149, "J=n:65"]},
            {"marker": "@@LPH_GUARD_V1@@", "fields": [10, 3, 51, 73, "J=n:66"]},
            {"marker": "@@LPH_GUARD_V1@@", "fields": [11, 3, 51, 149, "J=n:65"]},
            {"marker": "@@LPH_GUARD_V1@@", "fields": [12, 3, 51, 149, "J=n:88"]},
        ]
        guard_second.write_text(
            "\n".join(json.dumps(record, separators=(",", ":")) for record in guard_second_records) + "\n",
            encoding="utf-8",
        )
        guard_report = run_campaign(
            [guard_first, guard_second],
            guard_merged,
            guard_report_path,
            window_size=10,
        )
        guard_lines = guard_merged.read_text(encoding="utf-8").splitlines()
        guard_lines = [line for line in guard_lines if line.startswith("@@LPH_GUARD_V1@@")]
        guards = guard_report["guards"]
        require(len(guard_lines) == 6, "guard semantic dedupe removed evidence or retained duplicates")
        require(guard_lines[0] == first_guard, "first guard row or pair order was not preserved")
        require(guards["available"] is True, "guard evidence was not reported")
        require(guards["input_records"] == 8, "guard input count drifted")
        require(guards["unique_records"] == 6, "reordered guard rows were not safely deduplicated")
        require(guards["duplicates_removed"] == 2, "guard duplicate count drifted")
        require(guard_report["merge"]["guard_duplicates_removed"] == 2, "merge guard duplicate count drifted")
        require(guards["unique_events"] == 3, "guard event coverage drifted")
        require(guards["unique_vm_counts"] == 3, "guard VM-count coverage drifted")
        require(guards["unique_sites"] == 2, "guard site coverage drifted")
        require(guards["unique_opcodes"] == 2, "guard opcode coverage drifted")
        require(guards["execution_vm_counts"] == 2, "guards incorrectly inflated execution coverage")
        require(guards["execution_vm_counts_with_guards"] == 2, "guard/execution overlap drifted")
        require(guards["execution_vm_count_coverage_ratio"] == 1.0, "guard coverage ratio drifted")
        require(guards["conflicts"]["binding_conflicts"] == 1, "binding conflict was not reported")
        require(guards["conflicts"]["opcode_conflicts"] == 1, "opcode conflict was not reported")
        require(guards["conflicts"]["count"] == 2, "guard conflict total drifted")
        require(guards["conflicts"]["examples_truncated"] is False, "small conflict set was truncated")
        require(
            guards["conflicts"]["examples"][0]["values"] == ["n:65", "n:66"],
            "binding conflict values were not deterministic",
        )
        require("O=s:token=value" in guard_lines[0], "guard value containing '=' was not preserved")
        guard_marker_summary = next(
            item for item in guard_report["marker_types"] if item["marker"] == "@@LPH_GUARD_V1@@"
        )
        require(guard_marker_summary["records"] == 6, "guard marker summary drifted")
        require(guard_marker_summary["unique_vm_counts"] == 3, "guard marker VM summary drifted")
        require(guard_report["vm_windows"]["windows"][0]["guards"]["records"] == 4, "window guard count drifted")

        guard_jsonl = temp / "guard-merged.jsonl"
        run_campaign(
            [guard_first, guard_second],
            guard_jsonl,
            temp / "guard-jsonl-report.json",
            output_format="jsonl",
        )
        decoded_guards = [
            row
            for line in guard_jsonl.read_text(encoding="utf-8").splitlines()
            if (row := json.loads(line))["marker"] == "@@LPH_GUARD_V1@@"
        ]
        require(len(decoded_guards) == 6, "JSONL guard output disagrees with TSV output")
        require(decoded_guards[0]["fields"][-1] == "O=s:token=value", "JSONL changed an opaque guard value")

        invalid_guards = {
            "missing binding": marker("@@LPH_GUARD_V1@@", 1, 1, 1, 1),
            "activation": marker("@@LPH_GUARD_V1@@", 1, 0, 1, 1, "J=n:1"),
            "missing '='": marker("@@LPH_GUARD_V1@@", 1, 1, 1, 1, "J"),
            "invalid name": marker("@@LPH_GUARD_V1@@", 1, 1, 1, 1, "1J=n:1"),
            "duplicate name": marker("@@LPH_GUARD_V1@@", 1, 1, 1, 1, "J=n:1", "J=n:1"),
        }
        for case, invalid_guard in invalid_guards.items():
            invalid_path = temp / f"invalid-{case.replace(' ', '-')}.log"
            invalid_path.write_text(invalid_guard + "\n", encoding="utf-8")
            try:
                run_campaign(
                    [invalid_path],
                    temp / f"invalid-{case.replace(' ', '-')}-merged.log",
                    temp / f"invalid-{case.replace(' ', '-')}-report.json",
                )
            except CampaignError:
                pass
            else:
                raise AssertionError(f"invalid guard row was accepted: {case}")

        many_conflicts = temp / "many-guard-conflicts.log"
        many_conflict_rows = []
        for vm_count_value in range(1, 102):
            many_conflict_rows.append(
                marker("@@LPH_GUARD_V1@@", vm_count_value, 1, 1, 149, "J=n:1")
            )
            many_conflict_rows.append(
                marker("@@LPH_GUARD_V1@@", vm_count_value, 1, 1, 149, "J=n:2")
            )
        many_conflicts.write_text("\n".join(many_conflict_rows) + "\n", encoding="utf-8")
        many_conflict_report = run_campaign(
            [many_conflicts],
            temp / "many-guard-conflicts-merged.log",
            temp / "many-guard-conflicts-report.json",
        )
        many_guard_summary = many_conflict_report["guards"]
        require(many_guard_summary["unique_records"] == 202, "contradictory guard evidence was discarded")
        require(many_guard_summary["conflicts"]["count"] == 101, "large conflict count drifted")
        require(len(many_guard_summary["conflicts"]["examples"]) == 100, "conflict example cap drifted")
        require(many_guard_summary["conflicts"]["examples_truncated"] is True, "conflict cap was not reported")
        require(
            many_guard_summary["conflicts"]["examples"][0]["vm_count"] == 1
            and many_guard_summary["conflicts"]["examples"][-1]["vm_count"] == 100,
            "conflict examples are not deterministically ordered",
        )

        guard_path_first = temp / "guard-path-first.log"
        guard_path_second = temp / "guard-path-second.jsonl"
        guard_path_merged = temp / "guard-path-merged.log"
        guard_path_report_path = temp / "guard-path-report.json"
        first_guard_path = marker(
            "@@LPH_GUARD_PATH_V1@@",
            20,
            4,
            70,
            117,
            2,
            0,
            "100:120:1|130:140:0",
        )
        guard_path_first.write_text(
            "\n".join(
                [
                    marker("@@LPH_STEP_V1@@", 20, 4, 70, 117, 71, 0, "", "D=n:1"),
                    marker("@@LPH_STEP_V1@@", 21, 4, 71, 118, 72, 0, "", "D=n:1"),
                    first_guard_path,
                    first_guard_path,
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        guard_path_second_records = [
            {"line": first_guard_path},
            {
                "marker": "@@LPH_GUARD_PATH_V1@@",
                "fields": [20, 4, 70, 117, 2, 0, "100:120:0|130:140:0"],
            },
            {
                "marker": "@@LPH_GUARD_PATH_V1@@",
                "fields": [20, 4, 70, 118, 2, 0, "100:120:1|130:140:0"],
            },
            {
                "marker": "@@LPH_GUARD_PATH_V1@@",
                "fields": [20, 4, 70, 117, 2, 0, "130:140:0|100:120:1"],
            },
            {
                "marker": "@@LPH_GUARD_PATH_V1@@",
                "fields": [21, 4, 71, 118, 1, 1, "200:220:1"],
            },
            {
                "marker": "@@LPH_GUARD_PATH_V1@@",
                "fields": [22, 5, 1, 72, 0, 0, ""],
            },
        ]
        guard_path_second.write_text(
            "\n".join(json.dumps(record, separators=(",", ":")) for record in guard_path_second_records)
            + "\n",
            encoding="utf-8",
        )
        guard_path_report = run_campaign(
            [guard_path_first, guard_path_second],
            guard_path_merged,
            guard_path_report_path,
            window_size=10,
        )
        guard_path_lines = [
            line
            for line in guard_path_merged.read_text(encoding="utf-8").splitlines()
            if line.startswith("@@LPH_GUARD_PATH_V1@@")
        ]
        guard_paths = guard_path_report["guard_paths"]
        require(len(guard_path_lines) == 6, "guard-path dedupe discarded evidence or retained duplicates")
        require(guard_path_lines[0] == first_guard_path, "first guard-path row was not preserved verbatim")
        require(
            any(line.endswith("130:140:0|100:120:1") for line in guard_path_lines),
            "ordered guard-path decisions were incorrectly normalized as a set",
        )
        require(guard_paths["available"] is True, "guard-path evidence was not reported")
        require(guard_paths["input_records"] == 8, "guard-path input count drifted")
        require(guard_paths["unique_records"] == 6, "guard-path canonical dedupe drifted")
        require(guard_paths["duplicates_removed"] == 2, "guard-path duplicate count drifted")
        require(
            guard_path_report["merge"]["guard_path_duplicates_removed"] == 2,
            "merge guard-path duplicate count drifted",
        )
        require(guard_paths["decision_observations"] == 9, "guard-path decision count drifted")
        require(guard_paths["unique_events"] == 3, "guard-path event coverage drifted")
        require(guard_paths["unique_vm_counts"] == 3, "guard-path VM-count coverage drifted")
        require(guard_paths["unique_sites"] == 4, "guard-path site coverage drifted")
        require(guard_paths["unique_opcodes"] == 3, "guard-path opcode coverage drifted")
        require(guard_paths["complete_paths"] == 5, "complete guard-path count drifted")
        require(guard_paths["overflow_paths"] == 1, "overflow guard-path count drifted")
        require(guard_paths["complete_path_ratio"] == 0.833333, "guard-path completion ratio drifted")
        require(guard_paths["unique_conditions"] == 3, "guard-path condition coverage drifted")
        require(
            guard_paths["conditions_with_both_outcomes"] == 1,
            "guard-path outcome diversity drifted",
        )
        require(guard_paths["execution_vm_counts"] == 2, "guard paths inflated execution coverage")
        require(
            guard_paths["execution_vm_counts_with_guard_paths"] == 2,
            "guard-path/execution overlap drifted",
        )
        require(
            guard_paths["execution_vm_count_coverage_ratio"] == 1.0,
            "guard-path execution coverage ratio drifted",
        )
        require(guard_paths["conflicts"]["path_conflicts"] == 1, "path conflict was not reported")
        require(guard_paths["conflicts"]["opcode_conflicts"] == 1, "path opcode conflict was not reported")
        require(guard_paths["conflicts"]["count"] == 2, "guard-path conflict total drifted")
        require(
            [
                window["guard_paths"]["records"]
                for window in guard_path_report["vm_windows"]["windows"]
            ]
            == [4, 2],
            "window guard-path count drifted",
        )
        require(
            guard_path_report["vm_windows"]["windows"][0]["execution_vm_counts"] == 2,
            "guard paths inflated window execution coverage",
        )

        guard_path_jsonl = temp / "guard-path-merged.jsonl"
        run_campaign(
            [guard_path_first, guard_path_second],
            guard_path_jsonl,
            temp / "guard-path-jsonl-report.json",
            output_format="jsonl",
        )
        decoded_guard_paths = [
            row
            for line in guard_path_jsonl.read_text(encoding="utf-8").splitlines()
            if (row := json.loads(line))["marker"] == "@@LPH_GUARD_PATH_V1@@"
        ]
        require(len(decoded_guard_paths) == 6, "JSONL guard-path output disagrees with TSV output")
        require(
            decoded_guard_paths[0]["fields"][-1] == "100:120:1|130:140:0",
            "JSONL changed ordered guard-path decisions",
        )
        require(decoded_guard_paths[-1]["fields"][-1] == "", "JSONL lost the empty zero-decision path")

        invalid_guard_paths = {
            "missing field": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 0, 0),
            "extra field": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 0, 0, "", "extra"),
            "zero vm count": marker("@@LPH_GUARD_PATH_V1@@", 0, 1, 1, 1, 0, 0, ""),
            "zero activation": marker("@@LPH_GUARD_PATH_V1@@", 1, 0, 1, 1, 0, 0, ""),
            "zero pc": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 0, 1, 0, 0, ""),
            "opcode range": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 256, 0, 0, ""),
            "decision limit": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 4097, 0, ""),
            "overflow range": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 0, 2, ""),
            "count mismatch": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 2, 0, "1:2:1"),
            "zero with entry": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 0, 0, "1:2:1"),
            "nonzero empty": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 1, 0, ""),
            "empty entry": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 2, 0, "1:2:1|"),
            "entry shape": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 1, 0, "1:2"),
            "empty range": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 1, 0, "2:2:1"),
            "reversed range": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 1, 0, "3:2:1"),
            "decision range": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 1, 0, "1:2:2"),
            "negative integer": marker("@@LPH_GUARD_PATH_V1@@", 1, 1, 1, 1, 1, 0, "-1:2:1"),
            "noncanonical integer": marker("@@LPH_GUARD_PATH_V1@@", "01", 1, 1, 1, 0, 0, ""),
        }
        for case, invalid_guard_path in invalid_guard_paths.items():
            invalid_path = temp / f"invalid-guard-path-{case.replace(' ', '-')}.log"
            invalid_path.write_text(invalid_guard_path + "\n", encoding="utf-8")
            try:
                run_campaign(
                    [invalid_path],
                    temp / f"invalid-guard-path-{case.replace(' ', '-')}-merged.log",
                    temp / f"invalid-guard-path-{case.replace(' ', '-')}-report.json",
                )
            except CampaignError:
                pass
            else:
                raise AssertionError(f"invalid guard-path row was accepted: {case}")

        help_result = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        require(help_result.returncode == 0, "CLI help failed")
        require("VM-count window" in help_result.stdout, "CLI help is missing its purpose")

    print(
        "Luraph trace campaign OK: merge, hashes, windows, guards, guard paths, JSONL, "
        "and conflict checks passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
