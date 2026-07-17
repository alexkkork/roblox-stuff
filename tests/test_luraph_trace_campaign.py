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

    print("Luraph trace campaign OK: merge, hashes, windows, JSONL, and conflict checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
