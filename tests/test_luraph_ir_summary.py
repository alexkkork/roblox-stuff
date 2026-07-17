#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import luraph_ir_summary as summary_tool  # noqa: E402


def semantic_fixture() -> dict[str, object]:
    return {
        "version": 1,
        "kind": "luraph-runtime-semantic-dispatch-ir",
        "scope": "small-test-fixture",
        "instruction_count": 7,
        "declared_instruction_count": 8,
        "semantic_coverage_partition": {
            "available": True,
            "total": 8,
            "declared_total": 8,
            "materialized_total": 7,
            "static_semantic": 2,
            "runtime_validated_observational_semantic": 1,
            "trace_evidence_only": 1,
            "unresolved": 4,
            "partition_sum": 8,
            "disjoint": True,
            "partition_complete": True,
        },
        "prototypes": [
            {
                "runtime_id": 10,
                "instructions": [
                    {
                        "pc": 1,
                        "opcode": 7,
                        "semantic_coverage_class": "static_semantic",
                        "semantic_operation": {"kind": "register_write"},
                        "observational_semantic_operation": {"kind": "move"},
                        "trace_specialized_operation": {
                            "kind": "trace_specialized_instruction",
                            "observations": [{"large": [1, 2, 3]}],
                        },
                    },
                    {
                        "pc": 2,
                        "opcode": 7,
                        "semantic_operation": None,
                        "observational_semantic_operation": {
                            "kind": "move",
                            "path_specific": True,
                        },
                        "trace_specialized_operation": {
                            "kind": "trace_specialized_instruction"
                        },
                    },
                    {
                        "pc": 3,
                        "opcode": 9,
                        "semantic_operation": None,
                        "observational_semantic_operation": None,
                        "trace_specialized_operation": {
                            "kind": "trace_specialized_instruction"
                        },
                    },
                    {
                        "pc": 4,
                        "opcode": 9,
                        "semantic_operation": None,
                        "unresolved_reason": "missing_lane",
                    },
                    {
                        "pc": 5,
                        "opcode": 9,
                        "semantic_operation": {
                            "kind": "unresolved",
                            "reason": "lane",
                        },
                    },
                ],
            },
            {
                # Keep the identifier after instructions to exercise order independence.
                "instructions": [
                    {
                        "pc": 1,
                        "opcode": 3,
                        "semantic_coverage_class": "unresolved",
                        "selection_status": "missing",
                    },
                    {
                        "pc": 2,
                        "opcode": 3,
                        "semantic_operation": {"kind": "return"},
                    },
                ],
                "runtime_id": 20,
            },
        ],
        "activations": [{"activation": 1, "payload": {"ignored": [1, 2, 3]}}],
        "observed_steps": [
            {
                "activation": 1,
                "register_writes": [
                    {"register": 1, "value": {"type": "string", "value": "skip me"}}
                ],
            }
        ],
    }


def cfg_fixture() -> dict[str, object]:
    return {
        "version": 1,
        "kind": "luraph-payload-cfg",
        "scope": "small-test-fixture",
        "prototype_count": 2,
        "instruction_count": 7,
        "reachable_instructions": 6,
        "block_count": 3,
        "reachable_blocks": 2,
        "edge_count": 2,
        "cyclic_regions": 1,
        "irreducible_regions": 1,
        "invalid_edges": 1,
        "reachable_invalid_edges": 0,
        "observed_edge_sites": 2,
        "prototypes": [
            {
                "runtime_id": 10,
                "instruction_count": 5,
                "reachable_instructions": 4,
                "block_count": 2,
                "reachable_blocks": 1,
                "edge_count": 1,
                "cyclic_regions": 1,
                "irreducible_regions": 1,
                "invalid_edges": 1,
                "reachable_invalid_edges": 0,
                "observed_edge_sites": 1,
                "blocks": [
                    {
                        "id": "p10_b1",
                        "successors": ["p10_b2"],
                        "evidence": {"ignored": [1, 2, 3]},
                    }
                ],
            },
            {
                "runtime_id": 20,
                "instruction_count": 2,
                "reachable_instructions": 2,
                "block_count": 1,
                "reachable_blocks": 1,
                "edge_count": 1,
                "cyclic_regions": 0,
                "irreducible_regions": 0,
                "invalid_edges": 0,
                "reachable_invalid_edges": 0,
                "observed_edge_sites": 1,
                "blocks": [],
            },
        ],
    }


def report_fixture(*, accepted: bool = False) -> dict[str, object]:
    return {
        "status": "reconstructed" if accepted else "blocked",
        "exact_source": accepted,
        "artifacts": {
            "source": "reconstructed.luau" if accepted else None,
            "candidate": None,
            "semantic_candidate": "candidate.luau",
        },
        "coverage": {"large_ignored_section": [{"value": index} for index in range(10)]},
        "verification": {
            "source_claim_accepted": accepted,
            "semantic_lift_verified": accepted,
            "candidate": {
                "available": False,
                "compiled": False,
                "differentially_verified": False,
                "source_claim": False,
            },
            "semantic_candidate": {
                "available": True,
                "compiled": True,
                "differentially_verified": accepted,
                "fully_rendered": accepted,
                "source_claim": accepted,
            },
        },
    }


class BoundedReadStream(io.StringIO):
    def __init__(self, value: str, maximum: int) -> None:
        super().__init__(value)
        self.maximum = maximum
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> str:
        if size < 1 or size > self.maximum:
            raise AssertionError(f"unbounded or oversized read requested: {size}")
        self.read_sizes.append(size)
        return super().read(size)


class LuraphIrSummaryTests(unittest.TestCase):
    def test_semantic_classes_are_disjoint_and_grouped_by_prototype_opcode(self) -> None:
        encoded = json.dumps(semantic_fixture(), indent=2)
        result = summary_tool.summarize_semantic_stream(io.StringIO(encoded), top_unresolved=4)

        self.assertEqual(
            result["totals"],
            {
                "static_semantic": 2,
                "runtime_validated_observational_semantic": 1,
                "trace_evidence_only": 1,
                "unresolved": 3,
            },
        )
        self.assertEqual(result["materialized_total"], 7)
        self.assertIs(result["disjoint"], True)
        self.assertEqual(result["structurally_missing_unresolved"], 1)
        self.assertIs(result["declared_partition_consistent"], True)

        matrix = {
            (row["prototype"], row["opcode"]): row
            for row in result["by_prototype_opcode"]
        }
        self.assertEqual(
            matrix[(10, 7)]["classes"],
            {
                "static_semantic": 1,
                "runtime_validated_observational_semantic": 1,
                "trace_evidence_only": 0,
                "unresolved": 0,
            },
        )
        self.assertEqual(matrix[(10, 9)]["classes"]["unresolved"], 2)
        self.assertEqual(matrix[(20, 3)]["classes"]["static_semantic"], 1)

        top = result["top_unresolved_sites"]
        self.assertEqual(top[0]["prototype"], 10)
        self.assertEqual(top[0]["opcode"], 9)
        self.assertEqual(top[0]["occurrences"], 2)
        self.assertEqual(top[0]["sample_pcs"], [4, 5])

    def test_reader_uses_only_bounded_reads_and_skips_large_nested_values(self) -> None:
        chunk_size = 7
        stream = BoundedReadStream(json.dumps(semantic_fixture(), indent=2), chunk_size)
        result = summary_tool.summarize_semantic_stream(
            stream,
            top_unresolved=2,
            chunk_size=chunk_size,
        )

        self.assertEqual(result["materialized_total"], 7)
        self.assertGreater(len(stream.read_sizes), 10)
        self.assertEqual(set(stream.read_sizes), {chunk_size})

    def test_cfg_regions_and_source_claim_status_are_streamed(self) -> None:
        cfg = summary_tool.summarize_cfg_stream(
            io.StringIO(json.dumps(cfg_fixture(), indent=2)),
            chunk_size=11,
        )
        claim = summary_tool.summarize_report_stream(
            io.StringIO(json.dumps(report_fixture(), indent=2)),
            chunk_size=9,
        )

        self.assertEqual(cfg["totals"]["cyclic_regions"], 1)
        self.assertEqual(cfg["totals"]["irreducible_regions"], 1)
        self.assertEqual(cfg["totals"]["reachable_blocks"], 2)
        self.assertTrue(all(cfg["prototype_sums_match_totals"].values()))
        self.assertEqual([row["prototype"] for row in cfg["by_prototype"]], [10, 20])

        self.assertEqual(claim["claim_status"], "withheld")
        self.assertIs(claim["accepted"], False)
        self.assertIs(claim["exact_source"], False)
        self.assertIs(claim["consistent"], True)

    def test_accepted_source_claim_requires_and_reports_source_artifact(self) -> None:
        claim = summary_tool.summarize_report_stream(
            io.StringIO(json.dumps(report_fixture(accepted=True), indent=2)),
            chunk_size=5,
        )
        self.assertEqual(claim["claim_status"], "accepted")
        self.assertEqual(claim["source_artifact"], "reconstructed.luau")
        self.assertIs(claim["semantic_candidate_fully_rendered"], True)
        self.assertIs(claim["consistent"], True)

    def test_directory_cli_discovers_bundle_and_emits_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="luraph-ir-summary-test-") as temporary:
            directory = pathlib.Path(temporary)
            (directory / "runtime_semantic_ir.json").write_text(
                json.dumps(semantic_fixture(), indent=2), encoding="utf-8"
            )
            (directory / "cfg.json").write_text(
                json.dumps(cfg_fixture(), indent=2), encoding="utf-8"
            )
            (directory / "deobfuscation_report.json").write_text(
                json.dumps(report_fixture(), indent=2), encoding="utf-8"
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "luraph_ir_summary.py"),
                    str(directory),
                    "--top-unresolved",
                    "1",
                    "--chunk-size",
                    "13",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["semantic"]["materialized_total"], 7)
        self.assertEqual(len(result["semantic"]["top_unresolved_sites"]), 1)
        self.assertEqual(result["cfg"]["totals"]["cyclic_regions"], 1)
        self.assertEqual(result["source_claim"]["claim_status"], "withheld")


if __name__ == "__main__":
    unittest.main()
