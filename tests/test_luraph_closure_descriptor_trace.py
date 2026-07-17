#!/usr/bin/env python3
"""Validate bounded structural recovery of Luraph closure descriptors."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SUBJECT = ROOT / "tests" / "fixtures" / "luraph" / "subject_1b642e9523c1.luau"


def run_deobfuscator(deobfuscator: pathlib.Path, output: pathlib.Path, report: pathlib.Path,
                     trace: pathlib.Path | None = None) -> subprocess.CompletedProcess[str]:
    command = [
        str(deobfuscator), str(SUBJECT),
        "--output-dir", str(output),
        "--mode", "reconstruct",
        "--report", str(report),
    ]
    if trace is not None:
        command.extend(["--trace", str(trace)])
    return subprocess.run(
        command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deobfuscator", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="luraph-closure-descriptor-") as temporary:
        root = pathlib.Path(temporary)
        static_output = root / "static"
        static = run_deobfuscator(args.deobfuscator, static_output, root / "static-report.json")
        if static.returncode != 2:
            raise RuntimeError(f"static probe generation unexpectedly exited {static.returncode}:\n{static.stderr}")

        probe_source = (static_output / "structure_probe.luau").read_text(encoding="utf-8")
        if '__alex_lph_dump_nested(__alex_lph_value,"",0' in probe_source:
            raise RuntimeError("structure probe still recursively dumps complete descriptor tables")
        if ('rawget(__alex_lph_value,5)' not in probe_source
                or 'rawget(__alex_lph_value,9)' not in probe_source
                or '"/n:5"' not in probe_source):
            raise RuntimeError("structure probe no longer emits capture-only descriptor traces")

        trace = root / "trace.log"
        trace.write_text("\n".join([
            "@@LPH_PROTO_V1@@\t1\t2\tR,D",
            "@@LPH_PROTO_OBJECT_V1@@\t1\t101",
            "@@LPH_PROTO_V1@@\t2\t1\tR,D",
            "@@LPH_PROTO_OBJECT_V1@@\t2\t202",
            "@@LPH_PROTO_V1@@\t3\t1\tR,D",
            "@@LPH_PROTO_OBJECT_V1@@\t3\t303",
            "@@LPH_ACT_ARG_OBJECT_V1@@\t1\t1\t1\t700",
            "@@LPH_ACT_PROTO_V1@@\t1\t1\tnil\tnil\tnil\t2\t1\ts:6869|z:\t123",
            "@@LPH_ACT_ARG_TABLE_V1@@\t1\t1\t1\tn:3\tf:74726163656261636b",
            "@@LPH_ACT_ARG_TABLE_V1@@\t1\t1\t1\tn:4\tx:table",
            "@@LPH_ACT_ARG_TABLE_V1@@\t1\t1\t1\tn:4\tg:737472696e67",
            *[
                f"@@LPH_ACT_ARG_TABLE_V1@@\t1\t1\t1\tn:{1000 + index}\tn:{index}"
                for index in range(257)
            ],
            "@@LPH_ACT_ARG_TABLE_END_V1@@\t1\t1\t1\t1\t259",
            "@@LPH_CAPTURE_DOMAIN_V1@@\t1\t1\t1\t1\t0",
            "@@LPH_CAPTURE_VALUE_V1@@\t1\t1\t0\tx:table\tg:6465627567\t7",
            "@@LPH_CAPTURE_DOMAIN_V1@@\t2\t1\t1\t1\t0",
            "@@LPH_STEP_V1@@\t123\t1\t1\t77\t2\t1\t9=f:",
            "@@LPH_RETURN_V1@@\t124\t1\t1\t77\t3\t3\tn:1|z:|s:6869",
            "@@LPH_INSN_V1@@\t1\t1\t77\tR=n:40|D=x:table",
            "@@LPH_INSN_V1@@\t1\t2\t22\tR=n:50|D=x:table",
            "@@LPH_INSN_V1@@\t2\t1\t1\tR=z:|D=z:",
            "@@LPH_INSN_V1@@\t3\t1\t1\tR=z:|D=z:",
            "@@LPH_LANE_TOP_V1@@\t1\t1\tD\tn:4\tn:4",
            "@@LPH_LANE_TOP_V1@@\t1\t1\tD\tn:5\tt:303",
            "@@LPH_LANE_TOP_V1@@\t1\t1\tD\tn:9\tt:202",
            "@@LPH_LANE_TABLE_V1@@\t1\t1\tD\t1\t/n:5\tn:1\tt:304",
            "@@LPH_LANE_TABLE_V1@@\t1\t1\tD\t2\t/n:5/n:1\tn:2\tn:7",
            "@@LPH_LANE_TABLE_V1@@\t1\t1\tD\t2\t/n:5/n:1\tn:3\tn:0",
            "@@LPH_LANE_TOP_V1@@\t1\t2\tD\tn:4\tn:5",
            "@@LPH_LANE_TOP_V1@@\t1\t2\tD\tn:5\tt:305",
            "@@LPH_LANE_TOP_V1@@\t1\t2\tD\tn:9\tt:999",
            "@@LPH_LANE_TOP_V1@@\t2\t1\tD\tn:4\tn:6",
            "@@LPH_LANE_TOP_V1@@\t2\t1\tD\tn:5\tt:306",
            "@@LPH_LANE_TOP_V1@@\t2\t1\tD\tn:9\tt:303",
            "@@LPH_ACTIVATION@@\t125\t1\t0\t0\t0\t2",
            "@@LPH_CALL_V2@@\t126\t1\t0\t0\t0\t1\t77\t9\tprint\t1\ts:6869\tD",
            "hi",
            "@@LPH_VM@@\t127\t1\t0\t0\t0\t2\t22",
            "",
        ]), encoding="utf-8")

        output = root / "parsed"
        parsed_report_path = root / "parsed-report.json"
        parsed = run_deobfuscator(args.deobfuscator, output, parsed_report_path, trace)
        if parsed.returncode != 2:
            raise RuntimeError(f"descriptor parsing unexpectedly exited {parsed.returncode}:\n{parsed.stderr}")
        runtime_ir = json.loads((output / "runtime_prototypes.json").read_text(encoding="utf-8"))
        activation = runtime_ir["activations"][0]
        argument_entries = {
            entry["key"]["value"]: entry["value"]
            for entry in activation["argument_table_entries"]
        }
        if (activation["entry_vm_count"] != 123
                or activation["arguments"][0]["value"] != "hi"
                or activation["arguments"][1]["type"] != "nil"
                or argument_entries["3"]["name"] != "traceback"
                or argument_entries["4"]["type"] != "global_reference"
                or argument_entries["4"]["path"] != "string"
                or argument_entries["1256"]["value"] != "256"
                or activation["argument_objects"] != [{
                    "argument_index": 1,
                    "object_id": 700,
                }]
                or activation["argument_table_domains"] != [{
                    "argument_index": 1,
                    "complete": True,
                    "observed_entries": 259,
                }]):
            raise RuntimeError(f"activation argument evidence was not preserved: {activation}")
        capture_domain = next(
            row for row in runtime_ir["observed_capture_domains"]
            if row["prototype"] == 1
        )
        capture_value = capture_domain["values"]["0"]
        if (capture_domain["complete"] is not True or capture_domain["indices"] != [0]
                or capture_value["cell_slot"] != 7
                or capture_value["resolved_value"]["type"] != "global_reference"
                or capture_value["resolved_value"]["path"] != "debug"):
            raise RuntimeError(f"capture value evidence was not preserved: {capture_domain}")
        returned = runtime_ir["returns"][0]
        if (runtime_ir["return_count"] != 1 or returned["arity"] != 3
                or returned["captured"] != 3 or returned["complete"] is not True
                or returned["values"][0]["value"] != "1"
                or returned["values"][1]["type"] != "nil"
                or returned["values"][1]["value"] is not None
                or returned["values"][2]["value"] != "hi"):
            raise RuntimeError(f"return arity and nil-hole evidence was not preserved: {returned}")
        descriptors = {
            (descriptor["prototype"], descriptor["pc"]): descriptor
            for descriptor in runtime_ir["closure_descriptors"]
        }

        mutated = descriptors.get((1, 1))
        expected_capture = [{
            "capture_index": 0,
            "capture_kind": 0,
            "descriptor_index": 1,
            "kind_name": "open_register_cell",
            "slot": 7,
        }]
        if (not mutated or mutated["static_opcode"] != 77 or mutated["descriptor_lane"] != "D"
                or mutated["target_prototype"] != 2 or mutated["target_object_id"] != 202
                or mutated["destination_register"] != 9
                or mutated["destination_evidence"] != "observed_function_register_write"
                or mutated["captures"] != expected_capture
                or not mutated["complete"]):
            raise RuntimeError(f"structural non-22 closure descriptor was not recovered: {mutated}")

        unresolved = descriptors.get((1, 2))
        if (not unresolved or unresolved["target_object_id"] != 999
                or unresolved["target_prototype"] is not None or unresolved["complete"]):
            raise RuntimeError(f"unresolved closure target identity was not retained: {unresolved}")

        transitive = descriptors.get((2, 1))
        if (not transitive or transitive["target_prototype"] != 3
                or transitive["destination_register"] != 6
                or transitive["captures"] != [] or not transitive["complete"]):
            raise RuntimeError(f"transitive inactive closure descriptor was not recovered: {transitive}")

        activated_prototypes = {
            row["prototype"] for row in runtime_ir["activations"]
        }
        if activated_prototypes != {1}:
            raise RuntimeError(f"inactive closure targets unexpectedly had activations: {activated_prototypes}")

        payload_closure = json.loads(
            (output / "payload_closure_ir.json").read_text(encoding="utf-8")
        )
        payload_prototypes = {
            row["runtime_id"] for row in payload_closure["prototypes"]
        }
        if (payload_closure["activation_count"] != 1
                or payload_closure["activated_prototype_count"] != 1
                or payload_closure["closure_expanded_prototype_count"] != 2
                or payload_closure["closure_expansion_edge_count"] != 2
                or payload_closure["prototype_count"] != 3
                or payload_prototypes != {1, 2, 3}):
            raise RuntimeError(f"payload closure did not expand transitively: {payload_closure}")

        reachable = json.loads(
            (output / "payload_reachable_ir.json").read_text(encoding="utf-8")
        )
        reachable_prototypes = {
            row["runtime_id"] for row in reachable["prototypes"]
        }
        reachable_descriptors = {
            (row["prototype"], row["pc"]): row
            for row in reachable["closure_descriptors"]
        }
        if (reachable["prototype_count"] != 3
                or reachable_prototypes != {1, 2, 3}
                or reachable_descriptors[(2, 1)]["target_prototype"] != 3
                or not reachable_descriptors[(2, 1)]["complete"]):
            raise RuntimeError(f"reachable IR lost an inactive closure target: {reachable}")

        report = json.loads(parsed_report_path.read_text(encoding="utf-8"))
        payload_pass = next(
            row for row in report["passes"] if row["stage"] == "payload_slice"
        )
        if (payload_pass["activations"] != 1
                or payload_pass["activated_prototypes"] != 1
                or payload_pass["closure_expanded_prototypes"] != 2
                or payload_pass["closure_expansion_edges"] != 2
                or payload_pass["prototypes"] != 3):
            raise RuntimeError(f"payload slice report disagreed with its artifact: {payload_pass}")

    print("Luraph closure descriptor trace OK: structural and transitive inactive targets passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
