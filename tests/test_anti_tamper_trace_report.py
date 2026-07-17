#!/usr/bin/env python3
import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("anti_tamper_trace_report", ROOT / "tools" / "anti_tamper_trace_report.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class AntiTamperTraceReportTest(unittest.TestCase):
    def test_static_wyn_checks_are_named_from_evidence(self):
        source = """-- Protected by wYnFuscate:
        local fu=1675752813; fu=(fu*131+fm(fP,fG))%2147483647
        local fQ=((_ENV or _G)or{}); local fR=fk and fk(fQ)or nil; local fb=fR and fR.__index or nil
        local fh=os and os.clock; for f8=1,200000 do end; return dT>=2.5
        local d7=130+70; for Rs=1,d7 do local _=Rg[RE[RS(#RE)]..RS(d0)] end
        local RN=function()return function()end end; local ss=(RN()~=RN())
        if RU~=Ri then end; if v7[(17-7)*1000+408]~=(648-3)*100+65 then end
        if Gv<=248 then end; if Xz~=X2 or Xa~=X7 then VJ=1 end; if VJ~=0 then end
        """
        identifiers = {entry["id"] for entry in MODULE.classify_static_checks(source)}
        self.assertEqual(
            identifiers,
            {
                "hashed_global_resolution",
                "environment_topology",
                "timing_ratio",
                "random_environment_scan",
                "closure_identity",
                "container_topology",
                "vm_instruction_integrity",
            },
        )
        self.assertEqual(MODULE.detect_protector(source)["adapter"], "wynfuscate")

    def test_trace_separates_random_and_named_probes(self):
        events = [
            {"kind": "missing_global", "name": "12345"},
            {"kind": "missing_global", "name": "getgc"},
            {"kind": "missing_global", "name": "getgc"},
            {"kind": "api_call", "name": "game:GetService", "detail": "Players"},
        ]
        summary = MODULE.summarize_trace(events)
        self.assertEqual(summary["environment_reads"]["randomized"]["count"], 1)
        self.assertEqual(summary["environment_reads"]["named"][0], {"name": "getgc", "count": 2, "category": "debug_inspection"})
        self.assertEqual(summary["event_counts"]["api_call"], 1)

    def test_behavior_comparison_requires_protected_error_equivalence(self):
        runtime_report = {"status": "completed", "termination_reason": "completed", "returns": [], "typed_returns": [], "stdout": ["ok"], "stderr": []}
        errors = [{"normalized_sha256": "abc"}]
        self.assertTrue(MODULE.compare_behavior(runtime_report, dict(runtime_report), errors, list(errors))["equivalent"])
        self.assertFalse(MODULE.compare_behavior(runtime_report, dict(runtime_report), errors, [
            {"normalized_sha256": "different"}
        ])["equivalent"])

    def test_native_trace_counts_aggregated_environment_accesses(self):
        events = [
            {
                "kind": "trace_metadata",
                "schema": "rbx-native-environment-trace/v1",
                "active": True,
                "activation_clock_calls": 0,
                "accesses": 12,
                "unique_events": 3,
                "dropped": 0,
            },
            {
                "kind": "environment_access",
                "operation": "get_import",
                "scope": "script_environment",
                "key": "math",
                "key_type": "string",
                "value_type": "table",
                "hit": True,
                "count": 9,
            },
            {
                "kind": "environment_access",
                "operation": "get_table",
                "scope": "shared_global",
                "key": "getgc",
                "key_type": "string",
                "value_type": "nil",
                "hit": False,
                "count": 2,
            },
            {
                "kind": "environment_access",
                "operation": "raw_get",
                "scope": "closure_environment",
                "key": "1234",
                "key_type": "string",
                "value_type": "nil",
                "hit": False,
                "count": 1,
            },
        ]
        summary = MODULE.summarize_native_trace(events)
        self.assertEqual(summary["accesses"], 12)
        self.assertEqual(summary["unique_signatures"], 3)
        self.assertEqual(summary["hits"]["successful"]["accesses"], 9)
        self.assertEqual(summary["hits"]["missing"]["accesses"], 3)
        self.assertEqual(summary["randomized_missing_keys"], {"count": 1, "unique": 1})
        self.assertEqual(summary["named_missing_keys"][0]["key"], "getgc")
        self.assertEqual(summary["named_missing_keys"][0]["category"], "debug_inspection")
        self.assertTrue(summary["metadata_consistent"])


if __name__ == "__main__":
    unittest.main()
