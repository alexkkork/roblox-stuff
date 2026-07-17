#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"


def run(command: list[str], timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


class LuraphSemanticNameTests(unittest.TestCase):
    runtime: pathlib.Path
    temporary: tempfile.TemporaryDirectory[str]
    harness: pathlib.Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime = pathlib.Path(ARGS.runtime).resolve()
        if not cls.runtime.is_file():
            raise RuntimeError(f"runtime not found: {cls.runtime}")

        cls.temporary = tempfile.TemporaryDirectory(prefix="alex-luraph-semantic-names-")
        cls.addClassCleanup(cls.temporary.cleanup)
        temporary = pathlib.Path(cls.temporary.name)
        harness_source = temporary / "semantic_names_harness.cpp"
        cls.harness = temporary / "semantic_names_harness"
        harness_source.write_text(
            r'''#include "passes/names.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main(int argc, char** argv)
{
    if (argc != 2)
        return 2;
    std::ifstream input(argv[1], std::ios::binary);
    if (!input)
        return 3;
    const std::string source((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    const alex::deobfuscator::ResidualBindingRenameResult result =
        alex::deobfuscator::renameResidualBindings(source);
    if (!result.committed)
        return 4;
    std::cout << result.source;
    return 0;
}
''',
            encoding="utf-8",
        )

        compiler = os.environ.get("CXX", "c++")
        build = run(
            [
                compiler,
                "-std=c++20",
                "-O2",
                f"-I{ROOT / 'src' / 'deobfuscator'}",
                f"-I{ROOT / 'vendor' / 'luau' / 'Ast' / 'include'}",
                f"-I{ROOT / 'vendor' / 'luau' / 'Common' / 'include'}",
                str(harness_source),
                str(ROOT / "src" / "deobfuscator" / "passes" / "names.cpp"),
                str(BUILD / "vendor" / "luau" / "libLuau.Ast.a"),
                str(BUILD / "vendor" / "luau" / "libLuau.Common.a"),
                "-o",
                str(cls.harness),
            ],
            timeout=180,
        )
        if build.returncode != 0:
            raise RuntimeError(f"semantic name harness build failed\n{build.stdout}\n{build.stderr}")

    def rewrite(self, source: pathlib.Path) -> str:
        result = run([str(self.harness), str(source)], timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def execute(self, source: pathlib.Path, label: str) -> dict[str, object]:
        report = source.parent / f"{label}.json"
        result = run(
            [
                str(self.runtime),
                "--profile",
                "executor-client",
                "--network-policy",
                "offline",
                "--clock",
                "virtual",
                "--analysis-hooks",
                "off",
                "--timeout",
                "5",
                "--report",
                str(report),
                str(source),
            ],
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(report.is_file())
        return json.loads(report.read_text(encoding="utf-8"))

    def test_usage_based_names_are_deterministic_conservative_and_equivalent(self) -> None:
        root = pathlib.Path(self.temporary.name)
        source = root / "semantic-name-input.luau"
        source.write_text(
            '''local delta_time = "outer"
local heartbeat_signal = {}

function heartbeat_signal:Connect(callback)
    return callback(0.25)
end

local function function_1(argument_1)
    local local_1 = argument_1 * 2
    return local_1
end

local function_2 = function(argument_2)
    return function_1(argument_2)
end

local function function_3(argument_3)
    if type(argument_3) == "table" then
        return argument_3.Name
    end
    return argument_3 + 1
end

heartbeat_signal:Connect(function_2)
return function_1(3), function_3(4), delta_time
''',
            encoding="utf-8",
        )

        rewritten_text = self.rewrite(source)
        self.assertIn("local function calculate_number(number)", rewritten_text)
        self.assertIn("local on_heartbeat = function(delta_time_2)", rewritten_text)
        self.assertIn("heartbeat_signal:Connect(on_heartbeat)", rewritten_text)
        self.assertIn("argument_3", rewritten_text, "conflicting evidence must retain the generated parameter")
        self.assertNotIn("function_1", rewritten_text)
        self.assertNotIn("function_2", rewritten_text)

        rewritten = root / "semantic-name-rewritten.luau"
        rewritten.write_text(rewritten_text, encoding="utf-8")
        self.assertEqual(self.rewrite(rewritten), rewritten_text, "semantic naming must be idempotent")

        original_report = self.execute(source, "original")
        rewritten_report = self.execute(rewritten, "rewritten")
        self.assertEqual(original_report.get("returns"), [6, 5, "outer"])
        self.assertEqual(rewritten_report.get("returns"), original_report.get("returns"))
        self.assertEqual(rewritten_report.get("stdout"), original_report.get("stdout"))
        self.assertEqual(rewritten_report.get("stderr"), original_report.get("stderr"))
        self.assertEqual(rewritten_report.get("termination_reason"), original_report.get("termination_reason"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True)
    ARGS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__, *remaining])
