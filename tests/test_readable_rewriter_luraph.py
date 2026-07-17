#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build"


class LuraphReadableRewriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        build = subprocess.run(
            [
                "cmake",
                "--build",
                str(BUILD_DIR),
                "--target",
                "alex_deobfuscator",
                "--parallel",
                "2",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        if build.returncode != 0:
            raise RuntimeError(f"failed to build readable rewriter dependencies:\n{build.stdout}{build.stderr}")

        cls._temporary = tempfile.TemporaryDirectory(prefix="alex-luraph-readable-")
        cls.addClassCleanup(cls._temporary.cleanup)
        cls._root = pathlib.Path(cls._temporary.name)
        cls._harness = cls._root / "readable_rewriter_harness"
        nlohmann_include = BUILD_DIR / "_deps" / "nlohmann_json-src" / "include"
        compile_result = subprocess.run(
            [
                "c++",
                "-std=c++20",
                "-O2",
                "-DNDEBUG",
                f"-I{ROOT / 'src' / 'deobfuscator'}",
                f"-I{nlohmann_include}",
                str(ROOT / "tests" / "helpers" / "flow_harness.cpp"),
                str(ROOT / "src" / "deobfuscator" / "passes" / "flow.cpp"),
                str(ROOT / "src" / "deobfuscator" / "passes" / "names.cpp"),
                f"-I{ROOT / 'vendor' / 'luau' / 'Ast' / 'include'}",
                f"-I{ROOT / 'vendor' / 'luau' / 'Common' / 'include'}",
                str(BUILD_DIR / "vendor" / "luau" / "libLuau.Ast.a"),
                str(BUILD_DIR / "vendor" / "luau" / "libLuau.Common.a"),
                "-o",
                str(cls._harness),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        if compile_result.returncode != 0:
            raise RuntimeError(
                f"failed to compile readable rewriter harness:\n{compile_result.stdout}{compile_result.stderr}"
            )

    def rewrite(self, source: str) -> dict:
        fixture = self._root / f"{self._testMethodName}.luau"
        fixture.write_text(source, encoding="utf-8")
        result = subprocess.run(
            [str(self._harness), str(fixture), "--single-pass"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_bucketed_dispatcher_structures_as_one_cfg_region(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function bucketed(flag)
  local output = "A"
  local pc = 1
  while pc ~= nil do
    semantic_step(7, pc)
    local dispatch_bucket = math.floor((pc - 1) / 64)
    if dispatch_bucket == 0 then
      if pc == 1 then
        pc = 65
      else
        return nil
      end
    elseif dispatch_bucket == 1 then
      if pc == 65 then
        if flag then
          pc = 66
        else
          pc = 67
        end
      elseif pc == 66 then
        output ..= "B"
        pc = 68
      elseif pc == 67 then
        output ..= "C"
        pc = 68
      elseif pc == 68 then
        if true then
          pc = 69
        else
          pc = 70
        end
      elseif pc == 69 then
        pc = 71
      elseif pc == 70 then
        pc = 71
      elseif pc == 71 then
        return output
      else
        return nil
      end
    else
      return nil
    end
  end
  return nil
end

return bucketed(true), bucketed(false)
"""
        )

        rewritten = artifact["source"]
        metrics = artifact["metrics"]
        self.assertEqual(metrics["regions_found"], 1)
        self.assertEqual(metrics["regions_structured"], 1)
        self.assertEqual(metrics["blocks_structured"], 8)
        self.assertEqual(metrics["residual_state_machines"], 0)
        self.assertNotIn("local pc =", rewritten)
        self.assertNotIn("while pc ~= nil do", rewritten)
        self.assertNotIn("dispatch_bucket", rewritten)
        self.assertNotIn("semantic_step(7, pc)", rewritten)
        self.assertNotIn("if true then", rewritten)
        self.assertIn("if flag then", rewritten)
        self.assertIn('output ..= "B"', rewritten)
        self.assertIn('output ..= "C"', rewritten)

    def test_long_branch_condition_survives_terminator_removal(self) -> None:
        condition = "condition_name_that_is_longer_than_small_string_storage"
        artifact = self.rewrite(
            f"""local function semantic_step(_, _)
end

local function bucketed({condition})
  local pc = 1
  while pc ~= nil do
    semantic_step(7, pc)
    local dispatch_bucket = math.floor((pc - 1) / 64)
    if dispatch_bucket == 0 then
      if pc == 1 then
        if {condition} then
          pc = 2
        else
          pc = 3
        end
      elseif pc == 2 then
        return true
      elseif pc == 3 then
        return false
      else
        return nil
      end
    else
      return nil
    end
  end
  return nil
end

return bucketed(true)
"""
        )

        rewritten = artifact["source"]
        self.assertTrue(artifact["changed"])
        self.assertIn(f"if {condition} then", rewritten)
        rewritten.encode("utf-8")

    def test_replayed_transition_becomes_single_evaluation_branch(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function replay_activation_transition(_, _, _, _, _)
  return 2
end

local function bucketed(replay_positions)
  local pc = 1
  while pc ~= nil do
    semantic_step(7, pc)
    local dispatch_bucket = math.floor((pc - 1) / 64)
    if dispatch_bucket == 0 then
      if pc == 1 then
        pc = replay_activation_transition(replay_positions, 7, 1, {{2}, {3}}, 2)
      elseif pc == 2 then
        return true
      elseif pc == 3 then
        return false
      else
        return nil
      end
    else
      return nil
    end
  end
  return nil
end

return bucketed({})
"""
        )

        rewritten = artifact["source"]
        self.assertEqual(artifact["metrics"]["regions_structured"], 1)
        self.assertNotIn("while pc ~= nil do", rewritten)
        self.assertEqual(rewritten.count("replay_activation_transition(replay_positions, 7, 1"), 1)
        self.assertNotIn("local replay_target_1", rewritten)
        self.assertIn("if replay_activation_transition(replay_positions, 7, 1", rewritten)
        self.assertGreater(artifact["metrics"]["replay_targets_inlined"], 0)

    def test_repeated_replay_activations_are_compressed_after_structuring(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function expand_replay_runs(runs)
  local sequences = {}
  for _, run in ipairs(runs) do
    for _ = 1, run[1] do sequences[#sequences + 1] = run[2] end
  end
  return sequences
end

local function replay_activation_transition(_, _, _, _, _)
  return 2
end

local function bucketed(replay_positions)
  local pc = 1
  while pc ~= nil do
    semantic_step(7, pc)
    local dispatch_bucket = math.floor((pc - 1) / 64)
    if dispatch_bucket == 0 then
      if pc == 1 then
        pc = replay_activation_transition(replay_positions, 7, 1, {{2, 3}, {2, 3}, {2, 3}, {2, 3}, {2, 3}, {2, 3}, {2, 3}, {2, 3}, {2, 3}, {2, 3}, {2, 3}, {2, 3}}, 1)
      elseif pc == 2 then
        return true
      elseif pc == 3 then
        return false
      else
        return nil
      end
    else
      return nil
    end
  end
  return nil
end

return bucketed({})
"""
        )

        self.assertEqual(artifact["metrics"]["regions_structured"], 1)
        self.assertEqual(artifact["metrics"]["replay_sequences_compressed"], 1)
        self.assertEqual(artifact["metrics"]["replay_sequence_entries_collapsed"], 11)
        self.assertIn("expand_replay_runs({{12, {2, 3}}})", artifact["source"])

    def test_constant_arithmetic_transition_is_folded(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function bucketed()
  local pc = 1
  while pc ~= nil do
    semantic_step(7, pc)
    local dispatch_bucket = math.floor((pc - 1) / 64)
    if dispatch_bucket == 0 then
      if pc == 1 then
        pc = (1) + 1
      elseif pc == 2 then
        return "done"
      else
        return nil
      end
    else
      return nil
    end
  end
  return nil
end

return bucketed()
"""
        )

        self.assertEqual(artifact["metrics"]["regions_structured"], 1)
        self.assertNotIn("while pc ~= nil do", artifact["source"])
        self.assertIn('return "done"', artifact["source"])

    def test_natural_loop_preserves_implicit_terminal_exit(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function bucketed()
  local value = 0
  local pc = 1
  while pc ~= nil do
    semantic_step(7, pc)
    local dispatch_bucket = math.floor((pc - 1) / 64)
    if dispatch_bucket == 0 then
      if pc == 1 then
        value += 1
        if value < 3 then
          pc = 2
        else
          pc = 99
        end
      elseif pc == 2 then
        pc = 1
      else
        return nil
      end
    else
      return nil
    end
  end
  return nil
end

return bucketed()
"""
        )

        rewritten = artifact["source"]
        self.assertEqual(artifact["metrics"]["regions_structured"], 1)
        self.assertNotIn("while pc ~= nil do", rewritten)
        self.assertIn("while true do", rewritten)
        self.assertIn("break", rewritten)
        self.assertIn("return nil", rewritten)

    def test_scoped_inline_luraph_register_frame_is_scalarized(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2(captured_values, ...)
  local registers = {}
  registers[1] = 20
  registers[2] = registers[1] + 22
  return registers[2]
end

return recovered_routine_2({}, 1)
"""
        )

        rewritten = artifact["source"]
        self.assertGreater(artifact["metrics"]["register_table_slots_scalarized"], 0)
        self.assertNotIn("registers[", rewritten)
        self.assertNotIn("local registers", rewritten)
        self.assertIn("return (20 + 22)", rewritten)

    def test_captured_register_slot_stays_table_backed_during_partial_scalarization(self) -> None:
        artifact = self.rewrite(
            """local function capture_register_cell(open_cells, registers, slot)
  local cell = open_cells[slot]
  if not cell then cell = { [2] = slot, [3] = registers }; open_cells[slot] = cell end
  return cell
end

local function recovered_routine_2(captured_values, ...)
  local registers = {}
  local open_cells = {}
  local argument_count = select("#", ...)
  for argument_index = 1, argument_count do registers[argument_index] = select_value(argument_index, ...) end
  registers[1] = 20
  registers[5] = 22
  local cell = capture_register_cell(open_cells, registers, 5)
  return registers[1] + cell[3][cell[2]]
end

return recovered_routine_2({}, 1, 2, 3, 4, 5)
"""
        )

        rewritten = artifact["source"]
        self.assertGreater(artifact["metrics"]["register_table_slots_scalarized"], 0)
        self.assertIn("local registers", rewritten)
        self.assertIn("registers[5]", rewritten)
        self.assertNotIn("registers[1] = 20", rewritten)

    def test_bounded_clear_range_excludes_only_touched_register_slots(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2(captured_values, ...)
  local registers = {}
  registers[1] = 10
  registers[5] = 20
  local state = {}
  state.register_clear_range_3 = { from = 4, to = 6 }
  do
    local clear_range = state.register_clear_range_3
    if clear_range then
      for register_index = clear_range.from, clear_range.to do registers[register_index] = nil end
    end
  end
  return registers[1], registers[5]
end

return recovered_routine_2({})
"""
        )

        rewritten = artifact["source"]
        self.assertGreater(artifact["metrics"]["register_table_slots_scalarized"], 0)
        self.assertIn("local registers", rewritten)
        self.assertIn("registers[5]", rewritten)
        self.assertNotIn("registers[1] = 10", rewritten)

    def test_renamed_bounded_clear_range_keeps_other_slots_scalarizable(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2(captured_values, ...)
  local registers = {}
  registers[1] = 10
  registers[5] = 20
  local values_2 = { from = 4, to = 6 }
  do
    local clear_range = values_2
    if clear_range then
      for register_index = clear_range.from, clear_range.to do registers[register_index] = nil end
    end
  end
  return registers[1], registers[5]
end

return recovered_routine_2({})
"""
        )

        rewritten = artifact["source"]
        self.assertGreater(artifact["metrics"]["register_table_slots_scalarized"], 0)
        self.assertIn("local registers", rewritten)
        self.assertIn("registers[5]", rewritten)
        self.assertNotIn("registers[1] = 10", rewritten)

    def test_dead_register_frame_alias_does_not_block_scalarization(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2()
  local registers = {}
  local working_value
  registers[1] = 10
  registers[2] = 20
  working_value = registers
  working_value = registers[1] + registers[2]
  return working_value
end

return recovered_routine_2()
"""
        )

        rewritten = artifact["source"]
        self.assertGreater(artifact["metrics"]["register_table_slots_scalarized"], 0)
        self.assertNotIn("working_value = registers\n", rewritten)
        self.assertNotIn("registers[1]", rewritten)
        self.assertNotIn("registers[2]", rewritten)

    def test_dominating_state_index_is_specialized_before_register_scalarization(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2(captured_values, ...)
  local registers = {}
  local state = {}
  state.l = 2
  registers[(state.l + 1)] = 40
  registers[state.l] = 2
  return registers[3] + registers[2]
end

return recovered_routine_2({})
"""
        )

        rewritten = artifact["source"]
        self.assertGreater(artifact["metrics"]["register_table_slots_scalarized"], 0)
        self.assertNotIn("registers[state.l]", rewritten)
        self.assertNotIn("registers[(state.l + 1)]", rewritten)
        self.assertIn("return 40 + 2", rewritten)

    def test_immediate_state_alias_reads_and_writes_become_direct_register_accesses(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2(captured_values, ...)
  local registers = {}
  local state = {}
  registers[1] = 20
  state.w = registers
  state.K = 1
  state.w = state.w[state.K]
  state.l = registers
  state.M = 2
  state.l[state.M] = state.w + 22
  return registers[2]
end

return recovered_routine_2({})
"""
        )

        rewritten = artifact["source"]
        self.assertGreater(artifact["metrics"]["register_table_slots_scalarized"], 0)
        self.assertNotIn("state.w = registers", rewritten)
        self.assertNotIn("state.l = registers", rewritten)
        self.assertNotIn("state.w[state.K]", rewritten)
        self.assertNotIn("state.l[state.M]", rewritten)
        self.assertIn("state.w = number", rewritten)
        self.assertIn("return (state.w + 22)", rewritten)

    def test_stable_closure_copy_recovers_an_ordinary_direct_call(self) -> None:
        artifact = self.rewrite(
            """local function call_recovered(callable, fallback, captures, ...)
  if callable then
    return callable(...)
  end
  return fallback(captures, ...)
end

local recovered_routine_3
recovered_routine_3 = function(captured_values, ...)
  return ...
end

local function recovered_routine_2(captured_values, ...)
  local registers = {}
  local callback_captures = {}
  registers[10] = "stale VM value"
  registers[10] = function(...)
    return recovered_routine_3(callback_captures, ...)
  end
  registers[20] = registers[10]
  registers[21] = "hello"
  return call_recovered(registers[20], recovered_routine_3, captured_values, registers[21])
end

return recovered_routine_2({})
"""
        )

        rewritten = artifact["source"]
        self.assertEqual(artifact["metrics"]["direct_closure_calls_recovered"], 1)
        self.assertNotIn("call_recovered(registers[20]", rewritten)
        self.assertNotIn("recovered_routine_3, captured_values", rewritten)
        self.assertIn('"hello"', rewritten)

    def test_closure_call_is_not_recovered_after_a_later_slot_overwrite(self) -> None:
        artifact = self.rewrite(
            """local function call_recovered(callable, fallback, captures, ...)
  if callable then
    return callable(...)
  end
  return fallback(captures, ...)
end

local recovered_routine_3
recovered_routine_3 = function(captured_values, ...)
  return ...
end

local function recovered_routine_2(captured_values, ...)
  local registers = {}
  local callback_captures = {}
  registers[10] = function(...)
    return recovered_routine_3(callback_captures, ...)
  end
  registers[10] = nil
  registers[20] = registers[10]
  return call_recovered(registers[20], recovered_routine_3, captured_values, "hello")
end

return recovered_routine_2({})
"""
        )

        self.assertEqual(artifact["metrics"]["direct_closure_calls_recovered"], 0)
        self.assertIn("call_recovered", artifact["source"])

    def test_ignored_call_scope_becomes_a_plain_call_statement(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2(captured_values, ...)
  do local _ = print("hello") end
end

return recovered_routine_2({})
"""
        )

        self.assertGreater(artifact["metrics"]["unused_call_results_removed"], 0)
        self.assertNotIn("do local _ =", artifact["source"])
        self.assertIn('print("hello")', artifact["source"])

    def test_parenthesized_callee_keeps_its_ignored_result_scope(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2(captured_values, ...)
  local registers = {print}
  local top = 1
  do local _ = (registers[top])("hello") end
end

return recovered_routine_2({})
"""
        )

        self.assertIn("do local _ = (registers[top])", artifact["source"])

    def test_semantic_step_instrumentation_is_removed_from_readable_source(self) -> None:
        artifact = self.rewrite(
            """local semantic_step_count = 0
local semantic_site_counts = {}
local function semantic_step(prototype, pc)
  semantic_step_count += 1
  semantic_site_counts[prototype .. ":" .. pc] = semantic_step_count
end

local function recovered_routine_2(captured_values, ...)
  semantic_step(2, 10)
  print("payload")
end

return recovered_routine_2({})
"""
        )

        self.assertGreater(artifact["metrics"]["trace_instrumentation_removed"], 0)
        self.assertNotIn("semantic_step", artifact["source"])
        self.assertNotIn("semantic_step_count", artifact["source"])
        self.assertIn('print("payload")', artifact["source"])

    def test_unreferenced_recovered_prototype_is_removed(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_99(captured_values, ...)
  print("unreachable decoy")
end

local function recovered_routine_2(captured_values, ...)
  return "payload"
end

return recovered_routine_2({})
"""
        )

        self.assertEqual(artifact["metrics"]["unreachable_prototypes_removed"], 1)
        self.assertNotIn("recovered_routine_99", artifact["source"])
        self.assertNotIn("unreachable decoy", artifact["source"])
        self.assertIn('return "payload"', artifact["source"])

    def test_unread_runtime_lane_observation_and_helper_are_removed(self) -> None:
        artifact = self.rewrite(
            """local lane_activation_positions = {}
local function replay_runtime_lanes(positions, prototype, pc, sequences, repeat_from)
  lane_activation_positions[pc] = (lane_activation_positions[pc] or 0) + 1
  return sequences[1]
end

local function recovered_routine_2(captured_values, ...)
  local replay_positions = {}
  local runtime_lanes_10 = replay_runtime_lanes(replay_positions, 2, 10, {{{G = 1}}}, 0)
  return "payload"
end

return recovered_routine_2({})
"""
        )

        self.assertNotIn("runtime_lanes_10", artifact["source"])
        self.assertNotIn("replay_runtime_lanes", artifact["source"])
        self.assertNotIn("lane_activation_positions", artifact["source"])
        self.assertIn('return "payload"', artifact["source"])

    def test_duplicate_internal_empty_probe_is_collapsed(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2(captured_values, ...)
  local registers = {7}
  if registers[1] == 7 then
  end
  if registers[1] == 7 then
    return "payload"
  end
end

return recovered_routine_2({})
"""
        )

        self.assertEqual(artifact["source"].count("if registers[1] == 7 then"), 1)
        self.assertIn('return "payload"', artifact["source"])

    def test_standalone_internal_empty_probe_is_removed(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2(captured_values, ...)
  local registers = {7}
  if registers[1] == 9 then
  end
  return "payload"
end

return recovered_routine_2({})
"""
        )

        self.assertNotIn("if registers[1] == 9 then", artifact["source"])
        self.assertIn('return "payload"', artifact["source"])

    def test_cleared_high_register_replay_metadata_patch_is_removed(self) -> None:
        artifact = self.rewrite(
            """local function replay_activation_transition(_, _, _, _, _)
  return 8
end

local operand_values = {}
local opcode_values = {}
local function recovered_routine_2(captured_values, ...)
  local registers = {}
  local replay_positions = {}
  local replay_target_10 = replay_activation_transition(replay_positions, 2, 10, {{8}}, 0)
  if replay_target_10 == 8 then
    registers[70] = operand_values
    registers[71] = opcode_values
    registers[70][10] = 9
    registers[71][10] = 3
    for loop_index = 64, 71, 1 do
      registers[loop_index] = nil
    end
  end
  return "payload"
end

return recovered_routine_2({})
"""
        )

        self.assertEqual(artifact["metrics"]["high_register_replay_patches_removed"], 1)
        self.assertNotIn("replay_activation_transition(replay_positions", artifact["source"])
        self.assertNotIn("registers[70][10]", artifact["source"])
        self.assertIn('return "payload"', artifact["source"])

    def test_cleared_mid_register_replay_metadata_patch_is_removed(self) -> None:
        artifact = self.rewrite(
            """local function replay_activation_transition(_, _, _, _, _)
  return 8
end

local operand_values = {}
local function recovered_routine_2(captured_values, ...)
  local registers = {}
  local replay_positions = {}
  local state = {}
  local replay_target_10 = replay_activation_transition(replay_positions, 2, 10, {{8}}, 0)
  if replay_target_10 == 8 then
    registers[20] = operand_values
    registers[21] = 9
    registers[20][10] = registers[21]
    state.register_clear_range_3 = { from = 16, to = 23 }
    do
      local clear_range = state.register_clear_range_3
      if clear_range then
        for register_index = clear_range.from, clear_range.to do registers[register_index] = nil end
      end
    end
  end
  return "payload"
end

return recovered_routine_2({})
"""
        )

        self.assertEqual(artifact["metrics"]["cleared_replay_metadata_patches_removed"], 1)
        self.assertNotIn("registers[20][10]", artifact["source"])
        self.assertIn('return "payload"', artifact["source"])

    def test_cleared_low_register_replay_metadata_patch_is_removed(self) -> None:
        artifact = self.rewrite(
            """local function replay_activation_transition(_, _, _, _, _)
  return 8
end

local operand_values = {}
local function recovered_routine_2(captured_values, ...)
  local registers = {}
  local replay_positions = {}
  local replay_target_10 = replay_activation_transition(replay_positions, 2, 10, {{8}}, 0)
  if replay_target_10 == 8 then
    registers[5] = operand_values
    registers[5][10] = 9
    for loop_index = 3, 12, 1 do
      registers[loop_index] = nil
    end
  end
  return "payload"
end

return recovered_routine_2({})
"""
        )

        self.assertEqual(artifact["metrics"]["low_register_replay_patches_removed"], 1)
        self.assertNotIn("registers[5][10]", artifact["source"])
        self.assertIn('return "payload"', artifact["source"])

    def test_equivalent_replay_payload_discards_cleared_metadata_envelope(self) -> None:
        artifact = self.rewrite(
            """local function replay_activation_transition(_, _, _, _, _)
  return 8
end

local operand_values = {}
local function recovered_routine_2(captured_values, ...)
  local registers = {}
  local replay_positions = {}
  if replay_activation_transition(replay_positions, 2, 10, {{8}}, 0) == 8 then
    registers[12] = operand_values
    registers[18] = false
    if not registers[18] then
      registers[12][10] = 9
      for loop_index = 10, 19, 1 do
        registers[loop_index] = nil
      end
      print("payload")
    end
  else
    print("payload")
  end
  return true
end

return recovered_routine_2({})
"""
        )

        self.assertEqual(artifact["metrics"]["replay_branches_collapsed"], 1)
        self.assertNotIn("replay_activation_transition(replay_positions", artifact["source"])
        self.assertEqual(artifact["source"].count('print("payload")'), 1)
        self.assertIn("return true", artifact["source"])

    def test_linear_cleared_metadata_capsule_is_removed_between_payload_statements(self) -> None:
        artifact = self.rewrite(
            """local operand_values = {}
local opcode_values = {}
local function recovered_routine_2()
  local registers = {}
  print("before")
  registers[20] = operand_values
  registers[21] = opcode_values
  registers[20][10] = 9
  registers[21][10] = 3
  for loop_index = 18, 23, 1 do
    registers[loop_index] = nil
  end
  print("after")
end

return recovered_routine_2()
"""
        )

        self.assertEqual(artifact["metrics"]["linear_replay_metadata_patches_removed"], 1)
        self.assertNotIn("registers[20][10]", artifact["source"])
        self.assertIn('print("before")', artifact["source"])
        self.assertIn('print("after")', artifact["source"])

    def test_discarded_multiline_callback_factory_is_removed_as_a_region(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2()
  do
    local callback_captures = {
      [0] = "captured",
    }
    function(...)
      return callback_captures[0], ...
    end
  end
  return "payload"
end

return recovered_routine_2()
"""
        )

        self.assertEqual(artifact["metrics"]["discarded_anonymous_functions_removed"], 1)
        self.assertNotIn("function(...)", artifact["source"])
        self.assertNotIn("callback_captures", artifact["source"])
        self.assertIn('return "payload"', artifact["source"])

    def test_private_state_fields_are_scalarized_without_table_semantics(self) -> None:
        artifact = self.rewrite(
            """local environment = _ENV
local function recovered_routine_2()
  local state = { Q = environment }
  state.A = 2
  state.B = state.A + 3
  return state.B, state.Q
end

return recovered_routine_2()
"""
        )

        self.assertEqual(artifact["metrics"]["state_tables_scalarized"], 1)
        self.assertEqual(artifact["metrics"]["state_fields_scalarized"], 3)
        self.assertGreaterEqual(artifact["metrics"]["state_accesses_scalarized"], 5)
        self.assertNotIn("local state =", artifact["source"])
        self.assertNotIn("state.", artifact["source"])
        self.assertIn("return", artifact["source"])

    def test_private_state_scalarization_rejects_whole_table_escape(self) -> None:
        artifact = self.rewrite(
            """local environment = _ENV
local function consume(value)
  return value.A
end
local function recovered_routine_2()
  local state = { Q = environment }
  state.A = 2
  return consume(state)
end

return recovered_routine_2()
"""
        )

        self.assertEqual(artifact["metrics"]["state_tables_scalarized"], 0)
        self.assertIn("local state = { Q = environment }", artifact["source"])
        self.assertIn("consume(state)", artifact["source"])

    def test_canonical_state_numeric_loop_becomes_luau_for_loop(self) -> None:
        artifact = self.rewrite(
            """local function recovered_routine_2()
  local state = {}
  local current
  state.s = {[4] = state.f, [3] = state.A, [5] = state.s, [1] = state.I}
  state.l = 1
  state.A = (1 + 0)
  state.I = (3 + 0)
  state.f = (1 - state.A)
  while true do
    state.l = false
    state.f += state.A
    if state.A <= 0 then
      state.l = (state.f >= state.I)
    else
      state.l = (state.f <= state.I)
    end
    if state.l then
      current = state.f
    end
    if current <= 3 then
      print(current)
      continue
    end
    break
  end
  state.f = state.s[4]
  state.I = state.s[1]
  state.A = state.s[3]
  state.s = state.s[5]
end

return recovered_routine_2()
"""
        )

        self.assertEqual(artifact["metrics"]["numeric_loops_recovered"], 1, artifact["source"])
        self.assertIn("for numeric_index_1 = 1, 3 do", artifact["source"])
        self.assertIn("current = numeric_index_1", artifact["source"])
        self.assertNotIn("state.f += state.A", artifact["source"])

    def test_constant_call_pack_becomes_direct_multi_assignment(self) -> None:
        artifact = self.rewrite(
            """local helper_values = {}
local function recovered_routine_2()
  local registers = {}
  local top = 5
  state.l = 3
  state.M = 3
  state.w = 4
  if not ((state.M == 0)) then
    top = ((state.l + state.M) - 1)
  end
  state.K, state.L = nil
  if state.M ~= 1 then
    state.K, state.L = helper_values[53]((registers[state.l])(helper_values[23]((state.l + 1), registers, top)))
  else
    state.K, state.L = helper_values[53]((registers[state.l])())
  end
  if state.w ~= 1 then
    if state.w == 0 then
      state.K = ((state.K + state.l) - 1)
      top = state.K
    else
      state.K = ((state.l + state.w) - 2)
      top = (state.K + 1)
    end
    state.M = 0
    for loop_index = state.l, state.K, 1 do
      state.M += 1
      registers[loop_index] = state.L[state.M]
    end
  else
    top = (state.l - 1)
  end
  return registers[3]
end

return recovered_routine_2()
"""
        )

        self.assertGreaterEqual(artifact["metrics"]["result_packs_collapsed"], 1)
        self.assertRegex(artifact["source"], r"local_\d+, local_\d+, local_\d+ = local_\d+\(local_\d+, local_\d+\)")
        self.assertNotIn("state.K, state.L", artifact["source"])

    def test_fixed_top_unpack_range_becomes_explicit_arguments(self) -> None:
        artifact = self.rewrite(
            """local unpack_values = unpack or table.unpack
local function recovered_routine_2(callback)
  local registers = {}
  local top = 0
  registers[2] = callback
  registers[3] = "alpha"
  registers[4] = "beta"
  registers[5] = "gamma"
  top = ((2 + 4) - 1)
  registers[2](unpack_values(registers, (2 + 1), top))
  top = 1
  return top
end

return recovered_routine_2(print)
"""
        )

        self.assertEqual(artifact["metrics"]["fixed_top_call_packs_expanded"], 1)
        self.assertNotIn("unpack_values(registers", artifact["source"])
        self.assertIn('"alpha"', artifact["source"])
        self.assertIn('"beta"', artifact["source"])
        self.assertIn('"gamma"', artifact["source"])

    def test_fixed_register_call_pack_becomes_multiple_assignment(self) -> None:
        artifact = self.rewrite(
            """local helper_values = {}
local function recovered_routine_2()
  local registers = {}
  local state = {}
  local top = 4
  registers[2] = function(left, right) return left + right, left * right end
  registers[3] = 4
  registers[4] = 5
  state.l = 2
  state.M = 3
  state.w = 3
  if not ((state.M == 0)) then
    top = ((state.l + state.M) - 1)
  end
  state.K, state.L = nil
  if state.M ~= 1 then
    state.K, state.L = helper_values[53]((registers[state.l])(helper_values[23]((state.l + 1), registers, top)))
  else
    state.K, state.L = helper_values[53]((registers[state.l])())
  end
  if state.w ~= 1 then
    if state.w == 0 then
      state.K = ((state.K + state.l) - 1)
      top = state.K
    else
      state.K = ((state.l + state.w) - 2)
      top = (state.K + 1)
    end
    state.M = 0
    for loop_index = state.l, state.K, 1 do
      state.M += 1
      registers[loop_index] = state.L[state.M]
    end
  else
    top = (state.l - 1)
  end
  return registers[2], registers[3], top
end

return recovered_routine_2()
"""
        )

        self.assertEqual(artifact["metrics"]["result_packs_collapsed"], 1)
        self.assertIn("local_0, local_1 = local_0(4, 5)", artifact["source"])
        self.assertIn("top = 4", artifact["source"])
        self.assertNotIn("helper_values[53]((registers[state.l])", artifact["source"])

    def test_mixed_reducible_and_irreducible_routines_preserve_residual_cfg(self) -> None:
        irreducible_region = """  local pc = 1
  while pc ~= nil do
    semantic_step(9, pc)
    local dispatch_bucket = math.floor((pc - 1) / 64)
    if dispatch_bucket == 0 then
      if pc == 1 then
        if flag then
          pc = 2
        else
          pc = 3
        end
      elseif pc == 2 then
        touch("left")
        pc = 3
      elseif pc == 3 then
        touch("right")
        if flag then
          pc = 2
        else
          pc = nil
        end
      else
        return nil
      end
    else
      return nil
    end
  end
  return nil
"""
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function touch(_)
end

local function reducible()
  local pc = 1
  while pc ~= nil do
    semantic_step(8, pc)
    local dispatch_bucket = math.floor((pc - 1) / 64)
    if dispatch_bucket == 0 then
      if pc == 1 then
        touch("start")
        pc = 2
      elseif pc == 2 then
        pc = nil
      else
        return nil
      end
    else
      return nil
    end
  end
  return nil
end

local function irreducible(flag)
"""
            + irreducible_region
            + """end

return reducible, irreducible
"""
        )

        rewritten = artifact["source"]
        metrics = artifact["metrics"]
        self.assertEqual(metrics["regions_found"], 2)
        self.assertEqual(metrics["regions_structured"], 1)
        self.assertEqual(metrics["blocks_structured"], 2)
        self.assertEqual(metrics["residual_state_machines"], 1)
        self.assertIn(irreducible_region, rewritten)
        self.assertNotIn("semantic_step(8, pc)", rewritten)
        self.assertIn('touch("start")', rewritten)
        self.assertEqual(rewritten.count("local dispatch_bucket ="), 1)

    def test_flat_luraph_dispatcher_is_rebuilt_as_structured_control_flow(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function flat_dispatch(flag)
  local output = "start"
  local pc = 1
  while pc ~= nil do
    semantic_step(12, pc)
    if pc == 1 then
      if flag then
        pc = 2
      else
        pc = 3
      end
    elseif pc == 2 then
      output ..= ":yes"
      pc = 4
    elseif pc == 3 then
      output ..= ":no"
      pc = 4
    elseif pc == 4 then
      return output
    else
      return nil
    end
  end
  return nil
end

return flat_dispatch(true), flat_dispatch(false)
"""
        )

        rewritten = artifact["source"]
        metrics = artifact["metrics"]
        self.assertEqual(metrics["regions_found"], 1)
        self.assertEqual(metrics["regions_structured"], 1)
        self.assertEqual(metrics["blocks_structured"], 4)
        self.assertEqual(metrics["residual_state_machines"], 0)
        self.assertNotIn("local pc =", rewritten)
        self.assertNotIn("while pc ~= nil do", rewritten)
        self.assertNotIn("semantic_step(12, pc)", rewritten)
        self.assertIn("if flag then", rewritten)
        self.assertIn('output ..= ":yes"', rewritten)
        self.assertIn('output ..= ":no"', rewritten)

    def test_flat_trace_replay_transition_is_evaluated_once(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function replay_transition(_, _, _)
  return 2
end

local function flat_replay()
  local pc = 1
  while pc ~= nil do
    semantic_step(13, pc)
    if pc == 1 then
      pc = replay_transition(13, 1, {2, 3, 3})
    elseif pc == 2 then
      return "first"
    elseif pc == 3 then
      return "second"
    else
      return nil
    end
  end
  return nil
end

return flat_replay()
"""
        )

        rewritten = artifact["source"]
        metrics = artifact["metrics"]
        self.assertEqual(metrics["regions_structured"], 1)
        self.assertEqual(metrics["blocks_structured"], 3)
        self.assertEqual(metrics["residual_state_machines"], 0)
        self.assertNotIn("while pc ~= nil do", rewritten)
        self.assertEqual(rewritten.count("replay_transition(13, 1, {2, 3, 3})"), 1)
        self.assertIn("if replay_transition(13, 1, {2, 3, 3}) == 2 then", rewritten)

    def test_flat_replay_with_three_targets_remains_a_residual_state_machine(self) -> None:
        source = """local function semantic_step(_, _)
end

local function replay_transition(_, _, _)
  return 2
end

local function ambiguous_replay()
  local pc = 1
  while pc ~= nil do
    semantic_step(14, pc)
    if pc == 1 then
      pc = replay_transition(14, 1, {2, 3, 4})
    elseif pc == 2 then
      return "first"
    elseif pc == 3 then
      return "second"
    elseif pc == 4 then
      return "third"
    else
      return nil
    end
  end
  return nil
end

return ambiguous_replay()
"""
        artifact = self.rewrite(source)

        self.assertEqual(artifact["metrics"]["regions_found"], 1)
        self.assertEqual(artifact["metrics"]["regions_structured"], 0)
        self.assertEqual(artifact["metrics"]["residual_state_machines"], 1)
        self.assertEqual(artifact["metrics"]["residual_reasons"], {"parse_terminator_1": 1})
        self.assertIn("pc = replay_transition(14, 1, {2, 3, 4})", artifact["source"])

    def test_overwritten_nested_dispatcher_write_is_removed(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function touch(_)
end

local function overwritten(flag)
  local pc = 1
  while pc ~= nil do
    semantic_step(15, pc)
    if pc == 1 then
      if flag then
        touch("taken")
        pc = (1) + 1;
      end
      if flag then
      else
      end
      pc = 3
    elseif pc == 2 then
      return "wrong"
    elseif pc == 3 then
      return "done"
    else
      return nil
    end
  end
  return nil
end

return overwritten(true)
"""
        )

        rewritten = artifact["source"]
        self.assertEqual(artifact["metrics"]["regions_structured"], 1)
        self.assertEqual(artifact["metrics"]["dead_assignments_removed"], 1)
        self.assertNotIn("pc =", rewritten)
        self.assertIn('touch("taken")', rewritten)
        self.assertIn('return "done"', rewritten)
        self.assertNotIn('return "wrong"', rewritten)

    def test_observable_nested_dispatcher_write_keeps_the_region_residual(self) -> None:
        source = """local function semantic_step(_, _)
end

local function observe(_)
end

local function observable(flag)
  local pc = 1
  while pc ~= nil do
    semantic_step(16, pc)
    if pc == 1 then
      if flag then
        pc = 2
        observe(pc)
      end
      pc = 3
    elseif pc == 2 then
      return "branch"
    elseif pc == 3 then
      return "done"
    else
      return nil
    end
  end
  return nil
end

return observable(true)
"""
        artifact = self.rewrite(source)

        self.assertEqual(artifact["metrics"]["regions_structured"], 0)
        self.assertEqual(artifact["metrics"]["residual_state_machines"], 1)
        self.assertEqual(artifact["metrics"]["residual_reasons"], {"parse_terminator_1": 1})
        self.assertIn("observe(pc)", artifact["source"])
        self.assertIn("local pc = 1", artifact["source"])

    def test_unobserved_top_level_pc_write_before_branch_terminator_is_removed(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function overwritten_before_branch(flag)
  local pc = 1
  while pc ~= nil do
    semantic_step(18, pc)
    if pc == 1 then
      pc = (8) + 1;
      if flag then
      else
      end
      if flag then
        pc = 2
      else
        pc = 3
      end
    elseif pc == 2 then
      return "yes"
    elseif pc == 3 then
      return "no"
    else
      return nil
    end
  end
  return nil
end

return overwritten_before_branch
"""
        )

        rewritten = artifact["source"]
        self.assertEqual(artifact["metrics"]["regions_structured"], 1)
        self.assertEqual(artifact["metrics"]["dead_assignments_removed"], 1)
        self.assertNotIn("pc =", rewritten)
        self.assertIn("if flag then", rewritten)
        self.assertIn('return "yes"', rewritten)
        self.assertIn('return "no"', rewritten)

    def test_natural_loop_with_three_exits_uses_a_structured_selector(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function three_exit_loop(keep_going, choice)
  local output = "none"
  local pc = 1
  while pc ~= nil do
    semantic_step(17, pc)
    if pc == 1 then
      if keep_going then
        pc = 2
      else
        pc = 4
      end
    elseif pc == 2 then
      if choice == 1 then
        pc = 5
      else
        pc = 3
      end
    elseif pc == 3 then
      if choice == 2 then
        pc = 6
      else
        pc = 1
      end
    elseif pc == 4 then
      output = "done"
      pc = 7
    elseif pc == 5 then
      output = "one"
      pc = 7
    elseif pc == 6 then
      output = "two"
      pc = 7
    elseif pc == 7 then
      return output
    else
      return nil
    end
  end
  return nil
end

return three_exit_loop
"""
        )

        rewritten = artifact["source"]
        metrics = artifact["metrics"]
        self.assertEqual(metrics["regions_structured"], 1)
        self.assertEqual(metrics["blocks_structured"], 7)
        self.assertEqual(metrics["residual_state_machines"], 0)
        self.assertNotIn("while pc ~= nil do", rewritten)
        self.assertIn("local loop_exit_1", rewritten)
        self.assertIn("if loop_exit_1 == 1 then", rewritten)
        self.assertIn("elseif loop_exit_1 == 2 then", rewritten)
        self.assertIn('output = "done"', rewritten)
        self.assertIn('output = "one"', rewritten)
        self.assertIn('output = "two"', rewritten)

    def test_parenthesized_index_lvalue_becomes_valid_plain_luau(self) -> None:
        artifact = self.rewrite(
            """local function semantic_step(_, _)
end

local function indexed_write(captured_values, registers)
  local pc = 1
  while pc ~= nil do
    semantic_step(19, pc)
    if pc == 1 then
      (captured_values[0.0][3.0])[captured_values[0.0][2.0]] = registers[1];
      pc = 2
    elseif pc == 2 then
      return registers[1]
    else
      return nil
    end
  end
  return nil
end

return indexed_write
"""
        )

        rewritten = artifact["source"]
        self.assertEqual(artifact["metrics"]["regions_structured"], 1)
        self.assertGreater(artifact["metrics"]["redundant_parentheses_removed"], 0)
        self.assertNotIn(";(captured_values", rewritten)
        self.assertNotIn("(captured_values[0][3])[", rewritten)
        self.assertIn("captured_values[0][3][captured_values[0][2]] = registers[1]", rewritten)


if __name__ == "__main__":
    unittest.main()
