using System.Text.Json.Nodes;
using Luraph.Core.Emission;
using Luraph.Core.Ir;
using Luraph.Core.Lifting;
using Luraph.Core.Tests.Lifting;

namespace Luraph.Core.Tests.Emission;

public sealed class LuauEmitterTests
{
    [Fact]
    public void CompleteClosureBuildsDirectCallback()
    {
        JsonObject closure = SemanticFixture.Instruction(1, new JsonObject
        {
            ["kind"] = "protector_internal_sequence",
            ["operations"] = new JsonArray(new JsonObject
            {
                ["kind"] = "expression",
                ["value"] = new JsonObject
                {
                    ["kind"] = "immediate",
                    ["lane"] = "G",
                    ["value"] = new JsonObject
                    {
                        ["primitive"] = false,
                        ["type"] = "table",
                    },
                },
            }),
        }, 22);
        closure["closure_descriptor"] = SemanticFixture.Descriptor(
            2,
            5,
            SemanticFixture.Capture(0, 0, 10));
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, closure),
            SemanticFixture.Prototype(2, SemanticFixture.Instruction(1, SemanticFixture.Return())));
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")),
            SemanticFixture.CfgPrototype(2, SemanticFixture.Block(2, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("registers[5] = (function()", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("capture_register_cell(open_cells, registers, 10)", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("return recovered_routine_2(callback_captures, ...)", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("local opcode_values = {}", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("local operand_values = {}", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("helper_values[53]", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("semantic_step(1, pc)", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("recent path:", candidate.Source, StringComparison.Ordinal);
        Assert.Equal(1, candidate.Metrics.ClosureConstructors);
        Assert.Equal(0, candidate.Metrics.UnsupportedExpressions);
        Assert.DoesNotContain("runtime value is not a primitive", candidate.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownOperationIsNeverClaimedAsRendered()
    {
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, SemanticFixture.Instruction(1, new JsonObject { ["kind"] = "mystery" })));
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.False(candidate.FullyRendered);
        Assert.Contains("-- unresolved: mystery", candidate.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void TerminalBranchIsEmittedByTheCfgTransitionOnce()
    {
        JsonObject branch = new()
        {
            ["kind"] = "branch",
            ["condition"] = new JsonObject { ["kind"] = "constant", ["value"] = true },
            ["then"] = new JsonArray(new JsonObject
            {
                ["kind"] = "jump",
                ["target"] = new JsonObject { ["kind"] = "constant", ["value"] = 1 },
            }),
            ["else"] = new JsonArray(new JsonObject
            {
                ["kind"] = "jump",
                ["target"] = new JsonObject { ["kind"] = "constant", ["value"] = 2 },
            }),
        };
        JsonObject ir = SemanticFixture.Program(SemanticFixture.Prototype(1,
            SemanticFixture.Instruction(1, branch),
            SemanticFixture.Instruction(2, SemanticFixture.Return()),
            SemanticFixture.Instruction(3, SemanticFixture.Return())));
        JsonObject cfg = SemanticFixture.Cfg(SemanticFixture.CfgPrototype(1,
            SemanticFixture.Block(1, 1, "branch", "p1_b2", "p1_b3"),
            SemanticFixture.Block(1, 2, "return"),
            SemanticFixture.Block(1, 3, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.DoesNotContain("-- unresolved operation", candidate.Source, StringComparison.Ordinal);
        Assert.Equal(0, candidate.Metrics.UnsupportedOperations);
        Assert.Contains("if true then", candidate.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void ObservedSingleSuccessorBranchBecomesUnconditionalTransition()
    {
        JsonObject branch = new()
        {
            ["kind"] = "branch",
            ["condition"] = new JsonObject { ["kind"] = "constant", ["value"] = true },
            ["then"] = new JsonArray(new JsonObject
            {
                ["kind"] = "jump",
                ["target"] = new JsonObject { ["kind"] = "constant", ["value"] = 1 },
            }),
            ["else"] = new JsonArray(new JsonObject
            {
                ["kind"] = "jump",
                ["target"] = new JsonObject { ["kind"] = "constant", ["value"] = 2 },
            }),
        };
        JsonObject ir = SemanticFixture.Program(SemanticFixture.Prototype(1,
            SemanticFixture.Instruction(1, branch),
            SemanticFixture.Instruction(2, SemanticFixture.Return()),
            SemanticFixture.Instruction(3, SemanticFixture.Return())));
        JsonObject cfg = SemanticFixture.Cfg(SemanticFixture.CfgPrototype(1,
            SemanticFixture.Block(1, 1, "observed_branch", "p1_b3"),
            SemanticFixture.Block(1, 2, "return"),
            SemanticFixture.Block(1, 3, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.DoesNotContain("if true then", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("pc = 3", candidate.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void NestedTerminalBranchKeepsItsBodyButNotItsVmJump()
    {
        JsonObject operation = new()
        {
            ["kind"] = "protector_internal_sequence",
            ["operations"] = new JsonArray(new JsonObject
            {
                ["kind"] = "branch",
                ["condition"] = new JsonObject { ["kind"] = "constant", ["value"] = true },
                ["then"] = new JsonArray(
                    new JsonObject
                    {
                        ["kind"] = "register_write",
                        ["register"] = new JsonObject { ["kind"] = "constant", ["value"] = 5 },
                        ["value"] = new JsonObject { ["kind"] = "constant", ["value"] = 84 },
                    },
                    new JsonObject
                    {
                        ["kind"] = "jump",
                        ["target"] = new JsonObject { ["kind"] = "constant", ["value"] = 40 },
                    }),
                ["else"] = new JsonArray(),
            }),
        };
        JsonObject ir = SemanticFixture.Program(SemanticFixture.Prototype(1,
            SemanticFixture.Instruction(1, operation),
            SemanticFixture.Instruction(2, SemanticFixture.Return())));
        JsonObject cfg = SemanticFixture.Cfg(SemanticFixture.CfgPrototype(1,
            SemanticFixture.Block(1, 1, "observed_fallthrough", "p1_b2"),
            SemanticFixture.Block(1, 2, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("if true then", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("registers[5] = 84;", candidate.Source, StringComparison.Ordinal);
        Assert.DoesNotContain("pc = (40) + 1;", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("pc = 2", candidate.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void DirectSequenceJumpOverridesAnIncorrectFallthroughEdge()
    {
        JsonObject operation = new()
        {
            ["kind"] = "protector_internal_sequence",
            ["operations"] = new JsonArray(
                new JsonObject
                {
                    ["kind"] = "register_write",
                    ["register"] = new JsonObject { ["kind"] = "constant", ["value"] = 92 },
                    ["value"] = new JsonObject { ["kind"] = "constant", ["value"] = 230 },
                },
                new JsonObject
                {
                    ["kind"] = "jump",
                    ["target"] = new JsonObject { ["kind"] = "constant", ["value"] = 4837 },
                }),
        };
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1,
                SemanticFixture.Instruction(1, operation),
                SemanticFixture.Instruction(2, SemanticFixture.Return())));
        JsonObject cfg = SemanticFixture.Cfg(SemanticFixture.CfgPrototype(1,
            SemanticFixture.Block(1, 1, "fallthrough", "p1_b2"),
            SemanticFixture.Block(1, 2, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("registers[92] = 230;", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("pc = (4837) + 1", candidate.Source, StringComparison.Ordinal);
        Assert.DoesNotContain("pc = 2\n", candidate.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void ConsecutiveIndexedAssignmentsAreStatementTerminated()
    {
        static JsonObject Write(string field, int value) => new()
        {
            ["kind"] = "table_write",
            ["table"] = new JsonObject { ["kind"] = "vm_state", ["name"] = "state_table" },
            ["index"] = new JsonObject { ["kind"] = "constant", ["value"] = field },
            ["value"] = new JsonObject { ["kind"] = "constant", ["value"] = value },
        };
        JsonObject ir = SemanticFixture.Program(SemanticFixture.Prototype(1,
            SemanticFixture.Instruction(1, Write("first", 1)),
            SemanticFixture.Instruction(2, Write("second", 2)),
            SemanticFixture.Instruction(3, SemanticFixture.Return())));
        JsonObject cfg = SemanticFixture.Cfg(SemanticFixture.CfgPrototype(1,
            SemanticFixture.Block(1, 1, "observed_fallthrough", "p1_b2"),
            SemanticFixture.Block(1, 2, "observed_fallthrough", "p1_b3"),
            SemanticFixture.Block(1, 3, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        string[] lines = candidate.Source.Split('\n');
        string first = Assert.Single(lines, line => line.Contains("[\"first\"]", StringComparison.Ordinal));
        string second = Assert.Single(lines, line => line.Contains("[\"second\"]", StringComparison.Ordinal));
        Assert.EndsWith(";", first.TrimEnd(), StringComparison.Ordinal);
        Assert.EndsWith(";", second.TrimEnd(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReconstructedArtifactIsWithheldWhenCandidateIsIncomplete()
    {
        string output = Path.Combine(Path.GetTempPath(), "luraph-cs-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            JsonObject ir = SemanticFixture.Program(
                SemanticFixture.Prototype(1, SemanticFixture.Instruction(1, new JsonObject { ["kind"] = "mystery" })));
            JsonObject cfg = SemanticFixture.Cfg(
                SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")));
            ImportedArtifacts imported = new SemanticJsonImporter().Import(ir.ToJsonString(), cfg.ToJsonString());
            LiftResult lift = new SemanticLifter().Lift(imported);
            SemanticCandidate candidate = new LuauEmitter().Emit(lift);

            SemanticArtifactPaths paths = await new SemanticArtifactWriter().WriteAsync(output, lift, candidate);

            Assert.True(File.Exists(paths.Candidate));
            Assert.Null(paths.Reconstructed);
            Assert.False(File.Exists(Path.Combine(output, "reconstructed.luau")));
        }
        finally
        {
            if (Directory.Exists(output))
                Directory.Delete(output, true);
        }
    }

    private static SemanticCandidate Emit(JsonObject ir, JsonObject cfg)
    {
        ImportedArtifacts imported = new SemanticJsonImporter().Import(ir.ToJsonString(), cfg.ToJsonString());
        return new LuauEmitter().Emit(new SemanticLifter().Lift(imported));
    }
}
