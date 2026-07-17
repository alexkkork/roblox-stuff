using System.Text.Json.Nodes;
using Luraph.Core.Emission;
using Luraph.Core.Ir;
using Luraph.Core.Lifting;

namespace Luraph.Core.Tests.Lifting;

public sealed class SemanticJsonImporterTests
{
    [Fact]
    public void RuntimeLaneRemapsDenseCaptureKey()
    {
        JsonObject descriptor = SemanticFixture.Descriptor(
            2,
            5,
            SemanticFixture.Capture(0, 0, 10),
            SemanticFixture.Capture(1, 0, 11));
        JsonObject constructor = SemanticFixture.Instruction(1, new JsonObject
        {
            ["kind"] = "protector_internal_sequence",
            ["operations"] = new JsonArray(),
        }, 22);
        constructor["closure_descriptor"] = descriptor;

        JsonObject read = SemanticFixture.Instruction(1, SemanticFixture.Return(new JsonObject
        {
            ["kind"] = "index_read",
            ["table"] = new JsonObject { ["kind"] = "upvalue_file" },
            ["index"] = SemanticFixture.Immediate("G", 188),
        }), 119);
        read["static_lanes"] = new JsonObject { ["G"] = SemanticFixture.Number(188) };
        read["runtime_lane_overrides"] = new JsonObject { ["G"] = SemanticFixture.Number(0) };

        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, constructor),
            SemanticFixture.Prototype(2, read));
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")),
            SemanticFixture.CfgPrototype(2, SemanticFixture.Block(2, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("captured_values[0]", candidate.Source, StringComparison.Ordinal);
        Assert.DoesNotContain("captured_values[188]", candidate.Source, StringComparison.Ordinal);
        Assert.Equal(1, candidate.Metrics.CaptureKeyRemaps);
        Assert.Equal(0, candidate.Metrics.UnresolvedCaptureKeys);
    }

    [Fact]
    public void StaticCaptureKeyIsProvenWithoutARuntimeRemap()
    {
        JsonObject read = SemanticFixture.Instruction(1, SemanticFixture.Return(new JsonObject
        {
            ["kind"] = "index_read",
            ["table"] = new JsonObject { ["kind"] = "upvalue_file" },
            ["index"] = SemanticFixture.Immediate("G", 7),
        }));
        JsonObject ir = SemanticFixture.Program(SemanticFixture.Prototype(1, read));
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("captured_values[7]", candidate.Source, StringComparison.Ordinal);
        Assert.Equal(0, candidate.Metrics.UnresolvedCaptureKeys);
    }

    [Fact]
    public void NativeCaptureEvidenceRemapsTheExactInstructionSite()
    {
        JsonObject constructor = SemanticFixture.Instruction(1, new JsonObject
        {
            ["kind"] = "protector_internal_sequence",
            ["operations"] = new JsonArray(),
        });
        constructor["closure_descriptor"] = SemanticFixture.Descriptor(
            2,
            5,
            SemanticFixture.Capture(0, 0, 10),
            SemanticFixture.Capture(1, 0, 11));
        JsonObject read = SemanticFixture.Instruction(1, SemanticFixture.Return(new JsonObject
        {
            ["kind"] = "index_read",
            ["table"] = new JsonObject { ["kind"] = "upvalue_file" },
            ["index"] = SemanticFixture.Immediate("G", 188),
        }));
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, constructor),
            SemanticFixture.Prototype(2, read));
        ir["capture_key_resolutions"] = new JsonArray(new JsonObject
        {
            ["prototype"] = 2,
            ["pc"] = 1,
            ["encoded"] = 188,
            ["resolved"] = 1,
            ["complete"] = true,
            ["evidence"] = "call_target",
        });
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")),
            SemanticFixture.CfgPrototype(2, SemanticFixture.Block(2, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("captured_values[1]", candidate.Source, StringComparison.Ordinal);
        Assert.Equal(1, candidate.Metrics.CaptureKeyRemaps);
        Assert.Equal(0, candidate.Metrics.UnresolvedCaptureKeys);
    }

    [Fact]
    public void NativeCaptureEvidenceOutsideTheCompleteDomainIsRejected()
    {
        JsonObject read = SemanticFixture.Instruction(1, SemanticFixture.Return(new JsonObject
        {
            ["kind"] = "index_read",
            ["table"] = new JsonObject { ["kind"] = "upvalue_file" },
            ["index"] = SemanticFixture.Immediate("G", 188),
        }));
        JsonObject ir = SemanticFixture.Program(SemanticFixture.Prototype(1, read));
        ir["observed_capture_domains"] = new JsonArray(new JsonObject
        {
            ["prototype"] = 1,
            ["complete"] = true,
            ["indices"] = new JsonArray(0, 1),
        });
        ir["capture_key_resolutions"] = new JsonArray(new JsonObject
        {
            ["prototype"] = 1,
            ["pc"] = 1,
            ["encoded"] = 188,
            ["resolved"] = 9,
            ["complete"] = true,
        });
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.False(candidate.FullyRendered);
        Assert.Contains(candidate.Unresolved, issue => issue.Code == "invalid_capture_resolution");
        Assert.Equal(1, candidate.Metrics.UnresolvedCaptureKeys);
    }

    [Fact]
    public void ReturnArityMismatchBlocksFullClaim()
    {
        JsonObject instruction = SemanticFixture.Instruction(1, SemanticFixture.Return(new JsonObject
        {
            ["kind"] = "constant",
            ["value"] = SemanticFixture.Text("ok"),
        }));
        instruction["observed_returns"] = new JsonArray(new JsonObject
        {
            ["complete"] = true,
            ["arity"] = 2,
        });
        JsonObject ir = SemanticFixture.Program(SemanticFixture.Prototype(1, instruction));
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.False(candidate.FullyRendered);
        Assert.Equal(1, candidate.Metrics.ReturnArityMismatches);
        Assert.Contains(candidate.Unresolved, issue => issue.Code == "return_arity_mismatch");
    }

    [Fact]
    public void StableLaneBecomesLiteralAndDynamicLaneUsesReplay()
    {
        JsonObject operation = SemanticFixture.Return(SemanticFixture.Immediate("D", 1));
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, SemanticFixture.Instruction(1, operation)));
        ir["observed_lane_sequences"] = new JsonArray(new JsonObject
        {
            ["prototype"] = 1,
            ["pc"] = 1,
            ["lanes"] = new JsonArray("D"),
            ["activation_sequences"] = new JsonArray(
                new JsonObject { ["frames"] = new JsonArray(new JsonObject { ["D"] = SemanticFixture.Number(2) }) },
                new JsonObject { ["frames"] = new JsonArray(new JsonObject { ["D"] = SemanticFixture.Number(3) }) }),
            ["repeat_from_sequence"] = 2,
        });
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("local runtime_lanes_1", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("return runtime_lanes_1[\"D\"]", candidate.Source, StringComparison.Ordinal);
        Assert.Equal(1, candidate.Metrics.DynamicLaneReplaySites);
    }

    [Fact]
    public void PreparedRegisterClearBecomesBoundedRange()
    {
        JsonObject prepare = SemanticFixture.Instruction(1, new JsonObject
        {
            ["kind"] = "prepare_register_clear",
            ["state"] = "clear_a",
            ["from"] = new JsonObject { ["kind"] = "constant", ["value"] = SemanticFixture.Number(2) },
            ["to"] = new JsonObject { ["kind"] = "constant", ["value"] = SemanticFixture.Number(4) },
        });
        JsonObject clear = SemanticFixture.Instruction(2, new JsonObject
        {
            ["kind"] = "clear_prepared_register_range",
            ["state"] = "clear_a",
        });
        JsonObject ir = SemanticFixture.Program(SemanticFixture.Prototype(1, prepare, clear));
        JsonObject cfg = SemanticFixture.Cfg(SemanticFixture.CfgPrototype(1,
            SemanticFixture.Block(1, 1, "observed_fallthrough", "p1_b2"),
            SemanticFixture.Block(1, 2, "return")));

        ImportedArtifacts imported = new SemanticJsonImporter().Import(ir.ToJsonString(), cfg.ToJsonString());
        LiftResult lift = new SemanticLifter().Lift(imported);
        ClearRegisterRangeOperation operation = Assert.IsType<ClearRegisterRangeOperation>(lift.Program.Prototypes[0].Instructions[1].Operation);

        Assert.Equal("2", Assert.IsType<NumberExpression>(operation.From).Text);
        Assert.Equal("4", Assert.IsType<NumberExpression>(operation.To).Text);
    }

    [Fact]
    public void ReusedClearStatePairsWithEachAdjacentProducer()
    {
        static JsonObject Prepare(int from, int to) => SemanticFixture.Instruction(0, new JsonObject
        {
            ["kind"] = "prepare_register_clear",
            ["state"] = "clear_a",
            ["from"] = new JsonObject { ["kind"] = "constant", ["value"] = SemanticFixture.Number(from) },
            ["to"] = new JsonObject { ["kind"] = "constant", ["value"] = SemanticFixture.Number(to) },
        });
        static JsonObject Clear() => SemanticFixture.Instruction(0, new JsonObject
        {
            ["kind"] = "clear_prepared_register_range",
            ["state"] = "clear_a",
        });

        JsonObject firstPrepare = Prepare(2, 4);
        JsonObject firstClear = Clear();
        JsonObject secondPrepare = Prepare(7, 9);
        JsonObject secondClear = Clear();
        firstPrepare["pc"] = 1;
        firstClear["pc"] = 2;
        secondPrepare["pc"] = 3;
        secondClear["pc"] = 4;
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, firstPrepare, firstClear, secondPrepare, secondClear));
        JsonObject cfg = SemanticFixture.Cfg(SemanticFixture.CfgPrototype(1,
            SemanticFixture.Block(1, 1, "observed_fallthrough", "p1_b2"),
            SemanticFixture.Block(1, 2, "observed_fallthrough", "p1_b3"),
            SemanticFixture.Block(1, 3, "observed_fallthrough", "p1_b4"),
            SemanticFixture.Block(1, 4, "return")));

        ImportedArtifacts imported = new SemanticJsonImporter().Import(ir.ToJsonString(), cfg.ToJsonString());
        LiftResult lift = new SemanticLifter().Lift(imported);

        ClearRegisterRangeOperation first = Assert.IsType<ClearRegisterRangeOperation>(lift.Program.Prototypes[0].Instructions[1].Operation);
        ClearRegisterRangeOperation second = Assert.IsType<ClearRegisterRangeOperation>(lift.Program.Prototypes[0].Instructions[3].Operation);
        Assert.Equal("2", Assert.IsType<NumberExpression>(first.From).Text);
        Assert.Equal("7", Assert.IsType<NumberExpression>(second.From).Text);
        Assert.DoesNotContain(lift.Program.Unresolved, item => item.Code is "ambiguous_register_clear" or "orphan_register_clear_prepare");
    }

    [Fact]
    public void WrappedBranchJumpTargetsAreReadWithoutJsonTypeErrors()
    {
        JsonObject branch = new()
        {
            ["kind"] = "branch",
            ["condition"] = new JsonObject { ["kind"] = "constant", ["value"] = true },
            ["then"] = new JsonArray(new JsonObject
            {
                ["kind"] = "jump",
                ["target"] = new JsonObject
                {
                    ["kind"] = "constant",
                    ["value"] = SemanticFixture.Number(4),
                },
            }),
            ["else"] = new JsonArray(),
        };
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, SemanticFixture.Instruction(1, branch)));
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "branch")));

        ImportedArtifacts imported = new SemanticJsonImporter().Import(ir.ToJsonString(), cfg.ToJsonString());
        BranchOperation operation = Assert.IsType<BranchOperation>(imported.Program.Prototypes[0].Instructions[0].Operation);

        Assert.Equal(5, operation.TrueTarget);
    }

    [Fact]
    public void NullClosureTargetStaysIncompleteInsteadOfThrowing()
    {
        JsonObject instruction = SemanticFixture.Instruction(1, new JsonObject
        {
            ["kind"] = "protector_internal_sequence",
            ["operations"] = new JsonArray(),
        });
        JsonObject descriptor = SemanticFixture.Descriptor(2, 5);
        descriptor["complete"] = false;
        descriptor["target_prototype"] = null;
        instruction["closure_descriptor"] = descriptor;
        JsonObject ir = SemanticFixture.Program(SemanticFixture.Prototype(1, instruction));
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")));

        ImportedArtifacts imported = new SemanticJsonImporter().Import(ir.ToJsonString(), cfg.ToJsonString());
        ClosureDescriptor closure = Assert.IsType<ClosureDescriptor>(imported.Program.Prototypes[0].Instructions[0].Closure);

        Assert.False(closure.Complete);
        Assert.Equal((ulong)0, closure.TargetPrototype);
    }

    [Fact]
    public void PayloadBootstrapTableIsEmittedFromRuntimeEvidence()
    {
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, SemanticFixture.Instruction(1, SemanticFixture.Return())));
        ir["payload_activation_arguments"] = new JsonObject
        {
            ["argument_count"] = 1,
            ["arguments"] = new JsonArray(new JsonObject
            {
                ["primitive"] = false,
                ["type"] = "table",
            }),
            ["argument_table_domains"] = new JsonArray(new JsonObject
            {
                ["argument_index"] = 1,
                ["complete"] = true,
            }),
            ["argument_table_entries"] = new JsonArray(
                RootTableEntry(1, "function", "rawset", null),
                RootTableEntry(2, "global_reference", null, "string"),
                RootTableEntry(3, "string", null, null, "hello")),
        };
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("local root_argument_1 = {", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("[1] = (resolve_named_function)(\"rawset\")", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("[2] = (environment)[\"string\"]", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("[3] = \"hello\"", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("recovered_routine_1(root_captures, root_argument_1)", candidate.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void AnonymousBootstrapFunctionBlocksFullClaim()
    {
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, SemanticFixture.Instruction(1, SemanticFixture.Return())));
        ir["payload_activation_arguments"] = new JsonObject
        {
            ["arguments"] = new JsonArray(new JsonObject
            {
                ["primitive"] = false,
                ["type"] = "function",
                ["name"] = "",
            }),
            ["argument_table_domains"] = new JsonArray(),
            ["argument_table_entries"] = new JsonArray(),
        };
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.False(candidate.FullyRendered);
        Assert.Contains(candidate.Unresolved, issue => issue.Code == "unresolved_root_argument");
        Assert.Contains("local root_argument_1 = unresolved_helper", candidate.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void StableObservedCallArgumentsReplaceOnlyTheExactCallSite()
    {
        JsonObject call = new()
        {
            ["kind"] = "call",
            ["function"] = RegisterRead(10),
            ["arguments"] = new JsonArray(RegisterRead(11), RegisterRead(12)),
        };
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, SemanticFixture.Instruction(1, SemanticFixture.Return(call))),
            SemanticFixture.Prototype(9, SemanticFixture.Instruction(1, SemanticFixture.Return())));
        ir["prototype_call_edges"] = new JsonArray(new JsonObject
        {
            ["caller_prototype"] = 1,
            ["caller_pc"] = 1,
            ["callee_prototype"] = 9,
            ["arguments_complete"] = true,
            ["stable_arguments"] = new JsonArray(
                new JsonObject
                {
                    ["primitive"] = false,
                    ["type"] = "global_reference",
                    ["path"] = "debug.traceback",
                },
                SemanticFixture.Text("traceback")),
        });
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")),
            SemanticFixture.CfgPrototype(9, SemanticFixture.Block(9, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("(environment)[\"debug\"])[\"traceback\"]", candidate.Source, StringComparison.Ordinal);
        Assert.Contains("\"traceback\"", candidate.Source, StringComparison.Ordinal);
        Assert.DoesNotContain("registers[11], registers[12]", candidate.Source, StringComparison.Ordinal);
        Assert.Equal(1, candidate.Metrics.RuntimeSpecializedCallSites);
    }

    [Fact]
    public void UnprovenCallableNameDoesNotSpecializeCallArguments()
    {
        JsonObject call = new()
        {
            ["kind"] = "call",
            ["function"] = RegisterRead(10),
            ["arguments"] = new JsonArray(RegisterRead(11)),
        };
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, SemanticFixture.Instruction(1, SemanticFixture.Return(call))),
            SemanticFixture.Prototype(9, SemanticFixture.Instruction(1, SemanticFixture.Return())));
        ir["prototype_call_edges"] = new JsonArray(new JsonObject
        {
            ["caller_prototype"] = 1,
            ["caller_pc"] = 1,
            ["callee_prototype"] = 9,
            ["arguments_complete"] = true,
            ["stable_arguments"] = new JsonArray(new JsonObject
            {
                ["primitive"] = false,
                ["type"] = "function",
                ["name"] = "traceback",
            }),
        });
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")),
            SemanticFixture.CfgPrototype(9, SemanticFixture.Block(9, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("registers[11]", candidate.Source, StringComparison.Ordinal);
        Assert.Equal(0, candidate.Metrics.RuntimeSpecializedCallSites);
    }

    [Fact]
    public void NativeObservedArgumentIdentitiesSpecializeWhenEveryActivationAgrees()
    {
        JsonObject call = new()
        {
            ["kind"] = "call",
            ["function"] = RegisterRead(89),
            ["arguments"] = new JsonArray(RegisterRead(90), RegisterRead(91)),
        };
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(2, SemanticFixture.Instruction(1, SemanticFixture.Return(call))),
            SemanticFixture.Prototype(9, SemanticFixture.Instruction(1, SemanticFixture.Return())));
        ir["payload_root"]!["payload_prototype"] = 2;
        ir["prototype_call_edges"] = new JsonArray(new JsonObject
        {
            ["caller_prototype"] = 2,
            ["caller_pc"] = 1,
            ["callee_prototype"] = 9,
            ["observed_activations"] = 3,
            ["observed_argument_count"] = 2,
            ["observed_argument_count_complete"] = true,
            ["observed_argument_identities"] = new JsonArray(
                NativeArgument(1, 3, new JsonObject
                {
                    ["primitive"] = false,
                    ["type"] = "global_reference",
                    ["path"] = "debug.traceback",
                }),
                NativeArgument(2, 3, SemanticFixture.Text("traceback"))),
        });
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(2, SemanticFixture.Block(2, 1, "return")),
            SemanticFixture.CfgPrototype(9, SemanticFixture.Block(9, 1, "return")));

        SemanticCandidate candidate = Emit(ir, cfg);

        Assert.Contains("(environment)[\"debug\"])[\"traceback\"]", candidate.Source, StringComparison.Ordinal);
        Assert.DoesNotContain("registers[90], registers[91]", candidate.Source, StringComparison.Ordinal);
        Assert.Equal(1, candidate.Metrics.RuntimeSpecializedCallSites);
    }

    private static JsonObject NativeArgument(int index, int observations, JsonObject identity) => new()
    {
        ["argument_index"] = index,
        ["observed_activations"] = observations,
        ["identity"] = identity,
    };

    private static JsonObject RegisterRead(int index) => new()
    {
        ["kind"] = "register_read",
        ["index"] = new JsonObject { ["kind"] = "constant", ["value"] = index },
    };

    private static JsonObject RootTableEntry(
        int key,
        string type,
        string? name,
        string? path,
        string? value = null)
    {
        JsonObject runtimeValue = new()
        {
            ["primitive"] = type == "string",
            ["type"] = type,
        };
        if (name is not null)
            runtimeValue["name"] = name;
        if (path is not null)
            runtimeValue["path"] = path;
        if (value is not null)
            runtimeValue["value"] = value;
        return new JsonObject
        {
            ["argument_index"] = 1,
            ["key"] = SemanticFixture.Number(key),
            ["value"] = runtimeValue,
        };
    }

    private static SemanticCandidate Emit(JsonObject ir, JsonObject cfg)
    {
        ImportedArtifacts imported = new SemanticJsonImporter().Import(ir.ToJsonString(), cfg.ToJsonString());
        LiftResult lift = new SemanticLifter().Lift(imported);
        return new LuauEmitter().Emit(lift);
    }
}
