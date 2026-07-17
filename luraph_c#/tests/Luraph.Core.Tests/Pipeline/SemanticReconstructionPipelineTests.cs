using System.Text.Json.Nodes;
using Luraph.Core.Tests.Lifting;

namespace Luraph.Core.Pipeline;

public sealed class SemanticReconstructionPipelineTests
{
    [Fact]
    public void CompleteTypedGraphProducesReadyCandidate()
    {
        JsonObject ir = SemanticFixture.Program(SemanticFixture.Prototype(1,
            SemanticFixture.Instruction(1, SemanticFixture.Return(new JsonObject
            {
                ["kind"] = "constant",
                ["value"] = SemanticFixture.Text("ok"),
            }))));
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")));

        SemanticReconstructionResult result = new SemanticReconstructionPipeline().Reconstruct(
            ir.ToJsonString(), cfg.ToJsonString());

        Assert.True(result.Ready);
        Assert.True(result.Lift.Validation.Valid);
        Assert.Contains("return \"ok\"", result.Candidate.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void IncompleteClosureIsEmittedForInspectionButNotPromoted()
    {
        JsonObject instruction = SemanticFixture.Instruction(1, new JsonObject
        {
            ["kind"] = "protector_internal_sequence",
            ["operations"] = new JsonArray(),
        });
        JsonObject descriptor = SemanticFixture.Descriptor(2, 4);
        descriptor["complete"] = false;
        descriptor["target_prototype"] = null;
        instruction["closure_descriptor"] = descriptor;
        JsonObject ir = SemanticFixture.Program(
            SemanticFixture.Prototype(1, instruction),
            SemanticFixture.Prototype(2, SemanticFixture.Instruction(1, SemanticFixture.Return())));
        JsonObject cfg = SemanticFixture.Cfg(
            SemanticFixture.CfgPrototype(1, SemanticFixture.Block(1, 1, "return")),
            SemanticFixture.CfgPrototype(2, SemanticFixture.Block(2, 1, "return")));

        SemanticReconstructionResult result = new SemanticReconstructionPipeline().Reconstruct(
            ir.ToJsonString(), cfg.ToJsonString());

        Assert.False(result.Ready);
        Assert.NotEmpty(result.Candidate.Source);
        Assert.Contains(result.Candidate.Unresolved, issue => issue.Code == "incomplete_closure_descriptor");
    }
}
