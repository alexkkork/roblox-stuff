using Luraph.Core.Emission;
using Luraph.Core.Ir;
using Luraph.Core.Lifting;
using Luraph.Core.Readability;

namespace Luraph.Core.Pipeline;

public sealed record SemanticReconstructionResult(
    ReadabilityResult Readability,
    SemanticCandidate Candidate)
{
    public LiftResult Lift => Readability.Lift;

    public bool Ready =>
        Lift.Validation.Valid &&
        Lift.Program.Root is not null &&
        Lift.Program.Prototypes.Count > 0 &&
        Candidate.FullyRendered;
}

public sealed class SemanticReconstructionPipeline
{
    public SemanticReconstructionResult Reconstruct(string semanticIrJson, string cfgJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(semanticIrJson);
        ArgumentException.ThrowIfNullOrWhiteSpace(cfgJson);

        ImportedArtifacts imported = new SemanticJsonImporter().Import(semanticIrJson, cfgJson);
        LiftResult lift = new SemanticLifter().Lift(imported);
        ReadabilityResult readable = new ReadabilityPipeline().Apply(lift);
        SemanticCandidate candidate = new LuauEmitter().Emit(readable.Lift);
        return new SemanticReconstructionResult(readable, candidate);
    }
}
