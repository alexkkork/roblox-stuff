using Luraph.Core.Ir;
using Luraph.Core.Lifting;

namespace Luraph.Core.Readability;

public sealed record ReadabilityStats(
    int StructuredBlocks,
    int ResidualBlocks,
    int RegisterPrototypes,
    int RegisterSlots,
    int RegisterAccesses,
    int NamesImproved);

public sealed record ReadabilityResult(LiftResult Lift, ReadabilityStats Stats);

public sealed class ReadabilityPipeline
{
    public ReadabilityResult Apply(LiftResult lift)
    {
        RegisterScalarizationResult registers = new RegisterScalarizer().Apply(lift.Program);
        SemanticNamingResult names = new SemanticNamer().Apply(registers.Program);
        List<ControlFlowStructure> structures = lift.ControlFlow.Prototypes
            .Select(prototype => new ControlFlowStructurer().Analyze(prototype))
            .ToList();
        ReadabilityStats stats = new(
            structures.Sum(item => item.StructuredBlocks.Count),
            structures.Sum(item => item.ResidualBlocks.Count),
            registers.PrototypesChanged,
            registers.SlotsScalarized,
            registers.AccessesRewritten,
            names.NamesChanged);
        return new ReadabilityResult(lift with { Program = names.Program }, stats);
    }
}
