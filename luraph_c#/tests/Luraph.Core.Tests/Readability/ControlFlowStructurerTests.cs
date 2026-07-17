using Luraph.Core.Ir;
using Luraph.Core.Readability;

namespace Luraph.Core.Tests.Readability;

public sealed class ControlFlowStructurerTests
{
    [Fact]
    public void DiamondIsRecognizedAsOneBranch()
    {
        PrototypeControlFlow cfg = new(1, 1,
        [
            Block(1, BlockTerminatorKind.Branch, 2, 3),
            Block(2, BlockTerminatorKind.Fallthrough, 4),
            Block(3, BlockTerminatorKind.Fallthrough, 4),
            Block(4, BlockTerminatorKind.Return),
        ]);

        ControlFlowStructure result = new ControlFlowStructurer().Analyze(cfg);

        StructuredBranch branch = Assert.Single(result.Branches);
        Assert.Equal(1, branch.Header);
        Assert.Equal(4, branch.Join);
        Assert.Empty(result.ResidualBlocks);
    }

    [Fact]
    public void BackEdgeProducesNaturalLoop()
    {
        PrototypeControlFlow cfg = new(1, 1,
        [
            Block(1, BlockTerminatorKind.Fallthrough, 2),
            Block(2, BlockTerminatorKind.Branch, 2, 3),
            Block(3, BlockTerminatorKind.Return),
        ]);

        ControlFlowStructure result = new ControlFlowStructurer().Analyze(cfg);

        StructuredLoop loop = Assert.Single(result.Loops);
        Assert.Equal(2, loop.Header);
        Assert.Equal(3, loop.Exit);
        Assert.Equal(new HashSet<int> { 2 }, loop.Body);
    }

    private static BasicBlock Block(int pc, BlockTerminatorKind terminator, params int[] successors) =>
        new($"b{pc}", pc, pc, true, terminator, successors);
}
