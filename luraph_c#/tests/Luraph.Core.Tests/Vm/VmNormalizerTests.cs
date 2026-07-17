using Luraph.Core.Containers;
using Luraph.Core.Vm;

namespace Luraph.Core.Tests.Vm;

public sealed class VmNormalizerTests
{
    [Fact]
    public void NormalizesPlainAndReferencedLanes()
    {
        var root = VmNormalizer.NormalizeInstruction(Instruction(0, [2, 718, 90, 2]), 1_145, 37);
        var constants = VmNormalizer.NormalizeInstruction(Instruction(4, [2_409, 7_281, 39, 354]), 1_145, 37);
        var closure = VmNormalizer.NormalizeInstruction(Instruction(168, [91, 122, 22, 2]), 1_145, 37);

        Assert.Equal(1, root.Pc);
        Assert.Equal(90, root.Opcode);
        Assert.Equal(0, root.D.BaseValue);
        Assert.Equal(90, root.G.BaseValue);

        Assert.Equal((uint)1, constants.D.Residue);
        Assert.Equal(301, constants.D.Quotient);
        Assert.Equal(ReferenceKind.Constant, constants.D.SideReference.Kind);
        Assert.True(constants.D.SideReference.Valid);
        Assert.Equal(300, constants.D.SideReference.MetadataIndex);
        Assert.Equal(909, constants.G.SideReference.MetadataIndex);

        Assert.Equal(169, closure.Pc);
        Assert.Equal(ReferenceKind.Prototype, closure.D.SideReference.Kind);
        Assert.Equal(10, closure.D.SideReference.MetadataIndex);
    }

    [Fact]
    public void UsesEuclideanResiduesAndRelativePc()
    {
        var backward = VmNormalizer.NormalizeLane(8 * 4 + 5, 20, 10, 10);
        var forward = VmNormalizer.NormalizeLane(8 * 4 + 6, 20, 10, 10);
        var negative = VmNormalizer.NormalizeLane(-3, 20, 10, 10);

        Assert.Equal(16, backward.BaseValue);
        Assert.Equal(24, forward.BaseValue);
        Assert.Equal((uint)5, negative.Residue);
        Assert.Equal(-1, negative.Quotient);
        Assert.Equal(21, negative.BaseValue);
    }

    [Fact]
    public void RejectsOutOfRangeReferences()
    {
        var lane = VmNormalizer.NormalizeLane(8 * 99 + 1, 1, 10, 10);

        Assert.Equal(ReferenceKind.Constant, lane.SideReference.Kind);
        Assert.False(lane.SideReference.Valid);
        Assert.Null(lane.SideReference.MetadataIndex);
    }

    [Fact]
    public void NormalizesRootAndPrototypeMetadata()
    {
        var container = new ContainerAnalysis
        {
            ConstantPoolMode = 7,
            RootSelector = 2,
            Constants = [new(), new(), new(), new()],
            Prototypes =
            [
                new PrototypeMetadata
                {
                    Index = 0,
                    FinalValue = 12,
                    Instructions = [Instruction(0, [2, 718, 90, 2])],
                },
                new PrototypeMetadata { Index = 1, FinalValue = 35 },
            ],
        };

        var normalized = VmNormalizer.NormalizeContainer(container);

        Assert.True(normalized.RootValid);
        Assert.Equal(1, normalized.RootMetadataIndex);
        Assert.Equal((ulong)2, normalized.RootWrapperIndex);
        Assert.Equal((byte)7, normalized.ConstantPoolMode);
        Assert.Equal(1, normalized.Prototypes[0].WrapperIndex);
        Assert.Equal((ulong)12, normalized.Prototypes[0].RegisterCapacity);
        Assert.Single(normalized.Prototypes[0].Instructions);
    }

    [Fact]
    public void KeepsInvalidRootUnresolved()
    {
        var normalized = VmNormalizer.NormalizeContainer(new()
        {
            RootSelector = 0,
            Prototypes = [new PrototypeMetadata { Index = 0 }],
        });

        Assert.False(normalized.RootValid);
        Assert.Null(normalized.RootMetadataIndex);
    }

    private static InstructionMetadata Instruction(int index, long[] words) => new()
    {
        Index = index,
        Words = words.Select(value => new InstructionWordMetadata(value, default)).ToArray(),
    };
}
