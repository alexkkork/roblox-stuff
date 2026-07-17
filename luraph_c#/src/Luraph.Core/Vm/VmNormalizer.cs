using Luraph.Core.Containers;

namespace Luraph.Core.Vm;

public static class VmNormalizer
{
    public static OperandLane NormalizeLane(long rawWord, int pc, int constantCount, int prototypeCount)
    {
        var residue = rawWord % 8;
        if (residue < 0)
            residue += 8;
        var quotient = (rawWord - residue) / 8;
        var baseValue = quotient;
        var side = new SideReference();

        if (residue == 1)
            side = Reference(ReferenceKind.Constant, quotient, constantCount);
        else if (residue == 3)
            side = Reference(ReferenceKind.Prototype, quotient, prototypeCount);
        else if (residue == 5)
            baseValue = pc - quotient;
        else if (residue == 6)
            baseValue = pc + quotient;

        return new()
        {
            RawWord = rawWord,
            Residue = (uint)residue,
            Quotient = quotient,
            BaseValue = baseValue,
            SideReference = side,
        };
    }

    public static NormalizedInstruction NormalizeInstruction(
        InstructionMetadata instruction,
        int constantCount,
        int prototypeCount)
    {
        if (instruction.Words.Length != 4)
            throw new ArgumentException("A Luraph instruction needs four words.", nameof(instruction));
        var pc = checked(instruction.Index + 1);
        return new()
        {
            MetadataIndex = instruction.Index,
            Pc = pc,
            Opcode = instruction.Words[2].Value,
            D = NormalizeLane(instruction.Words[0].Value, pc, constantCount, prototypeCount),
            G = NormalizeLane(instruction.Words[1].Value, pc, constantCount, prototypeCount),
            P = NormalizeLane(instruction.Words[3].Value, pc, constantCount, prototypeCount),
        };
    }

    public static NormalizedContainer NormalizeContainer(ContainerAnalysis container)
    {
        var rootValid = container.RootSelector >= 1 && container.RootSelector <= (ulong)container.Prototypes.Count;
        var prototypes = container.Prototypes.Select(prototype => new NormalizedPrototype
        {
            MetadataIndex = prototype.Index,
            WrapperIndex = checked(prototype.Index + 1),
            RegisterCapacity = prototype.FinalValue,
            Instructions = prototype.Instructions
                .Select(instruction => NormalizeInstruction(instruction, container.Constants.Count, container.Prototypes.Count))
                .ToArray(),
        }).ToArray();

        return new()
        {
            ConstantPoolMode = container.ConstantPoolMode,
            RootWrapperIndex = container.RootSelector,
            RootMetadataIndex = rootValid ? checked((int)container.RootSelector - 1) : null,
            RootValid = rootValid,
            Prototypes = prototypes,
        };
    }

    private static SideReference Reference(ReferenceKind kind, long wrapperIndex, int count)
    {
        var valid = wrapperIndex >= 1 && wrapperIndex <= count;
        return new()
        {
            Kind = kind,
            WrapperIndex = wrapperIndex,
            MetadataIndex = valid ? checked((int)wrapperIndex - 1) : null,
            Valid = valid,
        };
    }
}
