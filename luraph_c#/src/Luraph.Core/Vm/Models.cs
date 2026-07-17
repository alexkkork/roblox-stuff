namespace Luraph.Core.Vm;

public enum ReferenceKind
{
    None,
    Constant,
    Prototype,
}

public sealed record SideReference
{
    public ReferenceKind Kind { get; init; }
    public long WrapperIndex { get; init; }
    public int? MetadataIndex { get; init; }
    public bool Valid { get; init; }
}

public sealed record OperandLane
{
    public long RawWord { get; init; }
    public uint Residue { get; init; }
    public long Quotient { get; init; }
    public long BaseValue { get; init; }
    public SideReference SideReference { get; init; } = new();
}

public sealed record NormalizedInstruction
{
    public int MetadataIndex { get; init; }
    public int Pc { get; init; } = 1;
    public long Opcode { get; init; }
    public required OperandLane D { get; init; }
    public required OperandLane G { get; init; }
    public required OperandLane P { get; init; }
}

public sealed record NormalizedPrototype
{
    public int MetadataIndex { get; init; }
    public int WrapperIndex { get; init; } = 1;
    public ulong RegisterCapacity { get; init; }
    public IReadOnlyList<NormalizedInstruction> Instructions { get; init; } = [];
}

public sealed record NormalizedContainer
{
    public byte ConstantPoolMode { get; init; }
    public ulong RootWrapperIndex { get; init; }
    public int? RootMetadataIndex { get; init; }
    public bool RootValid { get; init; }
    public IReadOnlyList<NormalizedPrototype> Prototypes { get; init; } = [];
}

