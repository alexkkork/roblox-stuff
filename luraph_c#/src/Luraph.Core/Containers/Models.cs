namespace Luraph.Core.Containers;

public readonly record struct ByteSpan(int Begin, int End)
{
    public int Length => Math.Max(0, End - Begin);
}

public enum ContainerDecodeStatus
{
    NotAttempted,
    Decoded,
    InvalidPrefix,
    MisalignedBody,
    InvalidCharacter,
    Radix85Overflow,
    OutputLimitExceeded,
}

public enum ContainerParseStatus
{
    NotAttempted,
    Parsed,
    Truncated,
    UlebOverflow,
    NonCanonicalUleb,
    CountUnderflow,
    CountLimitExceeded,
    SignedFoldOverflow,
    TrailerLimitExceeded,
}

public enum ConstantKind
{
    String,
    Integer,
    Boolean,
    Float,
    Nil,
}

public sealed record ConstantMetadata
{
    public int Index { get; init; }
    public byte Tag { get; init; }
    public ConstantKind Kind { get; init; }
    public ByteSpan Span { get; init; }
    public ByteSpan TagSpan { get; init; }
    public ByteSpan? LengthSpan { get; init; }
    public ByteSpan DataSpan { get; init; }
    public int DataBytes { get; init; }
    public long? SignedIntegerValue { get; init; }
    public ulong? UnsignedIntegerValue { get; init; }
    public bool? BooleanValue { get; init; }
    public float? Float32Value { get; init; }
    public double? Float64Value { get; init; }
    public uint? Float32Bits { get; init; }
    public ulong? Float64Bits { get; init; }
    public byte[] StringBytes { get; init; } = [];
}

public sealed record DescriptorMetadata(
    int Index,
    ulong RawValue,
    uint Kind,
    ulong ReferencedIndex,
    ByteSpan Span);

public sealed record InstructionWordMetadata(long Value, ByteSpan Span);

public sealed record InstructionMetadata
{
    public int Index { get; init; }
    public ByteSpan Span { get; init; }
    public InstructionWordMetadata[] Words { get; init; } = [];
}

public sealed record PrototypeMetadata
{
    public int Index { get; init; }
    public ByteSpan Span { get; init; }
    public ulong Meta { get; init; }
    public ByteSpan MetaSpan { get; init; }
    public int InstructionCount { get; init; }
    public ByteSpan InstructionCountSpan { get; init; }
    public ByteSpan InstructionWordsSpan { get; init; }
    public int DescriptorCount { get; init; }
    public ByteSpan DescriptorCountSpan { get; init; }
    public ByteSpan DescriptorsSpan { get; init; }
    public ulong FinalValue { get; init; }
    public ByteSpan FinalSpan { get; init; }
    public IReadOnlyList<InstructionMetadata> Instructions { get; init; } = [];
    public IReadOnlyList<DescriptorMetadata> Descriptors { get; init; } = [];
}

public sealed record ContainerAnalysis
{
    public int CarrierIndex { get; init; }
    public ContainerDecodeStatus DecodeStatus { get; init; }
    public ContainerParseStatus ParseStatus { get; init; }
    public int EncodedCarrierBytes { get; init; }
    public int EncodedBodyBytes { get; init; }
    public int Radix85GroupCount { get; init; }
    public int DecodedBytes { get; init; }
    public string DecodedSha256 { get; init; } = string.Empty;
    public int? EncodedErrorOffset { get; init; }
    public int? ParseErrorOffset { get; init; }
    public int ConstantCount { get; init; }
    public ByteSpan ConstantCountSpan { get; init; }
    public byte ConstantPoolMode { get; init; }
    public ByteSpan ConstantPoolModeSpan { get; init; }
    public ByteSpan ConstantsSpan { get; init; }
    public int PrototypeCount { get; init; }
    public ByteSpan PrototypeCountSpan { get; init; }
    public ByteSpan PrototypesSpan { get; init; }
    public int InstructionCount { get; init; }
    public int DescriptorCount { get; init; }
    public ulong RootSelector { get; init; }
    public ByteSpan RootSelectorSpan { get; init; }
    public ByteSpan TrailerSpan { get; init; }
    public IReadOnlyList<ConstantMetadata> Constants { get; init; } = [];
    public IReadOnlyList<PrototypeMetadata> Prototypes { get; init; } = [];
    public byte[] TrailerBytes { get; init; } = [];
}

public sealed record ContainerMetrics
{
    public int CandidateCount { get; internal set; }
    public int AttemptCount { get; internal set; }
    public int DecodedCount { get; internal set; }
    public int ParsedCount { get; internal set; }
    public int FailureCount { get; internal set; }
    public int EncodedBodyBytes { get; internal set; }
    public int Radix85GroupCount { get; internal set; }
    public int DecodedBytes { get; internal set; }
    public int ConstantCount { get; internal set; }
    public int PrototypeCount { get; internal set; }
    public int InstructionCount { get; internal set; }
    public int DescriptorCount { get; internal set; }
    public int TrailerBytes { get; internal set; }
}

