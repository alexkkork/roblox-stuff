using Luraph.Core.Scanning;

namespace Luraph.Core.Containers.Legacy;

public enum LegacyDecodeStatus
{
    NotAttempted,
    Decoded,
    InvalidPrefix,
    InvalidCharacter,
    MisalignedBody,
    Overflow,
    OutputLimitExceeded,
}

public enum LegacyParseStatus
{
    NotAttempted,
    MetadataOnly,
    Parsed,
    InvalidSource,
    CarrierNotFound,
    OffsetInferenceFailed,
    ConstantTagInferenceFailed,
    ConstantPoolInvalid,
    PrototypeLayoutInvalid,
    RootInvalid,
    LimitExceeded,
}

public enum LegacyConstantKind
{
    Boolean,
    Double,
    String,
    Int64,
}

public enum LegacyPayloadClass
{
    Unknown,
    Tiny,
    Substantial,
}

public enum LegacyOperandRole
{
    Constant,
    Forward,
    Backward,
    Prototype,
}

public enum LegacyOperandSlot
{
    C,
    A,
    B,
}

public sealed record LegacyOffsetEvidence(
    long Value,
    string Literal,
    SourceRange Range);

public sealed record LegacyCountCandidate(long Offset, int Count);

public sealed record LegacyInferenceMetrics
{
    public ulong? RawConstantCount { get; init; }
    public byte? InferredStringTag { get; init; }
    public int StringAnchorMatches { get; init; }
    public int ConstantTagTrials { get; init; }
    public IReadOnlyList<LegacyCountCandidate> ConstantCountCandidates { get; init; } = [];
}

public sealed record LegacyDiagnostic(
    DiagnosticSeverity Severity,
    string Code,
    string Message,
    int? ByteOffset = null,
    SourceRange? SourceRange = null);

public sealed record LegacyConstantTagMap(byte Boolean, byte Double, byte String, byte Int64)
{
    public bool IsDistinct => new HashSet<byte> { Boolean, Double, String, Int64 }.Count == 4;

    public LegacyConstantKind? Resolve(byte tag)
    {
        if (tag == Boolean)
            return LegacyConstantKind.Boolean;
        if (tag == Double)
            return LegacyConstantKind.Double;
        if (tag == String)
            return LegacyConstantKind.String;
        if (tag == Int64)
            return LegacyConstantKind.Int64;
        return null;
    }
}

public sealed record LegacyCountOffsets(long Constant, long Prototype, long Instruction);

public sealed record LegacyParseOptions
{
    public AnalysisLimits Limits { get; init; } = new();
    public LegacyConstantTagMap? ConstantTags { get; init; }
    public LegacyCountOffsets? CountOffsets { get; init; }
    public bool? HasExtraPrototypeField { get; init; }
    public int MaxOffsetCandidates { get; init; } = 8;
    public int MaxConstantAlignments { get; init; } = 16;
    public int MaxLayoutAttempts { get; init; } = 256;
}

public sealed record LegacyCarrierMetadata
{
    public string Marker { get; init; } = string.Empty;
    public int EncodedBytes { get; init; }
    public int EncodedBodyBytes { get; init; }
    public int GroupCount { get; init; }
    public int ZeroGroupCount { get; init; }
    public int DecodedBytes { get; init; }
    public string DecodedSha256 { get; init; } = string.Empty;
    public LegacyDecodeStatus Status { get; init; }
    public int? ErrorOffset { get; init; }
}

public sealed record LegacyConstant
{
    public int Index { get; init; }
    public byte Tag { get; init; }
    public LegacyConstantKind Kind { get; init; }
    public ByteSpan Span { get; init; }
    public bool? BooleanValue { get; init; }
    public double? DoubleValue { get; init; }
    public long? Int64Value { get; init; }
    public byte[] StringBytes { get; init; } = [];
}

public sealed record LegacyResolvedDescriptor(int Index, ulong Raw, ulong Base, uint Mode, ByteSpan Span);

public sealed record LegacyInstruction
{
    public int Index { get; init; }
    public ulong RawC { get; init; }
    public ulong RawA { get; init; }
    public ulong RawB { get; init; }
    public ulong Opcode { get; init; }
    public ByteSpan Span { get; init; }

    public ulong Lane(LegacyOperandSlot slot) => slot switch
    {
        LegacyOperandSlot.C => RawC,
        LegacyOperandSlot.A => RawA,
        _ => RawB,
    };
}

public sealed record LegacyLineEntry(int Pc, int Line);

public sealed record LegacyPrototypeReference(
    int SourcePrototype,
    int Pc,
    LegacyOperandSlot Slot,
    int TargetPrototype,
    bool Valid);

public sealed record LegacyPrototype
{
    public int Index { get; init; }
    public int MaxStack { get; init; }
    public int UpvalueCount { get; init; }
    public IReadOnlyList<LegacyResolvedDescriptor> Descriptors { get; init; } = [];
    public IReadOnlyList<LegacyInstruction> Instructions { get; init; } = [];
    public IReadOnlyList<LegacyLineEntry> Lines { get; init; } = [];
    public ByteSpan Span { get; init; }
}

public sealed record LegacyModeScore(
    LegacyOperandRole Role,
    uint Residue,
    LegacyOperandSlot? Slot,
    int Valid,
    int Invalid);

public sealed record LegacyModeMetadata
{
    public uint ConstantResidue { get; init; }
    public uint ForwardResidue { get; init; }
    public uint BackwardResidue { get; init; }
    public uint PrototypeResidue { get; init; }
    public LegacyOperandSlot PrototypeSlot { get; init; }
    public int CandidatesEvaluated { get; init; }
    public bool UniqueBest { get; init; }
    public bool ArrayPermutationResolved { get; init; }
    public int ArrayPermutationCandidates { get; init; } = 6;
    public IReadOnlyList<LegacyModeScore> Scores { get; init; } = [];
}

public sealed record LegacyContainerResult
{
    public LegacyParseStatus Status { get; init; }
    public LegacyCarrierMetadata Carrier { get; init; } = new();
    public IReadOnlyList<LegacyOffsetEvidence> OffsetEvidence { get; init; } = [];
    public LegacyCountOffsets? EffectiveOffsets { get; init; }
    public LegacyConstantTagMap? ConstantTags { get; init; }
    public LegacyInferenceMetrics Inference { get; init; } = new();
    public bool ConstantCacheEnabled { get; init; }
    public bool HasExtraPrototypeField { get; init; }
    public int ConstantCount { get; init; }
    public int PrototypeCount { get; init; }
    public int InstructionCount { get; init; }
    public int DescriptorCount { get; init; }
    public int LineEntryCount { get; init; }
    public int UpvalueCount { get; init; }
    public int RootPrototype { get; init; }
    public int ReachablePrototypeCount { get; init; }
    public int ReachableInstructionCount { get; init; }
    public LegacyPayloadClass PayloadClass { get; init; }
    public int LayoutAttempts { get; init; }
    public IReadOnlyList<LegacyConstant> Constants { get; init; } = [];
    public IReadOnlyList<LegacyPrototype> Prototypes { get; init; } = [];
    public LegacyModeMetadata? Modes { get; init; }
    public IReadOnlyList<LegacyPrototypeReference> PrototypeReferences { get; init; } = [];
    public IReadOnlyList<LegacyDiagnostic> Diagnostics { get; init; } = [];
}
