namespace Luraph.Core.Scanning;

public readonly record struct SourceRange(int Begin, int End)
{
    public int Length => Math.Max(0, End - Begin);
}

public enum WrapperKind
{
    None,
    ReturnedTable,
    ReturnedTableMethodDispatch,
}

public enum BlobKind
{
    OpaquePrintable,
    LphMarker,
    LphAmpersand,
    LphDollar,
}

public enum CarrierLiteralKind
{
    QuotedString,
    LongBracketString,
}

public enum CarrierDecodeStatus
{
    NotAttempted,
    DecodedLiteral,
    InvalidLiteral,
    UnsupportedLiteral,
    ByteLimitExceeded,
}

public enum ReaderValueKind
{
    UnsignedInteger,
    SignedInteger,
    FloatingPoint,
}

public enum ByteOrder
{
    Unknown,
    LittleEndian,
    BigEndian,
}

public enum StageKind
{
    ProtectionBanner,
    WrapperConstruction,
    EncodedPayload,
    ReaderSetup,
    InterpreterScaffolding,
    EntrypointDispatch,
}

public enum ConfidenceLevel
{
    None,
    Low,
    Medium,
    High,
}

public sealed record BannerInfo
{
    public bool Present { get; init; }
    public bool ExactProductMarker { get; init; }
    public bool OfficialUrlMarker { get; init; }
    public string Product { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public uint? Major { get; init; }
    public uint? Minor { get; init; }
    public uint? Patch { get; init; }
    public SourceRange? Range { get; init; }
}

public sealed record LuaAuthLauncherInfo
{
    public bool Present { get; init; }
    public bool ExactAssignmentShape { get; init; }
    public bool OfficialUrlMarker { get; init; }
    public bool MetadataRemovedFromBody { get; init; }
    public int CodeDigitCount { get; init; }
    public int ScriptIdByteCount { get; init; }
    public SourceRange? Range { get; init; }
    public SourceRange? ProtectedBodyRange { get; init; }
}

public sealed record WrapperShape
{
    public WrapperKind Kind { get; init; }
    public bool TopLevelReturn { get; init; }
    public bool ParenthesizedTable { get; init; }
    public bool BalancedTable { get; init; }
    public bool ZeroArgumentMethodCall { get; init; }
    public bool ForwardsVarargs { get; init; }
    public bool ConsumesEntireChunk { get; init; }
    public string MethodName { get; init; } = string.Empty;
    public int TableFieldCount { get; init; }
    public int FunctionMemberCount { get; init; }
    public SourceRange? TableRange { get; init; }
    public SourceRange? InvocationRange { get; init; }
}

public sealed record EnvelopeCounts
{
    public int SourceBytes { get; internal set; }
    public int TokenCount { get; internal set; }
    public int CommentCount { get; internal set; }
    public int IdentifierCount { get; internal set; }
    public int NumericLiteralCount { get; internal set; }
    public int StringLiteralCount { get; internal set; }
    public int StringLiteralSourceBytes { get; internal set; }
    public int EncodedStringCandidateCount { get; internal set; }
    public int EncodedBlobCandidateCount { get; internal set; }
    public int EncodedBlobSourceBytes { get; internal set; }
    public int TableConstructorCount { get; internal set; }
    public int FunctionLiteralCount { get; internal set; }
    public int LoopConstructCount { get; internal set; }
    public int IndexedAccessCount { get; internal set; }
    public int ReaderPrimitiveReferenceCount { get; internal set; }
}

public sealed record BlobCandidate(
    BlobKind Kind,
    SourceRange Range,
    int SourceBytes,
    int DistinctByteCount,
    double PrintableRatio,
    double WhitespaceRatio,
    bool LongBracketLiteral,
    bool HasLphMarker);

public sealed record CarrierExtraction
{
    public BlobKind Kind { get; init; }
    public CarrierLiteralKind LiteralKind { get; init; }
    public CarrierDecodeStatus Status { get; init; }
    public SourceRange LiteralRange { get; init; }
    public SourceRange ContentRange { get; init; }
    public SourceRange? ErrorRange { get; init; }
    public int LiteralSourceBytes { get; init; }
    public int DecodedByteCount { get; init; }
    public int? LphMarkerOffset { get; init; }
    public int? ContainerIndex { get; init; }
    public byte[] Bytes { get; init; } = [];
}

public sealed record ReaderMetadata(
    string Name,
    ReaderValueKind ValueKind,
    ByteOrder ByteOrder,
    int BitWidth,
    int ByteWidth,
    int ReferenceCount,
    bool DefinitionPresent,
    bool InferredFromIdentifier,
    bool ImplementationVerified,
    SourceRange NameRange,
    SourceRange? DefinitionRange);

public sealed record StaticDecodeMetrics
{
    public bool Eligible { get; internal set; }
    public bool Attempted { get; internal set; }
    public bool Complete { get; internal set; }
    public bool PayloadDecodeAttempted { get; internal set; }
    public bool PayloadDecoded { get; internal set; }
    public int CarrierCandidateCount { get; internal set; }
    public int CarrierAttemptCount { get; internal set; }
    public int CarrierDecodedCount { get; internal set; }
    public int CarrierFailureCount { get; internal set; }
    public int CarrierSkippedCount { get; internal set; }
    public int CarrierLiteralSourceBytes { get; internal set; }
    public int DecodedCarrierBytes { get; internal set; }
    public int ByteLimitHitCount { get; internal set; }
    public int ReaderMetadataCount { get; internal set; }
    public int ReaderDefinitionCount { get; internal set; }
    public int ReaderReferenceCount { get; internal set; }
}

public sealed record ScanStage(StageKind Kind, double Confidence, string Summary, SourceRange? Range = null);

public sealed record ConfidenceEvidence(string Code, double Weight, string Description);

public sealed record ScanConfidence
{
    public double Score { get; internal set; }
    public ConfidenceLevel Level { get; internal set; }
    public List<ConfidenceEvidence> Evidence { get; } = [];
}

public sealed record ScanDiagnostic(
    DiagnosticSeverity Severity,
    string Code,
    string Message,
    SourceRange? Range = null);
