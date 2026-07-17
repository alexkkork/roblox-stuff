using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Luraph.Core;

public static class DeobfuscatorInfo
{
    public const string Version = "9.0";
}

[JsonConverter(typeof(JsonStringEnumConverter<DeobfuscationMode>))]
public enum DeobfuscationMode
{
    Inspect,
    Disassemble,
    Reconstruct,
}

[JsonConverter(typeof(JsonStringEnumConverter<DeobfuscationStatus>))]
public enum DeobfuscationStatus
{
    Invalid,
    Inspected,
    Disassembled,
    Blocked,
    Reconstructed,
}

[JsonConverter(typeof(JsonStringEnumConverter<DiagnosticSeverity>))]
public enum DiagnosticSeverity
{
    Info,
    Warning,
    Error,
}

public sealed record AnalysisLimits
{
    public int MaxSourceBytes { get; init; } = 2 * 1024 * 1024;
    public int MaxTokens { get; init; } = 500_000;
    public int MaxNesting { get; init; } = 512;
    public int MaxBlobCandidates { get; init; } = 16;
    public int MaxCarrierBytes { get; init; } = 2 * 1024 * 1024;
    public int MaxContainerBytes { get; init; } = 2 * 1024 * 1024;
    public int MaxConstants { get; init; } = 100_000;
    public int MaxPrototypes { get; init; } = 10_000;
    public int MaxInstructions { get; init; } = 1_000_000;
    public int MaxDescriptors { get; init; } = 200_000;
    public int MaxTrailerBytes { get; init; } = 2 * 1024 * 1024;
    public int MaxDiagnostics { get; init; } = 32;
    public int MaxTraceBytes { get; init; } = 64 * 1024 * 1024;
}

public sealed record RuntimeSettings
{
    public string? BinaryPath { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
    public long MaxSteps { get; init; } = 2_000_000_000;
    public int MemoryLimitMb { get; init; } = 768;
    public bool AutoTrace { get; init; } = true;
    public int MaxProbePasses { get; init; } = 2;
}

public sealed record DeobfuscationRequest
{
    public required string InputPath { get; init; }
    public required string OutputDirectory { get; init; }
    public DeobfuscationMode Mode { get; init; } = DeobfuscationMode.Reconstruct;
    public RuntimeSettings Runtime { get; init; } = new();
    public AnalysisLimits Limits { get; init; } = new();
    public string? TracePath { get; init; }
    public long? TraceWindowStart { get; init; }
    public long? TraceWindowEnd { get; init; }
}

public sealed record ProgressEvent(
    string Stage,
    string Status,
    string Message,
    JsonObject? Metrics = null,
    int Attempt = 1);

public sealed record Diagnostic(
    string Stage,
    string Code,
    string Message,
    DiagnosticSeverity Severity = DiagnosticSeverity.Error,
    JsonObject? Details = null);

public sealed record TracePassSummary(
    int Pass,
    string Kind,
    bool Started,
    bool Completed,
    int ExitCode,
    long Bytes,
    string? TracePath,
    string? Reason);

public sealed record VerificationSummary
{
    public bool CompileAttempted { get; init; }
    public bool Compiled { get; init; }
    public bool RuntimeAttempted { get; init; }
    public bool Equivalent { get; init; }
    public bool BoundedOnly { get; init; }
    public string? Scope { get; init; }
    public IReadOnlyList<string> ProtectorScaffoldingExcluded { get; init; } = [];
    public string? Reason { get; init; }
}

public sealed record CoverageSummary
{
    public string LiftBackend { get; init; } = "static-container";
    public int Containers { get; init; }
    public int Prototypes { get; init; }
    public int Instructions { get; init; }
    public int ReachableInstructions { get; init; }
    public int ClassifiedInstructions { get; init; }
    public int DecoderPrototypes { get; init; }
    public int Constants { get; init; }
    public int Blocks { get; init; }
    public int LiftedOperations { get; init; }
    public int UnresolvedOperations { get; init; }
    public bool StatementCoverageComplete { get; init; }
    public int StructuredBlocks { get; init; }
    public int ResidualBlocks { get; init; }
    public int RegistersScalarized { get; init; }
    public int RegisterAccessesScalarized { get; init; }
    public int NamesImproved { get; init; }
}

public sealed record ArtifactManifest
{
    public string Report { get; init; } = "report.json";
    public string Envelope { get; init; } = "envelope.json";
    public string LegacyContainer { get; init; } = "legacy_container.json";
    public string Constants { get; init; } = "constants.json";
    public string Vm { get; init; } = "vm.json";
    public string Cfg { get; init; } = "cfg.json";
    public string SemanticIr { get; init; } = "semantic_ir.json";
    public string OpcodeHandlers { get; init; } = "opcode_handlers.json";
    public string Mapping { get; init; } = "mapping.json";
    public string Disassembly { get; init; } = "disassembly.txt";
    public IReadOnlyList<string> TraceLogs { get; init; } = [];
    public string? Candidate { get; init; }
    public string? Reconstructed { get; init; }
    public string? SemanticCandidate { get; init; }
    public string? Readability { get; init; }
    public string? NativeReport { get; init; }
    public string? NativeSemanticIr { get; init; }
    public string? NativeCandidate { get; init; }
}

public sealed record DeobfuscationResult
{
    public string Version { get; init; } = DeobfuscatorInfo.Version;
    public int SchemaVersion { get; init; } = 1;
    public string Backend { get; init; } = "dotnet";
    public string Adapter { get; init; } = "luraph-v14.7";
    public required DeobfuscationStatus Status { get; init; }
    public bool ExactSource { get; init; }
    public required string InputSha256 { get; init; }
    public required CoverageSummary Coverage { get; init; }
    public required VerificationSummary Verification { get; init; }
    public required ArtifactManifest Artifacts { get; init; }
    public IReadOnlyList<Diagnostic> Diagnostics { get; init; } = [];
    public IReadOnlyList<ProgressEvent> Stages { get; init; } = [];
    public IReadOnlyList<TracePassSummary> TracePasses { get; init; } = [];
}

public interface ILuraphDeobfuscator
{
    Task<DeobfuscationResult> DeobfuscateAsync(
        DeobfuscationRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);
}
