using System.Text.Json.Nodes;
using Luraph.Core.Tracing;

namespace Luraph.Core.Runtime;

public enum RuntimeRunStatus
{
    Completed,
    Failed,
    Unavailable,
    TimedOut,
    Cancelled,
    OutputLimit,
}

public sealed record RuntimeRunRequest
{
    public required string BinaryPath { get; init; }
    public LuraphProbe? Probe { get; init; }
    public string? Source { get; init; }
    public bool ForceLuraph { get; init; } = true;
    public bool TraceEnabled { get; init; } = true;
    public RuntimeSettings Settings { get; init; } = new();
    public TraceParseOptions TraceOptions { get; init; } = new();
    public int MaxOutputBytes { get; init; } = 8 * 1024 * 1024;
    public string? WorkingDirectory { get; init; }
    public string? TemporaryRoot { get; init; }

    public string EffectiveSource => Probe?.Source ?? Source ?? string.Empty;

    public static RuntimeRunRequest ForProbe(
        string binaryPath,
        LuraphProbe probe,
        RuntimeSettings? settings = null) => new()
        {
            BinaryPath = binaryPath,
            Probe = probe,
            ForceLuraph = true,
            TraceEnabled = true,
            Settings = settings ?? new RuntimeSettings(),
        };

    public static RuntimeRunRequest ForOriginalVerification(
        string binaryPath,
        string source,
        RuntimeSettings? settings = null) => new()
        {
            BinaryPath = binaryPath,
            Source = source,
            ForceLuraph = true,
            TraceEnabled = false,
            Settings = settings ?? new RuntimeSettings(),
        };

    public static RuntimeRunRequest ForCandidateVerification(
        string binaryPath,
        string source,
        RuntimeSettings? settings = null) => new()
        {
            BinaryPath = binaryPath,
            Source = source,
            ForceLuraph = false,
            TraceEnabled = false,
            Settings = settings ?? new RuntimeSettings(),
        };
}

public sealed record RuntimeRunResult
{
    public required RuntimeRunStatus Status { get; init; }
    public required int ExitCode { get; init; }
    public required IReadOnlyList<string> Arguments { get; init; }
    public required string StandardOutput { get; init; }
    public required string StandardError { get; init; }
    public required string TraceText { get; init; }
    public LuraphTraceDocument? Trace { get; init; }
    public JsonNode? Report { get; init; }
    public required TimeSpan Duration { get; init; }
    public bool OutputTruncated { get; init; }
    public bool TemporaryFilesRemoved { get; init; }
    public string? Reason { get; init; }

    public TracePassSummary ToPassSummary(LuraphProbe? probe) => new(
        probe?.Pass ?? 1,
        probe?.Kind == LuraphProbeKind.PayloadWindow ? "payload-window" : "call-focused",
        Status != RuntimeRunStatus.Unavailable,
        Status == RuntimeRunStatus.Completed,
        ExitCode,
        System.Text.Encoding.UTF8.GetByteCount(TraceText),
        null,
        Reason);
}

public interface IRbxRuntimeRunner
{
    Task<RuntimeRunResult> RunAsync(
        RuntimeRunRequest request,
        CancellationToken cancellationToken = default);
}
