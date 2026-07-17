namespace Luraph.Core.Tracing;

public sealed record TraceParseOptions
{
    public int MaxBytes { get; init; } = 64 * 1024 * 1024;
    public int MaxRows { get; init; } = 2_000_000;
    public int MaxInstructionsPerPrototype { get; init; } = 200_000;
    public int MaxWritesPerStep { get; init; } = 200_000;
    public int MaxCapturedReturns { get; init; } = 256;
}

public sealed record TraceParseDiagnostic(int Line, string Code, string Message);

public sealed record TraceSummary
{
    public long BytesRead { get; init; }
    public int RowsRead { get; init; }
    public int MarkerRows { get; init; }
    public int MalformedRows { get; init; }
    public int OutputRows { get; init; }
    public int Calls { get; init; }
    public int VmEvents { get; init; }
    public int Activations { get; init; }
    public int Prototypes { get; init; }
    public int Instructions { get; init; }
    public int LaneRows { get; init; }
    public int Steps { get; init; }
    public int Returns { get; init; }
    public bool ByteLimitHit { get; init; }
    public bool RowLimitHit { get; init; }
}

public sealed record LuraphTraceDocument
{
    public IReadOnlyList<LuraphTraceRecord> Records { get; init; } = [];
    public IReadOnlyList<string> OutputLines { get; init; } = [];
    public IReadOnlyList<TraceParseDiagnostic> Diagnostics { get; init; } = [];
    public required TraceSummary Summary { get; init; }

    public IEnumerable<T> OfType<T>() where T : LuraphTraceRecord => Records.OfType<T>();
}
