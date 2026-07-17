namespace Luraph.Core.Ir;

public sealed record SourceMapping(
    ulong Prototype,
    string Block,
    int PcStart,
    int PcEnd,
    int LineStart,
    int LineEnd,
    IReadOnlyList<int> Successors);

public sealed record CandidateMetrics
{
    public int Prototypes { get; init; }
    public int Blocks { get; init; }
    public int Operations { get; init; }
    public int UnsupportedExpressions { get; init; }
    public int UnsupportedOperations { get; init; }
    public int SymbolicTransitions { get; init; }
    public int DynamicEdgeSites { get; init; }
    public int ReplayedDynamicEdgeSites { get; init; }
    public int DynamicLaneReplaySites { get; init; }
    public int SpecializedStableLanes { get; init; }
    public int ClosureConstructors { get; init; }
    public int UnresolvedClosureDescriptors { get; init; }
    public int CaptureKeyRemaps { get; init; }
    public int UnresolvedCaptureKeys { get; init; }
    public int RuntimeSpecializedCallSites { get; init; }
    public int VerifiedReturnSites { get; init; }
    public int ReturnArityMismatches { get; init; }
    public int RegistersScalarized { get; init; }
    public int ReplayEntriesCollapsed { get; init; }
    public int NamesImproved { get; init; }

    public bool FullyRendered =>
        UnsupportedExpressions == 0 &&
        UnsupportedOperations == 0 &&
        SymbolicTransitions == 0 &&
        UnresolvedClosureDescriptors == 0 &&
        UnresolvedCaptureKeys == 0 &&
        ReturnArityMismatches == 0;
}

public sealed record SemanticCandidate(
    string Source,
    IReadOnlyList<SourceMapping> Mapping,
    CandidateMetrics Metrics,
    IReadOnlyList<UnresolvedFact> Unresolved)
{
    public bool FullyRendered => Metrics.FullyRendered && Unresolved.Count == 0;
}
