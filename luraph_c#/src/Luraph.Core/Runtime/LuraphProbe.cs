namespace Luraph.Core.Runtime;

public enum LuraphProbeKind
{
    CallFocused,
    PayloadWindow,
}

public sealed record LuraphProbe
{
    public required LuraphProbeKind Kind { get; init; }
    public required string Source { get; init; }
    public int Pass { get; init; } = 1;
    public string Name { get; init; } = "probe";
    public long? WindowStart { get; init; }
    public long? WindowEnd { get; init; }
}

public sealed record ProbeBuildRequest(
    string Source,
    LuraphProbeKind Kind,
    int Pass,
    long? WindowStart = null,
    long? WindowEnd = null);

public interface ILuraphProbeBuilder
{
    ValueTask<LuraphProbe> BuildAsync(
        ProbeBuildRequest request,
        CancellationToken cancellationToken = default);
}
