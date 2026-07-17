namespace Luraph.Core.Readability;

public sealed record ReplayRun<T>(T Value, int Count);

public sealed record ReplayCompressionResult<T>(
    IReadOnlyList<ReplayRun<T>> Runs,
    int OriginalCount,
    int CollapsedCount);

public static class ReplayCompressor
{
    public static ReplayCompressionResult<T> Compress<T>(
        IReadOnlyList<T> values,
        IEqualityComparer<T>? comparer = null)
    {
        comparer ??= EqualityComparer<T>.Default;
        List<ReplayRun<T>> runs = [];
        foreach (T value in values)
        {
            if (runs.Count > 0 && comparer.Equals(runs[^1].Value, value))
                runs[^1] = runs[^1] with { Count = runs[^1].Count + 1 };
            else
                runs.Add(new ReplayRun<T>(value, 1));
        }
        return new ReplayCompressionResult<T>(runs, values.Count, values.Count - runs.Count);
    }

    public static IReadOnlyList<T> Expand<T>(IReadOnlyList<ReplayRun<T>> runs)
    {
        List<T> values = [];
        foreach (ReplayRun<T> run in runs)
            for (int index = 0; index < run.Count; index++)
                values.Add(run.Value);
        return values;
    }
}
