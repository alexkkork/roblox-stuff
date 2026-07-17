using Luraph.Core.Readability;

namespace Luraph.Core.Tests.Readability;

public sealed class ReplayAndSourceTests
{
    [Fact]
    public void ReplayRunsRoundTrip()
    {
        int[] source = [1, 1, 1, 2, 3, 3, 3, 3];

        ReplayCompressionResult<int> compressed = ReplayCompressor.Compress(source);

        Assert.Equal(5, compressed.CollapsedCount);
        Assert.Equal(source, ReplayCompressor.Expand(compressed.Runs));
    }

    [Fact]
    public void InstrumentationAndIgnoredCallScopeAreCleaned()
    {
        const string source = "  semantic_step(7, pc)\n  do local _ = print(\"ok\") end\n  return nil\n";

        SourceRewriteResult result = ReadableSourceRewriter.Rewrite(source);

        Assert.DoesNotContain("semantic_step", result.Source, StringComparison.Ordinal);
        Assert.Contains("  print(\"ok\")", result.Source, StringComparison.Ordinal);
        Assert.Equal(1, result.InstrumentationLinesRemoved);
        Assert.Equal(1, result.CallScopesFlattened);
    }

    [Fact]
    public void ParenthesizedCalleeKeepsItsResultScope()
    {
        const string source = "do local _ = (callback)(\"ok\") end";

        SourceRewriteResult result = ReadableSourceRewriter.Rewrite(source);

        Assert.Equal(source, result.Source);
        Assert.Equal(0, result.CallScopesFlattened);
    }
}
