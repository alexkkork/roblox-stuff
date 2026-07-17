using System.Text.RegularExpressions;

namespace Luraph.Core.Readability;

public sealed record SourceRewriteResult(string Source, int InstrumentationLinesRemoved, int CallScopesFlattened);

public static partial class ReadableSourceRewriter
{
    public static SourceRewriteResult Rewrite(string source)
    {
        string[] lines = source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        List<string> output = [];
        int instrumentation = 0;
        int calls = 0;

        foreach (string line in lines)
        {
            if (SemanticStepLine().IsMatch(line))
            {
                instrumentation++;
                continue;
            }
            Match ignoredCall = IgnoredCallLine().Match(line);
            if (ignoredCall.Success)
            {
                output.Add(ignoredCall.Groups[1].Value + ignoredCall.Groups[2].Value);
                calls++;
                continue;
            }
            output.Add(line.TrimEnd());
        }

        return new SourceRewriteResult(string.Join('\n', output), instrumentation, calls);
    }

    [GeneratedRegex(@"^\s*semantic_step\([^)]*\)\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex SemanticStepLine();

    [GeneratedRegex(@"^(\s*)do local _ = ([A-Za-z_][A-Za-z0-9_\.]*\(.*\)) end\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex IgnoredCallLine();
}
