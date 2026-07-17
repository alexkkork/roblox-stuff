using Luraph.Core.Runtime;
using Luraph.Core.Tracing;

namespace Luraph.Core.Tests.Runtime;

public sealed class RuntimeArgumentBuilderTests
{
    [Fact]
    public void BuildsForcedOfflineProbeArguments()
    {
        var request = ProbeRequest();
        var args = RuntimeArgumentBuilder.Build(request, new RuntimeFileSet("/tmp/p.lua", "/tmp/t.log", "/tmp/r.json"));

        AssertPair(args, "--profile", "executor-client");
        AssertPair(args, "--execution-mode", "faithful");
        AssertPair(args, "--network-policy", "offline");
        AssertPair(args, "--clock", "virtual");
        AssertPair(args, "--filesystem", "disabled");
        AssertPair(args, "--memory-limit-mb", "768");
        AssertPair(args, "--luraph-mode", "force");
        AssertPair(args, "--probe-trace", "/tmp/t.log");
        Assert.Contains("--no-native-codegen", args);
        Assert.Equal("/tmp/p.lua", args[^1]);
    }

    [Fact]
    public void OriginalVerificationForcesLuraphWithoutTracing()
    {
        var request = RuntimeRunRequest.ForOriginalVerification(
            "/runtime", "return 1", ProbeRequest().Settings);
        var args = RuntimeArgumentBuilder.Build(request, new RuntimeFileSet("in.lua", null, "report.json"));

        AssertPair(args, "--luraph-mode", "force");
        Assert.DoesNotContain("--probe-trace", args);
        AssertPair(args, "--unsupported", "trace-nil");
    }

    [Fact]
    public void CandidateVerificationRunsPlainAndUntraced()
    {
        var request = RuntimeRunRequest.ForCandidateVerification(
            "/runtime", "return 1", ProbeRequest().Settings);
        var args = RuntimeArgumentBuilder.Build(request, new RuntimeFileSet("in.lua", null, "report.json"));

        AssertPair(args, "--luraph-mode", "off");
        AssertPair(args, "--unsupported", "error");
        Assert.DoesNotContain("--probe-trace", args);
        Assert.DoesNotContain("--luraph-max-steps", args);
    }

    private static RuntimeRunRequest ProbeRequest() => new()
    {
        BinaryPath = "/runtime",
        Probe = new LuraphProbe
        {
            Kind = LuraphProbeKind.CallFocused,
            Source = "return 1",
        },
        Settings = new RuntimeSettings
        {
            Timeout = TimeSpan.FromSeconds(15),
            MaxSteps = 30_000_000,
            MemoryLimitMb = 768,
        },
        TraceOptions = new TraceParseOptions { MaxBytes = 1024 },
    };

    private static void AssertPair(IReadOnlyList<string> args, string name, string value)
    {
        var index = args.IndexOf(name);
        Assert.True(index >= 0, $"missing {name}");
        Assert.Equal(value, args[index + 1]);
    }
}

file static class ListExtensions
{
    public static int IndexOf(this IReadOnlyList<string> values, string value)
    {
        for (var index = 0; index < values.Count; index++)
            if (values[index] == value)
                return index;
        return -1;
    }
}
