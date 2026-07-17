using System.Text.Json.Nodes;
using Luraph.Core.Runtime;

namespace Luraph.Core.Pipeline;

public sealed class RuntimeVerifierTests
{
    [Fact]
    public async Task RuntimeFailureAfterParsingStillReportsCompiled()
    {
        RuntimeRunResult failed = Run(RuntimeRunStatus.Failed, "runtime_error", "runtime_error");

        RuntimeVerificationResult result = await new RuntimeVerifier(new StubRuntime(failed)).VerifyAsync(
            "runtime", "original", "candidate", new RuntimeSettings());

        Assert.True(result.Summary.CompileAttempted);
        Assert.True(result.Summary.Compiled);
        Assert.True(result.Summary.RuntimeAttempted);
        Assert.False(result.Summary.Equivalent);
    }

    [Fact]
    public async Task CompilerFailureIsNotReportedAsRuntimeExecution()
    {
        RuntimeRunResult failed = Run(RuntimeRunStatus.Failed, "compile_error", "runtime_error");

        RuntimeVerificationResult result = await new RuntimeVerifier(new StubRuntime(failed)).VerifyAsync(
            "runtime", "original", "candidate", new RuntimeSettings());

        Assert.True(result.Summary.CompileAttempted);
        Assert.False(result.Summary.Compiled);
        Assert.False(result.Summary.RuntimeAttempted);
    }

    private static RuntimeRunResult Run(RuntimeRunStatus status, string reportStatus, string reason) => new()
    {
        Status = status,
        ExitCode = 1,
        Arguments = [],
        StandardOutput = string.Empty,
        StandardError = string.Empty,
        TraceText = string.Empty,
        Report = new JsonObject
        {
            ["status"] = reportStatus,
            ["termination_reason"] = reason,
        },
        Duration = TimeSpan.Zero,
        Reason = reason,
    };

    private sealed class StubRuntime(RuntimeRunResult result) : IRbxRuntimeRunner
    {
        public Task<RuntimeRunResult> RunAsync(
            RuntimeRunRequest request,
            CancellationToken cancellationToken = default) => Task.FromResult(result);
    }
}
