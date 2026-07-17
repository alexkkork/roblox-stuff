using System.Text.Json.Nodes;
using Luraph.Core.Runtime;

namespace Luraph.Core.Pipeline;

public sealed record RuntimeVerificationResult(
    VerificationSummary Summary,
    RuntimeRunResult? Original,
    RuntimeRunResult? Candidate);

public sealed class RuntimeVerifier(IRbxRuntimeRunner? runtime = null)
{
    private readonly IRbxRuntimeRunner runtime = runtime ?? new RbxRuntimeRunner();

    public async Task<RuntimeVerificationResult> VerifyAsync(
        string binary,
        string original,
        string candidate,
        RuntimeSettings settings,
        CancellationToken cancellationToken = default)
    {
        RuntimeRunResult candidateRun = await runtime.RunAsync(
            RuntimeRunRequest.ForCandidateVerification(binary, candidate, settings), cancellationToken).ConfigureAwait(false);
        if (candidateRun.Status == RuntimeRunStatus.Unavailable)
            return Result(false, false, false, false, candidateRun.Reason, null, candidateRun);
        if (candidateRun.Status != RuntimeRunStatus.Completed)
        {
            bool compiled = CandidateCompiled(candidateRun);
            return Result(true, compiled, compiled, false,
                candidateRun.Reason ?? (compiled ? "candidate_runtime_failed" : "candidate_compile_failed"),
                null, candidateRun);
        }

        RuntimeRunResult originalRun = await runtime.RunAsync(
            RuntimeRunRequest.ForOriginalVerification(binary, original, settings), cancellationToken).ConfigureAwait(false);
        if (originalRun.Status != RuntimeRunStatus.Completed)
            return Result(true, true, true, false,
                originalRun.Reason ?? "original_runtime_failed", originalRun, candidateRun);

        bool equivalent = Lines(originalRun.StandardOutput).SequenceEqual(Lines(candidateRun.StandardOutput)) &&
            Lines(originalRun.StandardError).SequenceEqual(Lines(candidateRun.StandardError)) &&
            NodeText(originalRun.Report, "termination_reason") == NodeText(candidateRun.Report, "termination_reason") &&
            NodeJson(originalRun.Report, "typed_returns") == NodeJson(candidateRun.Report, "typed_returns") &&
            NodeJson(originalRun.Report, "unsupported") == NodeJson(candidateRun.Report, "unsupported");
        return Result(true, true, true, equivalent,
            equivalent ? null : "runtime_mismatch", originalRun, candidateRun);
    }

    private static RuntimeVerificationResult Result(
        bool compileAttempted,
        bool compiled,
        bool runtimeAttempted,
        bool equivalent,
        string? reason,
        RuntimeRunResult? original,
        RuntimeRunResult? candidate) => new(new VerificationSummary
        {
            CompileAttempted = compileAttempted,
            Compiled = compiled,
            RuntimeAttempted = runtimeAttempted,
            Equivalent = equivalent,
            BoundedOnly = false,
            Scope = equivalent ? "complete_traced_payload_activation" : null,
            ProtectorScaffoldingExcluded = equivalent ? ["engine_lifecycle", "scheduler_internal_events"] : [],
            Reason = reason,
        }, original, candidate);

    private static bool CandidateCompiled(RuntimeRunResult run)
    {
        string? status = NodeText(run.Report, "status");
        if (string.Equals(status, "compile_error", StringComparison.Ordinal))
            return false;
        if (!string.IsNullOrWhiteSpace(status))
            return true;
        return !run.StandardError.Contains("[main_compile_error]", StringComparison.Ordinal);
    }

    private static string[] Lines(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal)
        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Where(line => !line.StartsWith("@@LPH_", StringComparison.Ordinal))
        .ToArray();

    private static string? NodeText(JsonNode? root, string name) => root?[name]?.GetValue<string>();

    private static string NodeJson(JsonNode? root, string name) => root?[name]?.ToJsonString() ?? "null";
}
