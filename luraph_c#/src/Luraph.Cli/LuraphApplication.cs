using System.Text.Json;
using Luraph.Core;
using Luraph.Core.Pipeline;

namespace Luraph.Cli;

internal sealed class LuraphApplication
{
    public async Task<(int ExitCode, DeobfuscationResult Result)> RunAsync(
        DeobfuscationRequest request,
        IProgress<ProgressEvent>? progress = null)
    {
        DeobfuscationResult result = await new LuraphDeobfuscator().DeobfuscateAsync(request, progress).ConfigureAwait(false);
        return (CodeFor(result), result);
    }

    public async Task<int> VerifyAsync(CliOptions options, IProgress<ProgressEvent>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(options.Runtime) || !File.Exists(options.Runtime))
            return ExitCodes.RuntimeUnavailable;
        Directory.CreateDirectory(options.Output);
        string original = await File.ReadAllTextAsync(options.Input!).ConfigureAwait(false);
        string reconstructed = await File.ReadAllTextAsync(options.Reconstructed!).ConfigureAwait(false);
        progress?.Report(new ProgressEvent("verify", "running", "running both scripts to compare them"));
        RuntimeVerificationResult result = await new RuntimeVerifier().VerifyAsync(options.Runtime, original, reconstructed,
            new RuntimeSettings
            {
                BinaryPath = options.Runtime,
                Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds),
                MaxSteps = options.MaxSteps,
            }).ConfigureAwait(false);
        string report = JsonSerializer.Serialize(result.Summary, JsonDefaults.Create());
        await File.WriteAllTextAsync(Path.Combine(options.Output, "verification.json"), report).ConfigureAwait(false);
        progress?.Report(new ProgressEvent("verify", result.Summary.Equivalent ? "done" : "blocked",
            result.Summary.Equivalent ? "both scripts did the same thing" : result.Summary.Reason ?? "the scripts didnt match"));
        return result.Summary.Equivalent ? ExitCodes.Success : ExitCodes.Blocked;
    }

    private static int CodeFor(DeobfuscationResult result) => result.Status switch
    {
        DeobfuscationStatus.Invalid => ExitCodes.InvalidInput,
        DeobfuscationStatus.Blocked when result.Diagnostics.Any(item => item.Code == "runtime_unavailable") => ExitCodes.RuntimeUnavailable,
        DeobfuscationStatus.Blocked => ExitCodes.Blocked,
        _ => ExitCodes.Success,
    };
}
