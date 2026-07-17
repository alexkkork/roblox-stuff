using System.Diagnostics;
using System.Text;
using Luraph.Core.Runtime;

namespace Luraph.Core.Pipeline;

public sealed record ProbeBuildResult(
    LuraphProbe? Probe,
    string? Reason,
    string? HelperPath,
    string? OpcodeHandlersJson = null);

public sealed record ProbeAnalysisResult(
    string? SemanticIrJson,
    string? ControlFlowJson,
    string? OpcodeHandlersJson,
    string? NativeReportJson,
    string? NativeCandidateSource,
    string? Reason,
    string? HelperPath)
{
    public bool HasSemanticArtifacts =>
        !string.IsNullOrWhiteSpace(SemanticIrJson) &&
        !string.IsNullOrWhiteSpace(ControlFlowJson);
}

public interface ILuraphProbeBuilder
{
    Task<ProbeBuildResult> BuildAsync(
        string inputPath,
        string source,
        string? trace,
        string? runtimePath,
        TimeSpan timeout,
        long? traceWindowStart = null,
        long? traceWindowEnd = null,
        CancellationToken cancellationToken = default);

    Task<ProbeAnalysisResult> AnalyzeAsync(
        string inputPath,
        string source,
        string trace,
        string? runtimePath,
        TimeSpan timeout,
        int maxArtifactBytes,
        CancellationToken cancellationToken = default);
}

public sealed class ProbeBuilder : ILuraphProbeBuilder
{
    public async Task<ProbeBuildResult> BuildAsync(
        string inputPath,
        string source,
        string? trace,
        string? runtimePath,
        TimeSpan timeout,
        long? traceWindowStart = null,
        long? traceWindowEnd = null,
        CancellationToken cancellationToken = default)
    {
        string? helper = FindHelper(runtimePath);
        if (helper is null)
            return new(null, "native probe oracle was not found", null);

        string temp = Path.Combine(Path.GetTempPath(), $"luraph-probe-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temp);
        try
        {
            string script = Path.Combine(temp, Path.GetFileName(inputPath));
            string output = Path.Combine(temp, "out");
            Directory.CreateDirectory(output);
            await File.WriteAllTextAsync(script, source, new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);

            List<string> args = [script, "--output-dir", output, "--mode", "reconstruct", "--report", Path.Combine(output, "report.json")];
            if (!string.IsNullOrEmpty(trace))
            {
                string tracePath = Path.Combine(temp, "input.trace");
                await File.WriteAllTextAsync(tracePath, trace, new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
                args.AddRange(["--trace", tracePath]);
            }
            if (traceWindowStart.HasValue && traceWindowEnd.HasValue)
            {
                args.AddRange([
                    "--trace-window",
                    traceWindowStart.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    traceWindowEnd.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ]);
            }

            int exitCode = await RunAsync(helper, args, timeout, cancellationToken).ConfigureAwait(false);
            bool targeted = traceWindowStart.HasValue && traceWindowEnd.HasValue;
            string probePath = Path.Combine(output, targeted ? "structure_probe.luau" : "trace_probe.luau");
            if (exitCode is not (0 or 2) || !File.Exists(probePath))
                return new(null, $"probe oracle exited with code {exitCode}", helper);

            string probeSource = await File.ReadAllTextAsync(probePath, cancellationToken).ConfigureAwait(false);
            string handlersPath = Path.Combine(output, "opcode_handlers.json");
            string? handlers = File.Exists(handlersPath)
                ? await File.ReadAllTextAsync(handlersPath, cancellationToken).ConfigureAwait(false)
                : null;
            bool refined = probeSource.Contains("@@LPH_STEP_V1@@", StringComparison.Ordinal);
            return new(new LuraphProbe
            {
                Kind = refined ? LuraphProbeKind.PayloadWindow : LuraphProbeKind.CallFocused,
                Pass = refined ? 2 : 1,
                Name = refined ? "payload-window" : "call-focused",
                Source = probeSource,
                WindowStart = traceWindowStart,
                WindowEnd = traceWindowEnd,
            }, null, helper, handlers);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new(null, error.Message, helper);
        }
        finally
        {
            TryDelete(temp);
        }
    }

    public async Task<ProbeAnalysisResult> AnalyzeAsync(
        string inputPath,
        string source,
        string trace,
        string? runtimePath,
        TimeSpan timeout,
        int maxArtifactBytes,
        CancellationToken cancellationToken = default)
    {
        if (maxArtifactBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxArtifactBytes));

        string? helper = FindHelper(runtimePath);
        if (helper is null)
            return new(null, null, null, null, null, "native semantic oracle was not found", null);
        if (string.IsNullOrWhiteSpace(trace))
            return new(null, null, null, null, null, "a structure trace is required for semantic analysis", helper);

        string temp = Path.Combine(Path.GetTempPath(), $"luraph-semantic-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temp);
        try
        {
            string script = Path.Combine(temp, Path.GetFileName(inputPath));
            string tracePath = Path.Combine(temp, "input.trace");
            string output = Path.Combine(temp, "out");
            string reportPath = Path.Combine(output, "report.json");
            Directory.CreateDirectory(output);
            await File.WriteAllTextAsync(script, source, new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
            await File.WriteAllTextAsync(tracePath, trace, new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);

            List<string> args =
            [
                script,
                "--output-dir", output,
                "--mode", "reconstruct",
                "--trace", tracePath,
                "--report", reportPath,
            ];
            int exitCode = await RunAsync(helper, args, timeout, cancellationToken).ConfigureAwait(false);
            if (exitCode is not (0 or 2))
                return new(null, null, null, null, null, $"semantic oracle exited with code {exitCode}", helper);

            string? semantic = await ReadBoundedAsync(Path.Combine(output, "semantic_ir.json"), maxArtifactBytes, cancellationToken).ConfigureAwait(false);
            string? cfg = await ReadBoundedAsync(Path.Combine(output, "cfg.json"), maxArtifactBytes, cancellationToken).ConfigureAwait(false);
            string? handlers = await ReadBoundedAsync(Path.Combine(output, "opcode_handlers.json"), maxArtifactBytes, cancellationToken).ConfigureAwait(false);
            string? report = await ReadBoundedAsync(reportPath, maxArtifactBytes, cancellationToken).ConfigureAwait(false);
            string? candidate = await ReadBoundedAsync(Path.Combine(output, "semantic_readable_candidate.luau"), maxArtifactBytes, cancellationToken).ConfigureAwait(false)
                ?? await ReadBoundedAsync(Path.Combine(output, "semantic_state_machine_candidate.luau"), maxArtifactBytes, cancellationToken).ConfigureAwait(false);
            string? reason = semantic is null || cfg is null
                ? "semantic oracle did not produce both semantic IR and CFG"
                : null;
            return new(semantic, cfg, handlers, report, candidate, reason, helper);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new(null, null, null, null, null, error.Message, helper);
        }
        finally
        {
            TryDelete(temp);
        }
    }

    private static async Task<string?> ReadBoundedAsync(
        string path,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
            return null;
        if (new FileInfo(path).Length > maxBytes)
            throw new InvalidDataException($"semantic artifact exceeded {maxBytes} bytes");
        return await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
    }

    private static string? FindHelper(string? runtimePath)
    {
        string? configured = Environment.GetEnvironmentVariable("LURAPH_CPP_ORACLE");
        string executable = OperatingSystem.IsWindows() ? "alex_deobfuscator.exe" : "alex_deobfuscator";
        List<string> candidates = [];
        if (!string.IsNullOrWhiteSpace(configured))
            candidates.Add(configured);
        if (!string.IsNullOrWhiteSpace(runtimePath))
            candidates.Add(Path.Combine(Path.GetDirectoryName(Path.GetFullPath(runtimePath))!, executable));
        candidates.Add(Path.Combine(AppContext.BaseDirectory, executable));
        candidates.AddRange(FindUpward(Environment.CurrentDirectory, executable));
        candidates.AddRange(FindUpward(AppContext.BaseDirectory, executable));
        return candidates.Distinct(StringComparer.Ordinal).FirstOrDefault(File.Exists);
    }

    private static IEnumerable<string> FindUpward(string start, string executable)
    {
        DirectoryInfo? directory = new(Path.GetFullPath(start));
        for (int depth = 0; directory is not null && depth < 8; depth++, directory = directory.Parent)
        {
            yield return Path.Combine(directory.FullName, executable);
            yield return Path.Combine(directory.FullName, "build", executable);
        }
    }

    private static async Task<int> RunAsync(
        string helper,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = helper,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            },
        };
        foreach (string argument in arguments)
            process.StartInfo.ArgumentList.Add(argument);
        process.Start();
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        stop.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(stop.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
                process.Kill(true);
            throw;
        }
        await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
        return process.ExitCode;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
        }
    }
}
