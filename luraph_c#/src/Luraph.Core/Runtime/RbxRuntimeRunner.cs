using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using Luraph.Core.Tracing;

namespace Luraph.Core.Runtime;

public sealed class RbxRuntimeRunner : IRbxRuntimeRunner
{
    private readonly LuraphTraceParser traceParser;

    public RbxRuntimeRunner(LuraphTraceParser? traceParser = null)
    {
        this.traceParser = traceParser ?? new LuraphTraceParser();
    }

    public async Task<RuntimeRunResult> RunAsync(
        RuntimeRunRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        RuntimeArgumentBuilder.Validate(request);

        var binary = Path.GetFullPath(request.BinaryPath);
        if (!File.Exists(binary))
            return Unavailable([], "runtime binary was not found");

        var tempRoot = request.TemporaryRoot is null
            ? Path.GetTempPath()
            : Path.GetFullPath(request.TemporaryRoot);
        Directory.CreateDirectory(tempRoot);
        var temp = Path.Combine(tempRoot, $"luraph-cs-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temp);

        RuntimeRunResult? result = null;
        try
        {
            var files = new RuntimeFileSet(
                Path.Combine(temp, "probe.luau"),
                request.TraceEnabled ? Path.Combine(temp, "trace.log") : null,
                Path.Combine(temp, "report.json"));
            await File.WriteAllTextAsync(files.Script, request.EffectiveSource, new UTF8Encoding(false), cancellationToken)
                .ConfigureAwait(false);

            var arguments = RuntimeArgumentBuilder.Build(request, files);
            result = await RunProcessAsync(binary, arguments, files, request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            TryDelete(temp);
        }

        return result! with { TemporaryFilesRemoved = !Directory.Exists(temp) };
    }

    private async Task<RuntimeRunResult> RunProcessAsync(
        string binary,
        IReadOnlyList<string> arguments,
        RuntimeFileSet files,
        RuntimeRunRequest request,
        CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = CreateStartInfo(binary, arguments, request.WorkingDirectory ?? Path.GetDirectoryName(files.Script)),
            EnableRaisingEvents = true,
        };
        var watch = Stopwatch.StartNew();
        try
        {
            if (!process.Start())
                return Unavailable(arguments, "runtime process did not start");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return Unavailable(arguments, ex.Message);
        }

        using var timeout = new CancellationTokenSource(request.Settings.Timeout);
        using var outputStop = new CancellationTokenSource();
        using var run = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            timeout.Token,
            outputStop.Token);
        var budget = new OutputBudget(request.MaxOutputBytes, outputStop);
        var stdout = CaptureAsync(process.StandardOutput.BaseStream, budget, run.Token);
        var stderr = CaptureAsync(process.StandardError.BaseStream, budget, run.Token);

        var interrupted = false;
        try
        {
            await process.WaitForExitAsync(run.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            interrupted = true;
            Kill(process);
            await WaitAfterKillAsync(process).ConfigureAwait(false);
        }

        var outBytes = await FinishCaptureAsync(stdout).ConfigureAwait(false);
        var errorBytes = await FinishCaptureAsync(stderr).ConfigureAwait(false);
        watch.Stop();

        var traceText = files.Trace is null
            ? string.Empty
            : await ReadBoundedTextAsync(files.Trace, request.TraceOptions.MaxBytes, CancellationToken.None)
                .ConfigureAwait(false);
        LuraphTraceDocument? trace = null;
        if (traceText.Length > 0)
            trace = traceParser.Parse(traceText, request.TraceOptions);
        var report = await ReadReportAsync(files.Report).ConfigureAwait(false);

        var status = RuntimeRunStatus.Failed;
        string? reason = null;
        if (cancellationToken.IsCancellationRequested)
        {
            status = RuntimeRunStatus.Cancelled;
            reason = "cancelled";
        }
        else if (budget.Hit)
        {
            status = RuntimeRunStatus.OutputLimit;
            reason = "output_limit";
        }
        else if (timeout.IsCancellationRequested)
        {
            status = RuntimeRunStatus.TimedOut;
            reason = "wall_timeout";
        }
        else if (!interrupted && process.ExitCode == 0)
        {
            status = RuntimeRunStatus.Completed;
        }
        else
        {
            reason = ReportReason(report) ?? "runtime_error";
        }

        return new RuntimeRunResult
        {
            Status = status,
            ExitCode = process.HasExited ? process.ExitCode : -1,
            Arguments = arguments,
            StandardOutput = Encoding.UTF8.GetString(outBytes),
            StandardError = Encoding.UTF8.GetString(errorBytes),
            TraceText = traceText,
            Trace = trace,
            Report = report,
            Duration = watch.Elapsed,
            OutputTruncated = budget.Hit,
            Reason = reason,
        };
    }

    private static ProcessStartInfo CreateStartInfo(
        string binary,
        IReadOnlyList<string> arguments,
        string? workingDirectory)
    {
        var start = new ProcessStartInfo
        {
            FileName = binary,
            WorkingDirectory = workingDirectory is null ? Environment.CurrentDirectory : Path.GetFullPath(workingDirectory),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        start.Environment["NO_PROXY"] = "*";
        start.Environment["no_proxy"] = "*";
        return start;
    }

    private static async Task<byte[]> CaptureAsync(
        Stream stream,
        OutputBudget budget,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    break;
                var accepted = budget.Take(read);
                if (accepted > 0)
                    await output.WriteAsync(buffer.AsMemory(0, accepted), CancellationToken.None).ConfigureAwait(false);
                if (accepted < read)
                    break;
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (IOException)
        {
            // proc can close the pipe while it exits
        }
        return output.ToArray();
    }

    private static async Task<byte[]> FinishCaptureAsync(Task<byte[]> capture)
    {
        try
        {
            return await capture.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return [];
        }
    }

    private static async Task<string> ReadBoundedTextAsync(
        string path,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
            return string.Empty;
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024, true);
        using var data = new MemoryStream(Math.Min(maxBytes, 1024 * 1024));
        var buffer = new byte[16 * 1024];
        while (data.Length < maxBytes)
        {
            var read = await input.ReadAsync(
                buffer.AsMemory(0, (int)Math.Min(buffer.Length, maxBytes - data.Length)),
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
                break;
            await data.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
        return Encoding.UTF8.GetString(data.GetBuffer(), 0, (int)data.Length);
    }

    private static async Task<JsonNode?> ReadReportAsync(string path)
    {
        if (!File.Exists(path))
            return null;
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);
            return await JsonNode.ParseAsync(stream).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException)
        {
            return null;
        }
    }

    private static string? ReportReason(JsonNode? report) =>
        report?["termination_reason"]?.GetValue<string>();

    private static void Kill(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(true);
        }
        catch (InvalidOperationException)
        {
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }

    private static async Task WaitAfterKillAsync(Process process)
    {
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is TimeoutException or InvalidOperationException)
        {
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static RuntimeRunResult Unavailable(IReadOnlyList<string> arguments, string reason) => new()
    {
        Status = RuntimeRunStatus.Unavailable,
        ExitCode = -1,
        Arguments = arguments,
        StandardOutput = string.Empty,
        StandardError = string.Empty,
        TraceText = string.Empty,
        Duration = TimeSpan.Zero,
        TemporaryFilesRemoved = true,
        Reason = reason,
    };

    private sealed class OutputBudget(int bytes, CancellationTokenSource stop)
    {
        private readonly object gate = new();
        private int remaining = bytes;

        public bool Hit { get; private set; }

        public int Take(int wanted)
        {
            lock (gate)
            {
                var accepted = Math.Min(wanted, remaining);
                remaining -= accepted;
                if (accepted < wanted)
                {
                    Hit = true;
                    stop.Cancel();
                }
                return accepted;
            }
        }
    }
}
