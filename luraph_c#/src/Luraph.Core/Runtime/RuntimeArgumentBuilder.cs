using System.Globalization;

namespace Luraph.Core.Runtime;

public sealed record RuntimeFileSet(string Script, string? Trace, string Report);

public static class RuntimeArgumentBuilder
{
    public const int MaxMemoryMb = 768;
    public const int MaxTraceBytes = 1024 * 1024 * 1024;

    public static IReadOnlyList<string> Build(RuntimeRunRequest request, RuntimeFileSet files)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(files);
        Validate(request);

        var timeout = request.Settings.Timeout.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture);
        List<string> args =
        [
            "--profile", "executor-client",
            "--execution-mode", "faithful",
            "--analysis-hooks", "off",
            "--network-policy", "offline",
            "--clock", "virtual",
            "--max-virtual-seconds", "30",
            "--filesystem", "disabled",
            "--memory-limit-mb", request.Settings.MemoryLimitMb.ToString(CultureInfo.InvariantCulture),
            "--unsupported", request.ForceLuraph ? "trace-nil" : "error",
            "--no-native-codegen",
        ];
        if (request.ForceLuraph)
        {
            args.AddRange([
                "--luraph-mode", "force",
                "--luraph-max-steps", request.Settings.MaxSteps.ToString(CultureInfo.InvariantCulture),
                "--luraph-stall-steps", "0",
            ]);
        }
        else
        {
            args.AddRange(["--luraph-mode", "off"]);
        }
        if (request.TraceEnabled)
        {
            args.Add("--probe-trace");
            args.Add(files.Trace!);
            args.Add("--probe-trace-limit-bytes");
            args.Add(request.TraceOptions.MaxBytes.ToString(CultureInfo.InvariantCulture));
        }
        args.AddRange(["--timeout", timeout, "--report", files.Report, files.Script]);
        return args;
    }

    public static void Validate(RuntimeRunRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.BinaryPath))
            throw new ArgumentException("runtime path is required", nameof(request));
        if (request.EffectiveSource.Length == 0)
            throw new ArgumentException("runtime source is empty", nameof(request));
        if (request.TraceEnabled && request.Probe is null)
            throw new ArgumentException("trace runs need a probe", nameof(request));
        if (request.Settings.Timeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(request), "runtime timeout must be positive");
        if (request.Settings.MaxSteps <= 0)
            throw new ArgumentOutOfRangeException(nameof(request), "runtime step budget must be positive");
        if (request.Settings.MemoryLimitMb is < 1 or > MaxMemoryMb)
            throw new ArgumentOutOfRangeException(nameof(request), "runtime memory must be between 1 and 768 MB");
        if (request.TraceOptions.MaxBytes is < 1 or > MaxTraceBytes)
            throw new ArgumentOutOfRangeException(nameof(request), "trace cap must be between 1 byte and 1 GiB");
        if (request.MaxOutputBytes < 1)
            throw new ArgumentOutOfRangeException(nameof(request), "output cap must be positive");
    }
}
