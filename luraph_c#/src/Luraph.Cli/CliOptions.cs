using Luraph.Core;

namespace Luraph.Cli;

internal enum CliCommandKind
{
    Help,
    Version,
    Deobfuscate,
    Inspect,
    Verify,
}

internal sealed record CliOptions
{
    public CliCommandKind Command { get; init; }
    public string? Input { get; init; }
    public string? Reconstructed { get; init; }
    public string Output { get; init; } = "luraph-output";
    public string? Runtime { get; init; }
    public string? Trace { get; init; }
    public long? TraceWindowStart { get; init; }
    public long? TraceWindowEnd { get; init; }
    public bool AutoTrace { get; init; } = true;
    public bool Json { get; init; }
    public bool ProgressJsonl { get; init; }
    public int TimeoutSeconds { get; init; } = 30;
    public long MaxSteps { get; init; } = 2_000_000_000;

    public DeobfuscationRequest ToRequest(DeobfuscationMode mode) => new()
    {
        InputPath = Input!,
        OutputDirectory = Output,
        Mode = mode,
        TracePath = Trace,
        TraceWindowStart = TraceWindowStart,
        TraceWindowEnd = TraceWindowEnd,
        Runtime = new RuntimeSettings
        {
            BinaryPath = Runtime,
            AutoTrace = AutoTrace,
            Timeout = TimeSpan.FromSeconds(TimeoutSeconds),
            MaxSteps = MaxSteps,
        },
    };

    public static CliOptions Parse(string[] args)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
            return new() { Command = CliCommandKind.Help };
        if (args[0] is "version" or "--version" or "-V")
            return new() { Command = CliCommandKind.Version };

        CliCommandKind command = args[0] switch
        {
            "deobfuscate" => CliCommandKind.Deobfuscate,
            "inspect" => CliCommandKind.Inspect,
            "verify" => CliCommandKind.Verify,
            _ => throw new CliException($"unknown command: {args[0]}", ExitCodes.InvalidInput),
        };

        List<string> positional = [];
        string output = "luraph-output";
        string? runtime = null;
        string? trace = null;
        long? traceWindowStart = null;
        long? traceWindowEnd = null;
        bool autoTrace = true;
        bool json = false;
        bool progressJsonl = false;
        int timeout = 30;
        long maxSteps = 2_000_000_000;

        for (int index = 1; index < args.Length; index++)
        {
            string arg = args[index];
            switch (arg)
            {
                case "--output" or "-o": output = Value(args, ref index, arg); break;
                case "--runtime": runtime = Value(args, ref index, arg); break;
                case "--trace": trace = Value(args, ref index, arg); break;
                case "--trace-window":
                    traceWindowStart = PositiveLong(Value(args, ref index, arg), arg);
                    traceWindowEnd = PositiveLong(Value(args, ref index, arg), arg);
                    if (traceWindowEnd < traceWindowStart)
                        throw new CliException("--trace-window END must be at least START", ExitCodes.InvalidInput);
                    break;
                case "--no-auto-trace": autoTrace = false; break;
                case "--json": json = true; break;
                case "--progress-jsonl": progressJsonl = true; break;
                case "--timeout": timeout = PositiveInt(Value(args, ref index, arg), arg); break;
                case "--max-steps": maxSteps = PositiveLong(Value(args, ref index, arg), arg); break;
                default:
                    if (arg.StartsWith("-", StringComparison.Ordinal))
                        throw new CliException($"unknown option: {arg}", ExitCodes.InvalidInput);
                    positional.Add(arg);
                    break;
            }
        }

        int wanted = command == CliCommandKind.Verify ? 2 : 1;
        if (positional.Count != wanted)
            throw new CliException(command == CliCommandKind.Verify
                ? "verify needs ORIGINAL and RECONSTRUCTED"
                : $"{args[0]} needs one input file", ExitCodes.InvalidInput);

        return new()
        {
            Command = command,
            Input = positional[0],
            Reconstructed = positional.Count > 1 ? positional[1] : null,
            Output = output,
            Runtime = BundledRuntime.Resolve(runtime),
            Trace = trace,
            TraceWindowStart = traceWindowStart,
            TraceWindowEnd = traceWindowEnd,
            AutoTrace = autoTrace,
            Json = json,
            ProgressJsonl = progressJsonl,
            TimeoutSeconds = timeout,
            MaxSteps = maxSteps,
        };
    }

    private static string Value(string[] args, ref int index, string option)
    {
        if (++index >= args.Length)
            throw new CliException($"{option} needs a value", ExitCodes.InvalidInput);
        return args[index];
    }

    private static int PositiveInt(string value, string option) =>
        int.TryParse(value, out int parsed) && parsed > 0
            ? parsed
            : throw new CliException($"{option} needs a positive integer", ExitCodes.InvalidInput);

    private static long PositiveLong(string value, string option) =>
        long.TryParse(value, out long parsed) && parsed > 0
            ? parsed
            : throw new CliException($"{option} needs a positive integer", ExitCodes.InvalidInput);
}

internal sealed class CliException(string message, int exitCode) : Exception(message)
{
    public int ExitCode { get; } = exitCode;
}
