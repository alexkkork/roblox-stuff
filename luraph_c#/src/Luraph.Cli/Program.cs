using System.Text.Json;
using Luraph.Core;

namespace Luraph.Cli;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            CliOptions options = CliOptions.Parse(args);
            if (options.Command == CliCommandKind.Help)
            {
                PrintHelp();
                return ExitCodes.Success;
            }
            if (options.Command == CliCommandKind.Version)
            {
                Console.WriteLine(DeobfuscatorInfo.Version);
                return ExitCodes.Success;
            }

            IProgress<ProgressEvent>? progress = options.ProgressJsonl
                ? new JsonLineProgress()
                : null;

            LuraphApplication application = new();
            if (options.Command == CliCommandKind.Verify)
                return await application.VerifyAsync(options, progress).ConfigureAwait(false);

            DeobfuscationMode mode = options.Command == CliCommandKind.Inspect
                ? DeobfuscationMode.Inspect
                : DeobfuscationMode.Reconstruct;
            (int exitCode, DeobfuscationResult result) = await application.RunAsync(options.ToRequest(mode), progress).ConfigureAwait(false);
            if (options.Json)
                Console.Out.WriteLine(JsonSerializer.Serialize(result, JsonDefaults.Create()));
            else
            {
                Console.Out.WriteLine($"status: {result.Status.ToString().ToLowerInvariant()}");
                Console.Out.WriteLine($"report: {Path.Combine(options.Output, result.Artifacts.Report)}");
            }
            return exitCode;
        }
        catch (CliException error)
        {
            Console.Error.WriteLine($"luraph-cs: {error.Message}");
            return error.ExitCode;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("luraph-cs: got stopped");
            return ExitCodes.TimedOut;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"luraph-cs: {error.Message}");
            return ExitCodes.InternalError;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine($"luraph-cs {DeobfuscatorInfo.Version}");
        Console.WriteLine("luraph-cs deobfuscate INPUT --output DIR [--runtime PATH] [--trace PATH] [--trace-window START END] [--no-auto-trace]");
        Console.WriteLine("luraph-cs inspect INPUT --output DIR");
        Console.WriteLine("luraph-cs verify ORIGINAL RECONSTRUCTED [--runtime PATH] --output DIR");
        Console.WriteLine("options: --timeout N --max-steps N --json --progress-jsonl --version");
        Console.WriteLine("the bundled runtime is used unless --runtime or RBX_LUAU_RUNTIME overrides it");
    }

    private sealed class JsonLineProgress : IProgress<ProgressEvent>
    {
        public void Report(ProgressEvent item)
        {
            string value = JsonSerializer.Serialize(item, JsonDefaults.Create(false));
            Console.Error.WriteLine($"@@LURAPH_PROGRESS@@{value}");
        }
    }
}
