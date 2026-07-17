using System.Runtime.InteropServices;

namespace Luraph.Cli;

internal static class BundledRuntime
{
    private const string EnvironmentVariable = "RBX_LUAU_RUNTIME";

    public static string? Resolve(string? explicitPath)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
            return Path.GetFullPath(explicitPath);

        string? environmentPath = Environment.GetEnvironmentVariable(EnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(environmentPath))
            return Path.GetFullPath(environmentPath);

        List<string> candidates = [];

        if (OperatingSystem.IsWindows())
        {
            string? architecture = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "x64",
                Architecture.Arm64 => "arm64",
                _ => null,
            };

            if (architecture is not null)
            {
                candidates.Add(Path.Combine(AppContext.BaseDirectory, "runtime", $"windows-{architecture}", "rbx_luau_runtime.exe"));
                candidates.Add(Path.Combine(Environment.CurrentDirectory, "runtime", $"windows-{architecture}", "rbx_luau_runtime.exe"));
            }
        }

        candidates.AddRange(
        [
            Path.Combine(AppContext.BaseDirectory, "runtime", "rbx_luau_runtime"),
            Path.Combine(AppContext.BaseDirectory, "rbx_luau_runtime"),
            Path.Combine(Environment.CurrentDirectory, "runtime", "rbx_luau_runtime"),
        ]);

        return candidates.FirstOrDefault(File.Exists);
    }
}
