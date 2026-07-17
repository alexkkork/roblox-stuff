using System.Runtime.InteropServices;
using Luraph.Core;
using Luraph.Core.Pipeline;

namespace Luraph.Integration.Tests;

public sealed class ReconstructionTests
{
    [Fact]
    public async Task ReconstructsAndVerifiesThePrimaryFixture()
    {
        if (!OperatingSystem.IsMacOS() || RuntimeInformation.ProcessArchitecture != Architecture.Arm64)
            return;

        string runtime = Path.Combine(AppContext.BaseDirectory, "runtime", "rbx_luau_runtime");
        if (!File.Exists(runtime))
            return;

        string fixtures = Path.Combine(AppContext.BaseDirectory, "Fixtures");
        string output = Path.Combine(Path.GetTempPath(), $"luraph-cs-test-{Guid.NewGuid():N}");
        try
        {
            DeobfuscationResult result = await new LuraphDeobfuscator().DeobfuscateAsync(new DeobfuscationRequest
            {
                InputPath = Path.Combine(fixtures, "subject_1b642e9523c1.luau"),
                OutputDirectory = output,
                TracePath = Path.Combine(fixtures, "subject_1b642e9523c1_refined_trace.log"),
                Runtime = new RuntimeSettings
                {
                    BinaryPath = runtime,
                    AutoTrace = false,
                    Timeout = TimeSpan.FromSeconds(20),
                },
            });

            Assert.Equal(DeobfuscationStatus.Reconstructed, result.Status);
            Assert.Equal(385, result.Coverage.LiftedOperations);
            Assert.True(result.Verification.Compiled);
            Assert.True(result.Verification.Equivalent);
            Assert.Equal("print(\"anti tamper BYPASSED\")\n",
                await File.ReadAllTextAsync(Path.Combine(output, "reconstructed.luau")));
        }
        finally
        {
            if (Directory.Exists(output))
                Directory.Delete(output, true);
        }
    }

}
