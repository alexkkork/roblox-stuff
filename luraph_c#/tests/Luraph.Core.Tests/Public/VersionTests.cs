using System.Text.Json;
using Luraph.Core;

namespace Luraph.Core.Tests.Public;

public sealed class VersionTests
{
    [Fact]
    public void ProductAndReportVersionAreExactlyNinePointZero()
    {
        DeobfuscationResult result = new()
        {
            Status = DeobfuscationStatus.Blocked,
            InputSha256 = string.Empty,
            Coverage = new CoverageSummary(),
            Verification = new VerificationSummary(),
            Artifacts = new ArtifactManifest(),
        };

        Assert.Equal("9.0", DeobfuscatorInfo.Version);
        Assert.Equal("9.0", result.Version);

        using JsonDocument report = JsonDocument.Parse(JsonSerializer.Serialize(result, JsonDefaults.Create()));
        Assert.Equal("9.0", report.RootElement.GetProperty("version").GetString());
        Assert.Equal(1, report.RootElement.GetProperty("schema_version").GetInt32());
        Assert.Equal("luraph-v14.7", report.RootElement.GetProperty("adapter").GetString());
    }
}
