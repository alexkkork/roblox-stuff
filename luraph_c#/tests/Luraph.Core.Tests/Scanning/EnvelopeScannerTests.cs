using System.Text;
using Luraph.Core.Containers;
using Luraph.Core.Scanning;

namespace Luraph.Core.Tests.Scanning;

public sealed class EnvelopeScannerTests
{
    [Fact]
    public void DetectsSupportedWrapperAndDecodesLongCarrier()
    {
        var source = Fixture("[=[LPH@opaque]=]");

        var result = EnvelopeScanner.Analyze(source);

        Assert.True(result.Complete);
        Assert.True(result.FamilyDetected);
        Assert.True(result.VersionSupported);
        Assert.Equal(WrapperKind.ReturnedTableMethodDispatch, result.Wrapper.Kind);
        Assert.True(result.Wrapper.ZeroArgumentMethodCall);
        Assert.True(result.Wrapper.ForwardsVarargs);
        Assert.True(result.Wrapper.ConsumesEntireChunk);
        Assert.True(result.StaticDecode.Eligible);
        Assert.True(result.StaticDecode.Complete);
        var carrier = Assert.Single(result.Carriers);
        Assert.Equal(CarrierDecodeStatus.DecodedLiteral, carrier.Status);
        Assert.Equal(CarrierLiteralKind.LongBracketString, carrier.LiteralKind);
        Assert.Equal("LPH@opaque", Encoding.UTF8.GetString(carrier.Bytes));
        Assert.Equal(0, carrier.LphMarkerOffset);
        Assert.Contains(result.Diagnostics, item => item.Code == "CARRIER_LITERAL_DECODED");
    }

    [Fact]
    public void DecodesQuotedLuauEscapesExactly()
    {
        var result = EnvelopeScanner.Analyze(Fixture("\"LPH@A\\x42\\067\\n\\u{44}\\z   E\""));

        var carrier = Assert.Single(result.Carriers);
        Assert.Equal(CarrierDecodeStatus.DecodedLiteral, carrier.Status);
        Assert.Equal("LPH@ABC\nDE", Encoding.UTF8.GetString(carrier.Bytes));
    }

    [Fact]
    public void NormalizesLongBracketFirstNewline()
    {
        var result = EnvelopeScanner.Analyze(Fixture("[=[\r\nLPH@line1\r\nline2]=]"));

        Assert.Equal("LPH@line1\nline2", Encoding.UTF8.GetString(Assert.Single(result.Carriers).Bytes));
    }

    [Fact]
    public void LeavesInterpolatedAndMalformedCarriersOpaque()
    {
        var interpolated = EnvelopeScanner.Analyze(Fixture("`LPH@{dynamic}`"));
        var malformed = EnvelopeScanner.Analyze(Fixture("\"LPH@\\xG1\""));

        Assert.Equal(CarrierDecodeStatus.UnsupportedLiteral, Assert.Single(interpolated.Carriers).Status);
        Assert.Contains(interpolated.Diagnostics, item => item.Code == "CARRIER_LITERAL_UNSUPPORTED");
        Assert.Equal(CarrierDecodeStatus.InvalidLiteral, Assert.Single(malformed.Carriers).Status);
        Assert.Contains(malformed.Diagnostics, item => item.Code == "CARRIER_LITERAL_INVALID");
    }

    [Fact]
    public void DoesNotDecodeWithoutCompleteWrapperProof()
    {
        const string source = "-- This file was protected using Luraph Obfuscator v14.7 [https://lura.ph/]\nlocal payload=[=[LPH@opaque]=]";

        var result = EnvelopeScanner.Analyze(source);

        Assert.True(result.FamilyDetected);
        Assert.False(result.StaticDecode.Eligible);
        Assert.Empty(result.Carriers);
        Assert.Contains(result.Diagnostics, item => item.Code == "STATIC_DECODE_SKIPPED_UNPROVEN_WRAPPER");
    }

    [Fact]
    public void EnforcesSourceTokenAndCarrierLimits()
    {
        var source = Fixture("\"LPH@0123456789\"");
        var sourceLimited = EnvelopeScanner.Analyze(source, new() { MaxSourceBytes = 8 });
        var tokenLimited = EnvelopeScanner.Analyze(source, new() { MaxTokens = 3 });
        var carrierLimited = EnvelopeScanner.Analyze(source, new() { MaxCarrierBytes = 8 });

        Assert.Contains(sourceLimited.Diagnostics, item => item.Code == "SOURCE_LIMIT");
        Assert.Contains(tokenLimited.Diagnostics, item => item.Code == "TOKEN_LIMIT");
        Assert.Equal(CarrierDecodeStatus.ByteLimitExceeded, Assert.Single(carrierLimited.Carriers).Status);
    }

    [Fact]
    public void ExtractsReaderHintsWithoutClaimingImplementationProof()
    {
        var result = EnvelopeScanner.Analyze(Fixture("[=[LPH@reader]=]"));

        var readu8 = Assert.Single(result.Readers, item => item.Name == "readu8");
        var readu32 = Assert.Single(result.Readers, item => item.Name == "readu32");
        Assert.True(readu8.DefinitionPresent);
        Assert.Equal(8, readu8.BitWidth);
        Assert.Equal(32, readu32.BitWidth);
        Assert.Equal(ByteOrder.Unknown, readu32.ByteOrder);
        Assert.True(readu32.InferredFromIdentifier);
        Assert.False(readu32.ImplementationVerified);
    }

    [Fact]
    public void ScansCommittedV147FixtureWithinDefaultLimits()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "tests", "fixtures", "luraph", "subject_1b642e9523c1.luau")))
            root = root.Parent;
        Assert.NotNull(root);
        var source = File.ReadAllText(Path.Combine(root.FullName, "tests", "fixtures", "luraph", "subject_1b642e9523c1.luau"));

        var result = EnvelopeScanner.Analyze(source);

        Assert.True(result.Complete);
        Assert.True(result.FamilyDetected);
        Assert.True(result.VersionSupported);
        Assert.Equal(WrapperKind.ReturnedTableMethodDispatch, result.Wrapper.Kind);
        Assert.True(result.StaticDecode.Complete);
        Assert.NotEmpty(result.Carriers);
        Assert.All(result.Carriers, carrier => Assert.Equal(CarrierDecodeStatus.DecodedLiteral, carrier.Status));
    }

    [Fact]
    public void DetectsLuaAuthWrappedLphDollarWithoutRetainingIdentityValues()
    {
        var body = Fixture("[=[LPH$!!!!!z!!!!!]=]")[(Fixture("[=[LPH$!!!!!z!!!!!]=]").IndexOf('\n') + 1)..];
        var source = "la_code=123456789;la_script_id='fixture_id_123'\n" +
            "--[[ LuaAuth protected loader. https://luaauth.com ]]\n\n" + body;

        var result = EnvelopeScanner.Analyze(source);

        Assert.True(result.Complete);
        Assert.True(result.FamilyDetected);
        Assert.True(result.VersionSupported);
        Assert.True(result.LuaAuthLauncher.Present);
        Assert.True(result.LuaAuthLauncher.ExactAssignmentShape);
        Assert.True(result.LuaAuthLauncher.MetadataRemovedFromBody);
        Assert.Equal(9, result.LuaAuthLauncher.CodeDigitCount);
        Assert.Equal(14, result.LuaAuthLauncher.ScriptIdByteCount);
        Assert.True(result.StaticDecode.Eligible);
        Assert.True(result.StaticDecode.Complete);
        Assert.Equal(BlobKind.LphDollar, Assert.Single(result.Carriers).Kind);
        Assert.True(result.Carriers[0].LiteralRange.Begin >= result.LuaAuthLauncher.ProtectedBodyRange!.Value.Begin);
        Assert.DoesNotContain("123456789", System.Text.Json.JsonSerializer.Serialize(result), StringComparison.Ordinal);
        Assert.DoesNotContain("fixture_id_123", System.Text.Json.JsonSerializer.Serialize(result), StringComparison.Ordinal);
        Assert.Contains(result.Diagnostics, item => item.Code == "LUAAUTH_LAUNCHER_REMOVED");
    }

    [Theory]
    [InlineData("la_code=123;la_script_id='bad/id'\n--[[ LuaAuth protected loader. https://luaauth.com ]]\nreturn 1")]
    [InlineData("la_code=123;la_script_id='safe'\n--[[ copied loader ]]\nreturn 'LPH$!!!!!'")]
    [InlineData("la_code=123;la_script_id='safe'\n--[[ LuaAuth protected loader. https://luaauth.com ]]\nlocal x='LPH$!!!!!'")]
    public void RejectsLuaAuthLauncherNearMisses(string source)
    {
        var result = EnvelopeScanner.Analyze(source);

        Assert.False(result.LuaAuthLauncher.Present);
        Assert.False(result.VersionSupported);
    }

    [Fact]
    public void ParsesContainerRecordsAndSpans()
    {
        var decoded = SyntheticContainer();
        var source = Fixture(LongLiteral(Radix85(decoded)));

        var result = EnvelopeScanner.Analyze(source);

        var container = Assert.Single(result.Containers);
        Assert.Equal(ContainerDecodeStatus.Decoded, container.DecodeStatus);
        Assert.Equal(ContainerParseStatus.Parsed, container.ParseStatus);
        Assert.Equal(3, container.ConstantCount);
        Assert.Equal(1, container.PrototypeCount);
        Assert.Equal(2, container.InstructionCount);
        Assert.Equal(2, container.DescriptorCount);
        Assert.Equal(64, container.DecodedSha256.Length);
        Assert.Equal(container.ConstantCountSpan.End, container.ConstantPoolModeSpan.Begin);
        Assert.Equal(container.ConstantPoolModeSpan.End, container.ConstantsSpan.Begin);
        Assert.Equal(container.ConstantsSpan.End, container.PrototypeCountSpan.Begin);

        Assert.Equal(ConstantKind.Integer, container.Constants[0].Kind);
        Assert.Equal(-32768, container.Constants[0].SignedIntegerValue);
        Assert.Equal(ConstantKind.String, container.Constants[1].Kind);
        Assert.Equal("abc", Encoding.UTF8.GetString(container.Constants[1].StringBytes));
        Assert.Equal(false, container.Constants[2].BooleanValue);

        var prototype = Assert.Single(container.Prototypes);
        Assert.Equal((ulong)7, prototype.Meta);
        Assert.Equal((ulong)20, prototype.FinalValue);
        Assert.Equal(-1, prototype.Instructions[0].Words[2].Value);
        Assert.Equal(-(1L << 52), prototype.Instructions[1].Words[2].Value);
        Assert.Equal((uint)2, prototype.Descriptors[0].Kind);
        Assert.Equal((ulong)1, prototype.Descriptors[1].ReferencedIndex);
    }

    [Theory]
    [InlineData("LPH&!!!!", ContainerDecodeStatus.MisalignedBody)]
    [InlineData("LPH&!!!! ", ContainerDecodeStatus.InvalidCharacter)]
    [InlineData("LPH&uuuuu", ContainerDecodeStatus.Radix85Overflow)]
    public void RejectsInvalidRadix85(string carrier, ContainerDecodeStatus expected)
    {
        var result = EnvelopeScanner.Analyze(Fixture(LongLiteral(carrier)));

        Assert.Equal(expected, Assert.Single(result.Containers).DecodeStatus);
        Assert.False(result.StaticDecode.Complete);
    }

    [Fact]
    public void ReportsNonCanonicalAndOverflowingUleb()
    {
        var noncanonical = Pad([0x80, 0x00]);
        var overflow = Pad([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]);

        var first = EnvelopeScanner.Analyze(Fixture(LongLiteral(Radix85(noncanonical))));
        var second = EnvelopeScanner.Analyze(Fixture(LongLiteral(Radix85(overflow))));

        Assert.Equal(ContainerParseStatus.NonCanonicalUleb, Assert.Single(first.Containers).ParseStatus);
        Assert.Equal(ContainerParseStatus.UlebOverflow, Assert.Single(second.Containers).ParseStatus);
    }

    private static string Fixture(string literal, string version = "14.7") =>
        $"-- This file was protected using Luraph Obfuscator v{version} [https://lura.ph/]\n" +
        "return({P=function(self)return function(...)return ... end end," +
        "readu8=function(s,i)return string.byte(s,i)end," +
        "readu32=function(s,i)return bit32.band(string.byte(s,i),255)end," +
        $"payload={literal}}}):P()(...);";

    private static string LongLiteral(string value) => $"[========[{value}]========]";

    private static byte[] SyntheticContainer()
    {
        var bytes = new List<byte>();
        AppendUleb(bytes, 12_618 + 3);
        bytes.Add(0x5a);

        bytes.Add(0);
        bytes.Add(0x00);
        bytes.Add(0x80);
        bytes.Add(117);
        AppendUleb(bytes, 3);
        bytes.AddRange("abc"u8.ToArray());
        bytes.Add(47);

        AppendUleb(bytes, 87_799 + 1);
        AppendUleb(bytes, 7);
        AppendUleb(bytes, 7_379 + 2);
        AppendInstruction(bytes, [0, 7, -1, -2]);
        AppendInstruction(bytes, [1, (1L << 52) - 1, -(1L << 52), -1_234_567]);
        AppendUleb(bytes, 2);
        AppendUleb(bytes, 1 * 4UL + 2);
        AppendUleb(bytes, 1 * 4UL + 3);
        AppendUleb(bytes, 20);
        AppendUleb(bytes, 1);
        while (bytes.Count % 4 != 0)
            bytes.Add(0xef);
        return [.. bytes];
    }

    private static void AppendInstruction(List<byte> bytes, long[] words)
    {
        foreach (var word in words)
            AppendUleb(bytes, SignedFold(word));
    }

    private static ulong SignedFold(long value) => value < 0 ? (1UL << 53) - (ulong)-value : (ulong)value;

    private static byte[] Pad(byte[] bytes)
    {
        var output = bytes.ToList();
        while (output.Count % 4 != 0)
            output.Add(0);
        return [.. output];
    }

    private static void AppendUleb(List<byte> output, ulong value)
    {
        do
        {
            var ch = (byte)(value & 0x7f);
            value >>= 7;
            if (value != 0)
                ch |= 0x80;
            output.Add(ch);
        }
        while (value != 0);
    }

    private static string Radix85(byte[] decoded)
    {
        Assert.Equal(0, decoded.Length % 4);
        var output = new StringBuilder("LPH&");
        for (var offset = 0; offset < decoded.Length; offset += 4)
        {
            uint value = 0;
            for (var i = 0; i < 4; i++)
                value |= (uint)decoded[offset + i] << (i * 8);
            var digits = new char[5];
            for (var i = 4; i >= 0; i--)
            {
                digits[i] = (char)(value % 85 + 33);
                value /= 85;
            }
            output.Append(digits);
        }
        return output.ToString();
    }
}
