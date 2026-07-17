using System.Text;
using Luraph.Core.Containers;

namespace Luraph.Core.Tests.Scanning;

public sealed class ContainerLimitTests
{
    [Fact]
    public void ReportsBiasedCountUnderflow()
    {
        var result = Decode(Pad([0]));

        Assert.Equal(ContainerParseStatus.CountUnderflow, result.ParseStatus);
        Assert.Equal(0, result.ParseErrorOffset);
    }

    [Fact]
    public void EnforcesConstantCountLimit()
    {
        var bytes = new List<byte>();
        AppendUleb(bytes, 12_619);

        var result = Decode(Pad(bytes), new() { MaxConstants = 0 });

        Assert.Equal(ContainerParseStatus.CountLimitExceeded, result.ParseStatus);
    }

    [Fact]
    public void RejectsSignedFoldOutside53BitDomain()
    {
        var bytes = new List<byte>();
        AppendUleb(bytes, 12_618);
        bytes.Add(0);
        AppendUleb(bytes, 87_800);
        AppendUleb(bytes, 0);
        AppendUleb(bytes, 7_380);
        AppendUleb(bytes, 1UL << 53);

        var result = Decode(Pad(bytes));

        Assert.Equal(ContainerParseStatus.SignedFoldOverflow, result.ParseStatus);
    }

    [Fact]
    public void EnforcesTrailerPreservationLimit()
    {
        var bytes = new List<byte>();
        AppendUleb(bytes, 12_618);
        bytes.Add(0);
        AppendUleb(bytes, 87_799);
        AppendUleb(bytes, 0);
        var padded = Pad(bytes);

        var result = Decode(padded, new() { MaxTrailerBytes = 0 });

        Assert.Equal(ContainerParseStatus.TrailerLimitExceeded, result.ParseStatus);
        Assert.Equal(padded.Length - 1, result.ParseErrorOffset);
    }

    [Fact]
    public void EnforcesDecodedContainerBudget()
    {
        var carrier = Encoding.ASCII.GetBytes("LPH&!!!!!!!!!!");

        var result = LphContainerDecoder.Decode(carrier, 0, new() { MaxContainerBytes = 4 });

        Assert.Equal(ContainerDecodeStatus.OutputLimitExceeded, result.DecodeStatus);
        Assert.Equal(2, result.Radix85GroupCount);
    }

    private static ContainerAnalysis Decode(byte[] bytes, AnalysisLimits? limits = null) =>
        LphContainerDecoder.Decode(Encoding.ASCII.GetBytes(Radix85(bytes)), 0, limits);

    private static byte[] Pad(IEnumerable<byte> values)
    {
        var bytes = values.ToList();
        while (bytes.Count % 4 != 0)
            bytes.Add(0xee);
        return [.. bytes];
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
