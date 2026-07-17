using System.Security.Cryptography;

namespace Luraph.Core.Containers.Legacy;

internal sealed record LegacyDecodeResult(LegacyCarrierMetadata Metadata, byte[] Bytes);

internal static class LegacyAscii85
{
    public static LegacyDecodeResult Decode(ReadOnlySpan<byte> carrier, int maxBytes)
    {
        if (carrier.Length < 4 || carrier[0] != 'L' || carrier[1] != 'P' || carrier[2] != 'H' || carrier[3] is < 33 or > 126)
            return Failed(LegacyDecodeStatus.InvalidPrefix, carrier.Length, 0);

        var body = carrier[4..];
        var output = new List<byte>(Math.Min(Math.Max(0, maxBytes), body.Length));
        var groups = 0;
        var zeroGroups = 0;
        var pos = 0;
        while (pos < body.Length)
        {
            if (body[pos] == 'z')
            {
                if (!Reserve(output, 4, maxBytes))
                    return Failed(LegacyDecodeStatus.OutputLimitExceeded, carrier.Length, pos + 4, body.Length, groups, zeroGroups);
                output.AddRange([0, 0, 0, 0]);
                pos++;
                groups++;
                zeroGroups++;
                continue;
            }

            if (pos + 5 > body.Length)
                return Failed(LegacyDecodeStatus.MisalignedBody, carrier.Length, pos + 4, body.Length, groups, zeroGroups);
            if (!Reserve(output, 4, maxBytes))
                return Failed(LegacyDecodeStatus.OutputLimitExceeded, carrier.Length, pos + 4, body.Length, groups, zeroGroups);

            ulong value = 0;
            for (var i = 0; i < 5; i++)
            {
                var ch = body[pos + i];
                if (ch is < 33 or > 117)
                    return Failed(LegacyDecodeStatus.InvalidCharacter, carrier.Length, pos + i + 4, body.Length, groups, zeroGroups);
                var digit = (ulong)(ch - 33);
                if (value > (uint.MaxValue - digit) / 85)
                    return Failed(LegacyDecodeStatus.Overflow, carrier.Length, pos + 4, body.Length, groups, zeroGroups);
                value = value * 85 + digit;
            }

            output.Add((byte)value);
            output.Add((byte)(value >> 8));
            output.Add((byte)(value >> 16));
            output.Add((byte)(value >> 24));
            pos += 5;
            groups++;
        }

        var bytes = output.ToArray();
        return new(new()
        {
            Marker = System.Text.Encoding.ASCII.GetString(carrier[..4]),
            EncodedBytes = carrier.Length,
            EncodedBodyBytes = body.Length,
            GroupCount = groups,
            ZeroGroupCount = zeroGroups,
            DecodedBytes = bytes.Length,
            DecodedSha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
            Status = LegacyDecodeStatus.Decoded,
        }, bytes);
    }

    private static bool Reserve(List<byte> output, int count, int maxBytes) =>
        output.Count <= Math.Max(0, maxBytes) - count;

    private static LegacyDecodeResult Failed(
        LegacyDecodeStatus status,
        int encodedBytes,
        int errorOffset,
        int bodyBytes = 0,
        int groups = 0,
        int zeroGroups = 0) => new(new()
        {
            EncodedBytes = encodedBytes,
            EncodedBodyBytes = bodyBytes,
            GroupCount = groups,
            ZeroGroupCount = zeroGroups,
            Status = status,
            ErrorOffset = errorOffset,
        }, []);
}

