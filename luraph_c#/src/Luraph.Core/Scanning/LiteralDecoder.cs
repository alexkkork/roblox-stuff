using System.Text;

namespace Luraph.Core.Scanning;

internal sealed record LiteralDecodeResult(
    CarrierDecodeStatus Status,
    byte[] Bytes,
    SourceRange? ErrorRange = null);

internal static class LiteralDecoder
{
    public static LiteralDecodeResult Decode(string source, Token token, int maxBytes) =>
        token.LongString ? DecodeLong(source, token, maxBytes) : DecodeQuoted(source, token, maxBytes);

    private static LiteralDecodeResult DecodeLong(string source, Token token, int maxBytes)
    {
        var output = new List<byte>(Math.Min(Math.Max(0, maxBytes), token.ContentEnd - token.ContentBegin));
        var cur = token.ContentBegin;
        if (cur < token.ContentEnd && source[cur] is '\n' or '\r')
        {
            var first = source[cur++];
            if (cur < token.ContentEnd && first != source[cur] && source[cur] is '\n' or '\r')
                cur++;
        }

        while (cur < token.ContentEnd)
        {
            var begin = cur;
            var ch = source[cur++];
            if (ch is '\n' or '\r')
            {
                if (cur < token.ContentEnd && source[cur] != ch && source[cur] is '\n' or '\r')
                    cur++;
                ch = '\n';
            }

            foreach (var value in Encoding.UTF8.GetBytes(new[] { ch }))
                if (!Add(output, value, maxBytes))
                    return new(CarrierDecodeStatus.ByteLimitExceeded, [], new(begin, cur));
        }
        return new(CarrierDecodeStatus.DecodedLiteral, [.. output]);
    }

    private static LiteralDecodeResult DecodeQuoted(string source, Token token, int maxBytes)
    {
        if (source[token.Begin] == '`')
            return new(CarrierDecodeStatus.UnsupportedLiteral, [], new(token.Begin, token.End));
        if (token.End <= token.Begin + 1 || token.End > source.Length || source[token.End - 1] != source[token.Begin])
            return Invalid(token.Begin, token.End);

        var output = new List<byte>(Math.Min(Math.Max(0, maxBytes), token.ContentEnd - token.ContentBegin));
        var cur = token.ContentBegin;
        while (cur < token.ContentEnd)
        {
            var begin = cur;
            var ch = source[cur++];
            if (ch != '\\')
            {
                if (ch is '\n' or '\r')
                    return Invalid(begin, cur);
                foreach (var value in Encoding.UTF8.GetBytes(new[] { ch }))
                    if (!Add(output, value, maxBytes))
                        return Limit(begin, cur);
                continue;
            }

            if (cur >= token.ContentEnd)
                return Invalid(begin, cur);
            var escape = source[cur++];
            byte? simple = escape switch
            {
                'a' => 7,
                'b' => 8,
                'f' => 12,
                'n' => 10,
                'r' => 13,
                't' => 9,
                'v' => 11,
                '\\' => 92,
                '\'' => 39,
                '"' => 34,
                _ => null,
            };
            if (simple.HasValue)
            {
                if (!Add(output, simple.Value, maxBytes))
                    return Limit(begin, cur);
                continue;
            }

            if (escape is '\n' or '\r')
            {
                if (cur < token.ContentEnd && source[cur] != escape && source[cur] is '\n' or '\r')
                    cur++;
                if (!Add(output, 10, maxBytes))
                    return Limit(begin, cur);
                continue;
            }

            if (escape == 'z')
            {
                while (cur < token.ContentEnd && char.IsWhiteSpace(source[cur]))
                    cur++;
                continue;
            }

            if (char.IsAsciiDigit(escape))
            {
                var value = escape - '0';
                var digits = 1;
                while (digits < 3 && cur < token.ContentEnd && char.IsAsciiDigit(source[cur]))
                {
                    value = value * 10 + source[cur++] - '0';
                    digits++;
                }
                if (value > 255)
                    return Invalid(begin, cur);
                if (!Add(output, (byte)value, maxBytes))
                    return Limit(begin, cur);
                continue;
            }

            if (escape == 'x')
            {
                if (cur + 2 > token.ContentEnd || Hex(source[cur]) < 0 || Hex(source[cur + 1]) < 0)
                    return Invalid(begin, Math.Min(token.ContentEnd, cur + 2));
                var value = (byte)(Hex(source[cur]) * 16 + Hex(source[cur + 1]));
                cur += 2;
                if (!Add(output, value, maxBytes))
                    return Limit(begin, cur);
                continue;
            }

            if (escape == 'u' && cur < token.ContentEnd && source[cur] == '{')
            {
                cur++;
                var digitsBegin = cur;
                var codepoint = 0;
                var bad = false;
                while (cur < token.ContentEnd && source[cur] != '}')
                {
                    var digit = Hex(source[cur]);
                    if (digit < 0 || codepoint > (0x10ffff - digit) / 16)
                    {
                        bad = true;
                        break;
                    }
                    codepoint = codepoint * 16 + digit;
                    cur++;
                }
                if (bad || cur == digitsBegin || cur >= token.ContentEnd || source[cur] != '}' || codepoint > 0x10ffff || codepoint is >= 0xd800 and <= 0xdfff)
                    return Invalid(begin, Math.Min(token.ContentEnd, cur + 1));
                cur++;
                foreach (var value in Encoding.UTF8.GetBytes(char.ConvertFromUtf32(codepoint)))
                    if (!Add(output, value, maxBytes))
                        return Limit(begin, cur);
                continue;
            }

            return Invalid(begin, cur);
        }
        return new(CarrierDecodeStatus.DecodedLiteral, [.. output]);

        LiteralDecodeResult Invalid(int begin, int end) => new(CarrierDecodeStatus.InvalidLiteral, [], new(begin, end));
        LiteralDecodeResult Limit(int begin, int end) => new(CarrierDecodeStatus.ByteLimitExceeded, [], new(begin, end));
    }

    private static bool Add(List<byte> output, byte value, int maxBytes)
    {
        if (output.Count >= Math.Max(0, maxBytes))
        {
            output.Clear();
            return false;
        }
        output.Add(value);
        return true;
    }

    private static int Hex(char ch) => ch switch
    {
        >= '0' and <= '9' => ch - '0',
        >= 'a' and <= 'f' => ch - 'a' + 10,
        >= 'A' and <= 'F' => ch - 'A' + 10,
        _ => -1,
    };
}
