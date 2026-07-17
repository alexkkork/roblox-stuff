using System.Globalization;
using Luraph.Core.Scanning;

namespace Luraph.Core.Containers.Legacy;

internal sealed record LegacySourceEvidence(
    byte[] Carrier,
    IReadOnlyList<LegacyOffsetEvidence> Offsets,
    IReadOnlyList<LegacyDiagnostic> Diagnostics);

internal static class LegacySourceScanner
{
    public static LegacySourceEvidence Scan(string source, LegacyParseOptions options)
    {
        var diagnostics = new List<LegacyDiagnostic>();
        var limits = options.Limits;
        if (string.IsNullOrEmpty(source))
        {
            diagnostics.Add(new(DiagnosticSeverity.Error, "LEGACY_EMPTY_SOURCE", "Source is empty."));
            return new([], [], diagnostics);
        }
        if (System.Text.Encoding.UTF8.GetByteCount(source) > Math.Max(0, limits.MaxSourceBytes))
        {
            diagnostics.Add(new(DiagnosticSeverity.Error, "LEGACY_SOURCE_LIMIT", "Source byte limit was exceeded."));
            return new([], [], diagnostics);
        }

        var scanDiagnostics = new List<ScanDiagnostic>();
        var lexed = LuauLexer.Lex(source, limits.MaxTokens, scanDiagnostics.Add);
        foreach (var item in scanDiagnostics)
            diagnostics.Add(new(item.Severity, item.Code, item.Message, SourceRange: item.Range));
        if (!lexed.Complete)
            return new([], [], diagnostics);

        byte[] carrier = [];
        foreach (var token in lexed.Tokens)
        {
            if (token.Kind != TokenKind.String)
                continue;
            var decoded = LiteralDecoder.Decode(source, token, limits.MaxCarrierBytes);
            if (decoded.Status != CarrierDecodeStatus.DecodedLiteral || decoded.Bytes.Length < 4)
                continue;
            if (decoded.Bytes[0] == 'L' && decoded.Bytes[1] == 'P' && decoded.Bytes[2] == 'H' && decoded.Bytes[3] is >= 33 and <= 126)
            {
                carrier = decoded.Bytes;
                break;
            }
        }

        var matches = MatchDelimiters(source, lexed.Tokens, limits.MaxNesting);
        var offsets = new List<LegacyOffsetEvidence>();
        for (var i = 1; i + 1 < lexed.Tokens.Count && offsets.Count < Math.Max(0, options.MaxOffsetCandidates); i++)
        {
            if (!LuauLexer.Is(lexed.Tokens[i], source, "-") || lexed.Tokens[i + 1].Kind != TokenKind.Number)
                continue;
            var closeCall = i - 1;
            if (!LuauLexer.Is(lexed.Tokens[closeCall], source, ")") || matches[closeCall] < 1)
                continue;
            var openCall = matches[closeCall];
            if (!LuauLexer.Is(lexed.Tokens[openCall - 1], source, "]"))
                continue;
            var literal = source[lexed.Tokens[i + 1].Begin..lexed.Tokens[i + 1].End];
            if (!TryNumber(literal, out var value))
                continue;
            offsets.Add(new(value, literal, new(lexed.Tokens[openCall - 1].Begin, lexed.Tokens[i + 1].End)));
        }

        if (carrier.Length == 0)
            diagnostics.Add(new(DiagnosticSeverity.Error, "LEGACY_CARRIER_NOT_FOUND", "No static LPH carrier literal was found."));
        if (offsets.Count == 0)
            diagnostics.Add(new(DiagnosticSeverity.Warning, "LEGACY_OFFSETS_NOT_FOUND", "No call-result subtraction offsets were proven in source."));
        else if (offsets.Count >= Math.Max(0, options.MaxOffsetCandidates))
            diagnostics.Add(new(DiagnosticSeverity.Warning, "LEGACY_OFFSET_LIMIT", "Offset evidence reached the configured candidate limit."));
        return new(carrier, offsets, diagnostics);
    }

    private static int[] MatchDelimiters(string source, IReadOnlyList<Token> tokens, int maxNesting)
    {
        var matches = Enumerable.Repeat(-1, tokens.Count).ToArray();
        var stack = new Stack<int>();
        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            if (token.Kind != TokenKind.Symbol || token.End - token.Begin != 1)
                continue;
            var ch = source[token.Begin];
            if (ch is '(' or '[' or '{')
            {
                if (stack.Count >= Math.Max(0, maxNesting))
                    return matches;
                stack.Push(i);
            }
            else if (ch is ')' or ']' or '}')
            {
                if (stack.Count == 0)
                    continue;
                var open = stack.Peek();
                if (!Pair(source[tokens[open].Begin], ch))
                    continue;
                stack.Pop();
                matches[open] = i;
                matches[i] = open;
            }
        }
        return matches;
    }

    private static bool Pair(char open, char close) =>
        open == '(' && close == ')' || open == '[' && close == ']' || open == '{' && close == '}';

    private static bool TryNumber(string literal, out long value)
    {
        var clean = literal.Replace("_", string.Empty, StringComparison.Ordinal);
        if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(clean.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value);
        if (!clean.StartsWith("0b", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(clean, NumberStyles.None, CultureInfo.InvariantCulture, out value);

        value = 0;
        foreach (var ch in clean.AsSpan(2))
        {
            if (ch is not ('0' or '1') || value > (long.MaxValue - (ch - '0')) / 2)
                return false;
            value = value * 2 + ch - '0';
        }
        return clean.Length > 2;
    }
}
