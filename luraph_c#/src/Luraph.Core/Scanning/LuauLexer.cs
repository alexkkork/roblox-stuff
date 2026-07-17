namespace Luraph.Core.Scanning;

internal enum TokenKind
{
    Identifier,
    Number,
    String,
    Symbol,
}

internal readonly record struct Token(
    TokenKind Kind,
    int Begin,
    int End,
    int ContentBegin = 0,
    int ContentEnd = 0,
    bool LongString = false);

internal sealed record LexResult(List<Token> Tokens, int CommentCount, bool Complete);

internal static class LuauLexer
{
    private const int MaxLongBracketEquals = 64;

    private static readonly string[] Operators =
    [
        "...", "//=", "..=", "==", "~=", "<=", ">=", "+=", "-=", "*=", "/=", "%=", "^=", "..", "//", "->", "::",
    ];

    public static LexResult Lex(string source, int maxTokens, Action<ScanDiagnostic> addDiagnostic)
    {
        var tokens = new List<Token>(Math.Min(Math.Max(0, maxTokens), source.Length / 3 + 1));
        var comments = 0;
        var complete = true;
        var pos = source.Length > 0 && source[0] == '\ufeff' ? 1 : 0;

        while (pos < source.Length)
        {
            if (char.IsWhiteSpace(source[pos]))
            {
                pos++;
                continue;
            }

            if (pos + 1 < source.Length && source[pos] == '-' && source[pos + 1] == '-')
            {
                comments++;
                pos += 2;
                if (TryLongBracketOpen(source, pos, out var equals, out _))
                {
                    if (TryLongBracketContent(source, pos, out var content))
                        pos = content.End + equals + 2;
                    else
                    {
                        complete = false;
                        addDiagnostic(new(DiagnosticSeverity.Warning, "UNTERMINATED_LONG_COMMENT", "A long-bracket comment is unterminated.", new(pos - 2, source.Length)));
                        pos = source.Length;
                    }
                }
                else
                {
                    while (pos < source.Length && source[pos] is not ('\n' or '\r'))
                        pos++;
                }
                continue;
            }

            if (tokens.Count >= Math.Max(0, maxTokens))
            {
                complete = false;
                addDiagnostic(new(DiagnosticSeverity.Error, "TOKEN_LIMIT", "Token limit reached before structural scanning completed."));
                break;
            }

            var begin = pos;
            if (source[pos] is '\'' or '"' or '`')
            {
                var end = QuotedStringEnd(source, pos);
                var terminated = end > pos + 1 && source[end - 1] == source[pos];
                tokens.Add(new(TokenKind.String, pos, end, pos + 1, terminated ? end - 1 : end));
                if (!terminated)
                {
                    complete = false;
                    addDiagnostic(new(DiagnosticSeverity.Warning, "UNTERMINATED_STRING", "A quoted string literal is unterminated.", new(pos, source.Length)));
                }
                pos = end;
                continue;
            }

            if (TryLongBracketOpen(source, pos, out var bracketEquals, out var contentBegin))
            {
                if (TryLongBracketContent(source, pos, out var content))
                {
                    pos = content.End + bracketEquals + 2;
                    tokens.Add(new(TokenKind.String, begin, pos, contentBegin, content.End, true));
                }
                else
                {
                    tokens.Add(new(TokenKind.String, begin, source.Length, contentBegin, source.Length, true));
                    complete = false;
                    addDiagnostic(new(DiagnosticSeverity.Warning, "UNTERMINATED_LONG_STRING", "A long-bracket string literal is unterminated.", new(begin, source.Length)));
                    pos = source.Length;
                }
                continue;
            }

            if (IsIdentifierStart(source[pos]))
            {
                pos++;
                while (pos < source.Length && IsIdentifierPart(source[pos]))
                    pos++;
                tokens.Add(new(TokenKind.Identifier, begin, pos));
                continue;
            }

            if (char.IsAsciiDigit(source[pos]) || source[pos] == '.' && pos + 1 < source.Length && char.IsAsciiDigit(source[pos + 1]))
            {
                pos = NumberEnd(source, pos);
                tokens.Add(new(TokenKind.Number, begin, pos));
                continue;
            }

            pos = SymbolEnd(source, pos);
            tokens.Add(new(TokenKind.Symbol, begin, pos));
        }

        return new(tokens, comments, complete);
    }

    public static bool Is(Token token, string source, string value) =>
        token.End - token.Begin == value.Length && source.AsSpan(token.Begin, value.Length).SequenceEqual(value);

    public static bool TryLongBracketOpen(string source, int pos, out int equals, out int contentBegin)
    {
        equals = 0;
        contentBegin = 0;
        if ((uint)pos >= (uint)source.Length || source[pos] != '[')
            return false;

        var cur = pos + 1;
        while (cur < source.Length && source[cur] == '=' && cur - pos - 1 <= MaxLongBracketEquals)
            cur++;
        equals = cur - pos - 1;
        if (equals > MaxLongBracketEquals || cur >= source.Length || source[cur] != '[')
            return false;
        contentBegin = cur + 1;
        return true;
    }

    private static bool TryLongBracketContent(string source, int pos, out SourceRange content)
    {
        content = default;
        if (!TryLongBracketOpen(source, pos, out var equals, out var contentBegin))
            return false;

        var cur = contentBegin;
        while (cur < source.Length)
        {
            if (source[cur] != ']')
            {
                cur++;
                continue;
            }

            var close = cur + 1;
            while (close < source.Length && source[close] == '=')
                close++;
            if (close - cur - 1 == equals && close < source.Length && source[close] == ']')
            {
                content = new(contentBegin, cur);
                return true;
            }
            cur = close;
        }
        return false;
    }

    private static bool IsIdentifierStart(char ch) => ch == '_' || char.IsAsciiLetter(ch);

    private static bool IsIdentifierPart(char ch) => ch == '_' || char.IsAsciiLetterOrDigit(ch);

    private static int QuotedStringEnd(string source, int pos)
    {
        var quote = source[pos];
        var cur = pos + 1;
        while (cur < source.Length)
        {
            if (source[cur] == quote)
                return cur + 1;
            if (source[cur] == '\\')
            {
                cur++;
                if (cur + 1 < source.Length && source[cur] is '\r' or '\n' && source[cur + 1] is '\r' or '\n' && source[cur] != source[cur + 1])
                    cur += 2;
                else if (cur < source.Length)
                    cur++;
                continue;
            }
            cur++;
        }
        return source.Length;
    }

    private static int NumberEnd(string source, int pos)
    {
        var cur = pos;
        while (cur < source.Length)
        {
            var ch = source[cur];
            if (char.IsAsciiLetterOrDigit(ch) || ch == '_')
            {
                cur++;
                continue;
            }
            if (ch == '.')
            {
                if (cur + 1 < source.Length && source[cur + 1] == '.')
                    break;
                cur++;
                continue;
            }
            if (ch is '+' or '-' && cur > pos && source[cur - 1] is 'e' or 'E' or 'p' or 'P')
            {
                cur++;
                continue;
            }
            break;
        }
        return cur;
    }

    private static int SymbolEnd(string source, int pos)
    {
        foreach (var op in Operators)
            if (pos + op.Length <= source.Length && source.AsSpan(pos, op.Length).SequenceEqual(op))
                return pos + op.Length;
        return pos + 1;
    }
}

