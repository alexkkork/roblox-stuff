using System.Text;
using Luraph.Core.Containers;

namespace Luraph.Core.Scanning;

public static class EnvelopeScanner
{
    private const int MinEncodedStringBytes = 64;
    private const int MinEncodedBlobBytes = 1_024;
    private const int MaxReaderMetadata = 32;

    private static readonly ReaderSpec[] ReaderSpecs =
    [
        new("readu8", ReaderValueKind.UnsignedInteger, 8),
        new("readu16", ReaderValueKind.UnsignedInteger, 16),
        new("readu32", ReaderValueKind.UnsignedInteger, 32),
        new("readi8", ReaderValueKind.SignedInteger, 8),
        new("readi16", ReaderValueKind.SignedInteger, 16),
        new("readi32", ReaderValueKind.SignedInteger, 32),
        new("readf32", ReaderValueKind.FloatingPoint, 32),
        new("readf64", ReaderValueKind.FloatingPoint, 64),
    ];

    private static readonly HashSet<string> ReaderPrimitives =
    [
        "readu8", "readu16", "readu32", "readi8", "readi16", "readi32", "readf32", "readf64", "byte", "char", "unpack", "bit32",
    ];

    public static EnvelopeAnalysis Analyze(string source, AnalysisLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        limits ??= new();
        var result = new EnvelopeAnalysis();
        result.Counts.SourceBytes = Encoding.UTF8.GetByteCount(source);
        AddDiagnostic(result, limits, DiagnosticSeverity.Info, "STRUCTURAL_ONLY",
            "Static envelope and proven container framing analysis only; input was not executed, and VM semantics or source recovery were not attempted.");

        if (source.Length == 0)
        {
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, "EMPTY_INPUT", "Input is empty.");
            return result;
        }
        if (result.Counts.SourceBytes > Math.Max(0, limits.MaxSourceBytes))
        {
            AddDiagnostic(result, limits, DiagnosticSeverity.Error, "SOURCE_LIMIT", "Source byte limit exceeded; no structural scan was performed.");
            return result;
        }

        result.LuaAuthLauncher = InspectLuaAuthLauncher(source);
        var bodyOffset = result.LuaAuthLauncher.ProtectedBodyRange?.Begin ?? 0;
        var protectedSource = source[bodyOffset..];
        result.Banner = InspectBanner(protectedSource);
        var luaAuthDollarCarrier = result.LuaAuthLauncher.Present &&
            protectedSource.Contains("LPH$", StringComparison.Ordinal);
        result.VersionSupported = result.Banner.Version == "14.7" || luaAuthDollarCarrier;
        if (result.Banner.ExactProductMarker && !result.VersionSupported)
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, "UNSUPPORTED_VERSION",
                "A Luraph banner was found, but its version is not the supported 14.7 envelope.", result.Banner.Range);
        if (result.LuaAuthLauncher.Present && !luaAuthDollarCarrier)
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, "LUAAUTH_CARRIER_UNSUPPORTED",
                "A LuaAuth launcher was recognized, but its protected body does not contain the supported LPH$ carrier.");

        var lexed = LuauLexer.Lex(protectedSource, limits.MaxTokens, diagnostic => AddDiagnostic(result, limits, diagnostic));
        result.Counts.TokenCount = lexed.Tokens.Count;
        result.Counts.CommentCount = lexed.CommentCount;
        InspectCountsAndBlobs(protectedSource, lexed.Tokens, result, limits);

        var matches = BalanceDelimiters(protectedSource, lexed.Tokens, result, limits, out var balanced);
        if (balanced)
            result.Wrapper = InspectWrapper(protectedSource, lexed.Tokens, matches);
        result.Complete = lexed.Complete && balanced;
        DecodeCarriers(protectedSource, lexed.Tokens, result, limits);
        ShiftBodyRanges(result, bodyOffset);
        if (result.LuaAuthLauncher.Present)
            AddDiagnostic(result, limits, DiagnosticSeverity.Info, "LUAAUTH_LAUNCHER_REMOVED",
                "LuaAuth launcher metadata was separated from the protected Luraph body.", result.LuaAuthLauncher.Range);
        InferStages(result);
        ScoreConfidence(result);

        if (result.FamilyDetected)
            AddDiagnostic(result, limits, DiagnosticSeverity.Info, "LURAPH_STRUCTURE_DETECTED",
                "Luraph structural signals were detected; classification remains envelope-only.");
        return result;
    }

    private static LuaAuthLauncherInfo InspectLuaAuthLauncher(string source)
    {
        var cursor = source.Length > 0 && source[0] == '\ufeff' ? 1 : 0;
        var launcherBegin = cursor;

        void SkipSpace()
        {
            while (cursor < source.Length && char.IsWhiteSpace(source[cursor]))
                cursor++;
        }

        bool Consume(string value)
        {
            if (!source.AsSpan(cursor).StartsWith(value, StringComparison.Ordinal))
                return false;
            cursor += value.Length;
            return true;
        }

        SkipSpace();
        if (!Consume("la_code"))
            return new();
        SkipSpace();
        if (!Consume("="))
            return new();
        SkipSpace();
        var codeBegin = cursor;
        while (cursor < source.Length && char.IsAsciiDigit(source[cursor]))
            cursor++;
        var codeDigits = cursor - codeBegin;
        if (codeDigits is < 1 or > 20)
            return new();
        SkipSpace();
        if (!Consume(";"))
            return new();
        SkipSpace();
        if (!Consume("la_script_id"))
            return new();
        SkipSpace();
        if (!Consume("="))
            return new();
        SkipSpace();
        if (cursor >= source.Length || source[cursor] is not ('\'' or '"'))
            return new();
        var quote = source[cursor++];
        var idBegin = cursor;
        while (cursor < source.Length && source[cursor] != quote)
        {
            var ch = source[cursor];
            if (!char.IsAsciiLetterOrDigit(ch) && ch is not ('_' or '-'))
                return new();
            cursor++;
        }
        var idBytes = cursor - idBegin;
        if (idBytes is < 1 or > 128 || cursor >= source.Length)
            return new();
        cursor++;
        SkipSpace();
        if (cursor < source.Length && source[cursor] == ';')
            cursor++;
        SkipSpace();

        if (!source.AsSpan(cursor).StartsWith("--[[", StringComparison.Ordinal))
            return new();
        var commentBegin = cursor + 4;
        var commentEnd = source.IndexOf("]]", commentBegin, StringComparison.Ordinal);
        if (commentEnd < 0)
            return new();
        var comment = source[commentBegin..commentEnd];
        var official = comment.Contains("LuaAuth", StringComparison.OrdinalIgnoreCase) &&
            comment.Contains("https://luaauth.com", StringComparison.OrdinalIgnoreCase);
        if (!official)
            return new();
        cursor = commentEnd + 2;
        if (cursor < source.Length && source[cursor] == '\r')
            cursor += cursor + 1 < source.Length && source[cursor + 1] == '\n' ? 2 : 1;
        else if (cursor < source.Length && source[cursor] == '\n')
            cursor += cursor + 1 < source.Length && source[cursor + 1] == '\r' ? 2 : 1;
        var bodyBegin = cursor;
        var bodyToken = cursor;
        while (bodyToken < source.Length && char.IsWhiteSpace(source[bodyToken]))
            bodyToken++;
        if (!source.AsSpan(bodyToken).StartsWith("return", StringComparison.Ordinal) ||
            bodyToken + 6 < source.Length && IsIdentifierContinue(source[bodyToken + 6]))
            return new();

        return new()
        {
            Present = true,
            ExactAssignmentShape = true,
            OfficialUrlMarker = true,
            MetadataRemovedFromBody = true,
            CodeDigitCount = codeDigits,
            ScriptIdByteCount = idBytes,
            Range = new(launcherBegin, bodyBegin),
            ProtectedBodyRange = new(bodyBegin, source.Length),
        };
    }

    private static bool IsIdentifierContinue(char ch) => ch == '_' || char.IsAsciiLetterOrDigit(ch);

    private static BannerInfo InspectBanner(string source)
    {
        var begin = source.Length > 0 && source[0] == '\ufeff' ? 1 : 0;
        while (begin < source.Length && source[begin] is ' ' or '\t')
            begin++;
        if (begin + 2 > source.Length || source.AsSpan(begin, 2).SequenceEqual("--") is false)
            return new();

        var end = begin + 2;
        while (end < source.Length && source[end] is not ('\n' or '\r'))
            end++;
        var comment = source[(begin + 2)..end];
        const string product = "Luraph Obfuscator";
        var productPos = comment.IndexOf(product, StringComparison.OrdinalIgnoreCase);
        if (productPos < 0)
            return new();

        var cur = productPos + product.Length;
        while (cur < comment.Length && char.IsWhiteSpace(comment[cur]))
            cur++;
        if (cur < comment.Length && comment[cur] is 'v' or 'V')
            cur++;
        var versionBegin = cur;
        while (cur < comment.Length && (char.IsAsciiDigit(comment[cur]) || comment[cur] == '.'))
            cur++;
        var version = cur > versionBegin && cur - versionBegin <= 32 ? comment[versionBegin..cur] : string.Empty;
        var parts = version.Split('.');

        return new()
        {
            Present = true,
            ExactProductMarker = comment.Contains("protected using Luraph Obfuscator", StringComparison.OrdinalIgnoreCase),
            OfficialUrlMarker = comment.Contains("https://lura.ph/", StringComparison.OrdinalIgnoreCase),
            Product = product,
            Version = version,
            Major = ParseVersionPart(parts, 0),
            Minor = ParseVersionPart(parts, 1),
            Patch = ParseVersionPart(parts, 2),
            Range = new(begin, end),
        };
    }

    private static uint? ParseVersionPart(string[] parts, int index)
    {
        if (index >= parts.Length || parts[index].Length is 0 or > 9)
            return null;
        return uint.TryParse(parts[index], out var value) && value <= 1_000_000_000 ? value : null;
    }

    private static int[] BalanceDelimiters(
        string source,
        IReadOnlyList<Token> tokens,
        EnvelopeAnalysis result,
        AnalysisLimits limits,
        out bool balanced)
    {
        var matches = Enumerable.Repeat(-1, tokens.Count).ToArray();
        var stack = new Stack<int>();
        balanced = true;

        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            if (token.Kind != TokenKind.Symbol || token.End - token.Begin != 1)
                continue;
            var ch = source[token.Begin];
            if (ch is '(' or '{' or '[')
            {
                if (stack.Count >= Math.Max(0, limits.MaxNesting))
                {
                    balanced = false;
                    AddDiagnostic(result, limits, DiagnosticSeverity.Error, "NESTING_LIMIT", "Delimiter nesting limit reached.", new(token.Begin, token.End));
                    break;
                }
                stack.Push(i);
            }
            else if (ch is ')' or '}' or ']')
            {
                if (stack.Count == 0 || !Matches(source[tokens[stack.Peek()].Begin], ch))
                {
                    balanced = false;
                    AddDiagnostic(result, limits, DiagnosticSeverity.Warning, "UNMATCHED_DELIMITER", "An unmatched closing delimiter was found.", new(token.Begin, token.End));
                    continue;
                }
                var open = stack.Pop();
                matches[open] = i;
                matches[i] = open;
            }
        }

        if (stack.Count > 0)
        {
            balanced = false;
            var token = tokens[stack.Peek()];
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, "UNCLOSED_DELIMITER", "An opening delimiter was not closed.", new(token.Begin, token.End));
        }
        return matches;
    }

    private static bool Matches(char open, char close) =>
        open == '(' && close == ')' || open == '{' && close == '}' || open == '[' && close == ']';

    private static WrapperShape InspectWrapper(string source, IReadOnlyList<Token> tokens, int[] matches)
    {
        if (tokens.Count == 0 || !LuauLexer.Is(tokens[0], source, "return"))
            return new();

        var index = 1;
        var parenthesis = -1;
        var parenthesized = false;
        if (index < tokens.Count && LuauLexer.Is(tokens[index], source, "("))
        {
            parenthesized = true;
            parenthesis = index++;
        }
        if (index >= tokens.Count || !LuauLexer.Is(tokens[index], source, "{") || matches[index] < 0)
            return new() { TopLevelReturn = true, ParenthesizedTable = parenthesized };

        var tableOpen = index;
        var tableClose = matches[index];
        var (fields, functions) = InspectTableFields(source, tokens, tableOpen, tableClose);
        var tableRange = new SourceRange(tokens[tableOpen].Begin, tokens[tableClose].End);
        index = tableClose + 1;
        if (parenthesis >= 0)
        {
            if (matches[parenthesis] < 0 || matches[parenthesis] != index)
                return TableOnly();
            index++;
        }

        var invocationBegin = index < tokens.Count ? tokens[index].Begin : tokens[tableOpen].Begin;
        if (index + 3 >= tokens.Count || !LuauLexer.Is(tokens[index], source, ":") || tokens[index + 1].Kind != TokenKind.Identifier ||
            !LuauLexer.Is(tokens[index + 2], source, "(") || matches[index + 2] < 0)
            return TableOnly();

        var method = source[tokens[index + 1].Begin..tokens[index + 1].End];
        var firstClose = matches[index + 2];
        var zeroArgs = firstClose == index + 3;
        index = firstClose + 1;
        if (index >= tokens.Count || !LuauLexer.Is(tokens[index], source, "(") || matches[index] < 0)
            return TableOnly();

        var dispatchClose = matches[index];
        var forwards = dispatchClose == index + 2 && LuauLexer.Is(tokens[index + 1], source, "...");
        index = dispatchClose + 1;
        while (index < tokens.Count && LuauLexer.Is(tokens[index], source, ";"))
            index++;

        return new()
        {
            Kind = WrapperKind.ReturnedTableMethodDispatch,
            TopLevelReturn = true,
            ParenthesizedTable = parenthesized,
            BalancedTable = true,
            ZeroArgumentMethodCall = zeroArgs,
            ForwardsVarargs = forwards,
            ConsumesEntireChunk = index == tokens.Count,
            MethodName = method.Length <= 64 ? method : string.Empty,
            TableFieldCount = fields,
            FunctionMemberCount = functions,
            TableRange = tableRange,
            InvocationRange = new(invocationBegin, tokens[dispatchClose].End),
        };

        WrapperShape TableOnly() => new()
        {
            Kind = WrapperKind.ReturnedTable,
            TopLevelReturn = true,
            ParenthesizedTable = parenthesized,
            BalancedTable = true,
            TableFieldCount = fields,
            FunctionMemberCount = functions,
            TableRange = tableRange,
        };
    }

    private static (int Fields, int Functions) InspectTableFields(string source, IReadOnlyList<Token> tokens, int open, int close)
    {
        var fields = 0;
        var functions = 0;
        var fieldBegin = open + 1;
        var delimiters = new Stack<char>();
        var blocks = new Stack<BlockKind>();

        void Finish(int end)
        {
            if (fieldBegin >= end)
                return;
            fields++;
            if (FieldIsFunction(source, tokens, fieldBegin, end))
                functions++;
        }

        for (var i = open + 1; i < close; i++)
        {
            var token = tokens[i];
            if (token.Kind == TokenKind.Symbol)
            {
                if (IsAny(token, source, "(", "{", "["))
                {
                    delimiters.Push(source[token.Begin]);
                    continue;
                }
                if (IsAny(token, source, ")", "}", "]"))
                {
                    if (delimiters.Count > 0)
                        delimiters.Pop();
                    continue;
                }
                if (delimiters.Count == 0 && blocks.Count == 0 && IsAny(token, source, ",", ";"))
                {
                    Finish(i);
                    fieldBegin = i + 1;
                }
                continue;
            }
            if (token.Kind != TokenKind.Identifier)
                continue;
            if (IsAny(token, source, "function", "if", "do"))
            {
                if (LuauLexer.Is(token, source, "do") && blocks.Count > 0 && blocks.Peek() == BlockKind.LoopAwaitingDo)
                {
                    blocks.Pop();
                    blocks.Push(BlockKind.End);
                }
                else
                    blocks.Push(BlockKind.End);
            }
            else if (IsAny(token, source, "while", "for"))
                blocks.Push(BlockKind.LoopAwaitingDo);
            else if (LuauLexer.Is(token, source, "repeat"))
                blocks.Push(BlockKind.Repeat);
            else if (LuauLexer.Is(token, source, "end") && blocks.Count > 0 && blocks.Peek() != BlockKind.Repeat)
                blocks.Pop();
            else if (LuauLexer.Is(token, source, "until") && blocks.Count > 0 && blocks.Peek() == BlockKind.Repeat)
                blocks.Pop();
        }
        Finish(close);
        return (fields, functions);
    }

    private static bool FieldIsFunction(string source, IReadOnlyList<Token> tokens, int begin, int end)
    {
        if (begin >= end)
            return false;
        if (LuauLexer.Is(tokens[begin], source, "function"))
            return true;
        var depth = 0;
        for (var i = begin; i < end; i++)
        {
            var token = tokens[i];
            if (token.Kind != TokenKind.Symbol)
                continue;
            if (IsAny(token, source, "(", "{", "["))
                depth++;
            else if (IsAny(token, source, ")", "}", "]"))
                depth = Math.Max(0, depth - 1);
            else if (depth == 0 && LuauLexer.Is(token, source, "=") && i + 1 < end && LuauLexer.Is(tokens[i + 1], source, "function"))
                return true;
        }
        return false;
    }

    private static void InspectCountsAndBlobs(
        string source,
        IReadOnlyList<Token> tokens,
        EnvelopeAnalysis result,
        AnalysisLimits limits)
    {
        foreach (var token in tokens)
        {
            switch (token.Kind)
            {
                case TokenKind.Identifier:
                    {
                        result.Counts.IdentifierCount++;
                        var value = source[token.Begin..token.End];
                        if (value == "function")
                            result.Counts.FunctionLiteralCount++;
                        if (value is "while" or "for" or "repeat")
                            result.Counts.LoopConstructCount++;
                        if (ReaderPrimitives.Contains(value))
                            result.Counts.ReaderPrimitiveReferenceCount++;
                        break;
                    }
                case TokenKind.Number:
                    result.Counts.NumericLiteralCount++;
                    break;
                case TokenKind.String:
                    {
                        result.Counts.StringLiteralCount++;
                        var sourceBytes = Math.Max(0, token.ContentEnd - token.ContentBegin);
                        result.Counts.StringLiteralSourceBytes += sourceBytes;
                        var stats = InspectString(source.AsSpan(token.ContentBegin, sourceBytes));
                        if (!EncodedStringCandidate(sourceBytes, stats))
                            break;
                        result.Counts.EncodedStringCandidateCount++;
                        if (sourceBytes < MinEncodedBlobBytes && !stats.HasLphMarker)
                            break;
                        result.Counts.EncodedBlobCandidateCount++;
                        result.Counts.EncodedBlobSourceBytes += sourceBytes;
                        if (result.Blobs.Count < Math.Max(0, limits.MaxBlobCandidates))
                            result.Blobs.Add(new(BlobKindFor(stats), new(token.Begin, token.End), sourceBytes, stats.Distinct,
                                stats.PrintableRatio, stats.WhitespaceRatio, token.LongString, stats.HasLphMarker));
                        break;
                    }
                case TokenKind.Symbol:
                    if (LuauLexer.Is(token, source, "{"))
                        result.Counts.TableConstructorCount++;
                    if (LuauLexer.Is(token, source, "["))
                        result.Counts.IndexedAccessCount++;
                    break;
            }
        }
        result.Blobs.Sort((left, right) => right.SourceBytes.CompareTo(left.SourceBytes));
    }

    private static void DecodeCarriers(string source, IReadOnlyList<Token> tokens, EnvelopeAnalysis result, AnalysisLimits limits)
    {
        result.StaticDecode.CarrierCandidateCount = result.Counts.EncodedBlobCandidateCount;
        result.StaticDecode.Eligible = result.Complete && result.Banner.ExactProductMarker && result.VersionSupported &&
            result.Wrapper.Kind == WrapperKind.ReturnedTableMethodDispatch && result.Wrapper.ZeroArgumentMethodCall &&
            result.Wrapper.ForwardsVarargs && result.Wrapper.ConsumesEntireChunk;
        if (!result.StaticDecode.Eligible)
        {
            if (result.VersionSupported && result.Counts.EncodedBlobCandidateCount > 0)
                AddDiagnostic(result, limits, DiagnosticSeverity.Info, "STATIC_DECODE_SKIPPED_UNPROVEN_WRAPPER",
                    "Carrier literals were not decoded because the complete v14.7 wrapper dispatch shape was not proven.");
            return;
        }

        result.StaticDecode.Attempted = true;
        result.StaticDecode.Complete = true;
        InspectReaders(source, tokens, result, limits);

        foreach (var token in tokens)
        {
            if (token.Kind != TokenKind.String)
                continue;
            var sourceBytes = Math.Max(0, token.ContentEnd - token.ContentBegin);
            var stats = InspectString(source.AsSpan(token.ContentBegin, sourceBytes));
            if (!EncodedBlobCandidate(sourceBytes, stats))
                continue;
            if (stats.HasLphMarker)
                result.ContainerMetrics.CandidateCount++;
            if (result.StaticDecode.CarrierAttemptCount >= Math.Max(0, limits.MaxBlobCandidates))
            {
                result.StaticDecode.CarrierSkippedCount++;
                result.StaticDecode.Complete = false;
                continue;
            }

            result.StaticDecode.CarrierAttemptCount++;
            result.StaticDecode.CarrierLiteralSourceBytes += sourceBytes;
            var remaining = Math.Max(0, limits.MaxCarrierBytes - result.StaticDecode.DecodedCarrierBytes);
            var decoded = LiteralDecoder.Decode(source, token, remaining);
            int? containerIndex = null;
            if (decoded.Status == CarrierDecodeStatus.DecodedLiteral)
            {
                result.StaticDecode.DecodedCarrierBytes += decoded.Bytes.Length;
                result.StaticDecode.CarrierDecodedCount++;
                if (stats.HasLphAmpersandMarker)
                    containerIndex = AddContainer(decoded.Bytes, result, limits);
            }
            else
            {
                result.StaticDecode.CarrierFailureCount++;
                result.StaticDecode.Complete = false;
                AddCarrierError(result, limits, decoded);
            }

            result.Carriers.Add(new()
            {
                Kind = BlobKindFor(stats),
                LiteralKind = token.LongString ? CarrierLiteralKind.LongBracketString : CarrierLiteralKind.QuotedString,
                Status = decoded.Status,
                LiteralRange = new(token.Begin, token.End),
                ContentRange = new(token.ContentBegin, token.ContentEnd),
                ErrorRange = decoded.ErrorRange,
                LiteralSourceBytes = sourceBytes,
                DecodedByteCount = decoded.Bytes.Length,
                LphMarkerOffset = FindLphMarker(decoded.Bytes),
                ContainerIndex = containerIndex,
                Bytes = decoded.Bytes,
            });
        }

        if (result.StaticDecode.CarrierSkippedCount > 0)
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, "CARRIER_TRACK_LIMIT",
                "Carrier tracking limit reached; additional candidates were counted but not decoded or retained.");
        if (result.StaticDecode.CarrierDecodedCount > 0)
            AddDiagnostic(result, limits, DiagnosticSeverity.Info, "CARRIER_LITERAL_DECODED",
                "Decoded exact Luau string-literal bytes from the proven v14.7 wrapper envelope.");
        if (result.StaticDecode.CarrierAttemptCount > 0)
            AddDiagnostic(result, limits, DiagnosticSeverity.Info, "VM_SEMANTICS_NOT_ATTEMPTED",
                "Carrier/container bytes were inspected only; VM semantics and source recovery were not attempted.");
    }

    private static int AddContainer(byte[] bytes, EnvelopeAnalysis result, AnalysisLimits limits)
    {
        result.ContainerMetrics.AttemptCount++;
        var budget = Math.Max(0, limits.MaxContainerBytes - result.ContainerMetrics.DecodedBytes);
        var container = LphContainerDecoder.Decode(bytes, result.Carriers.Count, limits, budget);
        result.ContainerMetrics.EncodedBodyBytes += container.EncodedBodyBytes;
        result.ContainerMetrics.Radix85GroupCount += container.Radix85GroupCount;

        if (container.DecodeStatus == ContainerDecodeStatus.Decoded)
        {
            result.ContainerMetrics.DecodedCount++;
            result.ContainerMetrics.DecodedBytes += container.DecodedBytes;
            AddDiagnostic(result, limits, DiagnosticSeverity.Info, "LPH_CONTAINER_DECODED",
                "Decoded strict LPH& radix-85 groups to little-endian container bytes.");
            if (container.ParseStatus == ContainerParseStatus.Parsed)
            {
                result.ContainerMetrics.ParsedCount++;
                result.ContainerMetrics.ConstantCount += container.ConstantCount;
                result.ContainerMetrics.PrototypeCount += container.PrototypeCount;
                result.ContainerMetrics.InstructionCount += container.InstructionCount;
                result.ContainerMetrics.DescriptorCount += container.DescriptorCount;
                result.ContainerMetrics.TrailerBytes += container.TrailerBytes.Length;
                AddDiagnostic(result, limits, DiagnosticSeverity.Info, "LPH_CONTAINER_PARSED",
                    "Parsed bounded LPH& constant and prototype records; unread trailer bytes were preserved without interpretation.");
            }
            else
            {
                result.ContainerMetrics.FailureCount++;
                result.StaticDecode.Complete = false;
                AddContainerParseError(result, limits, container.ParseStatus);
            }
        }
        else
        {
            result.ContainerMetrics.FailureCount++;
            result.StaticDecode.Complete = false;
            AddContainerDecodeError(result, limits, container.DecodeStatus);
        }

        var index = result.Containers.Count;
        result.Containers.Add(container);
        return index;
    }

    private static void InspectReaders(string source, IReadOnlyList<Token> tokens, EnvelopeAnalysis result, AnalysisLimits limits)
    {
        var observations = ReaderSpecs.ToDictionary(spec => spec.Name, _ => new ReaderObservation());
        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            if (token.Kind != TokenKind.Identifier)
                continue;
            var name = source[token.Begin..token.End];
            if (!observations.TryGetValue(name, out var item))
                continue;
            item.FirstRange ??= new(token.Begin, token.End);
            item.ReferenceCount++;
            result.StaticDecode.ReaderReferenceCount++;

            SourceRange? definition = null;
            if (i + 2 < tokens.Count && LuauLexer.Is(tokens[i + 1], source, "=") && LuauLexer.Is(tokens[i + 2], source, "function"))
                definition = new(token.Begin, tokens[i + 2].End);
            else if (i > 0 && LuauLexer.Is(tokens[i - 1], source, "function"))
                definition = new(tokens[i - 1].Begin, token.End);
            if (definition.HasValue)
            {
                item.DefinitionPresent = true;
                item.DefinitionRange ??= definition;
            }
        }

        var observed = 0;
        foreach (var spec in ReaderSpecs)
        {
            var item = observations[spec.Name];
            if (item.ReferenceCount == 0)
                continue;
            observed++;
            if (item.DefinitionPresent)
                result.StaticDecode.ReaderDefinitionCount++;
            if (result.Readers.Count >= MaxReaderMetadata)
                continue;
            result.Readers.Add(new(spec.Name, spec.Kind, ByteOrder.Unknown, spec.Bits, spec.Bits / 8,
                item.ReferenceCount, item.DefinitionPresent, true, false, item.FirstRange!.Value, item.DefinitionRange));
        }
        result.StaticDecode.ReaderMetadataCount = result.Readers.Count;

        if (result.Readers.Count > 0)
            AddDiagnostic(result, limits, DiagnosticSeverity.Info, "READER_METADATA_EXTRACTED",
                "Extracted reader identifier type and width hints; implementations are unverified and byte order remains unknown.");
        if (observed > result.Readers.Count)
        {
            result.StaticDecode.Complete = false;
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, "READER_METADATA_LIMIT",
                "Reader metadata tracking limit reached; some declared readers were counted but not retained.");
        }
    }

    private static StringStats InspectString(ReadOnlySpan<char> content)
    {
        if (content.Length == 0)
            return new();
        Span<bool> seen = stackalloc bool[256];
        var distinct = 0;
        var printable = 0;
        var whitespace = 0;
        for (var i = 0; i < content.Length; i++)
        {
            var ch = content[i];
            if (ch <= 255 && !seen[ch])
            {
                seen[ch] = true;
                distinct++;
            }
            if (ch is >= (char)32 and <= (char)126)
                printable++;
            if (char.IsWhiteSpace(ch))
                whitespace++;
        }
        var text = content.ToString();
        var marker = text.IndexOf("LPH", StringComparison.Ordinal);
        var hasMarker = marker >= 0 && marker + 3 < text.Length && text[marker + 3] is >= (char)33 and <= (char)126;
        return new(distinct, (double)printable / content.Length, (double)whitespace / content.Length,
            hasMarker, text.Contains("LPH&", StringComparison.Ordinal));
    }

    private static bool EncodedStringCandidate(int bytes, StringStats stats) =>
        stats.HasLphMarker || bytes >= MinEncodedStringBytes && stats.Distinct >= 12 && stats.PrintableRatio >= 0.90 && stats.WhitespaceRatio <= 0.08;

    private static bool EncodedBlobCandidate(int bytes, StringStats stats) =>
        EncodedStringCandidate(bytes, stats) && (bytes >= MinEncodedBlobBytes || stats.HasLphMarker);

    private static BlobKind BlobKindFor(StringStats stats) =>
        stats.HasLphAmpersandMarker ? BlobKind.LphAmpersand : stats.HasLphMarker ? BlobKind.LphMarker : BlobKind.OpaquePrintable;

    private static int? FindLphMarker(ReadOnlySpan<byte> bytes)
    {
        for (var i = 0; i + 3 < bytes.Length; i++)
            if (bytes[i] == 'L' && bytes[i + 1] == 'P' && bytes[i + 2] == 'H' && bytes[i + 3] is >= 33 and <= 126)
                return i;
        return null;
    }

    private static void InferStages(EnvelopeAnalysis result)
    {
        if (result.Banner.Present)
            result.Stages.Add(new(StageKind.ProtectionBanner, 1.0, "Luraph protection banner declaration.", result.Banner.Range));
        if (result.Wrapper.Kind != WrapperKind.None)
            result.Stages.Add(new(StageKind.WrapperConstruction, 0.98, "Returned table constructs the protected runtime envelope.", result.Wrapper.TableRange));
        if (result.Counts.EncodedBlobCandidateCount > 0)
        {
            var summary = result.ContainerMetrics.ParsedCount > 0
                ? "Strict LPH& framing and bounded container records were decoded; VM semantics remain opaque."
                : result.StaticDecode.CarrierDecodedCount > 0
                    ? "Exact carrier literal bytes were extracted; further transforms remain opaque."
                    : "One or more opaque encoded payload carriers are embedded as string literals.";
            result.Stages.Add(new(StageKind.EncodedPayload, 0.94, summary, result.Blobs.FirstOrDefault()?.Range));
        }
        if (result.Counts.EncodedBlobCandidateCount > 0 && result.Counts.ReaderPrimitiveReferenceCount >= 2)
            result.Stages.Add(new(StageKind.ReaderSetup, 0.88, result.StaticDecode.ReaderMetadataCount > 0
                ? "Reader identifier width hints were extracted; implementations, byte order, and runtime behavior remain unproven."
                : "Byte-reader primitives and an encoded carrier indicate decoder or deserializer setup."));
        if (result.Wrapper.FunctionMemberCount >= 16 && result.Counts.LoopConstructCount >= 8 && result.Counts.IndexedAccessCount >= 16)
            result.Stages.Add(new(StageKind.InterpreterScaffolding, 0.86,
                "Dense function, loop, and indexed-state scaffolding indicates an interpreter-style runtime.", result.Wrapper.TableRange));
        if (result.Wrapper.Kind == WrapperKind.ReturnedTableMethodDispatch && result.Wrapper.ZeroArgumentMethodCall && result.Wrapper.ForwardsVarargs)
            result.Stages.Add(new(StageKind.EntrypointDispatch, 0.99,
                "A zero-argument wrapper method is invoked and its result receives the chunk varargs.", result.Wrapper.InvocationRange));
    }

    private static void ScoreConfidence(EnvelopeAnalysis result)
    {
        AddEvidence(result, result.Banner.Present && result.Banner.ExactProductMarker, "LURAPH_BANNER", 0.42, "Leading comment names the Luraph Obfuscator product.");
        AddEvidence(result, result.VersionSupported, "VERSION_14_7", 0.18, "Banner version is exactly 14.7.");
        AddEvidence(result, result.Wrapper.Kind == WrapperKind.ReturnedTableMethodDispatch && result.Wrapper.ConsumesEntireChunk,
            "TABLE_METHOD_WRAPPER", 0.20, "Chunk is a returned table followed by method dispatch.");
        AddEvidence(result, result.Counts.EncodedBlobCandidateCount > 0, "OPAQUE_BLOB", 0.08, "Envelope contains an opaque encoded string blob.");
        AddEvidence(result, result.Counts.ReaderPrimitiveReferenceCount >= 2, "READER_PRIMITIVES", 0.05, "Envelope references multiple binary reader primitives.");
        AddEvidence(result, result.Wrapper.FunctionMemberCount >= 16, "DENSE_FUNCTION_TABLE", 0.04, "Outer table contains dense function-valued members.");
        AddEvidence(result, result.Wrapper.ForwardsVarargs, "VARARG_DISPATCH", 0.03, "Wrapper dispatch forwards chunk varargs.");

        result.Confidence.Score = Math.Clamp(result.Confidence.Score, 0, 1);
        result.Confidence.Level = result.Confidence.Score switch
        {
            >= 0.80 => ConfidenceLevel.High,
            >= 0.55 => ConfidenceLevel.Medium,
            >= 0.25 => ConfidenceLevel.Low,
            _ => ConfidenceLevel.None,
        };
        result.FamilyDetected = result.Banner.ExactProductMarker && result.Banner.Major.HasValue || result.Confidence.Score >= 0.70;
    }

    private static void AddEvidence(EnvelopeAnalysis result, bool add, string code, double weight, string text)
    {
        if (!add)
            return;
        result.Confidence.Score += weight;
        result.Confidence.Evidence.Add(new(code, weight, text));
    }

    private static void AddCarrierError(EnvelopeAnalysis result, AnalysisLimits limits, LiteralDecodeResult decoded)
    {
        if (decoded.Status == CarrierDecodeStatus.ByteLimitExceeded)
        {
            result.StaticDecode.ByteLimitHitCount++;
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, "CARRIER_DECODE_BYTE_LIMIT",
                "Carrier literal decoding exceeded the aggregate decoded-byte limit; no partial bytes were retained.", decoded.ErrorRange);
        }
        else if (decoded.Status == CarrierDecodeStatus.UnsupportedLiteral)
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, "CARRIER_LITERAL_UNSUPPORTED",
                "An interpolated string carrier was left opaque because its bytes are not provable without expression evaluation.", decoded.ErrorRange);
        else
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, "CARRIER_LITERAL_INVALID",
                "A carrier string contains an invalid or unsupported Luau escape and was left opaque.", decoded.ErrorRange);
    }

    private static void AddContainerDecodeError(EnvelopeAnalysis result, AnalysisLimits limits, ContainerDecodeStatus status)
    {
        var diagnostic = status switch
        {
            ContainerDecodeStatus.InvalidPrefix => ("LPH_AMPERSAND_PREFIX", "An LPH& marker was present, but the decoded literal did not begin with the required four-byte prefix."),
            ContainerDecodeStatus.MisalignedBody => ("LPH_RADIX85_ALIGNMENT", "The LPH& radix-85 body length is not divisible by five."),
            ContainerDecodeStatus.InvalidCharacter => ("LPH_RADIX85_CHARACTER", "The LPH& radix-85 body contains a byte outside ASCII 33 through 117."),
            ContainerDecodeStatus.Radix85Overflow => ("LPH_RADIX85_OVERFLOW", "An LPH& radix-85 group exceeds the unsigned 32-bit output domain."),
            ContainerDecodeStatus.OutputLimitExceeded => ("LPH_CONTAINER_OUTPUT_LIMIT", "LPH& decoding would exceed the aggregate decoded-container byte limit; no partial output was retained."),
            _ => default,
        };
        if (diagnostic != default)
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, diagnostic.Item1, diagnostic.Item2);
    }

    private static void AddContainerParseError(EnvelopeAnalysis result, AnalysisLimits limits, ContainerParseStatus status)
    {
        var diagnostic = status switch
        {
            ContainerParseStatus.Truncated => ("LPH_CONTAINER_TRUNCATED", "The decoded LPH& container ended during a required scalar or record."),
            ContainerParseStatus.UlebOverflow => ("LPH_ULEB_OVERFLOW", "An LPH& ULEB value exceeds the unsigned 64-bit domain."),
            ContainerParseStatus.NonCanonicalUleb => ("LPH_ULEB_NONCANONICAL", "An LPH& ULEB value uses a noncanonical redundant terminal group."),
            ContainerParseStatus.CountUnderflow => ("LPH_COUNT_UNDERFLOW", "A biased LPH& record count is smaller than its proven v14.7 bias."),
            ContainerParseStatus.CountLimitExceeded => ("LPH_CONTAINER_COUNT_LIMIT", "An LPH& constant, prototype, instruction, or descriptor count exceeds its configured limit."),
            ContainerParseStatus.SignedFoldOverflow => ("LPH_SIGNED_FOLD_OVERFLOW", "An instruction word lies outside the wrapper's proven 53-bit signed-fold domain."),
            ContainerParseStatus.TrailerLimitExceeded => ("LPH_TRAILER_LIMIT", "The unread LPH& trailer exceeds the configured preservation limit."),
            _ => default,
        };
        if (diagnostic != default)
            AddDiagnostic(result, limits, DiagnosticSeverity.Warning, diagnostic.Item1, diagnostic.Item2);
    }

    private static void AddDiagnostic(EnvelopeAnalysis result, AnalysisLimits limits, ScanDiagnostic diagnostic)
    {
        if (result.Diagnostics.Count < Math.Max(0, limits.MaxDiagnostics))
            result.Diagnostics.Add(diagnostic);
    }

    private static void AddDiagnostic(EnvelopeAnalysis result, AnalysisLimits limits, DiagnosticSeverity severity, string code, string message, SourceRange? range = null) =>
        AddDiagnostic(result, limits, new(severity, code, message, range));

    private static bool IsAny(Token token, string source, params string[] values) => values.Any(value => LuauLexer.Is(token, source, value));

    private enum BlockKind
    {
        End,
        LoopAwaitingDo,
        Repeat,
    }

    private sealed record ReaderSpec(string Name, ReaderValueKind Kind, int Bits);

    private sealed class ReaderObservation
    {
        public int ReferenceCount { get; set; }
        public bool DefinitionPresent { get; set; }
        public SourceRange? FirstRange { get; set; }
        public SourceRange? DefinitionRange { get; set; }
    }

    private readonly record struct StringStats(
        int Distinct,
        double PrintableRatio,
        double WhitespaceRatio,
        bool HasLphMarker,
        bool HasLphAmpersandMarker);
}
