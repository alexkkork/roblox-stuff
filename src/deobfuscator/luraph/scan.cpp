#include "scan.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <limits>
#include <string_view>
#include <utility>

namespace alex::deobfuscator::luraph
{
namespace
{

constexpr size_t kNoMatch = std::numeric_limits<size_t>::max();
constexpr size_t kMinimumEncodedStringBytes = 64;
constexpr size_t kMinimumEncodedBlobBytes = 1024;
constexpr size_t kMaximumLongBracketEquals = 64;

enum class TokenKind
{
    Identifier,
    Number,
    String,
    Symbol,
};

struct Token
{
    TokenKind kind = TokenKind::Symbol;
    size_t begin = 0;
    size_t end = 0;
    size_t content_begin = 0;
    size_t content_end = 0;
    bool long_string = false;
};

struct LexResult
{
    std::vector<Token> tokens;
    size_t comment_count = 0;
    bool complete = true;
};

bool asciiSpace(char ch)
{
    return std::isspace(static_cast<unsigned char>(ch)) != 0;
}

bool identifierStart(char ch)
{
    return ch == '_' || std::isalpha(static_cast<unsigned char>(ch)) != 0;
}

bool identifierContinue(char ch)
{
    return ch == '_' || std::isalnum(static_cast<unsigned char>(ch)) != 0;
}

char asciiLower(char ch)
{
    if (ch >= 'A' && ch <= 'Z')
        return static_cast<char>(ch - 'A' + 'a');
    return ch;
}

bool equalsIgnoreCase(std::string_view left, std::string_view right)
{
    if (left.size() != right.size())
        return false;
    for (size_t index = 0; index < left.size(); ++index)
        if (asciiLower(left[index]) != asciiLower(right[index]))
            return false;
    return true;
}

size_t findIgnoreCase(std::string_view haystack, std::string_view needle)
{
    if (needle.empty())
        return 0;
    if (needle.size() > haystack.size())
        return std::string_view::npos;
    for (size_t index = 0; index + needle.size() <= haystack.size(); ++index)
        if (equalsIgnoreCase(haystack.substr(index, needle.size()), needle))
            return index;
    return std::string_view::npos;
}

bool tokenIs(const Token& token, std::string_view source, std::string_view value)
{
    return token.end >= token.begin && token.end - token.begin == value.size() && source.substr(token.begin, value.size()) == value;
}

void addDiagnostic(
    EnvelopeAnalysis& result,
    const AnalysisLimits& limits,
    DiagnosticSeverity severity,
    std::string code,
    std::string message,
    std::optional<SourceRange> range = std::nullopt)
{
    if (result.diagnostics.size() >= limits.max_diagnostics)
        return;
    result.diagnostics.push_back(Diagnostic{severity, std::move(code), std::move(message), range});
}

struct LongBracketOpen
{
    size_t equals = 0;
    size_t content_begin = 0;
};

std::optional<LongBracketOpen> longBracketOpen(std::string_view source, size_t position)
{
    if (position >= source.size() || source[position] != '[')
        return std::nullopt;
    size_t cursor = position + 1;
    while (cursor < source.size() && source[cursor] == '=' && cursor - position - 1 <= kMaximumLongBracketEquals)
        ++cursor;
    const size_t equals = cursor - position - 1;
    if (equals > kMaximumLongBracketEquals || cursor >= source.size() || source[cursor] != '[')
        return std::nullopt;
    return LongBracketOpen{equals, cursor + 1};
}

std::optional<SourceRange> longBracketContent(std::string_view source, size_t position)
{
    const auto open = longBracketOpen(source, position);
    if (!open)
        return std::nullopt;

    size_t cursor = open->content_begin;
    while (cursor < source.size())
    {
        if (source[cursor] != ']')
        {
            ++cursor;
            continue;
        }

        size_t close = cursor + 1;
        while (close < source.size() && source[close] == '=')
            ++close;
        if (close - cursor - 1 == open->equals && close < source.size() && source[close] == ']')
            return SourceRange{open->content_begin, cursor};
        cursor = close;
    }
    return std::nullopt;
}

size_t quotedStringEnd(std::string_view source, size_t position)
{
    const char quote = source[position];
    size_t cursor = position + 1;
    while (cursor < source.size())
    {
        if (source[cursor] == quote)
            return cursor + 1;
        if (source[cursor] == '\\')
        {
            ++cursor;
            if (cursor + 1 < source.size() && ((source[cursor] == '\r' && source[cursor + 1] == '\n') ||
                                                  (source[cursor] == '\n' && source[cursor + 1] == '\r')))
                cursor += 2;
            else if (cursor < source.size())
                ++cursor;
            continue;
        }
        ++cursor;
    }
    return source.size();
}

size_t numberEnd(std::string_view source, size_t position)
{
    size_t cursor = position;
    while (cursor < source.size())
    {
        const char ch = source[cursor];
        if (std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_')
        {
            ++cursor;
            continue;
        }
        if (ch == '.')
        {
            if (cursor + 1 < source.size() && source[cursor + 1] == '.')
                break;
            ++cursor;
            continue;
        }
        if ((ch == '+' || ch == '-') && cursor > position)
        {
            const char previous = source[cursor - 1];
            if (previous == 'e' || previous == 'E' || previous == 'p' || previous == 'P')
            {
                ++cursor;
                continue;
            }
        }
        break;
    }
    return cursor;
}

size_t symbolEnd(std::string_view source, size_t position)
{
    constexpr std::array<std::string_view, 17> operators = {
        "...", "//=", "..=", "==", "~=", "<=", ">=", "+=", "-=", "*=", "/=", "%=", "^=", "..", "//", "->", "::",
    };
    for (std::string_view op : operators)
        if (position + op.size() <= source.size() && source.substr(position, op.size()) == op)
            return position + op.size();
    return position + 1;
}

LexResult lex(std::string_view source, EnvelopeAnalysis& result, const AnalysisLimits& limits)
{
    LexResult lexed;
    lexed.tokens.reserve(std::min(limits.max_tokens, source.size() / 3 + 1));

    size_t position = 0;
    if (source.size() >= 3 && static_cast<unsigned char>(source[0]) == 0xef && static_cast<unsigned char>(source[1]) == 0xbb &&
        static_cast<unsigned char>(source[2]) == 0xbf)
        position = 3;
    while (position < source.size())
    {
        if (asciiSpace(source[position]))
        {
            ++position;
            continue;
        }

        if (position + 1 < source.size() && source[position] == '-' && source[position + 1] == '-')
        {
            ++lexed.comment_count;
            position += 2;
            if (const auto open = longBracketOpen(source, position))
            {
                if (const auto content = longBracketContent(source, position))
                    position = content->end + open->equals + 2;
                else
                {
                    lexed.complete = false;
                    addDiagnostic(result, limits, DiagnosticSeverity::Warning, "UNTERMINATED_LONG_COMMENT", "A long-bracket comment is unterminated.",
                        SourceRange{position - 2, source.size()});
                    position = source.size();
                }
            }
            else
            {
                while (position < source.size() && source[position] != '\n' && source[position] != '\r')
                    ++position;
            }
            continue;
        }

        if (lexed.tokens.size() >= limits.max_tokens)
        {
            lexed.complete = false;
            addDiagnostic(result, limits, DiagnosticSeverity::Error, "TOKEN_LIMIT", "Token limit reached before structural scanning completed.");
            break;
        }

        Token token;
        token.begin = position;
        if (source[position] == '\'' || source[position] == '"' || source[position] == '`')
        {
            token.kind = TokenKind::String;
            token.end = quotedStringEnd(source, position);
            token.content_begin = position + 1;
            const bool terminated = token.end > position + 1 && source[token.end - 1] == source[position];
            token.content_end = terminated ? token.end - 1 : token.end;
            if (!terminated)
            {
                lexed.complete = false;
                addDiagnostic(result, limits, DiagnosticSeverity::Warning, "UNTERMINATED_STRING", "A quoted string literal is unterminated.", SourceRange{position, source.size()});
            }
        }
        else if (const auto open = longBracketOpen(source, position))
        {
            token.kind = TokenKind::String;
            token.long_string = true;
            token.content_begin = open->content_begin;
            if (const auto content = longBracketContent(source, position))
            {
                token.content_end = content->end;
                token.end = content->end + open->equals + 2;
            }
            else
            {
                token.content_end = source.size();
                token.end = source.size();
                lexed.complete = false;
                addDiagnostic(result, limits, DiagnosticSeverity::Warning, "UNTERMINATED_LONG_STRING", "A long-bracket string literal is unterminated.",
                    SourceRange{position, source.size()});
            }
        }
        else if (identifierStart(source[position]))
        {
            token.kind = TokenKind::Identifier;
            token.end = position + 1;
            while (token.end < source.size() && identifierContinue(source[token.end]))
                ++token.end;
        }
        else if (std::isdigit(static_cast<unsigned char>(source[position])) != 0 ||
                 (source[position] == '.' && position + 1 < source.size() && std::isdigit(static_cast<unsigned char>(source[position + 1])) != 0))
        {
            token.kind = TokenKind::Number;
            token.end = numberEnd(source, position);
        }
        else
        {
            token.kind = TokenKind::Symbol;
            token.end = symbolEnd(source, position);
        }

        lexed.tokens.push_back(token);
        position = token.end;
    }
    return lexed;
}

BannerInfo inspectBanner(std::string_view source)
{
    BannerInfo banner;
    size_t begin = 0;
    if (source.size() >= 3 && static_cast<unsigned char>(source[0]) == 0xef && static_cast<unsigned char>(source[1]) == 0xbb &&
        static_cast<unsigned char>(source[2]) == 0xbf)
        begin = 3;
    while (begin < source.size() && (source[begin] == ' ' || source[begin] == '\t'))
        ++begin;
    if (begin + 2 > source.size() || source.substr(begin, 2) != "--")
        return banner;

    size_t end = begin + 2;
    while (end < source.size() && source[end] != '\n' && source[end] != '\r')
        ++end;
    const std::string_view comment = source.substr(begin + 2, end - begin - 2);
    constexpr std::string_view product = "Luraph Obfuscator";
    const size_t productPosition = findIgnoreCase(comment, product);
    if (productPosition == std::string_view::npos)
        return banner;

    banner.present = true;
    banner.product = std::string(product);
    banner.range = SourceRange{begin, end};
    banner.official_url_marker = findIgnoreCase(comment, "https://lura.ph/") != std::string_view::npos;
    banner.exact_product_marker = findIgnoreCase(comment, "protected using Luraph Obfuscator") != std::string_view::npos;

    size_t cursor = productPosition + product.size();
    while (cursor < comment.size() && asciiSpace(comment[cursor]))
        ++cursor;
    if (cursor < comment.size() && (comment[cursor] == 'v' || comment[cursor] == 'V'))
        ++cursor;
    const size_t versionBegin = cursor;
    while (cursor < comment.size() && (std::isdigit(static_cast<unsigned char>(comment[cursor])) != 0 || comment[cursor] == '.'))
        ++cursor;
    if (cursor > versionBegin && cursor - versionBegin <= 32)
        banner.version = std::string(comment.substr(versionBegin, cursor - versionBegin));

    std::array<std::optional<unsigned int>*, 3> components = {&banner.major, &banner.minor, &banner.patch};
    size_t componentBegin = 0;
    for (size_t component = 0; component < components.size() && componentBegin < banner.version.size(); ++component)
    {
        size_t componentEnd = banner.version.find('.', componentBegin);
        if (componentEnd == std::string::npos)
            componentEnd = banner.version.size();
        if (componentEnd == componentBegin || componentEnd - componentBegin > 9)
            break;
        unsigned int value = 0;
        bool valid = true;
        for (size_t index = componentBegin; index < componentEnd; ++index)
        {
            if (banner.version[index] < '0' || banner.version[index] > '9' || value > 100000000)
            {
                valid = false;
                break;
            }
            value = value * 10 + static_cast<unsigned int>(banner.version[index] - '0');
        }
        if (!valid)
            break;
        *components[component] = value;
        componentBegin = componentEnd + 1;
    }
    return banner;
}

LuaAuthLauncherInfo inspectLuaAuthLauncher(std::string_view source)
{
    LuaAuthLauncherInfo launcher;
    size_t cursor = 0;
    if (source.size() >= 3 && static_cast<unsigned char>(source[0]) == 0xef && static_cast<unsigned char>(source[1]) == 0xbb &&
        static_cast<unsigned char>(source[2]) == 0xbf)
        cursor = 3;

    const auto skipSpace = [&]() {
        while (cursor < source.size() && asciiSpace(source[cursor]))
            ++cursor;
    };
    const auto consume = [&](std::string_view value) {
        if (cursor + value.size() > source.size() || source.substr(cursor, value.size()) != value)
            return false;
        cursor += value.size();
        return true;
    };

    const size_t launcherBegin = cursor;
    skipSpace();
    if (!consume("la_code"))
        return launcher;
    skipSpace();
    if (!consume("="))
        return launcher;
    skipSpace();
    const size_t codeBegin = cursor;
    while (cursor < source.size() && std::isdigit(static_cast<unsigned char>(source[cursor])) != 0)
        ++cursor;
    launcher.code_digit_count = cursor - codeBegin;
    if (launcher.code_digit_count == 0 || launcher.code_digit_count > 20)
        return LuaAuthLauncherInfo{};
    skipSpace();
    if (!consume(";"))
        return LuaAuthLauncherInfo{};
    skipSpace();
    if (!consume("la_script_id"))
        return LuaAuthLauncherInfo{};
    skipSpace();
    if (!consume("="))
        return LuaAuthLauncherInfo{};
    skipSpace();
    if (cursor >= source.size() || (source[cursor] != '\'' && source[cursor] != '"'))
        return LuaAuthLauncherInfo{};
    const char quote = source[cursor++];
    const size_t idBegin = cursor;
    while (cursor < source.size() && source[cursor] != quote)
    {
        const unsigned char byte = static_cast<unsigned char>(source[cursor]);
        if (!(std::isalnum(byte) != 0 || byte == '_' || byte == '-'))
            return LuaAuthLauncherInfo{};
        ++cursor;
    }
    launcher.script_id_byte_count = cursor - idBegin;
    if (launcher.script_id_byte_count == 0 || launcher.script_id_byte_count > 128 || cursor >= source.size())
        return LuaAuthLauncherInfo{};
    ++cursor;
    skipSpace();
    if (cursor < source.size() && source[cursor] == ';')
        ++cursor;
    skipSpace();

    if (cursor + 4 > source.size() || source.substr(cursor, 4) != "--[[")
        return LuaAuthLauncherInfo{};
    const size_t commentOpen = cursor + 2;
    const std::optional<LongBracketOpen> open = longBracketOpen(source, commentOpen);
    const std::optional<SourceRange> content = longBracketContent(source, commentOpen);
    if (!open || !content)
        return LuaAuthLauncherInfo{};
    const std::string_view comment = source.substr(content->begin, content->size());
    launcher.official_url_marker = findIgnoreCase(comment, "https://luaauth.com") != std::string_view::npos;
    if (!launcher.official_url_marker || findIgnoreCase(comment, "LuaAuth") == std::string_view::npos)
        return LuaAuthLauncherInfo{};
    cursor = content->end + open->equals + 2;
    if (cursor < source.size() && source[cursor] == '\r')
        cursor += cursor + 1 < source.size() && source[cursor + 1] == '\n' ? 2 : 1;
    else if (cursor < source.size() && source[cursor] == '\n')
        cursor += cursor + 1 < source.size() && source[cursor + 1] == '\r' ? 2 : 1;
    const size_t bodyBegin = cursor;
    size_t bodyToken = cursor;
    while (bodyToken < source.size() && asciiSpace(source[bodyToken]))
        ++bodyToken;
    if (bodyToken + 6 > source.size() || source.substr(bodyToken, 6) != "return" ||
        (bodyToken + 6 < source.size() && identifierContinue(source[bodyToken + 6])))
        return LuaAuthLauncherInfo{};

    launcher.present = true;
    launcher.exact_assignment_shape = true;
    launcher.metadata_removed_from_body = true;
    launcher.range = SourceRange{launcherBegin, bodyBegin};
    launcher.protected_body_range = SourceRange{bodyBegin, source.size()};
    return launcher;
}

bool matchingDelimiter(std::string_view open, std::string_view close)
{
    return (open == "(" && close == ")") || (open == "{" && close == "}") || (open == "[" && close == "]");
}

std::vector<size_t> balanceDelimiters(
    std::string_view source,
    const std::vector<Token>& tokens,
    EnvelopeAnalysis& result,
    const AnalysisLimits& limits,
    bool& balanced)
{
    std::vector<size_t> matches(tokens.size(), kNoMatch);
    std::vector<size_t> stack;
    stack.reserve(std::min(limits.max_nesting, tokens.size()));
    balanced = true;

    for (size_t index = 0; index < tokens.size(); ++index)
    {
        const Token& token = tokens[index];
        if (token.kind != TokenKind::Symbol || token.end - token.begin != 1)
            continue;
        const std::string_view value = source.substr(token.begin, 1);
        if (value == "(" || value == "{" || value == "[")
        {
            if (stack.size() >= limits.max_nesting)
            {
                balanced = false;
                addDiagnostic(result, limits, DiagnosticSeverity::Error, "NESTING_LIMIT", "Delimiter nesting limit reached.", SourceRange{token.begin, token.end});
                break;
            }
            stack.push_back(index);
        }
        else if (value == ")" || value == "}" || value == "]")
        {
            if (stack.empty() || !matchingDelimiter(source.substr(tokens[stack.back()].begin, 1), value))
            {
                balanced = false;
                addDiagnostic(result, limits, DiagnosticSeverity::Warning, "UNMATCHED_DELIMITER", "An unmatched closing delimiter was found.", SourceRange{token.begin, token.end});
                continue;
            }
            const size_t open = stack.back();
            stack.pop_back();
            matches[open] = index;
            matches[index] = open;
        }
    }

    if (!stack.empty())
    {
        balanced = false;
        const Token& token = tokens[stack.back()];
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "UNCLOSED_DELIMITER", "An opening delimiter was not closed.", SourceRange{token.begin, token.end});
    }
    return matches;
}

enum class BlockKind
{
    End,
    LoopAwaitingDo,
    Repeat,
};

bool fieldIsFunction(std::string_view source, const std::vector<Token>& tokens, size_t begin, size_t end)
{
    if (begin >= end)
        return false;
    if (tokenIs(tokens[begin], source, "function"))
        return true;

    std::vector<char> delimiters;
    for (size_t index = begin; index < end; ++index)
    {
        const Token& token = tokens[index];
        if (token.kind != TokenKind::Symbol)
            continue;
        if (tokenIs(token, source, "(") || tokenIs(token, source, "{") || tokenIs(token, source, "["))
        {
            delimiters.push_back(source[token.begin]);
            continue;
        }
        if (tokenIs(token, source, ")") || tokenIs(token, source, "}") || tokenIs(token, source, "]"))
        {
            if (!delimiters.empty())
                delimiters.pop_back();
            continue;
        }
        if (delimiters.empty() && tokenIs(token, source, "=") && index + 1 < end && tokenIs(tokens[index + 1], source, "function"))
            return true;
    }
    return false;
}

std::pair<size_t, size_t> inspectTableFields(
    std::string_view source,
    const std::vector<Token>& tokens,
    size_t openIndex,
    size_t closeIndex)
{
    // Commas delimit fields only outside nested punctuation and Lua block bodies.
    size_t fieldCount = 0;
    size_t functionCount = 0;
    size_t fieldBegin = openIndex + 1;
    std::vector<char> delimiters;
    std::vector<BlockKind> blocks;

    const auto finishField = [&](size_t fieldEnd) {
        if (fieldBegin >= fieldEnd)
            return;
        ++fieldCount;
        if (fieldIsFunction(source, tokens, fieldBegin, fieldEnd))
            ++functionCount;
    };

    for (size_t index = openIndex + 1; index < closeIndex; ++index)
    {
        const Token& token = tokens[index];
        if (token.kind == TokenKind::Symbol)
        {
            if (tokenIs(token, source, "(") || tokenIs(token, source, "{") || tokenIs(token, source, "["))
            {
                delimiters.push_back(source[token.begin]);
                continue;
            }
            if (tokenIs(token, source, ")") || tokenIs(token, source, "}") || tokenIs(token, source, "]"))
            {
                if (!delimiters.empty())
                    delimiters.pop_back();
                continue;
            }
            if (delimiters.empty() && blocks.empty() && (tokenIs(token, source, ",") || tokenIs(token, source, ";")))
            {
                finishField(index);
                fieldBegin = index + 1;
            }
            continue;
        }

        if (token.kind != TokenKind::Identifier)
            continue;
        if (tokenIs(token, source, "function") || tokenIs(token, source, "if") || tokenIs(token, source, "do"))
        {
            if (tokenIs(token, source, "do") && !blocks.empty() && blocks.back() == BlockKind::LoopAwaitingDo)
                blocks.back() = BlockKind::End;
            else
                blocks.push_back(BlockKind::End);
        }
        else if (tokenIs(token, source, "while") || tokenIs(token, source, "for"))
            blocks.push_back(BlockKind::LoopAwaitingDo);
        else if (tokenIs(token, source, "repeat"))
            blocks.push_back(BlockKind::Repeat);
        else if (tokenIs(token, source, "end"))
        {
            if (!blocks.empty() && blocks.back() != BlockKind::Repeat)
                blocks.pop_back();
        }
        else if (tokenIs(token, source, "until"))
        {
            if (!blocks.empty() && blocks.back() == BlockKind::Repeat)
                blocks.pop_back();
        }
    }
    finishField(closeIndex);
    return {fieldCount, functionCount};
}

WrapperShape inspectWrapper(
    std::string_view source,
    const std::vector<Token>& tokens,
    const std::vector<size_t>& matches)
{
    WrapperShape wrapper;
    if (tokens.empty() || !tokenIs(tokens[0], source, "return"))
        return wrapper;
    wrapper.top_level_return = true;

    size_t index = 1;
    size_t parenthesisOpen = kNoMatch;
    if (index < tokens.size() && tokenIs(tokens[index], source, "("))
    {
        wrapper.parenthesized_table = true;
        parenthesisOpen = index++;
    }
    if (index >= tokens.size() || !tokenIs(tokens[index], source, "{") || matches[index] == kNoMatch)
        return wrapper;

    const size_t tableOpen = index;
    const size_t tableClose = matches[index];
    wrapper.kind = WrapperKind::ReturnedTable;
    wrapper.balanced_table = true;
    wrapper.table_range = SourceRange{tokens[tableOpen].begin, tokens[tableClose].end};
    const auto [fields, functions] = inspectTableFields(source, tokens, tableOpen, tableClose);
    wrapper.table_field_count = fields;
    wrapper.function_member_count = functions;

    index = tableClose + 1;
    if (parenthesisOpen != kNoMatch)
    {
        if (matches[parenthesisOpen] == kNoMatch || matches[parenthesisOpen] != index)
            return wrapper;
        ++index;
    }

    const size_t invocationBegin = index < tokens.size() ? tokens[index].begin : tokens[tableOpen].begin;
    if (index + 3 >= tokens.size() || !tokenIs(tokens[index], source, ":") || tokens[index + 1].kind != TokenKind::Identifier ||
        !tokenIs(tokens[index + 2], source, "(") || matches[index + 2] == kNoMatch)
        return wrapper;

    const Token& method = tokens[index + 1];
    if (method.end - method.begin <= 64)
        wrapper.method_name = std::string(source.substr(method.begin, method.end - method.begin));
    const size_t firstCallClose = matches[index + 2];
    wrapper.zero_argument_method_call = firstCallClose == index + 3;
    index = firstCallClose + 1;
    if (index >= tokens.size() || !tokenIs(tokens[index], source, "(") || matches[index] == kNoMatch)
        return wrapper;

    const size_t dispatchClose = matches[index];
    wrapper.forwards_varargs = dispatchClose == index + 2 && tokenIs(tokens[index + 1], source, "...");
    index = dispatchClose + 1;
    while (index < tokens.size() && tokenIs(tokens[index], source, ";"))
        ++index;
    wrapper.consumes_entire_chunk = index == tokens.size();
    wrapper.invocation_range = SourceRange{invocationBegin, tokens[dispatchClose].end};
    wrapper.kind = WrapperKind::ReturnedTableMethodDispatch;
    return wrapper;
}

struct StringStats
{
    size_t distinct = 0;
    double printable_ratio = 0.0;
    double whitespace_ratio = 0.0;
    bool has_lph_marker = false;
    bool has_lph_ampersand_marker = false;
    bool has_lph_dollar_marker = false;
};

StringStats inspectString(std::string_view content)
{
    StringStats stats;
    if (content.empty())
        return stats;

    std::array<bool, 256> seen{};
    size_t printable = 0;
    size_t whitespace = 0;
    for (unsigned char ch : content)
    {
        if (!seen[ch])
        {
            seen[ch] = true;
            ++stats.distinct;
        }
        if (ch >= 32 && ch <= 126)
            ++printable;
        if (asciiSpace(static_cast<char>(ch)))
            ++whitespace;
    }
    stats.printable_ratio = static_cast<double>(printable) / static_cast<double>(content.size());
    stats.whitespace_ratio = static_cast<double>(whitespace) / static_cast<double>(content.size());
    stats.has_lph_ampersand_marker = content.find("LPH&") != std::string_view::npos;
    stats.has_lph_dollar_marker = content.find("LPH$") != std::string_view::npos;
    const size_t marker = content.find("LPH");
    stats.has_lph_marker = marker != std::string_view::npos && marker + 3 < content.size() &&
                           static_cast<unsigned char>(content[marker + 3]) >= 33 &&
                           static_cast<unsigned char>(content[marker + 3]) <= 126;
    return stats;
}

BlobKind blobKind(const StringStats& stats)
{
    if (stats.has_lph_dollar_marker)
        return BlobKind::LphDollar;
    if (stats.has_lph_ampersand_marker)
        return BlobKind::LphAmpersand;
    return stats.has_lph_marker ? BlobKind::LphMarker : BlobKind::OpaquePrintable;
}

bool encodedStringCandidate(size_t sourceBytes, const StringStats& stats)
{
    if (stats.has_lph_marker)
        return true;
    return sourceBytes >= kMinimumEncodedStringBytes && stats.distinct >= 12 && stats.printable_ratio >= 0.90 && stats.whitespace_ratio <= 0.08;
}

bool encodedBlobCandidate(size_t sourceBytes, const StringStats& stats)
{
    return encodedStringCandidate(sourceBytes, stats) && (sourceBytes >= kMinimumEncodedBlobBytes || stats.has_lph_marker);
}

bool readerPrimitive(std::string_view identifier)
{
    constexpr std::array<std::string_view, 13> names = {
        "readu8", "readu16", "readu32", "readi8", "readi16", "readi32", "readf32", "readf64", "readstring", "byte", "char", "unpack", "bit32",
    };
    return std::find(names.begin(), names.end(), identifier) != names.end();
}

struct ReaderSpec
{
    std::string_view name;
    ReaderValueKind value_kind;
    size_t bit_width;
};

constexpr std::array<ReaderSpec, 9> kReaderSpecs = {{
    {"readu8", ReaderValueKind::UnsignedInteger, 8},
    {"readu16", ReaderValueKind::UnsignedInteger, 16},
    {"readu32", ReaderValueKind::UnsignedInteger, 32},
    {"readi8", ReaderValueKind::SignedInteger, 8},
    {"readi16", ReaderValueKind::SignedInteger, 16},
    {"readi32", ReaderValueKind::SignedInteger, 32},
    {"readf32", ReaderValueKind::FloatingPoint, 32},
    {"readf64", ReaderValueKind::FloatingPoint, 64},
    {"readstring", ReaderValueKind::ByteString, 0},
}};

struct ReaderObservation
{
    size_t reference_count = 0;
    bool definition_present = false;
    SourceRange first_range;
    std::optional<SourceRange> definition_range;
};

const ReaderSpec* findReaderSpec(std::string_view name)
{
    const auto found = std::find_if(kReaderSpecs.begin(), kReaderSpecs.end(), [name](const ReaderSpec& spec) { return spec.name == name; });
    return found == kReaderSpecs.end() ? nullptr : &*found;
}

void inspectReaderMetadata(
    std::string_view source,
    const std::vector<Token>& tokens,
    EnvelopeAnalysis& result,
    const AnalysisLimits& limits)
{
    std::array<ReaderObservation, kReaderSpecs.size()> observations{};
    for (size_t index = 0; index < tokens.size(); ++index)
    {
        const Token& token = tokens[index];
        if (token.kind != TokenKind::Identifier)
            continue;

        const ReaderSpec* spec = findReaderSpec(source.substr(token.begin, token.end - token.begin));
        if (!spec)
            continue;
        const size_t specIndex = static_cast<size_t>(spec - kReaderSpecs.data());
        ReaderObservation& observation = observations[specIndex];
        if (observation.reference_count == 0)
            observation.first_range = SourceRange{token.begin, token.end};
        ++observation.reference_count;
        ++result.static_decode.reader_reference_count;

        std::optional<SourceRange> definitionRange;
        if (index + 2 < tokens.size() && tokenIs(tokens[index + 1], source, "=") && tokenIs(tokens[index + 2], source, "function"))
            definitionRange = SourceRange{token.begin, tokens[index + 2].end};
        else if (index > 0 && tokenIs(tokens[index - 1], source, "function"))
            definitionRange = SourceRange{tokens[index - 1].begin, token.end};
        if (definitionRange)
        {
            observation.definition_present = true;
            if (!observation.definition_range)
                observation.definition_range = definitionRange;
        }
    }

    size_t observedReaders = 0;
    for (size_t index = 0; index < kReaderSpecs.size(); ++index)
    {
        const ReaderObservation& observation = observations[index];
        if (observation.reference_count == 0)
            continue;
        ++observedReaders;
        if (observation.definition_present)
            ++result.static_decode.reader_definition_count;
        if (result.readers.size() >= limits.max_tracked_reader_metadata)
            continue;

        const ReaderSpec& spec = kReaderSpecs[index];
        result.readers.push_back(ReaderMetadata{
            std::string(spec.name),
            spec.value_kind,
            ByteOrder::Unknown,
            spec.bit_width,
            spec.bit_width / 8,
            observation.reference_count,
            observation.definition_present,
            true,
            false,
            observation.first_range,
            observation.definition_range,
            ReaderEvidenceKind::IdentifierHint,
            std::nullopt,
            false,
            0,
        });
    }
    result.static_decode.reader_metadata_count = result.readers.size();

    if (!result.readers.empty())
        addDiagnostic(result, limits, DiagnosticSeverity::Info, "READER_METADATA_EXTRACTED",
            "Extracted reader identifier type and width hints; implementations are unverified and byte order remains unknown.");
    if (observedReaders > result.readers.size())
    {
        result.static_decode.complete = false;
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "READER_METADATA_LIMIT",
            "Reader metadata tracking limit reached; some declared readers were counted but not retained.");
    }
}

struct LiteralDecodeResult
{
    CarrierDecodeStatus status = CarrierDecodeStatus::NotAttempted;
    std::optional<SourceRange> error_range;
    std::vector<unsigned char> bytes;
};

int hexDigit(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

bool appendDecodedBytes(
    LiteralDecodeResult& decoded,
    const unsigned char* bytes,
    size_t count,
    size_t maxBytes,
    SourceRange sourceRange)
{
    if (decoded.bytes.size() > maxBytes || count > maxBytes - decoded.bytes.size())
    {
        decoded.status = CarrierDecodeStatus::ByteLimitExceeded;
        decoded.error_range = sourceRange;
        decoded.bytes.clear();
        return false;
    }
    decoded.bytes.insert(decoded.bytes.end(), bytes, bytes + count);
    return true;
}

bool appendDecodedByte(LiteralDecodeResult& decoded, unsigned char byte, size_t maxBytes, SourceRange sourceRange)
{
    return appendDecodedBytes(decoded, &byte, 1, maxBytes, sourceRange);
}

LiteralDecodeResult decodeLongBracketLiteral(std::string_view source, const Token& token, size_t maxBytes)
{
    LiteralDecodeResult decoded;
    decoded.status = CarrierDecodeStatus::DecodedLiteral;
    size_t begin = token.content_begin;
    if (begin < token.content_end && (source[begin] == '\n' || source[begin] == '\r'))
    {
        const char first = source[begin++];
        if (begin < token.content_end && ((first == '\r' && source[begin] == '\n') || (first == '\n' && source[begin] == '\r')))
            ++begin;
    }

    decoded.bytes.reserve(std::min(maxBytes, token.content_end - begin));
    size_t cursor = begin;
    while (cursor < token.content_end)
    {
        const size_t characterBegin = cursor;
        unsigned char byte = static_cast<unsigned char>(source[cursor++]);
        if (byte == '\n' || byte == '\r')
        {
            if (cursor < token.content_end && ((byte == '\r' && source[cursor] == '\n') || (byte == '\n' && source[cursor] == '\r')))
                ++cursor;
            byte = '\n';
        }
        if (!appendDecodedByte(decoded, byte, maxBytes, SourceRange{characterBegin, cursor}))
            return decoded;
    }
    return decoded;
}

LiteralDecodeResult decodeQuotedLiteral(std::string_view source, const Token& token, size_t maxBytes)
{
    LiteralDecodeResult decoded;
    decoded.status = CarrierDecodeStatus::DecodedLiteral;
    const char quote = source[token.begin];
    if (quote == '`')
    {
        decoded.status = CarrierDecodeStatus::UnsupportedLiteral;
        decoded.error_range = SourceRange{token.begin, token.end};
        return decoded;
    }
    if (token.end <= token.begin + 1 || token.end > source.size() || source[token.end - 1] != quote)
    {
        decoded.status = CarrierDecodeStatus::InvalidLiteral;
        decoded.error_range = SourceRange{token.begin, token.end};
        return decoded;
    }

    decoded.bytes.reserve(std::min(maxBytes, token.content_end - token.content_begin));
    size_t cursor = token.content_begin;
    while (cursor < token.content_end)
    {
        const size_t characterBegin = cursor;
        const unsigned char byte = static_cast<unsigned char>(source[cursor++]);
        if (byte != '\\')
        {
            if (byte == '\n' || byte == '\r')
            {
                decoded.status = CarrierDecodeStatus::InvalidLiteral;
                decoded.error_range = SourceRange{characterBegin, cursor};
                decoded.bytes.clear();
                return decoded;
            }
            if (!appendDecodedByte(decoded, byte, maxBytes, SourceRange{characterBegin, cursor}))
                return decoded;
            continue;
        }

        if (cursor >= token.content_end)
        {
            decoded.status = CarrierDecodeStatus::InvalidLiteral;
            decoded.error_range = SourceRange{characterBegin, cursor};
            decoded.bytes.clear();
            return decoded;
        }

        const char escape = source[cursor++];
        unsigned char escapedByte = 0;
        bool simpleEscape = true;
        switch (escape)
        {
        case 'a': escapedByte = '\a'; break;
        case 'b': escapedByte = '\b'; break;
        case 'f': escapedByte = '\f'; break;
        case 'n': escapedByte = '\n'; break;
        case 'r': escapedByte = '\r'; break;
        case 't': escapedByte = '\t'; break;
        case 'v': escapedByte = '\v'; break;
        case '\\': escapedByte = '\\'; break;
        case '\'': escapedByte = '\''; break;
        case '"': escapedByte = '"'; break;
        case '\n':
            if (cursor < token.content_end && source[cursor] == '\r')
                ++cursor;
            escapedByte = '\n';
            break;
        case '\r':
            if (cursor < token.content_end && source[cursor] == '\n')
                ++cursor;
            escapedByte = '\n';
            break;
        default:
            simpleEscape = false;
            break;
        }
        if (simpleEscape)
        {
            if (!appendDecodedByte(decoded, escapedByte, maxBytes, SourceRange{characterBegin, cursor}))
                return decoded;
            continue;
        }

        if (escape == 'z')
        {
            while (cursor < token.content_end && asciiSpace(source[cursor]))
                ++cursor;
            continue;
        }

        if (escape >= '0' && escape <= '9')
        {
            unsigned int value = static_cast<unsigned int>(escape - '0');
            size_t digits = 1;
            while (digits < 3 && cursor < token.content_end && source[cursor] >= '0' && source[cursor] <= '9')
            {
                value = value * 10 + static_cast<unsigned int>(source[cursor++] - '0');
                ++digits;
            }
            if (value > 255)
            {
                decoded.status = CarrierDecodeStatus::InvalidLiteral;
                decoded.error_range = SourceRange{characterBegin, cursor};
                decoded.bytes.clear();
                return decoded;
            }
            if (!appendDecodedByte(decoded, static_cast<unsigned char>(value), maxBytes, SourceRange{characterBegin, cursor}))
                return decoded;
            continue;
        }

        if (escape == 'x')
        {
            if (cursor + 2 > token.content_end || hexDigit(source[cursor]) < 0 || hexDigit(source[cursor + 1]) < 0)
            {
                decoded.status = CarrierDecodeStatus::InvalidLiteral;
                decoded.error_range = SourceRange{characterBegin, std::min(token.content_end, cursor + 2)};
                decoded.bytes.clear();
                return decoded;
            }
            const unsigned char value = static_cast<unsigned char>(hexDigit(source[cursor]) * 16 + hexDigit(source[cursor + 1]));
            cursor += 2;
            if (!appendDecodedByte(decoded, value, maxBytes, SourceRange{characterBegin, cursor}))
                return decoded;
            continue;
        }

        if (escape == 'u' && cursor < token.content_end && source[cursor] == '{')
        {
            ++cursor;
            const size_t digitsBegin = cursor;
            unsigned int codepoint = 0;
            bool overflow = false;
            while (cursor < token.content_end && source[cursor] != '}')
            {
                const int digit = hexDigit(source[cursor]);
                if (digit < 0 || codepoint > (0x10ffffu - static_cast<unsigned int>(digit)) / 16u)
                {
                    overflow = true;
                    break;
                }
                codepoint = codepoint * 16u + static_cast<unsigned int>(digit);
                ++cursor;
            }
            if (overflow || cursor == digitsBegin || cursor >= token.content_end || source[cursor] != '}' || codepoint > 0x10ffffu ||
                (codepoint >= 0xd800u && codepoint <= 0xdfffu))
            {
                decoded.status = CarrierDecodeStatus::InvalidLiteral;
                decoded.error_range = SourceRange{characterBegin, std::min(token.content_end, cursor + 1)};
                decoded.bytes.clear();
                return decoded;
            }
            ++cursor;

            std::array<unsigned char, 4> utf8{};
            size_t utf8Bytes = 0;
            if (codepoint <= 0x7fu)
                utf8[utf8Bytes++] = static_cast<unsigned char>(codepoint);
            else if (codepoint <= 0x7ffu)
            {
                utf8[utf8Bytes++] = static_cast<unsigned char>(0xc0u | (codepoint >> 6u));
                utf8[utf8Bytes++] = static_cast<unsigned char>(0x80u | (codepoint & 0x3fu));
            }
            else if (codepoint <= 0xffffu)
            {
                utf8[utf8Bytes++] = static_cast<unsigned char>(0xe0u | (codepoint >> 12u));
                utf8[utf8Bytes++] = static_cast<unsigned char>(0x80u | ((codepoint >> 6u) & 0x3fu));
                utf8[utf8Bytes++] = static_cast<unsigned char>(0x80u | (codepoint & 0x3fu));
            }
            else
            {
                utf8[utf8Bytes++] = static_cast<unsigned char>(0xf0u | (codepoint >> 18u));
                utf8[utf8Bytes++] = static_cast<unsigned char>(0x80u | ((codepoint >> 12u) & 0x3fu));
                utf8[utf8Bytes++] = static_cast<unsigned char>(0x80u | ((codepoint >> 6u) & 0x3fu));
                utf8[utf8Bytes++] = static_cast<unsigned char>(0x80u | (codepoint & 0x3fu));
            }
            if (!appendDecodedBytes(decoded, utf8.data(), utf8Bytes, maxBytes, SourceRange{characterBegin, cursor}))
                return decoded;
            continue;
        }

        decoded.status = CarrierDecodeStatus::InvalidLiteral;
        decoded.error_range = SourceRange{characterBegin, cursor};
        decoded.bytes.clear();
        return decoded;
    }
    return decoded;
}

std::optional<uint64_t> unsignedIntegerToken(std::string_view source, const Token& token)
{
    if (token.kind != TokenKind::Number)
        return std::nullopt;
    const std::string_view text = source.substr(token.begin, token.end - token.begin);
    size_t cursor = 0;
    unsigned int base = 10;
    if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
    {
        base = 16;
        cursor = 2;
    }
    else if (text.size() >= 2 && text[0] == '0' && (text[1] == 'b' || text[1] == 'B'))
    {
        base = 2;
        cursor = 2;
    }

    uint64_t value = 0;
    bool sawDigit = false;
    for (; cursor < text.size(); ++cursor)
    {
        const char ch = text[cursor];
        if (ch == '_')
            continue;
        unsigned int digit = 0;
        if (ch >= '0' && ch <= '9')
            digit = static_cast<unsigned int>(ch - '0');
        else if (ch >= 'a' && ch <= 'f')
            digit = static_cast<unsigned int>(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F')
            digit = static_cast<unsigned int>(ch - 'A' + 10);
        else
            return std::nullopt;
        if (digit >= base || value > (std::numeric_limits<uint64_t>::max() - digit) / base)
            return std::nullopt;
        value = value * base + digit;
        sawDigit = true;
    }
    return sawDigit ? std::optional<uint64_t>(value) : std::nullopt;
}

std::optional<std::string> decodedIdentifierLiteral(std::string_view source, const Token& token)
{
    const LiteralDecodeResult strict = decodeQuotedLiteral(source, token, 32);
    if (strict.status == CarrierDecodeStatus::DecodedLiteral)
        return std::string(strict.bytes.begin(), strict.bytes.end());
    if (token.long_string || token.content_end < token.content_begin)
        return std::nullopt;

    // Luau accepts escaped identifier characters in protector-generated string
    // keys. Keep this permissive path private to short reader-property aliases;
    // carrier extraction continues to use the strict literal decoder.
    std::string value;
    for (size_t cursor = token.content_begin; cursor < token.content_end;)
    {
        char ch = source[cursor++];
        if (ch != '\\')
        {
            if (!identifierContinue(ch))
                return std::nullopt;
            value.push_back(ch);
            continue;
        }
        if (cursor >= token.content_end)
            return std::nullopt;
        ch = source[cursor++];
        if (ch == 'x')
        {
            if (cursor + 2 > token.content_end || hexDigit(source[cursor]) < 0 || hexDigit(source[cursor + 1]) < 0)
                return std::nullopt;
            const char decoded = static_cast<char>(hexDigit(source[cursor]) * 16 + hexDigit(source[cursor + 1]));
            cursor += 2;
            if (!identifierContinue(decoded))
                return std::nullopt;
            value.push_back(decoded);
            continue;
        }
        if (ch >= '0' && ch <= '9')
        {
            unsigned int decoded = static_cast<unsigned int>(ch - '0');
            size_t digits = 1;
            while (digits < 3 && cursor < token.content_end && source[cursor] >= '0' && source[cursor] <= '9')
            {
                decoded = decoded * 10 + static_cast<unsigned int>(source[cursor++] - '0');
                ++digits;
            }
            if (decoded > 127 || !identifierContinue(static_cast<char>(decoded)))
                return std::nullopt;
            value.push_back(static_cast<char>(decoded));
            continue;
        }
        if (!identifierContinue(ch))
            return std::nullopt;
        value.push_back(ch);
    }
    return value.empty() ? std::nullopt : std::optional<std::string>(std::move(value));
}

struct FunctionTokenRange
{
    size_t begin = 0;
    size_t end = 0;
};

std::vector<FunctionTokenRange> functionTokenRanges(std::string_view source, const std::vector<Token>& tokens)
{
    struct KeywordBlock
    {
        BlockKind kind = BlockKind::End;
        size_t begin = 0;
        bool function = false;
    };

    std::vector<KeywordBlock> blocks;
    std::vector<FunctionTokenRange> ranges;
    for (size_t index = 0; index < tokens.size(); ++index)
    {
        const Token& token = tokens[index];
        if (token.kind != TokenKind::Identifier)
            continue;
        if (tokenIs(token, source, "function"))
            blocks.push_back(KeywordBlock{BlockKind::End, index, true});
        else if (tokenIs(token, source, "if"))
            blocks.push_back(KeywordBlock{BlockKind::End, index, false});
        else if (tokenIs(token, source, "while") || tokenIs(token, source, "for"))
            blocks.push_back(KeywordBlock{BlockKind::LoopAwaitingDo, index, false});
        else if (tokenIs(token, source, "do"))
        {
            if (!blocks.empty() && blocks.back().kind == BlockKind::LoopAwaitingDo)
                blocks.back().kind = BlockKind::End;
            else
                blocks.push_back(KeywordBlock{BlockKind::End, index, false});
        }
        else if (tokenIs(token, source, "repeat"))
            blocks.push_back(KeywordBlock{BlockKind::Repeat, index, false});
        else if (tokenIs(token, source, "end"))
        {
            if (blocks.empty() || blocks.back().kind == BlockKind::Repeat)
                continue;
            const KeywordBlock block = blocks.back();
            blocks.pop_back();
            if (block.function)
                ranges.push_back(FunctionTokenRange{block.begin, index});
        }
        else if (tokenIs(token, source, "until"))
        {
            if (!blocks.empty() && blocks.back().kind == BlockKind::Repeat)
                blocks.pop_back();
        }
    }
    std::sort(ranges.begin(), ranges.end(), [](const FunctionTokenRange& left, const FunctionTokenRange& right) {
        return left.end - left.begin < right.end - right.begin;
    });
    return ranges;
}

std::optional<FunctionTokenRange> enclosingFunction(const std::vector<FunctionTokenRange>& ranges, size_t tokenIndex)
{
    for (const FunctionTokenRange& range : ranges)
        if (range.begin <= tokenIndex && tokenIndex <= range.end)
            return range;
    return std::nullopt;
}

std::optional<size_t> indexedSlotAt(std::string_view source, const std::vector<Token>& tokens, size_t index)
{
    if (index + 3 >= tokens.size() || tokens[index].kind != TokenKind::Identifier || !tokenIs(tokens[index + 1], source, "[") ||
        !tokenIs(tokens[index + 3], source, "]"))
        return std::nullopt;
    const std::optional<uint64_t> value = unsignedIntegerToken(source, tokens[index + 2]);
    if (!value || *value > std::numeric_limits<size_t>::max())
        return std::nullopt;
    return static_cast<size_t>(*value);
}

std::optional<size_t> slotCallAt(std::string_view source, const std::vector<Token>& tokens, size_t index)
{
    const std::optional<size_t> slot = indexedSlotAt(source, tokens, index);
    if (!slot || index + 5 >= tokens.size() || !tokenIs(tokens[index + 4], source, "(") || !tokenIs(tokens[index + 5], source, ")"))
        return std::nullopt;
    return slot;
}

bool comparisonOperator(const Token& token, std::string_view source)
{
    return tokenIs(token, source, "<") || tokenIs(token, source, "<=") || tokenIs(token, source, ">") || tokenIs(token, source, ">=") ||
           tokenIs(token, source, "==") || tokenIs(token, source, "~=");
}

void inspectLphDollarSchema(
    std::string_view source,
    const std::vector<Token>& tokens,
    EnvelopeAnalysis& result,
    const AnalysisLimits& limits)
{
    LphDollarSchemaMetadata schema;
    const std::vector<FunctionTokenRange> functions = functionTokenRanges(source, tokens);

    struct PrimitiveAlias
    {
        std::string identifier;
        std::string primitive;
    };
    std::vector<PrimitiveAlias> aliases;
    size_t bufferAliasCount = 0;
    for (size_t index = 0; index + 2 < tokens.size(); ++index)
    {
        if (tokens[index].kind != TokenKind::Identifier || !tokenIs(tokens[index + 1], source, "="))
            continue;
        if (tokens[index + 2].kind == TokenKind::Identifier && tokenIs(tokens[index + 2], source, "buffer"))
            ++bufferAliasCount;
        if (tokens[index + 2].kind != TokenKind::String || tokens[index + 2].long_string)
            continue;
        const std::optional<std::string> decoded = decodedIdentifierLiteral(source, tokens[index + 2]);
        if (!decoded)
            continue;
        if (findReaderSpec(*decoded))
            aliases.push_back(PrimitiveAlias{std::string(source.substr(tokens[index].begin, tokens[index].end - tokens[index].begin)), *decoded});
    }

    const auto aliasPrimitive = [&](std::string_view name) -> std::optional<std::string> {
        for (const PrimitiveAlias& alias : aliases)
            if (alias.identifier == name)
                return alias.primitive;
        return std::nullopt;
    };
    const auto addBinding = [&](std::string primitive, size_t slot, SourceRange range, ReaderEvidenceKind evidence) {
        const ReaderSpec* spec = findReaderSpec(primitive);
        if (!spec)
            return;
        for (const ReaderBindingMetadata& existing : schema.reader_bindings)
            if (existing.state_slot == slot && existing.primitive == primitive)
                return;
        schema.reader_bindings.push_back(ReaderBindingMetadata{
            std::move(primitive), spec->value_kind, evidence, ByteOrder::LittleEndian, spec->bit_width, spec->bit_width / 8,
            slot, false, 0, range});
    };

    for (size_t index = 0; index + 7 < tokens.size(); ++index)
    {
        const std::optional<size_t> slot = indexedSlotAt(source, tokens, index);
        if (!slot || !tokenIs(tokens[index + 4], source, "="))
            continue;
        size_t rhs = index + 5;
        while (rhs < tokens.size() && tokenIs(tokens[rhs], source, "("))
            ++rhs;
        if (rhs + 2 < tokens.size() && tokens[rhs].kind == TokenKind::Identifier && tokenIs(tokens[rhs + 1], source, ".") &&
            tokens[rhs + 2].kind == TokenKind::Identifier)
        {
            const std::string_view primitive = source.substr(tokens[rhs + 2].begin, tokens[rhs + 2].end - tokens[rhs + 2].begin);
            if (findReaderSpec(primitive))
                addBinding(std::string(primitive), *slot, SourceRange{tokens[index].begin, tokens[rhs + 2].end}, ReaderEvidenceKind::RuntimeMemberBinding);
            continue;
        }
        if (rhs + 5 < tokens.size() && tokens[rhs].kind == TokenKind::Identifier && tokenIs(tokens[rhs + 1], source, "[") &&
            tokens[rhs + 2].kind == TokenKind::Identifier && tokenIs(tokens[rhs + 3], source, ".") && tokens[rhs + 4].kind == TokenKind::Identifier &&
            tokenIs(tokens[rhs + 5], source, "]"))
        {
            const std::string_view alias = source.substr(tokens[rhs + 4].begin, tokens[rhs + 4].end - tokens[rhs + 4].begin);
            if (const std::optional<std::string> primitive = aliasPrimitive(alias))
                addBinding(*primitive, *slot, SourceRange{tokens[index].begin, tokens[rhs + 5].end}, ReaderEvidenceKind::RuntimeMemberBinding);
        }
    }

    // Accept parenthesized assignment targets and values. The protected wrapper
    // freely writes `(state)[slot]=(runtime.readu8)`, so the binding is anchored
    // on the assignment and its nearest numeric index rather than identifier text.
    for (size_t equals = 0; equals + 3 < tokens.size(); ++equals)
    {
        if (!tokenIs(tokens[equals], source, "="))
            continue;
        std::optional<size_t> slot;
        size_t slotBegin = equals;
        const size_t searchBegin = equals > 8 ? equals - 8 : 0;
        for (size_t cursor = searchBegin; cursor + 2 < equals; ++cursor)
        {
            if (!tokenIs(tokens[cursor], source, "[") || !tokenIs(tokens[cursor + 2], source, "]"))
                continue;
            const std::optional<uint64_t> parsed = unsignedIntegerToken(source, tokens[cursor + 1]);
            if (parsed && *parsed <= std::numeric_limits<size_t>::max())
            {
                slot = static_cast<size_t>(*parsed);
                slotBegin = cursor;
            }
        }
        if (!slot)
            continue;
        size_t rhs = equals + 1;
        while (rhs < tokens.size() && tokenIs(tokens[rhs], source, "("))
            ++rhs;
        if (rhs + 2 < tokens.size() && tokens[rhs].kind == TokenKind::Identifier && tokenIs(tokens[rhs + 1], source, ".") &&
            tokens[rhs + 2].kind == TokenKind::Identifier)
        {
            const std::string_view primitive = source.substr(tokens[rhs + 2].begin, tokens[rhs + 2].end - tokens[rhs + 2].begin);
            if (findReaderSpec(primitive))
                addBinding(std::string(primitive), *slot, SourceRange{tokens[slotBegin].begin, tokens[rhs + 2].end}, ReaderEvidenceKind::RuntimeMemberBinding);
            continue;
        }
        if (rhs + 5 < tokens.size() && tokens[rhs].kind == TokenKind::Identifier && tokenIs(tokens[rhs + 1], source, "[") &&
            tokens[rhs + 2].kind == TokenKind::Identifier && tokenIs(tokens[rhs + 3], source, ".") && tokens[rhs + 4].kind == TokenKind::Identifier &&
            tokenIs(tokens[rhs + 5], source, "]"))
        {
            const std::string_view alias = source.substr(tokens[rhs + 4].begin, tokens[rhs + 4].end - tokens[rhs + 4].begin);
            if (const std::optional<std::string> primitive = aliasPrimitive(alias))
                addBinding(*primitive, *slot, SourceRange{tokens[slotBegin].begin, tokens[rhs + 5].end}, ReaderEvidenceKind::RuntimeMemberBinding);
        }
    }

    struct BiasEvidence
    {
        size_t reader_slot = 0;
        uint64_t bias = 0;
        SourceRange range;
        std::optional<FunctionTokenRange> function;
    };
    std::vector<BiasEvidence> biases;
    std::vector<std::pair<size_t, SourceRange>> modeReaders;
    for (size_t index = 0; index + 7 < tokens.size(); ++index)
    {
        const std::optional<size_t> slot = slotCallAt(source, tokens, index);
        if (!slot)
            continue;
        if (tokenIs(tokens[index + 6], source, "-") && tokens[index + 7].kind == TokenKind::Number)
        {
            if (const std::optional<uint64_t> bias = unsignedIntegerToken(source, tokens[index + 7]))
                biases.push_back(BiasEvidence{*slot, *bias, SourceRange{tokens[index].begin, tokens[index + 7].end}, enclosingFunction(functions, index)});
        }
        if (tokenIs(tokens[index + 6], source, "~=") && tokens[index + 7].kind == TokenKind::Number &&
            unsignedIntegerToken(source, tokens[index + 7]) == 0)
            modeReaders.push_back({*slot, SourceRange{tokens[index].begin, tokens[index + 7].end}});
    }

    std::optional<size_t> rootReaderSlot;
    SourceRange rootRange;
    for (size_t index = 0; index + 8 < tokens.size(); ++index)
    {
        if (tokens[index].kind != TokenKind::Identifier || !tokenIs(tokens[index + 1], source, "[") ||
            tokens[index + 2].kind != TokenKind::Identifier)
            continue;
        const std::optional<size_t> slot = slotCallAt(source, tokens, index + 2);
        if (!slot || !tokenIs(tokens[index + 8], source, "]"))
            continue;
        rootReaderSlot = *slot;
        rootRange = SourceRange{tokens[index].begin, tokens[index + 8].end};
        break;
    }

    std::optional<size_t> tagReaderSlot;
    SourceRange tagRange;
    std::vector<uint64_t> tagBoundaries;
    if (!modeReaders.empty())
    {
        const size_t candidateSlot = modeReaders.front().first;
        for (size_t index = 0; index + 7 < tokens.size(); ++index)
        {
            if (tokens[index].kind != TokenKind::Identifier || !tokenIs(tokens[index + 1], source, "="))
                continue;
            const std::optional<size_t> slot = slotCallAt(source, tokens, index + 2);
            if (!slot || *slot != candidateSlot)
                continue;
            const std::string_view variable = source.substr(tokens[index].begin, tokens[index].end - tokens[index].begin);
            const std::optional<FunctionTokenRange> function = enclosingFunction(functions, index);
            if (!function)
                continue;
            std::vector<uint64_t> boundaries;
            for (size_t cursor = function->begin; cursor + 2 <= function->end; ++cursor)
            {
                if (tokens[cursor].kind != TokenKind::Identifier ||
                    source.substr(tokens[cursor].begin, tokens[cursor].end - tokens[cursor].begin) != variable ||
                    !comparisonOperator(tokens[cursor + 1], source))
                    continue;
                if (const std::optional<uint64_t> value = unsignedIntegerToken(source, tokens[cursor + 2]))
                    boundaries.push_back(*value);
            }
            std::sort(boundaries.begin(), boundaries.end());
            boundaries.erase(std::unique(boundaries.begin(), boundaries.end()), boundaries.end());
            if (boundaries.size() > tagBoundaries.size())
            {
                tagBoundaries = std::move(boundaries);
                tagReaderSlot = candidateSlot;
                tagRange = SourceRange{tokens[function->begin].begin, tokens[function->end].end};
            }
        }
    }

    bool ulebBodyVerified = false;
    for (const FunctionTokenRange& function : functions)
    {
        bool compares127 = false;
        bool subtracts128 = false;
        bool multiplies128 = false;
        for (size_t index = function.begin; index <= function.end; ++index)
        {
            const std::optional<uint64_t> value = unsignedIntegerToken(source, tokens[index]);
            if (!value)
                continue;
            if (*value == 127 && index > function.begin && comparisonOperator(tokens[index - 1], source))
                compares127 = true;
            if (*value == 128 && index > function.begin && tokenIs(tokens[index - 1], source, "-"))
                subtracts128 = true;
            if (*value == 128 && index > function.begin && tokenIs(tokens[index - 1], source, "*="))
                multiplies128 = true;
        }
        if (compares127 && subtracts128 && multiplies128)
        {
            ulebBodyVerified = true;
            break;
        }
    }

    size_t opaqueWordCount = 0;
    SourceRange opaqueWordRange;
    for (size_t index = 0; index + 3 < tokens.size(); ++index)
    {
        if (tokens[index].kind != TokenKind::Identifier || !tokenIs(tokens[index + 1], source, "=") || !tokenIs(tokens[index + 2], source, "{"))
            continue;
        size_t depth = 1;
        size_t numbers = 0;
        bool numericOnly = true;
        size_t cursor = index + 3;
        for (; cursor < tokens.size() && depth > 0; ++cursor)
        {
            if (tokenIs(tokens[cursor], source, "{"))
            {
                ++depth;
                numericOnly = false;
            }
            else if (tokenIs(tokens[cursor], source, "}"))
                --depth;
            else if (depth == 1 && tokens[cursor].kind == TokenKind::Number)
                ++numbers;
            else if (depth == 1 && !tokenIs(tokens[cursor], source, ","))
                numericOnly = false;
        }
        if (depth == 0 && numericOnly && numbers > opaqueWordCount)
        {
            opaqueWordCount = numbers;
            opaqueWordRange = SourceRange{tokens[index].begin, tokens[cursor - 1].end};
        }
    }

    const bool directReadersVerified = bufferAliasCount > 0 && schema.reader_bindings.size() >= 7;
    size_t rootBiasCount = 0;
    if (rootReaderSlot)
        for (const BiasEvidence& bias : biases)
            rootBiasCount += bias.reader_slot == *rootReaderSlot ? 1 : 0;
    schema.reader_bindings_verified = directReadersVerified;
    schema.variable_integer_reader_verified = ulebBodyVerified && rootReaderSlot.has_value();
    schema.variable_integer_reader_slot = rootReaderSlot;
    schema.scalar_byte_order = directReadersVerified ? ByteOrder::LittleEndian : ByteOrder::Unknown;
    if (rootReaderSlot)
        schema.root = RootCandidateMetadata{true, true, false, rootReaderSlot, rootRange};
    if (tagReaderSlot)
        schema.tags = TagScheduleMetadata{true, true, false, tagReaderSlot, tagBoundaries, tagRange};
    schema.keys = KeyScheduleMetadata{opaqueWordCount >= 4, false, false, opaqueWordCount, opaqueWordRange};
    schema.detected = directReadersVerified && ulebBodyVerified && rootReaderSlot && !modeReaders.empty() && tagReaderSlot &&
                      tagBoundaries.size() >= 4 && rootBiasCount >= 2;
    if (!schema.detected)
    {
        result.lph_dollar_schema = std::move(schema);
        return;
    }

    schema.reader_bindings_verified = true;
    schema.variable_integer_reader_verified = true;
    schema.record_lanes_recovered = true;
    schema.root_selection_recovered = true;
    schema.scalar_byte_order = ByteOrder::LittleEndian;
    schema.reader_bindings.push_back(ReaderBindingMetadata{
        "uleb128", ReaderValueKind::UnsignedInteger, ReaderEvidenceKind::BodyVerified, ByteOrder::LittleEndian, 0, 0,
        *rootReaderSlot, true, 0, rootRange});

    const size_t modeSlot = modeReaders.front().first;
    schema.reader_bindings.push_back(ReaderBindingMetadata{
        "readu8_cursor", ReaderValueKind::UnsignedInteger, ReaderEvidenceKind::BodyVerified, ByteOrder::LittleEndian, 8, 1,
        modeSlot, true, 1, modeReaders.front().second});

    size_t laneOrder = 0;
    schema.record_lanes.push_back(RecordLaneMetadata{
        RecordLaneKind::ConstantPoolMode, laneOrder++, modeSlot, std::nullopt, false, true, modeReaders.front().second});
    for (const BiasEvidence& bias : biases)
    {
        if (bias.reader_slot != *rootReaderSlot)
            continue;
        bool sharesModeFunction = false;
        if (bias.function)
            for (const auto& mode : modeReaders)
                if (mode.second.begin >= tokens[bias.function->begin].begin && mode.second.end <= tokens[bias.function->end].end)
                    sharesModeFunction = true;
        schema.record_lanes.push_back(RecordLaneMetadata{
            sharesModeFunction ? RecordLaneKind::ConstantCount : RecordLaneKind::PrototypeRecord,
            laneOrder++, bias.reader_slot, bias.bias, false, sharesModeFunction, bias.range});
    }
    schema.record_lanes.push_back(RecordLaneMetadata{
        RecordLaneKind::ConstantTag, laneOrder++, *tagReaderSlot, std::nullopt, true, false, tagRange});
    schema.record_lanes.push_back(RecordLaneMetadata{
        RecordLaneKind::ConstantPayload, laneOrder++, std::nullopt, std::nullopt, true, false, tagRange});
    schema.record_lanes.push_back(RecordLaneMetadata{
        RecordLaneKind::PrototypeCount, laneOrder++, *rootReaderSlot, std::nullopt, false, false, rootRange});
    schema.record_lanes.push_back(RecordLaneMetadata{
        RecordLaneKind::RootSelector, laneOrder++, *rootReaderSlot, std::nullopt, false, true, rootRange});

    schema.root = RootCandidateMetadata{true, true, false, rootReaderSlot, rootRange};
    schema.tags = TagScheduleMetadata{true, true, false, tagReaderSlot, std::move(tagBoundaries), tagRange};
    schema.keys = KeyScheduleMetadata{opaqueWordCount >= 4, false, false, opaqueWordCount, opaqueWordRange};

    for (const ReaderBindingMetadata& binding : schema.reader_bindings)
    {
        if (!findReaderSpec(binding.primitive))
            continue;
        auto found = std::find_if(result.readers.begin(), result.readers.end(), [&](const ReaderMetadata& reader) {
            return reader.name == binding.primitive;
        });
        if (found == result.readers.end())
        {
            result.readers.push_back(ReaderMetadata{
                binding.primitive, binding.value_kind, binding.byte_order, binding.bit_width, binding.byte_width, 1, true, false, true,
                binding.evidence_range, binding.evidence_range, binding.evidence, binding.state_slot, binding.cursor_advancing, binding.cursor_advance_bytes});
        }
        else
        {
            found->byte_order = binding.byte_order;
            found->implementation_verified = true;
            found->inferred_from_identifier = false;
            found->definition_present = true;
            found->definition_range = binding.evidence_range;
            found->evidence = binding.evidence;
            found->state_slot = binding.state_slot;
        }
    }
    result.static_decode.reader_metadata_count = result.readers.size();
    result.static_decode.reader_definition_count = static_cast<size_t>(std::count_if(result.readers.begin(), result.readers.end(), [](const ReaderMetadata& reader) {
        return reader.definition_present;
    }));
    result.lph_dollar_schema = std::move(schema);
    addDiagnostic(result, limits, DiagnosticSeverity::Info, "LPH_DOLLAR_STRUCTURAL_SCHEMA_RECOVERED",
        "Recovered the LuaAuth LPH$ reader bindings, variable-integer lane, constant record envelope, prototype lane, and root selection structurally; randomized tag meanings remain unknown.");
    addDiagnostic(result, limits, DiagnosticSeverity::Info, "LPH_DOLLAR_RANDOMIZED_TAGS_RETAINED",
        "Retained the tag reader and comparison boundaries without assigning Lua value or opcode meanings to randomized tag values.");
    if (result.lph_dollar_schema.keys.candidate_present)
        addDiagnostic(result, limits, DiagnosticSeverity::Info, "LPH_DOLLAR_KEY_SCHEDULE_UNPROVEN",
            "An opaque wrapper control-word table was identified, but no container key schedule or semantic mapping was claimed.");
}

uint32_t rotateRight(uint32_t value, unsigned int count)
{
    return (value >> count) | (value << (32u - count));
}

std::string sha256Hex(const std::vector<unsigned char>& bytes)
{
    constexpr std::array<uint32_t, 64> roundConstants = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    };
    std::array<uint32_t, 8> state = {
        0x6a09e667u,
        0xbb67ae85u,
        0x3c6ef372u,
        0xa54ff53au,
        0x510e527fu,
        0x9b05688cu,
        0x1f83d9abu,
        0x5be0cd19u,
    };

    const auto processBlock = [&](const unsigned char* block) {
        std::array<uint32_t, 64> words{};
        for (size_t index = 0; index < 16; ++index)
        {
            const size_t offset = index * 4;
            words[index] = (static_cast<uint32_t>(block[offset]) << 24u) | (static_cast<uint32_t>(block[offset + 1]) << 16u) |
                           (static_cast<uint32_t>(block[offset + 2]) << 8u) | static_cast<uint32_t>(block[offset + 3]);
        }
        for (size_t index = 16; index < words.size(); ++index)
        {
            const uint32_t s0 = rotateRight(words[index - 15], 7) ^ rotateRight(words[index - 15], 18) ^ (words[index - 15] >> 3u);
            const uint32_t s1 = rotateRight(words[index - 2], 17) ^ rotateRight(words[index - 2], 19) ^ (words[index - 2] >> 10u);
            words[index] = words[index - 16] + s0 + words[index - 7] + s1;
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];
        for (size_t index = 0; index < words.size(); ++index)
        {
            const uint32_t sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
            const uint32_t choice = (e & f) ^ (~e & g);
            const uint32_t temporary1 = h + sum1 + choice + roundConstants[index] + words[index];
            const uint32_t sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
            const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temporary2 = sum0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + temporary1;
            d = c;
            c = b;
            b = a;
            a = temporary1 + temporary2;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    };

    size_t offset = 0;
    while (offset + 64 <= bytes.size())
    {
        processBlock(bytes.data() + offset);
        offset += 64;
    }

    std::array<unsigned char, 128> tail{};
    const size_t remaining = bytes.size() - offset;
    std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end(), tail.begin());
    tail[remaining] = 0x80;
    const size_t tailBytes = remaining < 56 ? 64 : 128;
    const uint64_t bitLength = static_cast<uint64_t>(bytes.size()) * 8u;
    for (size_t index = 0; index < 8; ++index)
        tail[tailBytes - 1 - index] = static_cast<unsigned char>(bitLength >> (index * 8u));
    processBlock(tail.data());
    if (tailBytes == 128)
        processBlock(tail.data() + 64);

    constexpr char hex[] = "0123456789abcdef";
    std::string digest;
    digest.reserve(64);
    for (uint32_t word : state)
        for (int shift = 24; shift >= 0; shift -= 8)
        {
            const unsigned char byte = static_cast<unsigned char>(word >> static_cast<unsigned int>(shift));
            digest.push_back(hex[byte >> 4u]);
            digest.push_back(hex[byte & 0x0fu]);
        }
    return digest;
}

enum class CursorError
{
    None,
    Truncated,
    UlebOverflow,
    NonCanonicalUleb,
    SignedFoldOverflow,
};

struct UlebValue
{
    uint64_t value = 0;
    ByteSpan span;
};

class ContainerCursor
{
public:
    explicit ContainerCursor(const std::vector<unsigned char>& data, size_t offset = 0)
        : data(data)
        , position(std::min(offset, data.size()))
    {
        if (offset > data.size())
            fail(CursorError::Truncated, data.size());
    }

    [[nodiscard]] size_t offset() const
    {
        return position;
    }

    [[nodiscard]] size_t remaining() const
    {
        return data.size() - position;
    }

    [[nodiscard]] CursorError error() const
    {
        return currentError;
    }

    [[nodiscard]] size_t errorOffset() const
    {
        return currentErrorOffset;
    }

    bool readByte(unsigned char& value, ByteSpan& span)
    {
        const size_t begin = position;
        if (!require(1))
            return false;
        value = data[position++];
        span = ByteSpan{begin, position};
        return true;
    }

    bool readU64Little(uint64_t& value, ByteSpan& span)
    {
        return readUnsignedLittle(8, value, span);
    }

    bool readUnsignedLittle(size_t width, uint64_t& value, ByteSpan& span)
    {
        const size_t begin = position;
        if (width > sizeof(value) || !require(width))
            return false;
        value = 0;
        for (size_t index = 0; index < width; ++index)
            value |= static_cast<uint64_t>(data[position + index]) << (index * 8u);
        position += width;
        span = ByteSpan{begin, position};
        return true;
    }

    bool readBytes(uint64_t count, std::vector<unsigned char>& value, ByteSpan& span)
    {
        const size_t begin = position;
        if (count > remaining())
        {
            fail(CursorError::Truncated, position);
            return false;
        }
        const size_t size = static_cast<size_t>(count);
        value.assign(data.begin() + static_cast<std::ptrdiff_t>(position),
            data.begin() + static_cast<std::ptrdiff_t>(position + size));
        position += size;
        span = ByteSpan{begin, position};
        return true;
    }

    bool readUleb(UlebValue& output)
    {
        const size_t begin = position;
        uint64_t value = 0;
        for (size_t index = 0; index < 10; ++index)
        {
            if (!require(1))
                return false;
            const unsigned char byte = data[position++];
            const uint64_t payload = byte & 0x7fu;
            if (index == 9 && (payload > 1 || (byte & 0x80u) != 0))
            {
                fail(CursorError::UlebOverflow, begin);
                return false;
            }
            value |= payload << (index * 7u);
            if ((byte & 0x80u) == 0)
            {
                if (index > 0 && payload == 0)
                {
                    fail(CursorError::NonCanonicalUleb, begin);
                    return false;
                }
                output = UlebValue{value, ByteSpan{begin, position}};
                return true;
            }
        }
        fail(CursorError::UlebOverflow, begin);
        return false;
    }

    bool readSignedFold(int64_t& value, ByteSpan& span)
    {
        constexpr uint64_t threshold = uint64_t{1} << 52u;
        constexpr uint64_t modulus = uint64_t{1} << 53u;
        UlebValue raw;
        if (!readUleb(raw))
            return false;
        if (raw.value >= modulus)
        {
            fail(CursorError::SignedFoldOverflow, raw.span.begin);
            return false;
        }
        value = raw.value >= threshold ? -static_cast<int64_t>(modulus - raw.value) : static_cast<int64_t>(raw.value);
        span = raw.span;
        return true;
    }

    bool skip(uint64_t count, ByteSpan& span)
    {
        const size_t begin = position;
        if (count > remaining())
        {
            fail(CursorError::Truncated, position);
            return false;
        }
        position += static_cast<size_t>(count);
        span = ByteSpan{begin, position};
        return true;
    }

private:
    bool require(size_t count)
    {
        if (count <= remaining())
            return true;
        fail(CursorError::Truncated, position);
        return false;
    }

    void fail(CursorError error, size_t offset)
    {
        if (currentError == CursorError::None)
        {
            currentError = error;
            currentErrorOffset = offset;
        }
    }

    const std::vector<unsigned char>& data;
    size_t position = 0;
    CursorError currentError = CursorError::None;
    size_t currentErrorOffset = 0;
};

ContainerParseStatus parseStatus(CursorError error)
{
    switch (error)
    {
    case CursorError::None: return ContainerParseStatus::NotAttempted;
    case CursorError::Truncated: return ContainerParseStatus::Truncated;
    case CursorError::UlebOverflow: return ContainerParseStatus::UlebOverflow;
    case CursorError::NonCanonicalUleb: return ContainerParseStatus::NonCanonicalUleb;
    case CursorError::SignedFoldOverflow: return ContainerParseStatus::SignedFoldOverflow;
    }
    return ContainerParseStatus::Truncated;
}

bool setCursorFailure(ContainerAnalysis& analysis, const ContainerCursor& cursor)
{
    analysis.parse_status = parseStatus(cursor.error());
    analysis.parse_error_offset = cursor.errorOffset();
    return false;
}

bool decodeBiasedCount(
    const UlebValue& raw,
    uint64_t bias,
    size_t limit,
    size_t& value,
    ContainerAnalysis& analysis)
{
    if (raw.value < bias)
    {
        analysis.parse_status = ContainerParseStatus::CountUnderflow;
        analysis.parse_error_offset = raw.span.begin;
        return false;
    }
    const uint64_t adjusted = raw.value - bias;
    if (adjusted > limit)
    {
        analysis.parse_status = ContainerParseStatus::CountLimitExceeded;
        analysis.parse_error_offset = raw.span.begin;
        return false;
    }
    value = static_cast<size_t>(adjusted);
    return true;
}

bool parseContainerBytes(const std::vector<unsigned char>& bytes, ContainerAnalysis& analysis, const AnalysisLimits& limits)
{
    constexpr uint64_t constantCountBias = 12618;
    constexpr uint64_t prototypeCountBias = 87799;
    constexpr uint64_t instructionCountBias = 7379;
    ContainerCursor cursor(bytes);

    UlebValue constantCount;
    if (!cursor.readUleb(constantCount))
        return setCursorFailure(analysis, cursor);
    analysis.constant_count_span = constantCount.span;
    if (!decodeBiasedCount(constantCount, constantCountBias, limits.max_container_constants, analysis.constant_count, analysis))
        return false;
    if (!cursor.readByte(analysis.constant_pool_mode, analysis.constant_pool_mode_span))
        return setCursorFailure(analysis, cursor);
    analysis.constants.reserve(analysis.constant_count);
    const size_t constantsBegin = cursor.offset();
    for (size_t index = 0; index < analysis.constant_count; ++index)
    {
        ConstantMetadata metadata;
        metadata.index = index;
        const size_t recordBegin = cursor.offset();
        if (!cursor.readByte(metadata.tag, metadata.tag_span))
            return setCursorFailure(analysis, cursor);

        const auto readSignedInteger = [&](size_t width) {
            metadata.kind = ConstantKind::Integer;
            uint64_t raw = 0;
            if (!cursor.readUnsignedLittle(width, raw, metadata.data_span))
                return false;
            const size_t bitWidth = width * 8u;
            const uint64_t signBit = uint64_t{1} << (bitWidth - 1u);
            metadata.signed_integer_value = (raw & signBit) != 0
                ? static_cast<int64_t>(raw) - static_cast<int64_t>(uint64_t{1} << bitWidth)
                : static_cast<int64_t>(raw);
            return true;
        };
        const auto readUnsignedInteger = [&](size_t width) {
            metadata.kind = ConstantKind::Integer;
            uint64_t value = 0;
            if (!cursor.readUnsignedLittle(width, value, metadata.data_span))
                return false;
            metadata.unsigned_integer_value = value;
            return true;
        };
        const auto readNegatedU8 = [&]() {
            metadata.kind = ConstantKind::Integer;
            uint64_t value = 0;
            if (!cursor.readUnsignedLittle(1, value, metadata.data_span))
                return false;
            metadata.signed_integer_value = -static_cast<int64_t>(value);
            return true;
        };
        const auto readBoolean = [&](bool value) {
            metadata.kind = ConstantKind::Boolean;
            metadata.boolean_value = value;
            return cursor.skip(0, metadata.data_span);
        };
        const auto readFloat32 = [&]() {
            metadata.kind = ConstantKind::Float;
            uint64_t bits = 0;
            if (!cursor.readUnsignedLittle(4, bits, metadata.data_span))
                return false;
            metadata.float32_bits = static_cast<uint32_t>(bits);
            metadata.float32_value = std::bit_cast<float>(*metadata.float32_bits);
            return true;
        };
        const auto readFloat64 = [&]() {
            metadata.kind = ConstantKind::Float;
            uint64_t bits = 0;
            if (!cursor.readUnsignedLittle(8, bits, metadata.data_span))
                return false;
            metadata.float64_bits = bits;
            metadata.float64_value = std::bit_cast<double>(bits);
            return true;
        };
        const auto readString = [&]() {
            metadata.kind = ConstantKind::String;
            UlebValue length;
            if (!cursor.readUleb(length))
                return false;
            metadata.length_span = length.span;
            return cursor.readBytes(length.value, metadata.string_bytes, metadata.data_span);
        };

        // Luraph 14.7 randomizes the tag value within encoding families.  These
        // boundaries are the exact qc/xc/wc/Lc/Rc/Oc dispatch tree used by the
        // supported wrapper, not inferred Lua value ranges.
        bool constantDecoded = false;
        if (metadata.tag <= 39)
            constantDecoded = readSignedInteger(2);
        else if (metadata.tag <= 46)
            constantDecoded = readFloat64();
        else if (metadata.tag <= 67)
            constantDecoded = readBoolean(false);
        else if (metadata.tag <= 75)
            constantDecoded = readFloat32();
        else if (metadata.tag <= 89)
            constantDecoded = readNegatedU8();
        else if (metadata.tag == 90)
            constantDecoded = readSignedInteger(4);
        else if (metadata.tag <= 109)
            constantDecoded = readNegatedU8();
        else if (metadata.tag <= 116)
            constantDecoded = readBoolean(true);
        else if (metadata.tag <= 155)
            constantDecoded = readString();
        else if (metadata.tag == 156)
            constantDecoded = readUnsignedInteger(8);
        else if (metadata.tag <= 181)
            constantDecoded = readString();
        else if (metadata.tag <= 198)
            constantDecoded = readUnsignedInteger(1);
        else if (metadata.tag <= 232)
            constantDecoded = readUnsignedInteger(2);
        else
            constantDecoded = readUnsignedInteger(4);

        if (!constantDecoded)
            return setCursorFailure(analysis, cursor);
        metadata.data_bytes = metadata.data_span.size();
        metadata.span = ByteSpan{recordBegin, cursor.offset()};
        analysis.constants.push_back(std::move(metadata));
    }
    analysis.constants_span = ByteSpan{constantsBegin, cursor.offset()};

    UlebValue prototypeCount;
    if (!cursor.readUleb(prototypeCount))
        return setCursorFailure(analysis, cursor);
    analysis.prototype_count_span = prototypeCount.span;
    if (!decodeBiasedCount(prototypeCount, prototypeCountBias, limits.max_container_prototypes, analysis.prototype_count, analysis))
        return false;
    analysis.prototypes.reserve(analysis.prototype_count);
    const size_t prototypesBegin = cursor.offset();
    for (size_t index = 0; index < analysis.prototype_count; ++index)
    {
        PrototypeMetadata prototype;
        prototype.index = index;
        const size_t recordBegin = cursor.offset();
        UlebValue meta;
        if (!cursor.readUleb(meta))
            return setCursorFailure(analysis, cursor);
        prototype.meta = meta.value;
        prototype.meta_span = meta.span;

        UlebValue instructionCount;
        if (!cursor.readUleb(instructionCount))
            return setCursorFailure(analysis, cursor);
        prototype.instruction_count_span = instructionCount.span;
        const size_t remainingInstructionLimit = limits.max_container_instructions - analysis.instruction_count;
        if (!decodeBiasedCount(instructionCount, instructionCountBias, remainingInstructionLimit, prototype.instruction_count, analysis))
            return false;
        prototype.instructions.reserve(prototype.instruction_count);
        const size_t instructionWordsBegin = cursor.offset();
        for (size_t instruction = 0; instruction < prototype.instruction_count; ++instruction)
        {
            InstructionMetadata metadata;
            metadata.index = instruction;
            const size_t instructionBegin = cursor.offset();
            for (size_t word = 0; word < 4; ++word)
            {
                if (!cursor.readSignedFold(metadata.words[word].value, metadata.words[word].span))
                    return setCursorFailure(analysis, cursor);
            }
            metadata.span = ByteSpan{instructionBegin, cursor.offset()};
            prototype.instructions.push_back(std::move(metadata));
        }
        prototype.instruction_words_span = ByteSpan{instructionWordsBegin, cursor.offset()};
        analysis.instruction_count += prototype.instruction_count;

        UlebValue descriptorCount;
        if (!cursor.readUleb(descriptorCount))
            return setCursorFailure(analysis, cursor);
        prototype.descriptor_count_span = descriptorCount.span;
        if (descriptorCount.value > limits.max_container_descriptors - analysis.descriptor_count)
        {
            analysis.parse_status = ContainerParseStatus::CountLimitExceeded;
            analysis.parse_error_offset = descriptorCount.span.begin;
            return false;
        }
        prototype.descriptor_count = static_cast<size_t>(descriptorCount.value);
        prototype.descriptors.reserve(prototype.descriptor_count);
        const size_t descriptorsBegin = cursor.offset();
        for (size_t descriptor = 0; descriptor < prototype.descriptor_count; ++descriptor)
        {
            UlebValue raw;
            if (!cursor.readUleb(raw))
                return setCursorFailure(analysis, cursor);
            prototype.descriptors.push_back(DescriptorMetadata{
                descriptor,
                raw.value,
                static_cast<unsigned int>(raw.value % 4u),
                raw.value / 4u,
                raw.span,
            });
        }
        prototype.descriptors_span = ByteSpan{descriptorsBegin, cursor.offset()};
        analysis.descriptor_count += prototype.descriptor_count;

        UlebValue finalValue;
        if (!cursor.readUleb(finalValue))
            return setCursorFailure(analysis, cursor);
        prototype.final_value = finalValue.value;
        prototype.final_span = finalValue.span;
        prototype.span = ByteSpan{recordBegin, cursor.offset()};
        analysis.prototypes.push_back(std::move(prototype));
    }
    analysis.prototypes_span = ByteSpan{prototypesBegin, cursor.offset()};

    UlebValue rootSelector;
    if (!cursor.readUleb(rootSelector))
        return setCursorFailure(analysis, cursor);
    analysis.root_selector = rootSelector.value;
    analysis.root_selector_span = rootSelector.span;
    analysis.trailer_span = ByteSpan{cursor.offset(), bytes.size()};
    if (cursor.remaining() > limits.max_preserved_trailer_bytes)
    {
        analysis.parse_status = ContainerParseStatus::TrailerLimitExceeded;
        analysis.parse_error_offset = cursor.offset();
        return false;
    }
    analysis.trailer_bytes.assign(bytes.begin() + static_cast<std::ptrdiff_t>(cursor.offset()), bytes.end());
    analysis.parse_status = ContainerParseStatus::Parsed;
    return true;
}

bool parseLphDollarPrototypeSection(
    const std::vector<unsigned char>& bytes,
    size_t sectionBegin,
    uint64_t prototypeCountBias,
    uint64_t instructionCountBias,
    ContainerAnalysis& analysis,
    const AnalysisLimits& limits,
    bool retainRecords)
{
    ContainerCursor cursor(bytes, sectionBegin);
    UlebValue prototypeCount;
    if (!cursor.readUleb(prototypeCount))
        return setCursorFailure(analysis, cursor);
    analysis.prototype_count_span = prototypeCount.span;
    if (!decodeBiasedCount(prototypeCount, prototypeCountBias, limits.max_container_prototypes, analysis.prototype_count, analysis) ||
        analysis.prototype_count == 0)
        return false;

    if (retainRecords)
        analysis.prototypes.reserve(analysis.prototype_count);
    const size_t prototypesBegin = cursor.offset();
    size_t rangeMapCount = 0;
    for (size_t index = 0; index < analysis.prototype_count; ++index)
    {
        PrototypeMetadata prototype;
        prototype.index = index;
        const size_t recordBegin = cursor.offset();

        UlebValue descriptorCount;
        if (!cursor.readUleb(descriptorCount))
            return setCursorFailure(analysis, cursor);
        prototype.descriptor_count_span = descriptorCount.span;
        if (descriptorCount.value > limits.max_container_descriptors - analysis.descriptor_count)
        {
            analysis.parse_status = ContainerParseStatus::CountLimitExceeded;
            analysis.parse_error_offset = descriptorCount.span.begin;
            return false;
        }
        prototype.descriptor_count = static_cast<size_t>(descriptorCount.value);
        if (retainRecords)
            prototype.descriptors.reserve(prototype.descriptor_count);
        const size_t descriptorsBegin = cursor.offset();
        for (size_t descriptor = 0; descriptor < prototype.descriptor_count; ++descriptor)
        {
            UlebValue raw;
            if (!cursor.readUleb(raw))
                return setCursorFailure(analysis, cursor);
            if (retainRecords)
            {
                prototype.descriptors.push_back(DescriptorMetadata{
                    descriptor,
                    raw.value,
                    static_cast<unsigned int>(raw.value % 4u),
                    raw.value / 4u,
                    raw.span,
                });
            }
        }
        prototype.descriptors_span = ByteSpan{descriptorsBegin, cursor.offset()};
        analysis.descriptor_count += prototype.descriptor_count;

        UlebValue meta;
        UlebValue secondaryMeta;
        if (!cursor.readUleb(meta) || !cursor.readUleb(secondaryMeta))
            return setCursorFailure(analysis, cursor);
        prototype.meta = meta.value;
        prototype.meta_span = meta.span;
        prototype.secondary_meta = secondaryMeta.value;
        prototype.secondary_meta_span = secondaryMeta.span;

        uint64_t rawRangeMapCount = 0;
        if (!cursor.readUnsignedLittle(4, rawRangeMapCount, prototype.range_map_count_span))
            return setCursorFailure(analysis, cursor);
        if (rawRangeMapCount > limits.max_container_descriptors - rangeMapCount)
        {
            analysis.parse_status = ContainerParseStatus::CountLimitExceeded;
            analysis.parse_error_offset = prototype.range_map_count_span.begin;
            return false;
        }
        prototype.range_map_count = static_cast<size_t>(rawRangeMapCount);
        rangeMapCount += prototype.range_map_count;
        const size_t rangeMapBegin = cursor.offset();
        for (size_t range = 0; range < prototype.range_map_count; ++range)
        {
            uint64_t marker = 0;
            ByteSpan ignored;
            if (!cursor.readUnsignedLittle(4, marker, ignored))
                return setCursorFailure(analysis, cursor);
            if ((marker & 1u) != 0)
            {
                uint64_t first = 0;
                uint64_t second = 0;
                if (!cursor.readUnsignedLittle(4, first, ignored) || !cursor.readUnsignedLittle(4, second, ignored))
                    return setCursorFailure(analysis, cursor);
            }
        }
        prototype.range_map_span = ByteSpan{rangeMapBegin, cursor.offset()};

        UlebValue instructionCount;
        if (!cursor.readUleb(instructionCount))
            return setCursorFailure(analysis, cursor);
        prototype.instruction_count_span = instructionCount.span;
        const size_t remainingInstructionLimit = limits.max_container_instructions - analysis.instruction_count;
        if (!decodeBiasedCount(instructionCount, instructionCountBias, remainingInstructionLimit, prototype.instruction_count, analysis))
            return false;
        if (retainRecords)
            prototype.instructions.reserve(prototype.instruction_count);
        const size_t instructionWordsBegin = cursor.offset();
        for (size_t instruction = 0; instruction < prototype.instruction_count; ++instruction)
        {
            InstructionMetadata metadata;
            metadata.index = instruction;
            const size_t instructionBegin = cursor.offset();
            for (size_t word = 0; word < metadata.words.size(); ++word)
            {
                int64_t value = 0;
                ByteSpan span;
                if (!cursor.readSignedFold(value, span))
                    return setCursorFailure(analysis, cursor);
                // The first signed-fold lane is the serialized opcode byte. This
                // is a framing invariant; no randomized opcode meaning is assigned.
                if (word == 0 && (value < 0 || value > 255))
                    return false;
                if (retainRecords)
                    metadata.words[word] = InstructionWordMetadata{value, span};
            }
            metadata.span = ByteSpan{instructionBegin, cursor.offset()};
            if (retainRecords)
                prototype.instructions.push_back(std::move(metadata));
        }
        prototype.instruction_words_span = ByteSpan{instructionWordsBegin, cursor.offset()};
        analysis.instruction_count += prototype.instruction_count;
        prototype.span = ByteSpan{recordBegin, cursor.offset()};
        if (retainRecords)
            analysis.prototypes.push_back(std::move(prototype));
    }
    analysis.prototypes_span = ByteSpan{prototypesBegin, cursor.offset()};

    UlebValue rootSelector;
    if (!cursor.readUleb(rootSelector))
        return setCursorFailure(analysis, cursor);
    if (rootSelector.value == 0 || rootSelector.value > analysis.prototype_count)
        return false;
    analysis.root_selector = rootSelector.value;
    analysis.root_selector_span = rootSelector.span;
    analysis.trailer_span = ByteSpan{cursor.offset(), bytes.size()};
    if (cursor.remaining() > limits.max_preserved_trailer_bytes)
    {
        analysis.parse_status = ContainerParseStatus::TrailerLimitExceeded;
        analysis.parse_error_offset = cursor.offset();
        return false;
    }
    if (retainRecords)
        analysis.trailer_bytes.assign(bytes.begin() + static_cast<std::ptrdiff_t>(cursor.offset()), bytes.end());
    analysis.parse_status = ContainerParseStatus::StructuralMetadataRecovered;
    return true;
}

bool parseLphDollarStructure(
    const std::vector<unsigned char>& bytes,
    ContainerAnalysis& analysis,
    LphDollarSchemaMetadata& schema,
    const AnalysisLimits& limits)
{
    std::vector<uint64_t> biases;
    for (const RecordLaneMetadata& lane : schema.record_lanes)
    {
        if (!lane.numeric_bias || std::find(biases.begin(), biases.end(), *lane.numeric_bias) != biases.end())
            continue;
        biases.push_back(*lane.numeric_bias);
    }
    // The supported deserializer has one independently observed bias for each
    // count lane. More candidates are bounded rather than interpreted freely.
    if (biases.size() < 3 || biases.size() > 8)
        return false;

    ContainerCursor header(bytes);
    UlebValue rawConstantCount;
    if (!header.readUleb(rawConstantCount))
        return false;
    unsigned char poolMode = 0;
    ByteSpan poolModeSpan;
    if (!header.readByte(poolMode, poolModeSpan))
        return false;
    const size_t constantsBegin = header.offset();

    for (size_t constantBiasIndex = 0; constantBiasIndex < biases.size(); ++constantBiasIndex)
    {
        const uint64_t constantBias = biases[constantBiasIndex];
        if (rawConstantCount.value < constantBias || rawConstantCount.value - constantBias > limits.max_container_constants)
            continue;
        const size_t constantCount = static_cast<size_t>(rawConstantCount.value - constantBias);
        if (constantCount > bytes.size() - constantsBegin)
            continue;
        const size_t earliestPrototypeSection = constantsBegin + constantCount;

        // The wrapper reads constants before prototypes. Search for the first
        // section after the minimum one-byte-per-record envelope that validates
        // every prototype, instruction lane, and one-based root selector.
        for (size_t sectionBegin = earliestPrototypeSection; sectionBegin < bytes.size(); ++sectionBegin)
        {
            for (size_t prototypeBiasIndex = 0; prototypeBiasIndex < biases.size(); ++prototypeBiasIndex)
            {
                if (prototypeBiasIndex == constantBiasIndex)
                    continue;
                for (size_t instructionBiasIndex = 0; instructionBiasIndex < biases.size(); ++instructionBiasIndex)
                {
                    if (instructionBiasIndex == constantBiasIndex || instructionBiasIndex == prototypeBiasIndex)
                        continue;
                    ContainerAnalysis validation;
                    if (!parseLphDollarPrototypeSection(bytes, sectionBegin, biases[prototypeBiasIndex], biases[instructionBiasIndex],
                            validation, limits, false))
                        continue;

                    ContainerAnalysis retained;
                    if (!parseLphDollarPrototypeSection(bytes, sectionBegin, biases[prototypeBiasIndex], biases[instructionBiasIndex],
                            retained, limits, true))
                        return false;
                    analysis.constant_count = constantCount;
                    analysis.constant_count_span = rawConstantCount.span;
                    analysis.constant_pool_mode = poolMode;
                    analysis.constant_pool_mode_span = poolModeSpan;
                    analysis.constants_span = ByteSpan{constantsBegin, sectionBegin};
                    analysis.prototype_count = retained.prototype_count;
                    analysis.prototype_count_span = retained.prototype_count_span;
                    analysis.prototypes_span = retained.prototypes_span;
                    analysis.instruction_count = retained.instruction_count;
                    analysis.descriptor_count = retained.descriptor_count;
                    analysis.root_selector = retained.root_selector;
                    analysis.root_selector_span = retained.root_selector_span;
                    analysis.trailer_span = retained.trailer_span;
                    analysis.prototypes = std::move(retained.prototypes);
                    analysis.trailer_bytes = std::move(retained.trailer_bytes);
                    analysis.randomized_tag_semantics = true;
                    analysis.tag_semantic_mapping_recovered = false;
                    analysis.parse_status = ContainerParseStatus::StructuralMetadataRecovered;

                    for (RecordLaneMetadata& lane : schema.record_lanes)
                    {
                        if (!lane.numeric_bias)
                            continue;
                        if (*lane.numeric_bias == constantBias)
                        {
                            lane.kind = RecordLaneKind::ConstantCount;
                            lane.semantics_known = true;
                        }
                        else if (*lane.numeric_bias == biases[prototypeBiasIndex])
                        {
                            lane.kind = RecordLaneKind::PrototypeCount;
                            lane.semantics_known = true;
                        }
                        else if (*lane.numeric_bias == biases[instructionBiasIndex])
                        {
                            lane.kind = RecordLaneKind::InstructionCount;
                            lane.semantics_known = true;
                        }
                    }
                    const SourceRange prototypeEvidence = schema.root.evidence_range;
                    size_t laneOrder = schema.record_lanes.size();
                    const auto addLane = [&](RecordLaneKind kind, bool repeated) {
                        schema.record_lanes.push_back(RecordLaneMetadata{
                            kind, laneOrder++, schema.variable_integer_reader_slot, std::nullopt, repeated, true, prototypeEvidence});
                    };
                    addLane(RecordLaneKind::DescriptorCount, true);
                    addLane(RecordLaneKind::DescriptorRecord, true);
                    addLane(RecordLaneKind::PrototypeMetadata, true);
                    schema.record_lanes.push_back(RecordLaneMetadata{
                        RecordLaneKind::RangeMapCount, laneOrder++, std::nullopt, std::nullopt, true, true, prototypeEvidence});
                    schema.record_lanes.push_back(RecordLaneMetadata{
                        RecordLaneKind::RangeMapRecord, laneOrder++, std::nullopt, std::nullopt, true, true, prototypeEvidence});
                    addLane(RecordLaneKind::InstructionWords, true);
                    schema.root.selector_value_known = true;
                    return true;
                }
            }
        }
    }
    return false;
}

struct Radix85DecodeResult
{
    ContainerDecodeStatus status = ContainerDecodeStatus::NotAttempted;
    std::optional<size_t> error_offset;
    size_t body_bytes = 0;
    size_t group_count = 0;
    size_t zero_group_count = 0;
    unsigned char marker = 0;
    std::vector<unsigned char> bytes;
};

Radix85DecodeResult decodeLphContainer(const std::vector<unsigned char>& carrier, size_t maxBytes)
{
    Radix85DecodeResult decoded;
    constexpr std::array<unsigned char, 3> prefix = {'L', 'P', 'H'};
    constexpr size_t markerBytes = 4;
    if (carrier.size() < markerBytes || !std::equal(prefix.begin(), prefix.end(), carrier.begin()) ||
        (carrier[3] != '&' && carrier[3] != '$'))
    {
        decoded.status = ContainerDecodeStatus::InvalidPrefix;
        decoded.error_offset = 0;
        return decoded;
    }
    decoded.marker = carrier[3];
    decoded.body_bytes = carrier.size() - markerBytes;
    const bool zeroShorthand = decoded.marker == '$';
    if (!zeroShorthand && decoded.body_bytes % 5 != 0)
    {
        decoded.status = ContainerDecodeStatus::MisalignedBody;
        decoded.error_offset = carrier.size();
        return decoded;
    }
    decoded.bytes.reserve(std::min(maxBytes, (decoded.body_bytes / 5 + 1) * 4));
    uint64_t value = 0;
    size_t digits = 0;
    size_t groupBegin = markerBytes;
    const auto appendDigit = [&](uint64_t digit, size_t sourceOffset) {
        if (value > (std::numeric_limits<uint32_t>::max() - digit) / 85u)
        {
            decoded.status = ContainerDecodeStatus::Radix85Overflow;
            decoded.error_offset = groupBegin;
            decoded.bytes.clear();
            return false;
        }
        value = value * 85u + digit;
        ++digits;
        if (digits != 5)
            return true;
        if (decoded.bytes.size() > maxBytes || maxBytes - decoded.bytes.size() < 4)
        {
            decoded.status = ContainerDecodeStatus::OutputLimitExceeded;
            decoded.error_offset = groupBegin;
            decoded.bytes.clear();
            return false;
        }
        for (size_t index = 0; index < 4; ++index)
            decoded.bytes.push_back(static_cast<unsigned char>(value >> (index * 8u)));
        ++decoded.group_count;
        value = 0;
        digits = 0;
        groupBegin = sourceOffset + 1;
        return true;
    };
    for (size_t offset = markerBytes; offset < carrier.size(); ++offset)
    {
        const unsigned char byte = carrier[offset];
        if (zeroShorthand && byte == 'z')
        {
            ++decoded.zero_group_count;
            // The LuaAuth wrapper applies gsub("z", "!!!!!") before grouping,
            // so shorthand is valid even when it appears inside a source group.
            for (size_t expansion = 0; expansion < 5; ++expansion)
                if (!appendDigit(0, offset))
                    return decoded;
            continue;
        }
        if (byte < 33 || byte > 117)
        {
            decoded.status = ContainerDecodeStatus::InvalidCharacter;
            decoded.error_offset = offset;
            decoded.bytes.clear();
            return decoded;
        }
        if (!appendDigit(byte - 33u, offset))
            return decoded;
    }
    if (digits != 0)
    {
        decoded.status = ContainerDecodeStatus::MisalignedBody;
        decoded.error_offset = carrier.size();
        decoded.bytes.clear();
        return decoded;
    }
    decoded.status = ContainerDecodeStatus::Decoded;
    return decoded;
}

std::optional<size_t> findLphMarker(const std::vector<unsigned char>& bytes)
{
    constexpr std::array<unsigned char, 3> prefix = {'L', 'P', 'H'};
    auto found = bytes.begin();
    while ((found = std::search(found, bytes.end(), prefix.begin(), prefix.end())) != bytes.end())
    {
        const size_t offset = static_cast<size_t>(found - bytes.begin());
        if (offset + 3 < bytes.size() && bytes[offset + 3] >= 33 && bytes[offset + 3] <= 126)
            return offset;
        ++found;
    }
    return std::nullopt;
}

void addContainerDecodeDiagnostic(
    EnvelopeAnalysis& result,
    const AnalysisLimits& limits,
    ContainerDecodeStatus status)
{
    switch (status)
    {
    case ContainerDecodeStatus::InvalidPrefix:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_AMPERSAND_PREFIX",
            "An LPH container marker was present, but the decoded literal did not begin with a supported four-byte prefix.");
        break;
    case ContainerDecodeStatus::MisalignedBody:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_RADIX85_ALIGNMENT",
            "The LPH& radix-85 body length is not divisible by five.");
        break;
    case ContainerDecodeStatus::InvalidCharacter:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_RADIX85_CHARACTER",
            "The LPH& radix-85 body contains a byte outside ASCII 33 through 117.");
        break;
    case ContainerDecodeStatus::Radix85Overflow:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_RADIX85_OVERFLOW",
            "An LPH& radix-85 group exceeds the unsigned 32-bit output domain.");
        break;
    case ContainerDecodeStatus::OutputLimitExceeded:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_CONTAINER_OUTPUT_LIMIT",
            "LPH& decoding would exceed the aggregate decoded-container byte limit; no partial output was retained.");
        break;
    case ContainerDecodeStatus::NotAttempted:
    case ContainerDecodeStatus::Decoded:
        break;
    }
}

void addContainerParseDiagnostic(
    EnvelopeAnalysis& result,
    const AnalysisLimits& limits,
    ContainerParseStatus status)
{
    switch (status)
    {
    case ContainerParseStatus::Truncated:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_CONTAINER_TRUNCATED",
            "The decoded LPH& container ended during a required scalar or record.");
        break;
    case ContainerParseStatus::UnsupportedSchema:
    case ContainerParseStatus::StructuralMetadataRecovered:
        break;
    case ContainerParseStatus::UlebOverflow:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_ULEB_OVERFLOW",
            "An LPH& ULEB value exceeds the unsigned 64-bit domain.");
        break;
    case ContainerParseStatus::NonCanonicalUleb:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_ULEB_NONCANONICAL",
            "An LPH& ULEB value uses a noncanonical redundant terminal group.");
        break;
    case ContainerParseStatus::CountUnderflow:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_COUNT_UNDERFLOW",
            "A biased LPH& record count is smaller than its proven v14.7 bias.");
        break;
    case ContainerParseStatus::CountLimitExceeded:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_CONTAINER_COUNT_LIMIT",
            "An LPH& constant, prototype, instruction, or descriptor count exceeds its configured limit.");
        break;
    case ContainerParseStatus::SignedFoldOverflow:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_SIGNED_FOLD_OVERFLOW",
            "An instruction word lies outside the wrapper's proven 53-bit signed-fold domain.");
        break;
    case ContainerParseStatus::TrailerLimitExceeded:
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_TRAILER_LIMIT",
            "The unread LPH& trailer exceeds the configured preservation limit.");
        break;
    case ContainerParseStatus::NotAttempted:
    case ContainerParseStatus::Parsed:
        break;
    }
}

std::optional<size_t> inspectLphContainer(
    const std::vector<unsigned char>& carrier,
    size_t carrierIndex,
    EnvelopeAnalysis& result,
    const AnalysisLimits& limits)
{
    ++result.container_metrics.attempt_count;
    ContainerAnalysis analysis;
    analysis.carrier_index = carrierIndex;
    analysis.encoded_carrier_bytes = carrier.size();
    const size_t remainingBytes = limits.max_decoded_container_bytes - result.container_metrics.decoded_bytes;
    Radix85DecodeResult decoded = decodeLphContainer(carrier, remainingBytes);
    analysis.marker = decoded.marker;
    analysis.decode_status = decoded.status;
    analysis.encoded_body_bytes = decoded.body_bytes;
    analysis.radix85_group_count = decoded.group_count;
    analysis.radix85_zero_group_count = decoded.zero_group_count;
    analysis.encoded_error_offset = decoded.error_offset;
    result.container_metrics.encoded_body_bytes += decoded.body_bytes;
    result.container_metrics.radix85_group_count += decoded.group_count;
    result.container_metrics.radix85_zero_group_count += decoded.zero_group_count;

    if (decoded.status == ContainerDecodeStatus::Decoded)
    {
        analysis.decoded_bytes = decoded.bytes.size();
        analysis.decoded_sha256 = sha256Hex(decoded.bytes);
        analysis.decoded_data = decoded.bytes;
        analysis.transport_byte_order = ByteOrder::LittleEndian;
        ++result.container_metrics.decoded_count;
        result.container_metrics.decoded_bytes += decoded.bytes.size();
        addDiagnostic(result, limits, DiagnosticSeverity::Info, "LPH_CONTAINER_DECODED",
            decoded.marker == '$'
                ? "Decoded LPH$ radix-85 groups, including zero shorthand, to little-endian container bytes."
                : "Decoded strict LPH& radix-85 groups to little-endian container bytes.");

        if (decoded.marker == '$')
        {
            if (result.lph_dollar_schema.detected &&
                parseLphDollarStructure(decoded.bytes, analysis, result.lph_dollar_schema, limits))
            {
                ++result.container_metrics.structural_count;
                result.container_metrics.constant_count += analysis.constant_count;
                result.container_metrics.prototype_count += analysis.prototype_count;
                result.container_metrics.instruction_count += analysis.instruction_count;
                result.container_metrics.descriptor_count += analysis.descriptor_count;
                result.container_metrics.trailer_bytes += analysis.trailer_bytes.size();
                addDiagnostic(result, limits, DiagnosticSeverity::Info, "LPH_DOLLAR_SCHEMA_BOUNDARY_ADVANCED",
                    "Parsed the biased LPH$ count lanes, prototype records, instruction words, and one-based root selector; randomized constant and opcode meanings remain opaque.");
                addDiagnostic(result, limits, DiagnosticSeverity::Info, "LPH_DOLLAR_CONSTANT_TAGS_OPAQUE",
                    "Delimited the complete constant-record region without assigning randomized tag values to Lua types.");
            }
            else
            {
                analysis.parse_status = ContainerParseStatus::UnsupportedSchema;
                addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LPH_DOLLAR_SCHEMA_UNSUPPORTED",
                    result.lph_dollar_schema.detected
                        ? "The LPH$ reader schema was recovered, but no bounded prototype/root framing candidate validated against the decoded carrier."
                        : "The LPH$ container bytes were recovered exactly, but its randomized record schema was not structurally verified.");
            }
        }
        else if (parseContainerBytes(decoded.bytes, analysis, limits))
        {
            ++result.container_metrics.parsed_count;
            result.container_metrics.constant_count += analysis.constant_count;
            result.container_metrics.prototype_count += analysis.prototype_count;
            result.container_metrics.instruction_count += analysis.instruction_count;
            result.container_metrics.descriptor_count += analysis.descriptor_count;
            result.container_metrics.trailer_bytes += analysis.trailer_bytes.size();
            addDiagnostic(result, limits, DiagnosticSeverity::Info, "LPH_CONTAINER_PARSED",
                "Parsed bounded LPH& constant and prototype records; unread trailer bytes were preserved without interpretation.");
        }
        else
        {
            ++result.container_metrics.failure_count;
            result.static_decode.complete = false;
            addContainerParseDiagnostic(result, limits, analysis.parse_status);
        }
    }
    else
    {
        ++result.container_metrics.failure_count;
        result.static_decode.complete = false;
        addContainerDecodeDiagnostic(result, limits, decoded.status);
    }

    const size_t containerIndex = result.containers.size();
    result.containers.push_back(std::move(analysis));
    return containerIndex;
}

void decodeCarrierLiterals(
    std::string_view source,
    const std::vector<Token>& tokens,
    EnvelopeAnalysis& result,
    const AnalysisLimits& limits)
{
    result.static_decode.carrier_candidate_count = result.counts.encoded_blob_candidate_count;
    const bool supportedAttribution = (result.banner.exact_product_marker && result.version_supported) ||
                                      (result.luaauth_launcher.present && result.luaauth_launcher.exact_assignment_shape);
    result.static_decode.eligible = result.complete && supportedAttribution &&
                                    result.wrapper.kind == WrapperKind::ReturnedTableMethodDispatch && result.wrapper.zero_argument_method_call &&
                                    result.wrapper.forwards_varargs && result.wrapper.consumes_entire_chunk;
    if (!result.static_decode.eligible)
    {
        if (result.version_supported && result.counts.encoded_blob_candidate_count > 0)
            addDiagnostic(result, limits, DiagnosticSeverity::Info, "STATIC_DECODE_SKIPPED_UNPROVEN_WRAPPER",
                "Carrier literals were not decoded because the complete supported wrapper dispatch shape was not proven.");
        return;
    }

    result.static_decode.attempted = true;
    result.static_decode.complete = true;
    inspectReaderMetadata(source, tokens, result, limits);
    inspectLphDollarSchema(source, tokens, result, limits);

    for (const Token& token : tokens)
    {
        if (token.kind != TokenKind::String)
            continue;
        const size_t sourceBytes = token.content_end >= token.content_begin ? token.content_end - token.content_begin : 0;
        const StringStats stats = inspectString(source.substr(token.content_begin, sourceBytes));
        if (!encodedBlobCandidate(sourceBytes, stats))
            continue;
        if (stats.has_lph_marker)
            ++result.container_metrics.candidate_count;
        if (result.static_decode.carrier_attempt_count >= limits.max_tracked_blob_candidates)
        {
            ++result.static_decode.carrier_skipped_count;
            result.static_decode.complete = false;
            continue;
        }

        ++result.static_decode.carrier_attempt_count;
        result.static_decode.carrier_literal_source_bytes += sourceBytes;
        CarrierExtraction extraction;
        extraction.kind = blobKind(stats);
        extraction.literal_kind = token.long_string ? CarrierLiteralKind::LongBracketString : CarrierLiteralKind::QuotedString;
        extraction.literal_range = SourceRange{token.begin, token.end};
        extraction.content_range = SourceRange{token.content_begin, token.content_end};
        extraction.literal_source_bytes = sourceBytes;

        const size_t remainingBytes = limits.max_decoded_carrier_bytes - result.static_decode.decoded_carrier_bytes;
        LiteralDecodeResult decoded = token.long_string ? decodeLongBracketLiteral(source, token, remainingBytes) : decodeQuotedLiteral(source, token, remainingBytes);
        extraction.status = decoded.status;
        extraction.error_range = decoded.error_range;
        if (decoded.status == CarrierDecodeStatus::DecodedLiteral)
        {
            extraction.decoded_byte_count = decoded.bytes.size();
            extraction.lph_marker_offset = findLphMarker(decoded.bytes);
            extraction.bytes = std::move(decoded.bytes);
            result.static_decode.decoded_carrier_bytes += extraction.decoded_byte_count;
            ++result.static_decode.carrier_decoded_count;
            const bool leadingDecodedMarker = extraction.lph_marker_offset == 0 && extraction.bytes.size() >= 4 &&
                                              (extraction.bytes[3] == '&' || extraction.bytes[3] == '$');
            if (leadingDecodedMarker || stats.has_lph_ampersand_marker || stats.has_lph_dollar_marker)
            {
                if (!stats.has_lph_marker)
                    ++result.container_metrics.candidate_count;
                if (leadingDecodedMarker)
                    extraction.kind = extraction.bytes[3] == '$' ? BlobKind::LphDollar : BlobKind::LphAmpersand;
                extraction.container_index = inspectLphContainer(extraction.bytes, result.carriers.size(), result, limits);
            }
        }
        else
        {
            ++result.static_decode.carrier_failure_count;
            result.static_decode.complete = false;
            if (decoded.status == CarrierDecodeStatus::ByteLimitExceeded)
            {
                ++result.static_decode.byte_limit_hit_count;
                addDiagnostic(result, limits, DiagnosticSeverity::Warning, "CARRIER_DECODE_BYTE_LIMIT",
                    "Carrier literal decoding exceeded the aggregate decoded-byte limit; no partial bytes were retained.", extraction.error_range);
            }
            else if (decoded.status == CarrierDecodeStatus::UnsupportedLiteral)
                addDiagnostic(result, limits, DiagnosticSeverity::Warning, "CARRIER_LITERAL_UNSUPPORTED",
                    "An interpolated string carrier was left opaque because its bytes are not provable without expression evaluation.", extraction.error_range);
            else
                addDiagnostic(result, limits, DiagnosticSeverity::Warning, "CARRIER_LITERAL_INVALID",
                    "A carrier string contains an invalid or unsupported Luau escape and was left opaque.", extraction.error_range);
        }
        result.carriers.push_back(std::move(extraction));
    }

    if (result.static_decode.carrier_skipped_count > 0)
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "CARRIER_TRACK_LIMIT",
            "Carrier tracking limit reached; additional candidates were counted but not decoded or retained.");
    if (result.static_decode.carrier_decoded_count > 0)
        addDiagnostic(result, limits, DiagnosticSeverity::Info, "CARRIER_LITERAL_DECODED",
            "Decoded exact Luau string-literal bytes from the proven wrapper envelope.");
    result.static_decode.literal_complete = result.static_decode.carrier_attempt_count > 0 &&
                                            result.static_decode.carrier_failure_count == 0 &&
                                            result.static_decode.carrier_skipped_count == 0;
    result.static_decode.transport_complete = result.container_metrics.attempt_count > 0 &&
                                              result.container_metrics.decoded_count == result.container_metrics.attempt_count &&
                                              result.container_metrics.failure_count == 0;
    result.static_decode.schema_complete = false;
    result.static_decode.semantic_complete = false;
    if (result.static_decode.carrier_attempt_count > 0)
        addDiagnostic(result, limits, DiagnosticSeverity::Info, "VM_SEMANTICS_NOT_ATTEMPTED",
            "Carrier/container bytes were inspected only; VM semantics and source recovery were not attempted.");
}

void inspectCountsAndBlobs(
    std::string_view source,
    const std::vector<Token>& tokens,
    EnvelopeAnalysis& result,
    const AnalysisLimits& limits)
{
    for (const Token& token : tokens)
    {
        switch (token.kind)
        {
        case TokenKind::Identifier:
        {
            ++result.counts.identifier_count;
            const std::string_view identifier = source.substr(token.begin, token.end - token.begin);
            if (identifier == "function")
                ++result.counts.function_literal_count;
            if (identifier == "while" || identifier == "for" || identifier == "repeat")
                ++result.counts.loop_construct_count;
            if (readerPrimitive(identifier))
                ++result.counts.reader_primitive_reference_count;
            break;
        }
        case TokenKind::Number:
            ++result.counts.numeric_literal_count;
            break;
        case TokenKind::String:
        {
            ++result.counts.string_literal_count;
            const size_t sourceBytes = token.content_end >= token.content_begin ? token.content_end - token.content_begin : 0;
            result.counts.string_literal_source_bytes += sourceBytes;
            const StringStats stats = inspectString(source.substr(token.content_begin, sourceBytes));
            if (!encodedStringCandidate(sourceBytes, stats))
                break;
            ++result.counts.encoded_string_candidate_count;
            if (sourceBytes < kMinimumEncodedBlobBytes && !stats.has_lph_marker)
                break;

            ++result.counts.encoded_blob_candidate_count;
            result.counts.encoded_blob_source_bytes += sourceBytes;
            if (result.blobs.size() < limits.max_tracked_blob_candidates)
            {
                result.blobs.push_back(BlobCandidate{
                    blobKind(stats),
                    SourceRange{token.begin, token.end},
                    sourceBytes,
                    stats.distinct,
                    stats.printable_ratio,
                    stats.whitespace_ratio,
                    token.long_string,
                    stats.has_lph_marker,
                });
            }
            break;
        }
        case TokenKind::Symbol:
            if (tokenIs(token, source, "{"))
                ++result.counts.table_constructor_count;
            if (tokenIs(token, source, "["))
                ++result.counts.indexed_access_count;
            break;
        }
    }
    std::sort(result.blobs.begin(), result.blobs.end(), [](const BlobCandidate& left, const BlobCandidate& right) {
        return left.source_bytes > right.source_bytes;
    });
}

void addStage(EnvelopeAnalysis& result, StageKind kind, double confidence, std::string summary, std::optional<SourceRange> range = std::nullopt)
{
    result.stages.push_back(Stage{kind, confidence, std::move(summary), range});
}

void inferStages(EnvelopeAnalysis& result)
{
    if (result.luaauth_launcher.present)
        addStage(result, StageKind::ProtectionBanner, 1.0,
            "LuaAuth launcher metadata was separated from the protected Luraph body.", result.luaauth_launcher.range);
    if (result.banner.present)
        addStage(result, StageKind::ProtectionBanner, 1.0, "Luraph protection banner declaration.", result.banner.range);
    if (result.wrapper.kind != WrapperKind::None)
        addStage(result, StageKind::WrapperConstruction, 0.98, "Returned table constructs the protected runtime envelope.", result.wrapper.table_range);
    if (result.counts.encoded_blob_candidate_count > 0)
        addStage(result, StageKind::EncodedPayload, 0.94,
            result.container_metrics.parsed_count > 0
                ? "Strict LPH& framing and bounded container records were decoded; VM semantics remain opaque."
                : result.container_metrics.structural_count > 0
                ? "LPH$ transport, reader bindings, record lanes, and root selection were recovered; randomized tag meanings remain opaque."
                : result.container_metrics.decoded_count > 0
                ? "LPH container bytes were decoded exactly; its version-specific record schema remains opaque."
                : result.static_decode.carrier_decoded_count > 0
                ? "Exact carrier literal bytes were extracted; further transforms remain opaque."
                : "One or more opaque encoded payload carriers are embedded as string literals.",
            result.blobs.empty() ? std::nullopt : std::optional<SourceRange>(result.blobs.front().range));
    if (result.counts.encoded_blob_candidate_count > 0 && result.counts.reader_primitive_reference_count >= 2)
        addStage(result, StageKind::ReaderSetup, 0.88,
            result.lph_dollar_schema.reader_bindings_verified
                ? "Runtime reader bindings and little-endian scalar widths were verified from the deserializer; variable-length record semantics remain bounded."
                : result.static_decode.reader_metadata_count > 0
                ? "Reader identifier width hints were extracted; implementations, byte order, and runtime behavior remain unproven."
                : "Byte-reader primitives and an encoded carrier indicate decoder or deserializer setup.");
    if (result.wrapper.function_member_count >= 16 && result.counts.loop_construct_count >= 8 && result.counts.indexed_access_count >= 16)
        addStage(result, StageKind::InterpreterScaffolding, 0.86, "Dense function, loop, and indexed-state scaffolding indicates an interpreter-style runtime.",
            result.wrapper.table_range);
    else if (result.generated_interpreter)
        addStage(result, StageKind::InterpreterScaffolding, 0.96, "Runtime-generated Luraph interpreter scaffolding was identified structurally.");
    if (result.wrapper.kind == WrapperKind::ReturnedTableMethodDispatch && result.wrapper.zero_argument_method_call && result.wrapper.forwards_varargs)
        addStage(result, StageKind::EntrypointDispatch, 0.99, "A zero-argument wrapper method is invoked and its result receives the chunk varargs.",
            result.wrapper.invocation_range);
}

void addConfidenceEvidence(EnvelopeAnalysis& result, std::string code, double weight, std::string description)
{
    result.confidence.score += weight;
    result.confidence.evidence.push_back(ConfidenceEvidence{std::move(code), weight, std::move(description)});
}

void scoreConfidence(EnvelopeAnalysis& result)
{
    if (result.luaauth_launcher.present && result.luaauth_launcher.exact_assignment_shape)
        addConfidenceEvidence(result, "LUAAUTH_LAUNCHER", 0.24,
            "Leading LuaAuth assignments and official launcher notice were separated from the protected body; launcher identity alone is not Luraph attribution.");
    if (result.generated_interpreter)
        addConfidenceEvidence(result, "GENERATED_INTERPRETER", 0.82,
            "Large vararg-backed returned dispatcher contains dense functions, loops, indexed state, coroutine yield, buffer, and bit32 primitives.");
    if (result.banner.present && result.banner.exact_product_marker)
        addConfidenceEvidence(result, "LURAPH_BANNER", 0.42, "Leading comment names the Luraph Obfuscator product.");
    if (result.banner.version == "14.7")
        addConfidenceEvidence(result, "VERSION_14_7", 0.18, "Banner version is exactly 14.7.");
    if (result.family_kind == FamilyKind::LuaAuthLphDollar && result.container_metrics.decoded_count > 0)
        addConfidenceEvidence(result, "LPH_DOLLAR_TRANSPORT", 0.38,
            "A leading LPH$ carrier was decoded through the wrapper's radix-85 transport.");
    if (result.lph_dollar_schema.detected)
        addConfidenceEvidence(result, "LPH_DOLLAR_STRUCTURAL_SCHEMA", 0.24,
            "Reader bindings, record lanes, tag decision boundaries, and root selection match the LuaAuth LPH$ deserializer family.");
    if (result.wrapper.kind == WrapperKind::ReturnedTableMethodDispatch && result.wrapper.consumes_entire_chunk)
        addConfidenceEvidence(result, "TABLE_METHOD_WRAPPER", 0.20, "Chunk is a returned table followed by method dispatch.");
    if (result.counts.encoded_blob_candidate_count > 0)
        addConfidenceEvidence(result, "OPAQUE_BLOB", 0.08, "Envelope contains an opaque encoded string blob.");
    if (result.counts.reader_primitive_reference_count >= 2)
        addConfidenceEvidence(result, "READER_PRIMITIVES", 0.05, "Envelope references multiple binary reader primitives.");
    if (result.wrapper.function_member_count >= 16)
        addConfidenceEvidence(result, "DENSE_FUNCTION_TABLE", 0.04, "Outer table contains dense function-valued members.");
    if (result.wrapper.forwards_varargs)
        addConfidenceEvidence(result, "VARARG_DISPATCH", 0.03, "Wrapper dispatch forwards chunk varargs.");

    result.confidence.score = std::clamp(result.confidence.score, 0.0, 1.0);
    if (result.confidence.score >= 0.80)
        result.confidence.level = ConfidenceLevel::High;
    else if (result.confidence.score >= 0.55)
        result.confidence.level = ConfidenceLevel::Medium;
    else if (result.confidence.score >= 0.25)
        result.confidence.level = ConfidenceLevel::Low;
    else
        result.confidence.level = ConfidenceLevel::None;

    result.family_detected = result.generated_interpreter ||
                             result.family_kind == FamilyKind::LuaAuthLphDollar ||
                             result.family_kind == FamilyKind::Luraph147LphAmpersand ||
                             (result.banner.exact_product_marker && result.banner.major.has_value()) ||
                             result.confidence.score >= 0.70;
}

void shiftSourceRange(std::optional<SourceRange>& range, size_t offset)
{
    if (range)
    {
        range->begin += offset;
        range->end += offset;
    }
}

void shiftBodyRanges(EnvelopeAnalysis& result, size_t offset)
{
    if (offset == 0)
        return;
    shiftSourceRange(result.banner.range, offset);
    shiftSourceRange(result.wrapper.table_range, offset);
    shiftSourceRange(result.wrapper.invocation_range, offset);
    for (BlobCandidate& blob : result.blobs)
    {
        blob.range.begin += offset;
        blob.range.end += offset;
    }
    for (CarrierExtraction& carrier : result.carriers)
    {
        carrier.literal_range.begin += offset;
        carrier.literal_range.end += offset;
        carrier.content_range.begin += offset;
        carrier.content_range.end += offset;
        shiftSourceRange(carrier.error_range, offset);
    }
    for (ReaderMetadata& reader : result.readers)
    {
        reader.name_range.begin += offset;
        reader.name_range.end += offset;
        shiftSourceRange(reader.definition_range, offset);
    }
    if (result.lph_dollar_schema.detected)
    {
        const auto shiftRange = [offset](SourceRange& range) {
            range.begin += offset;
            range.end += offset;
        };
        for (ReaderBindingMetadata& binding : result.lph_dollar_schema.reader_bindings)
            shiftRange(binding.evidence_range);
        for (RecordLaneMetadata& lane : result.lph_dollar_schema.record_lanes)
            shiftRange(lane.evidence_range);
        if (result.lph_dollar_schema.root.present)
            shiftRange(result.lph_dollar_schema.root.evidence_range);
        if (result.lph_dollar_schema.tags.present)
            shiftRange(result.lph_dollar_schema.tags.evidence_range);
        if (result.lph_dollar_schema.keys.candidate_present)
            shiftRange(result.lph_dollar_schema.keys.evidence_range);
    }
    for (Diagnostic& diagnostic : result.diagnostics)
        shiftSourceRange(diagnostic.range, offset);
}

} // namespace

EnvelopeAnalysis analyzeEnvelope(std::string_view source, const AnalysisLimits& limits)
{
    EnvelopeAnalysis result;
    result.counts.source_bytes = source.size();
    addDiagnostic(result, limits, DiagnosticSeverity::Info, "STRUCTURAL_ONLY",
        "Static envelope and proven container framing analysis only; input was not executed, and VM semantics or source recovery were not attempted.");

    if (source.empty())
    {
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "EMPTY_INPUT", "Input is empty.");
        return result;
    }
    if (source.size() > limits.max_source_bytes)
    {
        addDiagnostic(result, limits, DiagnosticSeverity::Error, "SOURCE_LIMIT", "Source byte limit exceeded; no structural scan was performed.");
        return result;
    }

    const LuaAuthLauncherInfo launcher = inspectLuaAuthLauncher(source);
    const size_t bodyOffset = launcher.protected_body_range ? launcher.protected_body_range->begin : 0;
    const std::string_view protectedSource = source.substr(bodyOffset);
    result.luaauth_launcher = launcher;
    result.banner = inspectBanner(protectedSource);
    result.version_supported = result.banner.version == "14.7";
    if (result.banner.exact_product_marker && !result.version_supported)
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "UNSUPPORTED_VERSION", "A Luraph banner was found, but its version is not the supported 14.7 envelope.",
            result.banner.range);

    LexResult lexed = lex(protectedSource, result, limits);
    result.counts.token_count = lexed.tokens.size();
    result.counts.comment_count = lexed.comment_count;
    inspectCountsAndBlobs(protectedSource, lexed.tokens, result, limits);

    size_t prefixStart = 0;
    while (prefixStart < protectedSource.size() && asciiSpace(protectedSource[prefixStart]))
        ++prefixStart;
    const std::string_view prefix = protectedSource.substr(prefixStart, std::min<size_t>(256, protectedSource.size() - prefixStart));
    result.generated_interpreter = protectedSource.size() >= 16 * 1024 && prefix.starts_with("local ") &&
                                   prefix.find("=...;return({") != std::string_view::npos &&
                                   protectedSource.find("coroutine.yield") != std::string_view::npos &&
                                   protectedSource.find("buffer") != std::string_view::npos &&
                                   protectedSource.find("bit32") != std::string_view::npos &&
                                   result.counts.function_literal_count >= 32 &&
                                   result.counts.loop_construct_count >= 8 &&
                                   result.counts.indexed_access_count >= 64;

    bool delimitersBalanced = false;
    const std::vector<size_t> matches = balanceDelimiters(protectedSource, lexed.tokens, result, limits, delimitersBalanced);
    if (delimitersBalanced)
        result.wrapper = inspectWrapper(protectedSource, lexed.tokens, matches);
    result.complete = lexed.complete && delimitersBalanced;
    decodeCarrierLiterals(protectedSource, lexed.tokens, result, limits);
    const bool decodedDollarCarrier = std::any_of(result.containers.begin(), result.containers.end(), [](const ContainerAnalysis& container) {
        return container.marker == '$' && container.decode_status == ContainerDecodeStatus::Decoded;
    });
    const bool decodedAmpersandCarrier = std::any_of(result.containers.begin(), result.containers.end(), [](const ContainerAnalysis& container) {
        return container.marker == '&' && container.decode_status == ContainerDecodeStatus::Decoded;
    });
    if (decodedDollarCarrier && launcher.present)
    {
        result.family_kind = FamilyKind::LuaAuthLphDollar;
        result.version_supported = true; // Legacy adapter-capability flag used by the runtime probe pipeline.
        result.support_level = result.container_metrics.structural_count > 0
            ? SupportLevel::StructuralSchemaRecovered : SupportLevel::TransportDecoded;
    }
    else if (decodedAmpersandCarrier && result.banner.version == "14.7")
    {
        result.family_kind = FamilyKind::Luraph147LphAmpersand;
        result.support_level = result.container_metrics.parsed_count > 0
            ? SupportLevel::StructuralSchemaRecovered : SupportLevel::TransportDecoded;
    }
    else if (result.banner.exact_product_marker && result.banner.version == "14.7")
    {
        result.family_kind = FamilyKind::Luraph147LphAmpersand;
        result.support_level = SupportLevel::EnvelopeRecognized;
    }
    else if (result.generated_interpreter)
    {
        result.family_kind = FamilyKind::InterpreterLike;
        result.support_level = SupportLevel::EnvelopeRecognized;
    }
    else if (result.banner.present || launcher.present)
        result.support_level = SupportLevel::EnvelopeRecognized;
    if (launcher.present && !decodedDollarCarrier)
        addDiagnostic(result, limits, DiagnosticSeverity::Warning, "LUAAUTH_CARRIER_UNSUPPORTED",
            "A LuaAuth launcher was recognized, but no decoded leading LPH$ carrier was proven.");
    shiftBodyRanges(result, bodyOffset);
    if (launcher.present)
        addDiagnostic(result, limits, DiagnosticSeverity::Info, "LUAAUTH_LAUNCHER_REMOVED",
            "LuaAuth launcher assignments and notice were excluded from protected-body analysis and generated probes.", launcher.range);
    inferStages(result);
    scoreConfidence(result);

    if (result.generated_interpreter)
        addDiagnostic(result, limits, DiagnosticSeverity::Info, "LURAPH_GENERATED_INTERPRETER_DETECTED",
            "A runtime-generated Luraph interpreter was detected; it is not original payload source.");
    else if (result.family_detected)
        addDiagnostic(result, limits, DiagnosticSeverity::Info, "LURAPH_STRUCTURE_DETECTED",
            launcher.present
                ? "The supported LuaAuth-wrapped LPH$ Luraph structure was detected; launcher metadata is not payload source."
                : "Luraph structural signals were detected; classification remains envelope-only.");
    return result;
}

std::optional<std::string> buildCallTraceProbe(std::string_view source, uint64_t fullTraceStart, uint64_t fullTraceEnd)
{
    constexpr std::string_view activationNeedle = "m=function(...)local j,P";
    constexpr std::string_view dispatchNeedle = "while true do local w=(e[l]);";

    const size_t activationOffset = source.find(activationNeedle);
    const size_t dispatchOffset = source.find(dispatchNeedle);
    if (activationOffset == std::string_view::npos || dispatchOffset == std::string_view::npos ||
        source.find(activationNeedle, activationOffset + 1) != std::string_view::npos ||
        source.find(dispatchNeedle, dispatchOffset + 1) != std::string_view::npos)
        return std::nullopt;

    std::string probe(source);
    const std::string activationReplacement =
        "m=function(...)local __callerAid,__callerPc,__callerOp=_G.__curAid,_G.__curPc,_G.__curOp;"
        "_G.__lph_a=(_G.__lph_a or 0)+1;local __aid=_G.__lph_a;local j,P";
    probe.replace(activationOffset, activationNeedle.size(), activationReplacement);

    const size_t adjustedDispatchOffset = dispatchOffset + activationReplacement.size() - activationNeedle.size();
    std::string dispatchReplacement = R"LURAPH_TRACE(while true do local w=(e[l]);_G.__vmc=(_G.__vmc or 0)+1;_G.__curAid=__aid;_G.__curPc=l;_G.__curOp=w;local __registers=type(j)=="table" and j or nil;local __qi=type(Q)=="table" and rawget(Q,l) or nil;local __q=__registers and __qi and rawget(__registers,__qi) or nil;if type(__q)=="function" then local __qn=debug.info(__q,"n");if __qn=="print" or __qn=="warn" or __qn=="error" then local __parts={};if __registers and __qi then for __argi=1,8 do local __arg=rawget(__registers,__qi+__argi);if __arg==nil then break end;local __kind=type(__arg);local __encoded;if __kind=="string" then local __bytes={};for __byte=1,#__arg do __bytes[__byte]=string.format("%02x",string.byte(__arg,__byte));end;__encoded="s:"..table.concat(__bytes);elseif __kind=="number" then __encoded="n:"..tostring(__arg);elseif __kind=="boolean" then __encoded=__arg and "b:1" or "b:0";else __encoded="x:"..__kind;end;__parts[#__parts+1]=__encoded;end;end;print("@@LPH_CALL_V2@@",_G.__vmc,__aid,__callerAid,__callerPc,__callerOp,l,w,__qi,__qn,#__parts,table.concat(__parts,"|"));end;end;)LURAPH_TRACE";
    if (fullTraceStart > 0 && fullTraceEnd >= fullTraceStart)
    {
        dispatchReplacement += "if _G.__vmc>=" + std::to_string(fullTraceStart) + " and _G.__vmc<=" + std::to_string(fullTraceEnd) + " then ";
        dispatchReplacement += R"LURAPH_TRACE(local __ti=type(t)=="table" and rawget(t,l) or nil;local __ui=type(u)=="table" and rawget(u,l) or nil;local __q1=__registers and __qi and rawget(__registers,__qi+1) or nil;local __tv=__registers and __ti and rawget(__registers,__ti) or nil;local __uv=__registers and __ui and rawget(__registers,__ui) or nil;local __qt=type(__q);local __q1t=type(__q1);local __tt=type(__tv);local __ut=type(__uv);local __qv=(__qt=="string" or __qt=="number") and __q or __qt;local __q1v=(__q1t=="string" or __q1t=="number") and __q1 or __q1t;local __tvalue=(__tt=="string" or __tt=="number") and __tv or __tt;local __uvalue=(__ut=="string" or __ut=="number") and __uv or __ut;local __qn=__qt=="function" and debug.info(__q,"n") or "";local __q1n=__q1t=="function" and debug.info(__q1,"n") or "";local __tn=__tt=="function" and debug.info(__tv,"n") or "";local __un=__ut=="function" and debug.info(__uv,"n") or "";print("@@LPH_VM@@",_G.__vmc,__aid,__callerAid,__callerPc,__callerOp,l,w,__qi,__qt,__qv,__qn,__q1t,__q1v,__q1n,__ti,__tt,__tvalue,__tn,__ui,__ut,__uvalue,__un,type(f)=="table" and rawget(f,l) or nil,type(T)=="table" and rawget(T,l) or nil,type(x)=="table" and rawget(x,l) or nil);if l==1 then local __args={...};local __activationParts={};for __index=1,math.min(select("#",...),8) do local __value=__args[__index];local __valueType=type(__value);local __valueSummary=(__valueType=="string" or __valueType=="number") and __value or __valueType;__activationParts[#__activationParts+1]=tostring(__index)..":"..__valueType..":"..tostring(__valueSummary);end;print("@@LPH_ACTIVATION@@",_G.__vmc,__aid,__callerAid,__callerPc,__callerOp,select("#",...),table.concat(__activationParts,"|"));end;end;)LURAPH_TRACE";
    }
    probe.replace(adjustedDispatchOffset, dispatchNeedle.size(), dispatchReplacement);
    return probe;
}

std::string_view toString(DiagnosticSeverity severity)
{
    switch (severity)
    {
    case DiagnosticSeverity::Info: return "info";
    case DiagnosticSeverity::Warning: return "warning";
    case DiagnosticSeverity::Error: return "error";
    }
    return "unknown";
}

std::string_view toString(WrapperKind kind)
{
    switch (kind)
    {
    case WrapperKind::None: return "none";
    case WrapperKind::ReturnedTable: return "returned_table";
    case WrapperKind::ReturnedTableMethodDispatch: return "returned_table_method_dispatch";
    }
    return "unknown";
}

std::string_view toString(BlobKind kind)
{
    switch (kind)
    {
    case BlobKind::OpaquePrintable: return "opaque_printable";
    case BlobKind::LphMarker: return "lph_marker";
    case BlobKind::LphAmpersand: return "lph_ampersand";
    case BlobKind::LphDollar: return "lph_dollar";
    }
    return "unknown";
}

std::string_view toString(CarrierLiteralKind kind)
{
    switch (kind)
    {
    case CarrierLiteralKind::QuotedString: return "quoted_string";
    case CarrierLiteralKind::LongBracketString: return "long_bracket_string";
    }
    return "unknown";
}

std::string_view toString(CarrierDecodeStatus status)
{
    switch (status)
    {
    case CarrierDecodeStatus::NotAttempted: return "not_attempted";
    case CarrierDecodeStatus::DecodedLiteral: return "decoded_literal";
    case CarrierDecodeStatus::InvalidLiteral: return "invalid_literal";
    case CarrierDecodeStatus::UnsupportedLiteral: return "unsupported_literal";
    case CarrierDecodeStatus::ByteLimitExceeded: return "byte_limit_exceeded";
    }
    return "unknown";
}

std::string_view toString(ReaderValueKind kind)
{
    switch (kind)
    {
    case ReaderValueKind::UnsignedInteger: return "unsigned_integer";
    case ReaderValueKind::SignedInteger: return "signed_integer";
    case ReaderValueKind::FloatingPoint: return "floating_point";
    case ReaderValueKind::ByteString: return "byte_string";
    }
    return "unknown";
}

std::string_view toString(ReaderEvidenceKind kind)
{
    switch (kind)
    {
    case ReaderEvidenceKind::IdentifierHint: return "identifier_hint";
    case ReaderEvidenceKind::RuntimeMemberBinding: return "runtime_member_binding";
    case ReaderEvidenceKind::BodyVerified: return "body_verified";
    }
    return "unknown";
}

std::string_view toString(ByteOrder byteOrder)
{
    switch (byteOrder)
    {
    case ByteOrder::Unknown: return "unknown";
    case ByteOrder::LittleEndian: return "little_endian";
    case ByteOrder::BigEndian: return "big_endian";
    }
    return "unknown";
}

std::string_view toString(ContainerDecodeStatus status)
{
    switch (status)
    {
    case ContainerDecodeStatus::NotAttempted: return "not_attempted";
    case ContainerDecodeStatus::Decoded: return "decoded";
    case ContainerDecodeStatus::InvalidPrefix: return "invalid_prefix";
    case ContainerDecodeStatus::MisalignedBody: return "misaligned_body";
    case ContainerDecodeStatus::InvalidCharacter: return "invalid_character";
    case ContainerDecodeStatus::Radix85Overflow: return "radix85_overflow";
    case ContainerDecodeStatus::OutputLimitExceeded: return "output_limit_exceeded";
    }
    return "unknown";
}

std::string_view toString(ContainerParseStatus status)
{
    switch (status)
    {
    case ContainerParseStatus::NotAttempted: return "not_attempted";
    case ContainerParseStatus::Parsed: return "parsed";
    case ContainerParseStatus::StructuralMetadataRecovered: return "structural_metadata_recovered";
    case ContainerParseStatus::UnsupportedSchema: return "unsupported_schema";
    case ContainerParseStatus::Truncated: return "truncated";
    case ContainerParseStatus::UlebOverflow: return "uleb_overflow";
    case ContainerParseStatus::NonCanonicalUleb: return "noncanonical_uleb";
    case ContainerParseStatus::CountUnderflow: return "count_underflow";
    case ContainerParseStatus::CountLimitExceeded: return "count_limit_exceeded";
    case ContainerParseStatus::SignedFoldOverflow: return "signed_fold_overflow";
    case ContainerParseStatus::TrailerLimitExceeded: return "trailer_limit_exceeded";
    }
    return "unknown";
}

std::string_view toString(FamilyKind kind)
{
    switch (kind)
    {
    case FamilyKind::Unknown: return "unknown";
    case FamilyKind::Luraph147LphAmpersand: return "luraph_14_7_lph_ampersand";
    case FamilyKind::LuaAuthLphDollar: return "luaauth_lph_dollar";
    case FamilyKind::InterpreterLike: return "interpreter_like";
    }
    return "unknown";
}

std::string_view toString(SupportLevel level)
{
    switch (level)
    {
    case SupportLevel::None: return "none";
    case SupportLevel::EnvelopeRecognized: return "envelope_recognized";
    case SupportLevel::TransportDecoded: return "transport_decoded";
    case SupportLevel::StructuralSchemaRecovered: return "structural_schema_recovered";
    }
    return "unknown";
}

std::string_view toString(RecordLaneKind kind)
{
    switch (kind)
    {
    case RecordLaneKind::ConstantPoolMode: return "constant_pool_mode";
    case RecordLaneKind::ConstantCount: return "constant_count";
    case RecordLaneKind::ConstantTag: return "constant_tag";
    case RecordLaneKind::ConstantPayload: return "constant_payload";
    case RecordLaneKind::PrototypeCount: return "prototype_count";
    case RecordLaneKind::PrototypeRecord: return "prototype_record";
    case RecordLaneKind::DescriptorCount: return "descriptor_count";
    case RecordLaneKind::DescriptorRecord: return "descriptor_record";
    case RecordLaneKind::PrototypeMetadata: return "prototype_metadata";
    case RecordLaneKind::RangeMapCount: return "range_map_count";
    case RecordLaneKind::RangeMapRecord: return "range_map_record";
    case RecordLaneKind::InstructionCount: return "instruction_count";
    case RecordLaneKind::InstructionWords: return "instruction_words";
    case RecordLaneKind::RelocationTriple: return "relocation_triple";
    case RecordLaneKind::RootSelector: return "root_selector";
    }
    return "unknown";
}

std::string_view toString(ConstantKind kind)
{
    switch (kind)
    {
    case ConstantKind::Opaque: return "opaque";
    case ConstantKind::String: return "string";
    case ConstantKind::Integer: return "integer";
    case ConstantKind::Boolean: return "boolean";
    case ConstantKind::Float: return "float";
    case ConstantKind::Nil: return "nil";
    }
    return "unknown";
}

std::string_view toString(StageKind kind)
{
    switch (kind)
    {
    case StageKind::ProtectionBanner: return "protection_banner";
    case StageKind::WrapperConstruction: return "wrapper_construction";
    case StageKind::EncodedPayload: return "encoded_payload";
    case StageKind::ReaderSetup: return "reader_setup";
    case StageKind::InterpreterScaffolding: return "interpreter_scaffolding";
    case StageKind::EntrypointDispatch: return "entrypoint_dispatch";
    }
    return "unknown";
}

std::string_view toString(ConfidenceLevel level)
{
    switch (level)
    {
    case ConfidenceLevel::None: return "none";
    case ConfidenceLevel::Low: return "low";
    case ConfidenceLevel::Medium: return "medium";
    case ConfidenceLevel::High: return "high";
    }
    return "unknown";
}

} // namespace alex::deobfuscator::luraph
