#include "core/deob.hpp"
#include "luraph/call_semantics.hpp"
#include "luraph/index_read_semantics.hpp"
#include "luraph/range_clear_semantics.hpp"
#include "luraph/scan.hpp"
#include "luraph/emit.hpp"
#include "luraph/vm.hpp"
#include "prometheus/lift.hpp"
#include "passes/flow.hpp"
#include "passes/fields.hpp"
#include "runtime/register_overflow.hpp"

#include "alex/antitamper.hpp"

#include "Luau/Allocator.h"
#include "Luau/Ast.h"
#include "Luau/Compiler.h"
#include "Luau/Lexer.h"
#include "Luau/Parser.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <queue>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace alex::deobfuscator
{
namespace
{

namespace fs = std::filesystem;
using json = nlohmann::json;

constexpr size_t kMaxInputBytes = 1536 * 1024;
constexpr size_t kMaxDecodedConstants = 200000;
constexpr size_t kMaxCfgStates = 250000;
constexpr uint64_t kLuraphActivationTraceRowLimit = 262144;
constexpr size_t kLuraphActivationArgumentTableEntryLimit = 4096;

std::string readFile(const fs::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
        throw std::runtime_error("could not read input file");
    std::ostringstream output;
    output << stream.rdbuf();
    return output.str();
}

void writeFile(const fs::path& path, std::string_view value)
{
    fs::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream)
        throw std::runtime_error("could not write output artifact");
    stream.write(value.data(), static_cast<std::streamsize>(value.size()));
}

void writeJson(const fs::path& path, const json& value)
{
    writeFile(path, value.dump(2) + "\n");
}

std::string sha256(std::string_view value)
{
    return alex::antitamper::hex(alex::antitamper::sha256(value));
}

bool isIdentifierStart(char ch)
{
    return ch == '_' || std::isalpha(static_cast<unsigned char>(ch));
}

bool isIdentifier(char ch)
{
    return ch == '_' || std::isalnum(static_cast<unsigned char>(ch));
}

std::string trim(std::string_view value)
{
    size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first])))
        ++first;
    size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1])))
        --last;
    return std::string(value.substr(first, last - first));
}

std::string hexBytes(std::string_view value)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned char ch : value)
        out << std::setw(2) << static_cast<unsigned int>(ch);
    return out.str();
}

bool printableAscii(std::string_view value)
{
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) { return ch == '\n' || ch == '\r' || ch == '\t' || (ch >= 32 && ch <= 126); });
}

std::string quoteLuau(std::string_view value)
{
    std::string out = "\"";
    for (unsigned char ch : value)
    {
        switch (ch)
        {
        case '\\': out += "\\\\"; break;
        case '\"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 32 || ch == 127 || ch >= 128)
            {
                char buffer[5];
                std::snprintf(buffer, sizeof(buffer), "\\%03u", static_cast<unsigned int>(ch));
                out += buffer;
            }
            else
                out += static_cast<char>(ch);
        }
    }
    out += '"';
    return out;
}

class NumericParser
{
public:
    explicit NumericParser(std::string_view source)
        : source(source)
    {
    }

    std::optional<double> parse()
    {
        try
        {
            double result = expression();
            skip();
            if (position != source.size() || !std::isfinite(result))
                return std::nullopt;
            return result;
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

private:
    std::string_view source;
    size_t position = 0;

    void skip()
    {
        while (position < source.size() && std::isspace(static_cast<unsigned char>(source[position])))
            ++position;
    }

    bool take(char ch)
    {
        skip();
        if (position < source.size() && source[position] == ch)
        {
            ++position;
            return true;
        }
        return false;
    }

    double expression()
    {
        double value = term();
        while (true)
        {
            if (take('+'))
                value += term();
            else if (take('-'))
                value -= term();
            else
                return value;
        }
    }

    double term()
    {
        double value = power();
        while (true)
        {
            if (take('*'))
                value *= power();
            else if (take('/'))
                value /= power();
            else if (take('%'))
            {
                double rhs = power();
                value = std::fmod(value, rhs);
            }
            else
                return value;
        }
    }

    double power()
    {
        double value = unary();
        if (take('^'))
            value = std::pow(value, power());
        return value;
    }

    double unary()
    {
        if (take('+'))
            return unary();
        if (take('-'))
            return -unary();
        return primary();
    }

    double primary()
    {
        skip();
        if (take('('))
        {
            double value = expression();
            if (!take(')'))
                throw std::runtime_error("missing numeric close parenthesis");
            return value;
        }
        skip();
        size_t start = position;
        while (position < source.size() && (std::isdigit(static_cast<unsigned char>(source[position])) || source[position] == '.'))
            ++position;
        if (start == position)
            throw std::runtime_error("expected number");
        return std::stod(std::string(source.substr(start, position - start)));
    }
};

std::optional<int64_t> numericInteger(std::string_view expression)
{
    auto value = NumericParser(expression).parse();
    if (!value || std::abs(*value - std::round(*value)) > 1e-7 || *value < static_cast<double>(std::numeric_limits<int64_t>::min()) ||
        *value > static_cast<double>(std::numeric_limits<int64_t>::max()))
        return std::nullopt;
    return static_cast<int64_t>(std::llround(*value));
}

struct ParsedString
{
    std::string value;
    size_t end = 0;
};

ParsedString parseShortString(std::string_view source, size_t start)
{
    if (start >= source.size() || (source[start] != '\'' && source[start] != '"'))
        throw std::runtime_error("not a short string");
    char quote = source[start];
    std::string out;
    size_t i = start + 1;
    while (i < source.size())
    {
        char ch = source[i];
        if (ch == quote)
            return {out, i + 1};
        if (ch != '\\')
        {
            out += ch;
            ++i;
            continue;
        }
        ++i;
        if (i >= source.size())
            break;
        ch = source[i];
        if (std::isdigit(static_cast<unsigned char>(ch)))
        {
            unsigned int value = 0;
            size_t count = 0;
            while (i < source.size() && count < 3 && std::isdigit(static_cast<unsigned char>(source[i])))
            {
                value = value * 10 + static_cast<unsigned int>(source[i] - '0');
                ++i;
                ++count;
            }
            out += static_cast<char>(value & 0xff);
            continue;
        }
        switch (ch)
        {
        case 'a': out += '\a'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'v': out += '\v'; break;
        case '\\': out += '\\'; break;
        case '\"': out += '\"'; break;
        case '\'': out += '\''; break;
        default: out += ch; break;
        }
        ++i;
    }
    throw std::runtime_error("unterminated short string");
}

size_t findBalanced(std::string_view source, size_t start, char open, char close)
{
    int depth = 0;
    for (size_t i = start; i < source.size(); ++i)
    {
        if (source[i] == '\'' || source[i] == '"')
        {
            i = parseShortString(source, i).end - 1;
            continue;
        }
        if (source[i] == open)
            ++depth;
        else if (source[i] == close && --depth == 0)
            return i;
    }
    throw std::runtime_error("unbalanced source delimiter");
}

std::string decodeShortStrings(std::string_view source)
{
    std::string out;
    out.reserve(source.size());
    for (size_t i = 0; i < source.size();)
    {
        if (source[i] == '\'' || source[i] == '"')
        {
            ParsedString parsed = parseShortString(source, i);
            out += quoteLuau(parsed.value);
            i = parsed.end;
        }
        else
            out += source[i++];
    }
    return out;
}

std::vector<std::string> parseQuotedValues(std::string_view source)
{
    std::vector<std::string> values;
    for (size_t i = 0; i < source.size();)
    {
        if (source[i] == '\'' || source[i] == '"')
        {
            ParsedString parsed = parseShortString(source, i);
            values.push_back(std::move(parsed.value));
            i = parsed.end;
        }
        else
            ++i;
    }
    return values;
}

struct ParseContext
{
    Luau::Allocator allocator;
    Luau::AstNameTable names{allocator};
    Luau::ParseResult result;
};

std::unique_ptr<ParseContext> parseSource(std::string_view source)
{
    auto context = std::make_unique<ParseContext>();
    context->result = Luau::Parser::parse(source.data(), source.size(), context->names, context->allocator);
    return context;
}

json parseErrors(const Luau::ParseResult& result)
{
    json errors = json::array();
    for (const Luau::ParseError& error : result.errors)
    {
        errors.push_back({
            {"code", "luau_parse_error"},
            {"message", error.getMessage()},
            {"line", error.getLocation().begin.line + 1},
            {"column", error.getLocation().begin.column + 1},
        });
    }
    return errors;
}

std::optional<double> evaluateAstNumber(Luau::AstExpr* expression)
{
    if (!expression)
        return std::nullopt;
    if (auto node = expression->as<Luau::AstExprConstantNumber>())
        return node->value;
    if (auto node = expression->as<Luau::AstExprConstantInteger>())
        return static_cast<double>(node->value);
    if (auto node = expression->as<Luau::AstExprGroup>())
        return evaluateAstNumber(node->expr);
    if (auto node = expression->as<Luau::AstExprTypeAssertion>())
        return evaluateAstNumber(node->expr);
    if (auto node = expression->as<Luau::AstExprUnary>())
    {
        auto value = evaluateAstNumber(node->expr);
        if (!value || node->op != Luau::AstExprUnary::Op::Minus)
            return std::nullopt;
        return -*value;
    }
    if (auto node = expression->as<Luau::AstExprBinary>())
    {
        auto left = evaluateAstNumber(node->left);
        auto right = evaluateAstNumber(node->right);
        if (!left || !right)
            return std::nullopt;
        switch (node->op)
        {
        case Luau::AstExprBinary::Add: return *left + *right;
        case Luau::AstExprBinary::Sub: return *left - *right;
        case Luau::AstExprBinary::Mul: return *left * *right;
        case Luau::AstExprBinary::Div: return *left / *right;
        case Luau::AstExprBinary::FloorDiv: return std::floor(*left / *right);
        case Luau::AstExprBinary::Mod: return std::fmod(*left, *right);
        case Luau::AstExprBinary::Pow: return std::pow(*left, *right);
        default: return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<int64_t> evaluateAstInteger(Luau::AstExpr* expression)
{
    auto value = evaluateAstNumber(expression);
    if (!value || !std::isfinite(*value) || std::abs(*value - std::round(*value)) > 1e-7)
        return std::nullopt;
    return static_cast<int64_t>(std::llround(*value));
}

struct AstMetrics : Luau::AstVisitor
{
    size_t nodes = 0;
    size_t functions = 0;
    size_t whiles = 0;
    size_t conditionals = 0;
    size_t tables = 0;
    size_t calls = 0;
    size_t assignments = 0;
    size_t varargs = 0;

    bool visit(Luau::AstNode*) override
    {
        ++nodes;
        return true;
    }
    bool visit(Luau::AstExprFunction* node) override
    {
        ++nodes;
        ++functions;
        return true;
    }
    bool visit(Luau::AstStatWhile* node) override
    {
        ++nodes;
        ++whiles;
        return true;
    }
    bool visit(Luau::AstStatIf* node) override
    {
        ++nodes;
        ++conditionals;
        return true;
    }
    bool visit(Luau::AstExprTable* node) override
    {
        ++nodes;
        ++tables;
        return true;
    }
    bool visit(Luau::AstExprCall* node) override
    {
        ++nodes;
        ++calls;
        return true;
    }
    bool visit(Luau::AstStatAssign* node) override
    {
        ++nodes;
        ++assignments;
        return true;
    }
    bool visit(Luau::AstExprVarargs* node) override
    {
        ++nodes;
        ++varargs;
        return true;
    }
};

std::string constantString(Luau::AstExpr* expression)
{
    if (auto value = expression ? expression->as<Luau::AstExprConstantString>() : nullptr)
        return std::string(value->value.data, value->value.size);
    return {};
}

struct AlphabetCollector : Luau::AstVisitor
{
    std::map<unsigned char, int> alphabet;
    std::map<unsigned char, int> alphabet85;

    bool visit(Luau::AstExprTable* node) override
    {
        const size_t size = node->items.size;
        if ((size != 64 && size != 85) || (size == 64 && !alphabet.empty()) || (size == 85 && !alphabet85.empty()))
            return true;
        std::map<unsigned char, int> candidate;
        std::set<int> values;
        for (const auto& item : node->items)
        {
            std::string key = constantString(item.key);
            auto value = evaluateAstInteger(item.value);
            if (key.size() != 1 || !value || *value < 0 || *value >= static_cast<int64_t>(size))
                return true;
            candidate[static_cast<unsigned char>(key[0])] = static_cast<int>(*value);
            values.insert(static_cast<int>(*value));
        }
        if (candidate.size() == size && values.size() == size && *values.begin() == 0 && *values.rbegin() == static_cast<int>(size - 1))
        {
            if (size == 64)
                alphabet = std::move(candidate);
            else
                alphabet85 = std::move(candidate);
        }
        return true;
    }
};

struct Envelope
{
    std::string decoded_literals;
    std::string rewritten;
    std::string compact;
    std::string table_name;
    std::string lookup_name;
    int64_t lookup_offset = 0;
    std::vector<std::pair<int64_t, int64_t>> reversal_ranges;
    std::vector<std::string> encoded;
    std::vector<std::string> constants;
    size_t replacements = 0;
};

std::pair<std::string, std::vector<std::string>> extractInitialTable(std::string_view source)
{
    static const std::regex marker(R"(return\s*\(\s*function\s*\(\s*\.\.\.\s*\)\s*local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=)");
    std::cmatch match;
    if (!std::regex_search(source.begin(), source.end(), match, marker))
        throw std::runtime_error("initial encoded table was not found");
    std::string name = match[1].str();
    size_t start = static_cast<size_t>(match.position(0) + match.length(0));
    size_t brace = source.find('{', start);
    if (brace == std::string_view::npos)
        throw std::runtime_error("encoded table has no body");
    size_t end = findBalanced(source, brace, '{', '}');
    return {name, parseQuotedValues(source.substr(brace + 1, end - brace - 1))};
}

std::vector<std::string> splitTopLevel(std::string_view source, char separator)
{
    std::vector<std::string> values;
    size_t start = 0;
    int round = 0;
    int square = 0;
    int curly = 0;
    for (size_t i = 0; i < source.size(); ++i)
    {
        if (source[i] == '\'' || source[i] == '"')
        {
            i = parseShortString(source, i).end - 1;
            continue;
        }
        switch (source[i])
        {
        case '(': ++round; break;
        case ')': --round; break;
        case '[': ++square; break;
        case ']': --square; break;
        case '{': ++curly; break;
        case '}': --curly; break;
        default: break;
        }
        if (source[i] == separator && round == 0 && square == 0 && curly == 0)
        {
            values.push_back(trim(source.substr(start, i - start)));
            start = i + 1;
        }
    }
    values.push_back(trim(source.substr(start)));
    return values;
}

std::vector<std::pair<int64_t, int64_t>> extractRanges(std::string_view source)
{
    std::vector<std::pair<int64_t, int64_t>> ranges;
    size_t marker = source.find("ipairs({");
    if (marker == std::string_view::npos)
        return ranges;
    size_t outer = source.find('{', marker);
    size_t end = findBalanced(source, outer, '{', '}');
    std::string_view body = source.substr(outer + 1, end - outer - 1);
    for (size_t i = 0; i < body.size(); ++i)
    {
        if (body[i] != '{')
            continue;
        size_t close = findBalanced(body, i, '{', '}');
        std::vector<std::string> pair = splitTopLevel(body.substr(i + 1, close - i - 1), ',');
        if (pair.size() == 1)
            pair = splitTopLevel(body.substr(i + 1, close - i - 1), ';');
        if (pair.size() == 2)
        {
            auto left = numericInteger(pair[0]);
            auto right = numericInteger(pair[1]);
            if (left && right)
                ranges.emplace_back(*left, *right);
        }
        i = close;
    }
    return ranges;
}

void applyRanges(std::vector<std::string>& values, const std::vector<std::pair<int64_t, int64_t>>& ranges)
{
    for (auto [leftValue, rightValue] : ranges)
    {
        if (leftValue < 1 || rightValue < 1 || static_cast<size_t>(leftValue) > values.size() || static_cast<size_t>(rightValue) > values.size())
            throw std::runtime_error("encoded table permutation is out of range");
        size_t left = static_cast<size_t>(leftValue - 1);
        size_t right = static_cast<size_t>(rightValue - 1);
        while (left < right)
            std::swap(values[left++], values[right--]);
    }
}

std::tuple<std::string, int64_t> extractLookup(std::string_view source, const std::string& tableName)
{
    const std::string needle = "return " + tableName + "[";
    size_t position = source.find(needle);
    if (position == std::string_view::npos)
        throw std::runtime_error("constant lookup function was not found");
    size_t function = source.rfind("local function ", position);
    if (function == std::string_view::npos)
        throw std::runtime_error("constant lookup declaration was not found");
    size_t nameStart = function + std::string_view("local function ").size();
    size_t nameEnd = nameStart;
    while (nameEnd < source.size() && isIdentifier(source[nameEnd]))
        ++nameEnd;
    std::string functionName(source.substr(nameStart, nameEnd - nameStart));
    size_t openArg = source.find('(', nameEnd);
    size_t closeArg = source.find(')', openArg);
    std::string argument = trim(source.substr(openArg + 1, closeArg - openArg - 1));
    size_t bracketStart = position + needle.size();
    size_t bracketEnd = findBalanced(source, position + needle.size() - 1, '[', ']');
    std::string index = trim(source.substr(bracketStart, bracketEnd - bracketStart));
    if (index.rfind(argument, 0) != 0)
        throw std::runtime_error("constant lookup index does not use its argument");
    std::string remainder = trim(std::string_view(index).substr(argument.size()));
    int sign = 0;
    if (!remainder.empty() && remainder[0] == '-')
        sign = 1;
    else if (!remainder.empty() && remainder[0] == '+')
        sign = -1;
    else
        throw std::runtime_error("constant lookup offset was not recognized");
    std::string offsetExpression = trim(std::string_view(remainder).substr(1));
    auto offset = numericInteger(offsetExpression);
    if (!offset)
        throw std::runtime_error("constant lookup offset is not constant");
    return {functionName, sign * *offset};
}

std::string decodeCustomBase64(std::string_view source, const std::map<unsigned char, int>& alphabet)
{
    std::string output;
    uint32_t accumulator = 0;
    int count = 0;
    for (size_t i = 0; i < source.size(); ++i)
    {
        unsigned char ch = static_cast<unsigned char>(source[i]);
        auto found = alphabet.find(ch);
        if (found != alphabet.end())
        {
            accumulator += static_cast<uint32_t>(found->second) * static_cast<uint32_t>(std::pow(64, 3 - count));
            if (++count == 4)
            {
                output += static_cast<char>((accumulator >> 16) & 0xff);
                output += static_cast<char>((accumulator >> 8) & 0xff);
                output += static_cast<char>(accumulator & 0xff);
                accumulator = 0;
                count = 0;
            }
        }
        else if (ch == '=')
        {
            output += static_cast<char>((accumulator >> 16) & 0xff);
            if (i + 1 >= source.size() || source[i + 1] != '=')
                output += static_cast<char>((accumulator >> 8) & 0xff);
            break;
        }
    }
    return output;
}

std::string decodeCustomBase85(std::string_view source, const std::map<unsigned char, int>& alphabet)
{
    std::string output;
    for (size_t position = 0; position < source.size();)
    {
        const size_t chunkSize = std::min<size_t>(5, source.size() - position);
        if (chunkSize <= 1)
            break;

        uint64_t accumulator = 0;
        bool valid = true;
        for (size_t digit = 0; digit < 5; ++digit)
        {
            int value = 84;
            if (digit < chunkSize)
            {
                auto found = alphabet.find(static_cast<unsigned char>(source[position + digit]));
                if (found == alphabet.end())
                {
                    valid = false;
                    break;
                }
                value = found->second;
            }
            accumulator = accumulator * 85 + static_cast<uint64_t>(value);
        }

        if (valid)
        {
            const char bytes[] = {
                static_cast<char>((accumulator / 16777216) % 256),
                static_cast<char>((accumulator / 65536) % 256),
                static_cast<char>((accumulator / 256) % 256),
                static_cast<char>(accumulator % 256),
            };
            output.append(bytes, chunkSize - 1);
        }
        position += chunkSize;
    }
    return output;
}

std::string decodeEncodedString(
    std::string_view source,
    const std::map<unsigned char, int>& alphabet64,
    const std::map<unsigned char, int>& alphabet85)
{
    if (source.empty())
        return {};
    if (source.front() == '6')
        return decodeCustomBase64(source.substr(1), alphabet64);
    if (source.front() == 'O')
        return decodeCustomBase85(source.substr(1), alphabet85);
    throw std::runtime_error("encoded constant has an unknown string codec marker");
}

std::pair<std::string, size_t> replaceLookupCalls(std::string_view source, const std::string& lookupName, int64_t offset, const std::vector<std::string>& constants)
{
    std::string output;
    size_t replacements = 0;
    const std::string marker = lookupName + "(";
    for (size_t i = 0; i < source.size();)
    {
        if (source.substr(i, marker.size()) == marker && (i == 0 || !isIdentifier(source[i - 1])))
        {
            size_t open = i + lookupName.size();
            size_t close = findBalanced(source, open, '(', ')');
            auto expression = numericInteger(source.substr(open + 1, close - open - 1));
            if (expression)
            {
                int64_t index = *expression - offset;
                if (index >= 1 && static_cast<size_t>(index) <= constants.size())
                {
                    output += quoteLuau(constants[static_cast<size_t>(index - 1)]);
                    ++replacements;
                    i = close + 1;
                    continue;
                }
            }
        }
        output += source[i++];
    }
    return {output, replacements};
}

Envelope decodeEnvelope(std::string_view source)
{
    Envelope envelope;
    envelope.decoded_literals = decodeShortStrings(source);
    auto [tableName, values] = extractInitialTable(envelope.decoded_literals);
    envelope.table_name = tableName;
    envelope.encoded = std::move(values);
    envelope.reversal_ranges = extractRanges(envelope.decoded_literals);
    applyRanges(envelope.encoded, envelope.reversal_ranges);
    std::tie(envelope.lookup_name, envelope.lookup_offset) = extractLookup(envelope.decoded_literals, envelope.table_name);

    auto decodedAst = parseSource(envelope.decoded_literals);
    if (!decodedAst->result.errors.empty())
        throw std::runtime_error("decoded wrapper did not parse");
    AlphabetCollector collector;
    decodedAst->result.root->visit(&collector);
    if (collector.alphabet.size() != 64)
        throw std::runtime_error("custom 64-character alphabet was not found");

    const bool needsBase85 = std::any_of(envelope.encoded.begin(), envelope.encoded.end(), [](const std::string& value) {
        return !value.empty() && value.front() == 'O';
    });
    if (needsBase85 && collector.alphabet85.size() != 85)
        throw std::runtime_error("custom 85-character alphabet was not found");

    if (envelope.encoded.size() > kMaxDecodedConstants)
        throw std::runtime_error("decoded constant limit exceeded");
    for (const std::string& value : envelope.encoded)
        envelope.constants.push_back(decodeEncodedString(value, collector.alphabet, collector.alphabet85));
    std::tie(envelope.rewritten, envelope.replacements) = replaceLookupCalls(
        envelope.decoded_literals, envelope.lookup_name, envelope.lookup_offset, envelope.constants);

    static const std::regex iifeStart(R"(return\s*\(\s*function\s*\()");
    size_t second = std::string::npos;
    size_t matches = 0;
    for (std::sregex_iterator it(envelope.rewritten.begin(), envelope.rewritten.end(), iifeStart), end; it != end; ++it)
    {
        if (++matches == 2)
        {
            second = static_cast<size_t>(it->position());
            break;
        }
    }
    envelope.compact = second == std::string::npos ? envelope.rewritten : envelope.rewritten.substr(second);
    static const std::regex outerIifeTail(R"(end\s*\)\s*\(\s*\.\.\.\s*\)\s*$)");
    std::smatch outerTail;
    if (std::regex_search(envelope.compact, outerTail, outerIifeTail))
        envelope.compact.erase(static_cast<size_t>(outerTail.position()));
    return envelope;
}

class SourceView
{
public:
    explicit SourceView(std::string_view source)
        : source(source)
    {
        lineOffsets.push_back(0);
        for (size_t i = 0; i < source.size(); ++i)
            if (source[i] == '\n')
                lineOffsets.push_back(i + 1);
    }

    size_t offset(const Luau::Position& position) const
    {
        if (position.line >= lineOffsets.size())
            return source.size();
        return std::min(source.size(), lineOffsets[position.line] + position.column);
    }

    std::string slice(const Luau::Location& location, size_t limit = 4096) const
    {
        size_t begin = offset(location.begin);
        size_t end = offset(location.end);
        if (end < begin)
            end = begin;
        end = std::min(end, begin + limit);
        return std::string(source.substr(begin, end - begin));
    }

private:
    std::string_view source;
    std::vector<size_t> lineOffsets;
};

struct IfCounter : Luau::AstVisitor
{
    size_t count = 0;
    bool visit(Luau::AstStatIf*) override
    {
        ++count;
        return true;
    }
};

struct WhileCandidate
{
    Luau::AstStatWhile* node = nullptr;
    Luau::AstLocal* state = nullptr;
    size_t conditionals = 0;
};

struct WhileCollector : Luau::AstVisitor
{
    std::vector<WhileCandidate> candidates;

    bool visit(Luau::AstStatWhile* node) override
    {
        auto local = node->condition ? node->condition->as<Luau::AstExprLocal>() : nullptr;
        if (local)
        {
            IfCounter counter;
            node->body->visit(&counter);
            candidates.push_back({node, local->local, counter.count});
        }
        return true;
    }
};

std::string traceMarker(std::string_view source)
{
    return "[ALEX_WD_STATE:" + sha256(source).substr(0, 16) + "]";
}

std::string snapshotMarker(std::string_view source)
{
    return "[ALEX_WD_SNAPSHOT:" + sha256(source).substr(0, 16) + "]";
}

std::string buildTraceProbe(std::string_view compact, std::string_view marker)
{
    auto parsed = parseSource(compact);
    if (!parsed->result.errors.empty())
        throw std::runtime_error("trace probe source did not parse");
    WhileCollector whiles;
    parsed->result.root->visit(&whiles);
    auto best = std::max_element(whiles.candidates.begin(), whiles.candidates.end(), [](const WhileCandidate& left, const WhileCandidate& right) {
        return left.conditionals < right.conditionals;
    });
    if (best == whiles.candidates.end() || !best->node || !best->state || best->conditionals < 8 || !best->state->name.value)
        throw std::runtime_error("trace probe dispatcher was not found");

    std::string probe(compact);
    const std::string stateName(best->state->name.value);
    const std::regex dispatcherLoop("\\bwhile\\s+" + stateName + "\\s+do\\s+if\\b");
    std::smatch match;
    if (!std::regex_search(probe, match, dispatcherLoop))
        throw std::runtime_error("trace probe dispatcher text was not found");
    const std::string matched = match.str();
    const size_t finalIf = matched.rfind("if");
    if (finalIf == std::string::npos)
        throw std::runtime_error("trace probe insertion point was not found");
    const size_t insertAt = static_cast<size_t>(match.position()) + finalIf;
    probe.insert(insertAt, "print(" + quoteLuau(marker) + "," + std::string(best->state->name.value) + ") ");
    probe.insert(0, "--[[ Alex native offline state probe; line count intentionally preserved. ]] ");
    std::string bytecode = Luau::compile(probe);
    if (bytecode.empty() || bytecode[0] == 0)
        throw std::runtime_error("trace probe did not compile");
    return probe;
}

struct SnapshotBinding
{
    std::string normalized;
    std::string source;
    bool cell = false;
};

std::string buildSnapshotTraceProbe(
    std::string_view compact,
    std::string_view stateMarker,
    std::string_view cellMarker,
    int64_t payloadState,
    std::string_view cellsName,
    const std::vector<SnapshotBinding>& bindings)
{
    auto parsed = parseSource(compact);
    if (!parsed->result.errors.empty())
        throw std::runtime_error("snapshot probe source did not parse");
    WhileCollector whiles;
    parsed->result.root->visit(&whiles);
    auto best = std::max_element(whiles.candidates.begin(), whiles.candidates.end(), [](const WhileCandidate& left, const WhileCandidate& right) {
        return left.conditionals < right.conditionals;
    });
    if (best == whiles.candidates.end() || !best->node || !best->state || best->conditionals < 8 || !best->state->name.value)
        throw std::runtime_error("snapshot probe dispatcher was not found");
    auto validName = [](std::string_view name) {
        return !name.empty() && isIdentifierStart(name.front()) && std::all_of(name.begin() + 1, name.end(), isIdentifier);
    };
    if (!validName(cellsName))
        throw std::runtime_error("snapshot probe cell storage name is invalid");
    for (const SnapshotBinding& binding : bindings)
        if (!validName(binding.normalized) || !validName(binding.source))
            throw std::runtime_error("snapshot probe binding name is invalid");

    std::string probe(compact);
    const std::string stateName(best->state->name.value);
    const std::regex dispatcherLoop("\\bwhile\\s+" + stateName + "\\s+do\\s+if\\b");
    std::smatch match;
    if (!std::regex_search(probe, match, dispatcherLoop))
        throw std::runtime_error("snapshot probe dispatcher text was not found");
    const size_t finalIf = match.str().rfind("if");
    if (finalIf == std::string::npos)
        throw std::runtime_error("snapshot probe insertion point was not found");
    const size_t insertAt = static_cast<size_t>(match.position()) + finalIf;
    const std::string suffix = sha256(cellMarker).substr(0, 8);
    const std::string keyName = "__axk_" + suffix;
    const std::string valueName = "__axv_" + suffix;
    const std::string keyTypeName = "__axkt_" + suffix;
    const std::string valueTypeName = "__axvt_" + suffix;
    const std::string byteName = "__axb_" + suffix;
    auto encodedValue = [&byteName](const std::string& expression) {
        return "(type(" + expression + ")==\"string\" and (string.gsub(" + expression +
               ",\".\",function(" + byteName + ")return string.format(\"%02x\",string.byte(" + byteName + "))end)) or tostring(" + expression +
               "))";
    };

    std::string insertion = "print(" + quoteLuau(stateMarker) + "," + stateName + ") ";
    insertion += "if " + stateName + "==" + std::to_string(payloadState) + " then ";
    insertion += "print(" + quoteLuau(cellMarker) + ",\"begin\") ";
    for (const SnapshotBinding& binding : bindings)
    {
        const std::string value = binding.cell ? std::string(cellsName) + "[" + binding.source + "]" : binding.source;
        const std::string scope = binding.cell ? "cell" : "register";
        insertion += "print(" + quoteLuau(cellMarker) + ",\"value\"," + quoteLuau(scope) + "," + quoteLuau(binding.normalized) +
                     ",type(" + value + ")," + encodedValue(value) + ") ";
        insertion += "if type(" + value + ")==\"table\" then for " + keyName + "," + valueName + " in pairs(" + value + ") do ";
        insertion += "local " + keyTypeName + "=type(" + keyName + ") local " + valueTypeName + "=type(" + valueName + ") ";
        insertion += "if (" + keyTypeName + "==\"number\" or " + keyTypeName + "==\"string\" or " + keyTypeName + "==\"boolean\") and ";
        insertion += "(" + valueTypeName + "==\"number\" or " + valueTypeName + "==\"string\" or " + valueTypeName + "==\"boolean\") then ";
        insertion += "print(" + quoteLuau(cellMarker) + ",\"item\"," + quoteLuau(scope) + "," + quoteLuau(binding.normalized) + "," + keyTypeName + "," +
                     encodedValue(keyName) + "," + valueTypeName + "," + encodedValue(valueName) + ") end end end ";
    }
    insertion += "print(" + quoteLuau(cellMarker) + ",\"end\") end ";
    probe.insert(insertAt, insertion);
    probe.insert(0, "--[[ Alex native offline payload snapshot; line count intentionally preserved. ]] ");
    std::string bytecode = Luau::compile(probe);
    if (bytecode.empty() || bytecode[0] == 0)
        throw std::runtime_error("snapshot probe did not compile");
    return probe;
}

std::vector<int64_t> parseTraceStates(const fs::path& path, std::string_view marker)
{
    std::vector<int64_t> states;
    if (path.empty() || !fs::exists(path))
        return states;
    std::istringstream lines(readFile(path));
    std::string line;
    while (std::getline(lines, line))
    {
        if (!line.starts_with(marker))
            continue;
        std::string_view tail(line);
        tail.remove_prefix(marker.size());
        while (!tail.empty() && std::isspace(static_cast<unsigned char>(tail.front())))
            tail.remove_prefix(1);
        int64_t state = 0;
        const char* begin = tail.data();
        const char* end = begin + tail.size();
        auto parsed = std::from_chars(begin, end, state);
        if (parsed.ec == std::errc{} && parsed.ptr != begin)
            states.push_back(state);
        if (states.size() >= 250000)
            break;
    }
    return states;
}

struct SnapshotCell
{
    std::string type;
    std::optional<json> scalar;
    std::vector<std::pair<json, json>> items;
};

struct RuntimeSnapshot
{
    bool began = false;
    bool ended = false;
    size_t rows = 0;
    std::map<std::string, SnapshotCell> cells;
    std::map<std::string, SnapshotCell> registers;

    bool boundaryComplete() const
    {
        return began && ended;
    }
};

std::vector<std::string> splitTabs(std::string_view line)
{
    std::vector<std::string> fields;
    size_t start = 0;
    while (start <= line.size())
    {
        size_t end = line.find('\t', start);
        if (end == std::string_view::npos)
            end = line.size();
        fields.emplace_back(line.substr(start, end - start));
        if (end == line.size())
            break;
        start = end + 1;
    }
    return fields;
}

std::optional<json> snapshotAtom(std::string_view type, std::string_view encoded)
{
    if (type == "string")
    {
        if (encoded.size() % 2 != 0)
            return std::nullopt;
        std::string decoded;
        decoded.reserve(encoded.size() / 2);
        for (size_t index = 0; index < encoded.size(); index += 2)
        {
            unsigned int value = 0;
            const char* begin = encoded.data() + index;
            const char* end = begin + 2;
            auto parsed = std::from_chars(begin, end, value, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != end || value > 255)
                return std::nullopt;
            decoded.push_back(static_cast<char>(value));
        }
        if (printableAscii(decoded))
            return json{{"op", "constant"}, {"kind", "string"}, {"value", decoded}};
        return json{{"op", "constant"}, {"kind", "bytes"}, {"hex", hexBytes(decoded)}};
    }
    if (type == "boolean")
    {
        if (encoded == "true" || encoded == "false")
            return json{{"op", "constant"}, {"value", encoded == "true"}};
        return std::nullopt;
    }
    if (type == "number")
    {
        try
        {
            size_t consumed = 0;
            double value = std::stod(std::string(encoded), &consumed);
            if (consumed == encoded.size() && std::isfinite(value))
                return json{{"op", "constant"}, {"value", value}};
        }
        catch (...)
        {
        }
    }
    return std::nullopt;
}

RuntimeSnapshot parseRuntimeSnapshot(const fs::path& path, std::string_view marker)
{
    RuntimeSnapshot snapshot;
    if (path.empty() || !fs::exists(path))
        return snapshot;
    std::istringstream lines(readFile(path));
    std::string line;
    while (std::getline(lines, line))
    {
        if (!line.starts_with(marker))
            continue;
        std::vector<std::string> fields = splitTabs(line);
        if (fields.size() < 2 || fields[0] != marker)
            continue;
        if (fields[1] == "begin")
        {
            snapshot.began = true;
            continue;
        }
        if (fields[1] == "end")
        {
            snapshot.ended = true;
            continue;
        }
        if (fields[1] == "value" && fields.size() == 6)
        {
            std::map<std::string, SnapshotCell>& storage = fields[2] == "cell" ? snapshot.cells : snapshot.registers;
            SnapshotCell& cell = storage[fields[3]];
            cell.type = fields[4];
            cell.scalar = snapshotAtom(fields[4], fields[5]);
            ++snapshot.rows;
        }
        else if (fields[1] == "item" && fields.size() == 8)
        {
            auto key = snapshotAtom(fields[4], fields[5]);
            auto value = snapshotAtom(fields[6], fields[7]);
            if (key && value)
            {
                std::map<std::string, SnapshotCell>& storage = fields[2] == "cell" ? snapshot.cells : snapshot.registers;
                SnapshotCell& cell = storage[fields[3]];
                cell.type = "table";
                cell.items.emplace_back(std::move(*key), std::move(*value));
                ++snapshot.rows;
            }
        }
    }
    return snapshot;
}

void collectIntegerChoices(Luau::AstExpr* expression, std::set<int64_t>& values)
{
    if (!expression)
        return;
    if (auto value = evaluateAstInteger(expression))
    {
        values.insert(*value);
        return;
    }
    if (auto binary = expression->as<Luau::AstExprBinary>())
    {
        if (binary->op == Luau::AstExprBinary::And || binary->op == Luau::AstExprBinary::Or)
        {
            collectIntegerChoices(binary->left, values);
            collectIntegerChoices(binary->right, values);
        }
    }
    else if (auto group = expression->as<Luau::AstExprGroup>())
        collectIntegerChoices(group->expr, values);
}

struct StateAssignmentCollector : Luau::AstVisitor
{
    explicit StateAssignmentCollector(Luau::AstLocal* state)
        : state(state)
    {
    }

    Luau::AstLocal* state;
    std::set<int64_t> values;
    size_t assignments = 0;
    size_t dynamic_assignments = 0;

    bool visit(Luau::AstStatAssign* node) override
    {
        size_t count = std::min(node->vars.size, node->values.size);
        for (size_t i = 0; i < count; ++i)
        {
            auto local = node->vars.data[i]->as<Luau::AstExprLocal>();
            if (!local || local->local != state)
                continue;
            ++assignments;
            size_t before = values.size();
            collectIntegerChoices(node->values.data[i], values);
            if (values.size() == before)
                ++dynamic_assignments;
        }
        return true;
    }
};

struct IndexedKey
{
    Luau::AstLocal* base = nullptr;
    std::string key;

    bool operator<(const IndexedKey& other) const
    {
        if (base != other.base)
            return base < other.base;
        return key < other.key;
    }
};

struct NodeFinder : Luau::AstVisitor
{
    explicit NodeFinder(Luau::AstStatWhile* target)
        : target(target)
    {
    }

    Luau::AstStatWhile* target;
    bool found = false;

    bool visit(Luau::AstStatWhile* node) override
    {
        found = found || node == target;
        return !found;
    }
};

struct FunctionCollector : Luau::AstVisitor
{
    std::vector<Luau::AstExprFunction*> functions;

    bool visit(Luau::AstExprFunction* node) override
    {
        functions.push_back(node);
        return true;
    }
};

Luau::AstExprFunction* findContainingFunction(Luau::AstStatBlock* root, Luau::AstStatWhile* target, const SourceView& sourceView)
{
    FunctionCollector collector;
    root->visit(&collector);
    Luau::AstExprFunction* best = nullptr;
    size_t bestSpan = std::numeric_limits<size_t>::max();
    for (Luau::AstExprFunction* function : collector.functions)
    {
        NodeFinder finder(target);
        function->body->visit(&finder);
        if (!finder.found)
            continue;
        size_t begin = sourceView.offset(function->location.begin);
        size_t end = sourceView.offset(function->location.end);
        size_t span = end >= begin ? end - begin : std::numeric_limits<size_t>::max();
        if (span < bestSpan)
        {
            best = function;
            bestSpan = span;
        }
    }
    return best;
}

struct AssignmentNodeFinder : Luau::AstVisitor
{
    explicit AssignmentNodeFinder(Luau::AstStatAssign* target)
        : target(target)
    {
    }

    Luau::AstStatAssign* target;
    bool found = false;

    bool visit(Luau::AstStatAssign* node) override
    {
        found = found || node == target;
        return !found;
    }
};

Luau::AstExprFunction* findContainingFunction(Luau::AstStatBlock* root, Luau::AstStatAssign* target, const SourceView& sourceView)
{
    FunctionCollector collector;
    root->visit(&collector);
    Luau::AstExprFunction* best = nullptr;
    size_t bestSpan = std::numeric_limits<size_t>::max();
    for (Luau::AstExprFunction* function : collector.functions)
    {
        AssignmentNodeFinder finder(target);
        function->body->visit(&finder);
        if (!finder.found)
            continue;
        const size_t begin = sourceView.offset(function->location.begin);
        const size_t end = sourceView.offset(function->location.end);
        const size_t span = end >= begin ? end - begin : std::numeric_limits<size_t>::max();
        if (span < bestSpan)
        {
            best = function;
            bestSpan = span;
        }
    }
    return best;
}

struct HelperMetrics : Luau::AstVisitor
{
    size_t returns = 0;
    size_t whiles = 0;
    size_t numericFors = 0;
    size_t genericFors = 0;

    bool visit(Luau::AstStatReturn*) override
    {
        ++returns;
        return true;
    }

    bool visit(Luau::AstStatWhile*) override
    {
        ++whiles;
        return true;
    }

    bool visit(Luau::AstStatFor*) override
    {
        ++numericFors;
        return true;
    }

    bool visit(Luau::AstStatForIn*) override
    {
        ++genericFors;
        return true;
    }
};

Luau::AstLocal* findReturnPackLocal(Luau::AstExprFunction* dispatcher)
{
    if (!dispatcher || !dispatcher->body)
        return nullptr;
    for (size_t i = dispatcher->body->body.size; i > 0; --i)
    {
        auto statement = dispatcher->body->body.data[i - 1]->as<Luau::AstStatReturn>();
        if (!statement || statement->list.size != 1)
            continue;
        auto call = statement->list.data[0]->as<Luau::AstExprCall>();
        if (!call || call->args.size != 1)
            continue;
        if (auto value = call->args.data[0]->as<Luau::AstExprLocal>())
            return value->local;
    }
    return nullptr;
}

struct DispatcherBindingCollector : Luau::AstVisitor
{
    explicit DispatcherBindingCollector(Luau::AstExprFunction* dispatcher)
        : dispatcher(dispatcher)
    {
    }

    Luau::AstExprFunction* dispatcher;
    Luau::AstStatAssign* assignment = nullptr;
    Luau::AstLocal* local = nullptr;

    bool visit(Luau::AstStatAssign* node) override
    {
        size_t count = std::min(node->vars.size, node->values.size);
        for (size_t i = 0; i < count; ++i)
        {
            if (node->values.data[i] != dispatcher)
                continue;
            if (auto expression = node->vars.data[i]->as<Luau::AstExprLocal>())
            {
                assignment = node;
                local = expression->local;
                return false;
            }
        }
        return assignment == nullptr;
    }
};

struct LocalCallCollector : Luau::AstVisitor
{
    explicit LocalCallCollector(Luau::AstLocal* target)
        : target(target)
    {
    }

    Luau::AstLocal* target;
    bool found = false;

    bool visit(Luau::AstExprCall* node) override
    {
        auto function = node->func->as<Luau::AstExprLocal>();
        if (function && function->local == target && node->args.size >= 2 && node->args.data[1]->is<Luau::AstExprTable>())
            found = true;
        return !found;
    }
};

std::set<Luau::AstLocal*> findClosureFactories(Luau::AstStatAssign* binding, Luau::AstLocal* dispatcher)
{
    std::set<Luau::AstLocal*> factories;
    if (!binding || !dispatcher)
        return factories;
    size_t count = std::min(binding->vars.size, binding->values.size);
    for (size_t i = 0; i < count; ++i)
    {
        auto local = binding->vars.data[i]->as<Luau::AstExprLocal>();
        auto function = binding->values.data[i]->as<Luau::AstExprFunction>();
        if (!local || !function)
            continue;
        LocalCallCollector callsDispatcher(dispatcher);
        function->body->visit(&callsDispatcher);
        if (callsDispatcher.found)
            factories.insert(local->local);
    }
    return factories;
}

std::map<Luau::AstLocal*, std::string> resolveExternalRoles(
    Luau::AstStatAssign* binding,
    Luau::AstExprFunction* wrapper,
    Luau::AstLocal* dispatcher,
    Luau::AstLocal* cells,
    const std::set<Luau::AstLocal*>& factories,
    bool compactLayout
)
{
    std::map<Luau::AstLocal*, std::string> roles;
    if (wrapper && wrapper->args.size >= 7)
    {
        if (compactLayout)
        {
            roles[wrapper->args.data[0]] = "setmetatable_value";
            roles[wrapper->args.data[1]] = "getmetatable_value";
            roles[wrapper->args.data[2]] = "environment";
            roles[wrapper->args.data[3]] = "unpack_values";
            roles[wrapper->args.data[4]] = "select_value";
            roles[wrapper->args.data[5]] = "newproxy_value";
        }
        else
        {
            roles[wrapper->args.data[0]] = "environment";
            roles[wrapper->args.data[1]] = "unpack_values";
            roles[wrapper->args.data[2]] = "newproxy_value";
            roles[wrapper->args.data[3]] = "setmetatable_value";
            roles[wrapper->args.data[4]] = "getmetatable_value";
            roles[wrapper->args.data[5]] = "select_value";
        }
        roles[wrapper->args.data[6]] = "outer_arguments";
    }
    if (!binding)
        return roles;

    size_t count = std::min(binding->vars.size, binding->values.size);
    for (size_t i = 0; i < count; ++i)
    {
        auto target = binding->vars.data[i]->as<Luau::AstExprLocal>();
        if (!target || target->local == dispatcher || factories.contains(target->local))
            continue;
        Luau::AstExpr* value = binding->values.data[i];
        if (target->local == cells)
        {
            roles[target->local] = "cells";
            continue;
        }
        if (value->is<Luau::AstExprTable>())
        {
            roles[target->local] = "refcounts";
            continue;
        }
        if (evaluateAstNumber(value))
        {
            roles[target->local] = "next_cell_id";
            continue;
        }
        auto function = value->as<Luau::AstExprFunction>();
        if (!function)
            continue;
        HelperMetrics metrics;
        function->body->visit(&metrics);
        if (function->args.size == 0 && !function->vararg)
            roles[target->local] = "allocate_cell";
        else if (function->args.size == 1 && !function->vararg && metrics.whiles > 0)
            roles[target->local] = "release_captures";
        else if (function->args.size == 1 && !function->vararg && (metrics.numericFors > 0 || metrics.genericFors > 0))
            roles[target->local] = "capture_owner";
        else if (function->args.size == 1 && !function->vararg)
            roles[target->local] = "release_cell";
    }
    return roles;
}

struct PrototypeEntryCollector : Luau::AstVisitor
{
    explicit PrototypeEntryCollector(const std::set<Luau::AstLocal*>& factories, Luau::AstExprFunction* excludedFunction = nullptr)
        : factories(factories)
        , excludedFunction(excludedFunction)
    {
    }

    const std::set<Luau::AstLocal*>& factories;
    Luau::AstExprFunction* excludedFunction = nullptr;
    std::set<int64_t> entries;
    size_t calls = 0;
    size_t table_second_args = 0;

    bool visit(Luau::AstExprFunction* node) override
    {
        return node != excludedFunction;
    }

    bool visit(Luau::AstExprCall* node) override
    {
        ++calls;
        auto function = node->func->as<Luau::AstExprLocal>();
        if (function && factories.contains(function->local) && node->args.size >= 2 && node->args.data[1]->is<Luau::AstExprTable>())
        {
            ++table_second_args;
            if (auto value = evaluateAstInteger(node->args.data[0]))
                entries.insert(*value);
        }
        return true;
    }
};

struct IndexedWriteCollector : Luau::AstVisitor
{
    std::set<IndexedKey> writes;

    void collect(Luau::AstExpr* expression)
    {
        auto index = expression ? expression->as<Luau::AstExprIndexExpr>() : nullptr;
        auto base = index ? index->expr->as<Luau::AstExprLocal>() : nullptr;
        auto key = index ? index->index->as<Luau::AstExprConstantString>() : nullptr;
        if (base && key)
            writes.insert({base->local, std::string(key->value.data, key->value.size)});
    }

    bool visit(Luau::AstStatAssign* node) override
    {
        for (Luau::AstExpr* variable : node->vars)
            collect(variable);
        return true;
    }

    bool visit(Luau::AstStatCompoundAssign* node) override
    {
        collect(node->var);
        return true;
    }
};

Luau::AstExpr* unwrapLuraphExpression(Luau::AstExpr* expression);

std::optional<bool> evaluateStateCondition(
    Luau::AstExpr* expression,
    Luau::AstLocal* state,
    int64_t value,
    const std::map<Luau::AstLocal*, double>* bindings = nullptr)
{
    while (expression)
    {
        if (auto group = expression->as<Luau::AstExprGroup>())
            expression = group->expr;
        else if (auto assertion = expression->as<Luau::AstExprTypeAssertion>())
            expression = assertion->expr;
        else
            break;
    }
    if (auto constant = expression ? expression->as<Luau::AstExprConstantBool>() : nullptr)
        return constant->value;
    if (expression && expression->is<Luau::AstExprConstantNil>())
        return false;
    if (expression && expression->is<Luau::AstExprConstantString>())
        return true;
    if (auto local = expression ? expression->as<Luau::AstExprLocal>() : nullptr)
    {
        if (local->local == state)
            return true;
        if (bindings && bindings->contains(local->local))
            return true;
    }
    // Every numeric value is truthy in Luau, including zero and NaN. Constant
    // arithmetic can therefore be resolved without guessing any VM state.
    if (expression && evaluateAstNumber(expression).has_value())
        return true;
    if (auto unary = expression ? expression->as<Luau::AstExprUnary>() : nullptr)
    {
        if (unary->op != Luau::AstExprUnary::Op::Not)
            return std::nullopt;
        const std::optional<bool> nested = evaluateStateCondition(unary->expr, state, value, bindings);
        return nested ? std::optional<bool>(!*nested) : std::nullopt;
    }
    auto binary = expression ? expression->as<Luau::AstExprBinary>() : nullptr;
    if (!binary)
        return std::nullopt;
    if (binary->op == Luau::AstExprBinary::And || binary->op == Luau::AstExprBinary::Or)
    {
        const std::optional<bool> left = evaluateStateCondition(binary->left, state, value, bindings);
        if (!left)
            return std::nullopt;
        if (binary->op == Luau::AstExprBinary::And)
            return !*left ? std::optional<bool>(false) : evaluateStateCondition(binary->right, state, value, bindings);
        return *left ? std::optional<bool>(true) : evaluateStateCondition(binary->right, state, value, bindings);
    }
    Luau::AstExpr* leftExpression = unwrapLuraphExpression(binary->left);
    Luau::AstExpr* rightExpression = unwrapLuraphExpression(binary->right);
    auto leftLocal = leftExpression ? leftExpression->as<Luau::AstExprLocal>() : nullptr;
    auto rightLocal = rightExpression ? rightExpression->as<Luau::AstExprLocal>() : nullptr;
    auto resolveValue = [&](Luau::AstExpr* candidate, Luau::AstExprLocal* local) -> std::optional<double> {
        if (local && local->local == state)
            return static_cast<double>(value);
        if (local && bindings)
            if (auto found = bindings->find(local->local); found != bindings->end())
                return found->second;
        return evaluateAstNumber(candidate);
    };
    const std::optional<double> resolvedLeft = resolveValue(binary->left, leftLocal);
    const std::optional<double> resolvedRight = resolveValue(binary->right, rightLocal);
    if (!resolvedLeft || !resolvedRight)
        return std::nullopt;
    const double left = *resolvedLeft;
    const double right = *resolvedRight;

    switch (binary->op)
    {
    case Luau::AstExprBinary::CompareLt: return left < right;
    case Luau::AstExprBinary::CompareLe: return left <= right;
    case Luau::AstExprBinary::CompareGt: return left > right;
    case Luau::AstExprBinary::CompareGe: return left >= right;
    case Luau::AstExprBinary::CompareEq: return left == right;
    case Luau::AstExprBinary::CompareNe: return left != right;
    default: return std::nullopt;
    }
}

Luau::AstStatBlock* selectLeaf(
    Luau::AstStat* statement,
    Luau::AstLocal* state,
    int64_t value,
    const std::map<Luau::AstLocal*, double>* bindings = nullptr,
    bool* ambiguous = nullptr);

Luau::AstStatBlock* selectLeaf(
    Luau::AstStatBlock* block,
    Luau::AstLocal* state,
    int64_t value,
    const std::map<Luau::AstLocal*, double>* bindings,
    bool* ambiguous)
{
    if (!block || block->body.size == 0)
        return block;
    for (Luau::AstStat* statement : block->body)
    {
        if (auto nested = statement->as<Luau::AstStatIf>())
        {
            const std::optional<bool> decision = evaluateStateCondition(nested->condition, state, value, bindings);
            if (!decision.has_value())
            {
                if (ambiguous)
                    *ambiguous = true;
                continue;
            }

            if (*decision)
                return selectLeaf(nested->thenbody, state, value, bindings, ambiguous);

            // A one-sided opcode guard is a sibling leaf, not the end of the
            // dispatcher. Keep scanning the enclosing block when it misses.
            if (nested->elsebody)
                return selectLeaf(nested->elsebody, state, value, bindings, ambiguous);
        }
    }
    return block;
}

Luau::AstStatBlock* selectLeaf(
    Luau::AstStat* statement,
    Luau::AstLocal* state,
    int64_t value,
    const std::map<Luau::AstLocal*, double>* bindings,
    bool* ambiguous)
{
    if (!statement)
        return nullptr;
    if (auto block = statement->as<Luau::AstStatBlock>())
        return selectLeaf(block, state, value, bindings, ambiguous);
    auto conditional = statement->as<Luau::AstStatIf>();
    if (!conditional)
        return nullptr;
    auto decision = evaluateStateCondition(conditional->condition, state, value, bindings);
    if (!decision)
    {
        if (ambiguous)
            *ambiguous = true;
        return nullptr;
    }
    if (*decision)
        return selectLeaf(conditional->thenbody, state, value, bindings, ambiguous);
    return selectLeaf(conditional->elsebody, state, value, bindings, ambiguous);
}

struct BlockInfo
{
    int64_t state = 0;
    Luau::AstStatBlock* body = nullptr;
    std::set<int64_t> outgoing;
    size_t dynamic_transitions = 0;
    size_t statements = 0;
    std::set<IndexedKey> dynamic_index_reads;
};

bool isReturnSentinel(const BlockInfo& block, const std::set<IndexedKey>& indexedWrites)
{
    if (!block.dynamic_transitions || block.dynamic_index_reads.empty())
        return false;
    return std::none_of(block.dynamic_index_reads.begin(), block.dynamic_index_reads.end(), [&](const IndexedKey& key) {
        return indexedWrites.contains(key);
    });
}

std::optional<IndexedKey> opaqueIndexedRead(Luau::AstExpr* expression)
{
    while (expression)
    {
        if (auto group = expression->as<Luau::AstExprGroup>())
            expression = group->expr;
        else if (auto assertion = expression->as<Luau::AstExprTypeAssertion>())
            expression = assertion->expr;
        else
            break;
    }
    auto index = expression ? expression->as<Luau::AstExprIndexExpr>() : nullptr;
    auto base = index ? index->expr->as<Luau::AstExprLocal>() : nullptr;
    auto key = index ? index->index->as<Luau::AstExprConstantString>() : nullptr;
    if (!base || !base->upvalue || !key || key->value.size < 8)
        return std::nullopt;
    std::string text(key->value.data, key->value.size);
    if (!std::all_of(text.begin(), text.end(), [](unsigned char ch) { return std::isalnum(ch); }))
        return std::nullopt;
    return IndexedKey{base->local, std::move(text)};
}

struct CellStorageCollector : Luau::AstVisitor
{
    explicit CellStorageCollector(Luau::AstLocal* captures)
        : captures(captures)
    {
    }

    Luau::AstLocal* captures;
    std::map<Luau::AstLocal*, size_t> counts;

    bool visit(Luau::AstExprIndexExpr* node) override
    {
        auto storage = node->expr->as<Luau::AstExprLocal>();
        auto captureIndex = node->index->as<Luau::AstExprIndexExpr>();
        auto captureVector = captureIndex ? captureIndex->expr->as<Luau::AstExprLocal>() : nullptr;
        if (storage && captureVector && captureVector->local == captures)
            ++counts[storage->local];
        return true;
    }

    Luau::AstLocal* best() const
    {
        auto found = std::max_element(counts.begin(), counts.end(), [](const auto& left, const auto& right) { return left.second < right.second; });
        return found == counts.end() ? nullptr : found->first;
    }
};

class SemanticNormalizer
{
public:
    SemanticNormalizer(
        Luau::AstLocal* state,
        Luau::AstLocal* arguments,
        Luau::AstLocal* captures,
        Luau::AstLocal* owner,
        Luau::AstLocal* cells,
        Luau::AstLocal* environment,
        const std::set<Luau::AstLocal*>& factories,
        const std::map<Luau::AstLocal*, std::string>& externalRoles,
        Luau::AstLocal* returnPack,
        std::set<std::string> sentinelKeys
    )
        : state(state)
        , arguments(arguments)
        , captures(captures)
        , cells(cells)
        , environment(environment)
        , factories(factories)
        , sentinelKeys(std::move(sentinelKeys))
    {
        names[state] = "pc";
        names[arguments] = "arguments";
        names[captures] = "capture_ids";
        names[owner] = "frame_owner";
        if (cells)
            names[cells] = "cells";
        if (environment)
            names[environment] = "environment";
        for (const auto& [local, name] : externalRoles)
            if (local)
                names[local] = name;
        if (returnPack)
            names[returnPack] = "results";
        std::vector<Luau::AstLocal*> orderedFactories(factories.begin(), factories.end());
        std::sort(orderedFactories.begin(), orderedFactories.end(), [](Luau::AstLocal* left, Luau::AstLocal* right) {
            if (left->location.begin.line != right->location.begin.line)
                return left->location.begin.line < right->location.begin.line;
            return left->location.begin.column < right->location.begin.column;
        });
        for (Luau::AstLocal* factory : orderedFactories)
            names[factory] = "closure_factory_" + std::to_string(++factoryCount);
    }

    json block(Luau::AstStatBlock* value)
    {
        json result = json::array();
        if (!value)
            return result;
        for (Luau::AstStat* item : value->body)
            result.push_back(statement(item, 0));
        return result;
    }

    json registerRows() const
    {
        std::vector<std::pair<std::string, Luau::AstLocal*>> ordered;
        for (const auto& [local, name] : names)
            if (name.rfind("temporary_", 0) == 0)
                ordered.emplace_back(name, local);
        std::sort(ordered.begin(), ordered.end(), [](const auto& left, const auto& right) { return left.first < right.first; });
        json rows = json::array();
        for (const auto& [name, local] : ordered)
            rows.push_back({{"name", name}, {"kind", "dispatcher_scratch"}, {"line", local->location.begin.line + 1},
                {"column", local->location.begin.column + 1}});
        return rows;
    }

    std::optional<std::string> sourceNameFor(std::string_view normalizedName) const
    {
        for (const auto& [local, name] : names)
            if (name == normalizedName && local && local->name.value)
                return std::string(local->name.value);
        return std::nullopt;
    }

    size_t normalizedStatements() const
    {
        return normalized;
    }

    size_t unsupportedStatements() const
    {
        return unsupported;
    }

private:
    Luau::AstLocal* state;
    Luau::AstLocal* arguments;
    Luau::AstLocal* captures;
    Luau::AstLocal* cells;
    Luau::AstLocal* environment;
    const std::set<Luau::AstLocal*>& factories;
    std::set<std::string> sentinelKeys;
    std::map<Luau::AstLocal*, std::string> names;
    size_t temporaryCount = 0;
    size_t factoryCount = 0;
    size_t normalized = 0;
    size_t unsupported = 0;

    std::string localName(Luau::AstLocal* local)
    {
        auto found = names.find(local);
        if (found != names.end())
            return found->second;
        std::string name = "temporary_" + std::to_string(++temporaryCount);
        names[local] = name;
        return name;
    }

    json location(const Luau::AstNode* node) const
    {
        return {{"line", node->location.begin.line + 1}, {"column", node->location.begin.column + 1}};
    }

    static std::optional<std::string> stringConstant(Luau::AstExpr* value)
    {
        auto text = value ? value->as<Luau::AstExprConstantString>() : nullptr;
        return text ? std::optional<std::string>(std::string(text->value.data, text->value.size)) : std::nullopt;
    }

    static bool expandsResults(Luau::AstExpr* value)
    {
        return value && (value->is<Luau::AstExprCall>() || value->is<Luau::AstExprVarargs>());
    }

    json stringValue(std::string_view value) const
    {
        if (printableAscii(value))
            return {{"kind", "string"}, {"value", value}};
        return {{"kind", "bytes"}, {"hex", hexBytes(value)}};
    }

    std::optional<int64_t> captureSlot(Luau::AstExpr* value) const
    {
        auto outer = value ? value->as<Luau::AstExprIndexExpr>() : nullptr;
        auto storage = outer ? outer->expr->as<Luau::AstExprLocal>() : nullptr;
        auto inner = outer ? outer->index->as<Luau::AstExprIndexExpr>() : nullptr;
        auto vector = inner ? inner->expr->as<Luau::AstExprLocal>() : nullptr;
        if (!outer || !storage || storage->local != cells || !inner || !vector || vector->local != captures)
            return std::nullopt;
        return evaluateAstInteger(inner->index);
    }

    json target(Luau::AstExpr* value, size_t depth)
    {
        if (!value || depth > 128)
            return {{"kind", "unknown_target"}};
        if (auto local = value->as<Luau::AstExprLocal>())
            return {{"kind", local->local == state ? "program_counter" : "local"}, {"name", localName(local->local)}};
        if (auto slot = captureSlot(value))
            return {{"kind", "upvalue"}, {"slot", *slot}};
        if (auto index = value->as<Luau::AstExprIndexExpr>())
        {
            auto base = index->expr->as<Luau::AstExprLocal>();
            if (base && base->local == cells)
                return {{"kind", "cell"}, {"id", expression(index->index, depth + 1)}};
            if (base && base->local == environment)
            {
                if (auto key = stringConstant(index->index))
                    return {{"kind", "global"}, {"key", stringValue(*key)}};
            }
            return {{"kind", "index"}, {"table", expression(index->expr, depth + 1)}, {"index", expression(index->index, depth + 1)}};
        }
        if (auto index = value->as<Luau::AstExprIndexName>())
            return {{"kind", "index"}, {"table", expression(index->expr, depth + 1)},
                {"index", stringValue(index->index.value ? std::string_view(index->index.value) : std::string_view("<anonymous>"))}};
        return {{"kind", "unknown_target"}, {"expression", expression(value, depth + 1)}};
    }

    json expression(Luau::AstExpr* value, size_t depth)
    {
        if (!value || depth > 128)
            return {{"op", "unknown_expression"}};
        if (value->is<Luau::AstExprConstantNil>())
            return {{"op", "constant"}, {"value", nullptr}};
        if (auto item = value->as<Luau::AstExprConstantBool>())
            return {{"op", "constant"}, {"value", item->value}};
        if (auto item = value->as<Luau::AstExprConstantInteger>())
            return {{"op", "constant"}, {"value", item->value}};
        if (auto item = value->as<Luau::AstExprConstantNumber>())
            return {{"op", "constant"}, {"value", item->value}};
        if (auto item = value->as<Luau::AstExprConstantString>())
        {
            json result = stringValue(std::string_view(item->value.data, item->value.size));
            result["op"] = "constant";
            return result;
        }
        if (auto item = value->as<Luau::AstExprGroup>())
            return {{"op", "group"}, {"value", expression(item->expr, depth + 1)}};
        if (auto item = value->as<Luau::AstExprTypeAssertion>())
            return expression(item->expr, depth + 1);
        if (auto item = value->as<Luau::AstExprLocal>())
            return {{"op", "local_read"}, {"name", localName(item->local)}};
        if (auto item = value->as<Luau::AstExprGlobal>())
            return {{"op", "global_read"}, {"name", item->name.value ? item->name.value : "<anonymous>"}};
        if (value->is<Luau::AstExprVarargs>())
            return {{"op", "varargs"}};
        if (auto slot = captureSlot(value))
            return {{"op", "upvalue_read"}, {"slot", *slot}};
        if (auto item = value->as<Luau::AstExprIndexExpr>())
        {
            auto base = item->expr->as<Luau::AstExprLocal>();
            if (base && base->local == arguments)
                return {{"op", "argument_read"}, {"index", expression(item->index, depth + 1)}};
            if (base && base->local == cells)
                return {{"op", "cell_read"}, {"id", expression(item->index, depth + 1)}};
            if (base && base->local == environment)
            {
                if (auto key = stringConstant(item->index))
                {
                    if (sentinelKeys.contains(*key))
                        return {{"op", "protector_return_sentinel"}, {"assumed_value", nullptr}, {"key_sha256", sha256(*key)}};
                    return {{"op", "global_read"}, {"key", stringValue(*key)}};
                }
            }
            return {{"op", "index_read"}, {"table", expression(item->expr, depth + 1)}, {"index", expression(item->index, depth + 1)}};
        }
        if (auto item = value->as<Luau::AstExprIndexName>())
            return {{"op", "index_read"}, {"table", expression(item->expr, depth + 1)}, {"index", item->index.value ? item->index.value : "<anonymous>"}};
        if (auto item = value->as<Luau::AstExprUnary>())
            return {{"op", "unary"}, {"operator", Luau::toString(item->op)}, {"value", expression(item->expr, depth + 1)}};
        if (auto item = value->as<Luau::AstExprBinary>())
            return {{"op", "binary"}, {"operator", Luau::toString(item->op)}, {"left", expression(item->left, depth + 1)},
                {"right", expression(item->right, depth + 1)}};
        if (auto item = value->as<Luau::AstExprIfElse>())
            return {{"op", "if_expression"}, {"condition", expression(item->condition, depth + 1)},
                {"then", expression(item->trueExpr, depth + 1)}, {"else", expression(item->falseExpr, depth + 1)}};
        if (auto item = value->as<Luau::AstExprTable>())
        {
            json values = json::array();
            for (size_t i = 0; i < item->items.size; ++i)
            {
                const Luau::AstExprTable::Item& tableItem = item->items.data[i];
                std::string kind = tableItem.kind == Luau::AstExprTable::Item::Kind::List ? "list" :
                    tableItem.kind == Luau::AstExprTable::Item::Kind::Record ? "record" : "general";
                values.push_back({{"kind", kind}, {"key", tableItem.key ? expression(tableItem.key, depth + 1) : json(nullptr)},
                    {"value", expression(tableItem.value, depth + 1)},
                    {"expand_results", kind == "list" && i + 1 == item->items.size && expandsResults(tableItem.value)}});
            }
            return {{"op", "table"}, {"items", values}};
        }
        if (auto item = value->as<Luau::AstExprCall>())
        {
            json argumentsJson = json::array();
            for (Luau::AstExpr* argument : item->args)
                argumentsJson.push_back(expression(argument, depth + 1));
            auto functionLocal = item->func->as<Luau::AstExprLocal>();
            if (functionLocal && factories.contains(functionLocal->local) && item->args.size >= 2)
                return {{"op", "make_closure"}, {"factory", localName(functionLocal->local)},
                    {"entry", expression(item->args.data[0], depth + 1)}, {"captures", expression(item->args.data[1], depth + 1)}};
            return {{"op", "call"}, {"function", expression(item->func, depth + 1)}, {"arguments", argumentsJson}, {"method", item->self}};
        }
        if (auto item = value->as<Luau::AstExprFunction>())
            return {{"op", "native_closure"}, {"parameters", item->args.size}, {"vararg", item->vararg}};
        return {{"op", "unsupported_expression"}, {"location", location(value)}};
    }

    json statement(Luau::AstStat* value, size_t depth)
    {
        ++normalized;
        if (!value || depth > 128)
        {
            ++unsupported;
            return {{"op", "unsupported_statement"}};
        }
        json result;
        if (auto item = value->as<Luau::AstStatAssign>())
        {
            json targets = json::array();
            json values = json::array();
            for (Luau::AstExpr* variable : item->vars)
                targets.push_back(target(variable, depth + 1));
            for (Luau::AstExpr* expressionValue : item->values)
                values.push_back(expression(expressionValue, depth + 1));
            result = {{"op", "assign"}, {"targets", targets}, {"values", values}, {"target_arity", item->vars.size},
                {"value_arity", item->values.size},
                {"expand_final_result", item->values.size > 0 && expandsResults(item->values.data[item->values.size - 1])},
                {"evaluation_order", "values_before_writes"}};
        }
        else if (auto item = value->as<Luau::AstStatLocal>())
        {
            json targets = json::array();
            json values = json::array();
            for (Luau::AstLocal* variable : item->vars)
                targets.push_back({{"kind", "local"}, {"name", localName(variable)}});
            for (Luau::AstExpr* expressionValue : item->values)
                values.push_back(expression(expressionValue, depth + 1));
            result = {{"op", "local_assign"}, {"targets", targets}, {"values", values}, {"target_arity", item->vars.size},
                {"value_arity", item->values.size},
                {"expand_final_result", item->values.size > 0 && expandsResults(item->values.data[item->values.size - 1])}};
        }
        else if (auto item = value->as<Luau::AstStatCompoundAssign>())
            result = {{"op", "compound_assign"}, {"operator", Luau::toString(item->op)}, {"target", target(item->var, depth + 1)},
                {"value", expression(item->value, depth + 1)}};
        else if (auto item = value->as<Luau::AstStatExpr>())
            result = {{"op", "expression"}, {"value", expression(item->expr, depth + 1)}};
        else if (auto item = value->as<Luau::AstStatReturn>())
        {
            json values = json::array();
            for (Luau::AstExpr* expressionValue : item->list)
                values.push_back(expression(expressionValue, depth + 1));
            result = {{"op", "return"}, {"values", values}};
        }
        else if (auto item = value->as<Luau::AstStatIf>())
        {
            json thenBody = json::array();
            for (Luau::AstStat* child : item->thenbody->body)
                thenBody.push_back(statement(child, depth + 1));
            json elseBody = json::array();
            if (auto block = item->elsebody ? item->elsebody->as<Luau::AstStatBlock>() : nullptr)
                for (Luau::AstStat* child : block->body)
                    elseBody.push_back(statement(child, depth + 1));
            else if (item->elsebody)
                elseBody.push_back(statement(item->elsebody, depth + 1));
            result = {{"op", "if"}, {"condition", expression(item->condition, depth + 1)}, {"then", thenBody}, {"else", elseBody}};
        }
        else if (auto item = value->as<Luau::AstStatBlock>())
        {
            json body = json::array();
            for (Luau::AstStat* child : item->body)
                body.push_back(statement(child, depth + 1));
            result = {{"op", "block"}, {"body", body}};
        }
        else if (value->is<Luau::AstStatBreak>())
            result = {{"op", "break"}};
        else if (value->is<Luau::AstStatContinue>())
            result = {{"op", "continue"}};
        else
        {
            ++unsupported;
            result = {{"op", "unsupported_statement"}};
        }
        result["location"] = location(value);
        return result;
    }
};

struct StateFlow
{
    std::set<int64_t> values;
    bool unknown = false;
    bool falls_through = true;
    struct Constant
    {
        enum class Kind
        {
            Unknown,
            Nil,
            Boolean,
            Number,
            String,
        };

        Kind kind = Kind::Unknown;
        bool boolean = false;
        double number = 0;
        std::string string;

        static Constant nil()
        {
            Constant value;
            value.kind = Kind::Nil;
            return value;
        }

        static Constant booleanValue(bool input)
        {
            Constant value;
            value.kind = Kind::Boolean;
            value.boolean = input;
            return value;
        }

        static Constant numberValue(double input)
        {
            Constant value;
            value.kind = Kind::Number;
            value.number = input;
            return value;
        }

        static Constant stringValue(std::string input)
        {
            Constant value;
            value.kind = Kind::String;
            value.string = std::move(input);
            return value;
        }

        bool operator==(const Constant& other) const
        {
            if (kind != other.kind)
                return false;
            switch (kind)
            {
            case Kind::Unknown:
            case Kind::Nil: return true;
            case Kind::Boolean: return boolean == other.boolean;
            case Kind::Number: return number == other.number;
            case Kind::String: return string == other.string;
            }
            return false;
        }
    };

    std::map<Luau::AstLocal*, Constant> constants;
    std::set<IndexedKey> dynamic_index_reads;
};

using FlowConstant = StateFlow::Constant;

std::optional<bool> constantTruthy(const FlowConstant& value)
{
    switch (value.kind)
    {
    case FlowConstant::Kind::Nil: return false;
    case FlowConstant::Kind::Boolean: return value.boolean;
    case FlowConstant::Kind::Number:
    case FlowConstant::Kind::String: return true;
    case FlowConstant::Kind::Unknown: return std::nullopt;
    }
    return std::nullopt;
}

FlowConstant evaluateFlowConstant(Luau::AstExpr* expression, const std::map<Luau::AstLocal*, FlowConstant>& constants, size_t depth = 0)
{
    if (!expression || depth > 128)
        return {};
    if (expression->is<Luau::AstExprConstantNil>())
        return FlowConstant::nil();
    if (auto node = expression->as<Luau::AstExprConstantBool>())
        return FlowConstant::booleanValue(node->value);
    if (auto node = expression->as<Luau::AstExprConstantNumber>())
        return FlowConstant::numberValue(node->value);
    if (auto node = expression->as<Luau::AstExprConstantInteger>())
        return FlowConstant::numberValue(static_cast<double>(node->value));
    if (auto node = expression->as<Luau::AstExprConstantString>())
        return FlowConstant::stringValue(std::string(node->value.data, node->value.size));
    if (auto node = expression->as<Luau::AstExprGroup>())
        return evaluateFlowConstant(node->expr, constants, depth + 1);
    if (auto node = expression->as<Luau::AstExprLocal>())
    {
        auto found = constants.find(node->local);
        return found == constants.end() ? FlowConstant{} : found->second;
    }
    if (auto node = expression->as<Luau::AstExprTypeAssertion>())
        return evaluateFlowConstant(node->expr, constants, depth + 1);
    if (auto node = expression->as<Luau::AstExprUnary>())
    {
        FlowConstant value = evaluateFlowConstant(node->expr, constants, depth + 1);
        if (node->op == Luau::AstExprUnary::Op::Not)
        {
            auto truthy = constantTruthy(value);
            return truthy ? FlowConstant::booleanValue(!*truthy) : FlowConstant{};
        }
        if (node->op == Luau::AstExprUnary::Op::Minus && value.kind == FlowConstant::Kind::Number)
            return FlowConstant::numberValue(-value.number);
        if (node->op == Luau::AstExprUnary::Op::Len && value.kind == FlowConstant::Kind::String)
            return FlowConstant::numberValue(static_cast<double>(value.string.size()));
        return {};
    }
    if (auto node = expression->as<Luau::AstExprIfElse>())
    {
        FlowConstant condition = evaluateFlowConstant(node->condition, constants, depth + 1);
        auto truthy = constantTruthy(condition);
        if (!truthy)
            return {};
        return evaluateFlowConstant(*truthy ? node->trueExpr : node->falseExpr, constants, depth + 1);
    }
    auto node = expression->as<Luau::AstExprBinary>();
    if (!node)
        return {};

    FlowConstant left = evaluateFlowConstant(node->left, constants, depth + 1);
    if (node->op == Luau::AstExprBinary::And || node->op == Luau::AstExprBinary::Or)
    {
        auto truthy = constantTruthy(left);
        if (!truthy)
            return {};
        if (node->op == Luau::AstExprBinary::And)
            return *truthy ? evaluateFlowConstant(node->right, constants, depth + 1) : left;
        return *truthy ? left : evaluateFlowConstant(node->right, constants, depth + 1);
    }

    FlowConstant right = evaluateFlowConstant(node->right, constants, depth + 1);
    if (left.kind == FlowConstant::Kind::Number && right.kind == FlowConstant::Kind::Number)
    {
        double result = 0;
        switch (node->op)
        {
        case Luau::AstExprBinary::Add: result = left.number + right.number; break;
        case Luau::AstExprBinary::Sub: result = left.number - right.number; break;
        case Luau::AstExprBinary::Mul: result = left.number * right.number; break;
        case Luau::AstExprBinary::Div: result = left.number / right.number; break;
        case Luau::AstExprBinary::FloorDiv: result = std::floor(left.number / right.number); break;
        case Luau::AstExprBinary::Mod: result = std::fmod(left.number, right.number); break;
        case Luau::AstExprBinary::Pow: result = std::pow(left.number, right.number); break;
        case Luau::AstExprBinary::CompareEq: return FlowConstant::booleanValue(left.number == right.number);
        case Luau::AstExprBinary::CompareNe: return FlowConstant::booleanValue(left.number != right.number);
        case Luau::AstExprBinary::CompareLt: return FlowConstant::booleanValue(left.number < right.number);
        case Luau::AstExprBinary::CompareLe: return FlowConstant::booleanValue(left.number <= right.number);
        case Luau::AstExprBinary::CompareGt: return FlowConstant::booleanValue(left.number > right.number);
        case Luau::AstExprBinary::CompareGe: return FlowConstant::booleanValue(left.number >= right.number);
        default: return {};
        }
        return std::isfinite(result) ? FlowConstant::numberValue(result) : FlowConstant{};
    }
    if (node->op == Luau::AstExprBinary::Concat && left.kind == FlowConstant::Kind::String && right.kind == FlowConstant::Kind::String)
        return FlowConstant::stringValue(left.string + right.string);
    if (node->op == Luau::AstExprBinary::CompareEq || node->op == Luau::AstExprBinary::CompareNe)
    {
        if (left.kind == FlowConstant::Kind::Unknown || right.kind == FlowConstant::Kind::Unknown)
            return {};
        bool equal = left == right;
        return FlowConstant::booleanValue(node->op == Luau::AstExprBinary::CompareEq ? equal : !equal);
    }
    if (left.kind == FlowConstant::Kind::String && right.kind == FlowConstant::Kind::String)
    {
        switch (node->op)
        {
        case Luau::AstExprBinary::CompareLt: return FlowConstant::booleanValue(left.string < right.string);
        case Luau::AstExprBinary::CompareLe: return FlowConstant::booleanValue(left.string <= right.string);
        case Luau::AstExprBinary::CompareGt: return FlowConstant::booleanValue(left.string > right.string);
        case Luau::AstExprBinary::CompareGe: return FlowConstant::booleanValue(left.string >= right.string);
        default: break;
        }
    }
    return {};
}

void collectFlowIntegerChoices(
    Luau::AstExpr* expression,
    const std::map<Luau::AstLocal*, FlowConstant>& constants,
    Luau::AstLocal* state,
    const std::set<int64_t>& currentStateValues,
    std::set<int64_t>& values,
    size_t depth = 0)
{
    if (!expression || depth > 128)
        return;
    if (auto local = expression->as<Luau::AstExprLocal>(); local && local->local == state)
    {
        values.insert(currentStateValues.begin(), currentStateValues.end());
        return;
    }
    FlowConstant constant = evaluateFlowConstant(expression, constants, depth + 1);
    if (constant.kind == FlowConstant::Kind::Number && std::isfinite(constant.number) &&
        std::abs(constant.number - std::round(constant.number)) <= 1e-7 &&
        constant.number >= static_cast<double>(std::numeric_limits<int64_t>::min()) &&
        constant.number <= static_cast<double>(std::numeric_limits<int64_t>::max()))
    {
        values.insert(static_cast<int64_t>(std::llround(constant.number)));
        return;
    }
    if (auto binary = expression->as<Luau::AstExprBinary>())
    {
        if (binary->op == Luau::AstExprBinary::And || binary->op == Luau::AstExprBinary::Or)
        {
            collectFlowIntegerChoices(binary->left, constants, state, currentStateValues, values, depth + 1);
            collectFlowIntegerChoices(binary->right, constants, state, currentStateValues, values, depth + 1);
        }
    }
    else if (auto conditional = expression->as<Luau::AstExprIfElse>())
    {
        collectFlowIntegerChoices(conditional->trueExpr, constants, state, currentStateValues, values, depth + 1);
        collectFlowIntegerChoices(conditional->falseExpr, constants, state, currentStateValues, values, depth + 1);
    }
    else if (auto group = expression->as<Luau::AstExprGroup>())
        collectFlowIntegerChoices(group->expr, constants, state, currentStateValues, values, depth + 1);
}

StateFlow analyzeStateFlow(Luau::AstStatBlock* block, Luau::AstLocal* state, StateFlow flow);

StateFlow unionFlow(const StateFlow& left, const StateFlow& right)
{
    if (!left.falls_through)
        return right;
    if (!right.falls_through)
        return left;
    StateFlow result;
    result.values = left.values;
    result.values.insert(right.values.begin(), right.values.end());
    result.unknown = left.unknown || right.unknown;
    result.falls_through = true;
    result.dynamic_index_reads = left.dynamic_index_reads;
    result.dynamic_index_reads.insert(right.dynamic_index_reads.begin(), right.dynamic_index_reads.end());
    for (const auto& [local, value] : left.constants)
    {
        auto found = right.constants.find(local);
        if (found != right.constants.end() && found->second == value)
            result.constants[local] = value;
    }
    return result;
}

StateFlow analyzeStateStatement(Luau::AstStat* statement, Luau::AstLocal* state, StateFlow flow)
{
    if (!statement || !flow.falls_through)
        return flow;
    if (auto assignment = statement->as<Luau::AstStatAssign>())
    {
        size_t count = std::min(assignment->vars.size, assignment->values.size);
        const std::map<Luau::AstLocal*, FlowConstant> previousConstants = flow.constants;
        std::vector<FlowConstant> assigned;
        assigned.reserve(count);
        for (size_t i = 0; i < count; ++i)
            assigned.push_back(evaluateFlowConstant(assignment->values.data[i], previousConstants));
        for (size_t i = 0; i < count; ++i)
        {
            auto local = assignment->vars.data[i]->as<Luau::AstExprLocal>();
            if (!local)
                continue;
            flow.constants[local->local] = assigned[i];
            if (local->local == state)
            {
                std::set<int64_t> choices;
                collectFlowIntegerChoices(assignment->values.data[i], previousConstants, state, flow.values, choices);
                flow.values = std::move(choices);
                flow.unknown = flow.values.empty();
                flow.dynamic_index_reads.clear();
                if (flow.unknown)
                    if (auto indexed = opaqueIndexedRead(assignment->values.data[i]))
                        flow.dynamic_index_reads.insert(std::move(*indexed));
            }
        }
        return flow;
    }
    if (auto local = statement->as<Luau::AstStatLocal>())
    {
        std::vector<FlowConstant> assigned;
        assigned.reserve(local->vars.size);
        for (size_t i = 0; i < local->vars.size; ++i)
            assigned.push_back(i < local->values.size ? evaluateFlowConstant(local->values.data[i], flow.constants) : FlowConstant::nil());
        for (size_t i = 0; i < local->vars.size; ++i)
            flow.constants[local->vars.data[i]] = assigned[i];
        return flow;
    }
    if (auto compound = statement->as<Luau::AstStatCompoundAssign>())
    {
        auto local = compound->var->as<Luau::AstExprLocal>();
        if (!local)
            return flow;
        auto current = flow.constants.find(local->local);
        FlowConstant right = evaluateFlowConstant(compound->value, flow.constants);
        FlowConstant value;
        if (current != flow.constants.end() && current->second.kind == FlowConstant::Kind::Number && right.kind == FlowConstant::Kind::Number)
        {
            switch (compound->op)
            {
            case Luau::AstExprBinary::Add: value = FlowConstant::numberValue(current->second.number + right.number); break;
            case Luau::AstExprBinary::Sub: value = FlowConstant::numberValue(current->second.number - right.number); break;
            case Luau::AstExprBinary::Mul: value = FlowConstant::numberValue(current->second.number * right.number); break;
            case Luau::AstExprBinary::Div: value = FlowConstant::numberValue(current->second.number / right.number); break;
            case Luau::AstExprBinary::FloorDiv: value = FlowConstant::numberValue(std::floor(current->second.number / right.number)); break;
            case Luau::AstExprBinary::Mod: value = FlowConstant::numberValue(std::fmod(current->second.number, right.number)); break;
            case Luau::AstExprBinary::Pow: value = FlowConstant::numberValue(std::pow(current->second.number, right.number)); break;
            default: break;
            }
        }
        flow.constants[local->local] = value;
        if (local->local == state)
        {
            flow.values.clear();
            if (value.kind == FlowConstant::Kind::Number && std::isfinite(value.number) && std::abs(value.number - std::round(value.number)) <= 1e-7)
                flow.values.insert(static_cast<int64_t>(std::llround(value.number)));
            flow.unknown = flow.values.empty();
            flow.dynamic_index_reads.clear();
        }
        return flow;
    }
    if (auto conditional = statement->as<Luau::AstStatIf>())
    {
        FlowConstant condition = evaluateFlowConstant(conditional->condition, flow.constants);
        if (auto truthy = constantTruthy(condition))
        {
            if (*truthy)
                return analyzeStateFlow(conditional->thenbody, state, std::move(flow));
            if (auto elseBlock = conditional->elsebody ? conditional->elsebody->as<Luau::AstStatBlock>() : nullptr)
                return analyzeStateFlow(elseBlock, state, std::move(flow));
            if (conditional->elsebody)
                return analyzeStateStatement(conditional->elsebody, state, std::move(flow));
            return flow;
        }
        StateFlow thenFlow = analyzeStateFlow(conditional->thenbody, state, flow);
        StateFlow elseFlow = flow;
        if (auto elseBlock = conditional->elsebody ? conditional->elsebody->as<Luau::AstStatBlock>() : nullptr)
            elseFlow = analyzeStateFlow(elseBlock, state, flow);
        else if (conditional->elsebody)
            elseFlow = analyzeStateStatement(conditional->elsebody, state, flow);
        return unionFlow(thenFlow, elseFlow);
    }
    if (auto nested = statement->as<Luau::AstStatBlock>())
        return analyzeStateFlow(nested, state, flow);
    if (statement->is<Luau::AstStatReturn>() || statement->is<Luau::AstStatBreak>())
    {
        flow.falls_through = false;
        flow.values.clear();
        flow.unknown = false;
        flow.dynamic_index_reads.clear();
    }
    return flow;
}

StateFlow analyzeStateFlow(Luau::AstStatBlock* block, Luau::AstLocal* state, StateFlow flow)
{
    if (!block)
        return flow;
    for (Luau::AstStat* statement : block->body)
        flow = analyzeStateStatement(statement, state, std::move(flow));
    return flow;
}

struct StatementCounter : Luau::AstVisitor
{
    size_t count = 0;
    bool visit(Luau::AstStat*) override
    {
        ++count;
        return true;
    }
};

std::map<int64_t, BlockInfo> recoverBlocks(
    const WhileCandidate& dispatcher, const std::set<int64_t>& entries, const std::set<int64_t>& observedStates)
{
    std::map<int64_t, BlockInfo> blocks;
    if (!dispatcher.node || dispatcher.node->body->body.size == 0)
        return blocks;
    Luau::AstStat* tree = dispatcher.node->body->body.data[0];
    StateAssignmentCollector all(dispatcher.state);
    dispatcher.node->body->visit(&all);
    all.values.insert(entries.begin(), entries.end());
    all.values.insert(observedStates.begin(), observedStates.end());
    std::queue<int64_t> pending;
    std::set<int64_t> discovered = all.values;
    for (int64_t state : discovered)
        pending.push(state);
    while (!pending.empty())
    {
        if (discovered.size() > kMaxCfgStates)
            throw std::runtime_error("state count exceeds analysis limit");
        int64_t state = pending.front();
        pending.pop();
        Luau::AstStatBlock* leaf = selectLeaf(tree, dispatcher.state, state);
        if (!leaf)
            continue;
        StateFlow initial;
        initial.values.insert(state);
        StateFlow outgoing = analyzeStateFlow(leaf, dispatcher.state, std::move(initial));
        StatementCounter statements;
        leaf->visit(&statements);
        size_t instructionStatements = statements.count > 0 ? statements.count - 1 : 0;
        blocks[state] = {
            state,
            leaf,
            outgoing.values,
            outgoing.unknown && outgoing.falls_through ? 1u : 0u,
            instructionStatements,
            std::move(outgoing.dynamic_index_reads),
        };
        for (int64_t target : outgoing.values)
            if (discovered.insert(target).second)
                pending.push(target);
    }
    return blocks;
}

std::set<int64_t> reachableStates(const std::map<int64_t, BlockInfo>& blocks, const std::set<int64_t>& entries)
{
    std::set<int64_t> reached;
    std::queue<int64_t> pending;
    for (int64_t entry : entries)
        if (blocks.contains(entry))
            pending.push(entry);
    while (!pending.empty())
    {
        int64_t state = pending.front();
        pending.pop();
        if (!reached.insert(state).second)
            continue;
        auto block = blocks.find(state);
        if (block == blocks.end())
            continue;
        for (int64_t target : block->second.outgoing)
            if (blocks.contains(target) && !reached.contains(target))
                pending.push(target);
    }
    return reached;
}

struct RuntimeTraceAnalysis
{
    bool available = false;
    bool phase_split = false;
    size_t total_events = 0;
    size_t root_events = 0;
    size_t protector_events = 0;
    size_t payload_events = 0;
    std::optional<int64_t> first_payload_root;
    std::set<int64_t> hot_protector_states;
    std::set<int64_t> protector_states;
    std::set<int64_t> payload_root_states;
    std::set<int64_t> payload_helper_states;
    std::vector<int64_t> protector_root_sequence;
    std::vector<int64_t> payload_root_sequence;
};

RuntimeTraceAnalysis analyzeRuntimeTrace(const std::vector<int64_t>& states, const std::set<int64_t>& rootStates)
{
    RuntimeTraceAnalysis result;
    result.available = !states.empty();
    result.total_events = states.size();
    if (states.empty() || rootStates.empty())
        return result;

    std::map<int64_t, size_t> rootFrequency;
    for (int64_t state : states)
        if (rootStates.contains(state))
        {
            ++rootFrequency[state];
            ++result.root_events;
        }
    // Prometheus' bootstrap contains fixed 256-iteration permutation loops.
    // A low threshold confuses ordinary payload loops with protector traffic.
    constexpr size_t kProtectorHotStateMinimum = 128;
    for (const auto& [state, count] : rootFrequency)
        if (count >= kProtectorHotStateMinimum)
            result.hot_protector_states.insert(state);
    if (result.hot_protector_states.empty())
        return result;

    size_t cutoff = 0;
    bool foundCutoff = false;
    for (size_t i = 0; i < states.size(); ++i)
        if (result.hot_protector_states.contains(states[i]))
        {
            cutoff = i;
            foundCutoff = true;
        }
    if (!foundCutoff || cutoff + 1 >= states.size())
        return result;

    for (size_t i = 0; i <= cutoff; ++i)
    {
        result.protector_states.insert(states[i]);
        if (rootStates.contains(states[i]))
            result.protector_root_sequence.push_back(states[i]);
    }
    for (size_t i = cutoff + 1; i < states.size(); ++i)
    {
        int64_t state = states[i];
        if (rootStates.contains(state))
        {
            if (!result.first_payload_root)
                result.first_payload_root = state;
            result.payload_root_states.insert(state);
            result.payload_root_sequence.push_back(state);
        }
        else
            result.payload_helper_states.insert(state);
    }
    result.protector_events = cutoff + 1;
    result.payload_events = states.size() - result.protector_events;
    result.phase_split = result.first_payload_root.has_value() && !result.payload_root_states.empty();
    return result;
}

std::optional<double> evaluateJsonNumber(const json& expression)
{
    if (!expression.is_object())
        return std::nullopt;
    const std::string op = expression.value("op", "");
    if (op == "constant" && expression.contains("value") && expression["value"].is_number())
        return expression["value"].get<double>();
    if (op == "group")
        return evaluateJsonNumber(expression.value("value", json::object()));
    if (op == "unary" && expression.value("operator", "") == "-")
    {
        auto value = evaluateJsonNumber(expression.value("value", json::object()));
        return value ? std::optional<double>(-*value) : std::nullopt;
    }
    if (op != "binary")
        return std::nullopt;
    auto left = evaluateJsonNumber(expression.value("left", json::object()));
    auto right = evaluateJsonNumber(expression.value("right", json::object()));
    if (!left || !right)
        return std::nullopt;
    const std::string binary = expression.value("operator", "");
    if (binary == "+")
        return *left + *right;
    if (binary == "-")
        return *left - *right;
    if (binary == "*")
        return *left * *right;
    if (binary == "/")
        return *left / *right;
    if (binary == "//")
        return std::floor(*left / *right);
    if (binary == "%")
        return std::fmod(*left, *right);
    if (binary == "^")
        return std::pow(*left, *right);
    return std::nullopt;
}

std::optional<int64_t> evaluateJsonInteger(const json& expression)
{
    auto value = evaluateJsonNumber(expression);
    if (!value || !std::isfinite(*value) || std::abs(*value - std::round(*value)) > 1e-7)
        return std::nullopt;
    return static_cast<int64_t>(std::llround(*value));
}

void collectMakeClosureEntries(const json& value, std::set<int64_t>& entries)
{
    if (value.is_array())
    {
        for (const json& item : value)
            collectMakeClosureEntries(item, entries);
        return;
    }
    if (!value.is_object())
        return;
    if (value.value("op", "") == "make_closure")
        if (auto entry = evaluateJsonInteger(value.value("entry", json::object())))
            entries.insert(*entry);
    for (const auto& [key, item] : value.items())
    {
        (void)key;
        collectMakeClosureEntries(item, entries);
    }
}

std::string bytesFromHex(std::string_view hex)
{
    std::string result;
    if (hex.size() % 2 != 0)
        return result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        unsigned int value = 0;
        auto parsed = std::from_chars(hex.data() + i, hex.data() + i + 2, value, 16);
        if (parsed.ec != std::errc{})
            return {};
        result.push_back(static_cast<char>(value));
    }
    return result;
}

void collectLocalReads(const json& value, std::set<std::string>& reads)
{
    if (value.is_array())
    {
        for (const json& item : value)
            collectLocalReads(item, reads);
        return;
    }
    if (!value.is_object())
        return;
    if (value.value("op", "") == "local_read")
        reads.insert(value.value("name", ""));
    for (const auto& [key, item] : value.items())
    {
        (void)key;
        collectLocalReads(item, reads);
    }
}

struct PrometheusTemplateRecoveryStats
{
    size_t result_packs = 0;
    size_t fixed_arity_calls = 0;
    size_t fixed_arity_candidates = 0;
    size_t fixed_arity_projected_results_rejected = 0;
    size_t variadic_expansions = 0;
    size_t projected_results = 0;
    size_t projection_assignments_folded = 0;
    size_t transport_instructions_removed = 0;
    std::map<std::string, size_t> fixed_arity_rejections;
    std::set<std::string> counted_fixed_arity_candidates;

    void add(const PrometheusTemplateRecoveryStats& other)
    {
        result_packs += other.result_packs;
        fixed_arity_calls += other.fixed_arity_calls;
        fixed_arity_candidates += other.fixed_arity_candidates;
        fixed_arity_projected_results_rejected += other.fixed_arity_projected_results_rejected;
        variadic_expansions += other.variadic_expansions;
        projected_results += other.projected_results;
        projection_assignments_folded += other.projection_assignments_folded;
        transport_instructions_removed += other.transport_instructions_removed;
        for (const auto& [reason, count] : other.fixed_arity_rejections)
            fixed_arity_rejections[reason] += count;
    }

    void rejectFixedArity(const json& statement, std::string_view pack, size_t arity, std::string_view reason)
    {
        const json location = statement.value("location", json::object());
        const std::string key = std::to_string(location.value("line", 0)) + ":" +
                                std::to_string(location.value("column", 0)) + ":" + std::string(pack);
        if (!counted_fixed_arity_candidates.insert(key).second)
            return;
        ++fixed_arity_candidates;
        fixed_arity_projected_results_rejected += arity;
        ++fixed_arity_rejections[std::string(reason)];
    }

    json toJson() const
    {
        json rejections = json::object();
        for (const auto& [reason, count] : fixed_arity_rejections)
            rejections[reason] = count;
        return {
            {"result_packs", result_packs},
            {"fixed_arity_calls", fixed_arity_calls},
            {"fixed_arity_candidates", fixed_arity_candidates},
            {"fixed_arity_projected_results_rejected", fixed_arity_projected_results_rejected},
            {"fixed_arity_policy", "disabled_without_prototype_wide_reaching_definition_proof"},
            {"fixed_arity_rejections", std::move(rejections)},
            {"variadic_expansions", variadic_expansions},
            {"projected_results", projected_results},
            {"projection_assignments_folded", projection_assignments_folded},
            {"transport_instructions_removed", transport_instructions_removed},
        };
    }
};

size_t countLocalReadOccurrences(const json& value, std::string_view name)
{
    if (value.is_array())
    {
        size_t result = 0;
        for (const json& item : value)
            result += countLocalReadOccurrences(item, name);
        return result;
    }
    if (!value.is_object())
        return 0;
    size_t result = value.value("op", "") == "local_read" && value.value("name", "") == name ? 1 : 0;
    for (const auto& [key, item] : value.items())
    {
        (void)key;
        result += countLocalReadOccurrences(item, name);
    }
    return result;
}

bool writesLocal(const json& statement, std::string_view name)
{
    const std::string op = statement.value("op", "");
    if (op == "assign" || op == "local_assign")
        for (const json& target : statement.value("targets", json::array()))
            if (target.value("kind", "") == "local" && target.value("name", "") == name)
                return true;
    if (op == "compound_assign")
    {
        const json target = statement.value("target", json::object());
        return target.value("kind", "") == "local" && target.value("name", "") == name;
    }
    return false;
}

std::optional<std::pair<std::string, json>> prometheusCallResultPack(const json& statement)
{
    const std::string op = statement.value("op", "");
    if (op != "assign" && op != "local_assign")
        return std::nullopt;
    const json targets = statement.value("targets", json::array());
    const json values = statement.value("values", json::array());
    if (targets.size() != 1 || values.size() != 1 || targets[0].value("kind", "") != "local" ||
        values[0].value("op", "") != "table")
        return std::nullopt;
    const json items = values[0].value("items", json::array());
    if (items.size() != 1 || items[0].value("kind", "") != "list" || !items[0].value("expand_results", false))
        return std::nullopt;
    json packed = items[0].value("value", json::object());
    if (packed.value("op", "") != "call" && packed.value("op", "") != "varargs")
        return std::nullopt;
    return std::pair<std::string, json>{targets[0].value("name", ""), std::move(packed)};
}

std::optional<int64_t> projectedResultIndex(const json& value, std::string_view pack)
{
    if (value.value("op", "") != "index_read")
        return std::nullopt;
    const json table = value.value("table", json::object());
    if (table.value("op", "") != "local_read" || table.value("name", "") != pack)
        return std::nullopt;
    auto index = evaluateJsonInteger(value.value("index", json::object()));
    if (!index || *index < 1)
        return std::nullopt;
    return index;
}

bool isUnpackOfLocal(const json& value, std::string_view name)
{
    if (value.value("op", "") != "call" || value.value("method", false))
        return false;
    const json function = value.value("function", json::object());
    const json arguments = value.value("arguments", json::array());
    return function.value("op", "") == "local_read" && function.value("name", "") == "unpack_values" && arguments.size() == 1 &&
           arguments[0].value("op", "") == "local_read" && arguments[0].value("name", "") == name;
}

size_t replaceUnpackOfLocal(json& value, std::string_view name, const json& replacement)
{
    if (value.is_array())
    {
        size_t replaced = 0;
        for (json& item : value)
            replaced += replaceUnpackOfLocal(item, name, replacement);
        return replaced;
    }
    if (!value.is_object())
        return 0;
    if (isUnpackOfLocal(value, name))
    {
        value = replacement;
        return 1;
    }
    size_t replaced = 0;
    for (auto& [key, item] : value.items())
    {
        (void)key;
        replaced += replaceUnpackOfLocal(item, name, replacement);
    }
    return replaced;
}

struct ResultProjection
{
    int64_t result = 0;
    json target;
};

std::optional<size_t> canonicalFixedArityCall(const json& instructions, size_t packStatement, const std::string& pack)
{
    std::vector<ResultProjection> projections;
    size_t projectionEnd = packStatement + 1;
    while (projectionEnd < instructions.size())
    {
        const json& statement = instructions[projectionEnd];
        if (writesLocal(statement, pack))
            break;
        const std::string op = statement.value("op", "");
        if (op != "assign" && op != "local_assign")
            break;
        const json targets = statement.value("targets", json::array());
        const json values = statement.value("values", json::array());
        if (targets.empty() || targets.size() != values.size())
            break;
        std::vector<ResultProjection> statementProjections;
        statementProjections.reserve(values.size());
        for (size_t pair = 0; pair < values.size(); ++pair)
        {
            auto resultIndex = projectedResultIndex(values[pair], pack);
            if (!resultIndex || targets[pair].value("kind", "") != "local")
            {
                statementProjections.clear();
                break;
            }
            statementProjections.push_back({*resultIndex, targets[pair]});
        }
        if (statementProjections.size() != values.size())
            break;
        projections.insert(projections.end(), statementProjections.begin(), statementProjections.end());
        ++projectionEnd;
    }
    if (projectionEnd == packStatement + 1 || projections.size() < 2)
        return std::nullopt;

    for (size_t statementIndex = projectionEnd; statementIndex < instructions.size(); ++statementIndex)
    {
        if (writesLocal(instructions[statementIndex], pack))
            break;
        if (countLocalReadOccurrences(instructions[statementIndex], pack) != 0)
            return std::nullopt;
    }

    std::sort(projections.begin(), projections.end(), [](const ResultProjection& left, const ResultProjection& right) {
        return left.result < right.result;
    });
    std::set<std::string> targetNames;
    for (size_t index = 0; index < projections.size(); ++index)
    {
        if (projections[index].result != static_cast<int64_t>(index + 1))
            return std::nullopt;
        const std::string targetName = projections[index].target.value("name", "");
        if (targetName.empty() || targetName == pack || !targetNames.insert(targetName).second)
            return std::nullopt;
    }
    return projections.size();
}

bool recoverAdjacentVariadicExpansion(
    json& instructions,
    size_t packStatement,
    const std::string& pack,
    json packed,
    PrometheusTemplateRecoveryStats& stats)
{
    if (packStatement + 1 >= instructions.size() || writesLocal(instructions[packStatement + 1], pack) ||
        countLocalReadOccurrences(instructions[packStatement + 1], pack) != 1)
        return false;
    size_t reachingReads = 0;
    for (size_t statementIndex = packStatement + 1; statementIndex < instructions.size(); ++statementIndex)
    {
        if (writesLocal(instructions[statementIndex], pack))
            break;
        reachingReads += countLocalReadOccurrences(instructions[statementIndex], pack);
    }
    if (reachingReads != 1)
        return false;
    packed["result_mode"] = "all";
    packed["result_arity"] = "variadic";
    packed["recovered_from"] = "prometheus_call_result_pack";
    json consumer = instructions[packStatement + 1];
    if (replaceUnpackOfLocal(consumer, pack, packed) != 1)
        return false;
    consumer["recovered_template"] = {
        {"kind", "prometheus_final_result_expansion"},
        {"transport_pack", pack},
    };
    instructions[packStatement + 1] = std::move(consumer);
    instructions.erase(instructions.begin() + static_cast<json::difference_type>(packStatement));
    ++stats.result_packs;
    ++stats.variadic_expansions;
    ++stats.transport_instructions_removed;
    return true;
}

PrometheusTemplateRecoveryStats recoverPrometheusCompilerTemplates(json& instructions)
{
    PrometheusTemplateRecoveryStats stats;
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (size_t index = 0; index < instructions.size(); ++index)
        {
            auto pack = prometheusCallResultPack(instructions[index]);
            if (!pack || pack->first.empty())
                continue;
            if (auto arity = canonicalFixedArityCall(instructions, index, pack->first))
                stats.rejectFixedArity(
                    instructions[index], pack->first, *arity, "prototype_wide_reaching_definition_proof_unavailable");
            if (recoverAdjacentVariadicExpansion(instructions, index, pack->first, pack->second, stats))
            {
                changed = true;
                break;
            }
        }
    }
    return stats;
}

void collectCellIdentifierReads(const json& value, std::set<std::string>& reads)
{
    if (value.is_array())
    {
        for (const json& item : value)
            collectCellIdentifierReads(item, reads);
        return;
    }
    if (!value.is_object())
        return;
    const std::string op = value.value("op", "");
    const std::string kind = value.value("kind", "");
    if ((op == "cell_read" || kind == "cell") && value.value("id", json::object()).value("op", "") == "local_read")
        reads.insert(value.value("id", json::object()).value("name", ""));
    if (op == "make_closure")
        collectLocalReads(value.value("captures", json::object()), reads);
    for (const auto& [key, item] : value.items())
    {
        if (key != "captures" || op != "make_closure")
            collectCellIdentifierReads(item, reads);
    }
}

std::set<std::string> definedLocals(const json& statement)
{
    std::set<std::string> result;
    if (!statement.is_object())
        return result;
    const std::string op = statement.value("op", "");
    if (op == "assign" || op == "local_assign")
    {
        for (const json& target : statement.value("targets", json::array()))
            if ((target.value("kind", "") == "local" || target.value("kind", "") == "program_counter") && target.contains("name"))
                result.insert(target["name"].get<std::string>());
    }
    else if (op == "compound_assign")
    {
        const json target = statement.value("target", json::object());
        if ((target.value("kind", "") == "local" || target.value("kind", "") == "program_counter") && target.contains("name"))
            result.insert(target["name"].get<std::string>());
    }
    return result;
}

bool assignsAllocation(const json& statement, std::string_view name)
{
    if (statement.value("op", "") != "assign")
        return false;
    const json targets = statement.value("targets", json::array());
    const json values = statement.value("values", json::array());
    if (targets.size() != 1 || values.size() != 1 || targets[0].value("kind", "") != "local" || targets[0].value("name", "") != name)
        return false;
    const json call = values[0];
    return call.value("op", "") == "call" && call.value("arguments", json::array()).empty() &&
           call.value("function", json::object()).value("op", "") == "local_read" &&
           call.value("function", json::object()).value("name", "") == "allocate_cell";
}

bool writesCellNamed(const json& statement, std::string_view name)
{
    if (statement.value("op", "") != "assign")
        return false;
    for (const json& target : statement.value("targets", json::array()))
        if (target.value("kind", "") == "cell" && target.value("id", json::object()).value("op", "") == "local_read" &&
            target.value("id", json::object()).value("name", "") == name)
            return true;
    return false;
}

std::set<std::string> payloadLiveInRequirements(
    const RuntimeTraceAnalysis& trace, const std::map<int64_t, json>& normalizedBlocks)
{
    if (!trace.phase_split || trace.payload_root_sequence.empty())
        return {};

    const std::set<std::string> roleNames = {
        "pc", "arguments", "capture_ids", "frame_owner", "environment", "results", "allocate_cell", "release_cell", "release_captures",
        "capture_owner", "unpack_values", "newproxy_value", "setmetatable_value", "getmetatable_value", "select_value", "outer_arguments",
    };
    std::set<std::string> defined = roleNames;
    std::set<std::string> liveIns;
    for (int64_t state : trace.payload_root_sequence)
    {
        auto block = normalizedBlocks.find(state);
        if (block == normalizedBlocks.end())
            continue;
        for (const json& statement : block->second)
        {
            std::set<std::string> reads;
            collectLocalReads(statement, reads);
            if (statement.value("op", "") == "compound_assign")
            {
                const json target = statement.value("target", json::object());
                if (target.value("kind", "") == "local" || target.value("kind", "") == "program_counter")
                    reads.insert(target.value("name", ""));
            }
            for (const std::string& name : reads)
                if (!defined.contains(name) && name.rfind("closure_factory_", 0) != 0)
                    liveIns.insert(name);
            std::set<std::string> writes = definedLocals(statement);
            defined.insert(writes.begin(), writes.end());
        }
    }
    return liveIns;
}

std::set<std::string> payloadCellRequirements(
    const RuntimeTraceAnalysis& trace,
    const std::map<int64_t, json>& normalizedBlocks,
    const std::set<std::string>& liveIns)
{
    std::set<std::string> cells;
    if (!trace.phase_split)
        return cells;
    for (int64_t state : trace.payload_root_sequence)
    {
        auto block = normalizedBlocks.find(state);
        if (block == normalizedBlocks.end())
            continue;
        for (const json& statement : block->second)
        {
            std::set<std::string> reads;
            collectCellIdentifierReads(statement, reads);
            for (const std::string& name : reads)
                if (liveIns.contains(name))
                    cells.insert(name);
        }
    }
    return cells;
}

json recoverPayloadSetup(
    const RuntimeTraceAnalysis& trace,
    const std::map<int64_t, json>& normalizedBlocks,
    const std::set<std::string>& required)
{
    if (required.empty())
        return json::array();
    const std::set<std::string> roleNames = {
        "pc", "arguments", "capture_ids", "frame_owner", "environment", "results", "allocate_cell", "release_cell", "release_captures",
        "capture_owner", "unpack_values", "newproxy_value", "setmetatable_value", "getmetatable_value", "select_value", "outer_arguments",
    };

    struct Allocation
    {
        size_t sequence = 0;
        int64_t state = 0;
        size_t instruction = 0;
    };
    std::map<std::string, Allocation> allocations;
    for (size_t sequence = 0; sequence < trace.protector_root_sequence.size(); ++sequence)
    {
        int64_t state = trace.protector_root_sequence[sequence];
        auto block = normalizedBlocks.find(state);
        if (block == normalizedBlocks.end())
            continue;
        for (size_t instruction = 0; instruction < block->second.size(); ++instruction)
            for (const std::string& name : required)
                if (assignsAllocation(block->second[instruction], name))
                    allocations[name] = {sequence, state, instruction};
    }
    if (allocations.size() != required.size())
        return json::array();

    std::map<std::pair<size_t, int64_t>, std::set<size_t>> selected;
    for (const auto& [name, allocation] : allocations)
    {
        const json& instructions = normalizedBlocks.at(allocation.state);
        std::set<size_t>& marks = selected[{allocation.sequence, allocation.state}];
        marks.insert(allocation.instruction);
        for (size_t i = allocation.instruction + 1; i < instructions.size(); ++i)
        {
            if (assignsAllocation(instructions[i], name))
                break;
            if (writesCellNamed(instructions[i], name))
                marks.insert(i);
        }
    }

    for (auto& [location, marks] : selected)
    {
        const json& instructions = normalizedBlocks.at(location.second);
        bool changed = true;
        while (changed)
        {
            changed = false;
            std::vector<size_t> current(marks.begin(), marks.end());
            for (size_t index : current)
            {
                std::set<std::string> reads;
                collectLocalReads(instructions[index], reads);
                for (const std::string& name : reads)
                {
                    if (roleNames.contains(name) || name.rfind("closure_factory_", 0) == 0)
                        continue;
                    for (size_t previous = index; previous > 0; --previous)
                    {
                        const size_t candidate = previous - 1;
                        if (definedLocals(instructions[candidate]).contains(name))
                        {
                            if (marks.insert(candidate).second)
                                changed = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    json setup = json::array();
    for (const auto& [location, marks] : selected)
    {
        const json& instructions = normalizedBlocks.at(location.second);
        for (size_t index : marks)
            setup.push_back(instructions[index]);
    }
    return setup;
}

json recoveredSnapshotAssignments(
    const RuntimeSnapshot& snapshot,
    const std::set<std::string>& requiredCells,
    const std::set<std::string>& requiredRegisters)
{
    json assignments = json::array();
    auto identityByteLookup = [](const SnapshotCell& cell) {
        if (cell.type != "table" || cell.items.size() != 256)
            return false;
        std::map<int64_t, std::string> values;
        for (const auto& [key, itemValue] : cell.items)
        {
            auto index = evaluateJsonInteger(key);
            if (!index || *index < 1 || *index > 256 || itemValue.value("op", "") != "constant")
                return false;
            std::string value;
            if (itemValue.value("kind", "") == "bytes")
                value = bytesFromHex(itemValue.value("hex", ""));
            else if (itemValue.value("kind", "") == "string")
                value = itemValue.value("value", "");
            else
                return false;
            values[*index] = std::move(value);
        }
        for (int64_t index = 1; index <= 256; ++index)
            if (!values.contains(index) || values[index].size() != 1 || static_cast<unsigned char>(values[index][0]) != index - 1)
                return false;
        return true;
    };
    auto append = [&](const std::map<std::string, SnapshotCell>& storage, const std::string& name, bool cellTarget) {
        auto found = storage.find(name);
        if (found == storage.end())
            return;
        json value;
        if (found->second.type == "table")
        {
            if (identityByteLookup(found->second))
                value = {{"op", "identity_byte_table"}};
            else
            {
                json items = json::array();
                for (const auto& [key, itemValue] : found->second.items)
                    items.push_back({{"kind", "general"}, {"key", key}, {"value", itemValue}, {"expand_results", false}});
                value = {{"op", "table"}, {"items", std::move(items)}};
            }
        }
        else if (found->second.scalar)
            value = *found->second.scalar;
        else
            return;
        json target = cellTarget ? json{{"kind", "cell"}, {"id", {{"op", "local_read"}, {"name", name}}}} :
                                   json{{"kind", "local"}, {"name", name}};
        assignments.push_back({
            {"op", "assign"},
            {"targets", json::array({std::move(target)})},
            {"values", json::array({std::move(value)})},
            {"target_arity", 1},
            {"value_arity", 1},
            {"expand_final_result", false},
            {"evaluation_order", "snapshot_override"},
            {"location", {{"line", 0}, {"column", 0}}},
        });
    };
    for (const std::string& name : requiredCells)
        append(snapshot.cells, name, true);
    for (const std::string& name : requiredRegisters)
        append(snapshot.registers, name, false);
    return assignments;
}

bool snapshotSatisfies(
    const RuntimeSnapshot& snapshot,
    const std::set<std::string>& requiredCells,
    const std::set<std::string>& requiredRegisters)
{
    if (!snapshot.boundaryComplete())
        return false;
    for (const std::string& name : requiredCells)
    {
        auto found = snapshot.cells.find(name);
        if (found == snapshot.cells.end())
            return false;
    }
    for (const std::string& name : requiredRegisters)
    {
        auto found = snapshot.registers.find(name);
        if (found == snapshot.registers.end() || (found->second.type != "table" && !found->second.scalar))
            return false;
    }
    return true;
}

struct EmittedFunction
{
    int64_t identity_entry = 0;
    int64_t start_state = 0;
    std::string name;
    std::set<int64_t> blocks;
    json setup = json::array();
};

struct EmittedSource
{
    std::string source;
    json mapping = json::array();
    size_t statements = 0;
    size_t unsupported = 0;
};

class LuauStateMachineEmitter
{
public:
    LuauStateMachineEmitter(
        const std::map<int64_t, std::string>& functionNames,
        const std::map<int64_t, json>& normalizedBlocks,
        const json& registers
    )
        : functionNames(functionNames)
        , normalizedBlocks(normalizedBlocks)
    {
        for (const json& row : registers)
            if (row.contains("name") && row["name"].is_string())
                registerNames.push_back(row["name"].get<std::string>());
    }

    EmittedSource emit(const std::vector<EmittedFunction>& functions, int64_t rootIdentity)
    {
        append("-- Reconstructed from the WeAreDevs v1 semantic VM.\n");
        append("-- Original comments, formatting, and local names were not recoverable.\n");
        append("local environment = (getfenv and getfenv(0)) or _ENV\n");
        append("local unpack_values = unpack or table.unpack\n");
        append("local newproxy_value = environment[\"newproxy\"]\n");
        append("local setmetatable_value = setmetatable\n");
        append("local getmetatable_value = getmetatable\n");
        append("local select_value = select\n");
        append("local outer_arguments = {...}\n");
        append("local cells = {}\nlocal refcounts = {}\nlocal next_cell_id = 0\n");
        append("local function allocate_cell() next_cell_id += 1; refcounts[next_cell_id] = 1; return next_cell_id end\n");
        append("local function release_cell(_) return nil end\n");
        append("local function release_captures(_) return nil end\n");
        append("local function capture_owner(_) return {} end\n");
        append("local function bind_closure(prototype, capture_ids) return function(...) return prototype(capture_ids, ...) end end\n");
        append("local ");
        for (size_t i = 0; i < functions.size(); ++i)
        {
            if (i)
                append(", ");
            append(functions[i].name);
        }
        append("\n\n");

        for (const EmittedFunction& function : functions)
            emitFunction(function);
        auto root = functionNames.find(rootIdentity);
        if (root == functionNames.end())
        {
            ++unsupported;
            append("return nil\n");
        }
        else
            append("return " + root->second + "({}, unpack_values(outer_arguments))\n");
        return {output.str(), mapping, statementCount, unsupported};
    }

private:
    const std::map<int64_t, std::string>& functionNames;
    const std::map<int64_t, json>& normalizedBlocks;
    std::vector<std::string> registerNames;
    std::ostringstream output;
    json mapping = json::array();
    size_t line = 1;
    size_t statementCount = 0;
    size_t unsupported = 0;

    void append(std::string_view text)
    {
        output << text;
        line += static_cast<size_t>(std::count(text.begin(), text.end(), '\n'));
    }

    static std::string indent(size_t depth)
    {
        return std::string(depth * 2, ' ');
    }

    std::string expression(const json& value)
    {
        if (!value.is_object())
        {
            ++unsupported;
            return "nil";
        }
        const std::string op = value.value("op", "");
        const std::string kind = value.value("kind", "");
        if (op.empty() && kind == "string")
            return quoteLuau(value.value("value", ""));
        if (op.empty() && kind == "bytes")
            return quoteLuau(bytesFromHex(value.value("hex", "")));
        if (op == "constant")
        {
            if (kind == "bytes")
                return quoteLuau(bytesFromHex(value.value("hex", "")));
            if (kind == "string")
                return quoteLuau(value.value("value", ""));
            if (!value.contains("value") || value["value"].is_null())
                return "nil";
            if (value["value"].is_boolean())
                return value["value"].get<bool>() ? "true" : "false";
            if (value["value"].is_number())
                return value["value"].dump();
            if (value["value"].is_string())
                return quoteLuau(value["value"].get<std::string>());
        }
        if (op == "local_read")
            return value.value("name", "unknown_local");
        if (op == "global_read")
        {
            if (value.contains("key") && value["key"].is_object())
                return "environment[" + expression(value["key"]) + "]";
            return "environment[" + quoteLuau(value.value("name", "")) + "]";
        }
        if (op == "protector_return_sentinel")
            return "nil";
        if (op == "group")
            return "(" + expression(value.value("value", json::object())) + ")";
        if (op == "unary")
            return "(" + value.value("operator", "not") + " " + expression(value.value("value", json::object())) + ")";
        if (op == "binary")
            return "(" + expression(value.value("left", json::object())) + " " + value.value("operator", "+") + " " +
                   expression(value.value("right", json::object())) + ")";
        if (op == "if_expression")
            return "(if " + expression(value.value("condition", json::object())) + " then " + expression(value.value("then", json::object())) +
                   " else " + expression(value.value("else", json::object())) + ")";
        if (op == "varargs")
            return "...";
        if (op == "argument_read")
            return "arguments[" + expression(value.value("index", json::object())) + "]";
        if (op == "cell_read")
            return "cells[" + expression(value.value("id", json::object())) + "]";
        if (op == "upvalue_read")
            return "cells[capture_ids[" + std::to_string(value.value("slot", 0)) + "]]";
        if (op == "index_read")
        {
            std::string index;
            if (value.contains("index") && value["index"].is_string())
                index = quoteLuau(value["index"].get<std::string>());
            else
                index = expression(value.value("index", json::object()));
            return "(" + expression(value.value("table", json::object())) + ")[" + index + "]";
        }
        if (op == "table")
        {
            std::string result = "{";
            bool first = true;
            for (const json& item : value.value("items", json::array()))
            {
                if (!first)
                    result += ", ";
                first = false;
                const std::string itemKind = item.value("kind", "list");
                if (itemKind != "list")
                    result += "[" + expression(item.value("key", json::object())) + "] = ";
                result += expression(item.value("value", json::object()));
            }
            return result + "}";
        }
        if (op == "identity_byte_table")
            return "(function() local values = {} for index = 0, 255 do values[index + 1] = string.char(index) end return values end)()";
        if (op == "call")
        {
            std::vector<std::string> arguments;
            for (const json& argument : value.value("arguments", json::array()))
                arguments.push_back(expression(argument));
            const json function = value.value("function", json::object());
            if (value.value("method", false) && function.value("op", "") == "index_read")
            {
                std::string method;
                if (function.contains("index") && function["index"].is_string())
                    method = function["index"].get<std::string>();
                if (!method.empty() && isIdentifierStart(method.front()) && std::all_of(method.begin() + 1, method.end(), isIdentifier))
                    return "(" + expression(function.value("table", json::object())) + "):" + method + "(" + join(arguments) + ")";
                arguments.insert(arguments.begin(), expression(function.value("table", json::object())));
            }
            return "(" + expression(function) + ")(" + join(arguments) + ")";
        }
        if (op == "make_closure")
        {
            auto entry = evaluateJsonInteger(value.value("entry", json::object()));
            auto found = entry ? functionNames.find(*entry) : functionNames.end();
            if (found == functionNames.end())
            {
                ++unsupported;
                return "function(...) return nil end";
            }
            return "bind_closure(" + found->second + ", " + expression(value.value("captures", json::object())) + ")";
        }
        if (op == "native_closure")
            return "function(...) return nil end";
        ++unsupported;
        return "nil";
    }

    static std::string join(const std::vector<std::string>& values)
    {
        std::string result;
        for (size_t i = 0; i < values.size(); ++i)
        {
            if (i)
                result += ", ";
            result += values[i];
        }
        return result;
    }

    std::string target(const json& value)
    {
        const std::string kind = value.value("kind", "");
        if (kind == "local" || kind == "program_counter")
            return value.value("name", "unknown_local");
        if (kind == "cell")
            return "cells[" + expression(value.value("id", json::object())) + "]";
        if (kind == "upvalue")
            return "cells[capture_ids[" + std::to_string(value.value("slot", 0)) + "]]";
        if (kind == "global")
        {
            if (value.contains("key") && value["key"].is_object())
                return "environment[" + expression(value["key"]) + "]";
            return "environment[" + quoteLuau(value.value("name", "")) + "]";
        }
        if (kind == "index")
            return "(" + expression(value.value("table", json::object())) + ")[" + expression(value.value("index", json::object())) + "]";
        ++unsupported;
        return "unknown_target";
    }

    void statement(const json& value, size_t depth)
    {
        ++statementCount;
        const std::string op = value.value("op", "");
        if (op == "assign" || op == "local_assign")
        {
            std::vector<std::string> targets;
            std::vector<std::string> values;
            for (const json& item : value.value("targets", json::array()))
                targets.push_back(target(item));
            for (const json& item : value.value("values", json::array()))
                values.push_back(expression(item));
            append(indent(depth) + join(targets) + " = " + (values.empty() ? "nil" : join(values)) + ";\n");
            return;
        }
        if (op == "compound_assign")
        {
            std::string compoundOperator = value.value("operator", "+");
            if (!compoundOperator.ends_with('='))
                compoundOperator += '=';
            append(indent(depth) + target(value.value("target", json::object())) + " " + compoundOperator + " " +
                   expression(value.value("value", json::object())) + ";\n");
            return;
        }
        if (op == "expression")
        {
            append(indent(depth) + expression(value.value("value", json::object())) + ";\n");
            return;
        }
        if (op == "return")
        {
            std::vector<std::string> values;
            for (const json& item : value.value("values", json::array()))
                values.push_back(expression(item));
            append(indent(depth) + "return" + (values.empty() ? "" : " " + join(values)) + "\n");
            return;
        }
        if (op == "if")
        {
            append(indent(depth) + "if " + expression(value.value("condition", json::object())) + " then\n");
            for (const json& item : value.value("then", json::array()))
                statement(item, depth + 1);
            if (!value.value("else", json::array()).empty())
            {
                append(indent(depth) + "else\n");
                for (const json& item : value.value("else", json::array()))
                    statement(item, depth + 1);
            }
            append(indent(depth) + "end\n");
            return;
        }
        if (op == "block")
        {
            for (const json& item : value.value("body", json::array()))
                statement(item, depth);
            return;
        }
        if (op == "break" || op == "continue")
        {
            append(indent(depth) + op + "\n");
            return;
        }
        ++unsupported;
        append(indent(depth) + "-- unsupported normalized operation\n");
    }

    void emitFunction(const EmittedFunction& function)
    {
        append(function.name + " = function(capture_ids, ...)\n");
        append("  capture_ids = capture_ids or {}\n  local arguments = {...}\n  local pc = " + std::to_string(function.start_state) + "\n  local results = {}\n");
        if (!registerNames.empty())
            append("  local " + join(registerNames) + "\n");
        if (!function.setup.empty())
        {
            append("  -- Minimal cell setup retained from the protector prelude.\n");
            for (const json& item : function.setup)
                statement(item, 1);
        }
        append("  while pc do\n");
        bool first = true;
        for (int64_t state : function.blocks)
        {
            auto found = normalizedBlocks.find(state);
            if (found == normalizedBlocks.end())
                continue;
            const size_t firstLine = line;
            append(std::string(first ? "    if pc == " : "    elseif pc == ") + std::to_string(state) + " then\n");
            first = false;
            for (const json& item : found->second)
                statement(item, 3);
            mapping.push_back({{"function", function.name}, {"state", state}, {"line_start", firstLine}, {"line_end", line - 1}});
        }
        if (first)
            append("    return nil\n");
        else
            append("    else\n      return nil\n    end\n");
        append("  end\n  return unpack_values(results)\nend\n\n");
    }
};

bool plausibleSource(std::string_view value)
{
    if (value.size() < 12 || value.find('\0') != std::string_view::npos || !printableAscii(value))
        return false;
    size_t score = 0;
    for (std::string_view token : {"local ", "function", "return ", "print(", "game:", "Instance.new"})
        score += value.find(token) != std::string_view::npos;
    return score >= 2 && value.find("wearedevs.net/obfuscator") == std::string_view::npos;
}

std::optional<rbx::runtime::RegisterOverflowRewrite> prepareStandaloneSource(std::string_view source)
{
    std::string bytecode = Luau::compile(std::string(source));
    if (!bytecode.empty() && bytecode[0] != 0)
    {
        rbx::runtime::RegisterOverflowRewrite result;
        result.source.assign(source);
        return result;
    }
    if (bytecode.size() < 2)
        return std::nullopt;
    const std::string_view error(bytecode.data() + 1, bytecode.size() - 1);
    if (error.find("Out of local registers") == std::string_view::npos &&
        error.find("Out of upvalue registers") == std::string_view::npos)
        return std::nullopt;

    const bool upvalueOverflow = error.find("Out of upvalue registers") != std::string_view::npos;
    rbx::runtime::RegisterOverflowRewrite rewritten =
        rbx::runtime::spillRegisterOverflow(source, upvalueOverflow ? 90 : 140);
    if (!rewritten.applied)
        return std::nullopt;
    bytecode = Luau::compile(rewritten.source);
    if (bytecode.empty() || bytecode[0] == 0)
        return std::nullopt;
    return rewritten;
}

bool compiles(std::string_view source)
{
    return prepareStandaloneSource(source).has_value();
}

std::optional<std::string> compileDiagnostic(std::string_view source)
{
    const std::string bytecode = Luau::compile(std::string(source));
    if (!bytecode.empty() && bytecode[0] != 0)
        return std::nullopt;
    if (bytecode.size() > 1)
        return std::string(bytecode.data() + 1, bytecode.size() - 1);
    return std::string("Luau compiler rejected the candidate without a diagnostic");
}

json stateFieldRefinementMetrics(const std::optional<state_fields::RefinementResult>& refinement)
{
    if (!refinement)
    {
        return {
            {"attempted", false},
            {"parse_succeeded", nullptr},
            {"compile_attempted", false},
            {"candidate_compiled", nullptr},
            {"applied", false},
            {"generated_callback_fields_found", 0},
            {"fields_proposed", 0},
            {"fields_renamed", 0},
            {"references_proposed", 0},
            {"references_renamed", 0},
            {"ambiguous_fields", 0},
            {"unproven_fields", 0},
            {"unsafe_state_tables", 0},
            {"unsafe_fields", 0},
            {"name_collisions_detected", 0},
            {"name_collisions_avoided", 0},
            {"diagnostics", json::array()},
        };
    }

    return {
        {"attempted", true},
        {"parse_succeeded", refinement->parse_succeeded},
        {"compile_attempted", refinement->compile_attempted},
        {"candidate_compiled", refinement->compile_attempted ? json(refinement->candidate_compiled) : json(nullptr)},
        {"applied", refinement->committed},
        {"generated_callback_fields_found", refinement->generated_callback_fields_found},
        {"fields_proposed", refinement->fields_proposed},
        {"fields_renamed", refinement->fields_renamed},
        {"references_proposed", refinement->references_proposed},
        {"references_renamed", refinement->references_renamed},
        {"ambiguous_fields", refinement->ambiguous_fields},
        {"unproven_fields", refinement->unproven_fields},
        {"unsafe_state_tables", refinement->unsafe_state_tables},
        {"unsafe_fields", refinement->unsafe_fields},
        {"name_collisions_detected", refinement->name_collisions_detected},
        {"name_collisions_avoided", refinement->name_collisions_avoided},
        {"diagnostics", refinement->diagnostics},
    };
}

void publishProgress(const Options& options, std::string_view stage, std::string_view status,
    std::string_view message, json metrics = json::object())
{
    if (!options.progress)
        return;
    options.progress({
        {"stage", stage},
        {"status", status},
        {"message", message},
        {"metrics", std::move(metrics)},
    });
}

json artifactNode(const fs::path& root, const fs::path& path, std::string kind, std::string provenance, bool sourceBearing)
{
    std::string data = readFile(path);
    return {
        {"id", sha256(data)},
        {"kind", std::move(kind)},
        {"bytes", data.size()},
        {"path", fs::relative(path, root).generic_string()},
        {"provenance", std::move(provenance)},
        {"source_bearing", sourceBearing},
    };
}

json luraphRange(const std::optional<luraph::SourceRange>& range)
{
    if (!range)
        return nullptr;
    return {{"begin", range->begin}, {"end", range->end}, {"bytes", range->size()}};
}

json luraphByteSpan(const luraph::ByteSpan& span)
{
    return {{"begin", span.begin}, {"end", span.end}, {"bytes", span.size()}};
}

json luraphByteSpan(const std::optional<luraph::ByteSpan>& span)
{
    return span ? luraphByteSpan(*span) : json(nullptr);
}

bool hasParsedLuraphContainer(const luraph::EnvelopeAnalysis& analysis)
{
    return analysis.container_metrics.parsed_count > 0;
}

bool hasDecodedLuraphContainer(const luraph::EnvelopeAnalysis& analysis)
{
    return analysis.container_metrics.decoded_count > 0;
}

std::string_view luraphAdapterName(const luraph::EnvelopeAnalysis& analysis)
{
    if (analysis.generated_interpreter)
        return "luraph-runtime-interpreter";
    if (analysis.luaauth_launcher.present)
        return "luraph-luaauth-lph-dollar";
    return "luraph-v14.7";
}

size_t retainedLuraphInstructionCount(const luraph::EnvelopeAnalysis& analysis)
{
    size_t count = 0;
    for (const luraph::ContainerAnalysis& container : analysis.containers)
    {
        if (container.parse_status != luraph::ContainerParseStatus::Parsed &&
            container.parse_status != luraph::ContainerParseStatus::StructuralMetadataRecovered)
            continue;
        for (const luraph::PrototypeMetadata& prototype : container.prototypes)
            count += prototype.instructions.size();
    }
    return count;
}

json luraphSideReferenceArtifact(const luraph::vm::SideReference& reference)
{
    if (reference.kind == luraph::vm::ReferenceKind::None)
        return nullptr;
    return {
        {"kind", luraph::vm::toString(reference.kind)},
        {"wrapper_index", reference.wrapper_index},
        {"metadata_index", reference.metadata_index ? json(*reference.metadata_index) : json(nullptr)},
        {"valid", reference.valid},
    };
}

json luraphOperandLaneArtifact(const luraph::vm::OperandLane& lane)
{
    return {
        {"raw_word", lane.raw_word},
        {"residue", lane.residue},
        {"quotient", lane.quotient},
        {"base_value", lane.base_value},
        {"side_reference", luraphSideReferenceArtifact(lane.side_reference)},
    };
}

json luraphInstructionArtifact(
    const luraph::InstructionMetadata& instruction,
    size_t constantCount,
    size_t prototypeCount)
{
    const luraph::vm::NormalizedInstruction normalized =
        luraph::vm::normalizeInstruction(instruction, constantCount, prototypeCount);
    json words = json::array();
    for (size_t index = 0; index < instruction.words.size(); ++index)
    {
        const luraph::InstructionWordMetadata& word = instruction.words[index];
        words.push_back({
            {"index", index},
            {"value", word.value},
            {"span", luraphByteSpan(word.span)},
        });
    }
    return {
        {"index", instruction.index},
        {"pc", normalized.pc},
        {"span", luraphByteSpan(instruction.span)},
        {"encoding", "luraph-v14.7-normalized-lanes"},
        {"words", std::move(words)},
        {"opcode", normalized.opcode},
        {"opcode_decoded", true},
        {"operand_lanes_normalized", true},
        {"operation_semantics_recovered", false},
        {"operands", {
            {"D", luraphOperandLaneArtifact(normalized.D)},
            {"G", luraphOperandLaneArtifact(normalized.G)},
            {"p", luraphOperandLaneArtifact(normalized.p)},
        }},
    };
}

json luraphPrototypeArtifact(
    size_t containerIndex,
    const luraph::PrototypeMetadata& prototype,
    size_t constantCount,
    size_t prototypeCount)
{
    json instructions = json::array();
    for (const luraph::InstructionMetadata& instruction : prototype.instructions)
        instructions.push_back(luraphInstructionArtifact(instruction, constantCount, prototypeCount));

    json descriptors = json::array();
    for (const luraph::DescriptorMetadata& descriptor : prototype.descriptors)
    {
        descriptors.push_back({
            {"index", descriptor.index},
            {"raw_value", descriptor.raw_value},
            {"kind", descriptor.kind},
            {"referenced_index", descriptor.referenced_index},
            {"span", luraphByteSpan(descriptor.span)},
        });
    }

    return {
        {"container_index", containerIndex},
        {"index", prototype.index},
        {"wrapper_index", prototype.index + 1},
        {"span", luraphByteSpan(prototype.span)},
        {"meta", prototype.meta},
        {"meta_span", luraphByteSpan(prototype.meta_span)},
        {"instruction_count", prototype.instruction_count},
        {"instruction_count_span", luraphByteSpan(prototype.instruction_count_span)},
        {"instruction_words_span", luraphByteSpan(prototype.instruction_words_span)},
        {"instructions", std::move(instructions)},
        {"descriptor_count", prototype.descriptor_count},
        {"descriptor_count_span", luraphByteSpan(prototype.descriptor_count_span)},
        {"descriptors_span", luraphByteSpan(prototype.descriptors_span)},
        {"descriptors", std::move(descriptors)},
        {"final_value", prototype.final_value},
        {"register_capacity", prototype.final_value},
        {"entry_pc", 1},
        {"final_span", luraphByteSpan(prototype.final_span)},
        {"semantically_lifted", false},
    };
}

json luraphConstantArtifact(size_t containerIndex, const luraph::ConstantMetadata& constant)
{
    json artifact = {
        {"container_index", containerIndex},
        {"index", constant.index},
        {"wrapper_index", constant.index + 1},
        {"tag", constant.tag},
        {"kind", std::string(luraph::toString(constant.kind))},
        {"span", luraphByteSpan(constant.span)},
        {"tag_span", luraphByteSpan(constant.tag_span)},
        {"length_span", luraphByteSpan(constant.length_span)},
        {"data_span", luraphByteSpan(constant.data_span)},
        {"data_bytes", constant.data_bytes},
        {"value_bytes_retained", true},
        {"value_available", true},
    };

    if (constant.kind == luraph::ConstantKind::Integer)
    {
        if (constant.signed_integer_value)
        {
            artifact["value"] = *constant.signed_integer_value;
            artifact["signed"] = true;
            artifact["encoding"] = constant.tag <= 39 ? "i16-le"
                : constant.tag == 90                  ? "i32-le"
                                                      : "negated-u8";
        }
        else if (constant.unsigned_integer_value)
        {
            artifact["value"] = *constant.unsigned_integer_value;
            artifact["signed"] = false;
            artifact["encoding"] = constant.tag == 156 ? "u64-le"
                : constant.tag <= 198                  ? "u8"
                : constant.tag <= 232                  ? "u16-le"
                                                       : "u32-le";
        }
        else
            artifact["value_available"] = false;
    }
    else if (constant.kind == luraph::ConstantKind::Boolean)
    {
        if (constant.boolean_value)
            artifact["value"] = *constant.boolean_value;
        else
            artifact["value_available"] = false;
        artifact["encoding"] = "tag-immediate";
    }
    else if (constant.kind == luraph::ConstantKind::String)
    {
        const std::string bytes(constant.string_bytes.begin(), constant.string_bytes.end());
        artifact["encoding"] = "exact-bytes";
        artifact["bytes"] = bytes.size();
        artifact["bytes_hex"] = hexBytes(bytes);
        artifact["bytes_sha256"] = sha256(bytes);
        artifact["printable_ascii"] = printableAscii(bytes);
        artifact["text"] = printableAscii(bytes) ? json(bytes) : json(nullptr);
    }
    else if (constant.kind == luraph::ConstantKind::Float)
    {
        const bool is32 = constant.float32_bits.has_value();
        artifact["encoding"] = is32 ? "f32-le" : "f64-le";
        if (is32 && constant.float32_value)
        {
            const float value = *constant.float32_value;
            std::ostringstream bits;
            bits << "0x" << std::hex << std::setw(8) << std::setfill('0') << *constant.float32_bits;
            artifact["raw_bits"] = bits.str();
            artifact["negative_zero"] = value == 0.0f && std::signbit(value);
            artifact["classification"] = std::isnan(value) ? "nan"
                : std::isinf(value)                         ? (std::signbit(value) ? "negative_infinity" : "positive_infinity")
                                                            : "finite";
            artifact["value"] = std::isfinite(value) ? json(static_cast<double>(value)) : json(nullptr);
        }
        else if (constant.float64_bits && constant.float64_value)
        {
            const double value = *constant.float64_value;
            std::ostringstream bits;
            bits << "0x" << std::hex << std::setw(16) << std::setfill('0') << *constant.float64_bits;
            artifact["raw_bits"] = bits.str();
            artifact["negative_zero"] = value == 0.0 && std::signbit(value);
            artifact["classification"] = std::isnan(value) ? "nan"
                : std::isinf(value)                          ? (std::signbit(value) ? "negative_infinity" : "positive_infinity")
                                                             : "finite";
            artifact["value"] = std::isfinite(value) ? json(value) : json(nullptr);
        }
        else
            artifact["value_available"] = false;
    }
    else if (constant.kind == luraph::ConstantKind::Nil)
    {
        artifact["encoding"] = "nil";
        artifact["value"] = nullptr;
    }

    return artifact;
}

json luraphEnvelopeArtifact(const luraph::EnvelopeAnalysis& analysis)
{
    json blobs = json::array();
    for (const luraph::BlobCandidate& blob : analysis.blobs)
    {
        blobs.push_back({
            {"kind", std::string(luraph::toString(blob.kind))},
            {"range", luraphRange(blob.range)},
            {"source_bytes", blob.source_bytes},
            {"distinct_byte_count", blob.distinct_byte_count},
            {"printable_ratio", blob.printable_ratio},
            {"whitespace_ratio", blob.whitespace_ratio},
            {"long_bracket_literal", blob.long_bracket_literal},
            {"has_lph_marker", blob.has_lph_marker},
            {"content_included", false},
        });
    }

    json stages = json::array();
    for (const luraph::Stage& stage : analysis.stages)
    {
        stages.push_back({
            {"kind", std::string(luraph::toString(stage.kind))},
            {"confidence", stage.confidence},
            {"summary", stage.summary},
            {"range", luraphRange(stage.range)},
        });
    }

    json evidence = json::array();
    for (const luraph::ConfidenceEvidence& item : analysis.confidence.evidence)
        evidence.push_back({{"code", item.code}, {"weight", item.weight}, {"description", item.description}});

    json diagnostics = json::array();
    for (const luraph::Diagnostic& diagnostic : analysis.diagnostics)
    {
        diagnostics.push_back({
            {"severity", std::string(luraph::toString(diagnostic.severity))},
            {"code", diagnostic.code},
            {"message", diagnostic.message},
            {"range", luraphRange(diagnostic.range)},
        });
    }

    json carriers = json::array();
    for (size_t index = 0; index < analysis.carriers.size(); ++index)
    {
        const luraph::CarrierExtraction& carrier = analysis.carriers[index];
        carriers.push_back({
            {"index", index},
            {"kind", std::string(luraph::toString(carrier.kind))},
            {"literal_kind", std::string(luraph::toString(carrier.literal_kind))},
            {"decode_status", std::string(luraph::toString(carrier.status))},
            {"literal_range", luraphRange(carrier.literal_range)},
            {"content_range", luraphRange(carrier.content_range)},
            {"error_range", luraphRange(carrier.error_range)},
            {"literal_source_bytes", carrier.literal_source_bytes},
            {"decoded_bytes", carrier.decoded_byte_count},
            {"lph_marker_offset", carrier.lph_marker_offset ? json(*carrier.lph_marker_offset) : json(nullptr)},
            {"container_index", carrier.container_index ? json(*carrier.container_index) : json(nullptr)},
            {"content_included", false},
        });
    }

    json containers = json::array();
    for (size_t index = 0; index < analysis.containers.size(); ++index)
    {
        const luraph::ContainerAnalysis& container = analysis.containers[index];
        json item = {
            {"index", index},
            {"carrier_index", container.carrier_index},
            {"decode_status", std::string(luraph::toString(container.decode_status))},
            {"parse_status", std::string(luraph::toString(container.parse_status))},
            {"encoded_carrier_bytes", container.encoded_carrier_bytes},
            {"encoded_body_bytes", container.encoded_body_bytes},
            {"radix85_group_count", container.radix85_group_count},
            {"radix85_zero_group_count", container.radix85_zero_group_count},
            {"decoded_bytes", container.decoded_bytes},
            {"decoded_sha256", container.decoded_sha256.empty() ? json(nullptr) : json(container.decoded_sha256)},
            {"marker", container.marker == 0 ? json(nullptr) : json(std::string(1, static_cast<char>(container.marker)))},
            {"encoded_error_offset", container.encoded_error_offset ? json(*container.encoded_error_offset) : json(nullptr)},
            {"parse_error_offset", container.parse_error_offset ? json(*container.parse_error_offset) : json(nullptr)},
        };
        if (container.parse_status == luraph::ContainerParseStatus::Parsed)
        {
            item.update({
                {"constant_count", container.constant_count},
                {"constant_count_span", luraphByteSpan(container.constant_count_span)},
                {"constant_pool_mode", container.constant_pool_mode},
                {"constant_pool_mode_span", luraphByteSpan(container.constant_pool_mode_span)},
                {"constants_span", luraphByteSpan(container.constants_span)},
                {"prototype_count", container.prototype_count},
                {"prototype_count_span", luraphByteSpan(container.prototype_count_span)},
                {"prototypes_span", luraphByteSpan(container.prototypes_span)},
                {"instruction_count", container.instruction_count},
                {"descriptor_count", container.descriptor_count},
                {"root_selector", container.root_selector},
                {"root_wrapper_index", container.root_selector},
                {"root_metadata_index", container.root_selector >= 1 && container.root_selector <= container.prototypes.size()
                        ? json(container.root_selector - 1)
                        : json(nullptr)},
                {"root_selector_span", luraphByteSpan(container.root_selector_span)},
                {"trailer_span", luraphByteSpan(container.trailer_span)},
                {"trailer_bytes_retained", container.trailer_bytes.size()},
            });
        }
        containers.push_back(std::move(item));
    }

    const luraph::EnvelopeCounts& counts = analysis.counts;
    const luraph::StaticDecodeMetrics& staticDecode = analysis.static_decode;
    const luraph::ContainerMetrics& containerMetrics = analysis.container_metrics;
    const bool parsedContainer = hasParsedLuraphContainer(analysis);
    const bool decodedContainer = hasDecodedLuraphContainer(analysis);
    return {
        {"version", 1},
        {"adapter", luraphAdapterName(analysis)},
        {"scope", analysis.generated_interpreter ? "runtime-generated-interpreter" :
            (parsedContainer ? "source-envelope-and-decoded-container" :
                decodedContainer ? "source-envelope-and-decoded-carrier" : "source-envelope-only")},
        {"bounded", analysis.bounded},
        {"structural_scan_complete", analysis.complete},
        {"family_detected", analysis.family_detected},
        {"version_supported", analysis.version_supported},
        {"generated_interpreter", analysis.generated_interpreter},
        {"source_recovery_attempted", analysis.source_recovery_attempted},
        {"payload_decoded", staticDecode.payload_decoded},
        {"container_decoded", containerMetrics.decoded_count > 0},
        {"container_parsed", parsedContainer},
        {"instructions_disassembled", parsedContainer},
        {"semantic_lifted", false},
        {"banner", {
            {"present", analysis.banner.present},
            {"exact_product_marker", analysis.banner.exact_product_marker},
            {"official_url_marker", analysis.banner.official_url_marker},
            {"product", analysis.banner.product},
            {"version", analysis.banner.version},
            {"major", analysis.banner.major ? json(*analysis.banner.major) : json(nullptr)},
            {"minor", analysis.banner.minor ? json(*analysis.banner.minor) : json(nullptr)},
            {"patch", analysis.banner.patch ? json(*analysis.banner.patch) : json(nullptr)},
            {"range", luraphRange(analysis.banner.range)},
        }},
        {"luaauth_launcher", {
            {"present", analysis.luaauth_launcher.present},
            {"exact_assignment_shape", analysis.luaauth_launcher.exact_assignment_shape},
            {"official_url_marker", analysis.luaauth_launcher.official_url_marker},
            {"metadata_removed_from_body", analysis.luaauth_launcher.metadata_removed_from_body},
            {"code_digit_count", analysis.luaauth_launcher.code_digit_count},
            {"script_id_byte_count", analysis.luaauth_launcher.script_id_byte_count},
            {"values_retained", false},
            {"range", luraphRange(analysis.luaauth_launcher.range)},
            {"protected_body_range", luraphRange(analysis.luaauth_launcher.protected_body_range)},
        }},
        {"wrapper", {
            {"kind", std::string(luraph::toString(analysis.wrapper.kind))},
            {"top_level_return", analysis.wrapper.top_level_return},
            {"parenthesized_table", analysis.wrapper.parenthesized_table},
            {"balanced_table", analysis.wrapper.balanced_table},
            {"zero_argument_method_call", analysis.wrapper.zero_argument_method_call},
            {"forwards_varargs", analysis.wrapper.forwards_varargs},
            {"consumes_entire_chunk", analysis.wrapper.consumes_entire_chunk},
            {"method_name", analysis.wrapper.method_name},
            {"table_field_count", analysis.wrapper.table_field_count},
            {"function_member_count", analysis.wrapper.function_member_count},
            {"table_range", luraphRange(analysis.wrapper.table_range)},
            {"invocation_range", luraphRange(analysis.wrapper.invocation_range)},
        }},
        {"counts", {
            {"source_bytes", counts.source_bytes},
            {"tokens", counts.token_count},
            {"comments", counts.comment_count},
            {"identifiers", counts.identifier_count},
            {"numeric_literals", counts.numeric_literal_count},
            {"string_literals", counts.string_literal_count},
            {"string_literal_source_bytes", counts.string_literal_source_bytes},
            {"encoded_string_candidates", counts.encoded_string_candidate_count},
            {"encoded_blob_candidates", counts.encoded_blob_candidate_count},
            {"encoded_blob_source_bytes", counts.encoded_blob_source_bytes},
            {"table_constructors", counts.table_constructor_count},
            {"function_literals", counts.function_literal_count},
            {"loop_constructs", counts.loop_construct_count},
            {"indexed_accesses", counts.indexed_access_count},
            {"reader_primitive_references", counts.reader_primitive_reference_count},
        }},
        {"blobs", std::move(blobs)},
        {"static_decode", {
            {"eligible", staticDecode.eligible},
            {"attempted", staticDecode.attempted},
            {"complete", staticDecode.complete},
            {"payload_decode_attempted", staticDecode.payload_decode_attempted},
            {"payload_decoded", staticDecode.payload_decoded},
            {"carrier_candidates", staticDecode.carrier_candidate_count},
            {"carrier_attempts", staticDecode.carrier_attempt_count},
            {"carriers_decoded", staticDecode.carrier_decoded_count},
            {"carrier_failures", staticDecode.carrier_failure_count},
            {"carriers_skipped", staticDecode.carrier_skipped_count},
            {"carrier_literal_source_bytes", staticDecode.carrier_literal_source_bytes},
            {"decoded_carrier_bytes", staticDecode.decoded_carrier_bytes},
            {"byte_limit_hits", staticDecode.byte_limit_hit_count},
            {"reader_metadata", staticDecode.reader_metadata_count},
            {"reader_definitions", staticDecode.reader_definition_count},
            {"reader_references", staticDecode.reader_reference_count},
        }},
        {"container_metrics", {
            {"candidate_count", containerMetrics.candidate_count},
            {"attempt_count", containerMetrics.attempt_count},
            {"decoded_count", containerMetrics.decoded_count},
            {"parsed_count", containerMetrics.parsed_count},
            {"failure_count", containerMetrics.failure_count},
            {"candidates", containerMetrics.candidate_count},
            {"attempts", containerMetrics.attempt_count},
            {"decoded", containerMetrics.decoded_count},
            {"parsed", containerMetrics.parsed_count},
            {"failures", containerMetrics.failure_count},
            {"encoded_body_bytes", containerMetrics.encoded_body_bytes},
            {"radix85_group_count", containerMetrics.radix85_group_count},
            {"radix85_zero_group_count", containerMetrics.radix85_zero_group_count},
            {"radix85_groups", containerMetrics.radix85_group_count},
            {"decoded_bytes", containerMetrics.decoded_bytes},
            {"constant_count", containerMetrics.constant_count},
            {"prototype_count", containerMetrics.prototype_count},
            {"instruction_count", containerMetrics.instruction_count},
            {"descriptor_count", containerMetrics.descriptor_count},
            {"constants", containerMetrics.constant_count},
            {"prototypes", containerMetrics.prototype_count},
            {"instructions", containerMetrics.instruction_count},
            {"descriptors", containerMetrics.descriptor_count},
            {"trailer_bytes", containerMetrics.trailer_bytes},
        }},
        {"carriers", std::move(carriers)},
        {"containers", std::move(containers)},
        {"stages", std::move(stages)},
        {"confidence", {
            {"score", analysis.confidence.score},
            {"level", std::string(luraph::toString(analysis.confidence.level))},
            {"evidence", std::move(evidence)},
        }},
        {"diagnostics", std::move(diagnostics)},
    };
}

struct LuraphTraceValue
{
    std::string type;
    std::string value;
};

Luau::AstExpr* unwrapLuraphExpression(Luau::AstExpr* expression)
{
    while (expression)
    {
        if (auto group = expression->as<Luau::AstExprGroup>())
            expression = group->expr;
        else if (auto assertion = expression->as<Luau::AstExprTypeAssertion>())
            expression = assertion->expr;
        else
            break;
    }
    return expression;
}

struct LuraphLoopShape
{
    Luau::AstStat* loop = nullptr;
    Luau::AstStatBlock* body = nullptr;
    Luau::AstStatLocal* fetch = nullptr;
    Luau::AstLocal* pc = nullptr;
    Luau::AstLocal* opcode_table = nullptr;
    Luau::AstLocal* opcode = nullptr;
    size_t conditionals = 0;
};

struct LuraphLoopShapeCollector : Luau::AstVisitor
{
    std::vector<LuraphLoopShape> shapes;

    void collect(Luau::AstStat* loop, Luau::AstExpr* conditionExpression, Luau::AstStatBlock* body, bool expectedCondition)
    {
        Luau::AstExpr* unwrappedCondition = conditionExpression ? unwrapLuraphExpression(conditionExpression) : nullptr;
        auto condition = unwrappedCondition ? unwrappedCondition->as<Luau::AstExprConstantBool>() : nullptr;
        if (!condition || condition->value != expectedCondition || body->body.size == 0)
            return;
        auto fetch = body->body.data[0]->as<Luau::AstStatLocal>();
        if (!fetch || fetch->vars.size != 1 || fetch->values.size != 1)
            return;
        Luau::AstExpr* unwrappedValue = unwrapLuraphExpression(fetch->values.data[0]);
        auto indexed = unwrappedValue ? unwrappedValue->as<Luau::AstExprIndexExpr>() : nullptr;
        auto table = indexed ? unwrapLuraphExpression(indexed->expr)->as<Luau::AstExprLocal>() : nullptr;
        auto pc = indexed ? unwrapLuraphExpression(indexed->index)->as<Luau::AstExprLocal>() : nullptr;
        if (!table || !pc)
            return;
        IfCounter counter;
        body->visit(&counter);
        shapes.push_back({loop, body, fetch, pc->local, table->local, fetch->vars.data[0], counter.count});
    }

    bool visit(Luau::AstStatWhile* node) override
    {
        collect(node, node->condition, node->body, true);
        return true;
    }

    bool visit(Luau::AstStatRepeat* node) override
    {
        collect(node, node->condition, node->body, false);
        return true;
    }
};

struct LuraphConditionLocalFinder : Luau::AstVisitor
{
    explicit LuraphConditionLocalFinder(Luau::AstLocal* target)
        : target(target)
    {
    }

    Luau::AstLocal* target = nullptr;
    bool found = false;

    bool visit(Luau::AstExprLocal* node) override
    {
        found = found || node->local == target;
        return !found;
    }
};

struct LuraphOpcodeDispatcherCollector : Luau::AstVisitor
{
    explicit LuraphOpcodeDispatcherCollector(Luau::AstLocal* opcode)
        : opcode(opcode)
    {
    }

    struct Candidate
    {
        Luau::AstStatIf* node = nullptr;
        size_t conditionals = 0;
    };

    Luau::AstLocal* opcode = nullptr;
    std::vector<Candidate> candidates;

    bool visit(Luau::AstStatIf* node) override
    {
        LuraphConditionLocalFinder reference(opcode);
        node->condition->visit(&reference);
        if (!reference.found)
            return true;
        bool opcodeCondition = false;
        for (int64_t sample : {int64_t(0), int64_t(80), int64_t(255)})
            opcodeCondition = opcodeCondition || evaluateStateCondition(node->condition, opcode, sample).has_value();
        if (opcodeCondition)
        {
            IfCounter counter;
            node->visit(&counter);
            candidates.push_back({node, counter.count});
        }
        return true;
    }
};

struct LuraphGuardBindingCollector : Luau::AstVisitor
{
    explicit LuraphGuardBindingCollector(Luau::AstLocal* opcode)
        : opcode(opcode)
    {
    }

    Luau::AstLocal* opcode = nullptr;
    std::map<std::pair<Luau::AstLocal*, int64_t>, size_t> scores;

    bool visit(Luau::AstExprBinary* node) override
    {
        if (node->op != Luau::AstExprBinary::CompareEq && node->op != Luau::AstExprBinary::CompareNe)
            return true;
        Luau::AstExpr* leftExpression = unwrapLuraphExpression(node->left);
        Luau::AstExpr* rightExpression = unwrapLuraphExpression(node->right);
        auto leftLocal = leftExpression ? leftExpression->as<Luau::AstExprLocal>() : nullptr;
        auto rightLocal = rightExpression ? rightExpression->as<Luau::AstExprLocal>() : nullptr;
        const std::optional<int64_t> leftNumber = evaluateAstInteger(node->left);
        const std::optional<int64_t> rightNumber = evaluateAstInteger(node->right);
        if (leftLocal && leftLocal->local != opcode && rightNumber)
            ++scores[{leftLocal->local, *rightNumber}];
        else if (rightLocal && rightLocal->local != opcode && leftNumber)
            ++scores[{rightLocal->local, *leftNumber}];
        return true;
    }
};

struct LuraphLocalReferenceCollector : Luau::AstVisitor
{
    std::set<Luau::AstLocal*> locals;

    bool visit(Luau::AstExprLocal* node) override
    {
        locals.insert(node->local);
        return true;
    }
};

struct LuraphLocalConstantProofCollector : Luau::AstVisitor
{
    explicit LuraphLocalConstantProofCollector(Luau::AstLocal* target)
        : target(target)
    {
    }

    Luau::AstLocal* target = nullptr;
    Luau::AstStatLocal* declaration = nullptr;
    std::optional<double> initializer;
    size_t declarations = 0;
    size_t writes = 0;

    bool visit(Luau::AstStatLocal* node) override
    {
        for (size_t index = 0; index < node->vars.size; ++index)
        {
            if (node->vars.data[index] != target)
                continue;
            ++declarations;
            declaration = node;
            initializer = index < node->values.size
                ? evaluateAstNumber(node->values.data[index]) : std::nullopt;
        }
        return true;
    }

    bool visit(Luau::AstStatAssign* node) override
    {
        for (Luau::AstExpr* variable : node->vars)
        {
            Luau::AstExpr* expression = unwrapLuraphExpression(variable);
            auto local = expression ? expression->as<Luau::AstExprLocal>() : nullptr;
            if (local && local->local == target)
                ++writes;
        }
        return true;
    }

    bool visit(Luau::AstStatCompoundAssign* node) override
    {
        Luau::AstExpr* expression = unwrapLuraphExpression(node->var);
        auto local = expression ? expression->as<Luau::AstExprLocal>() : nullptr;
        if (local && local->local == target)
            ++writes;
        return true;
    }

    bool proven() const
    {
        return declarations == 1 && declaration && initializer.has_value() && writes == 0;
    }
};

std::map<Luau::AstLocal*, double> proveLuraphGuardBindings(
    Luau::AstStatBlock* root,
    Luau::AstStat* dispatcher,
    Luau::AstLocal* opcode,
    const SourceView& view,
    json* evidence = nullptr)
{
    std::map<Luau::AstLocal*, double> bindings;
    LuraphLocalReferenceCollector references;
    dispatcher->visit(&references);
    for (Luau::AstLocal* local : references.locals)
    {
        if (!local || local == opcode)
            continue;
        LuraphLocalConstantProofCollector proof(local);
        root->visit(&proof);
        if (!proof.proven())
            continue;
        bindings[local] = *proof.initializer;
        if (evidence)
        {
            evidence->push_back({
                {"local", local->name.value ? json(std::string(local->name.value)) : json(nullptr)},
                {"value", *proof.initializer},
                {"declaration_range", {
                    {"begin", view.offset(proof.declaration->location.begin)},
                    {"end", view.offset(proof.declaration->location.end)},
                }},
                {"writes_after_initialization", proof.writes},
                {"proof", "single_numeric_initializer_no_bound_local_writes"},
            });
        }
    }
    return bindings;
}

struct LuraphExecutedStatementPath
{
    std::vector<Luau::AstStat*> statements;
    bool complete = true;
    bool falls_through = true;
    bool ambiguous = false;
    size_t dispatcher_statements = 0;
    size_t continuation_statements = 0;
};

using LuraphBranchDecision = std::function<std::optional<bool>(Luau::AstStatIf*)>;

// A selected branch resumes in each enclosing block. Retain those continuations
// so normalization and validation see every statement executed by the handler.
bool accumulateLuraphExecutedStatements(
    Luau::AstStat* statement,
    const LuraphBranchDecision& decide,
    LuraphExecutedStatementPath& path);

bool accumulateLuraphExecutedStatements(
    Luau::AstStatBlock* block,
    const LuraphBranchDecision& decide,
    LuraphExecutedStatementPath& path,
    size_t begin = 0)
{
    if (!block)
        return true;
    for (size_t index = begin; index < block->body.size && path.falls_through; ++index)
        if (!accumulateLuraphExecutedStatements(block->body.data[index], decide, path))
            return false;
    return path.complete;
}

bool accumulateLuraphExecutedStatements(
    Luau::AstStat* statement,
    const LuraphBranchDecision& decide,
    LuraphExecutedStatementPath& path)
{
    if (!statement || !path.falls_through)
        return path.complete;
    if (auto block = statement->as<Luau::AstStatBlock>())
        return accumulateLuraphExecutedStatements(block, decide, path);
    if (auto conditional = statement->as<Luau::AstStatIf>())
    {
        const std::optional<bool> decision = decide(conditional);
        if (!decision)
        {
            path.complete = false;
            path.ambiguous = true;
            return false;
        }
        Luau::AstStat* selected = *decision
            ? static_cast<Luau::AstStat*>(conditional->thenbody)
            : conditional->elsebody;
        return !selected || accumulateLuraphExecutedStatements(selected, decide, path);
    }

    path.statements.push_back(statement);
    if (statement->is<Luau::AstStatReturn>() || statement->is<Luau::AstStatBreak>() ||
        statement->is<Luau::AstStatContinue>())
        path.falls_through = false;
    return true;
}

LuraphExecutedStatementPath selectLuraphExecutedStatementPath(
    Luau::AstStatIf* dispatcher,
    Luau::AstStatBlock* loopBody,
    const LuraphBranchDecision& decide)
{
    LuraphExecutedStatementPath path;
    if (!dispatcher || !loopBody || !accumulateLuraphExecutedStatements(dispatcher, decide, path))
        return path;

    path.dispatcher_statements = path.statements.size();
    if (!path.falls_through)
        return path;

    size_t dispatcherIndex = loopBody->body.size;
    for (size_t index = 0; index < loopBody->body.size; ++index)
        if (loopBody->body.data[index] == dispatcher)
        {
            dispatcherIndex = index;
            break;
        }
    if (dispatcherIndex == loopBody->body.size)
    {
        path.complete = false;
        path.ambiguous = true;
        return path;
    }

    accumulateLuraphExecutedStatements(loopBody, decide, path, dispatcherIndex + 1);
    path.continuation_statements = path.statements.size() - path.dispatcher_statements;
    return path;
}

Luau::AstStatBlock luraphExecutedStatementBlock(LuraphExecutedStatementPath& path)
{
    Luau::Location location;
    if (!path.statements.empty())
    {
        location.begin = path.statements.front()->location.begin;
        location.end = path.statements.back()->location.end;
    }
    return Luau::AstStatBlock(location,
        Luau::AstArray<Luau::AstStat*>{path.statements.data(), path.statements.size()});
}

json luraphExecutedStatementRanges(const LuraphExecutedStatementPath& path, const SourceView& view)
{
    json ranges = json::array();
    for (Luau::AstStat* statement : path.statements)
    {
        const size_t begin = view.offset(statement->location.begin);
        const size_t end = view.offset(statement->location.end);
        ranges.push_back({{"begin", begin}, {"end", end}, {"bytes", end >= begin ? end - begin : 0}});
    }
    return ranges;
}

std::string luraphExecutedStatementSource(const LuraphExecutedStatementPath& path, const SourceView& view)
{
    std::string source;
    for (Luau::AstStat* statement : path.statements)
    {
        if (!source.empty())
            source += "\n";
        source += view.slice(statement->location, 16384 - std::min<size_t>(source.size(), 16384));
        if (source.size() >= 16384)
            break;
    }
    return source;
}

struct LuraphGuardCondition
{
    Luau::AstExpr* expression = nullptr;
    std::string kind;
    std::vector<std::string> locals;
};

struct LuraphGuardConditionCollector : Luau::AstVisitor
{
    LuraphGuardConditionCollector(
        Luau::AstLocal* opcode,
        const std::map<Luau::AstLocal*, double>& bindings)
        : opcode(opcode)
        , bindings(bindings)
    {
    }

    Luau::AstLocal* opcode = nullptr;
    const std::map<Luau::AstLocal*, double>& bindings;
    std::vector<LuraphGuardCondition> conditions;

    void collect(Luau::AstExpr* expression, std::string_view kind)
    {
        bool staticallyDecidable = true;
        for (int64_t value = 0; value <= 255; ++value)
        {
            if (!evaluateStateCondition(expression, opcode, value, &bindings).has_value())
            {
                staticallyDecidable = false;
                break;
            }
        }
        if (staticallyDecidable)
            return;

        LuraphLocalReferenceCollector references;
        expression->visit(&references);
        std::vector<std::string> locals;
        for (Luau::AstLocal* local : references.locals)
            if (local && local->name.value)
                locals.emplace_back(local->name.value);
        std::sort(locals.begin(), locals.end());
        locals.erase(std::unique(locals.begin(), locals.end()), locals.end());
        conditions.push_back({expression, std::string(kind), std::move(locals)});
    }

    bool visit(Luau::AstStatIf* node) override
    {
        collect(node->condition, "if");
        return true;
    }

    bool visit(Luau::AstStatWhile* node) override
    {
        collect(node->condition, "while");
        return true;
    }

    bool visit(Luau::AstStatRepeat* node) override
    {
        collect(node->condition, "repeat");
        return true;
    }

    bool visit(Luau::AstExprFunction*) override
    {
        return false;
    }
};

json luraphGuardConditionManifest(
    Luau::AstStat* dispatcher,
    Luau::AstLocal* opcode,
    const std::map<Luau::AstLocal*, double>& bindings,
    const SourceView& view)
{
    LuraphGuardConditionCollector collector(opcode, bindings);
    dispatcher->visit(&collector);
    std::sort(collector.conditions.begin(), collector.conditions.end(), [&](const auto& left, const auto& right) {
        const size_t leftBegin = view.offset(left.expression->location.begin);
        const size_t rightBegin = view.offset(right.expression->location.begin);
        if (leftBegin != rightBegin)
            return leftBegin < rightBegin;
        return view.offset(left.expression->location.end) < view.offset(right.expression->location.end);
    });
    json rows = json::array();
    for (const LuraphGuardCondition& condition : collector.conditions)
    {
        rows.push_back({
            {"begin", view.offset(condition.expression->location.begin)},
            {"end", view.offset(condition.expression->location.end)},
            {"kind", condition.kind},
            {"locals", condition.locals},
            {"capture", "decision_at_evaluation"},
        });
    }
    return rows;
}

struct LuraphRegisterRoleCollector : Luau::AstVisitor
{
    explicit LuraphRegisterRoleCollector(Luau::AstLocal* pc)
        : pc(pc)
    {
    }

    Luau::AstLocal* pc = nullptr;
    std::map<Luau::AstLocal*, size_t> register_scores;
    std::set<Luau::AstLocal*> pc_indexed_tables;

    bool visit(Luau::AstExprIndexExpr* node) override
    {
        auto base = unwrapLuraphExpression(node->expr)->as<Luau::AstExprLocal>();
        Luau::AstExpr* indexExpression = unwrapLuraphExpression(node->index);
        if (auto index = indexExpression->as<Luau::AstExprLocal>())
        {
            if (base && index->local == pc)
                pc_indexed_tables.insert(base->local);
        }
        else if (auto nested = indexExpression->as<Luau::AstExprIndexExpr>())
        {
            auto lane = unwrapLuraphExpression(nested->expr)->as<Luau::AstExprLocal>();
            auto laneIndex = unwrapLuraphExpression(nested->index)->as<Luau::AstExprLocal>();
            if (base && lane && laneIndex && laneIndex->local == pc)
            {
                ++register_scores[base->local];
                pc_indexed_tables.insert(lane->local);
            }
        }
        return true;
    }
};

struct LuraphTopRoleCollector : Luau::AstVisitor
{
    explicit LuraphTopRoleCollector(Luau::AstLocal* registers)
        : registers(registers)
    {
    }

    Luau::AstLocal* registers = nullptr;
    std::map<Luau::AstLocal*, size_t> scores;

    bool visit(Luau::AstExprCall* node) override
    {
        bool passesRegisterFile = false;
        for (Luau::AstExpr* argument : node->args)
        {
            Luau::AstExpr* expression = unwrapLuraphExpression(argument);
            auto local = expression ? expression->as<Luau::AstExprLocal>() : nullptr;
            passesRegisterFile = passesRegisterFile || (local && local->local == registers);
        }
        if (!passesRegisterFile)
            return true;
        for (Luau::AstExpr* argument : node->args)
        {
            Luau::AstExpr* expression = unwrapLuraphExpression(argument);
            auto local = expression ? expression->as<Luau::AstExprLocal>() : nullptr;
            if (local && local->local != registers)
                ++scores[local->local];
        }
        return true;
    }
};

struct LuraphUpvalueRoleCollector : Luau::AstVisitor
{
    LuraphUpvalueRoleCollector(Luau::AstLocal* registers, Luau::AstLocal* pc, std::set<Luau::AstLocal*> lanes)
        : registers(registers)
        , pc(pc)
        , lanes(std::move(lanes))
    {
    }

    Luau::AstLocal* registers = nullptr;
    Luau::AstLocal* pc = nullptr;
    std::set<Luau::AstLocal*> lanes;
    std::map<Luau::AstLocal*, size_t> scores;

    bool visit(Luau::AstExprIndexExpr* node) override
    {
        auto base = unwrapLuraphExpression(node->expr)->as<Luau::AstExprLocal>();
        auto indexedOperand = unwrapLuraphExpression(node->index)->as<Luau::AstExprIndexExpr>();
        auto lane = indexedOperand ? unwrapLuraphExpression(indexedOperand->expr)->as<Luau::AstExprLocal>() : nullptr;
        auto lanePc = indexedOperand ? unwrapLuraphExpression(indexedOperand->index)->as<Luau::AstExprLocal>() : nullptr;
        if (base && base->local != registers && lane && lanePc && lanePc->local == pc && lanes.contains(lane->local))
            ++scores[base->local];
        return true;
    }
};

struct LuraphDirectRegisterSourceCollector : Luau::AstVisitor
{
    explicit LuraphDirectRegisterSourceCollector(Luau::AstLocal* registers)
        : registers(registers)
    {
    }

    Luau::AstLocal* registers = nullptr;
    std::map<Luau::AstLocal*, size_t> scores;

    bool visit(Luau::AstStatAssign* node) override
    {
        if (node->vars.size != 1 || node->values.size != 1)
            return true;
        Luau::AstExpr* target = unwrapLuraphExpression(node->vars.data[0]);
        auto index = target ? target->as<Luau::AstExprIndexExpr>() : nullptr;
        auto base = index ? unwrapLuraphExpression(index->expr)->as<Luau::AstExprLocal>() : nullptr;
        if (!base || base->local != registers)
            return true;
        Luau::AstExpr* value = unwrapLuraphExpression(node->values.data[0]);
        if (auto local = value ? value->as<Luau::AstExprLocal>() : nullptr)
            ++scores[local->local];
        return true;
    }
};

struct LuraphHelperRoleCollector : Luau::AstVisitor
{
    std::map<Luau::AstLocal*, size_t> scores;

    bool visit(Luau::AstExprCall* node) override
    {
        Luau::AstExpr* function = unwrapLuraphExpression(node->func);
        auto index = function ? function->as<Luau::AstExprIndexExpr>() : nullptr;
        auto base = index ? unwrapLuraphExpression(index->expr)->as<Luau::AstExprLocal>() : nullptr;
        Luau::AstExpr* key = index ? unwrapLuraphExpression(index->index) : nullptr;
        if (base && key && (key->is<Luau::AstExprConstantInteger>() || key->is<Luau::AstExprConstantNumber>()))
            ++scores[base->local];
        return true;
    }
};

struct LuraphOpcodeReferenceFinder : Luau::AstVisitor
{
    explicit LuraphOpcodeReferenceFinder(Luau::AstLocal* opcode)
        : opcode(opcode)
    {
    }

    Luau::AstLocal* opcode = nullptr;
    bool found = false;

    bool visit(Luau::AstExprLocal* node) override
    {
        found = found || node->local == opcode;
        return !found;
    }
};

Luau::AstLocal* luraphIndexedBase(Luau::AstExpr* expression)
{
    expression = unwrapLuraphExpression(expression);
    auto index = expression ? expression->as<Luau::AstExprIndexExpr>() : nullptr;
    Luau::AstExpr* baseExpression = index ? unwrapLuraphExpression(index->expr) : nullptr;
    auto base = baseExpression ? baseExpression->as<Luau::AstExprLocal>() : nullptr;
    return base ? base->local : nullptr;
}

struct LuraphHandlerEffects : Luau::AstVisitor
{
    LuraphHandlerEffects(Luau::AstLocal* registers, Luau::AstLocal* pc, std::set<Luau::AstLocal*> lanes)
        : registers(registers)
        , pc(pc)
        , lanes(std::move(lanes))
    {
    }

    Luau::AstLocal* registers = nullptr;
    Luau::AstLocal* pc = nullptr;
    std::set<Luau::AstLocal*> lanes;
    size_t register_reads = 0;
    size_t register_writes = 0;
    size_t register_calls = 0;
    size_t pc_writes = 0;
    size_t lane_reads = 0;
    size_t table_writes = 0;
    size_t calls = 0;
    size_t returns = 0;
    size_t closures = 0;
    size_t vararg_reads = 0;
    size_t conditionals = 0;

    void collectWrite(Luau::AstExpr* expression)
    {
        Luau::AstExpr* unwrapped = unwrapLuraphExpression(expression);
        if (auto local = unwrapped ? unwrapped->as<Luau::AstExprLocal>() : nullptr)
        {
            if (local->local == pc)
                ++pc_writes;
            return;
        }
        if (unwrapped && unwrapped->is<Luau::AstExprIndexExpr>())
        {
            ++table_writes;
            if (registers && luraphIndexedBase(unwrapped) == registers)
                ++register_writes;
        }
    }

    bool visit(Luau::AstExprIndexExpr* node) override
    {
        Luau::AstLocal* base = luraphIndexedBase(node);
        if (registers && base == registers)
            ++register_reads;
        if (lanes.contains(base))
            ++lane_reads;
        return true;
    }

    bool visit(Luau::AstStatAssign* node) override
    {
        for (Luau::AstExpr* variable : node->vars)
            collectWrite(variable);
        return true;
    }

    bool visit(Luau::AstStatCompoundAssign* node) override
    {
        collectWrite(node->var);
        return true;
    }

    bool visit(Luau::AstExprCall* node) override
    {
        ++calls;
        if (registers && luraphIndexedBase(node->func) == registers)
            ++register_calls;
        return true;
    }

    bool visit(Luau::AstStatReturn*) override
    {
        ++returns;
        return true;
    }

    bool visit(Luau::AstExprFunction*) override
    {
        ++closures;
        return false;
    }

    bool visit(Luau::AstExprVarargs*) override
    {
        ++vararg_reads;
        return true;
    }

    bool visit(Luau::AstStatIf*) override
    {
        ++conditionals;
        return true;
    }

    json artifact() const
    {
        json candidates = json::array();
        if (returns > 0)
            candidates.push_back("return");
        if (pc_writes > 0)
            candidates.push_back(conditionals > 0 ? "conditional_control_flow" : "control_flow");
        if (closures > 0)
            candidates.push_back("closure");
        if (register_calls > 0)
            candidates.push_back("call");
        if (register_writes > 0)
            candidates.push_back("register_write");
        if (table_writes > register_writes)
            candidates.push_back("table_write");
        if (vararg_reads > 0)
            candidates.push_back("vararg");
        return {
            {"register_reads", register_reads},
            {"register_writes", register_writes},
            {"register_calls", register_calls},
            {"pc_writes", pc_writes},
            {"lane_reads", lane_reads},
            {"table_writes", table_writes},
            {"calls", calls},
            {"returns", returns},
            {"closures", closures},
            {"vararg_reads", vararg_reads},
            {"conditionals", conditionals},
            {"operation_candidates", std::move(candidates)},
        };
    }
};

struct LuraphSemanticRoles
{
    Luau::AstLocal* registers = nullptr;
    Luau::AstLocal* pc = nullptr;
    Luau::AstLocal* opcode = nullptr;
    Luau::AstLocal* opcode_table = nullptr;
    Luau::AstLocal* top = nullptr;
    Luau::AstLocal* environment = nullptr;
    Luau::AstLocal* upvalues = nullptr;
    Luau::AstLocal* helpers = nullptr;
    std::map<Luau::AstLocal*, std::string> lanes;
    std::map<Luau::AstLocal*, std::string> semantic_locals;
};

struct LuraphLocalReferenceSet : Luau::AstVisitor
{
    std::set<Luau::AstLocal*> locals;

    bool visit(Luau::AstExprLocal* node) override
    {
        if (node->local)
            locals.insert(node->local);
        return true;
    }

    bool visit(Luau::AstExprFunction*) override
    {
        return false;
    }
};

struct LuraphOpcode8OperandAliasCollector : Luau::AstVisitor
{
    explicit LuraphOpcode8OperandAliasCollector(const LuraphSemanticRoles& roles)
        : roles(roles)
    {
    }

    const LuraphSemanticRoles& roles;
    std::map<Luau::AstLocal*, std::string> aliases;

    bool visit(Luau::AstStatAssign* node) override
    {
        if (node->vars.size != 1 || node->values.size != 1)
            return true;
        auto target = unwrapLuraphExpression(node->vars.data[0])->as<Luau::AstExprLocal>();
        auto source = unwrapLuraphExpression(node->values.data[0])->as<Luau::AstExprIndexExpr>();
        auto table = source ? unwrapLuraphExpression(source->expr)->as<Luau::AstExprLocal>() : nullptr;
        auto index = source ? unwrapLuraphExpression(source->index)->as<Luau::AstExprLocal>() : nullptr;
        if (!target || !table || !index || index->local != roles.pc)
            return true;
        const auto lane = roles.lanes.find(table->local);
        if (lane != roles.lanes.end())
            aliases[target->local] = lane->second;
        return true;
    }

    bool visit(Luau::AstExprFunction*) override
    {
        return false;
    }
};

struct LuraphOpcode8ShapeCollector : Luau::AstVisitor
{
    LuraphOpcode8ShapeCollector(
        const LuraphSemanticRoles& roles,
        const std::map<Luau::AstLocal*, std::string>& aliases)
        : roles(roles)
        , aliases(aliases)
    {
    }

    const LuraphSemanticRoles& roles;
    const std::map<Luau::AstLocal*, std::string>& aliases;
    std::set<Luau::AstLocal*> register_call_bases;
    std::set<Luau::AstLocal*> register_loop_bases;
    std::set<Luau::AstLocal*> top_dependencies;
    std::map<Luau::AstLocal*, std::set<int64_t>> compared_constants;
    size_t register_calls = 0;
    size_t register_result_loops = 0;

    bool visit(Luau::AstExprCall* node) override
    {
        auto function = unwrapLuraphExpression(node->func)->as<Luau::AstExprIndexExpr>();
        auto index = function ? unwrapLuraphExpression(function->index)->as<Luau::AstExprLocal>() : nullptr;
        if (function && index && luraphIndexedBase(function) == roles.registers && aliases.contains(index->local))
        {
            register_call_bases.insert(index->local);
            ++register_calls;
        }
        return true;
    }

    bool visit(Luau::AstStatFor* node) override
    {
        auto from = unwrapLuraphExpression(node->from)->as<Luau::AstExprLocal>();
        if (from && aliases.contains(from->local))
        {
            LuraphHandlerEffects effects(roles.registers, roles.pc, {});
            node->body->visit(&effects);
            if (effects.register_writes > 0)
            {
                register_loop_bases.insert(from->local);
                ++register_result_loops;
            }
        }
        return true;
    }

    bool visit(Luau::AstStatAssign* node) override
    {
        if (node->vars.size == 1 && node->values.size == 1)
        {
            auto target = unwrapLuraphExpression(node->vars.data[0])->as<Luau::AstExprLocal>();
            if (target && target->local == roles.top)
            {
                LuraphLocalReferenceSet references;
                node->values.data[0]->visit(&references);
                top_dependencies.insert(references.locals.begin(), references.locals.end());
            }
        }
        return true;
    }

    bool visit(Luau::AstExprBinary* node) override
    {
        if (node->op != Luau::AstExprBinary::CompareEq && node->op != Luau::AstExprBinary::CompareNe)
            return true;
        auto left = unwrapLuraphExpression(node->left)->as<Luau::AstExprLocal>();
        auto right = unwrapLuraphExpression(node->right)->as<Luau::AstExprLocal>();
        const std::optional<double> leftNumber = evaluateAstNumber(node->left);
        const std::optional<double> rightNumber = evaluateAstNumber(node->right);
        const auto retain = [&](Luau::AstExprLocal* local, const std::optional<double>& number) {
            if (!local || !number || !std::isfinite(*number) || std::floor(*number) != *number ||
                (*number != 0.0 && *number != 1.0) || !aliases.contains(local->local))
                return;
            compared_constants[local->local].insert(static_cast<int64_t>(*number));
        };
        retain(left, rightNumber);
        retain(right, leftNumber);
        return true;
    }

    bool visit(Luau::AstExprFunction*) override
    {
        return false;
    }
};

json recognizeLuraphOpcode8PackedCallShape(
    Luau::AstStatBlock* handler,
    const LuraphSemanticRoles& roles,
    bool staticGuardPathComplete)
{
    json result = {
        {"verified", false},
        {"static_guard_path_complete", staticGuardPathComplete},
        {"proof", "structural_ast"},
    };
    if (!handler || !roles.registers || !roles.pc || !roles.top)
    {
        result["diagnostic"] = "required VM roles are unavailable";
        return result;
    }

    LuraphOpcode8OperandAliasCollector aliasCollector(roles);
    handler->visit(&aliasCollector);
    LuraphOpcode8ShapeCollector shape(roles, aliasCollector.aliases);
    handler->visit(&shape);

    std::set<Luau::AstLocal*> baseCandidates;
    std::set_intersection(
        shape.register_call_bases.begin(), shape.register_call_bases.end(),
        shape.register_loop_bases.begin(), shape.register_loop_bases.end(),
        std::inserter(baseCandidates, baseCandidates.begin()));
    if (baseCandidates.size() != 1 || shape.register_calls < 2 || shape.register_result_loops == 0)
    {
        result["diagnostic"] = "callee/result-base alias is not uniquely proven";
        return result;
    }
    Luau::AstLocal* base = *baseCandidates.begin();

    std::set<Luau::AstLocal*> countCandidates;
    for (const auto& [local, constants] : shape.compared_constants)
        if (constants.contains(0) && constants.contains(1) && local != base)
            countCandidates.insert(local);

    std::set<Luau::AstLocal*> argumentCandidates;
    for (Luau::AstLocal* local : countCandidates)
        if (shape.top_dependencies.contains(local))
            argumentCandidates.insert(local);
    if (argumentCandidates.size() != 1)
    {
        result["diagnostic"] = "argument-count alias is not uniquely proven";
        return result;
    }
    Luau::AstLocal* argumentCount = *argumentCandidates.begin();
    countCandidates.erase(argumentCount);
    if (countCandidates.size() != 1)
    {
        result["diagnostic"] = "result-count alias is not uniquely proven";
        return result;
    }
    Luau::AstLocal* resultCount = *countCandidates.begin();

    const auto baseLane = aliasCollector.aliases.find(base);
    const auto argumentLane = aliasCollector.aliases.find(argumentCount);
    const auto resultLane = aliasCollector.aliases.find(resultCount);
    if (baseLane == aliasCollector.aliases.end() || argumentLane == aliasCollector.aliases.end() ||
        resultLane == aliasCollector.aliases.end() || baseLane->second == argumentLane->second ||
        baseLane->second == resultLane->second || argumentLane->second == resultLane->second)
    {
        result["diagnostic"] = "operand lanes are incomplete or aliased";
        return result;
    }

    result["verified"] = true;
    result["base_register_lane"] = baseLane->second;
    result["encoded_argument_count_lane"] = argumentLane->second;
    result["encoded_result_count_lane"] = resultLane->second;
    result["register_call_count"] = shape.register_calls;
    result["register_result_loop_count"] = shape.register_result_loops;
    result["diagnostic"] = "packed register-call handler shape verified from the Luau AST";
    return result;
}

std::optional<json> normalizeLuraphSemanticExpression(
    Luau::AstExpr* expression,
    const LuraphSemanticRoles& roles,
    int64_t opcode,
    bool& dependsOnVmState,
    size_t depth = 0)
{
    if (!expression || depth > 128)
        return std::nullopt;
    expression = unwrapLuraphExpression(expression);
    if (!expression)
        return std::nullopt;
    if (expression->is<Luau::AstExprConstantNil>())
        return json{{"kind", "constant"}, {"value", nullptr}};
    if (auto value = expression->as<Luau::AstExprConstantBool>())
        return json{{"kind", "constant"}, {"value", value->value}};
    if (auto value = expression->as<Luau::AstExprConstantInteger>())
        return json{{"kind", "constant"}, {"value", value->value}};
    if (auto value = expression->as<Luau::AstExprConstantNumber>())
        return json{{"kind", "constant"}, {"value", value->value}};
    if (auto value = expression->as<Luau::AstExprConstantString>())
        return json{{"kind", "constant"}, {"value", std::string(value->value.data, value->value.size)}};
    if (auto value = expression->as<Luau::AstExprGlobal>())
        return json{{"kind", "global"}, {"name", value->name.value ? value->name.value : "<anonymous>"}};
    if (expression->is<Luau::AstExprVarargs>())
        return json{{"kind", "varargs"}};
    if (auto value = expression->as<Luau::AstExprLocal>())
    {
        if (value->local == roles.pc)
            return json{{"kind", "current_pc"}};
        if (value->local == roles.opcode)
            return json{{"kind", "constant"}, {"value", opcode}, {"provenance", "opcode_value"}};
        if (value->local == roles.opcode_table)
            return json{{"kind", "opcode_table"}};
        if (value->local == roles.registers)
            return json{{"kind", "register_file"}};
        if (value->local == roles.top)
            return json{{"kind", "top_register"}};
        if (value->local == roles.environment)
            return json{{"kind", "environment"}};
        if (value->local == roles.upvalues)
            return json{{"kind", "upvalue_file"}};
        if (value->local == roles.helpers)
            return json{{"kind", "helper_table"}};
        if (auto semantic = roles.semantic_locals.find(value->local); semantic != roles.semantic_locals.end())
            return json{{"kind", "semantic_local"}, {"name", semantic->second}};
        if (auto lane = roles.lanes.find(value->local); lane != roles.lanes.end())
        {
            dependsOnVmState = true;
            return json{{"kind", "operand_table"}, {"lane", lane->second}};
        }
        dependsOnVmState = true;
        return json{{"kind", "vm_state"},
            {"name", value->local && value->local->name.value ? value->local->name.value : "<anonymous>"}};
    }
    if (auto value = expression->as<Luau::AstExprIndexExpr>())
    {
        Luau::AstExpr* baseExpression = unwrapLuraphExpression(value->expr);
        Luau::AstExpr* indexExpression = unwrapLuraphExpression(value->index);
        auto baseLocal = baseExpression ? baseExpression->as<Luau::AstExprLocal>() : nullptr;
        auto indexLocal = indexExpression ? indexExpression->as<Luau::AstExprLocal>() : nullptr;
        if (baseLocal && indexLocal && indexLocal->local == roles.pc)
        {
            if (auto lane = roles.lanes.find(baseLocal->local); lane != roles.lanes.end())
                return json{{"kind", "operand"}, {"lane", lane->second}};
        }
        std::optional<json> index = normalizeLuraphSemanticExpression(value->index, roles, opcode, dependsOnVmState, depth + 1);
        if (!index)
            return std::nullopt;
        if (baseLocal && baseLocal->local == roles.registers)
            return json{{"kind", "register_read"}, {"index", std::move(*index)}};
        if (baseLocal && baseLocal->local == roles.opcode_table)
            return json{{"kind", "opcode_read"}, {"index", std::move(*index)}};
        std::optional<json> table = normalizeLuraphSemanticExpression(value->expr, roles, opcode, dependsOnVmState, depth + 1);
        if (!table)
            return std::nullopt;
        return json{{"kind", "index_read"}, {"table", std::move(*table)}, {"index", std::move(*index)}};
    }
    if (auto value = expression->as<Luau::AstExprIndexName>())
    {
        std::optional<json> table = normalizeLuraphSemanticExpression(value->expr, roles, opcode, dependsOnVmState, depth + 1);
        if (!table)
            return std::nullopt;
        return json{{"kind", "index_read"}, {"table", std::move(*table)},
            {"index", json{{"kind", "constant"}, {"value", value->index.value ? value->index.value : "<anonymous>"}}}};
    }
    if (auto value = expression->as<Luau::AstExprUnary>())
    {
        std::optional<json> operand = normalizeLuraphSemanticExpression(value->expr, roles, opcode, dependsOnVmState, depth + 1);
        if (!operand)
            return std::nullopt;
        return json{{"kind", "unary"}, {"operator", Luau::toString(value->op)}, {"value", std::move(*operand)}};
    }
    if (auto value = expression->as<Luau::AstExprBinary>())
    {
        std::optional<json> left = normalizeLuraphSemanticExpression(value->left, roles, opcode, dependsOnVmState, depth + 1);
        std::optional<json> right = normalizeLuraphSemanticExpression(value->right, roles, opcode, dependsOnVmState, depth + 1);
        if (!left || !right)
            return std::nullopt;
        return json{{"kind", "binary"}, {"operator", Luau::toString(value->op)},
            {"left", std::move(*left)}, {"right", std::move(*right)}};
    }
    if (auto value = expression->as<Luau::AstExprIfElse>())
    {
        std::optional<json> condition = normalizeLuraphSemanticExpression(value->condition, roles, opcode, dependsOnVmState, depth + 1);
        std::optional<json> whenTrue = normalizeLuraphSemanticExpression(value->trueExpr, roles, opcode, dependsOnVmState, depth + 1);
        std::optional<json> whenFalse = normalizeLuraphSemanticExpression(value->falseExpr, roles, opcode, dependsOnVmState, depth + 1);
        if (!condition || !whenTrue || !whenFalse)
            return std::nullopt;
        return json{{"kind", "if_expression"}, {"condition", std::move(*condition)},
            {"then", std::move(*whenTrue)}, {"else", std::move(*whenFalse)}};
    }
    if (auto value = expression->as<Luau::AstExprCall>())
    {
        std::optional<json> function = normalizeLuraphSemanticExpression(value->func, roles, opcode, dependsOnVmState, depth + 1);
        if (!function)
            return std::nullopt;
        json arguments = json::array();
        for (Luau::AstExpr* argument : value->args)
        {
            std::optional<json> normalized = normalizeLuraphSemanticExpression(argument, roles, opcode, dependsOnVmState, depth + 1);
            if (!normalized)
                return std::nullopt;
            arguments.push_back(std::move(*normalized));
        }
        return json{{"kind", "call"}, {"function", std::move(*function)},
            {"arguments", std::move(arguments)}, {"method", value->self}};
    }
    if (auto value = expression->as<Luau::AstExprTable>())
    {
        json entries = json::array();
        for (const Luau::AstExprTable::Item& item : value->items)
        {
            std::optional<json> key;
            if (item.key)
                key = normalizeLuraphSemanticExpression(item.key, roles, opcode, dependsOnVmState, depth + 1);
            std::optional<json> itemValue = normalizeLuraphSemanticExpression(item.value, roles, opcode, dependsOnVmState, depth + 1);
            if ((item.key && !key) || !itemValue)
                return std::nullopt;
            entries.push_back({
                {"entry_kind", item.kind == Luau::AstExprTable::Item::Kind::List ? "list"
                    : item.kind == Luau::AstExprTable::Item::Kind::Record ? "record" : "general"},
                {"key", key ? std::move(*key) : json(nullptr)},
                {"value", std::move(*itemValue)},
            });
        }
        return json{{"kind", "table"}, {"entries", std::move(entries)}};
    }
    return std::nullopt;
}

std::optional<json> normalizeLuraphSemanticTarget(
    Luau::AstExpr* expression,
    const LuraphSemanticRoles& roles,
    int64_t opcode,
    bool& dependsOnVmState,
    size_t depth = 0)
{
    if (!expression || depth > 128)
        return std::nullopt;
    expression = unwrapLuraphExpression(expression);
    if (auto local = expression ? expression->as<Luau::AstExprLocal>() : nullptr)
    {
        if (local->local == roles.pc)
            return json{{"kind", "program_counter"}};
        if (local->local == roles.top)
            return json{{"kind", "top_register"}};
        if (auto semantic = roles.semantic_locals.find(local->local); semantic != roles.semantic_locals.end())
            return json{{"kind", "semantic_local"}, {"name", semantic->second}};
        dependsOnVmState = true;
        return json{{"kind", "vm_state"},
            {"name", local->local && local->local->name.value ? local->local->name.value : "<anonymous>"}};
    }
    if (auto index = expression ? expression->as<Luau::AstExprIndexExpr>() : nullptr)
    {
        Luau::AstExpr* baseExpression = unwrapLuraphExpression(index->expr);
        auto baseLocal = baseExpression ? baseExpression->as<Luau::AstExprLocal>() : nullptr;
        std::optional<json> normalizedIndex = normalizeLuraphSemanticExpression(
            index->index, roles, opcode, dependsOnVmState, depth + 1);
        if (!normalizedIndex)
            return std::nullopt;
        if (baseLocal && baseLocal->local == roles.registers)
            return json{{"kind", "register"}, {"index", std::move(*normalizedIndex)}};
        if (baseLocal && baseLocal->local == roles.opcode_table)
            return json{{"kind", "opcode_slot"}, {"index", std::move(*normalizedIndex)}};
        std::optional<json> table = normalizeLuraphSemanticExpression(index->expr, roles, opcode, dependsOnVmState, depth + 1);
        if (!table)
            return std::nullopt;
        return json{{"kind", "index"}, {"table", std::move(*table)}, {"index", std::move(*normalizedIndex)}};
    }
    if (auto index = expression ? expression->as<Luau::AstExprIndexName>() : nullptr)
    {
        std::optional<json> table = normalizeLuraphSemanticExpression(index->expr, roles, opcode, dependsOnVmState, depth + 1);
        if (!table)
            return std::nullopt;
        return json{{"kind", "index"}, {"table", std::move(*table)},
            {"index", json{{"kind", "constant"}, {"value", index->index.value ? index->index.value : "<anonymous>"}}}};
    }
    return std::nullopt;
}

std::optional<json> normalizeLuraphSemanticStatement(
    Luau::AstStat* statement,
    const LuraphSemanticRoles& roles,
    int64_t opcode,
    bool& dependsOnVmState,
    size_t depth = 0);

std::optional<json> normalizeLuraphSemanticBlock(
    Luau::AstStatBlock* block,
    const LuraphSemanticRoles& roles,
    int64_t opcode,
    bool& dependsOnVmState,
    size_t depth)
{
    if (!block || depth > 128)
        return std::nullopt;
    json operations = json::array();
    for (Luau::AstStat* statement : block->body)
    {
        std::optional<json> operation = normalizeLuraphSemanticStatement(statement, roles, opcode, dependsOnVmState, depth + 1);
        if (!operation)
            return std::nullopt;
        operations.push_back(std::move(*operation));
    }
    return operations;
}

std::optional<json> normalizeLuraphSemanticStatement(
    Luau::AstStat* statement,
    const LuraphSemanticRoles& roles,
    int64_t opcode,
    bool& dependsOnVmState,
    size_t depth)
{
    if (!statement || depth > 128)
        return std::nullopt;
    if (auto assignment = statement->as<Luau::AstStatAssign>())
    {
        json targets = json::array();
        json values = json::array();
        for (Luau::AstExpr* target : assignment->vars)
        {
            std::optional<json> normalized = normalizeLuraphSemanticTarget(target, roles, opcode, dependsOnVmState, depth + 1);
            if (!normalized)
                return std::nullopt;
            targets.push_back(std::move(*normalized));
        }
        for (Luau::AstExpr* value : assignment->values)
        {
            std::optional<json> normalized = normalizeLuraphSemanticExpression(value, roles, opcode, dependsOnVmState, depth + 1);
            if (!normalized)
                return std::nullopt;
            values.push_back(std::move(*normalized));
        }
        if (targets.size() == 1 && values.size() == 1)
        {
            const std::string targetKind = targets[0].value("kind", "");
            if (targetKind == "program_counter")
                return json{{"kind", "jump"}, {"target", std::move(values[0])}};
            if (targetKind == "top_register")
                return json{{"kind", "set_top"}, {"value", std::move(values[0])}};
            if (targetKind == "register")
                return json{{"kind", "register_write"}, {"register", std::move(targets[0]["index"])},
                    {"value", std::move(values[0])}};
            if (targetKind == "opcode_slot")
                return json{{"kind", "opcode_patch"}, {"index", std::move(targets[0]["index"])},
                    {"value", std::move(values[0])}, {"protector_state", true}};
            if (targetKind == "index")
                return json{{"kind", "table_write"}, {"table", std::move(targets[0]["table"])},
                    {"index", std::move(targets[0]["index"])}, {"value", std::move(values[0])}};
        }
        return json{{"kind", "assign"}, {"targets", std::move(targets)}, {"values", std::move(values)},
            {"evaluation_order", "values_before_writes"}};
    }
    if (auto compound = statement->as<Luau::AstStatCompoundAssign>())
    {
        std::optional<json> target = normalizeLuraphSemanticTarget(compound->var, roles, opcode, dependsOnVmState, depth + 1);
        std::optional<json> value = normalizeLuraphSemanticExpression(compound->value, roles, opcode, dependsOnVmState, depth + 1);
        if (!target || !value)
            return std::nullopt;
        if (target->value("kind", "") == "top_register")
            return json{{"kind", "adjust_top"}, {"operator", Luau::toString(compound->op)},
                {"value", std::move(*value)}};
        return json{{"kind", "compound_write"}, {"operator", Luau::toString(compound->op)},
            {"target", std::move(*target)}, {"value", std::move(*value)}};
    }
    if (auto expression = statement->as<Luau::AstStatExpr>())
    {
        std::optional<json> value = normalizeLuraphSemanticExpression(expression->expr, roles, opcode, dependsOnVmState, depth + 1);
        if (!value)
            return std::nullopt;
        return json{{"kind", "expression"}, {"value", std::move(*value)}};
    }
    if (auto result = statement->as<Luau::AstStatReturn>())
    {
        json values = json::array();
        for (Luau::AstExpr* value : result->list)
        {
            std::optional<json> normalized = normalizeLuraphSemanticExpression(value, roles, opcode, dependsOnVmState, depth + 1);
            if (!normalized)
                return std::nullopt;
            values.push_back(std::move(*normalized));
        }
        return json{{"kind", "return"}, {"values", std::move(values)}};
    }
    if (auto conditional = statement->as<Luau::AstStatIf>())
    {
        std::optional<json> condition = normalizeLuraphSemanticExpression(
            conditional->condition, roles, opcode, dependsOnVmState, depth + 1);
        std::optional<json> whenTrue = normalizeLuraphSemanticBlock(
            conditional->thenbody, roles, opcode, dependsOnVmState, depth + 1);
        json whenFalse = json::array();
        if (auto block = conditional->elsebody ? conditional->elsebody->as<Luau::AstStatBlock>() : nullptr)
        {
            std::optional<json> normalized = normalizeLuraphSemanticBlock(block, roles, opcode, dependsOnVmState, depth + 1);
            if (!normalized)
                return std::nullopt;
            whenFalse = std::move(*normalized);
        }
        else if (conditional->elsebody)
        {
            std::optional<json> normalized = normalizeLuraphSemanticStatement(
                conditional->elsebody, roles, opcode, dependsOnVmState, depth + 1);
            if (!normalized)
                return std::nullopt;
            whenFalse.push_back(std::move(*normalized));
        }
        if (!condition || !whenTrue)
            return std::nullopt;
        return json{{"kind", "branch"}, {"condition", std::move(*condition)},
            {"then", std::move(*whenTrue)}, {"else", std::move(whenFalse)}};
    }
    if (auto loop = statement->as<Luau::AstStatFor>())
    {
        std::optional<json> from = normalizeLuraphSemanticExpression(loop->from, roles, opcode, dependsOnVmState, depth + 1);
        std::optional<json> to = normalizeLuraphSemanticExpression(loop->to, roles, opcode, dependsOnVmState, depth + 1);
        std::optional<json> step;
        if (loop->step)
            step = normalizeLuraphSemanticExpression(loop->step, roles, opcode, dependsOnVmState, depth + 1);
        if (!from || !to || (loop->step && !step))
            return std::nullopt;
        LuraphSemanticRoles bodyRoles = roles;
        const std::string indexName = "loop_index";
        bodyRoles.semantic_locals[loop->var] = indexName;
        std::optional<json> body = normalizeLuraphSemanticBlock(loop->body, bodyRoles, opcode, dependsOnVmState, depth + 1);
        if (!body)
            return std::nullopt;
        return json{{"kind", "numeric_for"}, {"index", indexName}, {"from", std::move(*from)},
            {"to", std::move(*to)}, {"step", step ? std::move(*step) : json{{"kind", "constant"}, {"value", 1}}},
            {"body", std::move(*body)}};
    }
    if (auto block = statement->as<Luau::AstStatBlock>())
    {
        std::optional<json> body = normalizeLuraphSemanticBlock(block, roles, opcode, dependsOnVmState, depth + 1);
        if (!body)
            return std::nullopt;
        return json{{"kind", "block"}, {"operations", std::move(*body)}};
    }
    return std::nullopt;
}

struct LuraphNormalizedHandler
{
    json ir = nullptr;
    json semantic_operation = nullptr;
    bool normalization_complete = false;
    bool vm_state_independent = false;
};

bool luraphSemanticContainsUnknownState(const json& value)
{
    if (value.is_object())
    {
        const std::string kind = value.value("kind", "");
        if (kind == "vm_state" || kind == "operand_table")
            return true;
        for (const auto& [key, child] : value.items())
            if (luraphSemanticContainsUnknownState(child))
                return true;
    }
    else if (value.is_array())
    {
        for (const json& child : value)
            if (luraphSemanticContainsUnknownState(child))
                return true;
    }
    return false;
}

void substituteLuraphSemanticBindings(json& value, const std::map<std::string, json>& bindings, size_t depth = 0)
{
    if (depth > 128)
        return;
    if (value.is_object())
    {
        if (value.value("kind", "") == "vm_state")
        {
            auto binding = bindings.find(value.value("name", ""));
            if (binding != bindings.end())
            {
                value = binding->second;
                substituteLuraphSemanticBindings(value, bindings, depth + 1);
                return;
            }
        }
        for (auto& [key, child] : value.items())
            substituteLuraphSemanticBindings(child, bindings, depth + 1);
    }
    else if (value.is_array())
    {
        for (json& child : value)
            substituteLuraphSemanticBindings(child, bindings, depth + 1);
    }
}

void rewriteLuraphRegisterRangeCalls(json& value, size_t depth = 0)
{
    if (depth > 128)
        return;
    if (value.is_object())
    {
        for (auto& [key, child] : value.items())
            rewriteLuraphRegisterRangeCalls(child, depth + 1);
        if (value.value("kind", "") != "call")
            return;
        const json& function = value["function"];
        const json& arguments = value["arguments"];
        if (!arguments.is_array() || arguments.size() != 3 ||
            function.value("kind", "") != "index_read" ||
            (function["table"].value("kind", "") != "vm_state" && function["table"].value("kind", "") != "helper_table") ||
            function["index"].value("kind", "") != "constant")
            return;
        const bool registerLast = arguments[2].value("kind", "") == "register_file";
        const bool registerMiddle = arguments[1].value("kind", "") == "register_file";
        if (!registerLast && !registerMiddle)
            return;
        value = {
            {"kind", "register_range"},
            {"from", arguments[0]},
            {"to", registerLast ? arguments[1] : arguments[2]},
            {"result_arity", "multiple"},
            {"helper_index", function["index"]["value"]},
        };
    }
    else if (value.is_array())
    {
        for (json& child : value)
            rewriteLuraphRegisterRangeCalls(child, depth + 1);
    }
}

std::optional<json> liftStraightLineLuraphHandler(const json& operations)
{
    if (!operations.is_array())
        return std::nullopt;
    std::map<std::string, json> bindings;
    json preparedBindings = json::array();
    json lifted = json::array();
    for (const json& sourceOperation : operations)
    {
        if (!sourceOperation.is_object())
            return std::nullopt;
        const std::string kind = sourceOperation.value("kind", "");
        if (kind == "branch" || kind == "block")
            return std::nullopt;
        json operation = sourceOperation;
        if (kind == "assign")
        {
            json& targets = operation["targets"];
            json& values = operation["values"];
            if (targets.is_array() && values.is_array() && targets.size() == 1 && values.size() == 1 &&
                targets[0].value("kind", "") == "vm_state")
            {
                substituteLuraphSemanticBindings(values[0], bindings);
                if (luraphSemanticContainsUnknownState(values[0]))
                    return std::nullopt;
                const std::string name = targets[0].value("name", "");
                bindings[name] = values[0];
                preparedBindings.push_back({{"slot", name}, {"value", values[0]}});
                continue;
            }
        }
        rewriteLuraphRegisterRangeCalls(operation);
        substituteLuraphSemanticBindings(operation, bindings);
        if (luraphSemanticContainsUnknownState(operation))
            return std::nullopt;
        lifted.push_back(std::move(operation));
    }
    if (lifted.empty())
        return preparedBindings.empty() ? std::nullopt : std::optional<json>(json{
            {"kind", "prepare_vm_state"}, {"bindings", std::move(preparedBindings)}, {"protector_state", true},
        });
    if (lifted.size() == 1)
        return lifted[0];
    return json{{"kind", "operation_sequence"}, {"operations", std::move(lifted)}};
}

struct LuraphAssignmentCollector : Luau::AstVisitor
{
    std::vector<Luau::AstStatAssign*> assignments;

    bool visit(Luau::AstStatAssign* node) override
    {
        assignments.push_back(node);
        return true;
    }
};

bool luraphJsonContainsKind(const json& value, std::string_view kind);

std::optional<json> liftLuraphOpaqueRegisterTail(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles,
    int64_t opcode)
{
    if (!leaf)
        return std::nullopt;
    std::map<std::string, json> bindings;
    std::optional<json> candidate;
    std::optional<json> deferredTarget;
    std::optional<json> deferredValue;
    for (Luau::AstStat* statement : leaf->body)
    {
        auto assignment = statement->as<Luau::AstStatAssign>();
        if (!assignment)
            continue;
        if (assignment->vars.size != 1 || assignment->values.size != 1)
            continue;
        bool dependsOnVmState = false;
        std::optional<json> target = normalizeLuraphSemanticTarget(
            assignment->vars.data[0], roles, opcode, dependsOnVmState, 0);
        std::optional<json> value = normalizeLuraphSemanticExpression(
            assignment->values.data[0], roles, opcode, dependsOnVmState, 0);
        if (!target || !value)
            continue;
        substituteLuraphSemanticBindings(*value, bindings);
        if (target->value("kind", "") == "vm_state")
        {
            bindings[target->value("name", "")] = *value;
            continue;
        }
        substituteLuraphSemanticBindings(*target, bindings);
        if (target->value("kind", "") != "index" || (*target)["table"].value("kind", "") != "register_file")
            continue;
        deferredTarget = normalizeLuraphSemanticTarget(assignment->vars.data[0], roles, opcode, dependsOnVmState, 0);
        deferredValue = normalizeLuraphSemanticExpression(assignment->values.data[0], roles, opcode, dependsOnVmState, 0);
        json sourceValue = *value;
        if (sourceValue.value("kind", "") == "index_read" && sourceValue["table"].value("kind", "") == "vm_state" &&
            !luraphSemanticContainsUnknownState(sourceValue["index"]))
        {
            sourceValue = {
                {"kind", "global_read"},
                {"key", sourceValue["index"]},
                {"environment_state", sourceValue["table"].value("name", "")},
            };
        }
        if (luraphSemanticContainsUnknownState((*target)["index"]) || luraphSemanticContainsUnknownState(sourceValue))
            continue;
        candidate = json{
            {"kind", "register_write"},
            {"register", (*target)["index"]},
            {"value", std::move(sourceValue)},
            {"opaque_prefix_elided", true},
            {"source_semantic", true},
        };
    }
    if (deferredTarget && deferredValue)
    {
        candidate.reset();
        json target = *deferredTarget;
        json sourceValue = *deferredValue;
        substituteLuraphSemanticBindings(target, bindings);
        substituteLuraphSemanticBindings(sourceValue, bindings);
        if (target.value("kind", "") == "index" && target["table"].value("kind", "") == "register_file")
        {
            if (sourceValue.value("kind", "") == "index_read" && sourceValue["table"].value("kind", "") == "vm_state" &&
                !luraphSemanticContainsUnknownState(sourceValue["index"]))
            {
                sourceValue = {
                    {"kind", "global_read"},
                    {"key", sourceValue["index"]},
                    {"environment_state", sourceValue["table"].value("name", "")},
                };
            }
            if (!luraphSemanticContainsUnknownState(target["index"]) && !luraphSemanticContainsUnknownState(sourceValue) &&
                !luraphJsonContainsKind(sourceValue, "helper_table") && !luraphJsonContainsKind(sourceValue, "current_pc"))
            {
                candidate = json{
                    {"kind", "register_write"},
                    {"register", target["index"]},
                    {"value", std::move(sourceValue)},
                    {"opaque_prefix_elided", true},
                    {"source_semantic", true},
                };
            }
        }
    }
    return candidate;
}

std::optional<json> liftLuraphOpaqueProtectorTableTail(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles,
    int64_t opcode)
{
    if (!leaf)
        return std::nullopt;
    LuraphAssignmentCollector collector;
    leaf->visit(&collector);
    std::map<std::string, json> bindings;
    std::optional<json> candidate;
    for (Luau::AstStatAssign* assignment : collector.assignments)
    {
        if (assignment->vars.size != 1 || assignment->values.size != 1)
            continue;
        bool dependsOnVmState = false;
        std::optional<json> target = normalizeLuraphSemanticTarget(
            assignment->vars.data[0], roles, opcode, dependsOnVmState, 0);
        std::optional<json> value = normalizeLuraphSemanticExpression(
            assignment->values.data[0], roles, opcode, dependsOnVmState, 0);
        if (!target || !value)
            continue;
        substituteLuraphSemanticBindings(*value, bindings);
        if (target->value("kind", "") == "vm_state")
        {
            bindings[target->value("name", "")] = *value;
            continue;
        }
        substituteLuraphSemanticBindings(*target, bindings);
        if (target->value("kind", "") != "index" ||
            luraphJsonContainsKind(*target, "register_file") ||
            luraphJsonContainsKind(*target, "register_read") ||
            luraphJsonContainsKind(*target, "upvalue_file") ||
            luraphJsonContainsKind(*target, "environment") ||
            luraphJsonContainsKind(*target, "global"))
            continue;
        candidate = json{
            {"kind", "table_write"},
            {"table", (*target)["table"]},
            {"index", (*target)["index"]},
            {"value", *value},
            {"protector_state", true},
            {"source_semantic", false},
            {"opaque_prefix_elided", true},
            {"proof", "internal_table_write_without_register_global_environment_or_upvalue_target"},
        };
    }
    return candidate;
}

std::optional<json> liftLuraphOpaqueRegisterPoolTail(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles,
    int64_t opcode)
{
    if (!leaf)
        return std::nullopt;
    LuraphAssignmentCollector collector;
    leaf->visit(&collector);
    std::map<std::string, json> bindings;
    std::optional<json> candidate;
    for (Luau::AstStatAssign* assignment : collector.assignments)
    {
        if (assignment->vars.size != 1 || assignment->values.size != 1)
            continue;
        bool dependsOnVmState = false;
        std::optional<json> target = normalizeLuraphSemanticTarget(
            assignment->vars.data[0], roles, opcode, dependsOnVmState, 0);
        std::optional<json> value = normalizeLuraphSemanticExpression(
            assignment->values.data[0], roles, opcode, dependsOnVmState, 0);
        if (!target || !value)
            continue;
        substituteLuraphSemanticBindings(*value, bindings);
        if (target->value("kind", "") == "vm_state")
        {
            bindings[target->value("name", "")] = *value;
            continue;
        }
        substituteLuraphSemanticBindings(*target, bindings);
        if (target->value("kind", "") != "index" ||
            (*target)["table"].value("kind", "") != "register_file" ||
            luraphSemanticContainsUnknownState((*target)["index"]) ||
            luraphJsonContainsKind(*value, "current_pc"))
            continue;
        candidate = json{
            {"kind", "register_write"},
            {"register", (*target)["index"]},
            {"value", *value},
            {"opaque_pool_read", true},
            {"source_semantic", true},
            {"proof", "register_destination_resolved_with_opaque_value_pool_preserved"},
        };
    }
    return candidate;
}

std::optional<json> liftLuraphRegisterLaneTransfer(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles)
{
    if (!leaf || !roles.registers || !roles.pc)
        return std::nullopt;
    LuraphAssignmentCollector collector;
    leaf->visit(&collector);
    std::set<Luau::AstLocal*> registerAliases;
    std::map<Luau::AstLocal*, std::string> laneAliases;
    for (Luau::AstStatAssign* assignment : collector.assignments)
    {
        if (assignment->vars.size != 1 || assignment->values.size != 1)
            continue;
        auto target = unwrapLuraphExpression(assignment->vars.data[0])->as<Luau::AstExprLocal>();
        Luau::AstExpr* sourceExpression = unwrapLuraphExpression(assignment->values.data[0]);
        auto sourceLocal = sourceExpression ? sourceExpression->as<Luau::AstExprLocal>() : nullptr;
        if (target && sourceLocal && sourceLocal->local == roles.registers)
            registerAliases.insert(target->local);
        auto sourceIndex = sourceExpression ? sourceExpression->as<Luau::AstExprIndexExpr>() : nullptr;
        auto sourceBase = sourceIndex ? unwrapLuraphExpression(sourceIndex->expr)->as<Luau::AstExprLocal>() : nullptr;
        auto sourceKey = sourceIndex ? unwrapLuraphExpression(sourceIndex->index)->as<Luau::AstExprLocal>() : nullptr;
        if (target && sourceBase && sourceKey && sourceKey->local == roles.pc)
            if (auto lane = roles.lanes.find(sourceBase->local); lane != roles.lanes.end())
                laneAliases[target->local] = lane->second;
    }
    for (Luau::AstStatAssign* assignment : collector.assignments)
    {
        if (assignment->vars.size != 1 || assignment->values.size != 1)
            continue;
        auto target = unwrapLuraphExpression(assignment->vars.data[0])->as<Luau::AstExprIndexExpr>();
        auto table = target ? unwrapLuraphExpression(target->expr)->as<Luau::AstExprLocal>() : nullptr;
        auto index = target ? unwrapLuraphExpression(target->index)->as<Luau::AstExprLocal>() : nullptr;
        auto value = unwrapLuraphExpression(assignment->values.data[0])->as<Luau::AstExprLocal>();
        if (!table || !index || !value || !registerAliases.contains(table->local) ||
            !laneAliases.contains(index->local) || !laneAliases.contains(value->local))
            continue;
        return json{
            {"kind", "register_write"},
            {"register", {{"kind", "operand"}, {"lane", laneAliases[index->local]}}},
            {"value", {{"kind", "operand"}, {"lane", laneAliases[value->local]}}},
            {"opaque_pool_read", true},
            {"source_semantic", true},
            {"proof", "register_and_operand_lane_aliases_converge_at_terminal_table_write"},
        };
    }
    return std::nullopt;
}

struct LuraphNumericForCollector : Luau::AstVisitor
{
    std::vector<Luau::AstStatFor*> loops;

    bool visit(Luau::AstStatFor* node) override
    {
        loops.push_back(node);
        return true;
    }
};

void collectLuraphOpcodeSpecializedBlocks(
    Luau::AstStat* statement,
    Luau::AstLocal* opcodeLocal,
    int64_t opcode,
    std::vector<Luau::AstStatBlock*>& blocks,
    std::set<Luau::AstStatBlock*>& seen);

std::optional<json> liftLuraphRegisterClearRangeInBlock(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles)
{
    if (!leaf || !roles.registers || !roles.pc)
        return std::nullopt;
    LuraphAssignmentCollector assignments;
    leaf->visit(&assignments);
    struct LaneAssignment
    {
        Luau::AstLocal* local = nullptr;
        std::string lane;
        Luau::Location location;
    };
    std::vector<LaneAssignment> laneAssignments;
    for (Luau::AstStatAssign* assignment : assignments.assignments)
    {
        if (assignment->vars.size != 1 || assignment->values.size != 1)
            continue;
        auto target = unwrapLuraphExpression(assignment->vars.data[0])->as<Luau::AstExprLocal>();
        auto source = unwrapLuraphExpression(assignment->values.data[0])->as<Luau::AstExprIndexExpr>();
        auto table = source ? unwrapLuraphExpression(source->expr)->as<Luau::AstExprLocal>() : nullptr;
        auto index = source ? unwrapLuraphExpression(source->index)->as<Luau::AstExprLocal>() : nullptr;
        if (target && table && index && index->local == roles.pc)
            if (auto lane = roles.lanes.find(table->local); lane != roles.lanes.end())
                laneAssignments.push_back({target->local, lane->second, assignment->location});
    }
    const auto before = [](const Luau::Position& left, const Luau::Position& right) {
        return left.line < right.line || (left.line == right.line && left.column < right.column);
    };
    const auto boundLane = [&](Luau::AstExpr* expression, const Luau::Location& use) -> std::optional<std::string> {
        expression = unwrapLuraphExpression(expression);
        if (auto local = expression ? expression->as<Luau::AstExprLocal>() : nullptr)
        {
            const LaneAssignment* nearest = nullptr;
            for (const LaneAssignment& assignment : laneAssignments)
                if (assignment.local == local->local && before(assignment.location.begin, use.begin) &&
                    (!nearest || before(nearest->location.begin, assignment.location.begin)))
                    nearest = &assignment;
            if (nearest)
                return nearest->lane;
        }
        auto indexed = expression ? expression->as<Luau::AstExprIndexExpr>() : nullptr;
        auto table = indexed ? unwrapLuraphExpression(indexed->expr)->as<Luau::AstExprLocal>() : nullptr;
        auto index = indexed ? unwrapLuraphExpression(indexed->index)->as<Luau::AstExprLocal>() : nullptr;
        if (table && index && index->local == roles.pc)
            if (auto lane = roles.lanes.find(table->local); lane != roles.lanes.end())
                return lane->second;
        return std::nullopt;
    };

    LuraphNumericForCollector loops;
    leaf->visit(&loops);
    for (Luau::AstStatFor* loop : loops.loops)
    {
        bool clearsRegister = false;
        LuraphAssignmentCollector bodyAssignments;
        loop->body->visit(&bodyAssignments);
        std::set<Luau::AstLocal*> registerAliases;
        std::set<Luau::AstLocal*> indexAliases;
        std::set<Luau::AstLocal*> nilAliases;
        for (Luau::AstStatAssign* assignment : bodyAssignments.assignments)
        {
            if (assignment->vars.size != 1 || assignment->values.size != 1)
                continue;
            auto target = unwrapLuraphExpression(assignment->vars.data[0])->as<Luau::AstExprLocal>();
            Luau::AstExpr* source = unwrapLuraphExpression(assignment->values.data[0]);
            auto sourceLocal = source ? source->as<Luau::AstExprLocal>() : nullptr;
            if (!target)
                continue;
            if (sourceLocal && sourceLocal->local == roles.registers)
                registerAliases.insert(target->local);
            if (sourceLocal && sourceLocal->local == loop->var)
                indexAliases.insert(target->local);
            if (source && source->is<Luau::AstExprConstantNil>())
                nilAliases.insert(target->local);
        }
        for (Luau::AstStatAssign* assignment : bodyAssignments.assignments)
        {
            if (assignment->vars.size != 1 || assignment->values.size != 1)
                continue;
            auto target = unwrapLuraphExpression(assignment->vars.data[0])->as<Luau::AstExprIndexExpr>();
            auto table = target ? unwrapLuraphExpression(target->expr)->as<Luau::AstExprLocal>() : nullptr;
            auto index = target ? unwrapLuraphExpression(target->index)->as<Luau::AstExprLocal>() : nullptr;
            Luau::AstExpr* source = unwrapLuraphExpression(assignment->values.data[0]);
            auto sourceLocal = source ? source->as<Luau::AstExprLocal>() : nullptr;
            const bool nilValue = source && (source->is<Luau::AstExprConstantNil>() ||
                (sourceLocal && nilAliases.contains(sourceLocal->local)));
            const bool registerTable = table &&
                (table->local == roles.registers || registerAliases.contains(table->local));
            const bool loopIndex = index &&
                (index->local == loop->var || indexAliases.contains(index->local));
            clearsRegister = clearsRegister ||
                (nilValue && registerTable && loopIndex);
        }
        const std::optional<std::string> from = boundLane(loop->from, loop->location);
        const std::optional<std::string> to = boundLane(loop->to, loop->location);
        if (!clearsRegister || !from || !to)
            continue;
        return json{
            {"kind", "numeric_for"},
            {"index", "clear_register"},
            {"from", {{"kind", "operand"}, {"lane", *from}}},
            {"to", {{"kind", "operand"}, {"lane", *to}}},
            {"step", {{"kind", "constant"}, {"value", 1}}},
            {"body", json::array({{{"kind", "register_write"},
                {"register", {{"kind", "semantic_local"}, {"name", "clear_register"}}},
                {"value", {{"kind", "constant"}, {"value", nullptr}}}}})},
            {"protector_state", true},
            {"source_semantic", false},
            {"proof", "numeric_loop_assigns_nil_to_each_register_in_operand_lane_range"},
        };
    }
    return std::nullopt;
}

std::optional<json> liftLuraphRegisterClearRange(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles,
    int64_t opcode)
{
    if (!leaf || !roles.opcode)
        return std::nullopt;
    std::vector<Luau::AstStatBlock*> blocks;
    std::set<Luau::AstStatBlock*> seen;
    collectLuraphOpcodeSpecializedBlocks(leaf, roles.opcode, opcode, blocks, seen);
    for (Luau::AstStatBlock* block : blocks)
        if (std::optional<json> clear = liftLuraphRegisterClearRangeInBlock(block, roles))
            return clear;
    return std::nullopt;
}

std::optional<json> liftLuraphRegisterStatePreparation(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles)
{
    if (!leaf || !roles.registers || !roles.pc)
        return std::nullopt;
    LuraphAssignmentCollector assignments;
    leaf->visit(&assignments);
    std::set<std::pair<std::string, std::string>> candidates;
    for (Luau::AstStatAssign* assignment : assignments.assignments)
    {
        if (assignment->vars.size != 1 || assignment->values.size != 1)
            continue;
        auto target = unwrapLuraphExpression(assignment->vars.data[0])->as<Luau::AstExprLocal>();
        bool dependsOnVmState = false;
        std::optional<json> source = normalizeLuraphSemanticExpression(
            assignment->values.data[0], roles, 0, dependsOnVmState, 0);
        if (!target || !source || source->value("kind", "") != "register_read" ||
            !source->contains("index") || (*source)["index"].value("kind", "") != "operand" ||
            !(*source)["index"].contains("lane") || !(*source)["index"]["lane"].is_string())
            continue;
        candidates.emplace(target->local && target->local->name.value ? target->local->name.value : "state",
            (*source)["index"]["lane"].get<std::string>());
    }
    if (candidates.empty())
        return std::nullopt;
    std::set<std::string> lanes;
    for (const auto& [slot, lane] : candidates)
    {
        (void)slot;
        lanes.insert(lane);
    }
    if (lanes.size() != 1)
        return std::nullopt;
    const std::string slot = candidates.size() == 1 ? candidates.begin()->first : "prepared_register_value";
    const std::string& lane = *lanes.begin();
    return json{
        {"kind", "prepare_vm_state"},
        {"bindings", json::array({{{"slot", slot}, {"value", {{"kind", "register_read"},
            {"index", {{"kind", "operand"}, {"lane", lane}}}}}}})},
        {"protector_state", true},
        {"source_semantic", false},
        {"proof", "single_vm_state_local_reads_register_at_operand_lane"},
    };
}

struct LuraphSelfPatchEvidenceCollector : Luau::AstVisitor
{
    explicit LuraphSelfPatchEvidenceCollector(const LuraphSemanticRoles& roles)
        : roles(roles)
    {
    }

    const LuraphSemanticRoles& roles;
    bool opcode_table_write = false;
    bool register_access = false;
    std::map<Luau::AstLocal*, std::set<std::string>> lane_assignments;

    bool visit(Luau::AstExprIndexExpr* node) override
    {
        auto base = unwrapLuraphExpression(node->expr)->as<Luau::AstExprLocal>();
        register_access = register_access || (base && base->local == roles.registers);
        return true;
    }

    bool visit(Luau::AstStatAssign* node) override
    {
        if (node->vars.size != 1 || node->values.size != 1)
            return true;
        Luau::AstExpr* targetExpression = unwrapLuraphExpression(node->vars.data[0]);
        Luau::AstExpr* valueExpression = unwrapLuraphExpression(node->values.data[0]);
        if (auto target = targetExpression ? targetExpression->as<Luau::AstExprIndexExpr>() : nullptr)
        {
            auto base = unwrapLuraphExpression(target->expr)->as<Luau::AstExprLocal>();
            auto index = unwrapLuraphExpression(target->index)->as<Luau::AstExprLocal>();
            opcode_table_write = opcode_table_write ||
                (base && base->local == roles.opcode_table && index && index->local == roles.pc);
        }
        auto target = targetExpression ? targetExpression->as<Luau::AstExprLocal>() : nullptr;
        auto value = valueExpression ? valueExpression->as<Luau::AstExprIndexExpr>() : nullptr;
        auto base = value ? unwrapLuraphExpression(value->expr)->as<Luau::AstExprLocal>() : nullptr;
        auto index = value ? unwrapLuraphExpression(value->index)->as<Luau::AstExprLocal>() : nullptr;
        if (target && base && index && index->local == roles.pc)
            if (auto lane = roles.lanes.find(base->local); lane != roles.lanes.end())
                lane_assignments[target->local].insert(lane->second);
        return true;
    }
};

std::optional<json> liftLuraphSelfPatchingJumpTail(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles)
{
    if (!leaf || leaf->body.size == 0 || !roles.pc || !roles.opcode_table)
        return std::nullopt;
    auto terminal = leaf->body.data[leaf->body.size - 1]->as<Luau::AstStatAssign>();
    if (!terminal || terminal->vars.size != 1 || terminal->values.size != 1)
        return std::nullopt;
    auto target = unwrapLuraphExpression(terminal->vars.data[0])->as<Luau::AstExprLocal>();
    auto source = unwrapLuraphExpression(terminal->values.data[0])->as<Luau::AstExprLocal>();
    if (!target || target->local != roles.pc || !source)
        return std::nullopt;

    LuraphSelfPatchEvidenceCollector evidence(roles);
    leaf->visit(&evidence);
    auto lanes = evidence.lane_assignments.find(source->local);
    if (!evidence.opcode_table_write || evidence.register_access || lanes == evidence.lane_assignments.end() ||
        lanes->second.size() != 1)
        return std::nullopt;
    return json{
        {"kind", "jump"},
        {"target", {{"kind", "operand"}, {"lane", *lanes->second.begin()}}},
        {"opcode_self_patch", true},
        {"protector_state", true},
        {"source_semantic", false},
        {"proof", "terminal_pc_alias_and_current_opcode_table_write"},
    };
}

std::optional<json> liftLuraphOpaqueTerminalReturn(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles,
    int64_t opcode)
{
    if (!leaf || leaf->body.size == 0)
        return std::nullopt;
    Luau::AstStat* terminal = leaf->body.data[leaf->body.size - 1];
    if (!terminal->is<Luau::AstStatReturn>())
        return std::nullopt;

    std::map<std::string, json> bindings;
    for (size_t index = 0; index + 1 < leaf->body.size; ++index)
    {
        auto assignment = leaf->body.data[index]->as<Luau::AstStatAssign>();
        if (!assignment || assignment->vars.size != 1 || assignment->values.size != 1)
            continue;
        bool dependsOnVmState = false;
        std::optional<json> target = normalizeLuraphSemanticTarget(
            assignment->vars.data[0], roles, opcode, dependsOnVmState, 0);
        std::optional<json> value = normalizeLuraphSemanticExpression(
            assignment->values.data[0], roles, opcode, dependsOnVmState, 0);
        if (!target || !value || target->value("kind", "") != "vm_state")
            continue;
        substituteLuraphSemanticBindings(*value, bindings);
        bindings[target->value("name", "")] = std::move(*value);
    }

    bool dependsOnVmState = false;
    std::optional<json> result = normalizeLuraphSemanticStatement(
        terminal, roles, opcode, dependsOnVmState, 0);
    if (!result)
        return std::nullopt;
    substituteLuraphSemanticBindings(*result, bindings);
    rewriteLuraphRegisterRangeCalls(*result);
    if (luraphSemanticContainsUnknownState(*result))
        return std::nullopt;
    (*result)["implicit_close_upvalues"] = leaf->body.size > 1;
    (*result)["opaque_prefix_elided"] = leaf->body.size > 1;
    return result;
}

struct LuraphTableRoleReferenceCollector : Luau::AstVisitor
{
    explicit LuraphTableRoleReferenceCollector(const LuraphSemanticRoles& roles)
        : roles(roles)
    {
    }

    const LuraphSemanticRoles& roles;
    bool upvalues = false;
    bool registers = false;

    bool visit(Luau::AstExprIndexExpr* node) override
    {
        auto base = unwrapLuraphExpression(node->expr)->as<Luau::AstExprLocal>();
        upvalues = upvalues || (base && base->local == roles.upvalues);
        registers = registers || (base && base->local == roles.registers);
        return true;
    }
};

struct LuraphOpenUpvalueCloseEvidence : Luau::AstVisitor
{
    explicit LuraphOpenUpvalueCloseEvidence(Luau::AstLocal* registers)
        : registers(registers)
    {
    }

    Luau::AstLocal* registers = nullptr;
    bool register_reads = false;
    std::set<Luau::AstLocal*> iterated_tables;
    std::set<Luau::AstLocal*> written_tables;

    bool visit(Luau::AstStatForIn* node) override
    {
        if (node->values.size == 1)
        {
            auto table = unwrapLuraphExpression(node->values.data[0])->as<Luau::AstExprLocal>();
            if (table)
                iterated_tables.insert(table->local);
        }
        return true;
    }

    bool visit(Luau::AstExprIndexExpr* node) override
    {
        auto base = unwrapLuraphExpression(node->expr)->as<Luau::AstExprLocal>();
        register_reads = register_reads || (base && base->local == registers);
        return true;
    }

    bool visit(Luau::AstStatAssign* node) override
    {
        for (Luau::AstExpr* expression : node->vars)
        {
            auto indexed = unwrapLuraphExpression(expression)->as<Luau::AstExprIndexExpr>();
            auto base = indexed ? unwrapLuraphExpression(indexed->expr)->as<Luau::AstExprLocal>() : nullptr;
            if (base)
                written_tables.insert(base->local);
        }
        return true;
    }
};

std::optional<json> liftLuraphCloseUpvalues(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles)
{
    if (!leaf || leaf->body.size < 2 || !roles.registers)
        return std::nullopt;
    auto declaration = leaf->body.data[0]->as<Luau::AstStatLocal>();
    if (!declaration || declaration->vars.size != 1 || declaration->values.size != 1)
        return std::nullopt;
    Luau::AstExpr* value = unwrapLuraphExpression(declaration->values.data[0]);
    auto indexed = value ? value->as<Luau::AstExprIndexExpr>() : nullptr;
    auto base = indexed ? unwrapLuraphExpression(indexed->expr)->as<Luau::AstExprLocal>() : nullptr;
    auto index = indexed ? unwrapLuraphExpression(indexed->index)->as<Luau::AstExprLocal>() : nullptr;
    if (!base || !index || index->local != roles.pc)
        return std::nullopt;
    auto lane = roles.lanes.find(base->local);
    if (lane == roles.lanes.end())
        return std::nullopt;
    LuraphOpenUpvalueCloseEvidence evidence(roles.registers);
    leaf->visit(&evidence);
    std::vector<Luau::AstLocal*> openTables;
    std::set_intersection(evidence.iterated_tables.begin(), evidence.iterated_tables.end(),
        evidence.written_tables.begin(), evidence.written_tables.end(), std::back_inserter(openTables));
    if (!evidence.register_reads || openTables.size() != 1)
        return std::nullopt;
    return json{
        {"kind", "close_upvalues"},
        {"from", {{"kind", "operand"}, {"lane", lane->second}}},
        {"open_upvalue_table", openTables[0] && openTables[0]->name.value
            ? json(std::string(openTables[0]->name.value)) : json(nullptr)},
        {"source_semantic", true},
        {"proof", "upvalue_cell_rebind_and_release_loop"},
    };
}

struct LuraphGenericForPrepEvidence : Luau::AstVisitor
{
    size_t generic_loops = 0;
    size_t vararg_reads = 0;
    size_t closures = 0;

    bool visit(Luau::AstStatForIn*) override
    {
        ++generic_loops;
        return true;
    }

    bool visit(Luau::AstExprVarargs*) override
    {
        ++vararg_reads;
        return true;
    }

    bool visit(Luau::AstExprFunction*) override
    {
        ++closures;
        return true;
    }
};

std::optional<json> liftLuraphGenericForPrepare(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles)
{
    if (!leaf || leaf->body.size < 5 || !roles.pc || !roles.registers || !roles.helpers)
        return std::nullopt;
    LuraphGenericForPrepEvidence evidence;
    leaf->visit(&evidence);
    if (evidence.generic_loops != 1 || evidence.vararg_reads == 0 || evidence.closures != 1)
        return std::nullopt;

    std::optional<std::string> baseLane;
    std::optional<std::string> targetLane;
    for (Luau::AstStat* statement : leaf->body)
    {
        auto assignment = statement->as<Luau::AstStatAssign>();
        if (!assignment || assignment->vars.size != 1 || assignment->values.size != 1)
            continue;
        auto target = unwrapLuraphExpression(assignment->vars.data[0])->as<Luau::AstExprLocal>();
        auto value = unwrapLuraphExpression(assignment->values.data[0])->as<Luau::AstExprIndexExpr>();
        auto table = value ? unwrapLuraphExpression(value->expr)->as<Luau::AstExprLocal>() : nullptr;
        auto index = value ? unwrapLuraphExpression(value->index)->as<Luau::AstExprLocal>() : nullptr;
        if (!target || !table || !index || index->local != roles.pc)
            continue;
        auto lane = roles.lanes.find(table->local);
        if (lane == roles.lanes.end())
            continue;
        if (target->local == roles.pc)
            targetLane = lane->second;
        else if (!baseLane)
            baseLane = lane->second;
    }
    if (!baseLane || !targetLane)
        return std::nullopt;
    LuraphTableRoleReferenceCollector references(roles);
    leaf->visit(&references);
    if (!references.registers)
        return std::nullopt;
    return json{
        {"kind", "generic_for_prepare"},
        {"base_register", {{"kind", "operand"}, {"lane", *baseLane}}},
        {"loop_target", {{"kind", "operand"}, {"lane", *targetLane}}},
        {"protocol", "coroutine_wrapped_generic_iterator"},
        {"source_semantic", true},
        {"proof", "vararg_generic_loop_yield_trampoline"},
    };
}

void collectLuraphOpcodeSpecializedBlocks(
    Luau::AstStat* statement,
    Luau::AstLocal* opcodeLocal,
    int64_t opcode,
    std::vector<Luau::AstStatBlock*>& blocks,
    std::set<Luau::AstStatBlock*>& seen)
{
    if (!statement)
        return;
    if (auto block = statement->as<Luau::AstStatBlock>())
    {
        if (!seen.insert(block).second)
            return;
        for (Luau::AstStat* child : block->body)
            collectLuraphOpcodeSpecializedBlocks(child, opcodeLocal, opcode, blocks, seen);
        return;
    }
    auto conditional = statement->as<Luau::AstStatIf>();
    if (!conditional)
        return;
    const std::optional<bool> decision = evaluateStateCondition(conditional->condition, opcodeLocal, opcode);
    if (decision)
    {
        Luau::AstStat* selected = *decision ? static_cast<Luau::AstStat*>(conditional->thenbody) : conditional->elsebody;
        if (auto selectedBlock = selected ? selected->as<Luau::AstStatBlock>() : nullptr)
            if (!seen.contains(selectedBlock))
                blocks.push_back(selectedBlock);
        collectLuraphOpcodeSpecializedBlocks(selected, opcodeLocal, opcode, blocks, seen);
        return;
    }
    collectLuraphOpcodeSpecializedBlocks(conditional->thenbody, opcodeLocal, opcode, blocks, seen);
    collectLuraphOpcodeSpecializedBlocks(conditional->elsebody, opcodeLocal, opcode, blocks, seen);
}

int luraphSpecializedOperationScore(const json& operation)
{
    if (!operation.is_object() || luraphSemanticContainsUnknownState(operation))
        return -1;
    const std::string kind = operation.value("kind", "");
    if (kind == "register_write")
        return 120;
    if (kind == "return")
        return 115;
    if (kind == "table_write" || kind == "compound_write")
        return 110;
    if (kind == "numeric_for" || kind == "call" || kind == "expression")
        return 105;
    if (kind == "operation_sequence")
        return 100;
    if (kind == "jump" || kind == "branch")
        return 90;
    if (kind == "protector_internal_sequence" || operation.value("protector_state", false))
        return 20;
    return 60;
}

std::optional<json> liftLuraphStraightLineSuffix(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles,
    int64_t opcode)
{
    if (!leaf || leaf->body.size == 0)
        return std::nullopt;
    std::optional<json> best;
    size_t bestLength = 0;
    for (size_t begin = 0; begin < leaf->body.size; ++begin)
    {
        json operations = json::array();
        bool valid = true;
        bool dependsOnVmState = false;
        for (size_t index = begin; index < leaf->body.size; ++index)
        {
            std::optional<json> operation = normalizeLuraphSemanticStatement(
                leaf->body.data[index], roles, opcode, dependsOnVmState, 0);
            if (!operation)
            {
                valid = false;
                break;
            }
            operations.push_back(std::move(*operation));
        }
        if (!valid)
            continue;
        std::optional<json> candidate = liftStraightLineLuraphHandler(operations);
        if (!candidate || luraphSpecializedOperationScore(*candidate) < 0)
            continue;
        const size_t length = leaf->body.size - begin;
        if (length <= bestLength)
            continue;
        (*candidate)["straight_line_suffix"] = true;
        (*candidate)["proof"] = "direct_handler_suffix_with_local_bindings_resolved";
        best = std::move(candidate);
        bestLength = length;
    }
    return best;
}

std::optional<json> liftLuraphOpcodeSpecializedTail(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles,
    int64_t opcode)
{
    if (!leaf || !roles.opcode)
        return std::nullopt;

    std::vector<Luau::AstStatBlock*> blocks;
    std::set<Luau::AstStatBlock*> seen;
    collectLuraphOpcodeSpecializedBlocks(leaf, roles.opcode, opcode, blocks, seen);

    std::optional<json> best;
    int bestScore = -1;
    size_t bestStatements = std::numeric_limits<size_t>::max();
    for (Luau::AstStatBlock* block : blocks)
    {
        bool dependsOnVmState = false;
        std::optional<json> operations = normalizeLuraphSemanticBlock(
            block, roles, opcode, dependsOnVmState, 0);
        std::optional<json> candidate;
        if (operations && !operations->empty())
        {
            if (!dependsOnVmState && operations->size() == 1)
                candidate = (*operations)[0];
            else
                candidate = liftStraightLineLuraphHandler(*operations);
        }
        if (!candidate)
            candidate = liftLuraphOpaqueRegisterTail(block, roles, opcode);
        if (!candidate)
            candidate = liftLuraphOpaqueTerminalReturn(block, roles, opcode);
        if (!candidate)
            continue;

        const int score = luraphSpecializedOperationScore(*candidate);
        if (score < 0 || score < bestScore ||
            (score == bestScore && block->body.size >= bestStatements))
            continue;
        (*candidate)["opcode_specialized"] = true;
        (*candidate)["proof"] = "branch_condition_resolved_from_current_opcode";
        best = std::move(candidate);
        bestScore = score;
        bestStatements = block->body.size;
    }
    return best;
}

LuraphNormalizedHandler normalizeLuraphHandler(
    Luau::AstStatBlock* leaf,
    const LuraphSemanticRoles& roles,
    int64_t opcode)
{
    LuraphNormalizedHandler result;
    bool dependsOnVmState = false;
    std::optional<json> operations = normalizeLuraphSemanticBlock(leaf, roles, opcode, dependsOnVmState, 0);
    if (operations)
    {
        result.normalization_complete = true;
        result.vm_state_independent = !dependsOnVmState;
        result.ir = {
            {"kind", "handler_sequence"},
            {"opcode", opcode},
            {"operations", *operations},
            {"vm_state_independent", result.vm_state_independent},
        };
        if (result.vm_state_independent && operations->size() == 1)
            result.semantic_operation = (*operations)[0];
        else if (std::optional<json> lifted = liftStraightLineLuraphHandler(*operations))
        {
            result.semantic_operation = std::move(*lifted);
            result.vm_state_independent = true;
            result.ir["straight_line_temporaries_elided"] = true;
            result.ir["vm_state_independent"] = true;
        }
        if (result.semantic_operation.is_null() && operations->size() == 1 &&
            (*operations)[0].value("kind", "") == "register_write" &&
            (*operations)[0]["value"].value("kind", "") == "operand_table")
        {
            result.semantic_operation = (*operations)[0];
            result.semantic_operation["protector_state"] = true;
            result.semantic_operation["provenance"] = "protector_operand_lane";
            result.vm_state_independent = true;
            result.ir["protector_operand_lane"] = true;
            result.ir["vm_state_independent"] = true;
        }
    }
    if (result.semantic_operation.is_null())
    {
        if (std::optional<json> stateRead = liftLuraphRegisterStatePreparation(leaf, roles))
        {
            result.semantic_operation = std::move(*stateRead);
            if (result.ir.is_null())
                result.ir = json{{"kind", "register_state_preparation_handler"}, {"opcode", opcode}};
            result.ir["register_state_preparation_lifted"] = true;
        }
    }
    if (result.semantic_operation.is_null())
    {
        if (std::optional<json> suffix = liftLuraphStraightLineSuffix(leaf, roles, opcode))
        {
            result.semantic_operation = std::move(*suffix);
            result.vm_state_independent = true;
            if (result.ir.is_null())
                result.ir = json{{"kind", "straight_line_suffix_handler"}, {"opcode", opcode}};
            result.ir["straight_line_suffix_lifted"] = true;
            result.ir["vm_state_independent"] = true;
        }
    }
    if (result.semantic_operation.is_null())
    {
        if (std::optional<json> specialized = liftLuraphOpcodeSpecializedTail(leaf, roles, opcode))
        {
            result.semantic_operation = std::move(*specialized);
            result.vm_state_independent = true;
            if (result.ir.is_null())
                result.ir = json{{"kind", "opcode_specialized_handler"}, {"opcode", opcode}};
            result.ir["opcode_specialized_branch_lifted"] = true;
            result.ir["vm_state_independent"] = true;
        }
    }
    if (result.semantic_operation.is_null())
    {
        if (std::optional<json> jump = liftLuraphSelfPatchingJumpTail(leaf, roles))
        {
            result.semantic_operation = std::move(*jump);
            if (result.ir.is_null())
                result.ir = json{{"kind", "opaque_handler_tail"}, {"opcode", opcode}};
            result.ir["self_patching_jump_lifted"] = true;
        }
    }
    if (result.semantic_operation.is_null())
    {
        if (std::optional<json> genericFor = liftLuraphGenericForPrepare(leaf, roles))
        {
            result.semantic_operation = std::move(*genericFor);
            if (result.ir.is_null())
                result.ir = json{{"kind", "generic_for_prepare_handler"}, {"opcode", opcode}};
            result.ir["generic_for_prepare_lifted"] = true;
        }
    }
    if (result.semantic_operation.is_null())
    {
        if (std::optional<json> close = liftLuraphCloseUpvalues(leaf, roles))
        {
            result.semantic_operation = std::move(*close);
            if (result.ir.is_null())
                result.ir = json{{"kind", "upvalue_close_handler"}, {"opcode", opcode}};
            result.ir["upvalue_close_lifted"] = true;
        }
    }
    if (result.semantic_operation.is_null())
    {
        if (std::optional<json> tail = liftLuraphOpaqueRegisterTail(leaf, roles, opcode))
        {
            result.semantic_operation = std::move(*tail);
            if (result.ir.is_null())
                result.ir = json{{"kind", "opaque_handler_tail"}, {"opcode", opcode}};
            result.ir["opaque_prefix_elided"] = true;
        }
    }
    if (result.semantic_operation.is_null() && leaf && leaf->body.size > 0)
    {
        if (std::optional<json> terminalReturn = liftLuraphOpaqueTerminalReturn(leaf, roles, opcode))
        {
            result.semantic_operation = std::move(*terminalReturn);
            result.vm_state_independent = true;
            if (result.ir.is_null())
                result.ir = json{{"kind", "terminal_return_handler"}, {"opcode", opcode}};
            result.ir["opaque_terminal_return_lifted"] = true;
            result.ir["vm_state_independent"] = true;
        }
    }
    if (result.semantic_operation.is_null() && leaf && leaf->body.size > 0)
    {
        Luau::AstStat* terminal = leaf->body.data[leaf->body.size - 1];
        if (terminal->is<Luau::AstStatReturn>())
        {
            bool terminalDependsOnVmState = false;
            std::optional<json> terminalReturn = normalizeLuraphSemanticStatement(
                terminal, roles, opcode, terminalDependsOnVmState, 0);
            if (terminalReturn)
                rewriteLuraphRegisterRangeCalls(*terminalReturn);
            if (terminalReturn && !terminalDependsOnVmState && !luraphSemanticContainsUnknownState(*terminalReturn))
            {
                result.semantic_operation = std::move(*terminalReturn);
                result.semantic_operation["implicit_close_upvalues"] = leaf->body.size > 1;
                result.vm_state_independent = true;
                if (result.ir.is_null())
                    result.ir = json{{"kind", "terminal_return_handler"}, {"opcode", opcode}};
                result.ir["terminal_return_lifted"] = true;
                result.ir["vm_state_independent"] = true;
            }
        }
    }
    if (result.semantic_operation.is_null() && operations && !operations->empty())
    {
        result.semantic_operation = {
            {"kind", "protector_internal_sequence"},
            {"operations", *operations},
            {"protector_state", true},
            {"source_semantic", false},
        };
        result.ir["protector_internal_preserved"] = true;
    }
    if (result.semantic_operation.is_null())
    {
        if (std::optional<json> laneTransfer = liftLuraphRegisterLaneTransfer(leaf, roles))
        {
            result.semantic_operation = std::move(*laneTransfer);
            if (result.ir.is_null())
                result.ir = json{{"kind", "register_lane_transfer_handler"}, {"opcode", opcode}};
            result.ir["register_lane_transfer_lifted"] = true;
        }
    }
    if (result.semantic_operation.is_null())
    {
        if (std::optional<json> poolRead = liftLuraphOpaqueRegisterPoolTail(leaf, roles, opcode))
        {
            result.semantic_operation = std::move(*poolRead);
            if (result.ir.is_null())
                result.ir = json{{"kind", "opaque_register_pool_handler"}, {"opcode", opcode}};
            result.ir["opaque_register_pool_tail_lifted"] = true;
        }
    }
    if (result.semantic_operation.is_null())
    {
        if (std::optional<json> tableWrite = liftLuraphOpaqueProtectorTableTail(leaf, roles, opcode))
        {
            result.semantic_operation = std::move(*tableWrite);
            if (result.ir.is_null())
                result.ir = json{{"kind", "opaque_protector_table_handler"}, {"opcode", opcode}};
            result.ir["opaque_protector_table_tail_lifted"] = true;
        }
    }
    if (result.semantic_operation.is_null() && leaf && leaf->body.size > 0)
    {
        bool terminalDependsOnVmState = false;
        std::optional<json> terminal = normalizeLuraphSemanticStatement(
            leaf->body.data[leaf->body.size - 1], roles, opcode, terminalDependsOnVmState, 0);
        if (result.ir.is_null())
            result.ir = json{{"kind", "unresolved_handler"}, {"opcode", opcode}};
        result.ir["terminal_statement"] = terminal ? std::move(*terminal) : json(nullptr);
        result.ir["terminal_depends_on_vm_state"] = terminalDependsOnVmState;
    }
    return result;
}

bool luraphJsonContainsKind(const json& value, std::string_view kind)
{
    if (value.is_object())
    {
        if (value.value("kind", "") == kind)
            return true;
        for (const auto& [key, child] : value.items())
            if (luraphJsonContainsKind(child, kind))
                return true;
    }
    else if (value.is_array())
    {
        for (const json& child : value)
            if (luraphJsonContainsKind(child, kind))
                return true;
    }
    return false;
}

bool luraphJsonContainsNilConstant(const json& value)
{
    if (value.is_object())
    {
        if (value.value("kind", "") == "constant" && value.contains("value") && value["value"].is_null())
            return true;
        for (const auto& [key, child] : value.items())
            if (luraphJsonContainsNilConstant(child))
                return true;
    }
    else if (value.is_array())
    {
        for (const json& child : value)
            if (luraphJsonContainsNilConstant(child))
                return true;
    }
    return false;
}

bool luraphJsonContainsVmState(const json& value, std::string_view name)
{
    if (value.is_object())
    {
        if (value.value("kind", "") == "vm_state" && value.value("name", "") == name)
            return true;
        for (const auto& [key, child] : value.items())
            if (luraphJsonContainsVmState(child, name))
                return true;
    }
    else if (value.is_array())
    {
        for (const json& child : value)
            if (luraphJsonContainsVmState(child, name))
                return true;
    }
    return false;
}

const json* findLuraphSemanticKind(const json& value, std::string_view kind)
{
    if (value.is_object())
    {
        if (value.value("kind", "") == kind)
            return &value;
        for (const auto& [key, child] : value.items())
            if (const json* found = findLuraphSemanticKind(child, kind))
                return found;
    }
    else if (value.is_array())
    {
        for (const json& child : value)
            if (const json* found = findLuraphSemanticKind(child, kind))
                return found;
    }
    return nullptr;
}

void recognizeLuraphPreparedRegisterRanges(json& handlers)
{
    struct PreparedRange
    {
        size_t handler = 0;
        std::string start_state;
        std::string end_state;
        json start;
        json end;
    };
    std::vector<PreparedRange> preparations;
    for (size_t handlerIndex = 0; handlerIndex < handlers.size(); ++handlerIndex)
    {
        const json& operations = handlers[handlerIndex]["normalized_handler_ir"]["operations"];
        if (!operations.is_array() || operations.size() != 2)
            continue;
        PreparedRange prepared;
        prepared.handler = handlerIndex;
        bool valid = true;
        std::array<std::string*, 2> names = {&prepared.start_state, &prepared.end_state};
        std::array<json*, 2> values = {&prepared.start, &prepared.end};
        for (size_t index = 0; index < 2; ++index)
        {
            const json& operation = operations[index];
            const json& targets = operation["targets"];
            const json& operationValues = operation["values"];
            valid = valid && operation.value("kind", "") == "assign" && targets.is_array() && targets.size() == 1 &&
                operationValues.is_array() && operationValues.size() == 1 && targets[0].value("kind", "") == "vm_state" &&
                operationValues[0].value("kind", "") == "operand";
            if (!valid)
                break;
            *names[index] = targets[0].value("name", "");
            *values[index] = operationValues[0];
        }
        if (valid && !prepared.start_state.empty() && !prepared.end_state.empty())
            preparations.push_back(std::move(prepared));
    }

    size_t rangeId = 0;
    for (const PreparedRange& prepared : preparations)
    {
        for (size_t handlerIndex = 0; handlerIndex < handlers.size(); ++handlerIndex)
        {
            json& row = handlers[handlerIndex];
            const json& operations = row["normalized_handler_ir"]["operations"];
            if (!operations.is_array() || operations.size() != 1)
                continue;
            const json& loop = operations[0];
            if (loop.value("kind", "") != "numeric_for" || loop["from"].value("kind", "") != "vm_state" ||
                loop["to"].value("kind", "") != "vm_state" || loop["from"].value("name", "") != prepared.start_state ||
                loop["to"].value("name", "") != prepared.end_state || !luraphJsonContainsKind(loop["body"], "register_file") ||
                !luraphJsonContainsNilConstant(loop["body"]))
                continue;
            const std::string stateId = "register_clear_range_" + std::to_string(++rangeId);
            handlers[prepared.handler]["semantic_operation"] = {
                {"kind", "prepare_register_clear"}, {"state", stateId},
                {"from", prepared.start}, {"to", prepared.end}, {"protector_state", true},
            };
            handlers[prepared.handler]["vm_state_independent"] = true;
            handlers[prepared.handler]["normalized_handler_ir"]["cross_instruction_state"] = stateId;
            row["semantic_operation"] = {
                {"kind", "clear_prepared_register_range"}, {"state", stateId}, {"protector_state", true},
            };
            row["vm_state_independent"] = true;
            row["normalized_handler_ir"]["cross_instruction_state"] = stateId;
            break;
        }
    }
}

void recognizeLuraphNumericForState(json& handlers)
{
    for (size_t restoreIndex = 0; restoreIndex < handlers.size(); ++restoreIndex)
    {
        const json& restoreOperations = handlers[restoreIndex]["normalized_handler_ir"]["operations"];
        if (!restoreOperations.is_array() || restoreOperations.size() != 4)
            continue;
        std::map<int64_t, std::string> stateByKey;
        std::string frame;
        bool validRestore = true;
        for (const json& operation : restoreOperations)
        {
            const json& targets = operation["targets"];
            const json& values = operation["values"];
            if (operation.value("kind", "") != "assign" || !targets.is_array() || targets.size() != 1 ||
                !values.is_array() || values.size() != 1 || targets[0].value("kind", "") != "vm_state" ||
                values[0].value("kind", "") != "index_read" || values[0]["table"].value("kind", "") != "vm_state" ||
                values[0]["index"].value("kind", "") != "constant" || !values[0]["index"]["value"].is_number())
            {
                validRestore = false;
                break;
            }
            const int64_t key = static_cast<int64_t>(values[0]["index"]["value"].get<double>());
            const std::string sourceFrame = values[0]["table"].value("name", "");
            if (frame.empty())
                frame = sourceFrame;
            validRestore = validRestore && sourceFrame == frame;
            stateByKey[key] = targets[0].value("name", "");
        }
        if (!validRestore || stateByKey.size() != 4 || stateByKey[1] != frame || stateByKey[2].empty() ||
            stateByKey[3].empty() || stateByKey[5].empty())
            continue;
        const std::string limit = stateByKey[2];
        const std::string current = stateByKey[3];
        const std::string step = stateByKey[5];

        size_t prepareIndex = handlers.size();
        json base = nullptr;
        json bodyTarget = nullptr;
        for (size_t handlerIndex = 0; handlerIndex < handlers.size(); ++handlerIndex)
        {
            const json& operations = handlers[handlerIndex]["normalized_handler_ir"]["operations"];
            if (!operations.is_array() || operations.size() < 5 || !luraphJsonContainsVmState(operations, frame) ||
                !luraphJsonContainsVmState(operations, limit) || !luraphJsonContainsVmState(operations, current) ||
                !luraphJsonContainsVmState(operations, step))
                continue;
            const json& first = operations.front();
            if (first.value("kind", "") != "assign" || first["targets"].size() != 1 ||
                first["targets"][0].value("kind", "") != "vm_state" || first["targets"][0].value("name", "") != frame ||
                first["values"].size() != 1 || first["values"][0].value("kind", "") != "table")
                continue;
            for (const json& operation : operations)
            {
                if (operation.value("kind", "") == "assign" && operation["targets"].size() == 1 && operation["values"].size() == 1 &&
                    operation["targets"][0].value("kind", "") == "vm_state" && operation["values"][0].value("kind", "") == "operand" &&
                    operation["targets"][0].value("name", "") != frame)
                    base = operation["values"][0];
            }
            if (const json* jump = findLuraphSemanticKind(operations, "jump"))
                bodyTarget = (*jump)["target"];
            if (!base.is_null() && !bodyTarget.is_null())
            {
                prepareIndex = handlerIndex;
                break;
            }
        }
        if (prepareIndex == handlers.size())
            continue;

        size_t stepIndex = handlers.size();
        json resultRegister = nullptr;
        json loopTarget = nullptr;
        for (size_t handlerIndex = 0; handlerIndex < handlers.size(); ++handlerIndex)
        {
            const json& operations = handlers[handlerIndex]["normalized_handler_ir"]["operations"];
            if (!operations.is_array() || !luraphJsonContainsVmState(operations, limit) ||
                !luraphJsonContainsVmState(operations, current) || !luraphJsonContainsVmState(operations, step))
                continue;
            const json* compound = findLuraphSemanticKind(operations, "compound_write");
            const json* write = findLuraphSemanticKind(operations, "register_write");
            const json* jump = findLuraphSemanticKind(operations, "jump");
            if (!compound || !write || !jump || (*compound)["target"].value("kind", "") != "vm_state" ||
                (*compound)["target"].value("name", "") != current)
                continue;
            resultRegister = (*write)["register"];
            loopTarget = (*jump)["target"];
            stepIndex = handlerIndex;
            break;
        }
        if (stepIndex == handlers.size())
            continue;

        const std::string stateId = "numeric_for_state_1";
        handlers[prepareIndex]["semantic_operation"] = {
            {"kind", "numeric_for_prepare"}, {"state", stateId}, {"base_register", base},
            {"body_target", bodyTarget}, {"protector_state", true},
        };
        handlers[stepIndex]["semantic_operation"] = {
            {"kind", "numeric_for_step"}, {"state", stateId}, {"result_register", resultRegister},
            {"loop_target", loopTarget}, {"protector_state", true},
        };
        handlers[restoreIndex]["semantic_operation"] = {
            {"kind", "numeric_for_restore"}, {"state", stateId}, {"protector_state", true},
        };
        for (size_t handlerIndex : {prepareIndex, stepIndex, restoreIndex})
        {
            handlers[handlerIndex]["vm_state_independent"] = true;
            handlers[handlerIndex]["normalized_handler_ir"]["cross_instruction_state"] = stateId;
        }
        return;
    }
}

void recognizeLuraphVarargCapture(json& handlers)
{
    size_t captureId = 0;
    for (json& row : handlers)
    {
        const json& operations = row["normalized_handler_ir"]["operations"];
        if (!operations.is_array() || operations.size() != 1)
            continue;
        const json& assignment = operations[0];
        const json& targets = assignment["targets"];
        const json& values = assignment["values"];
        if (assignment.value("kind", "") != "assign" || !targets.is_array() || targets.size() != 2 ||
            !values.is_array() || values.size() != 1 || targets[0].value("kind", "") != "vm_state" ||
            targets[1].value("kind", "") != "vm_state" || values[0].value("kind", "") != "call" ||
            values[0]["arguments"].size() != 1 || values[0]["arguments"][0].value("kind", "") != "varargs")
            continue;
        const json& function = values[0]["function"];
        if (function.value("kind", "") != "index_read" || function["index"].value("kind", "") != "constant")
            continue;
        const std::string stateId = "vararg_capture_" + std::to_string(++captureId);
        row["semantic_operation"] = {
            {"kind", "capture_varargs"}, {"state", stateId}, {"values_slot", targets[0].value("name", "")},
            {"count_slot", targets[1].value("name", "")}, {"protector_state", true},
        };
        row["vm_state_independent"] = true;
        row["normalized_handler_ir"]["cross_instruction_state"] = stateId;
    }
}

struct LuraphOpcodeCatalog
{
    bool available = false;
    size_t resolved = 0;
    size_t unique_handlers = 0;
    json document = json::object();
};

LuraphOpcodeCatalog buildLuraphOpcodeCatalog(std::string_view source)
{
    LuraphOpcodeCatalog catalog;
    auto parsed = parseSource(source);
    if (!parsed->result.errors.empty())
        return catalog;
    LuraphLoopShapeCollector collector;
    parsed->result.root->visit(&collector);
    auto shape = std::max_element(collector.shapes.begin(), collector.shapes.end(), [](const LuraphLoopShape& left, const LuraphLoopShape& right) {
        return left.conditionals < right.conditionals;
    });
    if (shape == collector.shapes.end() || shape->conditionals < 40 || !shape->opcode || !shape->body)
        return catalog;

    LuraphOpcodeDispatcherCollector dispatcherCollector(shape->opcode);
    shape->body->visit(&dispatcherCollector);
    auto dispatcherCandidate = std::max_element(
        dispatcherCollector.candidates.begin(), dispatcherCollector.candidates.end(),
        [](const auto& left, const auto& right) { return left.conditionals < right.conditionals; });
    if (dispatcherCandidate == dispatcherCollector.candidates.end() || dispatcherCandidate->conditionals < 40)
        return catalog;
    Luau::AstStat* dispatcher = dispatcherCandidate->node;
    SourceView view(source);
    json provenGuardBindingEvidence = json::array();
    const std::map<Luau::AstLocal*, double> provenGuardBindings = proveLuraphGuardBindings(
        parsed->result.root, dispatcher, shape->opcode, view, &provenGuardBindingEvidence);

    LuraphGuardBindingCollector guardCollector(shape->opcode);
    dispatcher->visit(&guardCollector);
    auto guardBinding = std::max_element(
        guardCollector.scores.begin(), guardCollector.scores.end(),
        [](const auto& left, const auto& right) { return left.second < right.second; });

    LuraphRegisterRoleCollector roles(shape->pc);
    shape->body->visit(&roles);
    auto registerRole = std::max_element(roles.register_scores.begin(), roles.register_scores.end(), [](const auto& left, const auto& right) {
        return left.second < right.second;
    });
    Luau::AstLocal* registers = registerRole == roles.register_scores.end() ? nullptr : registerRole->first;
    LuraphTopRoleCollector topRoles(registers);
    shape->body->visit(&topRoles);
    auto topRole = std::max_element(topRoles.scores.begin(), topRoles.scores.end(), [](const auto& left, const auto& right) {
        return left.second < right.second;
    });
    Luau::AstLocal* top = topRole == topRoles.scores.end() || topRole->second < 2 ? nullptr : topRole->first;
    std::set<Luau::AstLocal*> lanes = roles.pc_indexed_tables;
    lanes.erase(shape->opcode_table);
    if (registers)
        lanes.erase(registers);
    LuraphUpvalueRoleCollector upvalueRoles(registers, shape->pc, lanes);
    shape->body->visit(&upvalueRoles);
    auto upvalueRole = std::max_element(upvalueRoles.scores.begin(), upvalueRoles.scores.end(), [](const auto& left, const auto& right) {
        return left.second < right.second;
    });
    Luau::AstLocal* upvalues = upvalueRole == upvalueRoles.scores.end() || upvalueRole->second < 2 ? nullptr : upvalueRole->first;

    LuraphDirectRegisterSourceCollector environmentRoles(registers);
    for (int64_t opcode = 0; opcode <= 255; ++opcode)
        if (Luau::AstStatBlock* leaf = selectLeaf(
                dispatcher, shape->opcode, opcode, &provenGuardBindings))
            leaf->visit(&environmentRoles);
    for (Luau::AstLocal* lane : lanes)
        environmentRoles.scores.erase(lane);
    environmentRoles.scores.erase(registers);
    environmentRoles.scores.erase(upvalues);
    auto environmentRole = std::max_element(environmentRoles.scores.begin(), environmentRoles.scores.end(), [](const auto& left, const auto& right) {
        return left.second < right.second;
    });
    Luau::AstLocal* environment = environmentRole == environmentRoles.scores.end() || environmentRole->second < 3
        ? nullptr
        : environmentRole->first;
    LuraphHelperRoleCollector helperRoles;
    shape->body->visit(&helperRoles);
    helperRoles.scores.erase(registers);
    helperRoles.scores.erase(upvalues);
    helperRoles.scores.erase(environment);
    for (Luau::AstLocal* lane : lanes)
        helperRoles.scores.erase(lane);
    auto helperRole = std::max_element(helperRoles.scores.begin(), helperRoles.scores.end(), [](const auto& left, const auto& right) {
        return left.second < right.second;
    });
    Luau::AstLocal* helpers = helperRole == helperRoles.scores.end() || helperRole->second < 3 ? nullptr : helperRole->first;
    std::vector<std::string> laneNames;
    LuraphSemanticRoles semanticRoles;
    semanticRoles.registers = registers;
    semanticRoles.pc = shape->pc;
    semanticRoles.opcode = shape->opcode;
    semanticRoles.opcode_table = shape->opcode_table;
    semanticRoles.top = top;
    semanticRoles.environment = environment;
    semanticRoles.upvalues = upvalues;
    semanticRoles.helpers = helpers;
    for (Luau::AstLocal* lane : lanes)
        if (lane && lane->name.value)
        {
            laneNames.emplace_back(lane->name.value);
            semanticRoles.lanes[lane] = lane->name.value;
        }
    std::sort(laneNames.begin(), laneNames.end());

    json guardBindingCandidates = json::array();
    std::vector<std::pair<std::pair<Luau::AstLocal*, int64_t>, size_t>> rankedGuardBindings(
        guardCollector.scores.begin(), guardCollector.scores.end());
    std::sort(rankedGuardBindings.begin(), rankedGuardBindings.end(), [](const auto& left, const auto& right) {
        if (left.second != right.second)
            return left.second > right.second;
        return left.first.second < right.first.second;
    });
    for (const auto& [binding, score] : rankedGuardBindings)
    {
        if (score < 2 || guardBindingCandidates.size() >= 16)
            break;
        guardBindingCandidates.push_back({
            {"local", binding.first && binding.first->name.value
                ? json(std::string(binding.first->name.value)) : json(nullptr)},
            {"value", binding.second},
            {"score", score},
        });
    }
    json dispatcherDecisions = json::array();
    if (auto rootConditional = dispatcher->as<Luau::AstStatIf>())
    {
        for (int64_t sample : {int64_t(0), int64_t(80), int64_t(255)})
        {
            const std::optional<bool> decision = evaluateStateCondition(
                rootConditional->condition, shape->opcode, sample, &provenGuardBindings);
            dispatcherDecisions.push_back({
                {"opcode", sample},
                {"decision", decision ? json(*decision) : json(nullptr)},
            });
        }
    }
    json handlers = json::array();
    std::set<std::pair<size_t, size_t>> uniqueRanges;
    size_t ambiguousHandlers = 0;
    size_t missingHandlers = 0;
    for (int64_t opcode = 0; opcode <= 255; ++opcode)
    {
        const LuraphBranchDecision decide = [&](Luau::AstStatIf* conditional) {
            return evaluateStateCondition(
                conditional->condition, shape->opcode, opcode, &provenGuardBindings);
        };
        LuraphExecutedStatementPath path = selectLuraphExecutedStatementPath(
            dispatcherCandidate->node, shape->body, decide);
        if (!path.complete)
        {
            bool legacyAmbiguous = false;
            if (Luau::AstStatBlock* candidate = selectLeaf(
                    dispatcher, shape->opcode, opcode, &provenGuardBindings, &legacyAmbiguous))
            {
                path.statements.assign(candidate->body.begin(), candidate->body.end());
                path.dispatcher_statements = path.statements.size();
                path.continuation_statements = 0;
            }
            path.ambiguous = true;
        }
        Luau::AstStatBlock executed = luraphExecutedStatementBlock(path);
        Luau::AstStatBlock* leaf = path.statements.empty() ? nullptr : &executed;
        bool opcodeLocalReused = false;
        if (leaf)
        {
            LuraphOpcodeReferenceFinder finder(shape->opcode);
            leaf->visit(&finder);
            opcodeLocalReused = finder.found;
        }
        const bool resolved = leaf != nullptr && path.complete && !path.ambiguous && !opcodeLocalReused;
        json row = {
            {"opcode", opcode},
            {"resolved", resolved},
            {"opcode_local_reused", opcodeLocalReused},
            {"selection_status", resolved ? "exact" : leaf ? "ambiguous" : "missing"},
            {"unresolved_guard_path", path.ambiguous || opcodeLocalReused},
            {"executed_path_complete", path.complete},
            {"executed_statement_count", path.statements.size()},
            {"dispatcher_statement_count", path.dispatcher_statements},
            {"continuation_statement_count", path.continuation_statements},
            {"executed_statement_ranges", luraphExecutedStatementRanges(path, view)},
        };
        if (leaf)
        {
            LuraphHandlerEffects effects(registers, shape->pc, lanes);
            leaf->visit(&effects);
            row["effects"] = effects.artifact();
            const LuraphNormalizedHandler normalized = normalizeLuraphHandler(leaf, semanticRoles, opcode);
            row["normalization_complete"] = normalized.normalization_complete;
            row["vm_state_independent"] = normalized.vm_state_independent;
            row["normalized_handler_ir"] = normalized.ir;
            json operation = normalized.semantic_operation;
            if (!operation.is_null() && luraphJsonContainsKind(operation, "helper_table"))
                operation["protector_state"] = true;
            const bool fullEffectNormalization = resolved && normalized.normalization_complete &&
                normalized.vm_state_independent && operation.is_object() &&
                !operation.value("protector_state", false) &&
                operation.value("source_semantic", true) &&
                !luraphSemanticContainsUnknownState(operation);
            row["full_effect_normalization"] = fullEffectNormalization;
            row["full_effect_validation"] = false;
            row["semantic_operation"] = nullptr;
            if (!operation.is_null())
            {
                operation["candidate_only"] = true;
                operation["path_complete"] = path.complete;
                operation["full_effect_normalization"] = fullEffectNormalization;
                operation["static_semantic"] = false;
                row["candidate_semantic_operation"] = std::move(operation);
            }
            if (opcode == 8)
                row["opcode8_call_shape"] = recognizeLuraphOpcode8PackedCallShape(
                    leaf, semanticRoles, resolved && path.complete && !path.ambiguous && !opcodeLocalReused);
        }
        if (leaf)
        {
            size_t begin = std::numeric_limits<size_t>::max();
            size_t end = 0;
            size_t bytes = 0;
            for (Luau::AstStat* statement : path.statements)
            {
                const size_t statementBegin = view.offset(statement->location.begin);
                const size_t statementEnd = view.offset(statement->location.end);
                begin = std::min(begin, statementBegin);
                end = std::max(end, statementEnd);
                bytes += statementEnd >= statementBegin ? statementEnd - statementBegin : 0;
            }
            row["range"] = {
                {"begin", begin}, {"end", end}, {"bytes", bytes},
                {"span_bytes", end >= begin ? end - begin : 0},
                {"contiguous", path.statements.size() <= 1},
            };
            row[resolved ? "handler_source" : "candidate_source"] =
                luraphExecutedStatementSource(path, view);
            if (!resolved)
                row["handler_source"] = nullptr;
            row["handler_source_truncated"] = bytes > 16384;
            if (resolved)
            {
                uniqueRanges.emplace(begin, end);
                ++catalog.resolved;
            }
            else
                ++ambiguousHandlers;
        }
        else
        {
            ++missingHandlers;
            row["range"] = nullptr;
            row["handler_source"] = nullptr;
            row["handler_source_truncated"] = false;
        }
        handlers.push_back(std::move(row));
    }
    recognizeLuraphPreparedRegisterRanges(handlers);
    recognizeLuraphNumericForState(handlers);
    recognizeLuraphVarargCapture(handlers);
    for (json& row : handlers)
    {
        if (!row.contains("semantic_operation") || row["semantic_operation"].is_null())
            continue;
        row["candidate_semantic_operation"] = row["semantic_operation"];
        row["candidate_semantic_operation"]["candidate_only"] = true;
        row["candidate_semantic_operation"]["path_complete"] =
            row.value("executed_path_complete", false);
        row["candidate_semantic_operation"]["static_semantic"] = false;
        row["semantic_operation"] = nullptr;
    }
    catalog.available = true;
    catalog.unique_handlers = uniqueRanges.size();
    catalog.document = {
        {"version", 1},
        {"kind", "luraph-v14.7-opcode-handler-catalog"},
        {"opcode_local", shape->opcode->name.value ? json(std::string(shape->opcode->name.value)) : json(nullptr)},
        {"opcode_table_local", shape->opcode_table && shape->opcode_table->name.value ? json(std::string(shape->opcode_table->name.value)) : json(nullptr)},
        {"pc_local", shape->pc && shape->pc->name.value ? json(std::string(shape->pc->name.value)) : json(nullptr)},
        {"register_table_local", registers && registers->name.value ? json(std::string(registers->name.value)) : json(nullptr)},
        {"top_register_local", top && top->name.value ? json(std::string(top->name.value)) : json(nullptr)},
        {"environment_local", environment && environment->name.value ? json(std::string(environment->name.value)) : json(nullptr)},
        {"upvalue_file_local", upvalues && upvalues->name.value ? json(std::string(upvalues->name.value)) : json(nullptr)},
        {"helper_table_local", helpers && helpers->name.value ? json(std::string(helpers->name.value)) : json(nullptr)},
        {"operand_lane_locals", laneNames},
        {"loop_kind", shape->loop->is<Luau::AstStatRepeat>() ? "repeat-until-false" : "while-true"},
        {"conditionals", shape->conditionals},
        {"dispatcher_conditionals", dispatcherCandidate->conditionals},
        {"dispatcher_range", {
            {"begin", view.offset(dispatcher->location.begin)},
            {"end", view.offset(dispatcher->location.end)},
        }},
        {"dispatcher_preview", view.slice(dispatcher->location, 1024)},
        {"dispatcher_decisions", std::move(dispatcherDecisions)},
        {"guard_binding", guardBinding != guardCollector.scores.end() && guardBinding->second >= 4 ? json{
            {"local", guardBinding->first.first && guardBinding->first.first->name.value
                ? json(std::string(guardBinding->first.first->name.value)) : json(nullptr)},
            {"value", guardBinding->first.second},
            {"score", guardBinding->second},
            {"applied_to_static_handlers", false},
            {"inference_only", true},
        } : json(nullptr)},
        {"guard_binding_candidates", std::move(guardBindingCandidates)},
        {"proven_guard_bindings", std::move(provenGuardBindingEvidence)},
        {"dynamic_guard_conditions", luraphGuardConditionManifest(
            dispatcher, shape->opcode, provenGuardBindings, view)},
        {"resolved_opcodes", catalog.resolved},
        {"exact_handlers", catalog.resolved},
        {"ambiguous_handlers", ambiguousHandlers},
        {"missing_handlers", missingHandlers},
        {"leaf_selection_complete", catalog.resolved == 256},
        {"unique_handlers", catalog.unique_handlers},
        {"handlers", std::move(handlers)},
    };
    return catalog;
}

struct LuraphDirectReturnCollector : Luau::AstVisitor
{
    std::vector<Luau::AstStatReturn*> returns;

    bool visit(Luau::AstStatReturn* node) override
    {
        returns.push_back(node);
        return false;
    }

    bool visit(Luau::AstExprFunction*) override
    {
        return false;
    }
};

std::optional<std::string> buildStructuralLuraphTraceProbe(
    std::string_view source,
    uint64_t fullTraceStart = 0,
    uint64_t fullTraceEnd = 0,
    std::string* failureReason = nullptr,
    bool structureDump = false,
    bool dynamicEvidence = false)
{
    const auto fail = [&](std::string_view reason) -> std::optional<std::string> {
        if (failureReason)
            *failureReason = reason;
        return std::nullopt;
    };
    if (failureReason)
        failureReason->clear();
    auto parsed = parseSource(source);
    if (!parsed->result.errors.empty())
        return fail("source_parse_failed");
    LuraphLoopShapeCollector collector;
    parsed->result.root->visit(&collector);
    auto shape = std::max_element(collector.shapes.begin(), collector.shapes.end(), [](const LuraphLoopShape& left, const LuraphLoopShape& right) {
        return left.conditionals < right.conditionals;
    });
    if (shape == collector.shapes.end() || shape->conditionals < 40 || !shape->pc || !shape->opcode_table || !shape->opcode ||
        !shape->pc->name.value || !shape->opcode->name.value)
        return fail("interpreter_loop_not_found");

    SourceView view(source);
    LuraphOpcodeDispatcherCollector dispatcherCollector(shape->opcode);
    shape->body->visit(&dispatcherCollector);
    auto dispatcherCandidate = std::max_element(
        dispatcherCollector.candidates.begin(), dispatcherCollector.candidates.end(),
        [](const auto& left, const auto& right) { return left.conditionals < right.conditionals; });
    Luau::AstStatIf* opcodeDispatcher = dispatcherCandidate != dispatcherCollector.candidates.end() &&
        dispatcherCandidate->conditionals >= 40 ? dispatcherCandidate->node : nullptr;
    std::map<Luau::AstLocal*, double> provenGuardBindings;
    std::vector<LuraphGuardCondition> dynamicGuardConditions;
    std::vector<std::string> guardNames;
    if (opcodeDispatcher)
    {
        provenGuardBindings = proveLuraphGuardBindings(
            parsed->result.root, opcodeDispatcher, shape->opcode, view);
        LuraphGuardConditionCollector conditionCollector(shape->opcode, provenGuardBindings);
        opcodeDispatcher->visit(&conditionCollector);
        dynamicGuardConditions = std::move(conditionCollector.conditions);

        LuraphGuardBindingCollector guardCollector(shape->opcode);
        opcodeDispatcher->visit(&guardCollector);
        std::map<Luau::AstLocal*, size_t> guardScores;
        for (const auto& [binding, score] : guardCollector.scores)
            guardScores[binding.first] += score;
        std::vector<std::pair<Luau::AstLocal*, size_t>> rankedGuards(
            guardScores.begin(), guardScores.end());
        std::sort(rankedGuards.begin(), rankedGuards.end(), [](const auto& left, const auto& right) {
            if (left.second != right.second)
                return left.second > right.second;
            const std::string_view leftName = left.first && left.first->name.value
                ? std::string_view(left.first->name.value) : std::string_view{};
            const std::string_view rightName = right.first && right.first->name.value
                ? std::string_view(right.first->name.value) : std::string_view{};
            return leftName < rightName;
        });
        const size_t dispatcherBegin = view.offset(opcodeDispatcher->location.begin);
        for (const auto& [local, score] : rankedGuards)
        {
            (void)score;
            if (!local || !local->name.value || view.offset(local->location.begin) >= dispatcherBegin)
                continue;
            const std::string name(local->name.value);
            if (name.empty() || std::find(guardNames.begin(), guardNames.end(), name) != guardNames.end())
                continue;
            guardNames.push_back(name);
            if (guardNames.size() >= 8)
                break;
        }
    }
    FunctionCollector functions;
    parsed->result.root->visit(&functions);
    Luau::AstExprFunction* function = nullptr;
    size_t functionSpan = std::numeric_limits<size_t>::max();
    const size_t loopBegin = view.offset(shape->loop->location.begin);
    const size_t loopEnd = view.offset(shape->loop->location.end);
    for (Luau::AstExprFunction* candidate : functions.functions)
    {
        if (!candidate->vararg || candidate->body->body.size == 0)
            continue;
        const size_t begin = view.offset(candidate->location.begin);
        const size_t end = view.offset(candidate->location.end);
        if (begin > loopBegin || end < loopEnd)
            continue;
        const size_t span = end - begin;
        if (span < functionSpan)
        {
            function = candidate;
            functionSpan = span;
        }
    }
    if (!function)
        return fail("vararg_interpreter_function_not_found");
    LuraphRegisterRoleCollector roles(shape->pc);
    shape->body->visit(&roles);
    auto registerRole = std::max_element(roles.register_scores.begin(), roles.register_scores.end(), [](const auto& left, const auto& right) {
        return left.second < right.second;
    });
    if (registerRole == roles.register_scores.end() || registerRole->second < 4 || !registerRole->first->name.value)
        return fail("register_table_role_not_proven");

    std::set<Luau::AstLocal*> semanticLanes = roles.pc_indexed_tables;
    semanticLanes.erase(shape->opcode_table);
    semanticLanes.erase(registerRole->first);
    LuraphUpvalueRoleCollector upvalueRoles(registerRole->first, shape->pc, semanticLanes);
    shape->body->visit(&upvalueRoles);
    auto upvalueRole = std::max_element(upvalueRoles.scores.begin(), upvalueRoles.scores.end(), [](const auto& left, const auto& right) {
        return left.second < right.second;
    });
    Luau::AstLocal* upvalues = upvalueRole == upvalueRoles.scores.end() || upvalueRole->second < 2
        ? nullptr : upvalueRole->first;

    std::vector<std::string> laneNames;
    for (Luau::AstLocal* lane : semanticLanes)
    {
        if (lane && lane->name.value)
            laneNames.emplace_back(lane->name.value);
    }
    std::sort(laneNames.begin(), laneNames.end());
    laneNames.erase(std::unique(laneNames.begin(), laneNames.end()), laneNames.end());
    if (laneNames.empty())
        return fail("operand_lanes_not_found");

    const std::string pcName(shape->pc->name.value);
    const std::string opcodeName(shape->opcode->name.value);
    const std::string opcodeTableName(shape->opcode_table->name.value);
    const std::string registersName(registerRole->first->name.value);
    const bool fullTraceEnabled = fullTraceStart > 0 && fullTraceEnd >= fullTraceStart;
    std::string instrumentation =
        "_G.__vmc=(_G.__vmc or 0)+1;_G.__curAid=__aid;_G.__curPc=" + pcName + ";_G.__curOp=" + opcodeName + ";";
    if (structureDump)
    {
        std::string laneCsv;
        for (size_t index = 0; index < laneNames.size(); ++index)
        {
            if (index > 0)
                laneCsv += ',';
            laneCsv += laneNames[index];
        }
        instrumentation += "local __alex_lph_seen=_G.__alex_lph_proto_seen;if type(__alex_lph_seen)~=\"table\" then __alex_lph_seen=setmetatable({},{__mode=\"k\"});_G.__alex_lph_proto_seen=__alex_lph_seen;end;";
        instrumentation += "if type(" + opcodeTableName + ")==\"table\" then local __alex_lph_pid=__alex_lph_seen[" + opcodeTableName + "];if __alex_lph_pid==nil then ";
        instrumentation += "_G.__alex_lph_proto_count=(_G.__alex_lph_proto_count or 0)+1;__alex_lph_pid=_G.__alex_lph_proto_count;__alex_lph_seen[" + opcodeTableName + "]=__alex_lph_pid;";
        instrumentation += R"LURAPH_DESC(local __alex_lph_object_ids=_G.__alex_lph_object_ids;if type(__alex_lph_object_ids)~="table" then __alex_lph_object_ids=setmetatable({},{__mode="k"});_G.__alex_lph_object_ids=__alex_lph_object_ids;end;local function __alex_lph_object_id(__alex_lph_object)local __alex_lph_id=__alex_lph_object_ids[__alex_lph_object];if __alex_lph_id==nil then _G.__alex_lph_object_count=(_G.__alex_lph_object_count or 0)+1;__alex_lph_id=_G.__alex_lph_object_count;__alex_lph_object_ids[__alex_lph_object]=__alex_lph_id;end;return __alex_lph_id;end;local function __alex_lph_encode_nested(__alex_lph_value)local __alex_lph_kind=type(__alex_lph_value);if __alex_lph_kind=="string" then local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_value do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_value,__alex_lph_byte));end;return "s:"..table.concat(__alex_lph_bytes);elseif __alex_lph_kind=="number" then return "n:"..tostring(__alex_lph_value);elseif __alex_lph_kind=="boolean" then return __alex_lph_value and "b:1" or "b:0";elseif __alex_lph_kind=="nil" then return "z:";elseif __alex_lph_kind=="table" then return "t:"..tostring(__alex_lph_object_id(__alex_lph_value));elseif __alex_lph_kind=="function" then local __alex_lph_name=debug.info(__alex_lph_value,"n") or "";local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_name do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_name,__alex_lph_byte));end;return "f:"..tostring(__alex_lph_object_id(__alex_lph_value))..":"..table.concat(__alex_lph_bytes);else return "x:"..__alex_lph_kind;end;end;local function __alex_lph_dump_nested(__alex_lph_root,__alex_lph_path,__alex_lph_depth,__alex_lph_nested_seen,__alex_lph_budget,__alex_lph_ip,__alex_lph_lane)if __alex_lph_depth>4 or __alex_lph_nested_seen[__alex_lph_root] or __alex_lph_budget[1]>=1024 then return;end;__alex_lph_nested_seen[__alex_lph_root]=true;local __alex_lph_items=0;for __alex_lph_key,__alex_lph_child in next,__alex_lph_root do __alex_lph_items+=1;__alex_lph_budget[1]+=1;if __alex_lph_items>256 or __alex_lph_budget[1]>1024 then break;end;local __alex_lph_key_encoded=__alex_lph_encode_nested(__alex_lph_key);local __alex_lph_child_encoded=__alex_lph_encode_nested(__alex_lph_child);print("@@LPH_LANE_TABLE_V1@@",__alex_lph_pid,__alex_lph_ip,__alex_lph_lane,__alex_lph_depth,__alex_lph_path,__alex_lph_key_encoded,__alex_lph_child_encoded);if type(__alex_lph_child)=="table" then __alex_lph_dump_nested(__alex_lph_child,__alex_lph_path.."/"..__alex_lph_key_encoded,__alex_lph_depth+1,__alex_lph_nested_seen,__alex_lph_budget,__alex_lph_ip,__alex_lph_lane);end;end;end;)LURAPH_DESC";
        instrumentation += "local __alex_lph_max=0;for __alex_lph_key in " + opcodeTableName + " do if type(__alex_lph_key)==\"number\" and __alex_lph_key%1==0 and __alex_lph_key>__alex_lph_max and __alex_lph_key<=200000 then __alex_lph_max=__alex_lph_key;end;end;";
        instrumentation += "print(\"@@LPH_PROTO_V1@@\",__alex_lph_pid,__alex_lph_max," + quoteLuau(laneCsv) + ");print(\"@@LPH_PROTO_OBJECT_V1@@\",__alex_lph_pid,__alex_lph_object_id(" + opcodeTableName + "));";
        instrumentation += "for __alex_lph_ip=1,__alex_lph_max do local __alex_lph_parts={};";
        for (const std::string& lane : laneNames)
        {
            instrumentation += "do local __alex_lph_value=type(" + lane + ")==\"table\" and rawget(" + lane + ",__alex_lph_ip) or nil;local __alex_lph_kind=type(__alex_lph_value);local __alex_lph_encoded;";
            instrumentation += R"LURAPH_STRUCT(if __alex_lph_kind=="string" then local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_value do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_value,__alex_lph_byte));end;__alex_lph_encoded="s:"..table.concat(__alex_lph_bytes);elseif __alex_lph_kind=="number" then __alex_lph_encoded="n:"..tostring(__alex_lph_value);elseif __alex_lph_kind=="boolean" then __alex_lph_encoded=__alex_lph_value and "b:1" or "b:0";elseif __alex_lph_kind=="nil" then __alex_lph_encoded="z:";else __alex_lph_encoded="x:"..__alex_lph_kind;end;)LURAPH_STRUCT";
            instrumentation += "if __alex_lph_kind==\"table\" then local __alex_lph_captures=rawget(__alex_lph_value,5);local __alex_lph_target=rawget(__alex_lph_value,9);if type(__alex_lph_captures)==\"table\" and type(__alex_lph_target)==\"table\" then for __alex_lph_top_key,__alex_lph_top_value in next,__alex_lph_value do print(\"@@LPH_LANE_TOP_V1@@\",__alex_lph_pid,__alex_lph_ip," + quoteLuau(lane) + ",__alex_lph_encode_nested(__alex_lph_top_key),__alex_lph_encode_nested(__alex_lph_top_value));end;__alex_lph_dump_nested(__alex_lph_captures,\"/n:5\",1,{}, {0},__alex_lph_ip," + quoteLuau(lane) + ");end;end;";
            instrumentation += "__alex_lph_parts[#__alex_lph_parts+1]=" + quoteLuau(lane + "=") + "..__alex_lph_encoded;end;";
        }
        instrumentation += "local __alex_lph_runtime_opcode=rawget(" + opcodeTableName + ",__alex_lph_ip);print(\"@@LPH_INSN_V1@@\",__alex_lph_pid,__alex_lph_ip,__alex_lph_runtime_opcode,table.concat(__alex_lph_parts,\"|\"));end;end;";
        instrumentation += "if " + pcName + "==1 then local __alex_lph_argument_object_ids=_G.__alex_lph_object_ids;if type(__alex_lph_argument_object_ids)==\"table\" then for __alex_lph_argument_index=1,math.min(__argCount,4) do local __alex_lph_argument_value=rawget(__alex_lph_args,__alex_lph_argument_index);if type(__alex_lph_argument_value)==\"table\" then local __alex_lph_argument_object_id=__alex_lph_argument_object_ids[__alex_lph_argument_value];if __alex_lph_argument_object_id==nil then _G.__alex_lph_object_count=(_G.__alex_lph_object_count or 0)+1;__alex_lph_argument_object_id=_G.__alex_lph_object_count;__alex_lph_argument_object_ids[__alex_lph_argument_value]=__alex_lph_argument_object_id;end;print(\"@@LPH_ACT_ARG_OBJECT_V1@@\",__aid,__alex_lph_pid,__alex_lph_argument_index,__alex_lph_argument_object_id);end;end;end;end;";
        if (dynamicEvidence && fullTraceEnabled)
        {
            instrumentation += "if _G.__vmc>=" + std::to_string(fullTraceStart) +
                " and _G.__vmc<=" + std::to_string(fullTraceEnd) +
                " and not __alex_lph_structure_announced then local __alex_lph_activation_args={};";
            instrumentation += R"LURAPH_ARGS(local function __alex_lph_hex(__alex_lph_text)local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_text do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_text,__alex_lph_byte));end;return table.concat(__alex_lph_bytes);end;local __alex_lph_reference_paths=_G.__alex_lph_reference_paths;if type(__alex_lph_reference_paths)~="table" then __alex_lph_reference_paths=setmetatable({},{__mode="k"});local __alex_lph_environment=(getfenv and getfenv(0)) or _ENV;local __alex_lph_roots={"_G","string","table","coroutine","task","debug","bit32","utf8","buffer","math","os","game","workspace","script","Enum","Instance","Vector2","Vector3","CFrame","Color3","UDim","UDim2","Rect","Ray","Region3","Random","DateTime","TweenInfo","BrickColor","NumberRange","NumberSequence","ColorSequence","PhysicalProperties","RaycastParams","OverlapParams"};for _,__alex_lph_root_name in ipairs(__alex_lph_roots) do local __alex_lph_root=rawget(__alex_lph_environment,__alex_lph_root_name);local __alex_lph_root_kind=type(__alex_lph_root);if __alex_lph_root~=nil and (__alex_lph_root_kind=="table" or __alex_lph_root_kind=="function" or __alex_lph_root_kind=="userdata") then __alex_lph_reference_paths[__alex_lph_root]=__alex_lph_root_name;if __alex_lph_root_kind=="table" then local __alex_lph_member_count=0;for __alex_lph_member_name,__alex_lph_member in next,__alex_lph_root do __alex_lph_member_count+=1;if __alex_lph_member_count>512 then break;end;local __alex_lph_member_kind=type(__alex_lph_member);if type(__alex_lph_member_name)=="string" and string.match(__alex_lph_member_name,"^[%a_][%w_]*$") and (__alex_lph_member_kind=="table" or __alex_lph_member_kind=="function" or __alex_lph_member_kind=="userdata") and __alex_lph_reference_paths[__alex_lph_member]==nil then __alex_lph_reference_paths[__alex_lph_member]=__alex_lph_root_name.."."..__alex_lph_member_name;end;end;end;end;end;_G.__alex_lph_reference_paths=__alex_lph_reference_paths;end;local function __alex_lph_encode_activation_arg(__alex_lph_value)local __alex_lph_kind=type(__alex_lph_value);if __alex_lph_kind=="string" then return "s:"..__alex_lph_hex(__alex_lph_value);elseif __alex_lph_kind=="number" then return "n:"..tostring(__alex_lph_value);elseif __alex_lph_kind=="boolean" then return __alex_lph_value and "b:1" or "b:0";elseif __alex_lph_kind=="nil" then return "z:";else local __alex_lph_reference=__alex_lph_reference_paths[__alex_lph_value];if __alex_lph_reference~=nil then return "g:"..__alex_lph_hex(__alex_lph_reference);elseif __alex_lph_kind=="function" then local __alex_lph_name=debug.info(__alex_lph_value,"n") or "";return "f:"..__alex_lph_hex(__alex_lph_name);else return "x:"..__alex_lph_kind;end;end;end;for __alex_lph_arg_index=1,math.min(__argCount,16) do __alex_lph_activation_args[__alex_lph_arg_index]=__alex_lph_encode_activation_arg(rawget(__alex_lph_args,__alex_lph_arg_index));end;)LURAPH_ARGS";
            instrumentation += "_G.__alex_lph_activation_rows=(_G.__alex_lph_activation_rows or 0)+1;if _G.__alex_lph_activation_rows<=" + std::to_string(kLuraphActivationTraceRowLimit) + " then print(\"@@LPH_ACT_PROTO_V1@@\",__aid,__alex_lph_pid,__callerAid,__callerPc,__callerOp,__argCount," + pcName + ",table.concat(__alex_lph_activation_args,\"|\"),_G.__vmc);elseif _G.__alex_lph_activation_rows==" + std::to_string(kLuraphActivationTraceRowLimit + 1) + " then print(\"@@LPH_ACT_PROTO_LIMIT_V1@@\"," + std::to_string(kLuraphActivationTraceRowLimit) + ",_G.__vmc);end;";
            if (upvalues && upvalues->name.value)
            {
                instrumentation += "do local __alex_lph_capture_seen=_G.__alex_lph_capture_domain_seen;if type(__alex_lph_capture_seen)~=\"table\" then __alex_lph_capture_seen={};_G.__alex_lph_capture_domain_seen=__alex_lph_capture_seen;end;if not __alex_lph_capture_seen[__alex_lph_pid] then __alex_lph_capture_seen[__alex_lph_pid]=true;local __alex_lph_capture_keys={};local __alex_lph_capture_complete=true;if type(" +
                    std::string(upvalues->name.value) + ")==\"table\" then for __alex_lph_capture_key in next," +
                    std::string(upvalues->name.value) + " do if type(__alex_lph_capture_key)==\"number\" and __alex_lph_capture_key%1==0 and __alex_lph_capture_key>=0 and __alex_lph_capture_key<=200000 then __alex_lph_capture_keys[#__alex_lph_capture_keys+1]=__alex_lph_capture_key;if #__alex_lph_capture_keys>256 then __alex_lph_capture_complete=false;break;end;else __alex_lph_capture_complete=false;end;end;else __alex_lph_capture_complete=false;end;table.sort(__alex_lph_capture_keys);print(\"@@LPH_CAPTURE_DOMAIN_V1@@\",__aid,__alex_lph_pid,__alex_lph_capture_complete and 1 or 0,#__alex_lph_capture_keys,table.concat(__alex_lph_capture_keys,\",\"));for _,__alex_lph_capture_key in ipairs(__alex_lph_capture_keys) do local __alex_lph_capture_cell=rawget(" +
                    std::string(upvalues->name.value) + ",__alex_lph_capture_key);local __alex_lph_capture_value=__alex_lph_capture_cell;local __alex_lph_capture_slot=nil;if type(__alex_lph_capture_cell)==\"table\" then __alex_lph_capture_slot=rawget(__alex_lph_capture_cell,2);local __alex_lph_capture_storage=rawget(__alex_lph_capture_cell,3);if type(__alex_lph_capture_slot)==\"number\" and type(__alex_lph_capture_storage)==\"table\" then __alex_lph_capture_value=rawget(__alex_lph_capture_storage,__alex_lph_capture_slot);end;end;print(\"@@LPH_CAPTURE_VALUE_V1@@\",__aid,__alex_lph_pid,__alex_lph_capture_key,__alex_lph_encode_activation_arg(__alex_lph_capture_cell),__alex_lph_encode_activation_arg(__alex_lph_capture_value),__alex_lph_capture_slot);end;end;end;";
            }
            instrumentation += "local __alex_lph_arg_table_seen=_G.__alex_lph_arg_table_seen;if type(__alex_lph_arg_table_seen)~=\"table\" then __alex_lph_arg_table_seen={};_G.__alex_lph_arg_table_seen=__alex_lph_arg_table_seen;end;if not __alex_lph_arg_table_seen[__alex_lph_pid] then __alex_lph_arg_table_seen[__alex_lph_pid]=true;for __alex_lph_arg_index=1,math.min(__argCount,4) do local __alex_lph_arg_value=rawget(__alex_lph_args,__alex_lph_arg_index);if type(__alex_lph_arg_value)==\"table\" then local __alex_lph_entry_count=0;local __alex_lph_arg_table_complete=true;for __alex_lph_key,__alex_lph_value in next,__alex_lph_arg_value do if __alex_lph_entry_count>=" +
                std::to_string(kLuraphActivationArgumentTableEntryLimit) +
                " then __alex_lph_arg_table_complete=false;break end;__alex_lph_entry_count+=1;print(\"@@LPH_ACT_ARG_TABLE_V1@@\",__aid,__alex_lph_pid,__alex_lph_arg_index,__alex_lph_encode_activation_arg(__alex_lph_key),__alex_lph_encode_activation_arg(__alex_lph_value));end;print(\"@@LPH_ACT_ARG_TABLE_END_V1@@\",__aid,__alex_lph_pid,__alex_lph_arg_index,__alex_lph_arg_table_complete and 1 or 0,__alex_lph_entry_count);end;end;end;__alex_lph_structure_announced=true;end;end;";
            instrumentation += "local __alex_lph_step_enabled=_G.__vmc>=" + std::to_string(fullTraceStart) + " and _G.__vmc<=" + std::to_string(fullTraceEnd) + ";";
            instrumentation += "local __alex_lph_pre_pc=" + pcName + ";local __alex_lph_pre_op=" + opcodeName + ";local __alex_lph_pre_regs={};local __alex_lph_pre_lanes={};local __alex_lph_pre_guards={};";
            instrumentation += R"LURAPH_OPERANDS(local function __alex_lph_encode_operand(__alex_lph_value)local __alex_lph_kind=type(__alex_lph_value);if __alex_lph_kind=="string" then local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_value do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_value,__alex_lph_byte));end;return "s:"..table.concat(__alex_lph_bytes);elseif __alex_lph_kind=="number" then return "n:"..tostring(__alex_lph_value);elseif __alex_lph_kind=="boolean" then return __alex_lph_value and "b:1" or "b:0";elseif __alex_lph_kind=="nil" then return "z:";elseif __alex_lph_kind=="function" then local __alex_lph_name=debug.info(__alex_lph_value,"n") or "";local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_name do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_name,__alex_lph_byte));end;return "f:"..table.concat(__alex_lph_bytes);else return "x:"..__alex_lph_kind;end;end;)LURAPH_OPERANDS";
            if (!dynamicGuardConditions.empty())
                instrumentation += R"LURAPH_GUARDS(local __alex_lph_guard_path={};local __alex_lph_guard_overflow=false;local function __alex_lph_guard_eval(__alex_lph_begin,__alex_lph_end,__alex_lph_value)if __alex_lph_step_enabled then if #__alex_lph_guard_path<4096 then __alex_lph_guard_path[#__alex_lph_guard_path+1]=tostring(__alex_lph_begin)..":"..tostring(__alex_lph_end)..":"..(__alex_lph_value and "1" or "0");else __alex_lph_guard_overflow=true;end;end;return __alex_lph_value;end;)LURAPH_GUARDS";
            for (const std::string& lane : laneNames)
            {
                instrumentation += "do local __alex_lph_operand=type(" + lane + ")==\"table\" and rawget(" + lane + ",__alex_lph_pre_pc) or nil;";
                instrumentation += "__alex_lph_pre_lanes[#__alex_lph_pre_lanes+1]=" + quoteLuau(lane + "=") + "..__alex_lph_encode_operand(__alex_lph_operand);end;";
            }
            instrumentation += "if __alex_lph_step_enabled and type(" + registersName + ")==\"table\" then for __alex_lph_key,__alex_lph_value in " + registersName + " do ";
            instrumentation += "if type(__alex_lph_key)==\"number\" and __alex_lph_key%1==0 and __alex_lph_key>=-200000 and __alex_lph_key<=200000 then __alex_lph_pre_regs[__alex_lph_key]=__alex_lph_value;end;end;end;";
        }
        else
            instrumentation += "end;";
    }

    if (!structureDump && dynamicEvidence && fullTraceEnabled)
    {
        instrumentation += "local __alex_lph_seen=_G.__alex_lph_proto_seen;if type(__alex_lph_seen)~=\"table\" then __alex_lph_seen=setmetatable({},{__mode=\"k\"});_G.__alex_lph_proto_seen=__alex_lph_seen;end;";
        instrumentation += "if type(" + opcodeTableName + ")==\"table\" then local __alex_lph_pid=__alex_lph_seen[" + opcodeTableName + "];if __alex_lph_pid==nil then _G.__alex_lph_proto_count=(_G.__alex_lph_proto_count or 0)+1;__alex_lph_pid=_G.__alex_lph_proto_count;__alex_lph_seen[" + opcodeTableName + "]=__alex_lph_pid;end;";
        instrumentation += "if _G.__vmc>=" + std::to_string(fullTraceStart) +
            " and _G.__vmc<=" + std::to_string(fullTraceEnd) +
            " and not __alex_lph_structure_announced then local __alex_lph_activation_args={};";
        instrumentation += R"LURAPH_ARGS(local function __alex_lph_hex(__alex_lph_text)local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_text do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_text,__alex_lph_byte));end;return table.concat(__alex_lph_bytes);end;local function __alex_lph_encode_activation_arg(__alex_lph_value)local __alex_lph_kind=type(__alex_lph_value);if __alex_lph_kind=="string" then return "s:"..__alex_lph_hex(__alex_lph_value);elseif __alex_lph_kind=="number" then return "n:"..tostring(__alex_lph_value);elseif __alex_lph_kind=="boolean" then return __alex_lph_value and "b:1" or "b:0";elseif __alex_lph_kind=="nil" then return "z:";elseif __alex_lph_kind=="function" then local __alex_lph_name=debug.info(__alex_lph_value,"n") or "";return "f:"..__alex_lph_hex(__alex_lph_name);else return "x:"..__alex_lph_kind;end;end;for __alex_lph_arg_index=1,math.min(__argCount,16) do __alex_lph_activation_args[__alex_lph_arg_index]=__alex_lph_encode_activation_arg(rawget(__alex_lph_args,__alex_lph_arg_index));end;)LURAPH_ARGS";
        instrumentation += "_G.__alex_lph_activation_rows=(_G.__alex_lph_activation_rows or 0)+1;if _G.__alex_lph_activation_rows<=" + std::to_string(kLuraphActivationTraceRowLimit) + " then print(\"@@LPH_ACT_PROTO_V1@@\",__aid,__alex_lph_pid,__callerAid,__callerPc,__callerOp,__argCount," + pcName + ",table.concat(__alex_lph_activation_args,\"|\"),_G.__vmc);elseif _G.__alex_lph_activation_rows==" + std::to_string(kLuraphActivationTraceRowLimit + 1) + " then print(\"@@LPH_ACT_PROTO_LIMIT_V1@@\"," + std::to_string(kLuraphActivationTraceRowLimit) + ",_G.__vmc);end;__alex_lph_structure_announced=true;end;end;";
        instrumentation += "local __alex_lph_step_enabled=_G.__vmc>=" + std::to_string(fullTraceStart) + " and _G.__vmc<=" + std::to_string(fullTraceEnd) + ";";
        instrumentation += "local __alex_lph_pre_pc=" + pcName + ";local __alex_lph_pre_op=" + opcodeName + ";local __alex_lph_pre_regs={};local __alex_lph_pre_lanes={};local __alex_lph_pre_guards={};";
        instrumentation += R"LURAPH_OPERANDS(local function __alex_lph_encode_operand(__alex_lph_value)local __alex_lph_kind=type(__alex_lph_value);if __alex_lph_kind=="string" then local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_value do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_value,__alex_lph_byte));end;return "s:"..table.concat(__alex_lph_bytes);elseif __alex_lph_kind=="number" then return "n:"..tostring(__alex_lph_value);elseif __alex_lph_kind=="boolean" then return __alex_lph_value and "b:1" or "b:0";elseif __alex_lph_kind=="nil" then return "z:";elseif __alex_lph_kind=="function" then local __alex_lph_name=debug.info(__alex_lph_value,"n") or "";local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_name do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_name,__alex_lph_byte));end;return "f:"..table.concat(__alex_lph_bytes);else return "x:"..__alex_lph_kind;end;end;)LURAPH_OPERANDS";
        if (!dynamicGuardConditions.empty())
            instrumentation += R"LURAPH_GUARDS(local __alex_lph_guard_path={};local __alex_lph_guard_overflow=false;local function __alex_lph_guard_eval(__alex_lph_begin,__alex_lph_end,__alex_lph_value)if __alex_lph_step_enabled then if #__alex_lph_guard_path<4096 then __alex_lph_guard_path[#__alex_lph_guard_path+1]=tostring(__alex_lph_begin)..":"..tostring(__alex_lph_end)..":"..(__alex_lph_value and "1" or "0");else __alex_lph_guard_overflow=true;end;end;return __alex_lph_value;end;)LURAPH_GUARDS";
        for (const std::string& lane : laneNames)
        {
            instrumentation += "do local __alex_lph_operand=type(" + lane + ")==\"table\" and rawget(" + lane + ",__alex_lph_pre_pc) or nil;";
            instrumentation += "__alex_lph_pre_lanes[#__alex_lph_pre_lanes+1]=" + quoteLuau(lane + "=") + "..__alex_lph_encode_operand(__alex_lph_operand);end;";
        }
        instrumentation += "if __alex_lph_step_enabled and type(" + registersName + ")==\"table\" then for __alex_lph_key,__alex_lph_value in " + registersName + " do ";
        instrumentation += "if type(__alex_lph_key)==\"number\" and __alex_lph_key%1==0 and __alex_lph_key>=-200000 and __alex_lph_key<=200000 then __alex_lph_pre_regs[__alex_lph_key]=__alex_lph_value;end;end;end;";
    }

    // Pure structure probes only need each prototype once. Call discovery is retained
    // for call-focused probes and refined payload windows, where activation evidence is
    // joined to the VM counter from the same execution.
    if (!structureDump || fullTraceEnabled)
    {
        instrumentation += "local __alex_lph_target=nil;local __alex_lph_index=nil;local __alex_lph_lane=nil;";
        for (const std::string& lane : laneNames)
        {
            instrumentation += "if __alex_lph_target==nil and type(" + registersName + ")==\"table\" and type(" + lane + ")==\"table\" then ";
            instrumentation += "local __alex_lph_candidate_index=rawget(" + lane + "," + pcName + ");";
            instrumentation += "local __alex_lph_candidate=type(__alex_lph_candidate_index)==\"number\" and rawget(" + registersName + ",__alex_lph_candidate_index) or nil;";
            instrumentation += "if type(__alex_lph_candidate)==\"function\" then local __alex_lph_name=debug.info(__alex_lph_candidate,\"n\");";
            instrumentation += "if __alex_lph_name==\"print\" or __alex_lph_name==\"warn\" or __alex_lph_name==\"error\" then ";
            instrumentation += "__alex_lph_target=__alex_lph_name;__alex_lph_index=__alex_lph_candidate_index;__alex_lph_lane=" + quoteLuau(lane) + ";end;end;end;";
        }
        instrumentation += "if __alex_lph_target~=nil then local __alex_lph_parts={};for __alex_lph_argi=1,8 do ";
        instrumentation += "local __alex_lph_arg=rawget(" + registersName + ",__alex_lph_index+__alex_lph_argi);if __alex_lph_arg==nil then break end;";
        instrumentation += R"LURAPH_TRACE(local __alex_lph_kind=type(__alex_lph_arg);local __alex_lph_encoded;if __alex_lph_kind=="string" then local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_arg do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_arg,__alex_lph_byte));end;__alex_lph_encoded="s:"..table.concat(__alex_lph_bytes);elseif __alex_lph_kind=="number" then __alex_lph_encoded="n:"..tostring(__alex_lph_arg);elseif __alex_lph_kind=="boolean" then __alex_lph_encoded=__alex_lph_arg and "b:1" or "b:0";else __alex_lph_encoded="x:"..__alex_lph_kind;end;__alex_lph_parts[#__alex_lph_parts+1]=__alex_lph_encoded;end;print("@@LPH_CALL_V2@@",_G.__vmc,__aid,__callerAid,__callerPc,__callerOp,)LURAPH_TRACE";
        instrumentation += pcName + "," + opcodeName + ",__alex_lph_index,__alex_lph_target,#__alex_lph_parts,table.concat(__alex_lph_parts,\"|\"),__alex_lph_lane);end;";
    }
    if (fullTraceEnabled)
    {
        instrumentation += "if _G.__vmc>=" + std::to_string(fullTraceStart) + " and _G.__vmc<=" + std::to_string(fullTraceEnd) + " then ";
        instrumentation += "print(\"@@LPH_VM@@\",_G.__vmc,__aid,__callerAid,__callerPc,__callerOp," + pcName + "," + opcodeName + ");";
        instrumentation += "if " + pcName + "==1 then print(\"@@LPH_ACTIVATION@@\",_G.__vmc,__aid,__callerAid,__callerPc,__callerOp,__argCount);end;end;";
    }

    size_t functionBodyOffset = view.offset(function->body->location.begin);
    size_t fetchEnd = view.offset(shape->fetch->location.end);
    const size_t dispatcherBodyBegin = view.offset(shape->body->location.begin);
    const size_t dispatcherBodyEnd = view.offset(shape->body->location.end);
    while (fetchEnd < source.size() && (source[fetchEnd] == ' ' || source[fetchEnd] == '\t'))
        ++fetchEnd;
    if (fetchEnd < source.size() && source[fetchEnd] == ';')
        ++fetchEnd;
    if (functionBodyOffset >= fetchEnd || fetchEnd > source.size())
        return fail("injection_offsets_invalid");

    struct ProbeInsertion
    {
        size_t offset = 0;
        size_t priority = 0;
        std::string text;
    };
    std::vector<ProbeInsertion> insertions;
    if (dynamicEvidence && fullTraceEnabled)
    {
        if (dispatcherBodyEnd < fetchEnd || dispatcherBodyEnd > source.size())
            return fail("post_injection_offset_invalid");
        std::string postInstrumentation = " if __alex_lph_step_enabled then ";
        postInstrumentation += "local __alex_lph_writes={};local __alex_lph_origins={};local __alex_lph_seen_keys={};";
        postInstrumentation += "local function __alex_lph_encode_value(__alex_lph_value)local __alex_lph_kind=type(__alex_lph_value);";
        postInstrumentation += R"LURAPH_STEP(if __alex_lph_kind=="string" then local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_value do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_value,__alex_lph_byte));end;return "s:"..table.concat(__alex_lph_bytes);elseif __alex_lph_kind=="number" then return "n:"..tostring(__alex_lph_value);elseif __alex_lph_kind=="boolean" then return __alex_lph_value and "b:1" or "b:0";elseif __alex_lph_kind=="nil" then return "z:";elseif __alex_lph_kind=="function" then local __alex_lph_name=debug.info(__alex_lph_value,"n") or "";local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_name do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_name,__alex_lph_byte));end;return "f:"..table.concat(__alex_lph_bytes);else return "x:"..__alex_lph_kind;end;end;)LURAPH_STEP";
        postInstrumentation += "if type(" + registersName + ")==\"table\" then for __alex_lph_key,__alex_lph_value in " + registersName + " do ";
        postInstrumentation += "if type(__alex_lph_key)==\"number\" and __alex_lph_key%1==0 and __alex_lph_key>=-200000 and __alex_lph_key<=200000 then __alex_lph_seen_keys[__alex_lph_key]=true;";
        postInstrumentation += "if not rawequal(rawget(__alex_lph_pre_regs,__alex_lph_key),__alex_lph_value) then __alex_lph_writes[#__alex_lph_writes+1]=tostring(__alex_lph_key)..\"=\"..__alex_lph_encode_value(__alex_lph_value);local __alex_lph_matches={};if __alex_lph_value~=nil then for __alex_lph_source,__alex_lph_source_value in __alex_lph_pre_regs do if __alex_lph_source~=__alex_lph_key and rawequal(__alex_lph_source_value,__alex_lph_value) then __alex_lph_matches[#__alex_lph_matches+1]=\"r:\"..tostring(__alex_lph_source);if #__alex_lph_matches>=2 then break;end;end;end;if #__alex_lph_matches<2 then for __alex_lph_argument=1,__argCount do if rawequal(rawget(__alex_lph_args,__alex_lph_argument),__alex_lph_value) then __alex_lph_matches[#__alex_lph_matches+1]=\"a:\"..tostring(__alex_lph_argument);if #__alex_lph_matches>=2 then break;end;end;end;end;end;if #__alex_lph_matches>0 then table.sort(__alex_lph_matches);__alex_lph_origins[#__alex_lph_origins+1]=tostring(__alex_lph_key)..\"=\"..table.concat(__alex_lph_matches,\",\");end;end;end;end;";
        postInstrumentation += "for __alex_lph_key,__alex_lph_value in __alex_lph_pre_regs do if not __alex_lph_seen_keys[__alex_lph_key] and rawget(" + registersName + ",__alex_lph_key)==nil then __alex_lph_writes[#__alex_lph_writes+1]=tostring(__alex_lph_key)..\"=z:\";end;end;end;";
        postInstrumentation += "table.sort(__alex_lph_writes);table.sort(__alex_lph_origins);";
        if (!guardNames.empty())
        {
            instrumentation += "if __alex_lph_step_enabled then ";
            for (const std::string& guard : guardNames)
                instrumentation += "__alex_lph_pre_guards[#__alex_lph_pre_guards+1]=" +
                    quoteLuau(guard + "=") + "..__alex_lph_encode_operand(" + guard + ");";
            instrumentation += "end;";
            postInstrumentation += "print(\"@@LPH_GUARD_V1@@\",_G.__vmc,__aid,__alex_lph_pre_pc,__alex_lph_pre_op,table.concat(__alex_lph_pre_guards,\"|\"));";
        }
        if (!dynamicGuardConditions.empty())
            postInstrumentation += "print(\"@@LPH_GUARD_PATH_V1@@\",_G.__vmc,__aid,__alex_lph_pre_pc,__alex_lph_pre_op,#__alex_lph_guard_path,__alex_lph_guard_overflow and 1 or 0,table.concat(__alex_lph_guard_path,\"|\"));";
        postInstrumentation += "print(\"@@LPH_STEP_V1@@\",_G.__vmc,__aid,__alex_lph_pre_pc,__alex_lph_pre_op," + pcName + ",#__alex_lph_writes,table.concat(__alex_lph_writes,\"|\"),table.concat(__alex_lph_pre_lanes,\"|\"),table.concat(__alex_lph_origins,\"|\"));end;";
        insertions.push_back({dispatcherBodyEnd, 0, std::move(postInstrumentation)});
        for (const LuraphGuardCondition& condition : dynamicGuardConditions)
        {
            const size_t begin = view.offset(condition.expression->location.begin);
            const size_t end = view.offset(condition.expression->location.end);
            if (begin >= end || begin < dispatcherBodyBegin || end > dispatcherBodyEnd || end > source.size())
                return fail("guard_condition_offset_invalid");
            insertions.push_back({end, 0, ")"});
            insertions.push_back({begin, 0,
                " __alex_lph_guard_eval(" + std::to_string(begin) + "," + std::to_string(end) + ","});
        }
    }
    insertions.push_back({fetchEnd, 0, std::move(instrumentation)});
    std::string activation = std::string(
        "local __callerAid,__callerPc,__callerOp=_G.__curAid,_G.__curPc,_G.__curOp;"
        "_G.__lph_a=(_G.__lph_a or 0)+1;local __aid=_G.__lph_a;local __argCount=select(\"#\",...);local __alex_lph_args={...};");
    if (dynamicEvidence && fullTraceEnabled)
    {
        std::string returnTracer = R"LURAPH_RETURN(do local function __alex_lph_encode_return(__alex_lph_value)local __alex_lph_kind=type(__alex_lph_value);if __alex_lph_kind=="string" then local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_value do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_value,__alex_lph_byte));end;return "s:"..table.concat(__alex_lph_bytes);elseif __alex_lph_kind=="number" then return "n:"..tostring(__alex_lph_value);elseif __alex_lph_kind=="boolean" then return __alex_lph_value and "b:1" or "b:0";elseif __alex_lph_kind=="nil" then return "z:";elseif __alex_lph_kind=="function" then local __alex_lph_name=debug.info(__alex_lph_value,"n") or "";local __alex_lph_bytes={};for __alex_lph_byte=1,#__alex_lph_name do __alex_lph_bytes[__alex_lph_byte]=string.format("%02x",string.byte(__alex_lph_name,__alex_lph_byte));end;return "f:"..table.concat(__alex_lph_bytes);else return "x:"..__alex_lph_kind;end;end;_G.__alex_lph_trace_return=function(__alex_lph_vm_count,__alex_lph_activation,__alex_lph_return_pc,__alex_lph_return_op,__alex_lph_caller_activation,__alex_lph_caller_pc,__alex_lph_caller_op,...)local __alex_lph_return_count=select("#",...);if __alex_lph_vm_count>=)LURAPH_RETURN";
        returnTracer += std::to_string(fullTraceStart);
        returnTracer += " and __alex_lph_vm_count<=" + std::to_string(fullTraceEnd);
        returnTracer += R"LURAPH_RETURN( then local __alex_lph_return_parts={};local __alex_lph_captured=math.min(__alex_lph_return_count,256);for __alex_lph_index=1,__alex_lph_captured do __alex_lph_return_parts[__alex_lph_index]=__alex_lph_encode_return(select(__alex_lph_index,...));end;print("@@LPH_RETURN_V1@@",__alex_lph_vm_count,__alex_lph_activation,__alex_lph_return_pc,__alex_lph_return_op,__alex_lph_return_count,__alex_lph_captured,table.concat(__alex_lph_return_parts,"|"));end;_G.__curAid,_G.__curPc,_G.__curOp=__alex_lph_caller_activation,__alex_lph_caller_pc,__alex_lph_caller_op;return ...;end;end;)LURAPH_RETURN";
        insertions.push_back({0, 0, std::move(returnTracer)});

        LuraphDirectReturnCollector returnCollector;
        shape->body->visit(&returnCollector);
        for (Luau::AstStatReturn* statement : returnCollector.returns)
        {
            const size_t returnBegin = view.offset(statement->location.begin);
            const size_t returnEnd = view.offset(statement->location.end);
            if (returnBegin < dispatcherBodyBegin || returnEnd > dispatcherBodyEnd)
                continue;
            if (returnEnd < returnBegin + 6 || returnEnd > source.size() ||
                source.substr(returnBegin, 6) != "return")
                return fail("return_instrumentation_offset_invalid");
            if (!dynamicGuardConditions.empty())
                insertions.push_back({returnBegin, 2,
                    "if __alex_lph_step_enabled then print(\"@@LPH_GUARD_PATH_V1@@\",_G.__vmc,__aid," +
                    pcName + "," + opcodeName + ",#__alex_lph_guard_path,__alex_lph_guard_overflow and 1 or 0,table.concat(__alex_lph_guard_path,\"|\")) end;"});
            if (statement->list.size == 0)
            {
                insertions.push_back({returnBegin + 6, 1,
                    " _G.__alex_lph_trace_return(_G.__vmc,__aid," + pcName + "," + opcodeName +
                    ",__callerAid,__callerPc,__callerOp)"});
            }
            else
            {
                const size_t expressionEnd = view.offset(statement->list.data[statement->list.size - 1]->location.end);
                if (expressionEnd <= returnBegin + 6 || expressionEnd > returnEnd)
                    return fail("return_expression_offset_invalid");
                insertions.push_back({expressionEnd, 0, ")"});
                insertions.push_back({returnBegin + 6, 1,
                    " _G.__alex_lph_trace_return(_G.__vmc,__aid," + pcName + "," + opcodeName +
                    ",__callerAid,__callerPc,__callerOp,"});
            }
        }
    }
    if (dynamicEvidence && fullTraceEnabled)
        activation += "local __alex_lph_structure_announced=false;";
    insertions.push_back({functionBodyOffset, 0, std::move(activation)});
    std::sort(insertions.begin(), insertions.end(), [](const ProbeInsertion& left, const ProbeInsertion& right) {
        if (left.offset != right.offset)
            return left.offset > right.offset;
        return left.priority < right.priority;
    });
    std::string probe(source);
    for (const ProbeInsertion& insertion : insertions)
        probe.insert(insertion.offset, insertion.text);
    return probe;
}

struct LuraphTraceCall
{
    uint64_t vm_count = 0;
    uint64_t activation = 0;
    std::optional<uint64_t> caller_activation;
    int64_t pc = 0;
    int64_t opcode = 0;
    std::optional<int64_t> register_index;
    std::string target;
    std::vector<LuraphTraceValue> arguments;
    bool output_confirmed = false;
};

struct LuraphVmEvent
{
    uint64_t vm_count = 0;
    uint64_t activation = 0;
    int64_t pc = 0;
    int64_t opcode = 0;
};

struct LuraphDynamicTrace
{
    size_t event_count = 0;
    size_t candidate_call_count = 0;
    size_t unresolved_call_count = 0;
    bool payload_activation_complete = false;
    std::optional<uint64_t> first_candidate_vm_count;
    std::optional<uint64_t> last_candidate_vm_count;
    std::vector<LuraphTraceCall> calls;
    std::vector<LuraphVmEvent> vm_events;
    std::set<uint64_t> activation_entries;
    std::vector<std::string> output_lines;
};

std::vector<std::string> splitTraceFields(std::string_view line)
{
    std::vector<std::string> fields;
    size_t begin = 0;
    while (begin <= line.size())
    {
        size_t end = line.find('\t', begin);
        if (end == std::string_view::npos)
            end = line.size();
        fields.emplace_back(line.substr(begin, end - begin));
        if (end == line.size())
            break;
        begin = end + 1;
    }
    return fields;
}

template<typename Integer>
std::optional<Integer> parseTraceInteger(std::string_view value)
{
    Integer result{};
    const char* begin = value.data();
    const char* end = begin + value.size();
    const auto parsed = std::from_chars(begin, end, result);
    if (parsed.ec != std::errc() || parsed.ptr != end)
        return std::nullopt;
    return result;
}

bool validTraceCallTarget(std::string_view value)
{
    if (value.empty() || !isIdentifierStart(value.front()))
        return false;
    if (!std::all_of(value.begin() + 1, value.end(), isIdentifier))
        return false;
    return value == "print" || value == "warn" || value == "error";
}

std::optional<std::string> luraphTraceValueSource(const LuraphTraceValue& value)
{
    if (value.type == "string")
        return quoteLuau(value.value);
    if (value.type == "number" && NumericParser(value.value).parse())
        return value.value;
    if (value.type == "boolean" && (value.value == "true" || value.value == "false"))
        return value.value;
    if (value.type == "nil")
        return std::string("nil");
    return std::nullopt;
}

std::optional<std::string> luraphTraceCallSource(const LuraphTraceCall& call)
{
    std::string result = call.target + "(";
    for (size_t index = 0; index < call.arguments.size(); ++index)
    {
        const std::optional<std::string> argument = luraphTraceValueSource(call.arguments[index]);
        if (!argument)
            return std::nullopt;
        if (index > 0)
            result += ", ";
        result += *argument;
    }
    result += ')';
    return result;
}

std::string luraphTraceRenderedArguments(const LuraphTraceCall& call)
{
    std::string result;
    for (size_t index = 0; index < call.arguments.size(); ++index)
    {
        if (index > 0)
            result += '\t';
        const LuraphTraceValue& value = call.arguments[index];
        result += value.type == "nil" ? "nil" : value.value;
    }
    return result;
}

std::optional<std::string> decodeTraceHex(std::string_view value)
{
    if (value.size() % 2 != 0)
        return std::nullopt;
    std::string decoded;
    decoded.reserve(value.size() / 2);
    const auto digit = [](char ch) -> int {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        return -1;
    };
    for (size_t index = 0; index < value.size(); index += 2)
    {
        const int high = digit(value[index]);
        const int low = digit(value[index + 1]);
        if (high < 0 || low < 0)
            return std::nullopt;
        decoded.push_back(static_cast<char>((high << 4) | low));
    }
    return decoded;
}

std::optional<LuraphTraceValue> parseLuraphTraceValue(std::string_view encoded)
{
    if (encoded.starts_with("s:"))
    {
        const std::optional<std::string> value = decodeTraceHex(encoded.substr(2));
        if (value)
            return LuraphTraceValue{"string", *value};
        return std::nullopt;
    }
    if (encoded.starts_with("n:"))
    {
        const std::string value(encoded.substr(2));
        if (NumericParser(value).parse())
            return LuraphTraceValue{"number", value};
        return std::nullopt;
    }
    if (encoded == "b:1")
        return LuraphTraceValue{"boolean", "true"};
    if (encoded == "b:0")
        return LuraphTraceValue{"boolean", "false"};
    if (encoded == "z:")
        return LuraphTraceValue{"nil", ""};
    return std::nullopt;
}

LuraphDynamicTrace parseLuraphDynamicTrace(const fs::path& path)
{
    LuraphDynamicTrace trace;
    std::istringstream input(readFile(path));
    std::string line;
    std::set<std::tuple<uint64_t, uint64_t, int64_t, std::string>> seenCalls;
    std::optional<size_t> pendingOutputCall;
    while (std::getline(input, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.starts_with("@@LPH_CALL_V2@@\t"))
        {
            ++trace.event_count;
            const std::vector<std::string> fields = splitTraceFields(line);
            if (fields.size() < 12 || !validTraceCallTarget(fields[9]))
                continue;
            const std::optional<uint64_t> vmCount = parseTraceInteger<uint64_t>(fields[1]);
            const std::optional<uint64_t> activation = parseTraceInteger<uint64_t>(fields[2]);
            const std::optional<int64_t> pc = parseTraceInteger<int64_t>(fields[6]);
            const std::optional<int64_t> opcode = parseTraceInteger<int64_t>(fields[7]);
            const std::optional<size_t> argumentCount = parseTraceInteger<size_t>(fields[10]);
            if (!vmCount || !activation || !pc || !opcode || !argumentCount || *argumentCount > 8)
                continue;

            LuraphTraceCall call;
            call.vm_count = *vmCount;
            call.activation = *activation;
            call.caller_activation = parseTraceInteger<uint64_t>(fields[3]);
            call.pc = *pc;
            call.opcode = *opcode;
            call.register_index = parseTraceInteger<int64_t>(fields[8]);
            call.target = fields[9];
            if (*argumentCount > 0)
            {
                size_t begin = 0;
                while (begin <= fields[11].size())
                {
                    const size_t end = fields[11].find('|', begin);
                    const std::string_view encoded(fields[11].data() + begin,
                        (end == std::string::npos ? fields[11].size() : end) - begin);
                    const std::optional<LuraphTraceValue> value = parseLuraphTraceValue(encoded);
                    if (!value)
                    {
                        call.arguments.clear();
                        break;
                    }
                    call.arguments.push_back(*value);
                    if (end == std::string::npos)
                        break;
                    begin = end + 1;
                }
            }
            if (call.arguments.size() != *argumentCount || !luraphTraceCallSource(call))
                continue;
            const auto fingerprint = std::make_tuple(call.vm_count, call.activation, call.pc, call.target);
            if (seenCalls.insert(fingerprint).second)
            {
                trace.calls.push_back(std::move(call));
                pendingOutputCall = trace.calls.size() - 1;
            }
            continue;
        }
        if (line.starts_with("@@LPH_VM@@\t"))
        {
            ++trace.event_count;
            const std::vector<std::string> fields = splitTraceFields(line);
            if (fields.size() < 8)
                continue;
            const std::optional<uint64_t> vmCount = parseTraceInteger<uint64_t>(fields[1]);
            const std::optional<uint64_t> activation = parseTraceInteger<uint64_t>(fields[2]);
            const std::optional<int64_t> pc = parseTraceInteger<int64_t>(fields[6]);
            const std::optional<int64_t> opcode = parseTraceInteger<int64_t>(fields[7]);
            if (!vmCount || !activation || !pc || !opcode)
                continue;
            trace.vm_events.push_back({*vmCount, *activation, *pc, *opcode});
            if (fields.size() < 26 || fields[9] != "function" || !validTraceCallTarget(fields[11]))
                continue;

            LuraphTraceCall call;
            call.vm_count = *vmCount;
            call.activation = *activation;
            call.caller_activation = parseTraceInteger<uint64_t>(fields[3]);
            call.pc = *pc;
            call.opcode = *opcode;
            call.register_index = parseTraceInteger<int64_t>(fields[8]);
            call.target = fields[11];
            call.arguments.push_back({fields[12], fields[13]});
            if (!luraphTraceCallSource(call))
                continue;
            const auto fingerprint = std::make_tuple(call.vm_count, call.activation, call.pc, call.target);
            if (seenCalls.insert(fingerprint).second)
            {
                trace.calls.push_back(std::move(call));
                pendingOutputCall = trace.calls.size() - 1;
            }
            continue;
        }
        if (line.starts_with("@@LPH_ACTIVATION@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            if (fields.size() > 2)
                if (const std::optional<uint64_t> activation = parseTraceInteger<uint64_t>(fields[2]))
                    trace.activation_entries.insert(*activation);
            continue;
        }
        if (line.starts_with("@@LPH_OUTPUT_V1@@\t"))
        {
            ++trace.event_count;
            const std::vector<std::string> fields = splitTraceFields(line);
            if (fields.size() != 3 || (fields[1] != "stdout" && fields[1] != "stderr"))
                continue;
            const std::optional<std::string> decoded = decodeTraceHex(fields[2]);
            if (!decoded)
                continue;
            line = fields[1] == "stderr" ? "[warn] " + *decoded : *decoded;
        }
        if (line.empty())
            continue;
        trace.output_lines.push_back(line);
        if (pendingOutputCall && *pendingOutputCall < trace.calls.size())
        {
            LuraphTraceCall& call = trace.calls[*pendingOutputCall];
            const std::string rendered = luraphTraceRenderedArguments(call);
            if (call.target == "print")
                call.output_confirmed = line == rendered;
            else if (call.target == "warn")
                call.output_confirmed = line.starts_with("[warn]") && line.find(rendered) != std::string::npos;
            else if (call.target == "error")
                call.output_confirmed = !rendered.empty() && line.starts_with("[main_runtime_error]") && line.find(rendered) != std::string::npos;
            pendingOutputCall.reset();
        }
    }
    trace.candidate_call_count = trace.calls.size();
    for (const LuraphTraceCall& call : trace.calls)
    {
        trace.first_candidate_vm_count = trace.first_candidate_vm_count
            ? std::min(*trace.first_candidate_vm_count, call.vm_count) : call.vm_count;
        trace.last_candidate_vm_count = trace.last_candidate_vm_count
            ? std::max(*trace.last_candidate_vm_count, call.vm_count) : call.vm_count;
    }
    trace.calls.erase(std::remove_if(trace.calls.begin(), trace.calls.end(), [](const LuraphTraceCall& call) {
        return !call.output_confirmed;
    }), trace.calls.end());
    trace.unresolved_call_count = trace.candidate_call_count - trace.calls.size();
    trace.payload_activation_complete = !trace.calls.empty() && std::all_of(trace.calls.begin(), trace.calls.end(), [&](const LuraphTraceCall& call) {
        if (!trace.activation_entries.contains(call.activation))
            return false;
        return std::any_of(trace.vm_events.begin(), trace.vm_events.end(), [&](const LuraphVmEvent& event) {
            return event.activation == call.activation && event.vm_count > call.vm_count;
        });
    });
    return trace;
}

struct LuraphRuntimePrototype
{
    uint64_t id = 0;
    size_t declared_instruction_count = 0;
    std::vector<std::string> lane_names;
    std::map<size_t, json> instructions;
};

struct LuraphRuntimeStructureTrace
{
    std::map<uint64_t, LuraphRuntimePrototype> prototypes;
    std::map<uint64_t, json> activations;
    std::map<uint64_t, uint64_t> prototype_object_ids;
    std::map<std::pair<uint64_t, size_t>, json> closure_descriptors;
    std::map<uint64_t, json> capture_domains;
    std::vector<LuraphVmEvent> vm_events;
    std::vector<json> steps;
    std::vector<json> returns;
    size_t instruction_count = 0;
    size_t malformed_rows = 0;
    std::map<std::string, size_t> malformed_row_kinds;
    bool complete = false;
    bool structure_reused = false;
};

std::optional<LuraphRuntimeStructureTrace> loadLuraphRuntimeStructureSeed(
    const fs::path& path,
    std::string_view expectedSourceHash)
{
    if (!fs::exists(path))
        return std::nullopt;
    json artifact;
    try
    {
        artifact = json::parse(readFile(path));
    }
    catch (...)
    {
        return std::nullopt;
    }
    if (!artifact.is_object() || artifact.value("version", 0) != 1 ||
        artifact.value("kind", "") != "luraph-runtime-decoded-prototypes" ||
        artifact.value("source_sha256", "") != expectedSourceHash ||
        !artifact.value("complete", false) || !artifact.contains("prototypes") ||
        !artifact["prototypes"].is_array())
        return std::nullopt;

    LuraphRuntimeStructureTrace seed;
    for (const json& row : artifact["prototypes"])
    {
        if (!row.is_object() || !row.contains("runtime_id") || !row["runtime_id"].is_number_unsigned() ||
            !row.contains("declared_instruction_count") || !row["declared_instruction_count"].is_number_unsigned() ||
            !row.contains("instructions") || !row["instructions"].is_array())
            return std::nullopt;
        const uint64_t id = row["runtime_id"].get<uint64_t>();
        const size_t declared = row["declared_instruction_count"].get<size_t>();
        if (id == 0 || declared > 200000 || row["instructions"].size() != declared)
            return std::nullopt;
        LuraphRuntimePrototype prototype;
        prototype.id = id;
        prototype.declared_instruction_count = declared;
        if (row.contains("lane_names") && row["lane_names"].is_array())
            for (const json& lane : row["lane_names"])
            {
                if (!lane.is_string())
                    return std::nullopt;
                const std::string name = lane.get<std::string>();
                if (name.empty() || !isIdentifierStart(name.front()) ||
                    !std::all_of(name.begin() + 1, name.end(), isIdentifier))
                    return std::nullopt;
                prototype.lane_names.push_back(name);
            }
        for (const json& instruction : row["instructions"])
        {
            if (!instruction.is_object() || !instruction.contains("pc") || !instruction["pc"].is_number_unsigned())
                return std::nullopt;
            const size_t pc = instruction["pc"].get<size_t>();
            if (pc == 0 || pc > declared || prototype.instructions.contains(pc))
                return std::nullopt;
            prototype.instructions[pc] = instruction;
        }
        seed.instruction_count += prototype.instructions.size();
        seed.prototypes[id] = std::move(prototype);
    }
    if (seed.prototypes.empty() || seed.instruction_count != artifact.value("instruction_count", size_t(0)))
        return std::nullopt;

    if (artifact.contains("closure_descriptors") && artifact["closure_descriptors"].is_array())
        for (const json& descriptor : artifact["closure_descriptors"])
        {
            if (!descriptor.is_object() || !descriptor.contains("prototype") || !descriptor["prototype"].is_number_unsigned() ||
                !descriptor.contains("pc") || !descriptor["pc"].is_number_unsigned())
                continue;
            seed.closure_descriptors[{descriptor["prototype"].get<uint64_t>(), descriptor["pc"].get<size_t>()}] = descriptor;
        }
    if (artifact.contains("observed_capture_domains") && artifact["observed_capture_domains"].is_array())
        for (const json& domain : artifact["observed_capture_domains"])
            if (domain.is_object() && domain.contains("prototype") && domain["prototype"].is_number_unsigned())
                seed.capture_domains[domain["prototype"].get<uint64_t>()] = domain;
    seed.complete = true;
    seed.structure_reused = true;
    return seed;
}

std::optional<uint64_t> luraphTraceObjectId(std::string_view encoded)
{
    return encoded.starts_with("t:") ? parseTraceInteger<uint64_t>(encoded.substr(2)) : std::nullopt;
}

std::optional<int64_t> luraphTraceEncodedInteger(std::string_view encoded)
{
    return encoded.starts_with("n:") ? parseTraceInteger<int64_t>(encoded.substr(2)) : std::nullopt;
}

json luraphRuntimeLaneValue(std::string_view encoded)
{
    const bool virtualRead = encoded.size() >= 2 && encoded[1] == ':' && encoded[0] >= 'A' && encoded[0] <= 'Z';
    std::string normalized(encoded);
    if (virtualRead)
        normalized[0] = static_cast<char>(normalized[0] - 'A' + 'a');
    encoded = normalized;
    const auto provenance = [&virtualRead](json value) {
        value["read_provenance"] = virtualRead ? "metatable_index" : "raw_table";
        return value;
    };
    if (encoded.starts_with("s:"))
    {
        const std::optional<std::string> value = decodeTraceHex(encoded.substr(2));
        if (value)
            return provenance({{"type", "string"}, {"value", printableAscii(*value) ? json(*value) : json(nullptr)},
                {"bytes_hex", std::string(encoded.substr(2))}, {"primitive", true}});
    }
    if (const std::optional<LuraphTraceValue> value = parseLuraphTraceValue(encoded))
        return provenance({{"type", value->type}, {"value", value->type == "nil" ? json(nullptr) : json(value->value)}, {"primitive", true}});
    if (encoded.starts_with("f:"))
    {
        const std::optional<std::string> name = decodeTraceHex(encoded.substr(2));
        if (name)
            return provenance({{"type", "function"}, {"value", nullptr}, {"primitive", false}, {"callable", true},
                {"name", printableAscii(*name) ? json(*name) : json(nullptr)}, {"name_hex", std::string(encoded.substr(2))}});
    }
    if (encoded.starts_with("g:"))
    {
        const std::optional<std::string> path = decodeTraceHex(encoded.substr(2));
        if (path && printableAscii(*path))
            return provenance({{"type", "global_reference"}, {"value", nullptr}, {"primitive", false},
                {"path", *path}, {"path_hex", std::string(encoded.substr(2))}});
    }
    if (encoded.starts_with("x:") && encoded.size() > 2)
        return provenance({{"type", std::string(encoded.substr(2))}, {"value", nullptr}, {"primitive", false}});
    return provenance({{"type", "invalid"}, {"value", nullptr}, {"primitive", false}});
}

std::optional<std::string> luraphClosureDestinationLane(const LuraphOpcodeCatalog& catalog, int64_t opcode)
{
    if (!catalog.available || !catalog.document.contains("handlers") || !catalog.document["handlers"].is_array())
        return std::nullopt;
    const auto findLane = [&](const auto& self, const json& value) -> std::optional<std::string> {
        if (value.is_array())
        {
            for (const json& child : value)
                if (std::optional<std::string> lane = self(self, child))
                    return lane;
            return std::nullopt;
        }
        if (!value.is_object())
            return std::nullopt;
        if (value.value("kind", "") == "register_write" && value.contains("register") &&
            value["register"].is_object() && value["register"].value("kind", "") == "operand" &&
            value["register"].contains("lane") && value["register"]["lane"].is_string() &&
            value.contains("value") && value["value"].is_object() &&
            value["value"].value("kind", "") == "vm_state")
            return value["register"]["lane"].get<std::string>();
        for (auto child = value.begin(); child != value.end(); ++child)
            if (std::optional<std::string> lane = self(self, child.value()))
                return lane;
        return std::nullopt;
    };
    for (const json& handler : catalog.document["handlers"])
    {
        if (handler.value("opcode", int64_t(-1)) != opcode || !handler.contains("semantic_operation"))
            continue;
        return findLane(findLane, handler["semantic_operation"]);
    }
    return std::nullopt;
}

LuraphRuntimeStructureTrace parseLuraphRuntimeStructureTrace(
    const fs::path& path,
    const LuraphOpcodeCatalog& catalog,
    const LuraphRuntimeStructureTrace* structureSeed = nullptr)
{
    LuraphRuntimeStructureTrace trace = structureSeed ? *structureSeed : LuraphRuntimeStructureTrace{};
    if (structureSeed)
    {
        trace.activations.clear();
        trace.vm_events.clear();
        trace.steps.clear();
        trace.returns.clear();
        trace.malformed_rows = 0;
        trace.malformed_row_kinds.clear();
    }
    std::string parsePhase = "initialize";
    try
    {
    using LaneSite = std::tuple<uint64_t, size_t, std::string>;
    using GuardSite = std::tuple<uint64_t, uint64_t, int64_t, int64_t>;
    std::map<LaneSite, std::map<std::string, std::string>> laneTopValues;
    std::map<LaneSite, std::vector<json>> laneTableRows;
    std::map<GuardSite, json> guardStates;
    std::map<GuardSite, json> guardPaths;
    std::set<GuardSite> completedStepSites;
    std::set<std::pair<size_t, size_t>> guardManifest;
    if (catalog.available && catalog.document.contains("dynamic_guard_conditions") &&
        catalog.document["dynamic_guard_conditions"].is_array())
    {
        for (const json& row : catalog.document["dynamic_guard_conditions"])
        {
            if (!row.is_object() || !row.contains("begin") || !row["begin"].is_number_unsigned() ||
                !row.contains("end") || !row["end"].is_number_unsigned())
                continue;
            const size_t begin = row["begin"].get<size_t>();
            const size_t end = row["end"].get<size_t>();
            if (begin < end)
                guardManifest.emplace(begin, end);
        }
    }
    std::istringstream input(readFile(path));
    std::string line;
    std::string rowKind = "unknown";
    const auto markMalformed = [&]() {
        trace.malformed_rows += 1;
        ++trace.malformed_row_kinds[rowKind];
    };
    parsePhase = "trace_rows";
    while (std::getline(input, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        const size_t markerEnd = line.find('\t');
        rowKind = markerEnd == std::string::npos ? line : line.substr(0, markerEnd);
        if (line.starts_with("@@LPH_PROTO_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> id = fields.size() >= 4 ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<size_t> count = fields.size() >= 4 ? parseTraceInteger<size_t>(fields[2]) : std::nullopt;
            if (!id || !count || *id == 0 || *count > 200000)
            {
                markMalformed();
                continue;
            }
            LuraphRuntimePrototype& prototype = trace.prototypes[*id];
            prototype.id = *id;
            prototype.declared_instruction_count = *count;
            prototype.lane_names.clear();
            size_t begin = 0;
            while (begin <= fields[3].size())
            {
                const size_t end = fields[3].find(',', begin);
                const std::string lane = fields[3].substr(begin, (end == std::string::npos ? fields[3].size() : end) - begin);
                if (!lane.empty() && isIdentifierStart(lane.front()) && std::all_of(lane.begin() + 1, lane.end(), isIdentifier))
                    prototype.lane_names.push_back(lane);
                if (end == std::string::npos)
                    break;
                begin = end + 1;
            }
            continue;
        }
        if (line.starts_with("@@LPH_PROTO_OBJECT_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> prototype = fields.size() >= 3
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> object = fields.size() >= 3
                ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            if (prototype && object && *prototype > 0 && *object > 0)
                trace.prototype_object_ids[*prototype] = *object;
            continue;
        }
        if (line.starts_with("@@LPH_LANE_TOP_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> prototype = fields.size() >= 6
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<size_t> pc = fields.size() >= 6
                ? parseTraceInteger<size_t>(fields[2]) : std::nullopt;
            if (prototype && pc && *prototype > 0 && *pc > 0 && !fields[3].empty())
                laneTopValues[{*prototype, *pc, fields[3]}][fields[4]] = fields[5];
            continue;
        }
        if (line.starts_with("@@LPH_LANE_TABLE_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> prototype = fields.size() >= 8
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<size_t> pc = fields.size() >= 8
                ? parseTraceInteger<size_t>(fields[2]) : std::nullopt;
            const std::optional<size_t> depth = fields.size() >= 8
                ? parseTraceInteger<size_t>(fields[4]) : std::nullopt;
            if (prototype && pc && depth && *prototype > 0 && *pc > 0 && *depth <= 4 && !fields[3].empty())
                laneTableRows[{*prototype, *pc, fields[3]}].push_back({
                    {"depth", *depth}, {"path", fields[5]}, {"key", fields[6]}, {"value", fields[7]},
                });
            continue;
        }
        if (line.starts_with("@@LPH_ACT_ARG_OBJECT_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> activation = fields.size() >= 5
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> prototype = fields.size() >= 5
                ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            const std::optional<size_t> argumentIndex = fields.size() >= 5
                ? parseTraceInteger<size_t>(fields[3]) : std::nullopt;
            const std::optional<uint64_t> objectId = fields.size() >= 5
                ? parseTraceInteger<uint64_t>(fields[4]) : std::nullopt;
            if (!activation || !prototype || !argumentIndex || !objectId || *activation == 0 ||
                *prototype == 0 || *argumentIndex == 0 || *argumentIndex > 4 || *objectId == 0 ||
                !trace.prototypes.contains(*prototype))
            {
                markMalformed();
                continue;
            }
            json& activationRow = trace.activations[*activation];
            if (activationRow.contains("prototype") && activationRow["prototype"].is_number_integer() &&
                activationRow["prototype"].get<uint64_t>() != *prototype)
            {
                markMalformed();
                continue;
            }
            activationRow["activation"] = *activation;
            activationRow["prototype"] = *prototype;
            json& objects = activationRow["argument_objects"];
            if (!objects.is_array())
                objects = json::array();
            const json observed = {{"argument_index", *argumentIndex}, {"object_id", *objectId}};
            auto existing = std::find_if(objects.begin(), objects.end(), [&](const json& row) {
                return row.is_object() && row.value("argument_index", size_t(0)) == *argumentIndex;
            });
            if (existing == objects.end())
                objects.push_back(observed);
            else if (*existing != observed)
                activationRow["argument_object_conflict"] = true;
            continue;
        }
        if (line.starts_with("@@LPH_ACT_PROTO_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> activation = fields.size() >= 7 ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> prototype = fields.size() >= 7 ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            if (!activation || !prototype || !trace.prototypes.contains(*prototype))
            {
                markMalformed();
                continue;
            }
            const auto optionalInteger = [&](size_t index) -> json {
                if (index >= fields.size() || fields[index] == "nil")
                    return nullptr;
                if (const std::optional<int64_t> value = parseTraceInteger<int64_t>(fields[index]))
                    return *value;
                return nullptr;
            };
            json arguments = json::array();
            if (fields.size() >= 9 && !fields[8].empty())
            {
                size_t begin = 0;
                while (begin <= fields[8].size())
                {
                    const size_t end = fields[8].find('|', begin);
                    const std::string_view encoded(fields[8].data() + begin,
                        (end == std::string::npos ? fields[8].size() : end) - begin);
                    arguments.push_back(luraphRuntimeLaneValue(encoded));
                    if (end == std::string::npos)
                        break;
                    begin = end + 1;
                }
            }
            json activationRow = {
                {"activation", *activation},
                {"prototype", *prototype},
                {"caller_activation", optionalInteger(3)},
                {"caller_pc", optionalInteger(4)},
                {"caller_opcode", optionalInteger(5)},
                {"argument_count", optionalInteger(6)},
                {"entry_pc", optionalInteger(7)},
            };
            if (auto existing = trace.activations.find(*activation); existing != trace.activations.end() &&
                existing->second.contains("prototype") && existing->second["prototype"].is_number_integer() &&
                existing->second["prototype"].get<uint64_t>() != *prototype)
            {
                markMalformed();
                continue;
            }
            if (fields.size() >= 9)
                activationRow["arguments"] = std::move(arguments);
            if (const json entryVmCount = optionalInteger(9); entryVmCount.is_number_integer())
                activationRow["entry_vm_count"] = entryVmCount;
            if (auto existing = trace.activations.find(*activation); existing != trace.activations.end() &&
                existing->second.contains("argument_table_entries") && existing->second["argument_table_entries"].is_array())
                activationRow["argument_table_entries"] = existing->second["argument_table_entries"];
            if (auto existing = trace.activations.find(*activation); existing != trace.activations.end() &&
                existing->second.contains("argument_table_domains") && existing->second["argument_table_domains"].is_array())
                activationRow["argument_table_domains"] = existing->second["argument_table_domains"];
            if (auto existing = trace.activations.find(*activation); existing != trace.activations.end() &&
                existing->second.value("argument_table_conflict", false))
                activationRow["argument_table_conflict"] = true;
            if (auto existing = trace.activations.find(*activation); existing != trace.activations.end() &&
                existing->second.contains("argument_objects") && existing->second["argument_objects"].is_array())
                activationRow["argument_objects"] = existing->second["argument_objects"];
            if (auto existing = trace.activations.find(*activation); existing != trace.activations.end() &&
                existing->second.value("argument_object_conflict", false))
                activationRow["argument_object_conflict"] = true;
            trace.activations[*activation] = std::move(activationRow);
            continue;
        }
        if (line.starts_with("@@LPH_ACT_ARG_TABLE_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> activation = fields.size() >= 6
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> prototype = fields.size() >= 6
                ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            const std::optional<size_t> argumentIndex = fields.size() >= 6
                ? parseTraceInteger<size_t>(fields[3]) : std::nullopt;
            if (!activation || !prototype || !argumentIndex || *activation == 0 || *prototype == 0 ||
                *argumentIndex == 0)
            {
                markMalformed();
                continue;
            }
            json& activationRow = trace.activations[*activation];
            if (activationRow.contains("prototype") && activationRow["prototype"].is_number_integer() &&
                activationRow["prototype"].get<uint64_t>() != *prototype)
            {
                markMalformed();
                continue;
            }
            activationRow["activation"] = *activation;
            activationRow["prototype"] = *prototype;
            json& entries = activationRow["argument_table_entries"];
            if (!entries.is_array())
                entries = json::array();
            json observed = {
                {"argument_index", *argumentIndex},
                {"key", luraphRuntimeLaneValue(fields[4])},
                {"value", luraphRuntimeLaneValue(fields[5])},
            };
            const auto evidenceQuality = [](const json& value) {
                if (!value.is_object())
                    return 0;
                const std::string type = value.value("type", "");
                if (type == "global_reference")
                    return 4;
                if (value.value("primitive", false))
                    return 3;
                if (type == "function" && value.contains("name") && value["name"].is_string() &&
                    !value["name"].get<std::string>().empty())
                    return 2;
                return 1;
            };
            bool merged = false;
            size_t entriesForArgument = 0;
            for (json& existing : entries)
            {
                if (!existing.is_object() || existing.value("argument_index", size_t(0)) != *argumentIndex)
                    continue;
                ++entriesForArgument;
                if (existing.value("key", json(nullptr)) != observed["key"])
                    continue;
                if (evidenceQuality(observed["value"]) > evidenceQuality(existing.value("value", json(nullptr))))
                    existing = observed;
                else if (evidenceQuality(observed["value"]) == evidenceQuality(existing.value("value", json(nullptr))) &&
                    existing.value("value", json(nullptr)) != observed["value"])
                    activationRow["argument_table_conflict"] = true;
                merged = true;
                break;
            }
            if (!merged)
            {
                if (entriesForArgument >= kLuraphActivationArgumentTableEntryLimit)
                {
                    markMalformed();
                    continue;
                }
                entries.push_back(std::move(observed));
            }
            continue;
        }
        if (line.starts_with("@@LPH_ACT_ARG_TABLE_END_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> activation = fields.size() >= 6
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> prototype = fields.size() >= 6
                ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            const std::optional<size_t> argumentIndex = fields.size() >= 6
                ? parseTraceInteger<size_t>(fields[3]) : std::nullopt;
            const std::optional<int64_t> complete = fields.size() >= 6
                ? parseTraceInteger<int64_t>(fields[4]) : std::nullopt;
            const std::optional<size_t> observedEntries = fields.size() >= 6
                ? parseTraceInteger<size_t>(fields[5]) : std::nullopt;
            if (!activation || !prototype || !argumentIndex || !complete || !observedEntries ||
                *activation == 0 || *prototype == 0 || *argumentIndex == 0 ||
                (*complete != 0 && *complete != 1) ||
                *observedEntries > kLuraphActivationArgumentTableEntryLimit ||
                (trace.activations.contains(*activation) &&
                    trace.activations[*activation].contains("prototype") &&
                    trace.activations[*activation]["prototype"].is_number_integer() &&
                    trace.activations[*activation]["prototype"].get<uint64_t>() != *prototype))
            {
                markMalformed();
                continue;
            }
            json observed = {
                {"argument_index", *argumentIndex},
                {"complete", *complete == 1},
                {"observed_entries", *observedEntries},
            };
            json& activationRow = trace.activations[*activation];
            activationRow["activation"] = *activation;
            activationRow["prototype"] = *prototype;
            json& domains = activationRow["argument_table_domains"];
            if (!domains.is_array())
                domains = json::array();
            bool merged = false;
            for (json& existing : domains)
            {
                if (!existing.is_object() || existing.value("argument_index", size_t(0)) != *argumentIndex)
                    continue;
                if (existing != observed)
                {
                    existing["complete"] = false;
                    activationRow["argument_table_conflict"] = true;
                }
                merged = true;
                break;
            }
            if (!merged)
                domains.push_back(std::move(observed));
            continue;
        }
        if (line.starts_with("@@LPH_CAPTURE_DOMAIN_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> activation = fields.size() >= 6
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> prototype = fields.size() >= 6
                ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            const std::optional<int64_t> complete = fields.size() >= 6
                ? parseTraceInteger<int64_t>(fields[3]) : std::nullopt;
            const std::optional<size_t> declared = fields.size() >= 6
                ? parseTraceInteger<size_t>(fields[4]) : std::nullopt;
            if (!activation || !prototype || !complete || !declared || *activation == 0 || *prototype == 0 ||
                (*complete != 0 && *complete != 1) || *declared > 256)
            {
                markMalformed();
                continue;
            }
            json indices = json::array();
            bool valid = true;
            if (*declared > 0)
            {
                size_t begin = 0;
                while (begin <= fields[5].size())
                {
                    const size_t end = fields[5].find(',', begin);
                    const std::string_view item(fields[5].data() + begin,
                        (end == std::string::npos ? fields[5].size() : end) - begin);
                    const std::optional<int64_t> index = parseTraceInteger<int64_t>(item);
                    if (!index || *index < 0 || *index > 200000)
                    {
                        valid = false;
                        break;
                    }
                    indices.push_back(*index);
                    if (end == std::string::npos)
                        break;
                    begin = end + 1;
                }
            }
            if (!valid || indices.size() != *declared)
            {
                markMalformed();
                continue;
            }
            json row = {{"prototype", *prototype}, {"complete", *complete == 1}, {"indices", std::move(indices)}};
            auto existing = trace.capture_domains.find(*prototype);
            if (existing == trace.capture_domains.end())
                trace.capture_domains[*prototype] = std::move(row);
            else
            {
                const bool matchingIndices = existing->second.value("indices", json::array()) == row["indices"];
                existing->second["complete"] = matchingIndices &&
                    existing->second.value("complete", false) && row.value("complete", false);
            }
            continue;
        }
        if (line.starts_with("@@LPH_CAPTURE_VALUE_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> activation = fields.size() >= 7
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> prototype = fields.size() >= 7
                ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            const std::optional<int64_t> index = fields.size() >= 7
                ? parseTraceInteger<int64_t>(fields[3]) : std::nullopt;
            const json cell = fields.size() >= 7 ? luraphRuntimeLaneValue(fields[4]) : json(nullptr);
            const json value = fields.size() >= 7 ? luraphRuntimeLaneValue(fields[5]) : json(nullptr);
            const std::optional<int64_t> slot = fields.size() >= 7 && fields[6] != "nil"
                ? parseTraceInteger<int64_t>(fields[6]) : std::nullopt;
            auto domain = prototype ? trace.capture_domains.find(*prototype) : trace.capture_domains.end();
            if (!activation || !prototype || !index || *activation == 0 || *prototype == 0 ||
                *index < 0 || *index > 200000 || domain == trace.capture_domains.end() ||
                !cell.is_object() || !value.is_object() || cell.value("type", "invalid") == "invalid" ||
                value.value("type", "invalid") == "invalid")
            {
                markMalformed();
                continue;
            }
            json observed = {{"capture_index", *index}, {"cell", cell}, {"resolved_value", value},
                {"cell_slot", slot ? json(*slot) : json(nullptr)},
                {"cell_slot_identity", fields[6] == "nil" ? json(nullptr) : json(fields[6])},
                {"cell_slot_integer", slot.has_value()}};
            json& values = domain->second["values"];
            if (!values.is_object())
                values = json::object();
            const std::string key = std::to_string(*index);
            if (!values.contains(key))
                values[key] = std::move(observed);
            else if (values[key] != observed)
                domain->second["complete"] = false;
            continue;
        }
        if (line.starts_with("@@LPH_RETURN_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> vmCount = fields.size() >= 8
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> activation = fields.size() >= 8
                ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            const std::optional<int64_t> pc = fields.size() >= 8
                ? parseTraceInteger<int64_t>(fields[3]) : std::nullopt;
            const std::optional<int64_t> opcode = fields.size() >= 8
                ? parseTraceInteger<int64_t>(fields[4]) : std::nullopt;
            const std::optional<size_t> arity = fields.size() >= 8
                ? parseTraceInteger<size_t>(fields[5]) : std::nullopt;
            const std::optional<size_t> captured = fields.size() >= 8
                ? parseTraceInteger<size_t>(fields[6]) : std::nullopt;
            if (!vmCount || !activation || !pc || !opcode || !arity || !captured ||
                *activation == 0 || *pc <= 0 || *captured > 256 || *captured > *arity)
            {
                markMalformed();
                continue;
            }
            json values = json::array();
            bool valid = true;
            if (*captured > 0)
            {
                size_t begin = 0;
                while (begin <= fields[7].size())
                {
                    const size_t end = fields[7].find('|', begin);
                    const std::string_view encoded(fields[7].data() + begin,
                        (end == std::string::npos ? fields[7].size() : end) - begin);
                    const json value = luraphRuntimeLaneValue(encoded);
                    if (!value.is_object() || value.value("type", "invalid") == "invalid")
                    {
                        valid = false;
                        break;
                    }
                    values.push_back(value);
                    if (end == std::string::npos)
                        break;
                    begin = end + 1;
                }
            }
            if (!valid || values.size() != *captured)
            {
                markMalformed();
                continue;
            }
            const GuardSite guardSite{*vmCount, *activation, *pc, *opcode};
            const auto guardPath = guardPaths.find(guardSite);
            trace.returns.push_back({
                {"vm_count", *vmCount},
                {"activation", *activation},
                {"pc", *pc},
                {"opcode", *opcode},
                {"arity", *arity},
                {"captured", *captured},
                {"complete", *captured == *arity},
                {"values", std::move(values)},
                {"guard_path", guardPath != guardPaths.end() ? guardPath->second : json(nullptr)},
            });
            continue;
        }
        if (line.starts_with("@@LPH_VM@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> vmCount = fields.size() >= 8
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> activation = fields.size() >= 8
                ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            const std::optional<int64_t> pc = fields.size() >= 8
                ? parseTraceInteger<int64_t>(fields[6]) : std::nullopt;
            const std::optional<int64_t> opcode = fields.size() >= 8
                ? parseTraceInteger<int64_t>(fields[7]) : std::nullopt;
            if (!vmCount || !activation || !pc || !opcode || *activation == 0 || *pc <= 0)
            {
                markMalformed();
                continue;
            }
            trace.vm_events.push_back({*vmCount, *activation, *pc, *opcode});
            continue;
        }
        if (line.starts_with("@@LPH_GUARD_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> vmCount = fields.size() >= 6
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> activation = fields.size() >= 6
                ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            const std::optional<int64_t> pc = fields.size() >= 6
                ? parseTraceInteger<int64_t>(fields[3]) : std::nullopt;
            const std::optional<int64_t> opcode = fields.size() >= 6
                ? parseTraceInteger<int64_t>(fields[4]) : std::nullopt;
            json guards = json::object();
            bool valid = vmCount && activation && pc && opcode && *vmCount > 0 && *activation > 0 && *pc > 0;
            for (size_t fieldIndex = 5; valid && fieldIndex < fields.size(); ++fieldIndex)
            {
                size_t begin = 0;
                while (valid && begin <= fields[fieldIndex].size())
                {
                    const size_t end = fields[fieldIndex].find('|', begin);
                    const std::string_view item(fields[fieldIndex].data() + begin,
                        (end == std::string::npos ? fields[fieldIndex].size() : end) - begin);
                    const size_t equal = item.find('=');
                    if (equal == std::string_view::npos || equal == 0 || equal > 64 || equal + 1 >= item.size())
                    {
                        valid = false;
                        break;
                    }
                    const std::string name(item.substr(0, equal));
                    if (!isIdentifierStart(name.front()) ||
                        !std::all_of(name.begin() + 1, name.end(), isIdentifier) || guards.contains(name))
                    {
                        valid = false;
                        break;
                    }
                    const json value = luraphRuntimeLaneValue(item.substr(equal + 1));
                    if (!value.is_object() || value.value("type", "invalid") == "invalid")
                    {
                        valid = false;
                        break;
                    }
                    guards[name] = value;
                    if (guards.size() > 32)
                    {
                        valid = false;
                        break;
                    }
                    if (end == std::string::npos)
                        break;
                    begin = end + 1;
                }
            }
            if (!valid || guards.empty())
            {
                markMalformed();
                continue;
            }
            const GuardSite site{*vmCount, *activation, *pc, *opcode};
            if (auto existing = guardStates.find(site); existing != guardStates.end() && existing->second != guards)
            {
                markMalformed();
                continue;
            }
            guardStates[site] = std::move(guards);
            continue;
        }
        if (line.starts_with("@@LPH_GUARD_PATH_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> vmCount = fields.size() == 8
                ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> activation = fields.size() == 8
                ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            const std::optional<int64_t> pc = fields.size() == 8
                ? parseTraceInteger<int64_t>(fields[3]) : std::nullopt;
            const std::optional<int64_t> opcode = fields.size() == 8
                ? parseTraceInteger<int64_t>(fields[4]) : std::nullopt;
            const std::optional<size_t> declared = fields.size() == 8
                ? parseTraceInteger<size_t>(fields[5]) : std::nullopt;
            const std::optional<int> overflow = fields.size() == 8
                ? parseTraceInteger<int>(fields[6]) : std::nullopt;
            bool valid = vmCount && activation && pc && opcode && declared && overflow &&
                *vmCount > 0 && *activation > 0 && *pc > 0 && *opcode >= 0 && *opcode <= 255 &&
                *declared <= 4096 && (*overflow == 0 || *overflow == 1) &&
                ((*declared == 0 && fields[7].empty()) || (*declared > 0 && !fields[7].empty()));
            if (valid)
            {
                const auto activationRow = trace.activations.find(*activation);
                const uint64_t prototype = activationRow != trace.activations.end()
                    ? activationRow->second.value("prototype", uint64_t(0)) : 0;
                valid = activationRow != trace.activations.end() && prototype != 0 &&
                    trace.prototypes.contains(prototype);
            }
            json decisions = json::array();
            size_t begin = 0;
            while (valid && begin < fields[7].size())
            {
                const size_t end = fields[7].find('|', begin);
                const std::string_view item(fields[7].data() + begin,
                    (end == std::string::npos ? fields[7].size() : end) - begin);
                const size_t firstColon = item.find(':');
                const size_t secondColon = firstColon == std::string_view::npos
                    ? std::string_view::npos : item.find(':', firstColon + 1);
                const std::optional<size_t> conditionBegin = firstColon == std::string_view::npos
                    ? std::nullopt : parseTraceInteger<size_t>(item.substr(0, firstColon));
                const std::optional<size_t> conditionEnd = secondColon == std::string_view::npos
                    ? std::nullopt : parseTraceInteger<size_t>(item.substr(firstColon + 1, secondColon - firstColon - 1));
                const std::optional<int> decision = secondColon == std::string_view::npos
                    ? std::nullopt : parseTraceInteger<int>(item.substr(secondColon + 1));
                if (!conditionBegin || !conditionEnd || !decision || *conditionBegin >= *conditionEnd ||
                    (*decision != 0 && *decision != 1) || !guardManifest.contains({*conditionBegin, *conditionEnd}))
                {
                    valid = false;
                    break;
                }
                decisions.push_back({
                    {"ordinal", decisions.size()},
                    {"begin", *conditionBegin},
                    {"end", *conditionEnd},
                    {"decision", *decision != 0},
                });
                if (decisions.size() > 4096)
                {
                    valid = false;
                    break;
                }
                if (end == std::string::npos)
                    break;
                begin = end + 1;
            }
            if (!valid || decisions.size() != *declared)
            {
                markMalformed();
                continue;
            }
            const GuardSite site{*vmCount, *activation, *pc, *opcode};
            if (completedStepSites.contains(site))
            {
                markMalformed();
                continue;
            }
            json path = {
                {"complete", *overflow == 0},
                {"overflow", *overflow != 0},
                {"decisions", std::move(decisions)},
            };
            if (auto existing = guardPaths.find(site); existing != guardPaths.end() && existing->second != path)
            {
                markMalformed();
                continue;
            }
            guardPaths[site] = std::move(path);
            continue;
        }
        if (line.starts_with("@@LPH_STEP_V1@@\t"))
        {
            const std::vector<std::string> fields = splitTraceFields(line);
            const std::optional<uint64_t> vmCount = fields.size() >= 8 ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
            const std::optional<uint64_t> activation = fields.size() >= 8 ? parseTraceInteger<uint64_t>(fields[2]) : std::nullopt;
            const std::optional<int64_t> pc = fields.size() >= 8 ? parseTraceInteger<int64_t>(fields[3]) : std::nullopt;
            const std::optional<int64_t> opcode = fields.size() >= 8 ? parseTraceInteger<int64_t>(fields[4]) : std::nullopt;
            const std::optional<int64_t> nextPc = fields.size() >= 8 ? parseTraceInteger<int64_t>(fields[5]) : std::nullopt;
            const std::optional<size_t> declaredWrites = fields.size() >= 8 ? parseTraceInteger<size_t>(fields[6]) : std::nullopt;
            if (!vmCount || !activation || !pc || !opcode || !nextPc || !declaredWrites || *declaredWrites > 200000)
            {
                markMalformed();
                continue;
            }
            json writes = json::array();
            bool valid = true;
            if (*declaredWrites > 0)
            {
                size_t begin = 0;
                while (begin <= fields[7].size())
                {
                    const size_t end = fields[7].find('|', begin);
                    const std::string_view item(fields[7].data() + begin,
                        (end == std::string::npos ? fields[7].size() : end) - begin);
                    const size_t equal = item.find('=');
                    const std::optional<int64_t> index = equal == std::string_view::npos
                        ? std::nullopt : parseTraceInteger<int64_t>(item.substr(0, equal));
                    if (!index || *index < -200000 || *index > 200000 || equal + 1 >= item.size())
                    {
                        valid = false;
                        break;
                    }
                    const json value = luraphRuntimeLaneValue(item.substr(equal + 1));
                    if (!value.is_object() || value.value("type", "invalid") == "invalid")
                    {
                        valid = false;
                        break;
                    }
                    writes.push_back({{"register", *index}, {"value", value}});
                    if (end == std::string::npos)
                        break;
                    begin = end + 1;
                }
            }
            if (!valid || writes.size() != *declaredWrites)
            {
                markMalformed();
                continue;
            }
            json runtimeLanes = json::object();
            if (fields.size() >= 9 && !fields[8].empty())
            {
                size_t begin = 0;
                while (begin <= fields[8].size())
                {
                    const size_t end = fields[8].find('|', begin);
                    const std::string_view item(fields[8].data() + begin,
                        (end == std::string::npos ? fields[8].size() : end) - begin);
                    const size_t equal = item.find('=');
                    if (equal == std::string_view::npos || equal == 0 || equal > 64 || equal + 1 >= item.size())
                    {
                        valid = false;
                        break;
                    }
                    const std::string lane(item.substr(0, equal));
                    if (!std::all_of(lane.begin(), lane.end(), [](unsigned char ch) {
                            return std::isalnum(ch) || ch == '_';
                        }))
                    {
                        valid = false;
                        break;
                    }
                    const json laneValue = luraphRuntimeLaneValue(item.substr(equal + 1));
                    if (!laneValue.is_object() || laneValue.value("type", "invalid") == "invalid")
                    {
                        valid = false;
                        break;
                    }
                    runtimeLanes[lane] = laneValue;
                    if (end == std::string::npos)
                        break;
                    begin = end + 1;
                }
            }
            if (!valid)
            {
                markMalformed();
                continue;
            }
            json writeOrigins = json::object();
            if (fields.size() >= 10 && !fields[9].empty())
            {
                std::set<int64_t> writtenRegisters;
                for (const json& write : writes)
                    if (write.contains("register") && write["register"].is_number_integer())
                        writtenRegisters.insert(write["register"].get<int64_t>());
                size_t begin = 0;
                while (begin <= fields[9].size())
                {
                    const size_t end = fields[9].find('|', begin);
                    const std::string_view item(fields[9].data() + begin,
                        (end == std::string::npos ? fields[9].size() : end) - begin);
                    const size_t equal = item.find('=');
                    const std::optional<int64_t> destination = equal == std::string_view::npos
                        ? std::nullopt : parseTraceInteger<int64_t>(item.substr(0, equal));
                    if (!destination || !writtenRegisters.contains(*destination) || equal + 1 >= item.size())
                    {
                        valid = false;
                        break;
                    }
                    json candidates = json::array();
                    size_t candidateBegin = equal + 1;
                    while (candidateBegin <= item.size())
                    {
                        const size_t candidateEnd = item.find(',', candidateBegin);
                        const std::string_view token = item.substr(candidateBegin,
                            (candidateEnd == std::string_view::npos ? item.size() : candidateEnd) - candidateBegin);
                        if (token.size() < 3 || token[1] != ':' || (token[0] != 'r' && token[0] != 'a'))
                        {
                            valid = false;
                            break;
                        }
                        const std::optional<int64_t> index = parseTraceInteger<int64_t>(token.substr(2));
                        if (!index || (token[0] == 'a' && *index <= 0) || *index < -200000 || *index > 200000)
                        {
                            valid = false;
                            break;
                        }
                        candidates.push_back({{"kind", token[0] == 'r' ? "register" : "argument"}, {"index", *index}});
                        if (candidateEnd == std::string_view::npos)
                            break;
                        candidateBegin = candidateEnd + 1;
                    }
                    if (!valid || candidates.empty() || candidates.size() > 2)
                    {
                        valid = false;
                        break;
                    }
                    writeOrigins[std::to_string(*destination)] = std::move(candidates);
                    if (end == std::string::npos)
                        break;
                    begin = end + 1;
                }
            }
            if (!valid)
            {
                markMalformed();
                continue;
            }
            const GuardSite guardSite{*vmCount, *activation, *pc, *opcode};
            const auto guardState = guardStates.find(guardSite);
            const auto guardPath = guardPaths.find(guardSite);
            trace.steps.push_back({
                {"vm_count", *vmCount},
                {"activation", *activation},
                {"pc", *pc},
                {"opcode", *opcode},
                {"next_pc", *nextPc},
                {"register_writes", std::move(writes)},
                {"runtime_lanes", std::move(runtimeLanes)},
                {"write_origins", std::move(writeOrigins)},
                {"guard_state", guardState != guardStates.end() ? guardState->second : json::object()},
                {"guard_path", guardPath != guardPaths.end() ? guardPath->second : json(nullptr)},
            });
            completedStepSites.insert(guardSite);
            continue;
        }
        if (!line.starts_with("@@LPH_INSN_V1@@\t"))
            continue;
        const std::vector<std::string> fields = splitTraceFields(line);
        const std::optional<uint64_t> id = fields.size() >= 5 ? parseTraceInteger<uint64_t>(fields[1]) : std::nullopt;
        const std::optional<size_t> pc = fields.size() >= 5 ? parseTraceInteger<size_t>(fields[2]) : std::nullopt;
        const std::optional<int64_t> opcode = fields.size() >= 5 ? parseTraceInteger<int64_t>(fields[3]) : std::nullopt;
        auto prototype = id ? trace.prototypes.find(*id) : trace.prototypes.end();
        if (!id || !pc || !opcode || *pc == 0 || prototype == trace.prototypes.end() || *pc > prototype->second.declared_instruction_count)
        {
            markMalformed();
            continue;
        }
        json lanes = json::object();
        size_t begin = 0;
        bool valid = true;
        while (begin <= fields[4].size())
        {
            const size_t end = fields[4].find('|', begin);
            const std::string_view item(fields[4].data() + begin, (end == std::string::npos ? fields[4].size() : end) - begin);
            const size_t equal = item.find('=');
            if (equal == std::string_view::npos || equal == 0)
            {
                valid = false;
                break;
            }
            const std::string lane(item.substr(0, equal));
            if (!isIdentifierStart(lane.front()) || !std::all_of(lane.begin() + 1, lane.end(), isIdentifier))
            {
                valid = false;
                break;
            }
            lanes[lane] = luraphRuntimeLaneValue(item.substr(equal + 1));
            if (end == std::string::npos)
                break;
            begin = end + 1;
        }
        if (!valid)
        {
            markMalformed();
            continue;
        }
        prototype->second.instructions[*pc] = {
            {"pc", *pc},
            {"opcode", *opcode},
            {"lanes", std::move(lanes)},
        };
    }

    parsePhase = "closure_descriptors";
    std::map<uint64_t, uint64_t> prototypeByObject;
    for (const auto& [prototype, object] : trace.prototype_object_ids)
        prototypeByObject[object] = prototype;

    std::map<std::pair<uint64_t, size_t>, size_t> observedClosureWriteCounts;
    std::map<std::pair<uint64_t, size_t>, std::set<int64_t>> observedClosureWriteRegisters;
    std::set<std::pair<uint64_t, size_t>> ambiguousObservedClosureWrites;
    for (const json& step : trace.steps)
    {
        const uint64_t activation = step.value("activation", uint64_t(0));
        const int64_t pc = step.value("pc", int64_t(-1));
        auto activationRow = trace.activations.find(activation);
        if (activationRow == trace.activations.end() || pc <= 0 ||
            !step.contains("register_writes") || !step["register_writes"].is_array())
            continue;
        const uint64_t prototype = activationRow->second.value("prototype", uint64_t(0));
        if (prototype == 0)
            continue;
        const std::pair<uint64_t, size_t> site = {prototype, static_cast<size_t>(pc)};
        ++observedClosureWriteCounts[site];
        std::vector<int64_t> functionRegisters;
        for (const json& write : step["register_writes"])
        {
            if (!write.is_object() || !write.contains("value") || !write["value"].is_object() ||
                write["value"].value("type", "") != "function")
                continue;
            functionRegisters.push_back(write.value("register", std::numeric_limits<int64_t>::min()));
        }
        if (functionRegisters.size() != 1 || functionRegisters.front() == std::numeric_limits<int64_t>::min())
            ambiguousObservedClosureWrites.insert(site);
        else
            observedClosureWriteRegisters[site].insert(functionRegisters.front());
    }
    for (const auto& [site, topValues] : laneTopValues)
    {
        const auto& [prototype, pc, lane] = site;
        auto prototypeRow = trace.prototypes.find(prototype);
        if (prototypeRow == trace.prototypes.end())
            continue;
        auto instruction = prototypeRow->second.instructions.find(pc);
        if (instruction == prototypeRow->second.instructions.end())
            continue;
        auto captureTable = topValues.find("n:5");
        auto targetTable = topValues.find("n:9");
        const std::optional<uint64_t> captureObject = captureTable == topValues.end()
            ? std::nullopt : luraphTraceObjectId(captureTable->second);
        const std::optional<uint64_t> targetObject = targetTable == topValues.end()
            ? std::nullopt : luraphTraceObjectId(targetTable->second);
        if (!captureObject || !targetObject)
            continue;
        const std::optional<uint64_t> targetPrototype = prototypeByObject.contains(*targetObject)
            ? std::optional<uint64_t>(prototypeByObject[*targetObject]) : std::nullopt;

        std::map<size_t, json> captures;
        if (auto rows = laneTableRows.find(site); rows != laneTableRows.end())
            for (const json& row : rows->second)
            {
                if (!row.is_object())
                    continue;
                const std::string path = row.value("path", "");
                constexpr std::string_view prefix = "/n:5/n:";
                if (!path.starts_with(prefix) || path.find('/', prefix.size()) != std::string::npos)
                    continue;
                const std::optional<size_t> descriptorIndex = parseTraceInteger<size_t>(
                    std::string_view(path).substr(prefix.size()));
                const std::optional<int64_t> key = luraphTraceEncodedInteger(row.value("key", ""));
                const std::optional<int64_t> value = luraphTraceEncodedInteger(row.value("value", ""));
                if (!descriptorIndex || !key || !value || *descriptorIndex == 0)
                    continue;
                json& capture = captures[*descriptorIndex];
                capture["descriptor_index"] = *descriptorIndex;
                capture["capture_index"] = *descriptorIndex - 1;
                if (*key == 2)
                    capture["slot"] = *value;
                else if (*key == 3)
                    capture["capture_kind"] = *value;
            }

        json captureRows = json::array();
        bool capturesComplete = true;
        for (auto& [index, capture] : captures)
        {
            (void)index;
            if (!capture.is_object())
            {
                capturesComplete = false;
                continue;
            }
            if (!capture.contains("capture_kind") || !capture.contains("slot"))
                capturesComplete = false;
            const int64_t kind = capture.value("capture_kind", int64_t(-1));
            capture["kind_name"] = kind == 0 ? "open_register_cell" :
                kind == 1 ? "register_value" : "inherited_upvalue_cell";
            captureRows.push_back(std::move(capture));
        }
        if (!instruction->second.is_object())
            continue;
        const int64_t staticOpcode = instruction->second.value("opcode", int64_t(-1));
        const std::optional<std::string> destinationLane = luraphClosureDestinationLane(catalog, staticOpcode);
        std::optional<int64_t> destination;
        std::string destinationEvidence;
        const std::pair<uint64_t, size_t> closureSite = {prototype, pc};
        if (!ambiguousObservedClosureWrites.contains(closureSite) &&
            observedClosureWriteCounts[closureSite] > 0 &&
            observedClosureWriteRegisters[closureSite].size() == 1)
        {
            destination = *observedClosureWriteRegisters[closureSite].begin();
            destinationEvidence = "observed_function_register_write";
        }
        if (!destination && destinationLane && instruction->second.contains("lanes") &&
            instruction->second["lanes"].contains(*destinationLane))
        {
            const json& laneValue = instruction->second["lanes"][*destinationLane];
            if (laneValue.is_object() && laneValue.value("type", "") == "number" &&
                laneValue.contains("value") && laneValue["value"].is_string())
                destination = parseTraceInteger<int64_t>(laneValue["value"].get<std::string>());
            if (destination)
                destinationEvidence = "handler_register_write_operand_lane";
        }
        if (!destination)
        {
            auto legacyDestination = topValues.find("n:4");
            destination = legacyDestination == topValues.end()
                ? std::nullopt : luraphTraceEncodedInteger(legacyDestination->second);
            if (destination)
                destinationEvidence = "descriptor_field_4_legacy";
        }
        trace.closure_descriptors[{prototype, pc}] = {
            {"target_prototype", targetPrototype ? json(*targetPrototype) : json(nullptr)},
            {"target_object_id", *targetObject},
            {"destination_register", destination ? json(*destination) : json(nullptr)},
            {"destination_lane", destinationLane ? json(*destinationLane) : json(nullptr)},
            {"destination_evidence", destinationEvidence.empty() ? json(nullptr) : json(destinationEvidence)},
            {"captures", std::move(captureRows)},
            {"complete", targetPrototype.has_value() && destination.has_value() && capturesComplete},
            {"target_evidence", "opcode_table_object_identity"},
            {"capture_evidence", "descriptor_table_lane_index_5"},
            {"descriptor_lane", lane},
            {"static_opcode", staticOpcode},
        };
    }

    parsePhase = "deduplicate_steps";
    trace.instruction_count = 0;
    std::map<std::tuple<uint64_t, uint64_t, int64_t>, json> uniqueSteps;
    for (json& step : trace.steps)
    {
        if (!step.is_object())
            continue;
        const auto key = std::make_tuple(
            step.value("vm_count", uint64_t(0)),
            step.value("activation", uint64_t(0)),
            step.value("pc", int64_t(-1)));
        auto existing = uniqueSteps.find(key);
        const size_t evidenceFields = size_t(!step.value("runtime_lanes", json::object()).empty()) +
            size_t(!step.value("guard_state", json::object()).empty()) +
            size_t(!step.value("write_origins", json::object()).empty());
        const size_t existingEvidenceFields = existing != uniqueSteps.end() && existing->second.is_object()
            ? size_t(!existing->second.value("runtime_lanes", json::object()).empty()) +
                size_t(!existing->second.value("guard_state", json::object()).empty()) +
                size_t(!existing->second.value("write_origins", json::object()).empty())
            : 0;
        if (existing == uniqueSteps.end() || evidenceFields > existingEvidenceFields)
            uniqueSteps[key] = std::move(step);
    }
    trace.steps.clear();
    trace.steps.reserve(uniqueSteps.size());
    for (auto& [key, step] : uniqueSteps)
    {
        (void)key;
        trace.steps.push_back(std::move(step));
    }
    parsePhase = "deduplicate_returns";
    std::map<std::tuple<uint64_t, uint64_t, int64_t>, json> uniqueReturns;
    for (json& returned : trace.returns)
    {
        if (!returned.is_object())
            continue;
        const uint64_t vmCount = returned.contains("vm_count") && returned["vm_count"].is_number_unsigned()
            ? returned["vm_count"].get<uint64_t>() : uint64_t(0);
        const uint64_t activation = returned.contains("activation") && returned["activation"].is_number_unsigned()
            ? returned["activation"].get<uint64_t>() : uint64_t(0);
        const int64_t pc = returned.contains("pc") && returned["pc"].is_number_integer()
            ? returned["pc"].get<int64_t>() : int64_t(-1);
        const auto key = std::make_tuple(vmCount, activation, pc);
        uniqueReturns[key] = std::move(returned);
    }
    trace.returns.clear();
    trace.returns.reserve(uniqueReturns.size());
    for (auto& [key, returned] : uniqueReturns)
    {
        (void)key;
        trace.returns.push_back(std::move(returned));
    }
    parsePhase = "validate_completeness";
    trace.complete = !trace.prototypes.empty() && trace.malformed_rows == 0;
    for (const auto& [id, prototype] : trace.prototypes)
    {
        (void)id;
        trace.instruction_count += prototype.instructions.size();
        trace.complete = trace.complete && prototype.instructions.size() == prototype.declared_instruction_count;
    }
    return trace;
    }
    catch (const std::exception& error)
    {
        throw std::runtime_error("phase " + parsePhase + ": " + error.what());
    }
}

using LuraphGuardDecisionKey = std::pair<size_t, size_t>;

size_t attachLuraphObservedGuardSemantics(
    std::string_view source,
    LuraphRuntimeStructureTrace& trace)
{
    auto parsed = parseSource(source);
    if (!parsed->result.errors.empty())
        return 0;
    LuraphLoopShapeCollector shapeCollector;
    parsed->result.root->visit(&shapeCollector);
    auto shape = std::max_element(
        shapeCollector.shapes.begin(), shapeCollector.shapes.end(),
        [](const LuraphLoopShape& left, const LuraphLoopShape& right) {
            return left.conditionals < right.conditionals;
        });
    if (shape == shapeCollector.shapes.end() || !shape->opcode || !shape->body || !shape->pc)
        return 0;
    LuraphOpcodeDispatcherCollector dispatcherCollector(shape->opcode);
    shape->body->visit(&dispatcherCollector);
    auto dispatcherCandidate = std::max_element(
        dispatcherCollector.candidates.begin(), dispatcherCollector.candidates.end(),
        [](const auto& left, const auto& right) { return left.conditionals < right.conditionals; });
    if (dispatcherCandidate == dispatcherCollector.candidates.end())
        return 0;
    Luau::AstStatIf* dispatcher = dispatcherCandidate->node;
    SourceView view(source);
    const std::map<Luau::AstLocal*, double> bindings = proveLuraphGuardBindings(
        parsed->result.root, dispatcher, shape->opcode, view);

    LuraphRegisterRoleCollector roles(shape->pc);
    shape->body->visit(&roles);
    auto registerRole = std::max_element(
        roles.register_scores.begin(), roles.register_scores.end(),
        [](const auto& left, const auto& right) { return left.second < right.second; });
    Luau::AstLocal* registers = registerRole == roles.register_scores.end() ? nullptr : registerRole->first;
    if (!registers)
        return 0;
    std::set<Luau::AstLocal*> lanes = roles.pc_indexed_tables;
    lanes.erase(shape->opcode_table);
    lanes.erase(registers);
    LuraphTopRoleCollector topRoles(registers);
    shape->body->visit(&topRoles);
    auto topRole = std::max_element(
        topRoles.scores.begin(), topRoles.scores.end(),
        [](const auto& left, const auto& right) { return left.second < right.second; });
    LuraphUpvalueRoleCollector upvalueRoles(registers, shape->pc, lanes);
    shape->body->visit(&upvalueRoles);
    auto upvalueRole = std::max_element(
        upvalueRoles.scores.begin(), upvalueRoles.scores.end(),
        [](const auto& left, const auto& right) { return left.second < right.second; });

    LuraphSemanticRoles semanticRoles;
    semanticRoles.registers = registers;
    semanticRoles.pc = shape->pc;
    semanticRoles.opcode = shape->opcode;
    semanticRoles.opcode_table = shape->opcode_table;
    semanticRoles.top = topRole == topRoles.scores.end() ? nullptr : topRole->first;
    semanticRoles.upvalues = upvalueRole == upvalueRoles.scores.end() ? nullptr : upvalueRole->first;
    for (Luau::AstLocal* lane : lanes)
        if (lane && lane->name.value)
            semanticRoles.lanes[lane] = lane->name.value;

    size_t attached = 0;
    for (json& step : trace.steps)
    {
        const json path = step.value("guard_path", json(nullptr));
        if (!path.is_object() || !path.value("complete", false) ||
            !path.contains("decisions") || !path["decisions"].is_array())
            continue;
        const int64_t opcode = step.value("opcode", int64_t(-1));
        if (opcode < 0 || opcode > 255)
            continue;
        std::map<LuraphGuardDecisionKey, std::vector<bool>> decisions;
        bool valid = true;
        for (const json& row : path["decisions"])
        {
            if (!row.is_object() || !row.contains("begin") || !row["begin"].is_number_unsigned() ||
                !row.contains("end") || !row["end"].is_number_unsigned() ||
                !row.contains("decision") || !row["decision"].is_boolean())
            {
                valid = false;
                break;
            }
            decisions[{row["begin"].get<size_t>(), row["end"].get<size_t>()}].push_back(
                row["decision"].get<bool>());
        }
        if (!valid)
            continue;
        std::map<LuraphGuardDecisionKey, size_t> decisionOffsets;
        size_t decisionsUsed = 0;
        const LuraphBranchDecision decide = [&](Luau::AstStatIf* conditional) -> std::optional<bool> {
            if (std::optional<bool> staticDecision = evaluateStateCondition(
                    conditional->condition, shape->opcode, opcode, &bindings))
                return staticDecision;
            const LuraphGuardDecisionKey key{
                view.offset(conditional->condition->location.begin),
                view.offset(conditional->condition->location.end),
            };
            const auto observed = decisions.find(key);
            size_t& offset = decisionOffsets[key];
            if (observed == decisions.end() || offset >= observed->second.size())
                return std::nullopt;
            ++decisionsUsed;
            return observed->second[offset++];
        };
        LuraphExecutedStatementPath executedPath = selectLuraphExecutedStatementPath(
            dispatcher, shape->body, decide);
        if (!executedPath.complete || executedPath.statements.empty() ||
            decisionsUsed != path["decisions"].size())
            continue;
        Luau::AstStatBlock executed = luraphExecutedStatementBlock(executedPath);
        LuraphOpcodeReferenceFinder opcodeReference(shape->opcode);
        executed.visit(&opcodeReference);
        if (opcodeReference.found)
            continue;
        const LuraphNormalizedHandler normalized = normalizeLuraphHandler(
            &executed, semanticRoles, opcode);
        if (!normalized.normalization_complete || !normalized.vm_state_independent ||
            !normalized.semantic_operation.is_object() ||
            normalized.semantic_operation.value("protector_state", false) ||
            !normalized.semantic_operation.value("source_semantic", true) ||
            luraphSemanticContainsUnknownState(normalized.semantic_operation))
            continue;
        step["guard_replay_candidate"] = normalized.semantic_operation;
        step["guard_replay_candidate"]["candidate_only"] = true;
        step["guard_replay_candidate"]["path_specific"] = true;
        step["guard_replay_candidate"]["static_semantic"] = false;
        step["guard_replay"] = {
            {"complete", true},
            {"candidate_only", true},
            {"decisions_available", path["decisions"].size()},
            {"decisions_used", decisionsUsed},
            {"executed_statement_count", executedPath.statements.size()},
            {"dispatcher_statement_count", executedPath.dispatcher_statements},
            {"continuation_statement_count", executedPath.continuation_statements},
            {"executed_statement_ranges", luraphExecutedStatementRanges(executedPath, view)},
            {"full_effect_normalization", true},
            {"proof", "recorded_condition_decisions_replayed_through_original_ast"},
        };
        ++attached;
    }
    return attached;
}

json luraphRuntimeStructureArtifact(const LuraphRuntimeStructureTrace& trace, std::string_view sourceHash)
{
    json prototypes = json::array();
    size_t declaredInstructionCount = 0;
    for (const auto& [id, prototype] : trace.prototypes)
    {
        declaredInstructionCount += prototype.declared_instruction_count;
        json instructions = json::array();
        for (const auto& [pc, instruction] : prototype.instructions)
        {
            (void)pc;
            instructions.push_back(instruction);
        }
        prototypes.push_back({
            {"runtime_id", id},
            {"declared_instruction_count", prototype.declared_instruction_count},
            {"observed_instruction_count", prototype.instructions.size()},
            {"complete", prototype.instructions.size() == prototype.declared_instruction_count},
            {"lane_names", prototype.lane_names},
            {"instructions", std::move(instructions)},
        });
    }
    json activations = json::array();
    for (const auto& [id, activation] : trace.activations)
    {
        (void)id;
        activations.push_back(activation);
    }
    json steps = json::array();
    for (const json& observed : trace.steps)
    {
        json step = observed;
        const uint64_t activation = observed.value("activation", uint64_t(0));
        if (auto found = trace.activations.find(activation); found != trace.activations.end())
            step["prototype"] = found->second["prototype"];
        else
            step["prototype"] = nullptr;
        steps.push_back(std::move(step));
    }
    json returns = json::array();
    for (const json& observed : trace.returns)
    {
        json returned = observed;
        const uint64_t activation = observed.value("activation", uint64_t(0));
        if (auto found = trace.activations.find(activation); found != trace.activations.end())
            returned["prototype"] = found->second["prototype"];
        else
            returned["prototype"] = nullptr;
        returns.push_back(std::move(returned));
    }
    json closureDescriptors = json::array();
    for (const auto& [site, descriptor] : trace.closure_descriptors)
    {
        json row = descriptor;
        row["prototype"] = site.first;
        row["pc"] = site.second;
        closureDescriptors.push_back(std::move(row));
    }
    json captureDomains = json::array();
    for (const auto& [prototype, domain] : trace.capture_domains)
    {
        (void)prototype;
        captureDomains.push_back(domain);
    }
    return {
        {"version", 1},
        {"kind", "luraph-runtime-decoded-prototypes"},
        {"scope", "reachable-prototypes-observed-offline"},
        {"source_sha256", sourceHash},
        {"structure_reused", trace.structure_reused},
        {"complete", trace.complete && trace.instruction_count == declaredInstructionCount},
        {"malformed_rows", trace.malformed_rows},
        {"malformed_row_kinds", trace.malformed_row_kinds},
        {"prototype_count", trace.prototypes.size()},
        {"activation_count", trace.activations.size()},
        {"step_count", trace.steps.size()},
        {"return_count", trace.returns.size()},
        {"instruction_count", trace.instruction_count},
        {"declared_instruction_count", declaredInstructionCount},
        {"observed_instruction_count", trace.instruction_count},
        {"activations", std::move(activations)},
        {"steps", std::move(steps)},
        {"returns", std::move(returns)},
        {"closure_descriptors", std::move(closureDescriptors)},
        {"observed_capture_domains", std::move(captureDomains)},
        {"prototypes", std::move(prototypes)},
    };
}

std::string luraphFingerprintHex(uint64_t value)
{
    std::ostringstream out;
    out << std::hex << std::setw(16) << std::setfill('0') << value;
    return out.str();
}

std::optional<int64_t> luraphRuntimeNumericLane(const json& instruction, std::string_view lane)
{
    if (!instruction.contains("lanes") || !instruction["lanes"].is_object() ||
        !instruction["lanes"].contains(std::string(lane)))
        return std::nullopt;
    const json& value = instruction["lanes"][std::string(lane)];
    if (!value.is_object() || !value.value("primitive", false) ||
        value.value("type", "") != "number" || !value.contains("value") ||
        !value["value"].is_string())
        return std::nullopt;
    return parseTraceInteger<int64_t>(value["value"].get<std::string>());
}

std::vector<luraph::vm::RuntimeOperandLaneAnchor> luraphRuntimeOperandLaneAnchors(
    const LuraphRuntimeStructureTrace& trace)
{
    std::set<std::string> integralLaneNames;
    bool laneNamesInitialized = false;
    for (const auto& [id, prototype] : trace.prototypes)
    {
        (void)id;
        if (prototype.declared_instruction_count == 0 ||
            prototype.instructions.size() != prototype.declared_instruction_count)
            continue;
        if (!laneNamesInitialized)
        {
            integralLaneNames.insert(prototype.lane_names.begin(), prototype.lane_names.end());
            laneNamesInitialized = true;
        }
        else
        {
            std::set<std::string> names(prototype.lane_names.begin(), prototype.lane_names.end());
            std::erase_if(integralLaneNames, [&](const std::string& name) {
                return !names.contains(name);
            });
        }
        std::erase_if(integralLaneNames, [&](const std::string& name) {
            return std::any_of(prototype.instructions.begin(), prototype.instructions.end(),
                [&](const auto& instruction) {
                    return !luraphRuntimeNumericLane(instruction.second, name).has_value();
                });
        });
    }
    if (!laneNamesInitialized || integralLaneNames.size() < 3)
        return {};

    std::vector<luraph::vm::RuntimeOperandLaneAnchor> anchors;
    anchors.reserve(trace.prototypes.size());
    for (const auto& [id, prototype] : trace.prototypes)
    {
        (void)id;
        if (prototype.declared_instruction_count == 0 ||
            prototype.instructions.size() != prototype.declared_instruction_count)
            continue;

        luraph::vm::RuntimeOperandLaneAnchor anchor;
        anchor.instruction_count = prototype.declared_instruction_count;
        bool complete = true;
        for (const std::string& laneName : integralLaneNames)
        {
            luraph::vm::NamedRuntimeOperandLaneSequence lane;
            lane.name = laneName;
            lane.values.reserve(anchor.instruction_count);
            for (size_t pc = 1; pc <= anchor.instruction_count; ++pc)
            {
                const auto instruction = prototype.instructions.find(pc);
                const std::optional<int64_t> value = instruction != prototype.instructions.end()
                    ? luraphRuntimeNumericLane(instruction->second, laneName) : std::nullopt;
                if (!value)
                {
                    complete = false;
                    break;
                }
                lane.values.push_back(*value);
            }
            if (!complete)
                break;
            anchor.lanes.push_back(std::move(lane));
        }
        if (complete)
            anchors.push_back(std::move(anchor));
    }
    return anchors;
}

std::optional<std::string_view> luraphProjectedRuntimeLane(
    const luraph::vm::OperandLaneProjection& projection,
    luraph::vm::NormalizedOperandLane normalizedLane)
{
    for (const luraph::vm::OperandLaneProjectionBinding& binding : projection.bindings)
        if (binding.normalized_lane == normalizedLane)
            return binding.runtime_name;
    return std::nullopt;
}

std::optional<std::vector<luraph::vm::CaptureDescriptorShape>> luraphRuntimeCaptureShape(
    const json& descriptor)
{
    if (!descriptor.value("complete", false) || !descriptor.contains("captures") ||
        !descriptor["captures"].is_array())
        return std::nullopt;
    std::vector<luraph::vm::CaptureDescriptorShape> captures;
    captures.reserve(descriptor["captures"].size());
    for (size_t index = 0; index < descriptor["captures"].size(); ++index)
    {
        const json& capture = descriptor["captures"][index];
        if (!capture.is_object() || capture.value("capture_index", std::numeric_limits<size_t>::max()) != index ||
            !capture.contains("capture_kind") || !capture["capture_kind"].is_number_integer() ||
            !capture.contains("slot") || !capture["slot"].is_number_integer())
            return std::nullopt;
        const int64_t kind = capture["capture_kind"].get<int64_t>();
        const int64_t slot = capture["slot"].get<int64_t>();
        if (kind < 0 || static_cast<uint64_t>(kind) > std::numeric_limits<unsigned int>::max() || slot < 0)
            return std::nullopt;
        captures.push_back({static_cast<unsigned int>(kind), static_cast<uint64_t>(slot)});
    }
    return captures;
}

std::vector<luraph::vm::RuntimePrototypeRecord> luraphRuntimePrototypeRecords(
    const LuraphRuntimeStructureTrace& trace,
    const std::optional<luraph::vm::OperandLaneProjection>& laneProjection = std::nullopt)
{
    std::vector<luraph::vm::RuntimePrototypeRecord> records;
    records.reserve(trace.prototypes.size());
    std::map<uint64_t, size_t> recordById;
    for (const auto& [id, prototype] : trace.prototypes)
    {
        luraph::vm::RuntimePrototypeRecord record;
        record.runtime_id = id;
        record.instruction_count = prototype.declared_instruction_count;
        bool complete = prototype.instructions.size() == prototype.declared_instruction_count;
        record.opcode_lanes.reserve(prototype.instructions.size());
        const std::optional<std::string_view> dLane = laneProjection
            ? luraphProjectedRuntimeLane(*laneProjection, luraph::vm::NormalizedOperandLane::D)
            : std::optional<std::string_view>("D");
        const std::optional<std::string_view> gLane = laneProjection
            ? luraphProjectedRuntimeLane(*laneProjection, luraph::vm::NormalizedOperandLane::G)
            : std::optional<std::string_view>("G");
        const std::optional<std::string_view> pLane = laneProjection
            ? luraphProjectedRuntimeLane(*laneProjection, luraph::vm::NormalizedOperandLane::p)
            : std::optional<std::string_view>("p");
        complete = complete && dLane && gLane && pLane;
        for (const auto& [pc, instruction] : prototype.instructions)
        {
            const std::optional<int64_t> D = dLane ? luraphRuntimeNumericLane(instruction, *dLane) : std::nullopt;
            const std::optional<int64_t> G = gLane ? luraphRuntimeNumericLane(instruction, *gLane) : std::nullopt;
            const std::optional<int64_t> p = pLane ? luraphRuntimeNumericLane(instruction, *pLane) : std::nullopt;
            if (!instruction.is_object() || instruction.value("pc", size_t(0)) != pc ||
                pc != record.opcode_lanes.size() + 1 || !instruction.contains("opcode") ||
                !instruction["opcode"].is_number_integer() || !D || !G || !p)
            {
                complete = false;
                continue;
            }
            record.opcode_lanes.push_back({
                pc,
                instruction["opcode"].get<int64_t>(),
                {*D, *G, *p},
            });
        }
        record.opcode_lanes_complete = complete && record.opcode_lanes.size() == record.instruction_count;
        if (!record.opcode_lanes_complete)
            record.opcode_lanes.clear();
        recordById.emplace(id, records.size());
        records.push_back(std::move(record));
    }

    std::set<uint64_t> topLevelPrototypes;
    for (const auto& [activationId, activation] : trace.activations)
    {
        (void)activationId;
        if (!activation.is_object() || !activation.value("caller_activation", json(nullptr)).is_null() ||
            !activation.contains("prototype") || !activation["prototype"].is_number_integer())
            continue;
        const uint64_t prototype = activation["prototype"].get<uint64_t>();
        if (recordById.contains(prototype))
            topLevelPrototypes.insert(prototype);
    }
    if (topLevelPrototypes.size() == 1)
        records[recordById.at(*topLevelPrototypes.begin())].is_root = true;

    std::map<uint64_t, std::pair<uint64_t, size_t>> observedParents;
    std::set<uint64_t> conflictingCaptures;
    for (const auto& [site, descriptor] : trace.closure_descriptors)
    {
        const auto& [parentId, sourcePc] = site;
        if (!recordById.contains(parentId) || !descriptor.is_object() ||
            !descriptor.contains("target_prototype") || !descriptor["target_prototype"].is_number_integer())
            continue;
        const uint64_t targetId = descriptor["target_prototype"].get<uint64_t>();
        if (!recordById.contains(targetId) || targetId == parentId)
            continue;

        luraph::vm::RuntimeClosureEvidence closure;
        closure.source_pc = sourcePc;
        closure.target_runtime_id = targetId;
        if (const auto captures = luraphRuntimeCaptureShape(descriptor))
        {
            closure.captures = *captures;
            closure.captures_complete = true;
            luraph::vm::RuntimePrototypeRecord& target = records[recordById.at(targetId)];
            if (target.captures_complete && target.captures != *captures)
                conflictingCaptures.insert(targetId);
            else
            {
                target.captures = *captures;
                target.captures_complete = true;
            }
        }
        records[recordById.at(parentId)].closure_targets.push_back(std::move(closure));
        auto [parent, inserted] = observedParents.emplace(targetId, site);
        if (!inserted && parent->second != site)
            parent->second = {0, 0};
    }
    for (luraph::vm::RuntimePrototypeRecord& record : records)
    {
        std::sort(record.closure_targets.begin(), record.closure_targets.end(),
            [](const auto& left, const auto& right) { return left.source_pc < right.source_pc; });
        if (conflictingCaptures.contains(record.runtime_id))
        {
            record.captures.clear();
            record.captures_complete = false;
        }
        if (auto parent = observedParents.find(record.runtime_id);
            parent != observedParents.end() && parent->second.first != 0)
        {
            record.parent_runtime_id = parent->second.first;
            record.parent_closure_pc = parent->second.second;
            record.is_root = false;
        }
    }
    return records;
}

json luraphPrototypeCorrespondenceArtifact(
    const luraph::EnvelopeAnalysis& analysis,
    const LuraphRuntimeStructureTrace& trace)
{
    const std::vector<luraph::vm::RuntimeOperandLaneAnchor> runtimeLaneAnchors =
        luraphRuntimeOperandLaneAnchors(trace);

    json containerReports = json::array();
    size_t validStaticContainers = 0;
    size_t completeContainerMatches = 0;
    std::optional<size_t> completeContainerIndex;
    for (size_t containerIndex = 0; containerIndex < analysis.containers.size(); ++containerIndex)
    {
        const luraph::ContainerAnalysis& container = analysis.containers[containerIndex];
        if (container.parse_status != luraph::ContainerParseStatus::Parsed &&
            container.parse_status != luraph::ContainerParseStatus::StructuralMetadataRecovered)
            continue;
        const luraph::vm::NormalizedContainer normalizedContainer =
            luraph::vm::normalizeContainer(container);
        const luraph::vm::OperandLaneProjectionResult laneProjection =
            luraph::vm::inferOperandLaneProjection(normalizedContainer, runtimeLaneAnchors);
        const std::optional<luraph::vm::OperandLaneProjection> uniqueLaneProjection =
            laneProjection.status == luraph::vm::OperandLaneProjectionStatus::Unique &&
                laneProjection.candidates.size() == 1
            ? std::optional<luraph::vm::OperandLaneProjection>(laneProjection.candidates.front())
            : std::nullopt;
        const std::vector<luraph::vm::RuntimePrototypeRecord> runtimeRecords =
            luraphRuntimePrototypeRecords(trace, uniqueLaneProjection);
        std::map<uint64_t, const luraph::vm::RuntimePrototypeRecord*> runtimeById;
        for (const luraph::vm::RuntimePrototypeRecord& record : runtimeRecords)
            runtimeById.emplace(record.runtime_id, &record);
        const luraph::vm::StaticPrototypeIndex staticIndex = luraph::vm::buildStaticPrototypeIndex(container);
        const luraph::vm::PrototypeCorrespondenceResult result =
            luraph::vm::correlateRuntimePrototypes(staticIndex, runtimeRecords);
        validStaticContainers += result.static_evidence_valid ? 1 : 0;

        json staticPrototypes = json::array();
        for (const luraph::vm::StaticPrototypeShape& prototype : staticIndex.prototypes)
        {
            json captures = json::array();
            for (size_t captureIndex = 0; captureIndex < prototype.fingerprint.captures.size(); ++captureIndex)
            {
                const luraph::vm::CaptureDescriptorShape& capture =
                    prototype.fingerprint.captures[captureIndex];
                captures.push_back({
                    {"capture_index", captureIndex},
                    {"capture_kind", capture.kind_code},
                    {"slot", capture.source_index},
                });
            }
            staticPrototypes.push_back({
                {"metadata_index", prototype.metadata_index},
                {"wrapper_index", prototype.wrapper_index},
                {"instruction_count", prototype.fingerprint.instruction_count},
                {"opcode_lane_fingerprint", luraphFingerprintHex(prototype.fingerprint.opcode_lane_digest)},
                {"captures", std::move(captures)},
                {"captures_complete", prototype.fingerprint.captures_complete},
                {"parent_metadata_index", prototype.parent_metadata_index
                    ? json(*prototype.parent_metadata_index) : json(nullptr)},
                {"parent_closure_pc", prototype.parent_closure_pc
                    ? json(*prototype.parent_closure_pc) : json(nullptr)},
            });
        }

        json matches = json::array();
        for (const luraph::vm::PrototypeCorrespondence& match : result.records)
        {
            const auto runtime = runtimeById.find(match.runtime_id);
            json candidates = json::array();
            for (size_t metadataIndex : match.candidate_metadata_indices)
                candidates.push_back({
                    {"metadata_index", metadataIndex},
                    {"wrapper_index", metadataIndex + 1},
                });
            json proof = json::array();
            for (luraph::vm::CorrespondenceProof item : match.proof)
                proof.push_back(luraph::vm::toString(item));
            matches.push_back({
                {"runtime_id", match.runtime_id},
                {"instruction_count", runtime != runtimeById.end()
                    ? json(runtime->second->instruction_count) : json(nullptr)},
                {"opcode_lane_fingerprint", runtime != runtimeById.end() &&
                        runtime->second->opcode_lanes_complete
                    ? json(luraphFingerprintHex(luraph::vm::opcodeLaneFingerprintDigest(
                        runtime->second->opcode_lanes))) : json(nullptr)},
                {"status", luraph::vm::toString(match.status)},
                {"static_metadata_index", match.static_metadata_index
                    ? json(*match.static_metadata_index) : json(nullptr)},
                {"static_wrapper_index", match.static_metadata_index
                    ? json(*match.static_metadata_index + 1) : json(nullptr)},
                {"candidates", std::move(candidates)},
                {"proof", std::move(proof)},
            });
        }
        const bool complete = result.static_evidence_valid && result.runtime_evidence_valid &&
            result.matched_count == runtimeRecords.size() && result.ambiguous_count == 0 &&
            result.unmatched_count == 0;
        if (complete)
        {
            ++completeContainerMatches;
            completeContainerIndex = containerIndex;
        }
        json projectionCandidates = json::array();
        for (const luraph::vm::OperandLaneProjection& candidate : laneProjection.candidates)
        {
            json bindings = json::object();
            for (const luraph::vm::OperandLaneProjectionBinding& binding : candidate.bindings)
                bindings[luraph::vm::toString(binding.normalized_lane)] = binding.runtime_name;
            projectionCandidates.push_back(std::move(bindings));
        }
        json residueCounts = json::array();
        for (size_t count : staticIndex.residue_diagnostics.counts)
            residueCounts.push_back(count);
        containerReports.push_back({
            {"container_index", containerIndex},
            {"status", !result.static_evidence_valid || !result.runtime_evidence_valid
                ? "invalid_evidence" : complete ? "complete" : result.matched_count > 0 ? "partial" : "unresolved"},
            {"complete", complete},
            {"static_evidence_valid", result.static_evidence_valid},
            {"runtime_evidence_valid", result.runtime_evidence_valid},
            {"static_prototype_count", staticIndex.prototypes.size()},
            {"runtime_prototype_count", runtimeRecords.size()},
            {"matched", result.matched_count},
            {"ambiguous", result.ambiguous_count},
            {"unmatched", result.unmatched_count},
            {"ambiguity_preserved", result.ambiguous_count > 0},
            {"diagnostic", result.diagnostic},
            {"instruction_schema", {
                {"status", luraph::vm::toString(staticIndex.schema_selection.status)},
                {"schema", luraph::vm::toString(staticIndex.schema_selection.schema)},
                {"lph_dollar_marker", staticIndex.schema_selection.lph_dollar_marker},
                {"transport_validated", staticIndex.schema_selection.transport_validated},
                {"structural_metadata_validated", staticIndex.schema_selection.structural_metadata_validated},
                {"static_graph_validated", staticIndex.schema_selection.static_graph_validated},
                {"diagnostic", staticIndex.schema_selection.diagnostic},
            }},
            {"operand_residues", {
                {"counts", std::move(residueCounts)},
                {"operand_lane_count", staticIndex.residue_diagnostics.operand_lane_count},
                {"valid_operand_lane_count", staticIndex.residue_diagnostics.valid_operand_lane_count},
                {"invalid_operand_lane_count", staticIndex.residue_diagnostics.invalid_operand_lane_count},
                {"first_invalid_prototype_metadata_index",
                    staticIndex.residue_diagnostics.first_invalid_prototype_metadata_index
                        ? json(*staticIndex.residue_diagnostics.first_invalid_prototype_metadata_index) : json(nullptr)},
                {"first_invalid_pc", staticIndex.residue_diagnostics.first_invalid_pc
                        ? json(*staticIndex.residue_diagnostics.first_invalid_pc) : json(nullptr)},
                {"first_invalid_lane", staticIndex.residue_diagnostics.first_invalid_lane
                        ? json(luraph::vm::toString(*staticIndex.residue_diagnostics.first_invalid_lane)) : json(nullptr)},
                {"first_invalid_residue", staticIndex.residue_diagnostics.first_invalid_residue
                        ? json(*staticIndex.residue_diagnostics.first_invalid_residue) : json(nullptr)},
                {"diagnostic", staticIndex.residue_diagnostics.diagnostic},
            }},
            {"operand_lane_projection", {
                {"status", luraph::vm::toString(laneProjection.status)},
                {"runtime_anchor_count", runtimeLaneAnchors.size()},
                {"uniquely_count_matched_anchor_count", laneProjection.uniquely_matched_anchor_count},
                {"candidate_count", laneProjection.candidates.size()},
                {"candidates", std::move(projectionCandidates)},
                {"diagnostic", laneProjection.diagnostic},
            }},
            {"static_prototypes", std::move(staticPrototypes)},
            {"matches", std::move(matches)},
        });
    }

    const bool uniqueCompleteMatch = completeContainerMatches == 1;
    return {
        {"version", 1},
        {"kind", "luraph-static-runtime-prototype-correspondence"},
        {"scope", "verified-static-container-and-bounded-offline-runtime"},
        {"status", containerReports.empty() ? "static_evidence_unavailable" :
            completeContainerMatches > 1 ? "ambiguous_static_container" :
            uniqueCompleteMatch ? "complete" : "partial"},
        {"complete", uniqueCompleteMatch},
        {"selected_container_index", uniqueCompleteMatch
            ? json(*completeContainerIndex) : json(nullptr)},
        {"valid_static_container_count", validStaticContainers},
        {"complete_container_match_count", completeContainerMatches},
        {"runtime_prototype_count", trace.prototypes.size()},
        {"evidence", {
            {"instruction_counts", true},
            {"ordered_opcode_lane_fingerprints", std::any_of(
                containerReports.begin(), containerReports.end(), [](const json& row) {
                    return row.contains("operand_lane_projection") &&
                        row["operand_lane_projection"].value("status", "") == "unique";
                })},
            {"observed_parent_child_edges", trace.closure_descriptors.size()},
            {"hash_only_matching", false},
        }},
        {"containers", std::move(containerReports)},
    };
}

json applyLuraphStaticClosureCorrespondence(
    LuraphRuntimeStructureTrace& trace,
    const json& correspondence)
{
    json metrics = {
        {"available", false},
        {"runtime_targets_resolved", 0},
        {"static_only_targets_resolved", 0},
        {"parent_wrapper_targets_resolved", 0},
        {"unresolved_sites", trace.closure_descriptors.size()},
    };
    if (!correspondence.value("complete", false) ||
        !correspondence.contains("selected_container_index") ||
        !correspondence["selected_container_index"].is_number_unsigned() ||
        !correspondence.contains("containers") || !correspondence["containers"].is_array())
        return metrics;
    const uint64_t selected = correspondence["selected_container_index"].get<uint64_t>();
    const json* container = nullptr;
    for (const json& candidate : correspondence["containers"])
        if (candidate.value("container_index", std::numeric_limits<uint64_t>::max()) == selected)
        {
            container = &candidate;
            break;
        }
    if (!container || !container->contains("matches") || !(*container)["matches"].is_array() ||
        !container->contains("static_prototypes") || !(*container)["static_prototypes"].is_array())
        return metrics;

    std::map<uint64_t, size_t> staticParentByRuntime;
    std::map<size_t, uint64_t> runtimeByStaticWrapper;
    for (const json& match : (*container)["matches"])
    {
        if (!match.is_object() || match.value("status", "") != "matched" ||
            !match.contains("runtime_id") || !match["runtime_id"].is_number_unsigned() ||
            !match.contains("static_metadata_index") || !match["static_metadata_index"].is_number_unsigned() ||
            !match.contains("static_wrapper_index") || !match["static_wrapper_index"].is_number_unsigned())
            continue;
        const uint64_t runtime = match["runtime_id"].get<uint64_t>();
        staticParentByRuntime[runtime] = match["static_metadata_index"].get<size_t>();
        runtimeByStaticWrapper[match["static_wrapper_index"].get<size_t>()] = runtime;
    }

    std::map<std::pair<size_t, size_t>, std::vector<const json*>> targetsByParentSite;
    std::map<std::pair<size_t, size_t>, std::vector<const json*>> targetsByParentWrapper;
    for (const json& prototype : (*container)["static_prototypes"])
    {
        if (!prototype.is_object() || !prototype.contains("parent_metadata_index") ||
            !prototype["parent_metadata_index"].is_number_unsigned())
            continue;
        const size_t parent = prototype["parent_metadata_index"].get<size_t>();
        if (prototype.contains("parent_closure_pc") && prototype["parent_closure_pc"].is_number_unsigned())
            targetsByParentSite[{parent, prototype["parent_closure_pc"].get<size_t>()}].push_back(&prototype);
        if (prototype.contains("wrapper_index") && prototype["wrapper_index"].is_number_unsigned())
            targetsByParentWrapper[{parent, prototype["wrapper_index"].get<size_t>()}].push_back(&prototype);
    }

    std::map<std::pair<uint64_t, size_t>, std::set<int64_t>> observedEffectiveOpcodes;
    for (const json& step : trace.steps)
    {
        const uint64_t activation = step.value("activation", uint64_t(0));
        const int64_t pc = step.value("pc", int64_t(-1));
        const int64_t opcode = step.value("opcode", int64_t(-1));
        const auto activationRow = trace.activations.find(activation);
        if (activationRow == trace.activations.end() || pc <= 0 || opcode < 0)
            continue;
        const uint64_t prototype = activationRow->second.value("prototype", uint64_t(0));
        if (prototype > 0)
            observedEffectiveOpcodes[{prototype, static_cast<size_t>(pc)}].insert(opcode);
    }

    size_t runtimeResolved = 0;
    size_t staticOnlyResolved = 0;
    size_t parentWrapperResolved = 0;
    for (auto& [site, descriptor] : trace.closure_descriptors)
    {
        const auto parent = staticParentByRuntime.find(site.first);
        if (parent == staticParentByRuntime.end())
            continue;
        const json* target = nullptr;
        std::string targetEvidence = "verified_static_parent_pc_correspondence";
        bool parentWrapperEvidence = false;
        if (const auto targets = targetsByParentSite.find({parent->second, site.second});
            targets != targetsByParentSite.end() && targets->second.size() == 1)
            target = targets->second.front();
        else if (const auto observed = observedEffectiveOpcodes.find(site);
            observed != observedEffectiveOpcodes.end() && observed->second == std::set<int64_t>{112})
        {
            const auto runtimeParent = trace.prototypes.find(site.first);
            if (runtimeParent != trace.prototypes.end())
            {
                const auto instruction = runtimeParent->second.instructions.find(site.second);
                if (instruction != runtimeParent->second.instructions.end())
                if (const std::optional<int64_t> wrapper = luraphRuntimeNumericLane(instruction->second, "S");
                    wrapper && *wrapper > 0)
                    if (const auto targets = targetsByParentWrapper.find({
                            parent->second, static_cast<size_t>(*wrapper)});
                        targets != targetsByParentWrapper.end() && targets->second.size() == 1)
                    {
                        target = targets->second.front();
                        targetEvidence = "runtime_validated_opcode112_parent_wrapper_operand";
                        parentWrapperEvidence = true;
                    }
            }
        }
        if (!target)
            continue;
        const json& targetRow = *target;
        if (!targetRow.contains("metadata_index") || !targetRow["metadata_index"].is_number_unsigned() ||
            !targetRow.contains("wrapper_index") || !targetRow["wrapper_index"].is_number_unsigned() ||
            !targetRow.value("captures_complete", false) || !targetRow.contains("captures") ||
            !targetRow["captures"].is_array())
            continue;
        const size_t wrapper = targetRow["wrapper_index"].get<size_t>();
        descriptor["static_target_metadata_index"] = targetRow["metadata_index"];
        descriptor["static_target_wrapper_index"] = wrapper;
        descriptor["static_target_instruction_count"] = targetRow.value("instruction_count", size_t(0));
        descriptor["captures"] = targetRow["captures"];
        descriptor["capture_evidence"] = "verified_static_prototype_descriptor";
        descriptor["target_evidence"] = targetEvidence;
        if (parentWrapperEvidence)
            ++parentWrapperResolved;
        const auto runtimeTarget = runtimeByStaticWrapper.find(wrapper);
        if (runtimeTarget == runtimeByStaticWrapper.end())
        {
            descriptor["target_prototype"] = nullptr;
            descriptor["complete"] = false;
            ++staticOnlyResolved;
            continue;
        }
        descriptor["target_prototype"] = runtimeTarget->second;
        descriptor["complete"] = descriptor.contains("destination_register") &&
            descriptor["destination_register"].is_number_integer() &&
            descriptor["destination_register"].get<int64_t>() >= 0;
        ++runtimeResolved;
    }
    metrics["available"] = true;
    metrics["runtime_targets_resolved"] = runtimeResolved;
    metrics["static_only_targets_resolved"] = staticOnlyResolved;
    metrics["parent_wrapper_targets_resolved"] = parentWrapperResolved;
    metrics["unresolved_sites"] = trace.closure_descriptors.size() - runtimeResolved - staticOnlyResolved;
    return metrics;
}

json materializeLuraphSemanticOperation(const json& value, const json& lanes)
{
    if (value.is_array())
    {
        json result = json::array();
        for (const json& item : value)
            result.push_back(materializeLuraphSemanticOperation(item, lanes));
        return result;
    }
    if (!value.is_object())
        return value;
    if (value.value("kind", "") == "operand" && value.contains("lane") && value["lane"].is_string())
    {
        const std::string lane = value["lane"].get<std::string>();
        return {
            {"kind", "immediate"},
            {"lane", lane},
            {"value", lanes.contains(lane) ? lanes[lane] : json(nullptr)},
        };
    }
    json result = json::object();
    for (auto item = value.begin(); item != value.end(); ++item)
        result[item.key()] = materializeLuraphSemanticOperation(item.value(), lanes);
    return result;
}

std::optional<int64_t> luraphMaterializedRegisterIndex(const json& operation)
{
    if (!operation.is_object() || operation.value("kind", "") != "register_write" ||
        !operation.contains("register") || !operation["register"].is_object())
        return std::nullopt;
    const json& index = operation["register"];
    if (index.value("kind", "") != "immediate" || !index.contains("value") || !index["value"].is_object())
        return std::nullopt;
    const json& value = index["value"];
    if (value.value("type", "") != "number" || !value.contains("value") || !value["value"].is_string())
        return std::nullopt;
    return parseTraceInteger<int64_t>(value["value"].get<std::string>());
}

std::optional<json> luraphObservedRegisterResolution(
    const json& operation,
    const std::vector<json>& observations)
{
    const std::optional<int64_t> registerIndex = luraphMaterializedRegisterIndex(operation);
    if (!registerIndex || observations.empty())
        return std::nullopt;
    std::optional<json> resolvedValue;
    size_t matches = 0;
    for (const json& observation : observations)
    {
        const json& writes = observation.value("register_writes", json::array());
        auto write = std::find_if(writes.begin(), writes.end(), [&](const json& candidate) {
            return candidate.value("register", std::numeric_limits<int64_t>::min()) == *registerIndex;
        });
        if (write == writes.end() || !write->contains("value"))
            return std::nullopt;
        if (!resolvedValue)
            resolvedValue = (*write)["value"];
        else if (*resolvedValue != (*write)["value"])
            return std::nullopt;
        ++matches;
    }
    return json{
        {"kind", "observed_register_value"},
        {"register", *registerIndex},
        {"value", std::move(*resolvedValue)},
        {"observation_count", matches},
        {"scope", "executed-payload-site"},
        {"static_value", false},
        {"non_speculative", true},
    };
}

bool luraphObservedRegisterWriteContradicts(
    const json& operation,
    const std::vector<json>& observations)
{
    const std::optional<int64_t> registerIndex = luraphMaterializedRegisterIndex(operation);
    if (!registerIndex || observations.empty())
        return false;
    bool observedAnyWrite = false;
    for (const json& observation : observations)
    {
        const json& writes = observation.value("register_writes", json::array());
        if (!writes.is_array())
            continue;
        for (const json& write : writes)
        {
            if (!write.contains("register") || !write["register"].is_number_integer())
                continue;
            observedAnyWrite = true;
            if (write["register"].get<int64_t>() == *registerIndex)
                return false;
        }
    }
    return observedAnyWrite;
}

std::optional<int64_t> luraphMaterializedImmediateInteger(const json& expression)
{
    if (!expression.is_object() || expression.value("kind", "") != "immediate" ||
        !expression.contains("value") || !expression["value"].is_object())
        return std::nullopt;
    const json& value = expression["value"];
    if (value.value("type", "") != "number" || !value.contains("value") || !value["value"].is_string())
        return std::nullopt;
    return parseTraceInteger<int64_t>(value["value"].get<std::string>());
}

bool luraphObservedSemanticContradicts(
    const json& operation,
    const std::vector<json>& observations)
{
    if (luraphObservedRegisterWriteContradicts(operation, observations))
        return true;
    if (!operation.is_object() || operation.value("kind", "") != "numeric_for" ||
        operation.value("proof", "") != "numeric_loop_assigns_nil_to_each_register_in_operand_lane_range")
        return false;
    const std::optional<int64_t> from = luraphMaterializedImmediateInteger(operation.value("from", json(nullptr)));
    const std::optional<int64_t> to = luraphMaterializedImmediateInteger(operation.value("to", json(nullptr)));
    if (!from || !to)
        return false;
    for (const json& observation : observations)
    {
        const json& writes = observation.value("register_writes", json::array());
        if (!writes.is_array())
            continue;
        for (const json& write : writes)
        {
            if (!write.contains("register") || !write["register"].is_number_integer() ||
                !write.contains("value") || !write["value"].is_object())
                continue;
            const int64_t index = write["register"].get<int64_t>();
            if (index < std::min(*from, *to) || index > std::max(*from, *to) ||
                write["value"].value("type", "") != "nil")
                return true;
        }
    }
    return false;
}

bool luraphObservedValuesEqual(const json& left, const json& right)
{
    if (!left.is_object() || !right.is_object() || left.value("type", "") != right.value("type", ""))
        return false;
    const std::string type = left.value("type", "");
    if (type == "nil")
        return true;
    if (type == "string")
        return left.contains("bytes_hex") && left["bytes_hex"].is_string() &&
            right.contains("bytes_hex") && right["bytes_hex"].is_string() &&
            left["bytes_hex"] == right["bytes_hex"];
    if (type == "number" || type == "boolean")
        return left.value("value", "") == right.value("value", "");
    if (type == "global_reference")
        return left.value("path", "") == right.value("path", "") && !left.value("path", "").empty();
    return false;
}

std::optional<double> luraphObservedExpressionNumber(const json& expression)
{
    if (!expression.is_object())
        return std::nullopt;
    const std::string kind = expression.value("kind", "");
    if (kind == "constant" && expression.contains("value") && expression["value"].is_number())
        return expression["value"].get<double>();
    if (kind == "immediate" && expression.contains("value") && expression["value"].is_object() &&
        expression["value"].value("type", "") == "number" &&
        expression["value"].contains("value") && expression["value"]["value"].is_string())
    {
        try
        {
            size_t consumed = 0;
            const std::string encoded = expression["value"]["value"].get<std::string>();
            const double value = std::stod(encoded, &consumed);
            return consumed == encoded.size() ? std::optional<double>(value) : std::nullopt;
        }
        catch (const std::exception&)
        {
            return std::nullopt;
        }
    }
    if (kind != "binary")
        return std::nullopt;
    const std::optional<double> left = luraphObservedExpressionNumber(expression.value("left", json(nullptr)));
    const std::optional<double> right = luraphObservedExpressionNumber(expression.value("right", json(nullptr)));
    if (!left || !right)
        return std::nullopt;
    const std::string operation = expression.value("operator", "");
    if (operation == "+")
        return *left + *right;
    if (operation == "-")
        return *left - *right;
    if (operation == "*")
        return *left * *right;
    if (operation == "/" && *right != 0.0)
        return *left / *right;
    return std::nullopt;
}

bool luraphObservedExpressionMatches(const json& expression, const json& observed)
{
    if (!expression.is_object() || !observed.is_object())
        return false;
    const std::string kind = expression.value("kind", "");
    if (kind == "immediate" && expression.contains("value") && expression["value"].is_object())
        return luraphObservedValuesEqual(expression["value"], observed);
    if (kind == "constant" && expression.contains("value"))
    {
        const json& value = expression["value"];
        if (value.is_null())
            return observed.value("type", "") == "nil";
        if (value.is_boolean())
            return observed.value("type", "") == "boolean" &&
                observed.value("value", "") == (value.get<bool>() ? "true" : "false");
        if (value.is_string())
            return observed.value("type", "") == "string" && observed.value("value", "") == value.get<std::string>();
    }
    const std::optional<double> expectedNumber = luraphObservedExpressionNumber(expression);
    if (!expectedNumber || observed.value("type", "") != "number" ||
        !observed.contains("value") || !observed["value"].is_string())
        return false;
    try
    {
        size_t consumed = 0;
        const std::string encoded = observed["value"].get<std::string>();
        const double actualNumber = std::stod(encoded, &consumed);
        return consumed == encoded.size() &&
            (std::isnan(*expectedNumber) ? std::isnan(actualNumber) : actualNumber == *expectedNumber);
    }
    catch (const std::exception&)
    {
        return false;
    }
}

std::optional<json> validateLuraphObservedCandidate(
    const json& operation,
    const std::vector<json>& observations,
    size_t pc,
    const std::vector<json>* observedReturns)
{
    if (!operation.is_object() ||
        operation.value("protector_state", false) ||
        !operation.value("source_semantic", true) ||
        luraphSemanticContainsUnknownState(operation))
        return std::nullopt;

    const std::string kind = operation.value("kind", "");
    if (kind == "operation_sequence")
    {
        const json& operations = operation.value("operations", json::array());
        if (!operations.is_array() || operations.empty())
            return std::nullopt;

        const json* principal = nullptr;
        int64_t pcAdjustment = 0;
        size_t validatedOperations = 0;
        for (const json& item : operations)
        {
            if (!item.is_object())
                return std::nullopt;
            if (item.value("kind", "") == "compound_write" &&
                item.value("target", json::object()).value("kind", "") == "program_counter")
            {
                const std::optional<double> value = luraphObservedExpressionNumber(
                    item.value("value", json(nullptr)));
                if (!value || !std::isfinite(*value) || std::floor(*value) != *value)
                    return std::nullopt;
                const int64_t adjustment = static_cast<int64_t>(*value);
                const std::string operatorName = item.value("operator", "");
                if (operatorName == "+")
                    pcAdjustment += adjustment;
                else if (operatorName == "-")
                    pcAdjustment -= adjustment;
                else
                    return std::nullopt;
                ++validatedOperations;
                continue;
            }
            if (principal)
                return std::nullopt;
            principal = &item;
        }
        if (!principal)
            return std::nullopt;

        std::optional<json> principalValidation = validateLuraphObservedCandidate(
            *principal, observations, pc, observedReturns);
        if (!principalValidation)
            return std::nullopt;
        const std::string principalKind = principal->value("kind", "");
        if (principalKind == "jump")
        {
            if (principalValidation->value("target_adjustment", std::numeric_limits<int64_t>::min()) !=
                pcAdjustment)
                return std::nullopt;
        }
        else if (principalKind == "register_write")
        {
            for (const json& observation : observations)
                if (observation.value("next_pc", std::numeric_limits<int64_t>::min()) !=
                    static_cast<int64_t>(pc) + pcAdjustment)
                    return std::nullopt;
        }
        else if (pcAdjustment != 0)
            return std::nullopt;

        const size_t observationCount = principalValidation->value(
            "observation_count", observations.size());
        return json{
            {"proof", "observed_complete_operation_sequence"},
            {"validated_fields", json::array({"operations", "register_writes", "next_pc"})},
            {"validated_operations", validatedOperations + 1},
            {"pc_adjustment", pcAdjustment},
            {"principal_validation", std::move(*principalValidation)},
            {"observation_count", observationCount},
        };
    }
    if (kind == "return")
    {
        if (!observedReturns || observedReturns->empty() ||
            !operation.contains("values") || !operation["values"].is_array())
            return std::nullopt;
        const json& expectedValues = operation["values"];
        size_t matchedReturns = 0;
        for (const json& returned : *observedReturns)
        {
            if (!returned.value("complete", false) ||
                returned.value("arity", std::numeric_limits<size_t>::max()) != expectedValues.size() ||
                !returned.contains("values") || !returned["values"].is_array() ||
                returned["values"].size() != expectedValues.size())
                return std::nullopt;
            for (size_t index = 0; index < expectedValues.size(); ++index)
                if (!luraphObservedExpressionMatches(expectedValues[index], returned["values"][index]))
                    return std::nullopt;
            ++matchedReturns;
        }
        return json{
            {"proof", "observed_return_arity_and_values"},
            {"validated_fields", json::array({"arity", "values"})},
            {"observation_count", matchedReturns},
        };
    }

    if (observations.empty())
        return std::nullopt;
    if (kind == "register_write")
    {
        const std::optional<int64_t> destination = luraphMaterializedRegisterIndex(operation);
        if (!destination || !operation.contains("value") || !operation["value"].is_object())
            return std::nullopt;

        const json& value = operation["value"];
        std::optional<json> expectedValue;
        std::optional<int64_t> expectedRegisterOrigin;
        if (value.value("kind", "") == "immediate" && value.contains("value") &&
            value["value"].is_object() && value["value"].value("primitive", false))
            expectedValue = value["value"];
        else if (value.value("kind", "") == "register_read")
            expectedRegisterOrigin = luraphMaterializedImmediateInteger(value.value("index", json(nullptr)));
        else
            return std::nullopt;

        size_t matchedWrites = 0;
        for (const json& observation : observations)
        {
            const json writes = observation.value("register_writes", json::array());
            if (!writes.is_array() || writes.size() != 1 || !writes[0].is_object() ||
                writes[0].value("register", std::numeric_limits<int64_t>::min()) != *destination ||
                !writes[0].contains("value") || !writes[0]["value"].is_object())
                return std::nullopt;

            if (expectedValue)
            {
                if (!luraphObservedValuesEqual(*expectedValue, writes[0]["value"]))
                    return std::nullopt;
            }
            else
            {
                const json origins = observation.value("write_origins", json::object());
                const auto origin = origins.is_object()
                    ? origins.find(std::to_string(*destination)) : origins.end();
                if (origin == origins.end() || !origin->is_array() || origin->size() != 1 ||
                    !(*origin)[0].is_object() || (*origin)[0].value("kind", "") != "register" ||
                    (*origin)[0].value("index", std::numeric_limits<int64_t>::min()) != *expectedRegisterOrigin)
                    return std::nullopt;
            }
            ++matchedWrites;
        }

        return json{
            {"proof", expectedValue ? "observed_destination_and_value" : "observed_destination_and_register_origin"},
            {"validated_fields", expectedValue
                ? json::array({"destination_register", "written_value"})
                : json::array({"destination_register", "source_register"})},
            {"observation_count", matchedWrites},
        };
    }

    if (kind == "jump")
    {
        const std::optional<int64_t> target = luraphMaterializedImmediateInteger(
            operation.value("target", json(nullptr)));
        if (!target)
            return std::nullopt;
        std::optional<int64_t> adjustment;
        for (const json& observation : observations)
        {
            const int64_t nextPc = observation.value("next_pc", int64_t(-1));
            std::optional<int64_t> currentAdjustment;
            for (int64_t candidate : {int64_t(0), int64_t(1)})
                if (*target + candidate == nextPc)
                {
                    currentAdjustment = candidate;
                    break;
                }
            if (!currentAdjustment || (adjustment && *adjustment != *currentAdjustment))
                return std::nullopt;
            adjustment = currentAdjustment;
        }
        if (!adjustment || *target + *adjustment == static_cast<int64_t>(pc + 1))
            return std::nullopt;
        return json{
            {"proof", "observed_control_transfer_target"},
            {"validated_fields", json::array({"target"})},
            {"target_adjustment", *adjustment},
            {"observation_count", observations.size()},
        };
    }

    return std::nullopt;
}

std::optional<size_t> luraphMaterializedNonnegativeSize(const json& expression)
{
    const std::optional<double> value = luraphObservedExpressionNumber(expression);
    if (!value || !std::isfinite(*value) || std::floor(*value) != *value || *value < 0.0 ||
        *value > static_cast<double>(std::numeric_limits<size_t>::max()))
        return std::nullopt;
    return static_cast<size_t>(*value);
}

std::optional<json> validateLuraphObservedIncompleteCallCandidate(
    const json& operation,
    const std::vector<json>& observations,
    const std::vector<json>& childActivations,
    size_t pc)
{
    if (!operation.is_object() || operation.value("kind", "") != "operation_sequence" ||
        operation.value("protector_state", false) || luraphSemanticContainsUnknownState(operation) ||
        observations.empty() || childActivations.size() != observations.size())
        return std::nullopt;
    const json& operations = operation.value("operations", json::array());
    if (!operations.is_array() || operations.empty())
        return std::nullopt;

    const json* call = nullptr;
    std::optional<int64_t> resultRegister;
    std::optional<size_t> currentTop;
    std::optional<size_t> callTop;
    size_t topAssignments = 0;
    for (const json& item : operations)
    {
        if (!item.is_object())
            return std::nullopt;
        const std::string kind = item.value("kind", "");
        if (kind == "set_top")
        {
            currentTop = luraphMaterializedNonnegativeSize(item.value("value", json(nullptr)));
            if (!currentTop)
                return std::nullopt;
            ++topAssignments;
            continue;
        }

        const json* candidateCall = nullptr;
        if (kind == "expression" && item.contains("value") && item["value"].is_object() &&
            item["value"].value("kind", "") == "call")
            candidateCall = &item["value"];
        else if (kind == "register_write" && item.contains("value") && item["value"].is_object() &&
            item["value"].value("kind", "") == "call")
        {
            resultRegister = luraphMaterializedRegisterIndex(item);
            if (!resultRegister || *resultRegister < 0)
                return std::nullopt;
            candidateCall = &item["value"];
        }
        if (!candidateCall || call)
            return std::nullopt;
        call = candidateCall;
        callTop = currentTop;
    }
    if (!call || call->value("method", false) || !call->contains("function") ||
        !(*call)["function"].is_object() || (*call)["function"].value("kind", "") != "register_read" ||
        !luraphMaterializedNonnegativeSize((*call)["function"].value("index", json(nullptr))) ||
        !call->contains("arguments") || !(*call)["arguments"].is_array())
        return std::nullopt;

    size_t argumentCount = 0;
    const json& arguments = (*call)["arguments"];
    if (arguments.size() == 1 && arguments.front().is_object() &&
        arguments.front().value("kind", "") == "register_range")
    {
        const json& range = arguments.front();
        const std::optional<size_t> begin = luraphMaterializedNonnegativeSize(
            range.value("from", json(nullptr)));
        std::optional<size_t> end;
        const json& endExpression = range.value("to", json(nullptr));
        if (endExpression.is_object() && endExpression.value("kind", "") == "top_register")
            end = callTop;
        else
            end = luraphMaterializedNonnegativeSize(endExpression);
        if (!begin || !end)
            return std::nullopt;
        argumentCount = *end < *begin ? 0 : *end - *begin + 1;
    }
    else
    {
        for (const json& argument : arguments)
            if (!argument.is_object() || argument.value("kind", "") != "register_read" ||
                !luraphMaterializedNonnegativeSize(argument.value("index", json(nullptr))))
                return std::nullopt;
        argumentCount = arguments.size();
    }

    std::set<uint64_t> callees;
    for (const json& child : childActivations)
    {
        if (!child.is_object() || child.value("argument_count", std::numeric_limits<size_t>::max()) != argumentCount)
            return std::nullopt;
        const uint64_t prototype = child.value("prototype", uint64_t(0));
        if (prototype == 0)
            return std::nullopt;
        callees.insert(prototype);
    }
    if (callees.size() != 1)
        return std::nullopt;

    for (const json& observation : observations)
    {
        if (observation.value("next_pc", std::numeric_limits<int64_t>::min()) !=
            static_cast<int64_t>(pc + 1))
            return std::nullopt;
        const json& writes = observation.value("register_writes", json::array());
        if (!writes.is_array())
            return std::nullopt;
        if (resultRegister)
        {
            if (writes.size() != 1 || !writes.front().is_object() ||
                writes.front().value("register", std::numeric_limits<int64_t>::min()) != *resultRegister)
                return std::nullopt;
        }
        else if (!writes.empty())
            return std::nullopt;
    }

    return json{
        {"proof", "observed_child_call_frame_and_parent_result"},
        {"validated_fields", json::array({
            "callee_prototype", "argument_count", "result_register", "register_writes", "next_pc",
        })},
        {"observation_count", observations.size()},
        {"callee_prototype", *callees.begin()},
        {"argument_count", argumentCount},
        {"result_register", resultRegister ? json(*resultRegister) : json(nullptr)},
        {"top_assignments", topAssignments},
        {"incomplete_handler_path", true},
        {"source_claim", false},
    };
}

std::optional<int64_t> luraphObservedInteger(const json& value)
{
    if (!value.is_object() || value.value("type", "") != "number" ||
        !value.contains("value") || !value["value"].is_string())
        return std::nullopt;
    return parseTraceInteger<int64_t>(value["value"].get<std::string>());
}

template<typename Value>
void intersectLuraphEvidence(std::optional<std::set<Value>>& retained, std::set<Value> candidates)
{
    if (!retained)
    {
        retained = std::move(candidates);
        return;
    }
    std::set<Value> intersection;
    std::set_intersection(retained->begin(), retained->end(), candidates.begin(), candidates.end(),
        std::inserter(intersection, intersection.begin()));
    retained = std::move(intersection);
}

enum class LuraphObservationalRuleKind
{
    None,
    Jump,
    LoadConstant,
    Move,
    Closure,
};

struct LuraphObservationalOpcodeRule
{
    LuraphObservationalRuleKind kind = LuraphObservationalRuleKind::None;
    std::string destination_lane;
    std::string value_lane;
    std::string source_lane;
    std::string target_lane;
    std::string descriptor_lane;
    int64_t target_adjustment = 0;
    size_t observations = 0;
    size_t write_observations = 0;
    size_t unchanged_observations = 0;
    size_t sites = 0;
};

std::map<int64_t, LuraphObservationalOpcodeRule> inferLuraphObservationalOpcodeRules(
    const LuraphRuntimeStructureTrace& trace)
{
    std::map<int64_t, std::vector<const json*>> byOpcode;
    for (const json& step : trace.steps)
        if (step.is_object() && step.contains("opcode") && step["opcode"].is_number_integer())
            byOpcode[step["opcode"].get<int64_t>()].push_back(&step);

    std::map<int64_t, LuraphObservationalOpcodeRule> rules;
    for (const auto& [opcode, observations] : byOpcode)
    {
        std::optional<std::set<std::pair<std::string, int64_t>>> transferCandidates;
        std::optional<std::set<std::string>> destinationCandidates;
        std::optional<std::set<std::string>> constantCandidates;
        std::optional<std::set<std::string>> moveSourceLaneCandidates;
        std::optional<std::set<std::string>> closureDescriptorLaneCandidates;
        std::optional<std::set<std::string>> closureTargetLaneCandidates;
        std::set<std::string> distinctConstants;
        std::set<std::pair<uint64_t, int64_t>> sites;
        size_t writeObservations = 0;
        size_t unchangedObservations = 0;
        size_t moveEvidence = 0;
        bool transferValid = observations.size() >= 3;
        bool constantValid = observations.size() >= 3;
        bool moveValid = observations.size() >= 3;
        bool closureValid = observations.size() >= 3;
        bool sawNonFallthrough = false;

        for (const json* observation : observations)
        {
            const uint64_t activation = observation->value("activation", uint64_t(0));
            const int64_t pc = observation->value("pc", int64_t(-1));
            const int64_t nextPc = observation->value("next_pc", int64_t(-1));
            sites.emplace(activation, pc);
            sawNonFallthrough = sawNonFallthrough || nextPc != pc + 1;
            const json lanes = observation->value("runtime_lanes", json::object());
            const json writes = observation->value("register_writes", json::array());
            auto activationRow = trace.activations.find(activation);
            const uint64_t prototype = activationRow == trace.activations.end()
                ? 0 : activationRow->second.value("prototype", uint64_t(0));

            std::set<std::pair<std::string, int64_t>> localTransfers;
            if (lanes.is_object())
                for (auto lane = lanes.begin(); lane != lanes.end(); ++lane)
                    if (const std::optional<int64_t> value = luraphObservedInteger(lane.value()))
                        for (int64_t adjustment : {int64_t(0), int64_t(1)})
                            if (*value + adjustment == nextPc)
                                localTransfers.emplace(lane.key(), adjustment);
            intersectLuraphEvidence(transferCandidates, std::move(localTransfers));
            transferValid = transferValid && writes.is_array() && writes.empty();

            if (!writes.is_array() || writes.size() > 1 || nextPc != pc + 1)
            {
                constantValid = false;
                moveValid = false;
                closureValid = false;
                continue;
            }
            if (writes.empty())
            {
                ++unchangedObservations;
                closureValid = false;
                continue;
            }
            ++writeObservations;
            const json& write = writes.front();
            if (!write.contains("register") || !write["register"].is_number_integer() ||
                !write.contains("value") || !write["value"].is_object())
            {
                constantValid = false;
                moveValid = false;
                closureValid = false;
                continue;
            }
            const int64_t destination = write["register"].get<int64_t>();
            const json& writtenValue = write["value"];
            std::set<std::string> localDestinations;
            std::set<std::string> localConstants;
            if (lanes.is_object())
                for (auto lane = lanes.begin(); lane != lanes.end(); ++lane)
                {
                    if (luraphObservedInteger(lane.value()) == destination)
                        localDestinations.insert(lane.key());
                    if (luraphObservedValuesEqual(lane.value(), writtenValue))
                        localConstants.insert(lane.key());
                }
            intersectLuraphEvidence(destinationCandidates, std::move(localDestinations));
            intersectLuraphEvidence(constantCandidates, std::move(localConstants));
            if (writtenValue.value("primitive", false))
                distinctConstants.insert(writtenValue.value("type", "") + ":" + writtenValue.dump());
            else
                constantValid = false;

            std::set<std::string> localMoveSources;
            const json origins = observation->value("write_origins", json::object());
            const auto origin = origins.is_object() ? origins.find(std::to_string(destination)) : origins.end();
            if (origin != origins.end() && origin->is_array() && origin->size() == 1 &&
                (*origin)[0].value("kind", "") == "register" && (*origin)[0].contains("index") &&
                (*origin)[0]["index"].is_number_integer())
            {
                const int64_t source = (*origin)[0]["index"].get<int64_t>();
                for (auto lane = lanes.begin(); lane != lanes.end(); ++lane)
                    if (luraphObservedInteger(lane.value()) == source)
                        localMoveSources.insert(lane.key());
                ++moveEvidence;
            }
            else
                moveValid = false;
            intersectLuraphEvidence(moveSourceLaneCandidates, std::move(localMoveSources));

            std::set<std::string> localDescriptorLanes;
            std::set<std::string> localTargetLanes;
            const auto descriptor = prototype > 0
                ? trace.closure_descriptors.find({prototype, static_cast<size_t>(pc)})
                : trace.closure_descriptors.end();
            if (writtenValue.value("type", "") != "function" || descriptor == trace.closure_descriptors.end() ||
                descriptor->second.value("destination_register", std::numeric_limits<int64_t>::min()) != destination)
                closureValid = false;
            else if (lanes.is_object())
            {
                const std::string structuralLane = descriptor->second.value("descriptor_lane", "");
                if (!structuralLane.empty() && lanes.contains(structuralLane) &&
                    lanes[structuralLane].value("type", "") == "table")
                    localDescriptorLanes.insert(structuralLane);
                for (auto lane = lanes.begin(); lane != lanes.end(); ++lane)
                    if (const std::optional<int64_t> value = luraphObservedInteger(lane.value());
                        value && *value > 0)
                        localTargetLanes.insert(lane.key());
            }
            intersectLuraphEvidence(closureDescriptorLaneCandidates, std::move(localDescriptorLanes));
            intersectLuraphEvidence(closureTargetLaneCandidates, std::move(localTargetLanes));
        }

        LuraphObservationalOpcodeRule rule;
        rule.observations = observations.size();
        rule.write_observations = writeObservations;
        rule.unchanged_observations = unchangedObservations;
        rule.sites = sites.size();
        if (destinationCandidates && destinationCandidates->size() == 1 && closureTargetLaneCandidates)
            closureTargetLaneCandidates->erase(*destinationCandidates->begin());
        if (closureValid && destinationCandidates && destinationCandidates->size() == 1 &&
            closureDescriptorLaneCandidates && closureDescriptorLaneCandidates->size() == 1 &&
            closureTargetLaneCandidates && closureTargetLaneCandidates->size() == 1 && sites.size() >= 2)
        {
            rule.kind = LuraphObservationalRuleKind::Closure;
            rule.destination_lane = *destinationCandidates->begin();
            rule.descriptor_lane = *closureDescriptorLaneCandidates->begin();
            rule.target_lane = *closureTargetLaneCandidates->begin();
        }
        else if (transferValid && sawNonFallthrough && transferCandidates && transferCandidates->size() == 1 && sites.size() >= 2)
        {
            rule.kind = LuraphObservationalRuleKind::Jump;
            rule.target_lane = transferCandidates->begin()->first;
            rule.target_adjustment = transferCandidates->begin()->second;
        }
        else if (moveValid && moveEvidence >= 2 && destinationCandidates && destinationCandidates->size() == 1 &&
            moveSourceLaneCandidates && moveSourceLaneCandidates->size() == 1 && sites.size() >= 2)
        {
            rule.kind = LuraphObservationalRuleKind::Move;
            rule.destination_lane = *destinationCandidates->begin();
            rule.source_lane = *moveSourceLaneCandidates->begin();
        }
        else if (constantValid && writeObservations >= 2 && distinctConstants.size() >= 2 &&
            destinationCandidates && destinationCandidates->size() == 1 && constantCandidates &&
            constantCandidates->size() == 1 && *destinationCandidates->begin() != *constantCandidates->begin() &&
            sites.size() >= 2)
        {
            rule.kind = LuraphObservationalRuleKind::LoadConstant;
            rule.destination_lane = *destinationCandidates->begin();
            rule.value_lane = *constantCandidates->begin();
        }
        if (rule.kind != LuraphObservationalRuleKind::None)
            rules[opcode] = std::move(rule);
    }
    return rules;
}

json inferLuraphObservationalSiteOperation(
    uint64_t prototype,
    size_t pc,
    int64_t opcode,
    const std::vector<json>& observations,
    const std::vector<json>* returned,
    const std::vector<json>* children,
    const json* closureDescriptor,
    const std::map<int64_t, LuraphObservationalOpcodeRule>& opcodeRules,
    const LuraphRuntimeStructureTrace& trace)
{
    const auto evidence = [&](std::string_view family) {
        return json{{"semantic_family", family}, {"proof", "complete_observation_set"},
            {"path_specific", true}, {"static_semantic", false}, {"prototype", prototype},
            {"pc", pc}, {"opcode", opcode}, {"observation_count", observations.size()}};
    };
    if (returned && !returned->empty())
    {
        json operation = evidence("return");
        operation["kind"] = "return";
        operation["observed_returns"] = *returned;
        operation["values"] = json::array();
        return operation;
    }
    if (children && !children->empty())
    {
        json operation = evidence("call");
        operation["kind"] = "call";
        operation["callee_activations"] = *children;
        std::set<uint64_t> prototypes;
        for (const json& child : *children)
            if (child.value("prototype", uint64_t(0)) > 0)
                prototypes.insert(child.value("prototype", uint64_t(0)));
        operation["callee_prototypes"] = prototypes;
        return operation;
    }
    if (closureDescriptor && closureDescriptor->value("complete", false) && !observations.empty())
    {
        const int64_t destination = closureDescriptor->value("destination_register", std::numeric_limits<int64_t>::min());
        bool complete = destination != std::numeric_limits<int64_t>::min();
        for (const json& observation : observations)
        {
            const json writes = observation.value("register_writes", json::array());
            complete = complete && writes.is_array() && writes.size() == 1 &&
                writes[0].value("register", std::numeric_limits<int64_t>::min()) == destination &&
                writes[0].contains("value") && writes[0]["value"].is_object() &&
                writes[0]["value"].value("type", "") == "function";
        }
        if (complete)
        {
            json operation = evidence("closure");
            operation["kind"] = "closure";
            operation["descriptor"] = *closureDescriptor;
            operation["destination_register"] = destination;
            return operation;
        }
    }

    std::set<int64_t> nextPcs;
    for (const json& observation : observations)
        nextPcs.insert(observation.value("next_pc", int64_t(-1)));
    if (nextPcs.size() > 1)
    {
        json operation = evidence("branch");
        operation["kind"] = "branch";
        operation["condition"] = nullptr;
        operation["observed_targets"] = nextPcs;
        return operation;
    }

    bool argumentCopy = !observations.empty();
    bool varyingArity = false;
    std::set<size_t> arities;
    size_t argumentWrites = 0;
    std::optional<std::map<int64_t, int64_t>> argumentBindings;
    for (const json& observation : observations)
    {
        const uint64_t activation = observation.value("activation", uint64_t(0));
        if (auto activationRow = trace.activations.find(activation); activationRow != trace.activations.end())
            arities.insert(activationRow->second.value("argument_count", size_t(0)));
        const json writes = observation.value("register_writes", json::array());
        const json origins = observation.value("write_origins", json::object());
        std::map<int64_t, int64_t> observedBindings;
        if (!writes.is_array())
        {
            argumentCopy = false;
            break;
        }
        for (const json& write : writes)
        {
            const int64_t destination = write.value("register", std::numeric_limits<int64_t>::min());
            const auto origin = origins.is_object() ? origins.find(std::to_string(destination)) : origins.end();
            if (destination == std::numeric_limits<int64_t>::min() || origin == origins.end() ||
                !origin->is_array() || origin->size() != 1 || (*origin)[0].value("kind", "") != "argument")
            {
                argumentCopy = false;
                break;
            }
            const int64_t argument = (*origin)[0].value(
                "index", std::numeric_limits<int64_t>::min());
            if (argument <= 0 || !observedBindings.emplace(destination, argument).second)
            {
                argumentCopy = false;
                break;
            }
            ++argumentWrites;
        }
        if (!argumentCopy)
            break;
        if (!argumentBindings)
            argumentBindings = std::move(observedBindings);
        else if (*argumentBindings != observedBindings)
        {
            argumentCopy = false;
            break;
        }
    }
    varyingArity = arities.size() > 1;
    if (argumentCopy && argumentWrites > 0 && argumentBindings && !argumentBindings->empty())
    {
        json operation = evidence(varyingArity ? "varargs" : "arguments");
        operation["kind"] = varyingArity ? "capture_varargs" : "load_arguments";
        operation["observed_argument_arities"] = arities;
        operation["write_count"] = argumentWrites;
        json bindings = json::array();
        for (const auto& [destination, argument] : *argumentBindings)
            bindings.push_back({
                {"argument_index", argument},
                {"destination_register", destination},
                {"proof", "complete_write_origin_set"},
            });
        operation["argument_bindings"] = std::move(bindings);
        return operation;
    }

    auto rule = opcodeRules.find(opcode);
    if (rule == opcodeRules.end())
        return nullptr;
    const LuraphObservationalOpcodeRule& proven = rule->second;
    json operation = evidence(proven.kind == LuraphObservationalRuleKind::Jump ? "jump" :
        proven.kind == LuraphObservationalRuleKind::LoadConstant ? "load_constant" :
        proven.kind == LuraphObservationalRuleKind::Closure ? "closure" : "move");
    operation["opcode_observations"] = proven.observations;
    operation["opcode_sites"] = proven.sites;
    operation["unchanged_observations"] = proven.unchanged_observations;
    if (proven.kind == LuraphObservationalRuleKind::Jump)
    {
        operation["kind"] = "jump";
        operation["target"] = {{"kind", "operand"}, {"lane", proven.target_lane},
            {"adjustment", proven.target_adjustment}};
    }
    else if (proven.kind == LuraphObservationalRuleKind::Closure)
    {
        operation["kind"] = "closure";
        operation["destination"] = {{"kind", "operand"}, {"lane", proven.destination_lane}};
        operation["descriptor"] = {{"kind", "operand"}, {"lane", proven.descriptor_lane}};
        operation["prototype_index"] = {{"kind", "operand"}, {"lane", proven.target_lane}};
        operation["target_prototype"] = nullptr;
        operation["captures"] = nullptr;
    }
    else
    {
        operation["kind"] = "register_write";
        operation["register"] = {{"kind", "operand"}, {"lane", proven.destination_lane}};
        if (proven.kind == LuraphObservationalRuleKind::LoadConstant)
            operation["value"] = {{"kind", "operand"}, {"lane", proven.value_lane}};
        else
            operation["value"] = {{"kind", "register_read"},
                {"index", {{"kind", "operand"}, {"lane", proven.source_lane}}}};
    }
    return operation;
}

std::optional<json> recognizeLuraphOpcode161TwoArgumentCall(
    uint64_t prototype,
    size_t pc,
    const json& effectiveLanes,
    const std::vector<json>& observations,
    const std::vector<json>& childActivations)
{
    const auto lane = effectiveLanes.find("S");
    const std::optional<int64_t> base = lane == effectiveLanes.end()
        ? std::nullopt : luraphObservedInteger(*lane);
    if (!base || *base < 0 || *base > std::numeric_limits<int64_t>::max() - 2 ||
        observations.empty() || childActivations.size() != observations.size())
        return std::nullopt;
    for (const json& observation : observations)
    {
        const json& writes = observation.value("register_writes", json::array());
        if (observation.value("next_pc", std::numeric_limits<int64_t>::min()) !=
                static_cast<int64_t>(pc + 1) ||
            !writes.is_array() || writes.size() != 1 || !writes.front().is_object() ||
            writes.front().value("register", std::numeric_limits<int64_t>::min()) != *base)
            return std::nullopt;
    }
    std::set<uint64_t> callees;
    for (const json& child : childActivations)
    {
        if (!child.is_object() || child.value("argument_count", size_t(0)) != 2)
            return std::nullopt;
        const uint64_t callee = child.value("prototype", uint64_t(0));
        if (callee == 0)
            return std::nullopt;
        callees.insert(callee);
    }
    if (callees.size() != 1)
        return std::nullopt;

    const auto constant = [](int64_t value) {
        return json{{"kind", "constant"}, {"value", value}};
    };
    const auto registerRead = [&](int64_t value) {
        return json{{"kind", "register_read"}, {"index", constant(value)}};
    };
    return json{
        {"kind", "operation_sequence"},
        {"semantic_family", "call"},
        {"opcode", 161},
        {"prototype", prototype},
        {"pc", pc},
        {"path_specific", true},
        {"static_semantic", false},
        {"source_claim", false},
        {"proof", "handler_shape_and_child_call_frame_runtime_validated"},
        {"observation_count", observations.size()},
        {"callee_prototype", *callees.begin()},
        {"operations", json::array({
            {
                {"kind", "register_write"},
                {"register", constant(*base)},
                {"value", {
                    {"kind", "call"},
                    {"method", false},
                    {"function", registerRead(*base)},
                    {"arguments", json::array({registerRead(*base + 1), registerRead(*base + 2)})},
                }},
            },
            {{"kind", "set_top"}, {"value", constant(*base)}},
        })},
        {"runtime_validation", {
            {"validated_fields", json::array({
                "callee_prototype", "argument_count", "destination_register", "next_pc",
            })},
            {"argument_count", 2},
            {"destination_register", *base},
            {"top_after", *base},
        }},
    };
}

json luraphOpcode8RangeArtifact(
    const luraph::call_semantics::RegisterRange& range)
{
    return {
        {"begin", range.begin},
        {"end_exclusive", range.end_exclusive ? json(*range.end_exclusive) : json(nullptr)},
        {"dynamic_end", !range.end_exclusive.has_value()},
    };
}

json luraphOpcode8CallArtifact(
    const luraph::call_semantics::Opcode8CallSemantics& semantics,
    luraph::call_semantics::GuardPathProof proof,
    size_t observationCount)
{
    const bool pathSpecific = proof == luraph::call_semantics::GuardPathProof::RuntimeObserved;
    json operation = {
        {"kind", "call"},
        {"semantic_family", "call"},
        {"opcode", 8},
        {"source_semantic", true},
        {"static_semantic", !pathSpecific},
        {"path_specific", pathSpecific},
        {"proof", pathSpecific
            ? "complete_runtime_guard_path_and_packed_handler_shape"
            : "complete_static_guard_path_and_packed_handler_shape"},
        {"guard_path_proof", luraph::call_semantics::toString(proof)},
        {"function_register", semantics.function_register},
        {"result_base_register", semantics.result_base_register},
        {"callee", {
            {"kind", "register_read"},
            {"index", semantics.function_register},
        }},
        {"encoded_argument_count", semantics.encoded_argument_count},
        {"encoded_result_count", semantics.encoded_result_count},
        {"argument_pack", {
            {"mode", luraph::call_semantics::toString(semantics.arguments.mode)},
            {"registers", luraphOpcode8RangeArtifact(semantics.arguments.registers)},
            {"count", semantics.arguments.count ? json(*semantics.arguments.count) : json(nullptr)},
        }},
        {"result_placement", {
            {"mode", luraph::call_semantics::toString(semantics.results.mode)},
            {"actual_result_arity", semantics.results.actual_result_arity
                ? json(*semantics.results.actual_result_arity) : json(nullptr)},
            {"requested_count", semantics.results.requested_count
                ? json(*semantics.results.requested_count) : json(nullptr)},
            {"logical_registers", luraphOpcode8RangeArtifact(semantics.results.logical_registers)},
            {"assignment_registers", luraphOpcode8RangeArtifact(semantics.results.assignment_registers)},
            {"assignment_count", semantics.results.assignment_count
                ? json(*semantics.results.assignment_count) : json(nullptr)},
            {"top_after", semantics.results.top_after ? json(*semantics.results.top_after) : json(nullptr)},
            {"nil_pads_missing_values", semantics.results.nil_pads_missing_values},
            {"truncates_extra_values", semantics.results.truncates_extra_values},
            {"encoded_one_loop_bound_anomaly", semantics.results.encoded_one_loop_bound_anomaly},
        }},
        // The current source emitter has no sound lowering for a dynamic register
        // result range. Keeping its legacy `arguments` field absent makes it fail
        // closed until the result-placement contract is implemented there.
        {"emission_status", "requires_register_call_result_lowering"},
        {"runtime_validated", semantics.runtime_validated},
        {"observation_count", observationCount},
    };
    if (pathSpecific)
        operation["candidate_only"] = true;
    return operation;
}

struct LuraphOpcode8PipelineRecognition
{
    json operation = nullptr;
    bool static_semantic = false;
    size_t validated_observations = 0;
    std::string status = "not_attempted";
    std::string diagnostic;
};

LuraphOpcode8PipelineRecognition recognizeLuraphOpcode8PipelineCall(
    const json& handler,
    const json& effectiveLanes,
    const std::vector<json>* observations)
{
    LuraphOpcode8PipelineRecognition output;
    const json shape = handler.value("opcode8_call_shape", json(nullptr));
    if (!shape.is_object() || !shape.value("verified", false))
    {
        output.status = "insufficient_evidence";
        output.diagnostic = "packed opcode-8 handler shape is not structurally verified";
        return output;
    }
    const auto laneInteger = [&](std::string_view field) -> std::optional<int64_t> {
        if (!shape.contains(std::string(field)) || !shape[std::string(field)].is_string())
            return std::nullopt;
        const std::string lane = shape[std::string(field)].get<std::string>();
        if (!effectiveLanes.is_object() || !effectiveLanes.contains(lane))
            return std::nullopt;
        return luraphObservedInteger(effectiveLanes[lane]);
    };
    const std::optional<int64_t> base = laneInteger("base_register_lane");
    const std::optional<int64_t> argumentCount = laneInteger("encoded_argument_count_lane");
    const std::optional<int64_t> resultCount = laneInteger("encoded_result_count_lane");
    if (!base || !argumentCount || !resultCount)
    {
        output.status = "invalid_evidence";
        output.diagnostic = "opcode-8 operand lanes are not complete non-negative integers";
        return output;
    }

    const auto recognize = [&](luraph::call_semantics::GuardPathProof proof,
                               const std::vector<int64_t>& changedRegisters) {
        luraph::call_semantics::Opcode8CallEvidence evidence;
        evidence.opcode = 8;
        evidence.packed_handler_shape_verified = true;
        evidence.guard_path_proof = proof;
        evidence.guard_path_complete = true;
        evidence.base_register = *base;
        evidence.encoded_argument_count = *argumentCount;
        evidence.encoded_result_count = *resultCount;
        evidence.observed_changed_registers = changedRegisters;
        return luraph::call_semantics::recognizeOpcode8Call(evidence);
    };

    if (shape.value("static_guard_path_complete", false))
    {
        const auto recognized = recognize(luraph::call_semantics::GuardPathProof::StaticallyProven, {});
        output.status = luraph::call_semantics::toString(recognized.status);
        output.diagnostic = recognized.diagnostic;
        if (recognized.semantics)
        {
            output.operation = luraphOpcode8CallArtifact(
                *recognized.semantics, luraph::call_semantics::GuardPathProof::StaticallyProven, 0);
            output.static_semantic = true;
        }
        return output;
    }

    if (!observations || observations->empty())
    {
        output.status = "insufficient_evidence";
        output.diagnostic = "opcode-8 site has neither a static proof nor runtime observations";
        return output;
    }

    std::optional<luraph::call_semantics::Opcode8CallSemantics> retained;
    for (const json& observation : *observations)
    {
        const json guardPath = observation.value("guard_path", json(nullptr));
        if (!guardPath.is_object() || !guardPath.value("complete", false) ||
            !guardPath.contains("decisions") || !guardPath["decisions"].is_array() ||
            guardPath["decisions"].empty())
        {
            output.status = "insufficient_evidence";
            output.diagnostic = "an observed opcode-8 execution lacks a complete guard path";
            return output;
        }
        const json writes = observation.value("register_writes", json::array());
        if (!writes.is_array())
        {
            output.status = "invalid_evidence";
            output.diagnostic = "opcode-8 changed-register evidence is not an array";
            return output;
        }
        std::vector<int64_t> changedRegisters;
        changedRegisters.reserve(writes.size());
        for (const json& write : writes)
        {
            if (!write.is_object() || !write.contains("register") || !write["register"].is_number_integer())
            {
                output.status = "invalid_evidence";
                output.diagnostic = "opcode-8 changed-register evidence has an invalid destination";
                return output;
            }
            changedRegisters.push_back(write["register"].get<int64_t>());
        }
        const auto recognized = recognize(
            luraph::call_semantics::GuardPathProof::RuntimeObserved, changedRegisters);
        if (!recognized.semantics)
        {
            output.status = luraph::call_semantics::toString(recognized.status);
            output.diagnostic = recognized.diagnostic;
            return output;
        }
        if (retained && (retained->function_register != recognized.semantics->function_register ||
                retained->encoded_argument_count != recognized.semantics->encoded_argument_count ||
                retained->encoded_result_count != recognized.semantics->encoded_result_count))
        {
            output.status = "contradictory_evidence";
            output.diagnostic = "opcode-8 operand semantics changed across observations of one site";
            return output;
        }
        retained = *recognized.semantics;
        ++output.validated_observations;
    }

    output.status = "recognized";
    output.diagnostic = "all observed opcode-8 executions have complete guard-path and write-range evidence";
    output.operation = luraphOpcode8CallArtifact(
        *retained, luraph::call_semantics::GuardPathProof::RuntimeObserved,
        output.validated_observations);
    return output;
}

struct LuraphExactLeafRecognition
{
    json operation = nullptr;
    std::string status = "insufficient_evidence";
    std::string diagnostic;
    size_t validated_observations = 0;
};

std::optional<int64_t> luraphRuntimeLaneInteger(const json& lanes, std::string_view name)
{
    if (!lanes.is_object() || !lanes.contains(std::string(name)))
        return std::nullopt;
    return luraphObservedInteger(lanes[std::string(name)]);
}

json luraphImmediateRuntimeLane(const json& lanes, std::string_view name)
{
    return {
        {"kind", "immediate"},
        {"lane", name},
        {"value", lanes.is_object() && lanes.contains(std::string(name))
            ? lanes[std::string(name)] : json(nullptr)},
    };
}

LuraphExactLeafRecognition recognizeLuraphOpcode28IndexRead(
    const json& effectiveLanes,
    const std::vector<json>* observations)
{
    LuraphExactLeafRecognition output;
    if (!observations || observations->empty())
    {
        output.diagnostic = "opcode-28 index read has no complete runtime guard-path observations";
        return output;
    }

    std::optional<luraph::index_read::RegisterTableIndexRead> retained;
    for (const json& observation : *observations)
    {
        const json runtimeLanes = observation.value("runtime_lanes", json::object());
        luraph::index_read::RuntimeOperands operands;
        operands.destination_register = luraphRuntimeLaneInteger(runtimeLanes, "r");
        operands.table_register = luraphRuntimeLaneInteger(runtimeLanes, "S");
        operands.index_operand_present = runtimeLanes.contains("V");

        luraph::index_read::ObservedGuardPathEvidence path;
        path.opcode = observation.value("opcode", int64_t(-1));
        path.selected_handler_begin = luraph::index_read::kExactFixtureLeafBegin;
        path.selected_handler_end = luraph::index_read::kExactFixtureLeafEnd;
        const json guardPath = observation.value("guard_path", json(nullptr));
        path.path_complete = guardPath.is_object() && guardPath.value("complete", false);
        path.path_overflow = guardPath.is_object() && guardPath.value("overflow", false);
        path.selected_handler_exactly = path.path_complete && !path.path_overflow;
        path.executed_statement_path_complete = path.selected_handler_exactly;
        path.full_effect_validation = path.selected_handler_exactly &&
            observation.value("next_pc", int64_t(-1)) == observation.value("pc", int64_t(-1)) + 1;
        path.lookup_attempt_observed = path.full_effect_validation;
        path.observation_count = 1;
        if (guardPath.is_object() && guardPath.contains("decisions") && guardPath["decisions"].is_array())
        {
            for (const json& decision : guardPath["decisions"])
            {
                if (!decision.is_object() || !decision.contains("begin") || !decision["begin"].is_number_unsigned() ||
                    !decision.contains("end") || !decision["end"].is_number_unsigned() ||
                    !decision.contains("decision") || !decision["decision"].is_boolean())
                    continue;
                path.decisions.push_back({
                    decision["begin"].get<size_t>(), decision["end"].get<size_t>(),
                    decision["decision"].get<bool>()});
            }
        }
        const json writes = observation.value("register_writes", json::array());
        if (writes.is_array())
            for (const json& write : writes)
                if (write.is_object() && write.contains("register") && write["register"].is_number_integer())
                    path.changed_register_writes.push_back(write["register"].get<int64_t>());

        const luraph::index_read::RecognitionResult recognized =
            luraph::index_read::recognizeOpcode28RegisterTableIndexRead(
                luraph::index_read::exactFixtureHandlerEvidence(), operands, path,
                luraph::index_read::RequiredProof::AnySemantic);
        output.status = luraph::index_read::toString(recognized.status);
        output.diagnostic = recognized.diagnostic;
        if (!recognized.recognized() || !recognized.proof->path_specific)
            return output;
        if (retained && (retained->destination_register != recognized.operation->destination_register ||
                retained->table_register != recognized.operation->table_register))
        {
            output.status = "contradictory_evidence";
            output.diagnostic = "opcode-28 operand registers changed across observations of one static site";
            return output;
        }
        retained = *recognized.operation;
        ++output.validated_observations;
    }

    output.status = "recognized";
    output.diagnostic = "all opcode-28 executions selected and validated the exact effectful index-read leaf";
    output.operation = {
        {"kind", "register_write"},
        {"semantic_family", "index_read"},
        {"static_semantic", false},
        {"path_specific", true},
        {"source_claim", false},
        {"proof", "runtime_observed_guard_path"},
        {"observation_count", output.validated_observations},
        {"register", luraphImmediateRuntimeLane(effectiveLanes, "r")},
        {"value", {
            {"kind", "index_read"},
            {"table", {
                {"kind", "register_read"},
                {"index", luraphImmediateRuntimeLane(effectiveLanes, "S")},
            }},
            {"index", luraphImmediateRuntimeLane(effectiveLanes, "V")},
            {"evaluation_order", json::array({"read_table_register", "read_index_operand",
                "perform_index_read", "write_destination_register"})},
            {"effect_barrier", true},
            {"may_invoke_index_metamethod", true},
            {"may_raise", true},
            {"evaluated_once", true},
            {"constant_foldable", false},
            {"common_subexpression_eliminable", false},
            {"dead_code_eliminable", false},
            {"reorderable", false},
        }},
    };
    return output;
}

LuraphExactLeafRecognition recognizeLuraphOpcode89RangeClear(
    const std::vector<json>* observations)
{
    LuraphExactLeafRecognition output;
    if (!observations || observations->empty())
    {
        output.diagnostic = "opcode-89 register clear has no complete runtime guard-path observations";
        return output;
    }

    std::optional<luraph::range_clear::RegisterRangeClear> retained;
    for (const json& observation : *observations)
    {
        const json runtimeLanes = observation.value("runtime_lanes", json::object());
        luraph::range_clear::RuntimeOperandLanes lanes;
        lanes.S = luraphRuntimeLaneInteger(runtimeLanes, "S");
        lanes.r = luraphRuntimeLaneInteger(runtimeLanes, "r");

        luraph::range_clear::ObservedGuardPathEvidence path;
        path.opcode = observation.value("opcode", int64_t(-1));
        path.selected_handler_begin = luraph::range_clear::kExactFixtureHandlerBegin;
        path.selected_handler_end = luraph::range_clear::kExactFixtureHandlerEnd;
        const json guardPath = observation.value("guard_path", json(nullptr));
        path.path_complete = guardPath.is_object() && guardPath.value("complete", false);
        path.path_overflow = guardPath.is_object() && guardPath.value("overflow", false);
        path.selected_handler_exactly = path.path_complete && !path.path_overflow;
        path.executed_statement_path_complete = path.selected_handler_exactly;
        path.full_effect_validation = path.selected_handler_exactly &&
            observation.value("next_pc", int64_t(-1)) == observation.value("pc", int64_t(-1)) + 1;
        path.observation_count = 1;
        if (guardPath.is_object() && guardPath.contains("decisions") && guardPath["decisions"].is_array())
        {
            for (const json& decision : guardPath["decisions"])
            {
                if (!decision.is_object() || !decision.contains("begin") || !decision["begin"].is_number_unsigned() ||
                    !decision.contains("end") || !decision["end"].is_number_unsigned() ||
                    !decision.contains("decision") || !decision["decision"].is_boolean())
                    continue;
                path.decisions.push_back({
                    decision["begin"].get<size_t>(), decision["end"].get<size_t>(),
                    decision["decision"].get<bool>()});
            }
        }
        const json writes = observation.value("register_writes", json::array());
        if (writes.is_array())
        {
            for (const json& write : writes)
            {
                if (!write.is_object() || !write.contains("register") || !write["register"].is_number_integer())
                    continue;
                const json value = write.value("value", json::object());
                path.changed_register_writes.push_back({
                    write["register"].get<int64_t>(), value.is_object() && value.value("type", "") == "nil"});
            }
        }

        const luraph::range_clear::RecognitionResult recognized =
            luraph::range_clear::recognizeOpcode89RegisterRangeClear(
                luraph::range_clear::exactFixtureHandlerEvidence(), lanes, path,
                luraph::range_clear::RequiredProof::PathSpecificSemantic);
        output.status = luraph::range_clear::toString(recognized.status);
        output.diagnostic = recognized.diagnostic;
        if (!recognized.recognized() || !recognized.proof->path_specific)
            return output;
        if (retained && (retained->first_register != recognized.operation->first_register ||
                retained->last_register != recognized.operation->last_register))
        {
            output.status = "contradictory_evidence";
            output.diagnostic = "opcode-89 register range changed across observations of one static site";
            return output;
        }
        retained = *recognized.operation;
        ++output.validated_observations;
    }

    output.status = "recognized";
    output.diagnostic = "all opcode-89 executions selected and validated the exact inclusive nil-clear leaf";
    output.operation = {
        {"kind", "register_clear_range"},
        {"semantic_family", "register_clear_range"},
        {"static_semantic", false},
        {"path_specific", true},
        {"source_claim", false},
        {"proof", "runtime_observed_guard_path"},
        {"observation_count", output.validated_observations},
        {"first_register_lane", "r"},
        {"last_register_lane", "S"},
        {"first_register", retained->first_register},
        {"last_register", retained->last_register},
        {"step", retained->step},
        {"inclusive_last_register", retained->inclusive_last_register},
        {"writes_nil", retained->writes_nil},
        {"empty", retained->empty},
        {"assignment_count", retained->assignment_count
            ? json(*retained->assignment_count) : json(nullptr)},
        {"assignment_count_overflow", retained->assignment_count_overflow},
    };
    return output;
}

json luraphRuntimeSemanticDispatchArtifact(
    const LuraphRuntimeStructureTrace& trace,
    const LuraphOpcodeCatalog& catalog,
    size_t& effectClassified,
    size_t& unresolved,
    size_t& semanticLifted)
{
    effectClassified = 0;
    unresolved = 0;
    semanticLifted = 0;
    size_t declaredInstructionCount = 0;
    for (const auto& [prototypeId, prototype] : trace.prototypes)
    {
        (void)prototypeId;
        declaredInstructionCount += prototype.declared_instruction_count;
    }
    std::map<int64_t, json> handlers;
    if (catalog.available && catalog.document.contains("handlers"))
    {
        for (const json& handler : catalog.document["handlers"])
            if (handler.contains("opcode") && handler["opcode"].is_number_integer())
                handlers[handler["opcode"].get<int64_t>()] = handler;
    }

    using RuntimeSite = std::pair<uint64_t, size_t>;
    std::map<RuntimeSite, std::vector<json>> observationsBySite;
    std::map<RuntimeSite, std::vector<json>> returnsBySite;
    std::map<RuntimeSite, std::vector<json>> childActivationsBySite;
    std::map<RuntimeSite, std::set<int64_t>> observedOpcodesBySite;
    size_t writeStepRows = 0;
    size_t writeOriginRows = 0;
    size_t writeOriginDestinations = 0;
    size_t uniqueRegisterOrigins = 0;
    size_t uniqueArgumentOrigins = 0;
    size_t ambiguousWriteOrigins = 0;
    for (const json& observed : trace.steps)
    {
        const uint64_t activation = observed.value("activation", uint64_t(0));
        const int64_t pc = observed.value("pc", int64_t(-1));
        auto activationRow = trace.activations.find(activation);
        if (activationRow == trace.activations.end() || pc <= 0)
            continue;
        const uint64_t prototype = activationRow->second.value("prototype", uint64_t(0));
        if (prototype == 0)
            continue;
        const RuntimeSite site{prototype, static_cast<size_t>(pc)};
        observationsBySite[site].push_back(observed);
        if (observed.contains("opcode") && observed["opcode"].is_number_integer())
            observedOpcodesBySite[site].insert(observed["opcode"].get<int64_t>());
        const json writes = observed.value("register_writes", json::array());
        if (writes.is_array() && !writes.empty())
            ++writeStepRows;
        const json origins = observed.value("write_origins", json::object());
        if (origins.is_object() && !origins.empty())
        {
            ++writeOriginRows;
            writeOriginDestinations += origins.size();
            for (auto origin = origins.begin(); origin != origins.end(); ++origin)
            {
                if (!origin.value().is_array() || origin.value().size() != 1 ||
                    !origin.value()[0].is_object())
                {
                    ++ambiguousWriteOrigins;
                    continue;
                }
                const std::string kind = origin.value()[0].value("kind", "");
                if (kind == "register")
                    ++uniqueRegisterOrigins;
                else if (kind == "argument")
                    ++uniqueArgumentOrigins;
                else
                    ++ambiguousWriteOrigins;
            }
        }
    }
    for (const LuraphVmEvent& event : trace.vm_events)
    {
        auto activationRow = trace.activations.find(event.activation);
        if (activationRow == trace.activations.end() || event.pc <= 0)
            continue;
        const uint64_t prototype = activationRow->second.value("prototype", uint64_t(0));
        if (prototype == 0)
            continue;
        observedOpcodesBySite[{prototype, static_cast<size_t>(event.pc)}].insert(event.opcode);
    }
    for (const json& returned : trace.returns)
    {
        const uint64_t activation = returned.value("activation", uint64_t(0));
        const int64_t pc = returned.value("pc", int64_t(-1));
        auto activationRow = trace.activations.find(activation);
        if (activationRow == trace.activations.end() || pc <= 0)
            continue;
        const uint64_t prototype = activationRow->second.value("prototype", uint64_t(0));
        if (prototype > 0)
            returnsBySite[{prototype, static_cast<size_t>(pc)}].push_back(returned);
    }
    for (const auto& [activationId, activation] : trace.activations)
    {
        (void)activationId;
        if (!activation.contains("caller_activation") || !activation["caller_activation"].is_number_integer() ||
            !activation.contains("caller_pc") || !activation["caller_pc"].is_number_integer())
            continue;
        const int64_t callerActivation = activation["caller_activation"].get<int64_t>();
        const int64_t callerPc = activation["caller_pc"].get<int64_t>();
        auto caller = callerActivation > 0
            ? trace.activations.find(static_cast<uint64_t>(callerActivation)) : trace.activations.end();
        if (caller == trace.activations.end() || callerPc <= 0)
            continue;
        const uint64_t callerPrototype = caller->second.value("prototype", uint64_t(0));
        if (callerPrototype == 0)
            continue;
        childActivationsBySite[{callerPrototype, static_cast<size_t>(callerPc)}].push_back({
            {"activation", activation.value("activation", uint64_t(0))},
            {"prototype", activation.value("prototype", uint64_t(0))},
            {"argument_count", activation.value("argument_count", json(nullptr))},
            {"entry_pc", activation.value("entry_pc", json(nullptr))},
        });
    }
    const std::map<int64_t, LuraphObservationalOpcodeRule> observationalOpcodeRules =
        inferLuraphObservationalOpcodeRules(trace);
    std::set<RuntimeSite> observationalSites;
    for (const auto& [site, observations] : observationsBySite)
    {
        (void)observations;
        observationalSites.insert(site);
    }
    for (const auto& [site, returns] : returnsBySite)
    {
        (void)returns;
        observationalSites.insert(site);
    }
    for (const auto& [site, children] : childActivationsBySite)
    {
        (void)children;
        observationalSites.insert(site);
    }

    const auto observedEffect = [&](uint64_t prototype, size_t pc, const std::vector<json>& observations) {
        json effect = {
            {"kind", "observed_effect"},
            {"proof", "bounded_runtime_observation"},
            {"path_specific", true},
            {"prototype", prototype},
            {"pc", pc},
            {"observation_count", observations.size()},
        };
        std::set<int64_t> nextPcs;
        std::set<std::vector<int64_t>> writeSignatures;
        std::set<std::string> writtenTypes;
        for (const json& observation : observations)
        {
            nextPcs.insert(observation.value("next_pc", int64_t(-1)));
            std::vector<int64_t> signature;
            const json writes = observation.value("register_writes", json::array());
            if (writes.is_array())
                for (const json& write : writes)
                {
                    if (write.contains("register") && write["register"].is_number_integer())
                        signature.push_back(write["register"].get<int64_t>());
                    if (write.contains("value") && write["value"].is_object())
                        writtenTypes.insert(write["value"].value("type", "unknown"));
                }
            std::sort(signature.begin(), signature.end());
            writeSignatures.insert(std::move(signature));
        }
        effect["next_pcs"] = nextPcs;
        effect["written_value_types"] = writtenTypes;

        auto returned = returnsBySite.find({prototype, pc});
        auto children = childActivationsBySite.find({prototype, pc});
        if (returned != returnsBySite.end())
        {
            effect["kind"] = "observed_return";
            effect["returns"] = returned->second;
            return effect;
        }
        if (children != childActivationsBySite.end())
        {
            effect["kind"] = "observed_call";
            effect["callee_activations"] = children->second;
            std::set<uint64_t> callees;
            for (const json& child : children->second)
                callees.insert(child.value("prototype", uint64_t(0)));
            effect["callee_prototypes"] = callees;
            effect["call_count"] = children->second.size();
            return effect;
        }

        std::optional<std::pair<std::string, int64_t>> transferLane;
        if (!observations.empty())
        {
            const json firstLanes = observations.front().value("runtime_lanes", json::object());
            if (firstLanes.is_object())
                for (auto lane = firstLanes.begin(); lane != firstLanes.end(); ++lane)
                    for (int64_t adjustment : {int64_t(0), int64_t(1)})
                    {
                        bool matched = true;
                        bool observedTransfer = false;
                        for (const json& observation : observations)
                        {
                            const int64_t nextPc = observation.value("next_pc", int64_t(-1));
                            const json lanes = observation.value("runtime_lanes", json::object());
                            if (!lanes.contains(lane.key()) || !lanes[lane.key()].is_object() ||
                                lanes[lane.key()].value("type", "") != "number" ||
                                !lanes[lane.key()].contains("value") || !lanes[lane.key()]["value"].is_string())
                            {
                                matched = false;
                                break;
                            }
                            const std::optional<int64_t> value =
                                parseTraceInteger<int64_t>(lanes[lane.key()]["value"].get<std::string>());
                            if (!value || *value + adjustment != nextPc)
                            {
                                matched = false;
                                break;
                            }
                            observedTransfer = observedTransfer || nextPc != static_cast<int64_t>(pc + 1);
                        }
                        if (matched && observedTransfer)
                        {
                            transferLane = {lane.key(), adjustment};
                            break;
                        }
                    }
        }

        const bool stableWrites = writeSignatures.size() == 1;
        const std::vector<int64_t> writes = stableWrites ? *writeSignatures.begin() : std::vector<int64_t>{};
        if (nextPcs.size() > 1)
        {
            effect["kind"] = "observed_branch";
            effect["condition"] = "unresolved";
        }
        else if (transferLane)
            effect["kind"] = "observed_jump";
        else if (stableWrites && writes.size() == 1)
            effect["kind"] = "observed_scalar_write";
        else if (stableWrites && writes.size() > 1 &&
            std::adjacent_find(writes.begin(), writes.end(), [](int64_t left, int64_t right) {
                return right != left + 1;
            }) == writes.end())
            effect["kind"] = "observed_contiguous_write";
        else if (nextPcs.size() == 1 && *nextPcs.begin() == static_cast<int64_t>(pc + 1) &&
            stableWrites && writes.empty())
            effect["kind"] = "observed_fallthrough";

        if (stableWrites)
            effect["register_writes"] = writes;
        else
            effect["register_writes"] = nullptr;
        if (transferLane)
        {
            effect["target_lane"] = transferLane->first;
            effect["target_adjustment"] = transferLane->second;
        }
        return effect;
    };
    size_t traceSpecialized = 0;
    size_t traceEffectClassified = 0;
    size_t runtimeOpcodeOverrides = 0;
    size_t runtimeOperandOverrides = 0;
    size_t observationalSemanticLifted = 0;
    size_t staticSemanticCoverage = 0;
    size_t runtimeValidatedObservationalSemanticCoverage = 0;
    size_t traceEvidenceOnlyCoverage = 0;
    size_t unresolvedSemanticCoverage = 0;
    size_t guardedCandidatesValidated = 0;
    size_t guardedCandidatesRejected = 0;
    size_t guardReplaySitesAttached = 0;
    size_t guardReplaySitesValidated = 0;
    size_t guardReplaySitesRejected = 0;
    size_t guardReplaySitesDivergent = 0;
    size_t opcode8CallSitesTotal = 0;
    size_t opcode8CallSitesStatic = 0;
    size_t opcode8CallSitesObservational = 0;
    size_t opcode8CallSitesRejected = 0;
    size_t opcode8CallObservationsValidated = 0;
    size_t opcode8EncodedOneQuirkSites = 0;
    json opcode8RecognitionStatusCounts = json::object();
    size_t opcode28SitesTotal = 0;
    size_t opcode28SitesObservational = 0;
    size_t opcode28SitesRejected = 0;
    size_t opcode28ObservationsValidated = 0;
    json opcode28RecognitionStatusCounts = json::object();
    size_t opcode89SitesTotal = 0;
    size_t opcode89SitesObservational = 0;
    size_t opcode89SitesRejected = 0;
    size_t opcode89ObservationsValidated = 0;
    json opcode89RecognitionStatusCounts = json::object();
    json observationalOperationCounts = json::object();

    json prototypes = json::array();
    for (const auto& [id, prototype] : trace.prototypes)
    {
        json instructions = json::array();
        for (const auto& [pc, instruction] : prototype.instructions)
        {
            const int64_t staticOpcode = instruction["opcode"].get<int64_t>();
            int64_t opcode = staticOpcode;
            auto observedSite = observationsBySite.find({id, pc});
            auto observedOpcodes = observedOpcodesBySite.find({id, pc});
            if (observedOpcodes != observedOpcodesBySite.end() && observedOpcodes->second.size() == 1 &&
                handlers.contains(*observedOpcodes->second.begin()))
                opcode = *observedOpcodes->second.begin();
            json effectiveLanes = instruction["lanes"];
            json laneOverrides = json::object();
            if (observedSite != observationsBySite.end())
            {
                for (auto lane = effectiveLanes.begin(); lane != effectiveLanes.end(); ++lane)
                {
                    std::optional<json> stableValue;
                    bool complete = true;
                    for (const json& observed : observedSite->second)
                    {
                        const json& runtimeLanes = observed.value("runtime_lanes", json::object());
                        // Older trace passes did not record operand lanes. They are missing
                        // evidence, not evidence that a later decoded operand is unstable.
                        if (!runtimeLanes.contains(lane.key()))
                            continue;
                        if (!runtimeLanes[lane.key()].value("primitive", false))
                        {
                            complete = false;
                            break;
                        }
                        if (!stableValue)
                            stableValue = runtimeLanes[lane.key()];
                        else if (*stableValue != runtimeLanes[lane.key()])
                        {
                            complete = false;
                            break;
                        }
                    }
                    if (complete && stableValue && *stableValue != lane.value())
                    {
                        laneOverrides[lane.key()] = *stableValue;
                        ++runtimeOperandOverrides;
                    }
                }
                for (auto override = laneOverrides.begin(); override != laneOverrides.end(); ++override)
                    effectiveLanes[override.key()] = override.value();
            }
            json row = instruction;
            row["static_opcode"] = staticOpcode;
            row["opcode"] = opcode;
            row["runtime_opcode_override"] = opcode != staticOpcode;
            row["runtime_opcode_observed"] = observedOpcodes != observedOpcodesBySite.end();
            row["static_lanes"] = instruction["lanes"];
            row["lanes"] = effectiveLanes;
            row["runtime_lane_overrides"] = laneOverrides;
            if (auto observedReturns = returnsBySite.find({id, pc}); observedReturns != returnsBySite.end())
                row["observed_returns"] = observedReturns->second;
            else
                row["observed_returns"] = json::array();
            if (opcode != staticOpcode)
                ++runtimeOpcodeOverrides;
            auto handler = handlers.find(opcode);
            bool classified = false;
            if (handler != handlers.end() && handler->second.contains("effects"))
            {
                row["handler_effects"] = handler->second["effects"];
                row["handler_range"] = handler->second.value("range", json(nullptr));
                const json& candidates = handler->second["effects"]["operation_candidates"];
                classified = candidates.is_array() && !candidates.empty();
            }
            else
            {
                row["handler_effects"] = nullptr;
                row["handler_range"] = nullptr;
            }
            row["effect_classified"] = classified;
            row["semantic_operation"] = nullptr;
            row["observational_semantic_operation"] = nullptr;
            row["trace_specialized_operation"] = nullptr;
            row["guarded_candidate_validation"] = nullptr;
            bool semanticAccepted = false;
            if (handler != handlers.end() && handler->second.contains("semantic_operation") &&
                !handler->second["semantic_operation"].is_null())
            {
                classified = true;
                row["effect_classified"] = true;
                row["semantic_operation"] = materializeLuraphSemanticOperation(
                    handler->second["semantic_operation"], effectiveLanes);
                if (observedSite != observationsBySite.end() && luraphObservedSemanticContradicts(
                        row["semantic_operation"], observedSite->second))
                {
                    row["rejected_semantic_operation"] = row["semantic_operation"];
                    row["semantic_operation"] = nullptr;
                    row["semantic_observation_contradiction"] = true;
                }
                else
                    semanticAccepted = true;
                if (semanticAccepted && !row["observed_returns"].empty() && row["semantic_operation"].is_object() &&
                    row["semantic_operation"].value("kind", "") == "return")
                {
                    std::set<size_t> arities;
                    bool complete = true;
                    for (const json& returned : row["observed_returns"])
                    {
                        arities.insert(returned.value("arity", size_t(0)));
                        complete = complete && returned.value("complete", false);
                    }
                    row["semantic_operation"]["runtime_return_observations"] = row["observed_returns"];
                    row["semantic_operation"]["runtime_return_arities"] = arities;
                    row["semantic_operation"]["runtime_return_values_complete"] = complete;
                }
                if (semanticAccepted && observedSite != observationsBySite.end())
                    if (std::optional<json> resolution = luraphObservedRegisterResolution(
                            row["semantic_operation"], observedSite->second))
                        row["semantic_operation"]["runtime_resolution"] = std::move(*resolution);
                if (semanticAccepted)
                    ++semanticLifted;
            }
            const auto observedReturnsForSite = returnsBySite.find({id, pc});
            const auto childActivationsForSite = childActivationsBySite.find({id, pc});
            const auto closureDescriptor = trace.closure_descriptors.find({id, pc});
            if (!semanticAccepted && opcode == 161 &&
                observedSite != observationsBySite.end() &&
                childActivationsForSite != childActivationsBySite.end())
            {
                if (std::optional<json> recognized = recognizeLuraphOpcode161TwoArgumentCall(
                        id, pc, effectiveLanes, observedSite->second, childActivationsForSite->second))
                {
                    row["observational_semantic_operation"] = std::move(*recognized);
                    row["opcode161_two_argument_call_recognition"] = {
                        {"status", "runtime_validated"},
                        {"validated_observations", observedSite->second.size()},
                    };
                    ++observationalSemanticLifted;
                    observationalOperationCounts["call"] =
                        observationalOperationCounts.value("call", size_t(0)) + 1;
                }
                else
                    row["opcode161_two_argument_call_recognition"] = {
                        {"status", "evidence_mismatch"},
                        {"validated_observations", 0},
                    };
            }
            if (!semanticAccepted && opcode == 8 && handler != handlers.end())
            {
                ++opcode8CallSitesTotal;
                const std::vector<json>* siteObservations = observedSite != observationsBySite.end()
                    ? &observedSite->second : nullptr;
                LuraphOpcode8PipelineRecognition recognized = recognizeLuraphOpcode8PipelineCall(
                    handler->second, effectiveLanes, siteObservations);
                row["opcode8_call_recognition"] = {
                    {"status", recognized.status},
                    {"diagnostic", recognized.diagnostic},
                    {"validated_observations", recognized.validated_observations},
                    {"static_semantic", recognized.static_semantic},
                };
                opcode8RecognitionStatusCounts[recognized.status] =
                    opcode8RecognitionStatusCounts.value(recognized.status, size_t(0)) + 1;
                opcode8CallObservationsValidated += recognized.validated_observations;
                if (recognized.operation.is_object())
                {
                    if (recognized.operation.value("encoded_result_count", int64_t(-1)) == 1)
                        ++opcode8EncodedOneQuirkSites;
                    if (recognized.static_semantic)
                    {
                        row["semantic_operation"] = std::move(recognized.operation);
                        semanticAccepted = true;
                        ++semanticLifted;
                        ++opcode8CallSitesStatic;
                    }
                    else
                    {
                        row["observational_semantic_operation"] = std::move(recognized.operation);
                        ++observationalSemanticLifted;
                        ++opcode8CallSitesObservational;
                        observationalOperationCounts["call"] =
                            observationalOperationCounts.value("call", size_t(0)) + 1;
                    }
                }
                else
                    ++opcode8CallSitesRejected;
            }
            if (!semanticAccepted && opcode == 28 &&
                row["observational_semantic_operation"].is_null())
            {
                ++opcode28SitesTotal;
                const std::vector<json>* siteObservations = observedSite != observationsBySite.end()
                    ? &observedSite->second : nullptr;
                LuraphExactLeafRecognition recognized = recognizeLuraphOpcode28IndexRead(
                    effectiveLanes, siteObservations);
                row["opcode28_index_read_recognition"] = {
                    {"status", recognized.status},
                    {"diagnostic", recognized.diagnostic},
                    {"validated_observations", recognized.validated_observations},
                    {"static_semantic", false},
                };
                opcode28RecognitionStatusCounts[recognized.status] =
                    opcode28RecognitionStatusCounts.value(recognized.status, size_t(0)) + 1;
                opcode28ObservationsValidated += recognized.validated_observations;
                if (recognized.operation.is_object())
                {
                    row["observational_semantic_operation"] = std::move(recognized.operation);
                    ++observationalSemanticLifted;
                    ++opcode28SitesObservational;
                    observationalOperationCounts["index_read"] =
                        observationalOperationCounts.value("index_read", size_t(0)) + 1;
                }
                else
                    ++opcode28SitesRejected;
            }
            if (!semanticAccepted && opcode == 89 &&
                row["observational_semantic_operation"].is_null())
            {
                ++opcode89SitesTotal;
                const std::vector<json>* siteObservations = observedSite != observationsBySite.end()
                    ? &observedSite->second : nullptr;
                LuraphExactLeafRecognition recognized = recognizeLuraphOpcode89RangeClear(siteObservations);
                row["opcode89_range_clear_recognition"] = {
                    {"status", recognized.status},
                    {"diagnostic", recognized.diagnostic},
                    {"validated_observations", recognized.validated_observations},
                    {"static_semantic", false},
                };
                opcode89RecognitionStatusCounts[recognized.status] =
                    opcode89RecognitionStatusCounts.value(recognized.status, size_t(0)) + 1;
                opcode89ObservationsValidated += recognized.validated_observations;
                if (recognized.operation.is_object())
                {
                    row["observational_semantic_operation"] = std::move(recognized.operation);
                    ++observationalSemanticLifted;
                    ++opcode89SitesObservational;
                    observationalOperationCounts["register_clear_range"] =
                        observationalOperationCounts.value("register_clear_range", size_t(0)) + 1;
                }
                else
                    ++opcode89SitesRejected;
            }
            if (!semanticAccepted && observedSite != observationsBySite.end() &&
                row["observational_semantic_operation"].is_null())
            {
                std::optional<json> replayed;
                bool completeReplay = !observedSite->second.empty();
                for (const json& observation : observedSite->second)
                {
                    const json operation = observation.value(
                        "guard_replay_candidate", json(nullptr));
                    if (!operation.is_object())
                    {
                        completeReplay = false;
                        break;
                    }
                    if (!replayed)
                        replayed = operation;
                    else if (*replayed != operation)
                    {
                        completeReplay = false;
                        ++guardReplaySitesDivergent;
                        break;
                    }
                }
                if (completeReplay && replayed)
                {
                    ++guardReplaySitesAttached;
                    json operation = materializeLuraphSemanticOperation(*replayed, effectiveLanes);
                    if (std::optional<json> validation = validateLuraphObservedCandidate(
                            operation, observedSite->second, pc,
                            observedReturnsForSite != returnsBySite.end()
                                ? &observedReturnsForSite->second : nullptr))
                    {
                        operation["static_semantic"] = false;
                        operation["path_specific"] = true;
                        operation["candidate_proof"] = operation.value("proof", "");
                        operation["proof"] = "recorded_guard_path_candidate_runtime_validated";
                        operation["runtime_validation"] = *validation;
                        operation["full_effect_validation"] = true;
                        operation["guard_replay_observations"] = observedSite->second.size();
                        row["guard_replay_validated_effect"] = operation;
                        row["observational_semantic_operation"] = std::move(operation);
                        row["guard_path_replayed"] = true;
                        row["guard_replay_validation"] = *validation;
                        ++guardReplaySitesValidated;
                        ++observationalSemanticLifted;
                        const std::string family = row["observational_semantic_operation"].value(
                            "semantic_family", row["observational_semantic_operation"].value("kind", "unknown"));
                        observationalOperationCounts[family] =
                            observationalOperationCounts.value(family, size_t(0)) + 1;
                    }
                    else
                    {
                        row["guard_replay_candidate"] = std::move(operation);
                        row["guard_replay_rejected"] = true;
                        ++guardReplaySitesRejected;
                    }
                }
            }
            if (!semanticAccepted && observedSite != observationsBySite.end() &&
                row["observational_semantic_operation"].is_null() &&
                handler != handlers.end() &&
                handler->second.value("selection_status", "") == "ambiguous" &&
                handler->second.value("vm_state_independent", false) &&
                handler->second.contains("candidate_semantic_operation") &&
                handler->second["candidate_semantic_operation"].is_object())
            {
                json candidate = materializeLuraphSemanticOperation(
                    handler->second["candidate_semantic_operation"], effectiveLanes);
                std::optional<json> validation;
                const bool completePath = handler->second.value("executed_path_complete", false) &&
                    handler->second.value("full_effect_normalization", false);
                bool incompleteCallCandidate = false;
                if (completePath)
                    validation = validateLuraphObservedCandidate(
                        candidate, observedSite->second, pc,
                        observedReturnsForSite != returnsBySite.end()
                            ? &observedReturnsForSite->second : nullptr);
                else if (childActivationsForSite != childActivationsBySite.end())
                {
                    validation = validateLuraphObservedIncompleteCallCandidate(
                        candidate, observedSite->second, childActivationsForSite->second, pc);
                    incompleteCallCandidate = validation.has_value();
                }
                if (validation)
                {
                    candidate["static_semantic"] = false;
                    candidate["path_specific"] = true;
                    candidate["candidate_proof"] = candidate.value("proof", "");
                    candidate["proof"] = incompleteCallCandidate
                        ? "runtime_validated_incomplete_call_handler_candidate"
                        : "runtime_validated_ambiguous_handler_candidate";
                    candidate["runtime_validation"] = *validation;
                    candidate["full_effect_validation"] = completePath;
                    candidate["source_claim"] = false;
                    row["observational_semantic_operation"] = std::move(candidate);
                    row["guarded_candidate_validation"] = *validation;
                    row["incomplete_call_candidate_validated"] = incompleteCallCandidate;
                    ++guardedCandidatesValidated;
                    ++observationalSemanticLifted;
                    const std::string family = row["observational_semantic_operation"].value(
                        "semantic_family", row["observational_semantic_operation"].value("kind", "unknown"));
                    observationalOperationCounts[family] =
                        observationalOperationCounts.value(family, size_t(0)) + 1;
                }
                else
                {
                    row["rejected_candidate_semantic_operation"] = std::move(candidate);
                    row["candidate_rejection_reason"] = completePath
                        ? "runtime_effect_validation_failed"
                        : "incomplete_executed_statement_path";
                    ++guardedCandidatesRejected;
                }
            }
            if (!semanticAccepted && (observedSite != observationsBySite.end() ||
                observedReturnsForSite != returnsBySite.end() ||
                childActivationsForSite != childActivationsBySite.end()) &&
                row["observational_semantic_operation"].is_null())
            {
                static const std::vector<json> noObservations;
                const std::vector<json>& siteObservations = observedSite != observationsBySite.end()
                    ? observedSite->second : noObservations;
                const json observational = inferLuraphObservationalSiteOperation(
                    id, pc, opcode, siteObservations,
                    observedReturnsForSite != returnsBySite.end() ? &observedReturnsForSite->second : nullptr,
                    childActivationsForSite != childActivationsBySite.end() ? &childActivationsForSite->second : nullptr,
                    closureDescriptor != trace.closure_descriptors.end() ? &closureDescriptor->second : nullptr,
                    observationalOpcodeRules, trace);
                if (observational.is_object())
                {
                    row["observational_semantic_operation"] = observational;
                    ++observationalSemanticLifted;
                    const std::string family = observational.value("semantic_family", observational.value("kind", "unknown"));
                    observationalOperationCounts[family] = observationalOperationCounts.value(family, size_t(0)) + 1;
                }
            }
            if (!semanticAccepted && (observedSite != observationsBySite.end() ||
                observedReturnsForSite != returnsBySite.end() ||
                childActivationsForSite != childActivationsBySite.end()))
            {
                json observations = json::array();
                std::set<int64_t> nextPcs;
                static const std::vector<json> noObservations;
                const std::vector<json>& siteObservations = observedSite != observationsBySite.end()
                    ? observedSite->second : noObservations;
                for (const json& observed : siteObservations)
                {
                    nextPcs.insert(observed.value("next_pc", int64_t(-1)));
                    observations.push_back({
                        {"activation", observed.value("activation", uint64_t(0))},
                        {"vm_count", observed.value("vm_count", uint64_t(0))},
                        {"next_pc", observed.value("next_pc", int64_t(-1))},
                        {"register_writes", observed.value("register_writes", json::array())},
                        {"runtime_lanes", observed.value("runtime_lanes", json::object())},
                    });
                }
                row["trace_specialized_operation"] = {
                    {"kind", "trace_specialized_instruction"},
                    {"static_semantic", false},
                    {"protector_state", true},
                    {"scope", "observed-payload-activations"},
                    {"observation_count", observations.size()},
                    {"next_pcs", nextPcs},
                    {"observations", std::move(observations)},
                };
                row["trace_specialized_operation"]["observed_effect"] =
                    observedEffect(id, pc, siteObservations);
                row["path_effect_classified"] = true;
                ++traceSpecialized;
                ++traceEffectClassified;
            }
            if (semanticAccepted)
            {
                row["semantic_coverage_class"] = "static_semantic";
                ++staticSemanticCoverage;
            }
            else if (row["observational_semantic_operation"].is_object() ||
                row.value("guard_replay_validated_effect", json(nullptr)).is_object())
            {
                row["semantic_coverage_class"] = "runtime_validated_observational_semantic";
                ++runtimeValidatedObservationalSemanticCoverage;
            }
            else if (row["trace_specialized_operation"].is_object())
            {
                row["semantic_coverage_class"] = "trace_evidence_only";
                ++traceEvidenceOnlyCoverage;
            }
            else
            {
                row["semantic_coverage_class"] = "unresolved";
                ++unresolvedSemanticCoverage;
            }
            if (classified)
                ++effectClassified;
            else
                ++unresolved;
            instructions.push_back(std::move(row));
            (void)pc;
        }
        prototypes.push_back({
            {"runtime_id", id},
            {"complete", prototype.instructions.size() == prototype.declared_instruction_count},
            {"lane_names", prototype.lane_names},
            {"instructions", std::move(instructions)},
        });
    }
    json activations = json::array();
    for (const auto& [id, activation] : trace.activations)
    {
        (void)id;
        activations.push_back(activation);
    }
    json steps = json::array();
    for (const json& observed : trace.steps)
    {
        json step = observed;
        const uint64_t activation = observed.value("activation", uint64_t(0));
        if (auto found = trace.activations.find(activation); found != trace.activations.end())
            step["prototype"] = found->second["prototype"];
        else
            step["prototype"] = nullptr;
        steps.push_back(std::move(step));
    }
    json returnRows = json::array();
    for (const json& observed : trace.returns)
    {
        json returned = observed;
        const uint64_t activation = observed.value("activation", uint64_t(0));
        if (auto found = trace.activations.find(activation); found != trace.activations.end())
            returned["prototype"] = found->second["prototype"];
        else
            returned["prototype"] = nullptr;
        returnRows.push_back(std::move(returned));
    }
    const size_t materializedInstructionCount = effectClassified + unresolved;
    if (declaredInstructionCount > materializedInstructionCount)
        unresolvedSemanticCoverage += declaredInstructionCount - materializedInstructionCount;
    const size_t semanticCoverageTotal = std::max(declaredInstructionCount, materializedInstructionCount);
    const size_t semanticCoveragePartitionSum = staticSemanticCoverage +
        runtimeValidatedObservationalSemanticCoverage + traceEvidenceOnlyCoverage +
        unresolvedSemanticCoverage;
    return {
        {"version", 1},
        {"kind", "luraph-runtime-semantic-dispatch-ir"},
        {"scope", "reachable-prototypes-observed-offline"},
        {"handler_leaf_selection_complete", catalog.resolved == 256},
        {"effect_classification_complete", unresolved == 0},
        {"semantic_lifting_complete", declaredInstructionCount > 0 && semanticLifted == declaredInstructionCount},
        {"instruction_count", effectClassified + unresolved},
        {"declared_instruction_count", declaredInstructionCount},
        {"observed_instruction_count", effectClassified + unresolved},
        {"effect_classified_instructions", effectClassified},
        {"unresolved_instructions", unresolved},
        {"semantic_lifted_instructions", semanticLifted},
        {"semantic_unresolved_instructions", effectClassified + unresolved - semanticLifted},
        {"trace_specialized_instructions", traceSpecialized},
        {"trace_effect_classified_instructions", traceEffectClassified},
        {"observational_sites", observationalSites.size()},
        {"observational_semantic_lifted", observationalSemanticLifted},
        {"observational_semantic_unresolved", observationalSites.size() - observationalSemanticLifted},
        {"guarded_candidates_validated", guardedCandidatesValidated},
        {"guarded_candidates_rejected", guardedCandidatesRejected},
        {"guard_replay_sites_attached", guardReplaySitesAttached},
        {"guard_replay_sites_validated", guardReplaySitesValidated},
        {"guard_replay_sites_rejected", guardReplaySitesRejected},
        {"guard_replay_sites_divergent", guardReplaySitesDivergent},
        {"opcode8_call_coverage", {
            {"available", opcode8CallSitesTotal > 0},
            {"scope", "runtime-decoded-opcode-8-instruction-sites"},
            {"sites_total", opcode8CallSitesTotal},
            {"static_semantic_sites", opcode8CallSitesStatic},
            {"runtime_observational_sites", opcode8CallSitesObservational},
            {"unresolved_sites", opcode8CallSitesTotal - opcode8CallSitesStatic - opcode8CallSitesObservational},
            {"rejected_sites", opcode8CallSitesRejected},
            {"validated_runtime_executions", opcode8CallObservationsValidated},
            {"encoded_one_quirk_sites", opcode8EncodedOneQuirkSites},
            {"recognition_status_counts", std::move(opcode8RecognitionStatusCounts)},
            {"static_requires_complete_guard_path", true},
            {"runtime_evidence_is_path_specific", true},
            {"encoded_one_quirk_preserved", true},
        }},
        {"opcode28_index_read_coverage", {
            {"available", opcode28SitesTotal > 0},
            {"scope", "runtime-decoded-opcode-28-instruction-sites"},
            {"sites_total", opcode28SitesTotal},
            {"runtime_observational_sites", opcode28SitesObservational},
            {"unresolved_sites", opcode28SitesTotal - opcode28SitesObservational},
            {"rejected_sites", opcode28SitesRejected},
            {"validated_runtime_executions", opcode28ObservationsValidated},
            {"recognition_status_counts", std::move(opcode28RecognitionStatusCounts)},
            {"runtime_evidence_is_path_specific", true},
            {"metamethod_and_error_behavior_preserved", true},
        }},
        {"opcode89_range_clear_coverage", {
            {"available", opcode89SitesTotal > 0},
            {"scope", "runtime-decoded-opcode-89-instruction-sites"},
            {"sites_total", opcode89SitesTotal},
            {"runtime_observational_sites", opcode89SitesObservational},
            {"unresolved_sites", opcode89SitesTotal - opcode89SitesObservational},
            {"rejected_sites", opcode89SitesRejected},
            {"validated_runtime_executions", opcode89ObservationsValidated},
            {"recognition_status_counts", std::move(opcode89RecognitionStatusCounts)},
            {"runtime_evidence_is_path_specific", true},
            {"inclusive_nil_clear_preserved", true},
        }},
        {"unobserved_instructions", declaredInstructionCount > observationalSites.size()
            ? declaredInstructionCount - observationalSites.size() : size_t(0)},
        {"structurally_missing_instructions", declaredInstructionCount > effectClassified + unresolved
            ? declaredInstructionCount - (effectClassified + unresolved) : size_t(0)},
        {"captured_but_unexecuted_instructions", effectClassified + unresolved > observationalSites.size()
            ? effectClassified + unresolved - observationalSites.size() : size_t(0)},
        {"observational_operation_counts", std::move(observationalOperationCounts)},
        {"observational_path_specific", true},
        {"semantic_coverage_partition", {
            {"available", semanticCoverageTotal > 0},
            {"scope", "runtime-decoded-instruction-sites"},
            {"total", semanticCoverageTotal},
            {"declared_total", declaredInstructionCount},
            {"materialized_total", materializedInstructionCount},
            {"static_semantic", staticSemanticCoverage},
            {"runtime_validated_observational_semantic", runtimeValidatedObservationalSemanticCoverage},
            {"trace_evidence_only", traceEvidenceOnlyCoverage},
            {"unresolved", unresolvedSemanticCoverage},
            {"partition_sum", semanticCoveragePartitionSum},
            {"disjoint", true},
            {"partition_complete", semanticCoveragePartitionSum == semanticCoverageTotal},
            {"semantic_coverage_complete", semanticCoveragePartitionSum == semanticCoverageTotal &&
                traceEvidenceOnlyCoverage == 0 && unresolvedSemanticCoverage == 0},
            {"runtime_validated_observational_semantic_is_path_specific", true},
            {"trace_evidence_only_is_semantic", false},
        }},
        {"write_origin_evidence", {
            {"available", writeOriginRows > 0},
            {"step_rows", trace.steps.size()},
            {"write_step_rows", writeStepRows},
            {"origin_rows", writeOriginRows},
            {"origin_destinations", writeOriginDestinations},
            {"unique_register_origins", uniqueRegisterOrigins},
            {"unique_argument_origins", uniqueArgumentOrigins},
            {"ambiguous_origins", ambiguousWriteOrigins},
            {"absent_from_all_steps", !trace.steps.empty() && writeOriginRows == 0},
        }},
        {"runtime_opcode_overrides", runtimeOpcodeOverrides},
        {"runtime_operand_overrides", runtimeOperandOverrides},
        {"observed_semantic_coverage", semanticLifted + traceSpecialized},
        {"observed_site_coverage", observationalSites.size()},
        {"activation_count", trace.activations.size()},
        {"activations", std::move(activations)},
        {"observed_step_count", trace.steps.size()},
        {"observed_steps", std::move(steps)},
        {"observed_return_count", trace.returns.size()},
        {"observed_returns", std::move(returnRows)},
        {"prototypes", std::move(prototypes)},
    };
}

struct LuraphPayloadClosureMetrics
{
    size_t activations = 0;
    size_t activated_prototypes = 0;
    size_t closure_expanded_prototypes = 0;
    size_t closure_expansion_edges = 0;
    size_t prototypes = 0;
    size_t instructions = 0;
    size_t statically_lifted = 0;
    size_t source_semantic = 0;
    size_t protector_internal = 0;
    size_t unresolved_observed = 0;
    size_t observed_steps = 0;
    size_t observed_returns = 0;
};

struct LuraphPayloadRootEvidence
{
    uint64_t bootstrap_activation = 0;
    uint64_t bootstrap_prototype = 0;
    uint64_t payload_activation = 0;
    uint64_t payload_prototype = 0;
    int64_t caller_pc = 0;
    int64_t caller_opcode = 0;
    uint64_t bootstrap_return_vm_count = 0;
    uint64_t payload_entry_vm_count = 0;
    std::string evidence;
};

bool luraphSemanticIsTerminalCall(const json& operation)
{
    if (!operation.is_object() || operation.value("kind", "") != "return" ||
        !operation.contains("values") || !operation["values"].is_array() ||
        operation["values"].size() != 1)
        return false;
    const json& value = operation["values"][0];
    return value.is_object() && value.value("kind", "") == "call";
}

std::optional<LuraphPayloadRootEvidence> findLuraphPayloadRoot(
    const LuraphRuntimeStructureTrace& runtime,
    const json& runtimeSemantic)
{
    if (!runtimeSemantic.contains("prototypes") || !runtimeSemantic["prototypes"].is_array())
        return std::nullopt;
    std::map<std::pair<uint64_t, int64_t>, const json*> semanticBySite;
    for (const json& prototype : runtimeSemantic["prototypes"])
    {
        const uint64_t prototypeId = prototype.value("runtime_id", uint64_t(0));
        if (prototypeId == 0 || !prototype.contains("instructions") || !prototype["instructions"].is_array())
            continue;
        for (const json& instruction : prototype["instructions"])
            semanticBySite[{prototypeId, instruction.value("pc", int64_t(-1))}] = &instruction;
    }

    // The bootstrap may return a callable/descriptor to the native wrapper, which
    // invokes the payload as a new top-level VM activation. This is not a child
    // call: the previous activation must have completed immediately before it.
    std::vector<std::pair<uint64_t, uint64_t>> topLevelActivations;
    for (const auto& [activationId, activation] : runtime.activations)
    {
        if (!activation.value("caller_activation", json(nullptr)).is_null())
            continue;
        const uint64_t entryVmCount = activation.value("entry_vm_count", uint64_t(0));
        if (entryVmCount > 0)
            topLevelActivations.emplace_back(entryVmCount, activationId);
    }
    std::sort(topLevelActivations.begin(), topLevelActivations.end());
    for (size_t index = 1; index < topLevelActivations.size(); ++index)
    {
        const auto [entryVmCount, activationId] = topLevelActivations[index];
        const auto [previousEntryVmCount, previousActivationId] = topLevelActivations[index - 1];
        (void)previousEntryVmCount;
        auto payloadActivation = runtime.activations.find(activationId);
        auto bootstrapActivation = runtime.activations.find(previousActivationId);
        if (payloadActivation == runtime.activations.end() || bootstrapActivation == runtime.activations.end())
            continue;
        const json* completedBootstrapReturn = nullptr;
        for (const json& returned : runtime.returns)
        {
            if (returned.value("activation", uint64_t(0)) != previousActivationId ||
                !returned.value("complete", false) || returned.value("vm_count", uint64_t(0)) + 1 != entryVmCount)
                continue;
            completedBootstrapReturn = &returned;
            break;
        }
        if (!completedBootstrapReturn)
            continue;
        const uint64_t bootstrapPrototype = bootstrapActivation->second.value("prototype", uint64_t(0));
        const uint64_t payloadPrototype = payloadActivation->second.value("prototype", uint64_t(0));
        if (bootstrapPrototype == 0 || payloadPrototype == 0 ||
            !runtime.prototypes.contains(payloadPrototype))
            continue;
        return LuraphPayloadRootEvidence{
            previousActivationId,
            bootstrapPrototype,
            activationId,
            payloadPrototype,
            completedBootstrapReturn->value("pc", int64_t(-1)),
            completedBootstrapReturn->value("opcode", int64_t(-1)),
            completedBootstrapReturn->value("vm_count", uint64_t(0)),
            entryVmCount,
            "sequential_top_level_handoff",
        };
    }

    std::optional<LuraphPayloadRootEvidence> selected;
    size_t selectedInstructionCount = 0;
    for (const auto& [activationId, activation] : runtime.activations)
    {
        if (!activation.contains("caller_activation") || !activation["caller_activation"].is_number_integer() ||
            !activation.contains("caller_pc") || !activation["caller_pc"].is_number_integer())
            continue;
        const int64_t callerActivationValue = activation["caller_activation"].get<int64_t>();
        if (callerActivationValue <= 0)
            continue;
        const uint64_t callerActivation = static_cast<uint64_t>(callerActivationValue);
        auto parent = runtime.activations.find(callerActivation);
        if (parent == runtime.activations.end() || !parent->second["caller_activation"].is_null())
            continue;
        const uint64_t parentPrototype = parent->second.value("prototype", uint64_t(0));
        const uint64_t childPrototype = activation.value("prototype", uint64_t(0));
        const int64_t callerPc = activation["caller_pc"].get<int64_t>();
        auto semantic = semanticBySite.find({parentPrototype, callerPc});
        if (semantic == semanticBySite.end() ||
            !semantic->second->contains("semantic_operation") ||
            !luraphSemanticIsTerminalCall((*semantic->second)["semantic_operation"]))
            continue;
        auto child = runtime.prototypes.find(childPrototype);
        const size_t childInstructionCount = child == runtime.prototypes.end()
            ? 0 : child->second.instructions.size();
        if (selected && childInstructionCount <= selectedInstructionCount)
            continue;
        selectedInstructionCount = childInstructionCount;
        selected = LuraphPayloadRootEvidence{
            callerActivation,
            parentPrototype,
            activationId,
            childPrototype,
            callerPc,
            activation.contains("caller_opcode") && activation["caller_opcode"].is_number_integer()
                ? activation["caller_opcode"].get<int64_t>() : int64_t(-1),
            0,
            activation.value("entry_vm_count", uint64_t(0)),
            "bootstrap_terminal_return_call",
        };
    }
    return selected;
}

json luraphGuardHotspotArtifact(const LuraphRuntimeStructureTrace& runtime)
{
    std::map<uint64_t, size_t> activationSteps;
    std::map<uint64_t, size_t> prototypeSteps;
    std::map<std::tuple<uint64_t, int64_t, int64_t, uint64_t>, size_t> childSites;
    std::optional<uint64_t> firstVmCount;
    std::optional<uint64_t> lastVmCount;
    for (const json& step : runtime.steps)
    {
        const uint64_t activation = step.value("activation", uint64_t(0));
        ++activationSteps[activation];
        if (auto row = runtime.activations.find(activation); row != runtime.activations.end())
            ++prototypeSteps[row->second.value("prototype", uint64_t(0))];
        const uint64_t vmCount = step.value("vm_count", uint64_t(0));
        firstVmCount = firstVmCount ? std::min(*firstVmCount, vmCount) : vmCount;
        lastVmCount = lastVmCount ? std::max(*lastVmCount, vmCount) : vmCount;
    }
    for (const auto& [activationId, activation] : runtime.activations)
    {
        (void)activationId;
        if (!activation.contains("caller_activation") || !activation["caller_activation"].is_number_integer())
            continue;
        const int64_t caller = activation["caller_activation"].get<int64_t>();
        if (caller < 0)
            continue;
        ++childSites[{
            static_cast<uint64_t>(caller),
            activation.value("caller_pc", int64_t(-1)),
            activation.value("caller_opcode", int64_t(-1)),
            activation.value("prototype", uint64_t(0)),
        }];
    }
    const auto topRows = [](const std::map<uint64_t, size_t>& counts, std::string_view key) {
        std::vector<std::pair<uint64_t, size_t>> sorted(counts.begin(), counts.end());
        std::sort(sorted.begin(), sorted.end(), [](const auto& left, const auto& right) {
            return left.second > right.second || (left.second == right.second && left.first < right.first);
        });
        json rows = json::array();
        for (size_t index = 0; index < std::min<size_t>(20, sorted.size()); ++index)
            rows.push_back({{std::string(key), sorted[index].first}, {"observed_steps", sorted[index].second}});
        return rows;
    };
    std::vector<std::pair<std::tuple<uint64_t, int64_t, int64_t, uint64_t>, size_t>> sortedSites(
        childSites.begin(), childSites.end());
    std::sort(sortedSites.begin(), sortedSites.end(), [](const auto& left, const auto& right) {
        return left.second > right.second;
    });
    json sites = json::array();
    for (size_t index = 0; index < std::min<size_t>(20, sortedSites.size()); ++index)
    {
        const auto& [key, count] = sortedSites[index];
        sites.push_back({
            {"caller_activation", std::get<0>(key)},
            {"caller_pc", std::get<1>(key)},
            {"caller_opcode", std::get<2>(key)},
            {"callee_prototype", std::get<3>(key)},
            {"activation_count", count},
        });
    }
    return {
        {"version", 1},
        {"kind", "luraph-pre-payload-guard-hotspot"},
        {"scope", "bounded-offline-observed-window"},
        {"first_vm_count", firstVmCount ? json(*firstVmCount) : json(nullptr)},
        {"last_vm_count", lastVmCount ? json(*lastVmCount) : json(nullptr)},
        {"observed_steps", runtime.steps.size()},
        {"observed_activations", activationSteps.size()},
        {"observed_prototypes", prototypeSteps.size()},
        {"classification", "protector_integrity_or_environment_guard_scaffolding"},
        {"classification_is_inference", true},
        {"top_activations", topRows(activationSteps, "activation")},
        {"top_prototypes", topRows(prototypeSteps, "prototype")},
        {"repeated_child_sites", std::move(sites)},
    };
}

json luraphObservedCfgArtifact(const LuraphRuntimeStructureTrace& runtime)
{
    using Node = std::pair<uint64_t, int64_t>;
    using Edge = std::tuple<uint64_t, int64_t, int64_t>;
    std::map<Node, size_t> nodeVisits;
    std::map<Node, std::set<int64_t>> nodeOpcodes;
    std::map<Edge, size_t> edgeVisits;
    std::set<uint64_t> prototypes;
    size_t invalidTargets = 0;

    for (const json& step : runtime.steps)
    {
        const uint64_t activation = step.value("activation", uint64_t(0));
        auto activationRow = runtime.activations.find(activation);
        if (activationRow == runtime.activations.end())
            continue;
        const uint64_t prototype = activationRow->second.value("prototype", uint64_t(0));
        const int64_t pc = step.value("pc", int64_t(-1));
        const int64_t nextPc = step.value("next_pc", int64_t(-1));
        const int64_t opcode = step.value("opcode", int64_t(-1));
        if (prototype == 0 || pc <= 0 || nextPc <= 0)
            continue;

        prototypes.insert(prototype);
        ++nodeVisits[{prototype, pc}];
        nodeOpcodes[{prototype, pc}].insert(opcode);
        ++edgeVisits[{prototype, pc, nextPc}];

        auto prototypeRow = runtime.prototypes.find(prototype);
        if (prototypeRow == runtime.prototypes.end() ||
            !prototypeRow->second.instructions.contains(static_cast<size_t>(nextPc)))
            ++invalidTargets;
    }

    json nodes = json::array();
    for (const auto& [node, visits] : nodeVisits)
    {
        json opcodes = json::array();
        for (int64_t opcode : nodeOpcodes[node])
            opcodes.push_back(opcode);
        nodes.push_back({
            {"id", "p" + std::to_string(node.first) + ":pc" + std::to_string(node.second)},
            {"prototype", node.first},
            {"pc", node.second},
            {"opcodes", std::move(opcodes)},
            {"visits", visits},
        });
    }

    json edges = json::array();
    for (const auto& [edge, visits] : edgeVisits)
    {
        const auto& [prototype, from, to] = edge;
        auto prototypeRow = runtime.prototypes.find(prototype);
        const bool targetValid = prototypeRow != runtime.prototypes.end() &&
            prototypeRow->second.instructions.contains(static_cast<size_t>(to));
        edges.push_back({
            {"from", "p" + std::to_string(prototype) + ":pc" + std::to_string(from)},
            {"to", "p" + std::to_string(prototype) + ":pc" + std::to_string(to)},
            {"prototype", prototype},
            {"from_pc", from},
            {"to_pc", to},
            {"kind", to == from + 1 ? "fallthrough" : "observed_transfer"},
            {"visits", visits},
            {"target_valid", targetValid},
        });
    }

    return {
        {"version", 1},
        {"kind", "luraph-observed-control-flow-graph"},
        {"scope", "bounded-offline-execution-window"},
        {"complete", false},
        {"full_payload_cfg_recovered", false},
        {"observed_step_count", runtime.steps.size()},
        {"prototype_count", prototypes.size()},
        {"node_count", nodeVisits.size()},
        {"edge_count", edgeVisits.size()},
        {"invalid_edge_targets", invalidTargets},
        {"nodes", std::move(nodes)},
        {"edges", std::move(edges)},
    };
}

json luraphCompactObservedSemanticArtifact(const json& runtimeSemantic)
{
    json prototypes = json::array();
    size_t retainedInstructions = 0;
    size_t observedReturns = 0;
    if (runtimeSemantic.contains("prototypes") && runtimeSemantic["prototypes"].is_array())
        for (const json& prototype : runtimeSemantic["prototypes"])
        {
            json instructions = json::array();
            if (prototype.contains("instructions") && prototype["instructions"].is_array())
                for (const json& instruction : prototype["instructions"])
                {
                    const json semantic = instruction.value("semantic_operation", json(nullptr));
                    const json observational = instruction.value("observational_semantic_operation", json(nullptr));
                    const json specialized = instruction.value("trace_specialized_operation", json(nullptr));
                    const json returns = instruction.value("observed_returns", json::array());
                    if (semantic.is_null() && observational.is_null() && specialized.is_null() &&
                        (!returns.is_array() || returns.empty()))
                        continue;
                    json row = {
                        {"pc", instruction.value("pc", size_t(0))},
                        {"opcode", instruction.value("opcode", int64_t(-1))},
                        {"static_opcode", instruction.value("static_opcode", int64_t(-1))},
                        {"effect_classified", instruction.value("effect_classified", false)},
                        {"path_effect_classified", instruction.value("path_effect_classified", false)},
                        {"semantic_operation", semantic},
                        {"observational_semantic_operation", observational},
                        {"observed_returns", returns},
                    };
                    if (specialized.is_object())
                    {
                        row["trace_specialized_operation"] = {
                            {"kind", specialized.value("kind", "trace_specialized_instruction")},
                            {"static_semantic", false},
                            {"scope", specialized.value("scope", "bounded-runtime-observation")},
                            {"observation_count", specialized.value("observation_count", size_t(0))},
                            {"next_pcs", specialized.value("next_pcs", json::array())},
                            {"observed_effect", specialized.value("observed_effect", json(nullptr))},
                        };
                    }
                    else
                        row["trace_specialized_operation"] = nullptr;
                    if (returns.is_array())
                        observedReturns += returns.size();
                    instructions.push_back(std::move(row));
                    ++retainedInstructions;
                }
            prototypes.push_back({
                {"runtime_id", prototype.value("runtime_id", uint64_t(0))},
                {"complete", false},
                {"observed_instruction_count", instructions.size()},
                {"instructions", std::move(instructions)},
            });
        }

    json activations = json::array();
    if (runtimeSemantic.contains("activations") && runtimeSemantic["activations"].is_array())
        for (const json& activation : runtimeSemantic["activations"])
            activations.push_back({
                {"activation", activation.value("activation", uint64_t(0))},
                {"prototype", activation.value("prototype", uint64_t(0))},
                {"caller_activation", activation.value("caller_activation", json(nullptr))},
                {"caller_pc", activation.value("caller_pc", json(nullptr))},
                {"caller_opcode", activation.value("caller_opcode", json(nullptr))},
                {"argument_count", activation.value("argument_count", json(nullptr))},
                {"entry_pc", activation.value("entry_pc", json(nullptr))},
            });

    return {
        {"version", 2},
        {"kind", "luraph-observed-effect-ir"},
        {"status", "bounded-observed-effects-not-full-static-semantics"},
        {"scope", "bounded-offline-execution-window"},
        {"complete", false},
        {"source_recovered", false},
        {"path_specific", true},
        {"instruction_count", runtimeSemantic.value("instruction_count", size_t(0))},
        {"observed_instruction_count", retainedInstructions},
        {"unobserved_instruction_count", runtimeSemantic.value("instruction_count", size_t(0)) -
            std::min(runtimeSemantic.value("instruction_count", size_t(0)), retainedInstructions)},
        {"trace_effect_classified_instructions", runtimeSemantic.value("trace_effect_classified_instructions", size_t(0))},
        {"static_semantic_instructions", runtimeSemantic.value("semantic_lifted_instructions", size_t(0))},
        {"observed_step_count", runtimeSemantic.value("observed_step_count", size_t(0))},
        {"observed_return_count", observedReturns},
        {"activation_count", activations.size()},
        {"activations", std::move(activations)},
        {"prototypes", std::move(prototypes)},
    };
}

json luraphPayloadClosureArtifact(
    const LuraphRuntimeStructureTrace& runtime,
    const LuraphDynamicTrace& dynamic,
    const json& runtimeSemantic,
    LuraphPayloadClosureMetrics& metrics,
    const std::optional<LuraphPayloadRootEvidence>& payloadRoot = std::nullopt)
{
    std::set<uint64_t> activationIds;
    if (!dynamic.calls.empty())
    {
        for (const LuraphTraceCall& call : dynamic.calls)
            activationIds.insert(call.activation);
    }
    else if (payloadRoot)
        activationIds.insert(payloadRoot->payload_activation);

    bool changed = true;
    while (changed)
    {
        changed = false;
        for (const auto& [id, activation] : runtime.activations)
        {
            if (activationIds.contains(id) || !activation.contains("caller_activation") ||
                !activation["caller_activation"].is_number_integer())
                continue;
            const int64_t caller = activation["caller_activation"].get<int64_t>();
            if (caller >= 0 && activationIds.contains(static_cast<uint64_t>(caller)))
                changed = activationIds.insert(id).second || changed;
        }
    }

    std::set<uint64_t> prototypeIds;
    json activations = json::array();
    for (uint64_t id : activationIds)
    {
        auto found = runtime.activations.find(id);
        if (found == runtime.activations.end())
            continue;
        activations.push_back(found->second);
        if (found->second.contains("prototype") && found->second["prototype"].is_number_unsigned())
            prototypeIds.insert(found->second["prototype"].get<uint64_t>());
        else if (found->second.contains("prototype") && found->second["prototype"].is_number_integer())
            prototypeIds.insert(static_cast<uint64_t>(found->second["prototype"].get<int64_t>()));
    }

    std::set<uint64_t> semanticPrototypeIds;
    if (runtimeSemantic.contains("prototypes") && runtimeSemantic["prototypes"].is_array())
        for (const json& prototype : runtimeSemantic["prototypes"])
        {
            const uint64_t id = prototype.value("runtime_id", uint64_t(0));
            if (id > 0)
                semanticPrototypeIds.insert(id);
        }

    const size_t activatedPrototypeCount = prototypeIds.size();
    std::set<std::pair<uint64_t, size_t>> closureExpansionEdges;
    changed = true;
    while (changed)
    {
        changed = false;
        for (const auto& [site, descriptor] : runtime.closure_descriptors)
        {
            if (!prototypeIds.contains(site.first) || !descriptor.is_object() ||
                !descriptor.value("complete", false) || !descriptor.contains("target_prototype") ||
                (!descriptor["target_prototype"].is_number_integer() &&
                    !descriptor["target_prototype"].is_number_unsigned()))
                continue;

            uint64_t target = 0;
            if (descriptor["target_prototype"].is_number_unsigned())
                target = descriptor["target_prototype"].get<uint64_t>();
            else
            {
                const int64_t signedTarget = descriptor["target_prototype"].get<int64_t>();
                if (signedTarget <= 0)
                    continue;
                target = static_cast<uint64_t>(signedTarget);
            }
            if (target == 0 || !runtime.prototypes.contains(target) ||
                !semanticPrototypeIds.contains(target))
                continue;

            closureExpansionEdges.insert(site);
            changed = prototypeIds.insert(target).second || changed;
        }
    }

    std::set<std::pair<uint64_t, size_t>> observedInstructionSites;
    for (const json& observed : runtime.steps)
    {
        const uint64_t activation = observed.value("activation", uint64_t(0));
        auto activationRow = runtime.activations.find(activation);
        if (!activationIds.contains(activation) || activationRow == runtime.activations.end())
            continue;
        const uint64_t prototype = activationRow->second.value("prototype", uint64_t(0));
        const int64_t pc = observed.value("pc", int64_t(-1));
        if (prototype > 0 && pc > 0)
            observedInstructionSites.emplace(prototype, static_cast<size_t>(pc));
    }

    json prototypes = json::array();
    if (runtimeSemantic.contains("prototypes") && runtimeSemantic["prototypes"].is_array())
    {
        for (const json& prototype : runtimeSemantic["prototypes"])
        {
            const uint64_t id = prototype.value("runtime_id", uint64_t(0));
            if (!prototypeIds.contains(id))
                continue;
            json row = prototype;
            const size_t instructionCount = row.contains("instructions") && row["instructions"].is_array()
                ? row["instructions"].size() : 0;
            size_t staticallyLifted = 0;
            size_t sourceSemantic = 0;
            size_t protectorInternal = 0;
            size_t unresolvedObserved = 0;
            if (row.contains("instructions") && row["instructions"].is_array())
                for (json& instruction : row["instructions"])
                    if (auto descriptor = runtime.closure_descriptors.find({id, instruction.value("pc", size_t(0))});
                        descriptor != runtime.closure_descriptors.end())
                        instruction["closure_descriptor"] = descriptor->second;
            if (row.contains("instructions") && row["instructions"].is_array())
                for (const json& instruction : row["instructions"])
                {
                    if (instruction.contains("semantic_operation") && !instruction["semantic_operation"].is_null())
                    {
                        ++staticallyLifted;
                        if (instruction["semantic_operation"].value("protector_state", false))
                            ++protectorInternal;
                        else
                            ++sourceSemantic;
                    }
                    else if (observedInstructionSites.contains({id, instruction.value("pc", size_t(0))}))
                        ++unresolvedObserved;
                }
            row["static_semantic_lifted"] = staticallyLifted;
            row["static_semantic_unresolved"] = instructionCount - staticallyLifted;
            row["source_semantic_instructions"] = sourceSemantic;
            row["protector_internal_instructions"] = protectorInternal;
            row["unresolved_observed_instructions"] = unresolvedObserved;
            metrics.instructions += instructionCount;
            metrics.statically_lifted += staticallyLifted;
            metrics.source_semantic += sourceSemantic;
            metrics.protector_internal += protectorInternal;
            metrics.unresolved_observed += unresolvedObserved;
            prototypes.push_back(std::move(row));
        }
    }

    json captureDomains = json::array();
    for (const auto& [prototype, domain] : runtime.capture_domains)
        if (prototypeIds.contains(prototype))
            captureDomains.push_back(domain);

    json steps = json::array();
    for (const json& observed : runtime.steps)
    {
        const uint64_t activation = observed.value("activation", uint64_t(0));
        if (!activationIds.contains(activation))
            continue;
        json row = observed;
        if (auto found = runtime.activations.find(activation); found != runtime.activations.end())
            row["prototype"] = found->second["prototype"];
        steps.push_back(std::move(row));
    }

    json returns = json::array();
    for (const json& observed : runtime.returns)
    {
        const uint64_t activation = observed.value("activation", uint64_t(0));
        if (!activationIds.contains(activation))
            continue;
        json row = observed;
        if (auto found = runtime.activations.find(activation); found != runtime.activations.end())
            row["prototype"] = found->second["prototype"];
        returns.push_back(std::move(row));
    }

    json calls = json::array();
    for (const LuraphTraceCall& call : dynamic.calls)
    {
        json arguments = json::array();
        for (const LuraphTraceValue& argument : call.arguments)
            arguments.push_back({{"type", argument.type},
                {"value", argument.type == "nil" ? json(nullptr) : json(argument.value)}});
        calls.push_back({
            {"vm_count", call.vm_count},
            {"activation", call.activation},
            {"pc", call.pc},
            {"opcode", call.opcode},
            {"target", call.target},
            {"arguments", std::move(arguments)},
            {"output_confirmed", call.output_confirmed},
        });
    }

    metrics.activations = activations.size();
    metrics.activated_prototypes = activatedPrototypeCount;
    metrics.closure_expanded_prototypes = prototypeIds.size() - activatedPrototypeCount;
    metrics.closure_expansion_edges = closureExpansionEdges.size();
    metrics.prototypes = prototypes.size();
    metrics.observed_steps = steps.size();
    metrics.observed_returns = returns.size();
    json payloadRootArtifact = nullptr;
    if (!dynamic.calls.empty())
    {
        const uint64_t confirmedActivation = dynamic.calls.front().activation;
        const bool sharedActivation = std::all_of(dynamic.calls.begin(), dynamic.calls.end(),
            [&](const LuraphTraceCall& call) { return call.activation == confirmedActivation; });
        auto confirmed = runtime.activations.find(confirmedActivation);
        if (sharedActivation && confirmed != runtime.activations.end())
        {
            const json& activation = confirmed->second;
            const json callerActivationEvidence = activation.value("caller_activation", json(nullptr));
            const std::optional<int64_t> callerActivation = callerActivationEvidence.is_number_integer()
                ? std::optional<int64_t>(callerActivationEvidence.get<int64_t>()) : std::nullopt;
            const json callerPcEvidence = activation.value("caller_pc", json(nullptr));
            const json callerOpcodeEvidence = activation.value("caller_opcode", json(nullptr));
            uint64_t bootstrapPrototype = 0;
            if (callerActivation && *callerActivation >= 0)
                if (auto caller = runtime.activations.find(static_cast<uint64_t>(*callerActivation)); caller != runtime.activations.end())
                    bootstrapPrototype = caller->second.value("prototype", uint64_t(0));
            payloadRootArtifact = {
                {"bootstrap_activation", callerActivation && *callerActivation >= 0
                    ? json(*callerActivation) : json(nullptr)},
                {"bootstrap_prototype", bootstrapPrototype > 0 ? json(bootstrapPrototype) : json(nullptr)},
                {"payload_activation", confirmedActivation},
                {"payload_prototype", activation.value("prototype", json(nullptr))},
                {"caller_pc", callerPcEvidence},
                {"caller_opcode", callerOpcodeEvidence},
                {"evidence", "confirmed_payload_call_activation"},
                {"closure_descriptor", nullptr},
            };
            if (bootstrapPrototype > 0 && callerPcEvidence.is_number_integer() &&
                callerPcEvidence.get<int64_t>() >= 0)
                if (auto descriptor = runtime.closure_descriptors.find({
                        bootstrapPrototype, static_cast<size_t>(callerPcEvidence.get<int64_t>())});
                    descriptor != runtime.closure_descriptors.end())
                    payloadRootArtifact["closure_descriptor"] = descriptor->second;
        }
    }
    if (payloadRootArtifact.is_null() && payloadRoot)
    {
        payloadRootArtifact = {
            {"bootstrap_activation", payloadRoot->bootstrap_activation},
            {"bootstrap_prototype", payloadRoot->bootstrap_prototype},
            {"payload_activation", payloadRoot->payload_activation},
            {"payload_prototype", payloadRoot->payload_prototype},
            {"caller_pc", payloadRoot->caller_pc},
            {"caller_opcode", payloadRoot->caller_opcode},
            {"bootstrap_return_vm_count", payloadRoot->bootstrap_return_vm_count > 0
                ? json(payloadRoot->bootstrap_return_vm_count) : json(nullptr)},
            {"payload_entry_vm_count", payloadRoot->payload_entry_vm_count > 0
                ? json(payloadRoot->payload_entry_vm_count) : json(nullptr)},
            {"evidence", payloadRoot->evidence},
            {"closure_descriptor", nullptr},
        };
        if (auto descriptor = runtime.closure_descriptors.find({
                payloadRoot->bootstrap_prototype, static_cast<size_t>(payloadRoot->caller_pc)});
            descriptor != runtime.closure_descriptors.end())
            payloadRootArtifact["closure_descriptor"] = descriptor->second;
        if (payloadRootArtifact["closure_descriptor"].is_null())
        {
            const json* matched = nullptr;
            for (const auto& [site, descriptor] : runtime.closure_descriptors)
            {
                if (site.first != payloadRoot->bootstrap_prototype ||
                    !descriptor.contains("target_prototype") ||
                    !descriptor["target_prototype"].is_number_integer() ||
                    descriptor["target_prototype"].get<int64_t>() != static_cast<int64_t>(payloadRoot->payload_prototype))
                    continue;
                if (matched)
                {
                    matched = nullptr;
                    break;
                }
                matched = &descriptor;
            }
            if (matched)
                payloadRootArtifact["closure_descriptor"] = *matched;
        }
    }
    return {
        {"version", 1},
        {"kind", "luraph-observed-payload-closure"},
        {"scope", !dynamic.calls.empty()
            ? "confirmed-call-roots-descendant-activations-and-proven-closure-targets"
            : payloadRoot && payloadRoot->evidence == "sequential_top_level_handoff"
                ? "sequential-top-level-handoff-descendant-activations-and-proven-closure-targets"
                : "bootstrap-terminal-call-root-descendant-activations-and-proven-closure-targets"},
        {"payload_root", std::move(payloadRootArtifact)},
        {"source_recovered", false},
        {"static_semantic_complete", metrics.instructions > 0 && metrics.statically_lifted == metrics.instructions},
        {"activation_count", metrics.activations},
        {"activated_prototype_count", metrics.activated_prototypes},
        {"closure_expanded_prototype_count", metrics.closure_expanded_prototypes},
        {"closure_expansion_edge_count", metrics.closure_expansion_edges},
        {"prototype_count", metrics.prototypes},
        {"instruction_count", metrics.instructions},
        {"static_semantic_lifted", metrics.statically_lifted},
        {"static_semantic_unresolved", metrics.instructions - metrics.statically_lifted},
        {"source_semantic_instructions", metrics.source_semantic},
        {"protector_internal_instructions", metrics.protector_internal},
        {"unresolved_observed_instructions", metrics.unresolved_observed},
        {"observed_path_coverage_complete", metrics.instructions > 0 &&
            metrics.statically_lifted + metrics.unresolved_observed == metrics.instructions},
        {"observed_step_count", metrics.observed_steps},
        {"observed_return_count", metrics.observed_returns},
        {"activations", std::move(activations)},
        {"confirmed_calls", std::move(calls)},
        {"observed_steps", std::move(steps)},
        {"observed_returns", std::move(returns)},
        {"observed_capture_domains", std::move(captureDomains)},
        {"prototypes", std::move(prototypes)},
    };
}

std::optional<size_t> luraphSemanticPc(const json& value)
{
    const json* numeric = &value;
    if (value.is_object() && value.value("kind", "") == "immediate" && value.contains("value"))
        numeric = &value["value"];
    if (!numeric->is_object() || numeric->value("type", "") != "number" ||
        !numeric->contains("value") || !(*numeric)["value"].is_string())
        return std::nullopt;
    const std::optional<int64_t> parsed = parseTraceInteger<int64_t>((*numeric)["value"].get<std::string>());
    if (!parsed || *parsed <= 0)
        return std::nullopt;
    return static_cast<size_t>(*parsed);
}

const json& luraphDirectSequenceTerminal(const json& operation)
{
    const json* terminal = &operation;
    while (terminal->is_object())
    {
        const std::string kind = terminal->value("kind", "");
        if (kind != "operation_sequence" && kind != "protector_internal_sequence" && kind != "block")
            break;
        if (!terminal->contains("operations") || !(*terminal)["operations"].is_array() ||
            (*terminal)["operations"].empty())
            break;
        terminal = &(*terminal)["operations"].back();
    }
    return *terminal;
}

std::vector<size_t> luraphSemanticSuccessors(const json& operation, size_t pc, size_t instructionCount,
    std::string& terminator, size_t& invalidEdges)
{
    std::vector<size_t> successors;
    const auto encodedTarget = [](const json& value) -> std::optional<size_t> {
        const std::optional<size_t> target = luraphSemanticPc(value);
        if (!target || *target == std::numeric_limits<size_t>::max())
            return std::nullopt;
        return *target + 1;
    };
    const auto add = [&](std::optional<size_t> target) {
        if (!target || *target == 0 || *target > instructionCount)
            ++invalidEdges;
        else
            successors.push_back(*target);
    };
    const auto fallthrough = [&]() {
        if (pc < instructionCount)
            successors.push_back(pc + 1);
    };
    const json& terminalOperation = luraphDirectSequenceTerminal(operation);
    const std::string kind = terminalOperation.value("kind", "unknown");
    if (kind == "return")
        terminator = "return";
    else if (kind == "jump")
    {
        terminator = "jump";
        add(terminalOperation.contains("target") ? encodedTarget(terminalOperation["target"]) : std::nullopt);
    }
    else if (kind == "branch")
    {
        terminator = "branch";
        const auto arm = [&](std::string_view name) {
            if (!terminalOperation.contains(std::string(name)) || !terminalOperation[std::string(name)].is_array() ||
                terminalOperation[std::string(name)].empty())
            {
                fallthrough();
                return;
            }
            const json& last = terminalOperation[std::string(name)].back();
            if (last.is_object() && last.value("kind", "") == "jump" && last.contains("target"))
                add(encodedTarget(last["target"]));
            else
                fallthrough();
        };
        arm("then");
        arm("else");
    }
    else if (kind == "generic_for_prepare")
    {
        terminator = "generic_for_prepare";
        add(terminalOperation.contains("loop_target") ? encodedTarget(terminalOperation["loop_target"]) : std::nullopt);
    }
    else
    {
        terminator = "fallthrough";
        fallthrough();
    }
    std::sort(successors.begin(), successors.end());
    successors.erase(std::unique(successors.begin(), successors.end()), successors.end());
    return successors;
}

json luraphPayloadCfgArtifact(const json& payloadClosure)
{
    std::map<uint64_t, std::set<size_t>> observedEntryPcs;
    std::map<uint64_t, std::set<size_t>> observedPcs;
    std::map<std::pair<uint64_t, size_t>, std::set<size_t>> observedNextPcs;
    if (payloadClosure.contains("activations") && payloadClosure["activations"].is_array())
        for (const json& activation : payloadClosure["activations"])
            if (activation.contains("entry_pc") && activation["entry_pc"].is_number_integer())
            {
                const int64_t entryPc = activation["entry_pc"].get<int64_t>();
                if (entryPc > 0)
                    observedEntryPcs[activation.value("prototype", uint64_t(0))].insert(static_cast<size_t>(entryPc));
            }
    if (payloadClosure.contains("observed_steps") && payloadClosure["observed_steps"].is_array())
        for (const json& step : payloadClosure["observed_steps"])
            if (step.contains("prototype") && step["prototype"].is_number_integer() &&
                step.contains("pc") && step["pc"].is_number_integer() &&
                step.contains("next_pc") && step["next_pc"].is_number_integer())
            {
                const int64_t pc = step["pc"].get<int64_t>();
                const int64_t nextPc = step["next_pc"].get<int64_t>();
                if (pc > 0 && nextPc > 0)
                {
                    const uint64_t prototype = step["prototype"].get<uint64_t>();
                    observedNextPcs[{prototype, static_cast<size_t>(pc)}].insert(static_cast<size_t>(nextPc));
                    observedPcs[prototype].insert(static_cast<size_t>(pc));
                }
            }
    json prototypeRows = json::array();
    size_t totalBlocks = 0;
    size_t totalEdges = 0;
    size_t totalReachable = 0;
    size_t totalReachableInstructions = 0;
    size_t totalCyclicRegions = 0;
    size_t totalIrreducibleRegions = 0;
    size_t totalInvalidEdges = 0;
    size_t totalReachableInvalidEdges = 0;
    size_t totalObservedEdgeSites = 0;
    if (!payloadClosure.contains("prototypes") || !payloadClosure["prototypes"].is_array())
        return {{"version", 1}, {"kind", "luraph-payload-cfg"}, {"prototypes", prototypeRows}};

    for (const json& prototype : payloadClosure["prototypes"])
    {
        if (!prototype.contains("instructions") || !prototype["instructions"].is_array() ||
            prototype["instructions"].empty())
            continue;
        const uint64_t prototypeId = prototype.value("runtime_id", uint64_t(0));
        const size_t instructionCount = prototype["instructions"].size();
        std::map<size_t, std::vector<size_t>> successorsByPc;
        std::map<size_t, std::string> terminatorByPc;
        std::map<size_t, size_t> invalidEdgesByPc;
        std::set<size_t> entryPcs = observedEntryPcs[prototypeId];
        if (entryPcs.empty())
            entryPcs.insert(1);
        std::set<size_t> leaders = entryPcs;
        size_t invalidEdges = 0;
        size_t observedEdgeSites = 0;
        for (const json& instruction : prototype["instructions"])
        {
            const size_t pc = instruction.value("pc", size_t(0));
            if (pc == 0 || pc > instructionCount)
                continue;
            const json& operation = instruction.contains("semantic_operation")
                ? instruction["semantic_operation"] : json(nullptr);
            std::string terminator;
            size_t staticInvalidEdges = 0;
            std::vector<size_t> successors = luraphSemanticSuccessors(
                operation.is_object() ? operation : json::object(), pc, instructionCount, terminator, staticInvalidEdges);
            size_t instructionInvalidEdges = 0;
            if (auto observed = observedNextPcs.find({prototypeId, pc}); observed != observedNextPcs.end())
            {
                successors.clear();
                for (size_t target : observed->second)
                {
                    if (target > instructionCount)
                        ++instructionInvalidEdges;
                    else
                        successors.push_back(target);
                }
                terminator = "observed_" + terminator;
                ++observedEdgeSites;
            }
            else
                instructionInvalidEdges = staticInvalidEdges;
            invalidEdges += instructionInvalidEdges;
            invalidEdgesByPc[pc] = instructionInvalidEdges;
            successorsByPc[pc] = successors;
            terminatorByPc[pc] = terminator;
            if (terminator != "fallthrough")
            {
                if (pc < instructionCount)
                    leaders.insert(pc + 1);
                leaders.insert(successors.begin(), successors.end());
            }
        }

        std::vector<size_t> orderedLeaders(leaders.begin(), leaders.end());
        std::map<size_t, size_t> blockForPc;
        struct Block { size_t start = 0; size_t end = 0; std::vector<size_t> successors; std::string terminator; };
        std::vector<Block> blocks;
        for (size_t index = 0; index < orderedLeaders.size(); ++index)
        {
            const size_t start = orderedLeaders[index];
            if (start == 0 || start > instructionCount)
                continue;
            const size_t end = index + 1 < orderedLeaders.size()
                ? std::min(instructionCount, orderedLeaders[index + 1] - 1) : instructionCount;
            const size_t blockIndex = blocks.size();
            for (size_t pc = start; pc <= end; ++pc)
                blockForPc[pc] = blockIndex;
            blocks.push_back({start, end, {}, terminatorByPc[end]});
        }
        for (Block& block : blocks)
        {
            for (size_t targetPc : successorsByPc[block.end])
                if (auto target = blockForPc.find(targetPc); target != blockForPc.end())
                    block.successors.push_back(target->second);
            std::sort(block.successors.begin(), block.successors.end());
            block.successors.erase(std::unique(block.successors.begin(), block.successors.end()), block.successors.end());
        }

        std::set<size_t> reachable;
        std::vector<size_t> work;
        for (size_t entryPc : entryPcs)
            if (auto entry = blockForPc.find(entryPc); entry != blockForPc.end())
                work.push_back(entry->second);
        for (size_t observedPc : observedPcs[prototypeId])
            if (auto observed = blockForPc.find(observedPc); observed != blockForPc.end())
                work.push_back(observed->second);
        while (!work.empty())
        {
            const size_t block = work.back();
            work.pop_back();
            if (block >= blocks.size() || !reachable.insert(block).second)
                continue;
            work.insert(work.end(), blocks[block].successors.begin(), blocks[block].successors.end());
        }
        size_t reachableInstructions = 0;
        size_t reachableInvalidEdges = 0;
        for (size_t block : reachable)
        {
            reachableInstructions += blocks[block].end - blocks[block].start + 1;
            reachableInvalidEdges += invalidEdgesByPc[blocks[block].end];
        }

        std::vector<int> indices(blocks.size(), -1), low(blocks.size(), -1);
        std::vector<size_t> stack;
        std::vector<bool> onStack(blocks.size(), false);
        std::vector<std::vector<size_t>> components;
        int nextIndex = 0;
        std::function<void(size_t)> visit = [&](size_t block) {
            indices[block] = low[block] = nextIndex++;
            stack.push_back(block);
            onStack[block] = true;
            for (size_t successor : blocks[block].successors)
            {
                if (!reachable.contains(successor))
                    continue;
                if (indices[successor] < 0)
                {
                    visit(successor);
                    low[block] = std::min(low[block], low[successor]);
                }
                else if (onStack[successor])
                    low[block] = std::min(low[block], indices[successor]);
            }
            if (low[block] != indices[block])
                return;
            std::vector<size_t> component;
            while (!stack.empty())
            {
                const size_t member = stack.back();
                stack.pop_back();
                onStack[member] = false;
                component.push_back(member);
                if (member == block)
                    break;
            }
            components.push_back(std::move(component));
        };
        for (size_t block : reachable)
            if (indices[block] < 0)
                visit(block);

        size_t cyclicRegions = 0;
        size_t irreducibleRegions = 0;
        for (const std::vector<size_t>& component : components)
        {
            const bool selfLoop = component.size() == 1 &&
                std::find(blocks[component[0]].successors.begin(), blocks[component[0]].successors.end(), component[0]) !=
                    blocks[component[0]].successors.end();
            if (component.size() == 1 && !selfLoop)
                continue;
            ++cyclicRegions;
            const std::set<size_t> members(component.begin(), component.end());
            std::set<size_t> entries;
            for (size_t source = 0; source < blocks.size(); ++source)
                if (!members.contains(source))
                    for (size_t target : blocks[source].successors)
                        if (members.contains(target))
                            entries.insert(target);
            if (entries.size() > 1)
                ++irreducibleRegions;
        }

        json blockRows = json::array();
        for (size_t index = 0; index < blocks.size(); ++index)
        {
            json successors = json::array();
            for (size_t target : blocks[index].successors)
                successors.push_back("p" + std::to_string(prototypeId) + "_b" + std::to_string(target + 1));
            blockRows.push_back({
                {"id", "p" + std::to_string(prototypeId) + "_b" + std::to_string(index + 1)},
                {"start_pc", blocks[index].start},
                {"end_pc", blocks[index].end},
                {"terminator", blocks[index].terminator},
                {"reachable", reachable.contains(index)},
                {"successors", std::move(successors)},
            });
            totalEdges += blocks[index].successors.size();
        }
        json entryBlocks = json::array();
        json entryPcRows = json::array();
        for (size_t entryPc : entryPcs)
        {
            entryPcRows.push_back(entryPc);
            if (auto entry = blockForPc.find(entryPc); entry != blockForPc.end())
                entryBlocks.push_back("p" + std::to_string(prototypeId) + "_b" + std::to_string(entry->second + 1));
        }
        prototypeRows.push_back({
            {"runtime_id", prototypeId},
            {"entry_pc", entryPcs.size() == 1 ? json(*entryPcs.begin()) : json(nullptr)},
            {"entry_pcs", std::move(entryPcRows)},
            {"entry_blocks", std::move(entryBlocks)},
            {"instruction_count", instructionCount},
            {"block_count", blocks.size()},
            {"reachable_blocks", reachable.size()},
            {"reachable_instructions", reachableInstructions},
            {"edge_count", std::accumulate(blocks.begin(), blocks.end(), size_t(0),
                [](size_t count, const Block& block) { return count + block.successors.size(); })},
            {"cyclic_regions", cyclicRegions},
            {"irreducible_regions", irreducibleRegions},
            {"invalid_edges", invalidEdges},
            {"reachable_invalid_edges", reachableInvalidEdges},
            {"observed_edge_sites", observedEdgeSites},
            {"blocks", std::move(blockRows)},
        });
        totalBlocks += blocks.size();
        totalReachable += reachable.size();
        totalReachableInstructions += reachableInstructions;
        totalCyclicRegions += cyclicRegions;
        totalIrreducibleRegions += irreducibleRegions;
        totalInvalidEdges += invalidEdges;
        totalReachableInvalidEdges += reachableInvalidEdges;
        totalObservedEdgeSites += observedEdgeSites;
    }
    return {
        {"version", 1},
        {"kind", "luraph-payload-cfg"},
        {"scope", "bootstrap-payload-closure"},
        {"prototype_count", prototypeRows.size()},
        {"block_count", totalBlocks},
        {"reachable_blocks", totalReachable},
        {"reachable_instructions", totalReachableInstructions},
        {"edge_count", totalEdges},
        {"cyclic_regions", totalCyclicRegions},
        {"irreducible_regions", totalIrreducibleRegions},
        {"invalid_edges", totalInvalidEdges},
        {"reachable_invalid_edges", totalReachableInvalidEdges},
        {"observed_edge_sites", totalObservedEdgeSites},
        {"prototypes", std::move(prototypeRows)},
    };
}

json luraphReachablePayloadIrArtifact(
    const json& payloadClosure, const json& payloadCfg, const LuraphOpcodeCatalog& opcodeCatalog)
{
    std::map<uint64_t, std::vector<std::pair<size_t, size_t>>> reachableRanges;
    std::map<uint64_t, json> entryPcsByPrototype;
    if (payloadCfg.contains("prototypes") && payloadCfg["prototypes"].is_array())
    {
        for (const json& prototype : payloadCfg["prototypes"])
        {
            const uint64_t id = prototype.value("runtime_id", uint64_t(0));
            if (id == 0 || !prototype.contains("blocks") || !prototype["blocks"].is_array())
                continue;
            entryPcsByPrototype[id] = prototype.value("entry_pcs", json::array({1}));
            for (const json& block : prototype["blocks"])
                if (block.value("reachable", false))
                    reachableRanges[id].push_back({
                        block.value("start_pc", size_t(0)),
                        block.value("end_pc", size_t(0)),
                    });
        }
    }

    json prototypes = json::array();
    json closureDescriptors = json::array();
    size_t instructionCount = 0;
    size_t protectorInstructions = 0;
    if (payloadClosure.contains("prototypes") && payloadClosure["prototypes"].is_array())
    {
        for (const json& prototype : payloadClosure["prototypes"])
        {
            const uint64_t id = prototype.value("runtime_id", uint64_t(0));
            auto ranges = reachableRanges.find(id);
            if (ranges == reachableRanges.end() || !prototype.contains("instructions") ||
                !prototype["instructions"].is_array())
                continue;
            json instructions = json::array();
            for (const json& instruction : prototype["instructions"])
            {
                const size_t pc = instruction.value("pc", size_t(0));
                if (instruction.contains("closure_descriptor") && instruction["closure_descriptor"].is_object())
                {
                    json descriptor = instruction["closure_descriptor"];
                    descriptor["prototype"] = id;
                    descriptor["pc"] = pc;
                    closureDescriptors.push_back(std::move(descriptor));
                }
                const bool reachable = std::any_of(ranges->second.begin(), ranges->second.end(),
                    [&](const auto& range) { return pc >= range.first && pc <= range.second; });
                if (!reachable)
                    continue;
                if (instruction.contains("semantic_operation") && instruction["semantic_operation"].is_object() &&
                    instruction["semantic_operation"].value("protector_state", false))
                    ++protectorInstructions;
                instructions.push_back(instruction);
                ++instructionCount;
            }
            prototypes.push_back({
                {"runtime_id", id},
                {"entry_pc", entryPcsByPrototype[id].size() == 1
                    ? entryPcsByPrototype[id][0] : json(nullptr)},
                {"entry_pcs", entryPcsByPrototype[id]},
                {"instruction_count", instructions.size()},
                {"instructions", std::move(instructions)},
            });
        }
    }

    std::map<uint64_t, uint64_t> prototypeByActivation;
    if (payloadClosure.contains("activations") && payloadClosure["activations"].is_array())
        for (const json& activation : payloadClosure["activations"])
            prototypeByActivation[activation.value("activation", uint64_t(0))] =
                activation.value("prototype", uint64_t(0));
    using ObservedCallEdgeKey = std::tuple<uint64_t, int64_t, int64_t, uint64_t>;
    struct ObservedCallFrame
    {
        size_t activation_count = 0;
        bool argument_count_complete = true;
        bool initialized = false;
        size_t argument_count = 0;
        std::vector<json> argument_identities;
        std::vector<bool> stable_argument_identities;
    };
    std::map<ObservedCallEdgeKey, ObservedCallFrame> observedCallFrames;
    if (payloadClosure.contains("activations") && payloadClosure["activations"].is_array())
    {
        for (const json& activation : payloadClosure["activations"])
        {
            if (!activation.contains("caller_activation") || !activation["caller_activation"].is_number_integer())
                continue;
            const int64_t callerActivation = activation["caller_activation"].get<int64_t>();
            auto callerPrototype = callerActivation > 0
                ? prototypeByActivation.find(static_cast<uint64_t>(callerActivation)) : prototypeByActivation.end();
            if (callerPrototype == prototypeByActivation.end())
                continue;
            const int64_t callerPc = activation.contains("caller_pc") && activation["caller_pc"].is_number_integer()
                ? activation["caller_pc"].get<int64_t>() : -1;
            const int64_t callerOpcode = activation.contains("caller_opcode") && activation["caller_opcode"].is_number_integer()
                ? activation["caller_opcode"].get<int64_t>() : -1;
            ObservedCallFrame& frame = observedCallFrames[{
                callerPrototype->second, callerPc, callerOpcode,
                activation.value("prototype", uint64_t(0)),
            }];
            ++frame.activation_count;

            std::optional<size_t> argumentCount;
            if (activation.contains("argument_count"))
            {
                const json& count = activation["argument_count"];
                if (count.is_number_unsigned() && count.get<uint64_t>() <= 16)
                    argumentCount = static_cast<size_t>(count.get<uint64_t>());
                else if (count.is_number_integer())
                {
                    const int64_t value = count.get<int64_t>();
                    if (value >= 0 && value <= 16)
                        argumentCount = static_cast<size_t>(value);
                }
            }
            const json arguments = activation.value("arguments", json(nullptr));
            if (!argumentCount || !arguments.is_array() || arguments.size() != *argumentCount)
            {
                frame.argument_count_complete = false;
                continue;
            }
            if (!frame.initialized)
            {
                frame.initialized = true;
                frame.argument_count = *argumentCount;
                frame.argument_identities.assign(arguments.begin(), arguments.end());
                frame.stable_argument_identities.resize(*argumentCount, true);
                for (size_t index = 0; index < *argumentCount; ++index)
                    if (!arguments[index].is_object() || arguments[index].value("type", "invalid") == "invalid")
                        frame.stable_argument_identities[index] = false;
                continue;
            }
            if (!frame.argument_count_complete || frame.argument_count != *argumentCount)
            {
                frame.argument_count_complete = false;
                continue;
            }
            for (size_t index = 0; index < *argumentCount; ++index)
                if (!arguments[index].is_object() || arguments[index].value("type", "invalid") == "invalid" ||
                    arguments[index] != frame.argument_identities[index])
                    frame.stable_argument_identities[index] = false;
        }
    }

    const auto observedCallerHandler = [&](int64_t opcode) -> std::optional<json> {
        if (opcode < 0 || !opcodeCatalog.available || !opcodeCatalog.document.contains("handlers") ||
            !opcodeCatalog.document["handlers"].is_array())
            return std::nullopt;
        const json* matched = nullptr;
        for (const json& handler : opcodeCatalog.document["handlers"])
        {
            if (handler.value("opcode", int64_t(-1)) != opcode)
                continue;
            if (matched)
                return std::nullopt;
            matched = &handler;
        }
        if (!matched || !matched->value("resolved", false) ||
            !matched->value("normalization_complete", false) || !matched->value("vm_state_independent", false) ||
            !matched->contains("effects") || !(*matched)["effects"].is_object() ||
            !matched->contains("semantic_operation") || !(*matched)["semantic_operation"].is_object())
            return std::nullopt;
        const json& effects = (*matched)["effects"];
        const json candidates = effects.value("operation_candidates", json::array());
        if (effects.value("calls", size_t(0)) != 1 || effects.value("register_calls", size_t(0)) != 1 ||
            !candidates.is_array() || candidates.size() != 1 || candidates[0] != "call")
            return std::nullopt;
        return json{
            {"opcode", opcode},
            {"normalization_complete", true},
            {"vm_state_independent", true},
            {"effects", effects},
            {"semantic_operation", (*matched)["semantic_operation"]},
        };
    };

    json callEdges = json::array();
    for (const auto& [edge, frame] : observedCallFrames)
    {
        const bool argumentCountComplete = frame.initialized && frame.argument_count_complete;
        json argumentIdentities = json::array();
        if (argumentCountComplete)
            for (size_t index = 0; index < frame.argument_count; ++index)
                if (frame.stable_argument_identities[index])
                    argumentIdentities.push_back({
                        {"argument_index", index + 1},
                        {"identity", frame.argument_identities[index]},
                        {"observed_activations", frame.activation_count},
                    });
        json row = {
            {"caller_prototype", std::get<0>(edge)},
            {"caller_pc", std::get<1>(edge)},
            {"caller_opcode", std::get<2>(edge)},
            {"callee_prototype", std::get<3>(edge)},
            {"observed_activations", frame.activation_count},
            {"observed_argument_count_complete", argumentCountComplete},
            {"observed_argument_count", argumentCountComplete ? json(frame.argument_count) : json(nullptr)},
            {"observed_argument_identities", std::move(argumentIdentities)},
        };
        if (const std::optional<json> handler = observedCallerHandler(std::get<2>(edge)))
            row["observed_caller_handler"] = *handler;
        callEdges.push_back(std::move(row));
    }

    struct ActivationTransitionSequence
    {
        uint64_t activation = 0;
        uint64_t first_vm_count = std::numeric_limits<uint64_t>::max();
        std::vector<size_t> next_pcs;
        std::set<int64_t> opcodes;
        std::set<std::string> instruction_fingerprints;
    };
    struct ActivationLaneSequence
    {
        uint64_t activation = 0;
        uint64_t first_vm_count = std::numeric_limits<uint64_t>::max();
        std::vector<json> frames;
    };
    using TransitionSite = std::pair<uint64_t, size_t>;
    std::map<TransitionSite, std::vector<size_t>> transitionSequences;
    std::map<TransitionSite, std::map<uint64_t, ActivationTransitionSequence>> activationTransitionSequences;
    std::map<TransitionSite, std::map<uint64_t, ActivationLaneSequence>> activationLaneSequences;
    if (payloadClosure.contains("observed_steps") && payloadClosure["observed_steps"].is_array())
        for (const json& step : payloadClosure["observed_steps"])
            if (step.contains("prototype") && step["prototype"].is_number_integer() &&
                step.contains("pc") && step["pc"].is_number_integer() &&
                step.contains("next_pc") && step["next_pc"].is_number_integer())
            {
                const int64_t prototype = step["prototype"].get<int64_t>();
                const int64_t pc = step["pc"].get<int64_t>();
                const int64_t nextPc = step["next_pc"].get<int64_t>();
                if (prototype > 0 && pc > 0 && nextPc > 0)
                {
                    const TransitionSite site{static_cast<uint64_t>(prototype), static_cast<size_t>(pc)};
                    transitionSequences[site].push_back(static_cast<size_t>(nextPc));
                    const uint64_t activation = step.value("activation", uint64_t(0));
                    if (activation > 0)
                    {
                        ActivationTransitionSequence& sequence = activationTransitionSequences[site][activation];
                        sequence.activation = activation;
                        sequence.first_vm_count = std::min(sequence.first_vm_count,
                            step.value("vm_count", uint64_t(0)));
                        sequence.next_pcs.push_back(static_cast<size_t>(nextPc));
                        if (step.contains("opcode") && step["opcode"].is_number_integer())
                            sequence.opcodes.insert(step["opcode"].get<int64_t>());
                        const json fingerprintSource = {
                            {"opcode", step.value("opcode", int64_t(-1))},
                            {"runtime_lanes", step.value("runtime_lanes", json::object())},
                        };
                        sequence.instruction_fingerprints.insert(sha256(fingerprintSource.dump()).substr(0, 16));
                    }
                    const json runtimeLanes = step.value("runtime_lanes", json::object());
                    if (activation > 0 && runtimeLanes.is_object())
                    {
                        json frame = json::object();
                        for (auto lane = runtimeLanes.begin(); lane != runtimeLanes.end(); ++lane)
                            if (lane.value().is_object() && lane.value().value("primitive", false) &&
                                lane.value().value("type", "") != "nil")
                                frame[lane.key()] = lane.value();
                        ActivationLaneSequence& laneSequence = activationLaneSequences[site][activation];
                        laneSequence.activation = activation;
                        laneSequence.first_vm_count = std::min(laneSequence.first_vm_count,
                            step.value("vm_count", uint64_t(0)));
                        laneSequence.frames.push_back(std::move(frame));
                    }
                }
            }
    json transitionRows = json::array();
    for (const auto& [site, sequence] : transitionSequences)
    {
        std::vector<ActivationTransitionSequence> orderedActivations;
        if (auto found = activationTransitionSequences.find(site); found != activationTransitionSequences.end())
            for (const auto& [activation, activationSequence] : found->second)
            {
                (void)activation;
                orderedActivations.push_back(activationSequence);
            }
        std::sort(orderedActivations.begin(), orderedActivations.end(), [](const auto& left, const auto& right) {
            if (left.first_vm_count != right.first_vm_count)
                return left.first_vm_count < right.first_vm_count;
            return left.activation < right.activation;
        });

        std::map<std::vector<size_t>, size_t> sequenceFrequency;
        for (const ActivationTransitionSequence& activation : orderedActivations)
            ++sequenceFrequency[activation.next_pcs];
        std::vector<std::vector<size_t>> normalizedSequences;
        normalizedSequences.reserve(orderedActivations.size());
        size_t prefixCompletedActivations = 0;
        for (const ActivationTransitionSequence& activation : orderedActivations)
        {
            std::vector<size_t> normalized = activation.next_pcs;
            size_t bestFrequency = 0;
            for (const auto& [candidate, frequency] : sequenceFrequency)
            {
                if (frequency < 3 || candidate.size() <= activation.next_pcs.size() ||
                    !std::equal(activation.next_pcs.begin(), activation.next_pcs.end(), candidate.begin()))
                    continue;
                if (frequency > bestFrequency ||
                    (frequency == bestFrequency && candidate.size() < normalized.size()))
                {
                    normalized = candidate;
                    bestFrequency = frequency;
                }
            }
            if (normalized != activation.next_pcs)
                ++prefixCompletedActivations;
            normalizedSequences.push_back(std::move(normalized));
        }

        size_t repeatFromSequence = 0;
        for (size_t index = 0; index + 3 <= normalizedSequences.size(); ++index)
        {
            const bool stable = std::all_of(normalizedSequences.begin() + static_cast<std::ptrdiff_t>(index + 1),
                normalizedSequences.end(), [&](const std::vector<size_t>& candidate) {
                    return candidate == normalizedSequences[index];
                });
            if (stable)
            {
                repeatFromSequence = index + 1;
                break;
            }
        }

        json activationRows = json::array();
        for (size_t index = 0; index < orderedActivations.size(); ++index)
        {
            const ActivationTransitionSequence& activation = orderedActivations[index];
            const bool prefixCompleted = normalizedSequences[index] != activation.next_pcs;
            activationRows.push_back({
                {"activation", activation.activation},
                {"first_vm_count", activation.first_vm_count == std::numeric_limits<uint64_t>::max()
                    ? json(nullptr) : json(activation.first_vm_count)},
                {"observed_next_pcs", activation.next_pcs},
                {"next_pcs", normalizedSequences[index]},
                {"prefix_completed_from_stable_epoch", prefixCompleted},
                {"opcodes", activation.opcodes},
                {"instruction_fingerprints", activation.instruction_fingerprints},
            });
        }
        transitionRows.push_back({
            {"prototype", site.first},
            {"pc", site.second},
            {"model", activationRows.empty() ? "legacy-global" : "activation-scoped"},
            {"next_pcs", sequence},
            {"activation_sequences", std::move(activationRows)},
            {"repeat_from_sequence", repeatFromSequence},
            {"prefix_completed_activations", prefixCompletedActivations},
        });
    }

    json laneReplayRows = json::array();
    for (const auto& [site, activations] : activationLaneSequences)
    {
        std::vector<ActivationLaneSequence> orderedActivations;
        for (const auto& [activation, sequence] : activations)
        {
            (void)activation;
            orderedActivations.push_back(sequence);
        }
        std::sort(orderedActivations.begin(), orderedActivations.end(), [](const auto& left, const auto& right) {
            if (left.first_vm_count != right.first_vm_count)
                return left.first_vm_count < right.first_vm_count;
            return left.activation < right.activation;
        });
        if (orderedActivations.empty() || orderedActivations.front().frames.empty())
            continue;

        std::set<std::string> commonLanes;
        for (auto lane = orderedActivations.front().frames.front().begin();
            lane != orderedActivations.front().frames.front().end(); ++lane)
            commonLanes.insert(lane.key());
        for (const ActivationLaneSequence& activation : orderedActivations)
            for (const json& frame : activation.frames)
                for (auto lane = commonLanes.begin(); lane != commonLanes.end();)
                    if (!frame.contains(*lane) || !frame[*lane].is_object())
                        lane = commonLanes.erase(lane);
                    else
                        ++lane;

        std::set<std::string> volatileLanes;
        for (const std::string& lane : commonLanes)
            for (const ActivationLaneSequence& activation : orderedActivations)
            {
                std::set<std::string> observedValues;
                for (const json& frame : activation.frames)
                    observedValues.insert(frame[lane].dump());
                if (observedValues.size() > 1)
                {
                    volatileLanes.insert(lane);
                    break;
                }
            }
        if (volatileLanes.empty())
            continue;

        std::vector<json> projectedSequences;
        for (const ActivationLaneSequence& activation : orderedActivations)
        {
            json frames = json::array();
            for (const json& frame : activation.frames)
            {
                json projected = json::object();
                for (const std::string& lane : volatileLanes)
                    projected[lane] = frame[lane];
                frames.push_back(std::move(projected));
            }
            projectedSequences.push_back(frames);
        }

        std::map<std::string, std::pair<size_t, json>> sequenceFrequency;
        for (const json& sequence : projectedSequences)
        {
            auto& frequency = sequenceFrequency[sequence.dump()];
            ++frequency.first;
            frequency.second = sequence;
        }
        std::vector<json> normalizedSequences;
        normalizedSequences.reserve(projectedSequences.size());
        size_t prefixCompletedActivations = 0;
        for (const json& observed : projectedSequences)
        {
            json normalized = observed;
            size_t bestFrequency = 0;
            for (const auto& [fingerprint, candidateEntry] : sequenceFrequency)
            {
                (void)fingerprint;
                const size_t frequency = candidateEntry.first;
                const json& candidate = candidateEntry.second;
                if (frequency < 3 || candidate.size() <= observed.size())
                    continue;
                bool prefixMatches = true;
                for (size_t index = 0; index < observed.size(); ++index)
                    if (observed[index] != candidate[index])
                    {
                        prefixMatches = false;
                        break;
                    }
                if (!prefixMatches)
                    continue;
                if (frequency > bestFrequency ||
                    (frequency == bestFrequency && candidate.size() < normalized.size()))
                {
                    normalized = candidate;
                    bestFrequency = frequency;
                }
            }
            if (normalized != observed)
                ++prefixCompletedActivations;
            normalizedSequences.push_back(std::move(normalized));
        }

        json activationRows = json::array();
        for (size_t index = 0; index < orderedActivations.size(); ++index)
        {
            const ActivationLaneSequence& activation = orderedActivations[index];
            activationRows.push_back({
                {"activation", activation.activation},
                {"first_vm_count", activation.first_vm_count == std::numeric_limits<uint64_t>::max()
                    ? json(nullptr) : json(activation.first_vm_count)},
                {"observed_frames", projectedSequences[index]},
                {"frames", normalizedSequences[index]},
                {"prefix_completed_from_stable_epoch", normalizedSequences[index] != projectedSequences[index]},
            });
        }
        size_t repeatFromSequence = 0;
        for (size_t index = 0; index + 3 <= normalizedSequences.size(); ++index)
        {
            const bool stable = std::all_of(normalizedSequences.begin() + static_cast<std::ptrdiff_t>(index + 1),
                normalizedSequences.end(), [&](const json& candidate) {
                    return candidate == normalizedSequences[index];
                });
            if (stable)
            {
                repeatFromSequence = index + 1;
                break;
            }
        }
        laneReplayRows.push_back({
            {"prototype", site.first},
            {"pc", site.second},
            {"lanes", volatileLanes},
            {"activation_sequences", std::move(activationRows)},
            {"repeat_from_sequence", repeatFromSequence},
            {"prefix_completed_activations", prefixCompletedActivations},
        });
    }

    json payloadActivationArguments = nullptr;
    json rootArgumentTablePrototypes = json::array();
    json rootArgumentTableIdentity = nullptr;
    const json payloadRoot = payloadClosure.value("payload_root", json(nullptr));
    const uint64_t payloadActivation = payloadRoot.is_object()
        ? payloadRoot.value("payload_activation", uint64_t(0)) : uint64_t(0);
    if (payloadActivation > 0 && payloadClosure.contains("activations") && payloadClosure["activations"].is_array())
        for (const json& activation : payloadClosure["activations"])
            if (activation.value("activation", uint64_t(0)) == payloadActivation)
            {
                payloadActivationArguments = activation;
                break;
            }
    if (payloadActivationArguments.is_object() &&
        !payloadActivationArguments.value("argument_object_conflict", false) &&
        payloadActivationArguments.contains("argument_objects") &&
        payloadActivationArguments["argument_objects"].is_array())
    {
        std::optional<uint64_t> rootObjectId;
        for (const json& object : payloadActivationArguments["argument_objects"])
            if (object.is_object() && object.value("argument_index", size_t(0)) == 1 &&
                object.contains("object_id") && object["object_id"].is_number_unsigned())
            {
                const uint64_t objectId = object["object_id"].get<uint64_t>();
                if (objectId > 0 && !rootObjectId)
                    rootObjectId = objectId;
                else if (objectId == 0 || (rootObjectId && *rootObjectId != objectId))
                {
                    rootObjectId.reset();
                    break;
                }
            }
        if (rootObjectId && payloadClosure.contains("activations") && payloadClosure["activations"].is_array())
        {
            std::set<uint64_t> sharedPrototypes;
            for (const json& activation : payloadClosure["activations"])
            {
                if (!activation.is_object() || activation.value("argument_object_conflict", false) ||
                    !activation.contains("argument_objects") || !activation["argument_objects"].is_array())
                    continue;
                for (const json& object : activation["argument_objects"])
                    if (object.is_object() && object.value("argument_index", size_t(0)) == 1 &&
                        object.value("object_id", uint64_t(0)) == *rootObjectId)
                        sharedPrototypes.insert(activation.value("prototype", uint64_t(0)));
            }
            sharedPrototypes.erase(0);
            for (uint64_t prototype : sharedPrototypes)
                rootArgumentTablePrototypes.push_back(prototype);
            rootArgumentTableIdentity = {
                {"object_id", *rootObjectId},
                {"argument_index", 1},
                {"prototype_count", sharedPrototypes.size()},
                {"evidence", "runtime_table_object_identity"},
                {"complete_for_listed_prototypes", true},
            };
        }
    }

    return {
        {"version", 1},
        {"kind", "luraph-reachable-payload-semantic-ir"},
        {"scope", "entry-reachable-instructions-only"},
        {"payload_root", payloadRoot},
        {"payload_activation_arguments", std::move(payloadActivationArguments)},
        {"root_argument_table_identity", std::move(rootArgumentTableIdentity)},
        {"root_argument_table_prototypes", std::move(rootArgumentTablePrototypes)},
        {"prototype_count", prototypes.size()},
        {"instruction_count", instructionCount},
        {"source_semantic_instructions", instructionCount - protectorInstructions},
        {"protector_internal_instructions", protectorInstructions},
        {"observed_return_count", payloadClosure.value("observed_return_count", size_t(0))},
        {"observed_returns", payloadClosure.value("observed_returns", json::array())},
        {"prototype_call_edges", std::move(callEdges)},
        {"observed_transition_sequences", std::move(transitionRows)},
        {"observed_lane_sequences", std::move(laneReplayRows)},
        {"observed_capture_domains", payloadClosure.value("observed_capture_domains", json::array())},
        {"closure_descriptors", std::move(closureDescriptors)},
        {"prototypes", std::move(prototypes)},
    };
}

std::string shortenLuraphReadableText(std::string value, size_t limit = 96)
{
    for (char& ch : value)
        if (ch == '\n' || ch == '\r' || ch == '\t')
            ch = ' ';
    value = trim(value);
    if (value.size() <= limit)
        return value;
    value.resize(limit > 3 ? limit - 3 : limit);
    return value + "...";
}

std::string luraphJsonStringOr(const json& object, std::string_view key, std::string fallback = {})
{
    if (!object.is_object())
        return fallback;
    auto value = object.find(std::string(key));
    return value != object.end() && value->is_string() ? value->get<std::string>() : fallback;
}

std::string luraphReadablePrimitive(const json& value)
{
    if (value.is_null())
        return "nothing";
    if (value.is_boolean())
        return value.get<bool>() ? "true" : "false";
    if (value.is_number())
        return value.dump();
    if (value.is_string())
        return quoteLuau(shortenLuraphReadableText(value.get<std::string>()));
    if (!value.is_object())
        return "an unknown value";

    const std::string type = luraphJsonStringOr(value, "type");
    if (type == "nil")
        return "nothing";
    if (type == "boolean")
        return luraphJsonStringOr(value, "value", "false");
    if (type == "number")
        return luraphJsonStringOr(value, "value", "0");
    if (type == "string")
        return quoteLuau(shortenLuraphReadableText(luraphJsonStringOr(value, "value")));
    if (type == "function")
    {
        const std::string name = luraphJsonStringOr(value, "name");
        return name.empty() ? "a function" : "the function " + quoteLuau(name);
    }
    return "a " + (type.empty() ? std::string("value") : type) + " value";
}

std::string luraphReadableExpression(const json& expression, size_t depth = 0)
{
    if (depth > 24)
        return "a nested value";
    if (!expression.is_object())
        return luraphReadablePrimitive(expression);

    const std::string kind = luraphJsonStringOr(expression, "kind");
    if (kind == "immediate")
        return luraphReadablePrimitive(expression.value("value", json(nullptr)));
    if (kind == "constant")
        return luraphReadablePrimitive(expression.value("value", json(nullptr)));
    if (kind == "observed_register_value")
        return luraphReadablePrimitive(expression.value("value", json(nullptr)));
    if (kind == "register_read")
        return "temporary " + luraphReadableExpression(expression.value("index", json(nullptr)), depth + 1);
    if (kind == "top_register")
        return "the current result position";
    if (kind == "register_file")
        return "the temporary-value area";
    if (kind == "upvalue_file")
        return "the captured values";
    if (kind == "varargs")
        return "the extra arguments";
    if (kind == "semantic_local")
        return luraphJsonStringOr(expression, "name", "a local value");
    if (kind == "vm_state")
        return "internal state " + quoteLuau(luraphJsonStringOr(expression, "name", "?"));
    if (kind == "helper_table")
        return "an internal helper table";
    if (kind == "opcode_table")
        return "the protected instruction table";
    if (kind == "operand_table")
        return "the protected operand table";
    if (kind == "index_read")
    {
        const std::string table = luraphReadableExpression(expression.value("table", json(nullptr)), depth + 1);
        const std::string index = luraphReadableExpression(expression.value("index", json(nullptr)), depth + 1);
        return "the entry " + index + " inside " + table;
    }
    if (kind == "binary")
    {
        const std::string left = luraphReadableExpression(expression.value("left", json(nullptr)), depth + 1);
        const std::string right = luraphReadableExpression(expression.value("right", json(nullptr)), depth + 1);
        return "(" + left + " " + luraphJsonStringOr(expression, "operator", "?") + " " + right + ")";
    }
    if (kind == "unary")
        return luraphJsonStringOr(expression, "operator") + " " +
            luraphReadableExpression(expression.value("value", json(nullptr)), depth + 1);
    if (kind == "call")
    {
        std::string result = "call " + luraphReadableExpression(expression.value("function", json(nullptr)), depth + 1);
        if (expression.contains("arguments") && expression["arguments"].is_array())
        {
            result += " with ";
            if (expression["arguments"].empty())
                result += "no arguments";
            else
                result += std::to_string(expression["arguments"].size()) +
                    (expression["arguments"].size() == 1 ? " argument" : " arguments");
        }
        return result;
    }
    if (kind == "register_range")
        return "temporary values " + luraphReadableExpression(expression.value("from", json(nullptr)), depth + 1) +
            " through " + luraphReadableExpression(expression.value("to", json(nullptr)), depth + 1);
    if (kind == "table")
        return "a new table";
    return kind.empty() ? "an unknown value" : "a " + kind + " value";
}

bool luraphReadableContainsKind(const json& value, std::string_view wanted, size_t depth = 0)
{
    if (depth > 64)
        return false;
    if (value.is_object())
    {
        if (luraphJsonStringOr(value, "kind") == wanted)
            return true;
        for (const auto& [key, child] : value.items())
            if (luraphReadableContainsKind(child, wanted, depth + 1))
                return true;
    }
    else if (value.is_array())
    {
        for (const json& child : value)
            if (luraphReadableContainsKind(child, wanted, depth + 1))
                return true;
    }
    return false;
}

void collectLuraphReadableSymbols(const json& value, std::set<std::string>& functions, std::set<std::string>& strings,
    size_t depth = 0)
{
    if (depth > 64)
        return;
    if (value.is_object())
    {
        if (luraphJsonStringOr(value, "kind") == "observed_register_value" && value.contains("value") && value["value"].is_object())
        {
            const json& observed = value["value"];
            const std::string type = luraphJsonStringOr(observed, "type");
            if (type == "function")
            {
                const std::string name = luraphJsonStringOr(observed, "name");
                if (!name.empty())
                    functions.insert(name);
            }
            else if (type == "string")
            {
                const std::string text = shortenLuraphReadableText(luraphJsonStringOr(observed, "value"));
                if (!text.empty() && printableAscii(text))
                    strings.insert(text);
            }
        }
        for (const auto& [key, child] : value.items())
            collectLuraphReadableSymbols(child, functions, strings, depth + 1);
    }
    else if (value.is_array())
    {
        for (const json& child : value)
            collectLuraphReadableSymbols(child, functions, strings, depth + 1);
    }
}

std::optional<std::string> luraphReadableObservedValue(const json& operation)
{
    if (!operation.is_object() || !operation.contains("runtime_resolution") ||
        !operation["runtime_resolution"].is_object())
        return std::nullopt;
    const json& resolution = operation["runtime_resolution"];
    if (!resolution.contains("value"))
        return std::nullopt;
    return luraphReadablePrimitive(resolution["value"]);
}

bool luraphReadableObservedNamedValue(const json& operation)
{
    if (!operation.is_object() || !operation.contains("runtime_resolution") ||
        !operation["runtime_resolution"].is_object())
        return false;
    const json& resolution = operation["runtime_resolution"];
    if (!resolution.contains("value") || !resolution["value"].is_object())
        return false;
    const json& value = resolution["value"];
    const std::string type = luraphJsonStringOr(value, "type");
    if (type == "function")
        return !luraphJsonStringOr(value, "name").empty();
    if (type == "string")
        return luraphJsonStringOr(value, "value").size() >= 4;
    return false;
}

std::string luraphReadableTarget(const json& target)
{
    if (!target.is_object())
        return "a value";
    const std::string kind = luraphJsonStringOr(target, "kind");
    if (kind == "register")
        return "temporary " + luraphReadableExpression(target.value("index", json(nullptr)));
    if (kind == "index")
        return "entry " + luraphReadableExpression(target.value("index", json(nullptr))) + " inside " +
            luraphReadableExpression(target.value("table", json(nullptr)));
    if (kind == "top_register")
        return "the current result position";
    if (kind == "semantic_local")
        return luraphJsonStringOr(target, "name", "a local value");
    if (kind == "vm_state")
        return "internal state " + quoteLuau(luraphJsonStringOr(target, "name", "?"));
    return kind.empty() ? "a value" : "a " + kind + " value";
}

std::string describeLuraphReadableOperation(const json& operation, size_t depth = 0)
{
    if (!operation.is_object() || depth > 12)
        return "Performs a recovered operation.";
    const std::string kind = luraphJsonStringOr(operation, "kind");
    if (kind == "register_write")
    {
        const std::string destination = "temporary " +
            luraphReadableExpression(operation.value("register", json(nullptr)), depth + 1);
        if (std::optional<std::string> observed = luraphReadableObservedValue(operation))
            return "Recovers " + *observed + " and remembers it as " + destination + ".";
        const json value = operation.value("value", json(nullptr));
        if (luraphReadableContainsKind(value, "call"))
            return "Runs " + luraphReadableExpression(value, depth + 1) + " and saves the answer as " + destination + ".";
        if (value.is_object() && value.value("kind", "") == "index_read")
            return "Reads " + luraphReadableExpression(value, depth + 1) + " and remembers it as " + destination + ".";
        return "Sets " + destination + " to " + luraphReadableExpression(value, depth + 1) + ".";
    }
    if (kind == "table_write")
        return "Stores " + luraphReadableExpression(operation.value("value", json(nullptr)), depth + 1) + " at " +
            luraphReadableExpression(operation.value("index", json(nullptr)), depth + 1) + " inside " +
            luraphReadableExpression(operation.value("table", json(nullptr)), depth + 1) + ".";
    if (kind == "expression")
    {
        const json value = operation.value("value", json(nullptr));
        return luraphReadableContainsKind(value, "call")
            ? "Runs " + luraphReadableExpression(value, depth + 1) + "."
            : "Evaluates " + luraphReadableExpression(value, depth + 1) + ".";
    }
    if (kind == "branch")
        return "Checks whether " + luraphReadableExpression(operation.value("condition", json(nullptr)), depth + 1) +
            "; the answer chooses which path runs next.";
    if (kind == "jump")
        return "Continues at recovered step " + luraphReadableExpression(operation.value("target", json(nullptr)), depth + 1) + ".";
    if (kind == "return")
    {
        const json values = operation.value("values", json::array());
        if (!values.is_array() || values.empty())
            return "Finishes this routine without returning a value.";
        std::string result = "Finishes this routine and returns ";
        for (size_t index = 0; index < values.size(); ++index)
        {
            if (index > 0)
                result += index + 1 == values.size() ? " and " : ", ";
            result += luraphReadableExpression(values[index], depth + 1);
        }
        return result + ".";
    }
    if (kind == "numeric_for")
        return "Repeats a counted loop from " + luraphReadableExpression(operation.value("from", json(nullptr)), depth + 1) +
            " to " + luraphReadableExpression(operation.value("to", json(nullptr)), depth + 1) + ".";
    if (kind == "generic_for_prepare")
        return "Prepares to repeat work for every value in a collection.";
    if (kind == "capture_varargs")
        return "Collects any extra arguments passed to this routine.";
    if (kind == "close_upvalues")
        return "Finishes using values captured by nested routines.";
    if (kind == "set_top" || kind == "adjust_top")
        return "Updates how many call results are currently active.";
    if (kind == "assign")
    {
        const json targets = operation.value("targets", json::array());
        const json values = operation.value("values", json::array());
        if (targets.is_array() && targets.size() == 1 && values.is_array() && values.size() == 1)
            return "Sets " + luraphReadableTarget(targets[0]) + " to " + luraphReadableExpression(values[0], depth + 1) + ".";
        return "Updates " + std::to_string(targets.is_array() ? targets.size() : 0) + " values together.";
    }
    if (kind == "compound_write")
        return "Updates " + luraphReadableTarget(operation.value("target", json(nullptr))) + " using " +
            luraphJsonStringOr(operation, "operator", "an arithmetic operation") + ".";
    if (kind == "operation_sequence")
    {
        std::vector<std::string> parts;
        const json operations = operation.value("operations", json::array());
        if (operations.is_array())
            for (const json& child : operations)
            {
                const std::string childKind = child.is_object() ? luraphJsonStringOr(child, "kind") : "";
                if (childKind == "set_top" || childKind == "adjust_top")
                    continue;
                parts.push_back(describeLuraphReadableOperation(child, depth + 1));
            }
        if (parts.empty())
            return "Updates the current call results.";
        std::string result;
        for (size_t index = 0; index < parts.size(); ++index)
        {
            if (index > 0)
                result += " Then ";
            result += parts[index];
        }
        return result;
    }
    if (kind == "protector_internal_sequence" || kind == "prepare_vm_state" ||
        kind == "prepare_register_clear" || kind == "clear_prepared_register_range")
        return "Performs internal protection bookkeeping.";
    return "Performs a recovered " + (kind.empty() ? std::string("operation") : kind) + ".";
}

bool luraphReadableKeyAction(const json& operation)
{
    if (!operation.is_object() || operation.value("protector_state", false))
        return false;
    const std::string kind = luraphJsonStringOr(operation, "kind");
    if (kind == "protector_internal_sequence" || kind == "prepare_vm_state" ||
        kind == "prepare_register_clear" || kind == "clear_prepared_register_range" || kind == "jump" || kind == "set_top")
        return false;
    return kind == "branch" || kind == "return" || kind == "numeric_for" || kind == "generic_for_prepare" ||
        kind == "capture_varargs" || kind == "close_upvalues" || kind == "table_write" ||
        luraphReadableContainsKind(operation, "call") || luraphReadableObservedNamedValue(operation);
}

int luraphReadableActionPriority(const json& operation)
{
    const std::string kind = luraphJsonStringOr(operation, "kind");
    if (luraphReadableContainsKind(operation, "call"))
        return 1;
    if (luraphReadableObservedNamedValue(operation))
        return 2;
    if (kind == "return" || kind == "capture_varargs" || kind == "close_upvalues")
        return 3;
    if (kind == "numeric_for" || kind == "generic_for_prepare")
        return 4;
    if (kind == "branch")
        return 5;
    if (kind == "table_write")
        return 6;
    return 7;
}

std::string joinLuraphReadable(const std::set<std::string>& values, size_t limit = 24)
{
    std::string result;
    size_t count = 0;
    for (const std::string& value : values)
    {
        if (count >= limit)
            break;
        if (!result.empty())
            result += ", ";
        result += value;
        ++count;
    }
    if (values.size() > count)
        result += ", and " + std::to_string(values.size() - count) + " more";
    return result;
}

bool luraphReadableHasAny(const std::set<std::string>& symbols, std::initializer_list<std::string_view> names)
{
    return std::any_of(names.begin(), names.end(), [&](std::string_view name) {
        return symbols.contains(std::string(name));
    });
}

std::string luraphReadableRoutineRole(const std::set<std::string>& functions, const std::map<std::string, size_t>& kinds,
    bool root, bool hasChildren)
{
    std::vector<std::string> roles;
    if (luraphReadableHasAny(functions, {"getfenv", "setfenv", "info", "traceback", "identifyexecutor", "iscclosure", "islclosure"}))
        roles.push_back("execution-environment and integrity checker");
    if (luraphReadableHasAny(functions, {"byte", "char", "concat", "find", "format", "gmatch", "gsub", "match", "rep", "sub"}))
        roles.push_back("text decoder or transformer");
    if (luraphReadableHasAny(functions, {"spawn", "defer", "delay", "wait", "cancel"}))
        roles.push_back("task scheduler helper");
    if (luraphReadableHasAny(functions, {"resume", "wrap", "running", "isyieldable", "close"}))
        roles.push_back("coroutine and callback helper");
    if (luraphReadableHasAny(functions, {"rawget", "rawset", "setmetatable", "getmetatable", "insert", "pack", "unpack"}))
        roles.push_back("table and metatable helper");
    if (luraphReadableHasAny(functions, {"pcall", "xpcall", "assert", "error"}))
        roles.push_back("protected-call and error handler");
    if (luraphReadableHasAny(functions, {"loadstring"}))
        roles.push_back("dynamic Luau loader");
    if (roles.empty() && hasChildren)
        roles.push_back(root ? "main coordinator for recovered helper routines" : "coordinator for nested helper routines");
    if (roles.empty() && kinds.contains("numeric_for") && kinds.at("numeric_for") > 0)
        roles.push_back("repeated data-processing helper");
    if (roles.empty() && kinds.contains("table_write") && kinds.at("table_write") > 0)
        roles.push_back("table-building helper");
    if (roles.empty())
        roles.push_back("low-level value-processing helper");

    std::string result;
    for (size_t index = 0; index < roles.size() && index < 3; ++index)
    {
        if (!result.empty())
            result += index + 1 == std::min<size_t>(roles.size(), 3) ? " and " : ", ";
        result += roles[index];
    }
    return result;
}

std::string buildLuraphReadableLift(const json& reachableIr)
{
    struct ActionSummary
    {
        size_t first_pc = 0;
        size_t count = 0;
        size_t observations = 0;
        int priority = 7;
    };

    std::map<uint64_t, std::map<size_t, std::map<uint64_t, size_t>>> calleesBySite;
    if (reachableIr.contains("prototype_call_edges") && reachableIr["prototype_call_edges"].is_array())
        for (const json& edge : reachableIr["prototype_call_edges"])
            calleesBySite[edge.value("caller_prototype", uint64_t(0))][edge.value("caller_pc", size_t(0))]
                [edge.value("callee_prototype", uint64_t(0))] += edge.value("observed_activations", size_t(0));

    std::set<std::string> allFunctions;
    std::set<std::string> allStrings;
    collectLuraphReadableSymbols(reachableIr, allFunctions, allStrings);
    const json payloadRoot = reachableIr.value("payload_root", json(nullptr));
    const uint64_t rootPrototype = payloadRoot.is_object()
        ? payloadRoot.value("payload_prototype", uint64_t(0)) : uint64_t(0);

    std::ostringstream out;
    out << "LURAPH LIFTED PROGRAM - PLAIN-LANGUAGE GUIDE\n";
    out << "================================================\n\n";
    out << "WHAT THIS FILE IS\n";
    out << "This is the readable view of the recovered program behavior. It is not the original source code yet: "
           "the original names, comments, and formatting were erased by the protector. The exact machine-readable lift remains in payload_reachable_ir.json.\n\n";
    out << "THE SHORT VERSION\n";
    out << "The captured program first behaves like a protected loader: it checks the environment, reconstructs text and tables, "
           "sets up safe-call and coroutine/task helpers, and keeps a path able to compile hidden Luau. Most of the behavior visible "
           "so far is protection and runtime support. The final gameplay or user-script behavior has not yet been cleanly separated, "
           "so this report deliberately does not invent a story for it.\n\n";
    out << "RECOVERY SUMMARY\n";
    out << "- " << reachableIr.value("prototype_count", size_t(0)) << " recovered routines (a routine is a hidden function).\n";
    out << "- " << reachableIr.value("instruction_count", size_t(0)) << " reachable operations were translated into meanings.\n";
    out << "- " << reachableIr.value("source_semantic_instructions", size_t(0)) << " operations describe program behavior.\n";
    out << "- " << reachableIr.value("protector_internal_instructions", size_t(0))
        << " protection-only operations are identified and collapsed in this guide.\n";
    out << "- The recovered main routine is routine " << (rootPrototype == 0 ? 1 : rootPrototype) << ".\n\n";

    out << "WHAT THE RECOVERED LAYER APPEARS TO DO\n";
    if (luraphReadableHasAny(allFunctions, {"getfenv", "setfenv", "info", "traceback", "getmetatable"}))
        out << "- Examines the execution environment, stack/debug information, and metatables.\n";
    if (luraphReadableHasAny(allFunctions, {"loadstring"}))
        out << "- Contains a path that can compile and run Luau text.\n";
    if (luraphReadableHasAny(allFunctions, {"spawn", "defer", "delay", "wait", "cancel"}))
        out << "- Schedules immediate, deferred, delayed, and cancelable work.\n";
    if (luraphReadableHasAny(allFunctions, {"resume", "wrap", "running", "isyieldable", "close"}))
        out << "- Coordinates coroutines, yielding, and resumed callbacks.\n";
    if (luraphReadableHasAny(allFunctions, {"pcall", "xpcall", "assert", "error"}))
        out << "- Runs protected calls and handles failures or assertions.\n";
    if (luraphReadableHasAny(allFunctions, {"byte", "char", "concat", "find", "format", "gmatch", "gsub", "match", "rep", "sub"}))
        out << "- Decodes, searches, formats, and rebuilds text.\n";
    if (luraphReadableHasAny(allFunctions, {"rawget", "rawset", "setmetatable", "getmetatable", "insert", "pack", "unpack"}))
        out << "- Builds and modifies tables, including low-level table and metatable access.\n";
    if (luraphReadableHasAny(allFunctions, {"HttpGet", "RequestAsync", "request", "http_request"}))
        out << "- Includes an observed web-request capability.\n";
    else
        out << "- No named web-request function was observed in the captured execution path.\n";
    out << "These are evidence-backed capability clues, not a claim that every path ran to completion.\n\n";

    if (!allFunctions.empty())
    {
        out << "NAMED FUNCTIONS OBSERVED\n";
        out << joinLuraphReadable(allFunctions, 40) << "\n\n";
    }
    if (!allStrings.empty())
    {
        std::set<std::string> usefulStrings;
        for (const std::string& value : allStrings)
            if (value.size() >= 4)
                usefulStrings.insert(quoteLuau(value));
        if (!usefulStrings.empty())
        {
            out << "READABLE TEXT OBSERVED\n";
            out << joinLuraphReadable(usefulStrings, 30) << "\n\n";
        }
    }

    out << "ROUTINE-BY-ROUTINE WALKTHROUGH\n";
    out << "Temporary numbers below are generated labels for values whose original names were removed.\n\n";
    if (!reachableIr.contains("prototypes") || !reachableIr["prototypes"].is_array())
        return out.str();

    for (const json& prototype : reachableIr["prototypes"])
    {
        const uint64_t id = prototype.value("runtime_id", uint64_t(0));
        const bool root = id == rootPrototype;
        std::map<std::string, size_t> kindCounts;
        std::set<std::string> functions;
        std::set<std::string> strings;
        std::map<std::string, ActionSummary> actions;
        size_t protector = 0;
        if (prototype.contains("instructions") && prototype["instructions"].is_array())
        {
            for (const json& instruction : prototype["instructions"])
            {
                const json operation = instruction.value("semantic_operation", json(nullptr));
                const std::string kind = operation.is_object() ? operation.value("kind", "unknown") : "unknown";
                ++kindCounts[kind];
                collectLuraphReadableSymbols(operation, functions, strings);
                if ((operation.is_object() && operation.value("protector_state", false)) ||
                    kind == "protector_internal_sequence")
                    ++protector;
                const size_t pc = instruction.value("pc", size_t(0));
                auto caller = calleesBySite.find(id);
                if (caller != calleesBySite.end())
                {
                    auto site = caller->second.find(pc);
                    if (site != caller->second.end())
                    {
                        for (const auto& [callee, observations] : site->second)
                        {
                            const std::string description = "Runs recovered routine " + std::to_string(callee) + ".";
                            ActionSummary& summary = actions[description];
                            if (summary.count == 0)
                            {
                                summary.first_pc = pc;
                                summary.priority = 0;
                            }
                            ++summary.count;
                            summary.observations += observations;
                        }
                        continue;
                    }
                }
                if (!luraphReadableKeyAction(operation))
                    continue;
                const std::string description = describeLuraphReadableOperation(operation);
                ActionSummary& summary = actions[description];
                if (summary.count == 0)
                {
                    summary.first_pc = pc;
                    summary.priority = luraphReadableActionPriority(operation);
                }
                ++summary.count;
            }
        }

        out << "ROUTINE " << id << (root ? " - MAIN ENTRY" : " - HELPER") << "\n";
        out << "  Size: " << prototype.value("instruction_count", size_t(0)) << " recovered operations";
        if (protector > 0)
            out << "; " << protector << " protection-only operations collapsed";
        out << ".\n";
        out << "  Shape: " << kindCounts["branch"] << " decisions, "
            << kindCounts["numeric_for"] + kindCounts["generic_for_prepare"] << " loop steps, "
            << kindCounts["operation_sequence"] << " call sequences, and " << kindCounts["return"] << " exits.\n";
        out << "  Likely role: " << luraphReadableRoutineRole(functions, kindCounts, root,
            calleesBySite.contains(id) && !calleesBySite[id].empty()) << ".\n";
        if (!functions.empty())
            out << "  Named functions used: " << joinLuraphReadable(functions, 18) << ".\n";
        std::set<std::string> readableStrings;
        for (const std::string& value : strings)
            if (value.size() >= 4)
                readableStrings.insert(quoteLuau(value));
        if (!readableStrings.empty())
            out << "  Text clues: " << joinLuraphReadable(readableStrings, 12) << ".\n";
        if (actions.empty())
            out << "  Key actions: only low-level value preparation was observed on the reachable path.\n";
        else
        {
            out << "  Key actions:\n";
            std::vector<std::pair<std::string, ActionSummary>> orderedActions(actions.begin(), actions.end());
            std::sort(orderedActions.begin(), orderedActions.end(), [](const auto& left, const auto& right) {
                if (left.second.priority != right.second.priority)
                    return left.second.priority < right.second.priority;
                if (left.second.first_pc != right.second.first_pc)
                    return left.second.first_pc < right.second.first_pc;
                return left.first < right.first;
            });
            size_t emitted = 0;
            std::map<int, size_t> categoryCounts;
            for (const auto& [description, summary] : orderedActions)
            {
                if (emitted >= 36)
                    break;
                const size_t categoryLimit = summary.priority <= 2 ? 18 :
                    summary.priority == 3 ? 8 : summary.priority == 4 ? 8 : 6;
                if (categoryCounts[summary.priority] >= categoryLimit)
                    continue;
                out << "  - At recovered step " << summary.first_pc << ": ";
                if (summary.priority == 0)
                    out << "(" << summary.count << (summary.count == 1 ? " call site, " : " call sites, ")
                        << summary.observations << (summary.observations == 1 ? " observed run) " : " observed runs) ");
                else if (summary.count > 1)
                    out << "(" << summary.count << " similar actions) ";
                out << description << "\n";
                ++emitted;
                ++categoryCounts[summary.priority];
            }
            if (actions.size() > emitted)
                out << "  - " << actions.size() - emitted << " additional repeated/detail actions are retained in payload_reachable_ir.json.\n";
        }
        out << "\n";
    }

    out << "HOW TO INTERPRET THIS RESULT\n";
    out << "The program has been lifted from hidden VM instructions into explicit behavior. The next reconstruction pass must "
           "combine temporary values, recover loops/conditions as normal Luau, and assign useful local names. Until that pass "
           "compiles and matches the protected program, this guide remains an explanation of the lift rather than claimed source code.\n";
    return out.str();
}

struct LuraphObservedCandidate
{
    bool complete = false;
    std::string source;
    json provenance = json::array();
};

bool luraphObservedValueMatches(const LuraphTraceValue& expected, const json& observed)
{
    if (!observed.is_object() || observed.value("type", "") != expected.type)
        return false;
    if (expected.type == "nil")
        return observed.contains("value") && observed["value"].is_null();
    if (expected.type == "string")
    {
        if (observed.contains("bytes_hex") && observed["bytes_hex"].is_string())
            return observed["bytes_hex"].get<std::string>() == hexBytes(expected.value);
        return observed.value("value", "") == expected.value;
    }
    if (expected.type == "boolean")
        return observed.value("value", "") == expected.value;
    if (expected.type == "number")
    {
        const std::optional<double> left = NumericParser(expected.value).parse();
        const std::optional<double> right = observed.contains("value") && observed["value"].is_string()
            ? NumericParser(observed["value"].get<std::string>()).parse() : std::nullopt;
        return left && right && *left == *right;
    }
    return false;
}

LuraphObservedCandidate buildLuraphObservedCandidate(
    const LuraphRuntimeStructureTrace& runtime,
    const LuraphDynamicTrace& dynamic)
{
    LuraphObservedCandidate candidate;
    if (dynamic.calls.empty())
        return candidate;

    for (const LuraphTraceCall& call : dynamic.calls)
    {
        const std::optional<std::string> statement = luraphTraceCallSource(call);
        if (!statement || !call.register_index)
            return candidate;

        std::map<int64_t, json> latestWrites;
        for (const json& step : runtime.steps)
        {
            if (step.value("activation", uint64_t(0)) != call.activation ||
                step.value("vm_count", uint64_t(0)) > call.vm_count ||
                !step.contains("register_writes") || !step["register_writes"].is_array())
                continue;
            for (const json& write : step["register_writes"])
                if (write.contains("register") && write["register"].is_number_integer() && write.contains("value"))
                    latestWrites[write["register"].get<int64_t>()] = {
                        {"vm_count", step["vm_count"]},
                        {"pc", step["pc"]},
                        {"opcode", step["opcode"]},
                        {"value", write["value"]},
                    };
        }

        auto functionProducer = latestWrites.find(*call.register_index);
        if (functionProducer == latestWrites.end())
            return candidate;
        const json& functionValue = functionProducer->second["value"];
        if (functionValue.value("type", "") != "function" || functionValue.value("name", "") != call.target)
            return candidate;

        json argumentProducers = json::array();
        for (size_t index = 0; index < call.arguments.size(); ++index)
        {
            const int64_t argumentRegister = *call.register_index + static_cast<int64_t>(index) + 1;
            auto producer = latestWrites.find(argumentRegister);
            if (producer == latestWrites.end() || !luraphObservedValueMatches(call.arguments[index], producer->second["value"]))
                return candidate;
            json row = producer->second;
            row["register"] = argumentRegister;
            row["argument"] = index + 1;
            argumentProducers.push_back(std::move(row));
        }

        candidate.source += *statement + "\n";
        candidate.provenance.push_back({
            {"statement", *statement},
            {"call", {{"vm_count", call.vm_count}, {"activation", call.activation}, {"pc", call.pc},
                         {"opcode", call.opcode}, {"register", *call.register_index}, {"output_confirmed", call.output_confirmed}}},
            {"function_producer", functionProducer->second},
            {"argument_producers", std::move(argumentProducers)},
            {"claim", "observed_value_slice"},
        });
    }
    candidate.complete = !candidate.source.empty();
    return candidate;
}

struct LuraphStatementReconstruction
{
    bool complete = false;
    bool full_instruction_coverage = false;
    std::string source;
    std::string reason = "not_attempted";
    std::string proof_scope = "none";
    size_t covered_instructions = 0;
    json coverage = json::array();
    json statements = json::array();
    json decoder_prototypes = json::array();
};

LuraphStatementReconstruction buildLuraphObservedOutputReconstruction(
    const json& closure,
    const LuraphObservedCandidate& candidate,
    const LuraphDynamicTrace& dynamic)
{
    LuraphStatementReconstruction result;
    result.reason = "observed_output_proof_incomplete";
    if (!candidate.complete || !dynamic.payload_activation_complete || dynamic.calls.empty() ||
        !closure.contains("activations") || !closure["activations"].is_array() ||
        !closure.contains("observed_returns") || !closure["observed_returns"].is_array())
        return result;

    const uint64_t rootActivation = dynamic.calls.front().activation;
    uint64_t lastCallVmCount = 0;
    for (const LuraphTraceCall& call : dynamic.calls)
    {
        if (call.activation != rootActivation || (call.target != "print" && call.target != "warn") ||
            !call.output_confirmed)
            return result;
        lastCallVmCount = std::max(lastCallVmCount, call.vm_count);
    }
    if (candidate.provenance.size() != dynamic.calls.size())
        return result;

    const json* activation = nullptr;
    for (const json& row : closure["activations"])
        if (row.value("activation", uint64_t(0)) == rootActivation)
        {
            activation = &row;
            break;
        }
    if (!activation || activation->value("entry_pc", int64_t(-1)) != 1 ||
        activation->value("entry_vm_count", uint64_t(0)) == 0 ||
        activation->value("entry_vm_count", uint64_t(0)) >= lastCallVmCount)
        return result;

    const json* completedReturn = nullptr;
    for (const json& row : closure["observed_returns"])
        if (row.value("activation", uint64_t(0)) == rootActivation && row.value("complete", false) &&
            row.value("arity", size_t(1)) == 0 && row.value("vm_count", uint64_t(0)) > lastCallVmCount)
        {
            completedReturn = &row;
            break;
        }
    if (!completedReturn)
        return result;

    size_t line = 1;
    for (const json& statement : candidate.provenance)
    {
        if (!statement.is_object() || statement.value("claim", "") != "observed_value_slice" ||
            !statement.contains("call") || !statement["call"].is_object() ||
            !statement["call"].value("output_confirmed", false) ||
            !statement.contains("function_producer") || !statement["function_producer"].is_object() ||
            !statement.contains("argument_producers") || !statement["argument_producers"].is_array())
            return result;
        result.statements.push_back(statement);
        result.coverage.push_back({
            {"line", line++},
            {"activation", rootActivation},
            {"call_pc", statement["call"].value("pc", int64_t(-1))},
            {"function_producer_pc", statement["function_producer"].value("pc", int64_t(-1))},
            {"argument_producer_count", statement["argument_producers"].size()},
            {"disposition", "observed_output_statement"},
        });
    }
    result.coverage.push_back({
        {"activation", rootActivation},
        {"return_pc", completedReturn->value("pc", int64_t(-1))},
        {"return_arity", 0},
        {"disposition", "observed_terminal_return"},
    });
    result.covered_instructions = dynamic.calls.size() + 1;
    result.source = candidate.source;
    result.complete = !result.source.empty() && compiles(result.source);
    result.full_instruction_coverage = false;
    result.proof_scope = "completed-output-only-payload-trace";
    result.reason = result.complete ? "completed_output_only_trace" : "reconstructed_source_did_not_compile";
    return result;
}

LuraphStatementReconstruction buildLuraphStatementReconstruction(
    const json& closure,
    const LuraphObservedCandidate& candidate)
{
    LuraphStatementReconstruction result;
    if (!candidate.complete || !closure.value("static_semantic_complete", false) ||
        !closure.contains("activations") || !closure["activations"].is_array() ||
        !closure.contains("prototypes") || !closure["prototypes"].is_array())
    {
        result.reason = "payload_closure_or_candidate_incomplete";
        return result;
    }

    std::map<uint64_t, json> activations;
    for (const json& activation : closure["activations"])
        if (activation.contains("activation") && activation["activation"].is_number_unsigned())
            activations[activation["activation"].get<uint64_t>()] = activation;
        else if (activation.contains("activation") && activation["activation"].is_number_integer())
            activations[static_cast<uint64_t>(activation["activation"].get<int64_t>())] = activation;

    std::optional<uint64_t> rootActivation;
    std::set<int64_t> producerPcs;
    std::map<int64_t, size_t> statementLines;
    size_t line = 1;
    for (const json& statement : candidate.provenance)
    {
        const json& call = statement["call"];
        if (!call.contains("activation") || !call["activation"].is_number_unsigned() ||
            !call.contains("pc") || !call["pc"].is_number_integer())
        {
            result.reason = "candidate_provenance_incomplete";
            return result;
        }
        const uint64_t activation = call["activation"].get<uint64_t>();
        if (rootActivation && *rootActivation != activation)
        {
            result.reason = "multiple_payload_root_activations";
            return result;
        }
        rootActivation = activation;
        statementLines[call["pc"].get<int64_t>()] = line++;
        if (statement.contains("function_producer") && statement["function_producer"].contains("pc"))
            producerPcs.insert(statement["function_producer"]["pc"].get<int64_t>());
        if (statement.contains("argument_producers") && statement["argument_producers"].is_array())
            for (const json& producer : statement["argument_producers"])
                if (producer.contains("pc") && producer["pc"].is_number_integer())
                    producerPcs.insert(producer["pc"].get<int64_t>());
    }
    auto rootRow = rootActivation ? activations.find(*rootActivation) : activations.end();
    if (rootRow == activations.end() || !rootRow->second.contains("prototype"))
    {
        result.reason = "payload_root_prototype_missing";
        return result;
    }
    const uint64_t rootPrototype = rootRow->second["prototype"].get<uint64_t>();

    std::set<uint64_t> decoderPrototypes;
    std::map<uint64_t, std::set<uint64_t>> decoderActivations;
    for (const auto& [activationId, activation] : activations)
    {
        if (activationId == *rootActivation)
            continue;
        uint64_t current = activationId;
        std::optional<uint64_t> directChild;
        std::set<uint64_t> visited;
        while (current != *rootActivation && visited.insert(current).second)
        {
            auto row = activations.find(current);
            if (row == activations.end() || !row->second.contains("caller_activation") ||
                !row->second["caller_activation"].is_number_integer())
                break;
            const int64_t caller = row->second["caller_activation"].get<int64_t>();
            if (caller < 0)
                break;
            if (static_cast<uint64_t>(caller) == *rootActivation)
                directChild = current;
            current = static_cast<uint64_t>(caller);
        }
        if (current != *rootActivation || !directChild)
        {
            result.reason = "payload_descendant_ancestry_incomplete";
            return result;
        }
        const json& direct = activations[*directChild];
        if (!direct.contains("caller_pc") || !direct["caller_pc"].is_number_integer() ||
            !producerPcs.contains(direct["caller_pc"].get<int64_t>()))
        {
            result.reason = "descendant_activation_not_owned_by_value_producer";
            return result;
        }
        if (!activation.contains("prototype"))
        {
            result.reason = "decoder_prototype_missing";
            return result;
        }
        const uint64_t prototype = activation["prototype"].get<uint64_t>();
        if (prototype == rootPrototype)
        {
            result.reason = "payload_root_reentered_as_decoder";
            return result;
        }
        decoderPrototypes.insert(prototype);
        decoderActivations[prototype].insert(activationId);
    }

    size_t expectedInstructions = 0;
    bool rootFound = false;
    for (const json& prototype : closure["prototypes"])
    {
        const uint64_t prototypeId = prototype.value("runtime_id", uint64_t(0));
        const json& instructions = prototype["instructions"];
        expectedInstructions += instructions.size();
        if (prototypeId == rootPrototype)
        {
            rootFound = true;
            for (const json& instruction : instructions)
            {
                const int64_t pc = instruction.value("pc", int64_t(-1));
                const int64_t opcode = instruction.value("opcode", int64_t(-1));
                const json& operation = instruction["semantic_operation"];
                std::string disposition;
                json row = {{"prototype", prototypeId}, {"pc", pc}, {"opcode", opcode}};
                if (producerPcs.contains(pc))
                    disposition = "runtime_value_producer";
                else if (auto emitted = statementLines.find(pc); emitted != statementLines.end())
                {
                    disposition = "emitted_statement";
                    row["line"] = emitted->second;
                }
                else if (!operation.is_object())
                {
                    result.reason = "root_instruction_unclassified";
                    return result;
                }
                else if (operation.value("protector_state", false))
                    disposition = "protector_control_elided";
                else if (operation.value("kind", "") == "return" && operation.value("values", json::array()).empty())
                    disposition = "implicit_terminal_return";
                else
                {
                    result.reason = "unmapped_root_semantic_operation";
                    return result;
                }
                row["disposition"] = disposition;
                result.coverage.push_back(std::move(row));
                ++result.covered_instructions;
            }
            continue;
        }
        if (!decoderPrototypes.contains(prototypeId))
        {
            result.reason = "unclassified_payload_prototype";
            return result;
        }
        json activationEvidence = json::array();
        for (uint64_t activation : decoderActivations[prototypeId])
            activationEvidence.push_back(activation);
        result.decoder_prototypes.push_back({
            {"prototype", prototypeId},
            {"activations", activationEvidence},
            {"ownership", "runtime_value_producer_descendant"},
        });
        for (const json& instruction : instructions)
        {
            if (!instruction.contains("semantic_operation") || instruction["semantic_operation"].is_null())
            {
                result.reason = "decoder_instruction_unclassified";
                return result;
            }
            result.coverage.push_back({
                {"prototype", prototypeId},
                {"pc", instruction.value("pc", int64_t(-1))},
                {"opcode", instruction.value("opcode", int64_t(-1))},
                {"disposition", "runtime_value_decoder_elided"},
            });
            ++result.covered_instructions;
        }
    }
    if (!rootFound || result.covered_instructions != expectedInstructions ||
        expectedInstructions != closure.value("instruction_count", size_t(0)))
    {
        result.reason = "statement_coverage_count_mismatch";
        return result;
    }
    result.source = candidate.source;
    result.statements = candidate.provenance;
    result.complete = !result.source.empty() && compiles(result.source);
    result.full_instruction_coverage = result.complete;
    result.proof_scope = result.complete ? "complete-static-instruction-map" : "none";
    result.reason = result.complete ? "complete" : "reconstructed_source_did_not_compile";
    return result;
}

Result finishLuraphAnalysis(const Options& options, std::string_view source, const luraph::EnvelopeAnalysis& analysis, json report)
{
    Result result;
    const fs::path envelopePath = options.output_dir / "luraph_envelope_analysis.json";
    const fs::path irPath = options.output_dir / "semantic_ir.json";
    const fs::path cfgPath = options.output_dir / "cfg.json";
    const fs::path constantsPath = options.output_dir / "constants.json";
    const fs::path disassemblyPath = options.output_dir / "vm_disassembly.txt";
    const fs::path mapPath = options.output_dir / "reconstruction_map.json";
    const fs::path graphPath = options.output_dir / "artifact_graph.json";
    const fs::path reportPath = options.output_dir / "deobfuscation_report.json";
    const fs::path traceProbePath = options.output_dir / "trace_probe.luau";
    const fs::path structureProbePath = options.output_dir / "structure_probe.luau";
    const fs::path opcodeHandlersPath = options.output_dir / "opcode_handlers.json";
    const fs::path runtimePrototypesPath = options.output_dir / "runtime_prototypes.json";
    const fs::path prototypeCorrespondencePath = options.output_dir / "prototype_correspondence.json";
    const fs::path runtimeSemanticPath = options.output_dir / "runtime_semantic_ir.json";
    const fs::path payloadClosurePath = options.output_dir / "payload_closure_ir.json";
    const fs::path payloadReachableIrPath = options.output_dir / "payload_reachable_ir.json";
    const fs::path readableLiftPath = options.output_dir / "lifted_program.txt";
    const fs::path semanticCandidatePath = options.output_dir / "semantic_state_machine_candidate.luau";
    const fs::path semanticReadablePath = options.output_dir / "semantic_readable_candidate.luau";
    const fs::path semanticReadableFailedPath = options.output_dir / "semantic_readable_candidate.failed.luau";
    const fs::path semanticCandidateMapPath = options.output_dir / "semantic_state_machine_map.json";
    const fs::path guardHotspotPath = options.output_dir / "guard_hotspot.json";
    const fs::path payloadCandidatePath = options.output_dir / "payload_candidate.luau";
    const fs::path payloadCandidateProvenancePath = options.output_dir / "payload_candidate_provenance.json";
    const fs::path decodedContainerPath = options.output_dir / "decoded_lph_container.bin";
    const bool parsedContainer = hasParsedLuraphContainer(analysis);
    const bool decodedContainer = hasDecodedLuraphContainer(analysis);
    const size_t retainedInstructions = retainedLuraphInstructionCount(analysis);
    const size_t protectedBodyOffset = analysis.luaauth_launcher.protected_body_range
        ? analysis.luaauth_launcher.protected_body_range->begin : 0;
    const std::string_view protectedSource = source.substr(std::min(protectedBodyOffset, source.size()));
    std::string analysisScope = analysis.generated_interpreter ? "runtime-generated-interpreter" :
        (parsedContainer ? "source-envelope-and-decoded-container" :
            decodedContainer ? "source-envelope-and-decoded-carrier" : "source-envelope-only");

    report["adapter"] = luraphAdapterName(analysis);
    report["status"] = "blocked";
    report["exact_source"] = false;
    report["fallback_used"] = false;
    report["analysis_scope"] = analysisScope;
    bool decodedContainerWritten = false;
    for (const luraph::ContainerAnalysis& container : analysis.containers)
    {
        if (container.decode_status != luraph::ContainerDecodeStatus::Decoded || container.decoded_data.empty())
            continue;
        writeFile(decodedContainerPath,
            std::string_view(reinterpret_cast<const char*>(container.decoded_data.data()), container.decoded_data.size()));
        decodedContainerWritten = true;
        break;
    }
    report["launcher"] = {
        {"kind", analysis.luaauth_launcher.present ? json("luaauth") : json(nullptr)},
        {"metadata_removed", analysis.luaauth_launcher.metadata_removed_from_body},
        {"values_retained", false},
        {"protected_body_bytes", protectedSource.size()},
    };

    auto buildTraceProbe = [&](uint64_t rangeStart = 0, uint64_t rangeEnd = 0, std::string* generator = nullptr,
                               std::string* failureReason = nullptr, bool includeStructure = false,
                               bool includeDynamicEvidence = false) -> std::optional<std::string> {
        if (!analysis.version_supported && !analysis.generated_interpreter)
        {
            if (failureReason)
                *failureReason = "luraph_version_not_supported";
            return std::nullopt;
        }
        std::string structuralFailure;
        if (std::optional<std::string> structural = buildStructuralLuraphTraceProbe(
                protectedSource, rangeStart, rangeEnd, &structuralFailure, includeStructure, includeDynamicEvidence))
        {
            if (compiles(*structural))
            {
                if (generator)
                    *generator = "structural-ast-v1";
                return structural;
            }
            structuralFailure = "structural_probe_compile_failed";
        }
        if (!includeStructure)
        {
            if (std::optional<std::string> legacy = luraph::buildCallTraceProbe(protectedSource, rangeStart, rangeEnd);
                legacy && compiles(*legacy))
            {
                if (generator)
                    *generator = "legacy-shape-v2";
                return legacy;
            }
        }
        if (failureReason)
            *failureReason = structuralFailure.empty() ? "legacy_and_structural_shapes_unmatched" : structuralFailure;
        return std::nullopt;
    };

    std::string traceProbeGenerator;
    std::string traceProbeFailure;
    const uint64_t requestedTraceStart = options.trace_window_start.value_or(0);
    const uint64_t requestedTraceEnd = options.trace_window_end.value_or(0);
    const std::optional<std::string> traceProbe = buildTraceProbe(
        requestedTraceStart, requestedTraceEnd, &traceProbeGenerator, &traceProbeFailure);
    const bool traceProbeCompiled = traceProbe.has_value();
    if (traceProbeCompiled)
        writeFile(traceProbePath, *traceProbe);
    report["passes"].push_back({
        {"stage", "trace_probe"},
        {"ok", traceProbeCompiled},
        {"kind", "call-focused-v2"},
        {"generator", traceProbeCompiled ? json(traceProbeGenerator) : json(nullptr)},
        {"failure_reason", traceProbeCompiled ? json(nullptr) : json(traceProbeFailure)},
        {"network_policy", "offline"},
        {"source_emitted", traceProbeCompiled},
    });
    std::string structureProbeFailure;
    const std::optional<std::string> structureProbe = (analysis.version_supported || analysis.generated_interpreter)
        ? buildStructuralLuraphTraceProbe(
            protectedSource, requestedTraceStart, requestedTraceEnd, &structureProbeFailure, true, true)
        : std::nullopt;
    const bool structureProbeCompiled = structureProbe && compiles(*structureProbe);
    json structureProbeDiagnostics = json::array();
    if (structureProbe && !structureProbeCompiled)
    {
        structureProbeFailure = compileDiagnostic(*structureProbe).value_or("structural_probe_compile_failed");
        const auto failedProbe = parseSource(*structureProbe);
        structureProbeDiagnostics = parseErrors(failedProbe->result);
    }
    if (structureProbeCompiled)
        writeFile(structureProbePath, *structureProbe);
    report["passes"].push_back({
        {"stage", "structure_probe"},
        {"ok", structureProbeCompiled},
        {"kind", "decoded-prototype-lanes-v1"},
        {"failure_reason", structureProbeCompiled ? json(nullptr) : json(structureProbeFailure)},
        {"failure_diagnostics", std::move(structureProbeDiagnostics)},
        {"network_policy", "offline"},
        {"source_emitted", structureProbeCompiled},
        {"trace_window_start", requestedTraceStart > 0 ? json(requestedTraceStart) : json(nullptr)},
        {"trace_window_end", requestedTraceEnd > 0 ? json(requestedTraceEnd) : json(nullptr)},
    });

    auto parsed = parseSource(protectedSource);
    const bool inputParsed = parsed->result.errors.empty();
    report["passes"].push_back({{"stage", "parse"}, {"ok", inputParsed}, {"lines", parsed->result.lines}});
    const LuraphOpcodeCatalog opcodeCatalog = inputParsed ? buildLuraphOpcodeCatalog(protectedSource) : LuraphOpcodeCatalog{};
    if (opcodeCatalog.available)
        writeJson(opcodeHandlersPath, opcodeCatalog.document);
    report["passes"].push_back({
        {"stage", "opcode_handlers"},
        {"ok", opcodeCatalog.available && opcodeCatalog.resolved > 0},
        {"resolved_opcodes", opcodeCatalog.resolved},
        {"exact_handlers", opcodeCatalog.document.value("exact_handlers", size_t(0))},
        {"ambiguous_handlers", opcodeCatalog.document.value("ambiguous_handlers", size_t(0))},
        {"missing_handlers", opcodeCatalog.document.value("missing_handlers", size_t(0))},
        {"total_opcodes", 256},
        {"unique_handlers", opcodeCatalog.unique_handlers},
        {"semantic_classification_complete", false},
    });
    report["passes"].push_back({
        {"stage", "detect"},
        {"ok", analysis.family_detected},
        {"adapter", luraphAdapterName(analysis)},
        {"confidence", analysis.confidence.score},
        {"version_supported", analysis.version_supported},
        {"generated_interpreter", analysis.generated_interpreter},
        {"structural_scan_complete", analysis.complete},
    });
    for (const luraph::Stage& stage : analysis.stages)
    {
        report["passes"].push_back({
            {"stage", std::string(luraph::toString(stage.kind))},
            {"ok", true},
            {"scope", "source-envelope"},
            {"confidence", stage.confidence},
            {"range", luraphRange(stage.range)},
        });
    }

    std::optional<LuraphRuntimeStructureTrace> runtimeStructure;
    std::optional<json> runtimeSemanticDocument;
    size_t runtimeEffectClassified = 0;
    size_t runtimeUnresolved = 0;
    size_t runtimeSemanticLifted = 0;
    size_t runtimeTraceSpecialized = 0;
    size_t runtimeTraceEffects = 0;
    size_t runtimeObservationalSites = 0;
    size_t runtimeObservationalLifted = 0;
    size_t runtimeObservationalUnresolved = 0;
    size_t runtimeGuardedCandidatesValidated = 0;
    size_t runtimeGuardedCandidatesRejected = 0;
    size_t runtimeGuardReplaySitesAttached = 0;
    size_t runtimeGuardReplaySitesValidated = 0;
    size_t runtimeGuardReplaySitesRejected = 0;
    size_t runtimeGuardReplaySitesDivergent = 0;
    size_t runtimeUnobservedInstructions = 0;
    json runtimeObservationalOperationCounts = json::object();
    json runtimeWriteOriginEvidence = json::object();
    json runtimeOpcode8CallCoverage = json{{"available", false}};
    json runtimeOpcode28IndexReadCoverage = json{{"available", false}};
    json runtimeOpcode89RangeClearCoverage = json{{"available", false}};
    if (options.trace)
    {
        LuraphRuntimeStructureTrace parsedStructure;
        const std::optional<LuraphRuntimeStructureTrace> structureSeed =
            loadLuraphRuntimeStructureSeed(runtimePrototypesPath, sha256(protectedSource));
        try
        {
            parsedStructure = parseLuraphRuntimeStructureTrace(
                *options.trace, opcodeCatalog, structureSeed ? &*structureSeed : nullptr);
            if (!parsedStructure.steps.empty())
                attachLuraphObservedGuardSemantics(protectedSource, parsedStructure);
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string("runtime structure trace parsing failed: ") + error.what());
        }
        if (!parsedStructure.prototypes.empty() || parsedStructure.malformed_rows > 0)
        {
            runtimeStructure = std::move(parsedStructure);
            if (!runtimeStructure->prototypes.empty())
            {
                writeJson(runtimePrototypesPath, luraphRuntimeStructureArtifact(*runtimeStructure, sha256(protectedSource)));
                try
                {
                    runtimeSemanticDocument = luraphRuntimeSemanticDispatchArtifact(
                        *runtimeStructure, opcodeCatalog, runtimeEffectClassified, runtimeUnresolved, runtimeSemanticLifted);
                    runtimeTraceSpecialized = runtimeSemanticDocument->value("trace_specialized_instructions", size_t(0));
                    runtimeTraceEffects = runtimeSemanticDocument->value("trace_effect_classified_instructions", size_t(0));
                    runtimeObservationalSites = runtimeSemanticDocument->value("observational_sites", size_t(0));
                    runtimeObservationalLifted = runtimeSemanticDocument->value("observational_semantic_lifted", size_t(0));
                    runtimeObservationalUnresolved = runtimeSemanticDocument->value("observational_semantic_unresolved", size_t(0));
                    runtimeGuardedCandidatesValidated = runtimeSemanticDocument->value(
                        "guarded_candidates_validated", size_t(0));
                    runtimeGuardedCandidatesRejected = runtimeSemanticDocument->value(
                        "guarded_candidates_rejected", size_t(0));
                    runtimeGuardReplaySitesValidated = runtimeSemanticDocument->value(
                        "guard_replay_sites_validated", size_t(0));
                    runtimeGuardReplaySitesAttached = runtimeSemanticDocument->value(
                        "guard_replay_sites_attached", size_t(0));
                    runtimeGuardReplaySitesRejected = runtimeSemanticDocument->value(
                        "guard_replay_sites_rejected", size_t(0));
                    runtimeGuardReplaySitesDivergent = runtimeSemanticDocument->value(
                        "guard_replay_sites_divergent", size_t(0));
                    runtimeUnobservedInstructions = runtimeSemanticDocument->value("unobserved_instructions", size_t(0));
                    runtimeObservationalOperationCounts = runtimeSemanticDocument->value(
                        "observational_operation_counts", json::object());
                    runtimeWriteOriginEvidence = runtimeSemanticDocument->value(
                        "write_origin_evidence", json::object());
                    runtimeOpcode8CallCoverage = runtimeSemanticDocument->value(
                        "opcode8_call_coverage", json{{"available", false}});
                    runtimeOpcode28IndexReadCoverage = runtimeSemanticDocument->value(
                        "opcode28_index_read_coverage", json{{"available", false}});
                    runtimeOpcode89RangeClearCoverage = runtimeSemanticDocument->value(
                        "opcode89_range_clear_coverage", json{{"available", false}});
                }
                catch (const std::exception& error)
                {
                    throw std::runtime_error(std::string("runtime semantic materialization failed: ") + error.what());
                }
                writeJson(runtimeSemanticPath, *runtimeSemanticDocument);
            }
            size_t decodedDeclaredInstructions = 0;
            for (const auto& [prototypeId, prototype] : runtimeStructure->prototypes)
            {
                (void)prototypeId;
                decodedDeclaredInstructions += prototype.declared_instruction_count;
            }
            const bool decodedComplete = runtimeStructure->complete && decodedDeclaredInstructions > 0 &&
                runtimeStructure->instruction_count == decodedDeclaredInstructions;
            report["passes"].push_back({
                {"stage", "runtime_decode"},
                {"ok", decodedComplete},
                {"scope", "reachable-prototypes-observed-offline"},
                {"prototypes", runtimeStructure->prototypes.size()},
                {"instructions", runtimeStructure->instruction_count},
                {"declared_instructions", decodedDeclaredInstructions},
                {"observed_instructions", runtimeStructure->instruction_count},
                {"observed_steps", runtimeStructure->steps.size()},
                {"malformed_rows", runtimeStructure->malformed_rows},
                {"complete", decodedComplete},
                {"structure_reused", runtimeStructure->structure_reused},
                {"semantic_classification_complete", false},
            });
            report["passes"].push_back({
                {"stage", "semantic_classify"},
                {"ok", runtimeEffectClassified > 0 || runtimeTraceSpecialized > 0},
                {"scope", "runtime-opcode-handler-effects"},
                {"effect_classified_instructions", runtimeEffectClassified},
                {"trace_specialized_sites", runtimeTraceSpecialized},
                {"observed_effect_classified_sites", runtimeTraceEffects},
                {"observational_sites", runtimeObservationalSites},
                {"observational_semantic_lifted", runtimeObservationalLifted},
                {"observational_semantic_unresolved", runtimeObservationalUnresolved},
                {"guarded_candidates_validated", runtimeGuardedCandidatesValidated},
                {"guarded_candidates_rejected", runtimeGuardedCandidatesRejected},
                {"guard_replay_sites_validated", runtimeGuardReplaySitesValidated},
                {"guard_replay_sites_attached", runtimeGuardReplaySitesAttached},
                {"guard_replay_sites_rejected", runtimeGuardReplaySitesRejected},
                {"guard_replay_sites_divergent", runtimeGuardReplaySitesDivergent},
                {"unobserved_instructions", runtimeUnobservedInstructions},
                {"observational_operation_counts", runtimeObservationalOperationCounts},
                {"opcode8_call_coverage", runtimeOpcode8CallCoverage},
                {"opcode28_index_read_coverage", runtimeOpcode28IndexReadCoverage},
                {"opcode89_range_clear_coverage", runtimeOpcode89RangeClearCoverage},
                {"trace_specialized_is_path_specific", true},
                {"write_origin_evidence", runtimeWriteOriginEvidence},
                {"unresolved_instructions", runtimeUnresolved},
                {"semantic_lifted_instructions", runtimeSemanticLifted},
                {"semantic_unresolved_instructions", decodedDeclaredInstructions - runtimeSemanticLifted},
                {"semantic_lifting_complete", decodedDeclaredInstructions > 0 && runtimeSemanticLifted == decodedDeclaredInstructions},
            });
            if (runtimeWriteOriginEvidence.value("absent_from_all_steps", false))
                report["diagnostics"].push_back({
                    {"stage", "semantic_classify"},
                    {"severity", "info"},
                    {"code", "luraph_write_origin_evidence_missing"},
                    {"message", "This trace predates origin-aware step rows. Move and argument-copy semantics remain unresolved until an evidence-only probe records write_origins."},
                    {"details", runtimeWriteOriginEvidence},
                });
            report["diagnostics"].push_back({
                {"stage", "runtime_decode"},
                {"severity", decodedComplete ? "info" : "warning"},
                {"code", decodedComplete ? "luraph_runtime_prototypes_decoded" : "luraph_runtime_prototypes_partial"},
                {"message", decodedComplete
                    ? "Reachable decoded prototype lanes were captured and validated from the bounded offline runtime."
                    : "Some runtime prototype rows were missing or malformed; the partial artifact was retained without a source claim."},
            });
        }
    }
    const bool runtimeDecoded = runtimeStructure && !runtimeStructure->prototypes.empty();
    size_t runtimeDeclaredInstructions = 0;
    if (runtimeStructure)
        for (const auto& [prototypeId, prototype] : runtimeStructure->prototypes)
        {
            (void)prototypeId;
            runtimeDeclaredInstructions += prototype.declared_instruction_count;
        }
    const size_t runtimeObservedInstructions = runtimeStructure ? runtimeStructure->instruction_count : 0;
    const bool runtimeSchemaComplete = runtimeStructure && runtimeStructure->complete &&
        runtimeDeclaredInstructions > 0 && runtimeObservedInstructions == runtimeDeclaredInstructions;
    if (runtimeDecoded)
    {
        analysisScope = parsedContainer
            ? "source-envelope-static-and-runtime-decoded-prototypes"
            : "source-envelope-and-runtime-decoded-prototypes";
        report["analysis_scope"] = analysisScope;
        if (!parsedContainer)
        {
            report["diagnostics"].push_back({
                {"stage", "runtime_decode"},
                {"severity", runtimeSchemaComplete ? "info" : "warning"},
                {"code", "luraph_runtime_schema_bypass"},
                {"message", runtimeSchemaComplete
                    ? "The runtime exposed a complete prototype and instruction corpus for this bounded execution."
                    : "The runtime exposed only a partial prototype or instruction corpus; retained rows remain useful evidence but are not reported as complete."},
                {"details", {
                    {"prototypes", runtimeStructure->prototypes.size()},
                    {"declared_instructions", runtimeDeclaredInstructions},
                    {"observed_instructions", runtimeObservedInstructions},
                    {"complete", runtimeSchemaComplete},
                }},
            });
        }
    }

    std::optional<json> prototypeCorrespondenceDocument;
    json runtimeClosureCorrespondence = {{"available", false}};
    const bool staticPrototypeGraphAvailable = std::any_of(
        analysis.containers.begin(), analysis.containers.end(), [](const luraph::ContainerAnalysis& container) {
            return container.parse_status == luraph::ContainerParseStatus::Parsed ||
                container.parse_status == luraph::ContainerParseStatus::StructuralMetadataRecovered;
        });
    if (runtimeDecoded && staticPrototypeGraphAvailable)
    {
        prototypeCorrespondenceDocument = luraphPrototypeCorrespondenceArtifact(analysis, *runtimeStructure);
        writeJson(prototypeCorrespondencePath, *prototypeCorrespondenceDocument);
        runtimeClosureCorrespondence = applyLuraphStaticClosureCorrespondence(
            *runtimeStructure, *prototypeCorrespondenceDocument);
        writeJson(runtimePrototypesPath,
            luraphRuntimeStructureArtifact(*runtimeStructure, sha256(protectedSource)));
        const json* singleContainer = prototypeCorrespondenceDocument->contains("containers") &&
                (*prototypeCorrespondenceDocument)["containers"].is_array() &&
                (*prototypeCorrespondenceDocument)["containers"].size() == 1
            ? &(*prototypeCorrespondenceDocument)["containers"][0] : nullptr;
        report["passes"].push_back({
            {"stage", "prototype_correspondence"},
            {"ok", prototypeCorrespondenceDocument->value("complete", false)},
            {"status", prototypeCorrespondenceDocument->value("status", "partial")},
            {"scope", "verified-static-container-and-bounded-offline-runtime"},
            {"selected_container_index", prototypeCorrespondenceDocument->value(
                "selected_container_index", json(nullptr))},
            {"matched", singleContainer ? (*singleContainer)["matched"] : json(nullptr)},
            {"ambiguous", singleContainer ? (*singleContainer)["ambiguous"] : json(nullptr)},
            {"unmatched", singleContainer ? (*singleContainer)["unmatched"] : json(nullptr)},
            {"ambiguity_preserved", singleContainer
                ? (*singleContainer)["ambiguity_preserved"] : json(nullptr)},
            {"artifact", prototypeCorrespondencePath.filename().string()},
        });
        report["passes"].push_back({
            {"stage", "closure_correspondence"},
            {"ok", runtimeClosureCorrespondence.value("available", false)},
            {"scope", "verified-static-parent-pc-and-runtime-prototype-correspondence"},
            {"runtime_targets_resolved", runtimeClosureCorrespondence.value(
                "runtime_targets_resolved", size_t(0))},
            {"static_only_targets_resolved", runtimeClosureCorrespondence.value(
                "static_only_targets_resolved", size_t(0))},
            {"parent_wrapper_targets_resolved", runtimeClosureCorrespondence.value(
                "parent_wrapper_targets_resolved", size_t(0))},
            {"unresolved_sites", runtimeClosureCorrespondence.value("unresolved_sites", size_t(0))},
        });
        if (!prototypeCorrespondenceDocument->value("complete", false))
            report["diagnostics"].push_back({
                {"stage", "prototype_correspondence"},
                {"severity", "info"},
                {"code", "luraph_prototype_correspondence_partial"},
                {"message", "Static and runtime prototypes were matched only where instruction and graph evidence was unique; unresolved candidates remain explicit in the correspondence artifact."},
                {"details", {
                    {"status", prototypeCorrespondenceDocument->value("status", "partial")},
                    {"valid_static_containers", prototypeCorrespondenceDocument->value(
                        "valid_static_container_count", size_t(0))},
                    {"complete_container_matches", prototypeCorrespondenceDocument->value(
                        "complete_container_match_count", size_t(0))},
                }},
            });
    }

    std::optional<LuraphDynamicTrace> dynamicTrace;
    std::optional<LuraphPayloadClosureMetrics> payloadClosureMetrics;
    std::optional<json> payloadClosureDocument;
    std::optional<json> payloadCfgDocument;
    std::optional<json> observedCfgDocument;
    std::optional<json> payloadReachableIrDocument;
    std::optional<luraph::SemanticCandidate> semanticCandidate;
    std::optional<readable::RewriteResult> semanticReadableCandidate;
    std::optional<std::string> semanticReadableCompileError;
    std::optional<LuraphObservedCandidate> observedCandidate;
    std::optional<LuraphStatementReconstruction> statementReconstruction;
    std::optional<json> guardHotspotDocument;
    std::optional<LuraphPayloadRootEvidence> payloadRoot;
    bool observedCandidateCompiled = false;
    bool semanticCandidateCompiled = false;
    bool semanticReadableCandidateCompiled = false;
    bool traceRefinementRequired = false;
    if (runtimeStructure && runtimeSemanticDocument)
    {
        try
        {
            payloadRoot = findLuraphPayloadRoot(*runtimeStructure, *runtimeSemanticDocument);
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string("payload root discovery failed: ") + error.what());
        }
        if (payloadRoot)
        {
            report["passes"].push_back({
                {"stage", "payload_root"},
                {"ok", true},
                {"evidence", payloadRoot->evidence},
                {"bootstrap_activation", payloadRoot->bootstrap_activation},
                {"bootstrap_prototype", payloadRoot->bootstrap_prototype},
                {"payload_activation", payloadRoot->payload_activation},
                {"payload_prototype", payloadRoot->payload_prototype},
                {"caller_pc", payloadRoot->caller_pc},
                {"caller_opcode", payloadRoot->caller_opcode},
                {"bootstrap_return_vm_count", payloadRoot->bootstrap_return_vm_count > 0
                    ? json(payloadRoot->bootstrap_return_vm_count) : json(nullptr)},
                {"payload_entry_vm_count", payloadRoot->payload_entry_vm_count > 0
                    ? json(payloadRoot->payload_entry_vm_count) : json(nullptr)},
            });
        }
    }
    if (options.trace)
    {
        try
        {
            dynamicTrace = parseLuraphDynamicTrace(*options.trace);
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string("dynamic trace parsing failed: ") + error.what());
        }
        report["passes"].push_back({
            {"stage", "trace"},
            {"ok", !dynamicTrace->calls.empty()},
            {"events", dynamicTrace->event_count},
            {"payload_calls", dynamicTrace->calls.size()},
            {"candidate_calls", dynamicTrace->candidate_call_count},
            {"unresolved_candidates", dynamicTrace->unresolved_call_count},
            {"first_candidate_vm_count", dynamicTrace->first_candidate_vm_count
                ? json(*dynamicTrace->first_candidate_vm_count) : json(nullptr)},
            {"last_candidate_vm_count", dynamicTrace->last_candidate_vm_count
                ? json(*dynamicTrace->last_candidate_vm_count) : json(nullptr)},
            {"vm_events", dynamicTrace->vm_events.size()},
            {"payload_activation_complete", dynamicTrace->payload_activation_complete},
            {"scope", "bounded-offline-runtime"},
        });
        if (!dynamicTrace->calls.empty() && !dynamicTrace->payload_activation_complete)
        {
            uint64_t firstCall = dynamicTrace->calls.front().vm_count;
            uint64_t lastCall = firstCall;
            for (const LuraphTraceCall& call : dynamicTrace->calls)
            {
                firstCall = std::min(firstCall, call.vm_count);
                lastCall = std::max(lastCall, call.vm_count);
            }
            const uint64_t rangeStart = firstCall > 4096 ? firstCall - 4096 : 1;
            const uint64_t rangeEnd = lastCall > std::numeric_limits<uint64_t>::max() - 512
                ? std::numeric_limits<uint64_t>::max()
                : lastCall + 512;
            std::string refinedProbeGenerator;
            const std::optional<std::string> refinedProbe = buildTraceProbe(
                rangeStart, rangeEnd, &refinedProbeGenerator, nullptr, !runtimeDecoded, true);
            traceRefinementRequired = refinedProbe.has_value();
            if (traceRefinementRequired)
            {
                writeFile(traceProbePath, *refinedProbe);
                report["passes"].push_back({
                    {"stage", "trace_refine"},
                    {"ok", true},
                    {"range_start", rangeStart},
                    {"range_end", rangeEnd},
                    {"generator", refinedProbeGenerator},
                    {"evidence_mode", runtimeDecoded ? "dynamic-only" : "structure-and-dynamic"},
                    {"structure_reused", runtimeDecoded},
                    {"reason", "payload_activation_boundary_required"},
                });
                report["diagnostics"].push_back({
                    {"stage", "trace"},
                    {"severity", "info"},
                    {"code", "luraph_trace_refinement_required"},
                    {"message", "A payload call was confirmed. A second bounded probe was generated to capture its complete virtual activation before source is emitted."},
                });
            }
        }
        else if (dynamicTrace->calls.empty() && !payloadRoot && dynamicTrace->last_candidate_vm_count)
        {
            const uint64_t hotspot = *dynamicTrace->last_candidate_vm_count;
            const uint64_t rangeStart = 1;
            const uint64_t rangeEnd = hotspot > std::numeric_limits<uint64_t>::max() - 4096
                ? std::numeric_limits<uint64_t>::max()
                : hotspot + 4096;
            std::string refinedProbeGenerator;
            const std::optional<std::string> refinedProbe = buildTraceProbe(
                rangeStart, rangeEnd, &refinedProbeGenerator, nullptr, !runtimeDecoded, true);
            traceRefinementRequired = refinedProbe.has_value();
            if (traceRefinementRequired)
            {
                writeFile(traceProbePath, *refinedProbe);
                report["passes"].push_back({
                    {"stage", "trace_refine"},
                    {"ok", true},
                    {"range_start", rangeStart},
                    {"range_end", rangeEnd},
                    {"generator", refinedProbeGenerator},
                    {"evidence_mode", runtimeDecoded ? "dynamic-only" : "structure-and-dynamic"},
                    {"structure_reused", runtimeDecoded},
                    {"reason", "unconfirmed_call_hotspot_boundary"},
                });
                report["diagnostics"].push_back({
                    {"stage", "trace"},
                    {"severity", "info"},
                    {"code", "luraph_hotspot_refinement_required"},
                    {"message", "No payload call completed before the bounded stop. A second probe was generated around the last observed VM hotspot to classify the guard cycle."},
                });
            }
        }
    }

    if (runtimeStructure && dynamicTrace && dynamicTrace->calls.empty() && !payloadRoot && !runtimeStructure->steps.empty())
    {
        guardHotspotDocument = luraphGuardHotspotArtifact(*runtimeStructure);
        (*guardHotspotDocument)["static_semantic_lifted"] = runtimeSemanticLifted;
        (*guardHotspotDocument)["static_semantic_unresolved"] =
            runtimeDeclaredInstructions - runtimeSemanticLifted;
        (*guardHotspotDocument)["observational_sites"] = runtimeObservationalSites;
        (*guardHotspotDocument)["observational_semantic_lifted"] = runtimeObservationalLifted;
        (*guardHotspotDocument)["observational_semantic_unresolved"] = runtimeObservationalUnresolved;
        (*guardHotspotDocument)["guarded_candidates_validated"] = runtimeGuardedCandidatesValidated;
        (*guardHotspotDocument)["guarded_candidates_rejected"] = runtimeGuardedCandidatesRejected;
        (*guardHotspotDocument)["guard_replay_sites_validated"] = runtimeGuardReplaySitesValidated;
        (*guardHotspotDocument)["guard_replay_sites_divergent"] = runtimeGuardReplaySitesDivergent;
        (*guardHotspotDocument)["unobserved_instructions"] = runtimeUnobservedInstructions;
        (*guardHotspotDocument)["observational_operation_counts"] = runtimeObservationalOperationCounts;
        (*guardHotspotDocument)["observational_path_specific"] = true;
        (*guardHotspotDocument)["write_origin_evidence"] = runtimeWriteOriginEvidence;
        writeJson(guardHotspotPath, *guardHotspotDocument);
        report["passes"].push_back({
            {"stage", "guard_hotspot"},
            {"ok", true},
            {"observed_steps", runtimeStructure->steps.size()},
            {"observed_activations", (*guardHotspotDocument)["observed_activations"]},
            {"observed_prototypes", (*guardHotspotDocument)["observed_prototypes"]},
            {"semantic_lifted", runtimeSemanticLifted},
            {"semantic_unresolved", runtimeDeclaredInstructions - runtimeSemanticLifted},
            {"observational_sites", runtimeObservationalSites},
            {"observational_semantic_lifted", runtimeObservationalLifted},
            {"observational_semantic_unresolved", runtimeObservationalUnresolved},
            {"guarded_candidates_validated", runtimeGuardedCandidatesValidated},
            {"guarded_candidates_rejected", runtimeGuardedCandidatesRejected},
            {"guard_replay_sites_validated", runtimeGuardReplaySitesValidated},
            {"guard_replay_sites_divergent", runtimeGuardReplaySitesDivergent},
            {"unobserved_instructions", runtimeUnobservedInstructions},
            {"observational_operation_counts", runtimeObservationalOperationCounts},
            {"observational_path_specific", true},
            {"write_origin_evidence", runtimeWriteOriginEvidence},
        });
        report["diagnostics"].push_back({
            {"stage", "trace"},
            {"severity", "info"},
            {"code", "luraph_guard_hotspot_traced"},
            {"message", "The bounded run stopped before a payload call, but the active integrity/environment guard window and its descendant prototypes were captured for semantic analysis."},
        });
    }

    if (runtimeStructure && !runtimeStructure->steps.empty())
    {
        observedCfgDocument = luraphObservedCfgArtifact(*runtimeStructure);
        report["passes"].push_back({
            {"stage", "observed_cfg"},
            {"ok", observedCfgDocument->value("invalid_edge_targets", size_t(0)) == 0},
            {"scope", "bounded-offline-execution-window"},
            {"complete", false},
            {"prototypes", observedCfgDocument->value("prototype_count", size_t(0))},
            {"nodes", observedCfgDocument->value("node_count", size_t(0))},
            {"edges", observedCfgDocument->value("edge_count", size_t(0))},
            {"observed_steps", observedCfgDocument->value("observed_step_count", size_t(0))},
            {"invalid_edge_targets", observedCfgDocument->value("invalid_edge_targets", size_t(0))},
        });
    }

    if (runtimeStructure && runtimeSemanticDocument && dynamicTrace &&
        (!dynamicTrace->calls.empty() || payloadRoot))
    {
        payloadClosureMetrics.emplace();
        try
        {
            payloadClosureDocument = luraphPayloadClosureArtifact(
                *runtimeStructure, *dynamicTrace, *runtimeSemanticDocument, *payloadClosureMetrics, payloadRoot);
            writeJson(payloadClosurePath, *payloadClosureDocument);
            payloadCfgDocument = luraphPayloadCfgArtifact(*payloadClosureDocument);
            payloadReachableIrDocument = luraphReachablePayloadIrArtifact(
                *payloadClosureDocument, *payloadCfgDocument, opcodeCatalog);
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string("payload semantic slicing failed: ") + error.what());
        }
        try
        {
            writeJson(payloadReachableIrPath, *payloadReachableIrDocument);
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string("reachable payload artifact write failed: ") + error.what());
        }
        try
        {
            writeFile(readableLiftPath, buildLuraphReadableLift(*payloadReachableIrDocument));
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string("readable payload lift failed: ") + error.what());
        }
        try
        {
            semanticCandidate = luraph::emitSemanticCandidate(*payloadReachableIrDocument, *payloadCfgDocument);
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string("semantic candidate emission failed: ") + error.what());
        }
        if (!semanticCandidate->capture_key_resolutions.empty())
        {
            (*payloadReachableIrDocument)["capture_key_resolutions"] = semanticCandidate->capture_key_resolutions;
            writeJson(payloadReachableIrPath, *payloadReachableIrDocument);
        }
        writeFile(semanticCandidatePath, semanticCandidate->source);
        semanticCandidateCompiled = compiles(semanticCandidate->source);
        if (semanticCandidateCompiled)
        {
            semanticReadableCandidate = readable::rewriteStateMachines(
                semanticCandidate->source, semanticCandidate->mapping,
                [&](std::string_view stage, std::string_view status, std::string_view message, const json& metrics) {
                    publishProgress(options, std::string("semantic_") + std::string(stage), status, message, metrics);
                }, {.allow_register_overflow = true, .stabilize_residual_names = true});
            semanticReadableCandidateCompiled = semanticReadableCandidate->changed &&
                compiles(semanticReadableCandidate->source);
            if (semanticReadableCandidateCompiled)
                writeFile(semanticReadablePath, semanticReadableCandidate->source);
            else if (semanticReadableCandidate->changed)
            {
                semanticReadableCompileError = compileDiagnostic(semanticReadableCandidate->source);
                writeFile(semanticReadableFailedPath, semanticReadableCandidate->source);
            }
        }
        writeJson(semanticCandidateMapPath, {
            {"version", 1},
            {"kind", "luraph-semantic-state-machine-map"},
            {"source_claim", false},
            {"compiled", semanticCandidateCompiled},
            {"fully_rendered", semanticCandidate->fully_rendered()},
            {"prototypes", semanticCandidate->prototypes},
            {"blocks", semanticCandidate->blocks},
            {"operations", semanticCandidate->operations},
            {"unsupported_expressions", semanticCandidate->unsupported_expressions},
            {"unsupported_operations", semanticCandidate->unsupported_operations},
            {"symbolic_transitions", semanticCandidate->symbolic_transitions},
            {"dynamic_edge_sites", semanticCandidate->dynamic_edge_sites},
            {"replayed_dynamic_edge_sites", semanticCandidate->replayed_dynamic_edge_sites},
            {"activation_scoped_transition_sites", semanticCandidate->activation_scoped_transition_sites},
            {"dynamic_lane_replay_sites", semanticCandidate->dynamic_lane_replay_sites},
            {"replayed_dynamic_lane_values", semanticCandidate->replayed_dynamic_lane_values},
            {"specialized_stable_lanes", semanticCandidate->specialized_stable_lanes},
            {"specialized_stable_lane_values", semanticCandidate->specialized_stable_lane_values},
            {"stable_mutation_epoch_sites", semanticCandidate->stable_mutation_epoch_sites},
            {"steady_state_transition_sites", semanticCandidate->steady_state_transition_sites},
            {"periodic_transition_sites", semanticCandidate->periodic_transition_sites},
            {"unobserved_branch_arms", semanticCandidate->unobserved_branch_arms},
            {"runtime_specializations", semanticCandidate->runtime_specializations},
            {"inferred_root_slots", semanticCandidate->inferred_root_slots},
            {"root_argument_shared_prototypes", semanticCandidate->root_argument_shared_prototypes},
            {"root_argument_references_specialized", semanticCandidate->root_argument_references_specialized},
            {"absent_root_argument_references_specialized", semanticCandidate->absent_root_argument_references_specialized},
            {"root_argument_table_complete", semanticCandidate->root_argument_table_complete},
            {"root_call_frame_specialized", semanticCandidate->root_call_frame_specialized},
            {"closure_constructors", semanticCandidate->closure_constructors},
            {"unresolved_closure_descriptors", semanticCandidate->unresolved_closure_descriptors},
            {"capture_key_remaps", semanticCandidate->capture_key_remaps},
            {"unresolved_capture_keys", semanticCandidate->unresolved_capture_keys},
            {"observed_return_events", semanticCandidate->observed_return_events},
            {"verified_return_sites", semanticCandidate->verified_return_sites},
            {"return_arity_mismatches", semanticCandidate->return_arity_mismatches},
            {"direct_prototype_calls", semanticCandidate->direct_prototype_calls},
            {"fixed_register_calls", semanticCandidate->fixed_register_calls},
            {"open_register_calls", semanticCandidate->open_register_calls},
            {"observed_global_call_arguments", semanticCandidate->observed_global_call_arguments},
            {"blocks_map", semanticCandidate->mapping},
        });
        report["passes"].push_back({
            {"stage", "semantic_refine"},
            {"ok", semanticReadableCandidateCompiled},
            {"available", semanticReadableCandidate.has_value()},
            {"changed", semanticReadableCandidate ? semanticReadableCandidate->changed : false},
            {"compiled", semanticReadableCandidateCompiled},
            {"compile_error", semanticReadableCompileError ? json(*semanticReadableCompileError) : json(nullptr)},
            {"diagnostic_artifact", semanticReadableCompileError
                    ? json(semanticReadableFailedPath.filename().string()) : json(nullptr)},
            {"source_claim", false},
            {"representation", "cleaned-trace-specialized-state-machine"},
            {"regions_found", semanticReadableCandidate ? semanticReadableCandidate->regions_found : 0},
            {"regions_structured", semanticReadableCandidate ? semanticReadableCandidate->regions_structured : 0},
            {"blocks_structured", semanticReadableCandidate ? semanticReadableCandidate->blocks_structured : 0},
            {"reentry_nodes_split", semanticReadableCandidate ? semanticReadableCandidate->reentry_nodes_split : 0},
            {"residual_state_machines", semanticReadableCandidate ? semanticReadableCandidate->residual_state_machines : 0},
            {"residual_reasons", semanticReadableCandidate ? semanticReadableCandidate->residual_reasons : json::object()},
            {"constants_propagated", semanticReadableCandidate ? semanticReadableCandidate->constants_propagated : 0},
            {"aliases_propagated", semanticReadableCandidate ? semanticReadableCandidate->aliases_propagated : 0},
            {"register_tables_scalarized", semanticReadableCandidate ? semanticReadableCandidate->register_tables_scalarized : 0},
            {"register_tables_fully_scalarized", semanticReadableCandidate ? semanticReadableCandidate->register_tables_fully_scalarized : 0},
            {"register_tables_partially_scalarized", semanticReadableCandidate ? semanticReadableCandidate->register_tables_partially_scalarized : 0},
            {"register_table_slots_scalarized", semanticReadableCandidate ? semanticReadableCandidate->register_table_slots_scalarized : 0},
            {"register_table_accesses_scalarized", semanticReadableCandidate ? semanticReadableCandidate->register_table_accesses_scalarized : 0},
            {"fixed_top_call_packs_expanded", semanticReadableCandidate ? semanticReadableCandidate->fixed_top_call_packs_expanded : 0},
            {"state_tables_scalarized", semanticReadableCandidate ? semanticReadableCandidate->state_tables_scalarized : 0},
            {"state_fields_scalarized", semanticReadableCandidate ? semanticReadableCandidate->state_fields_scalarized : 0},
            {"state_accesses_scalarized", semanticReadableCandidate ? semanticReadableCandidate->state_accesses_scalarized : 0},
            {"replay_sequences_compressed", semanticReadableCandidate ? semanticReadableCandidate->replay_sequences_compressed : 0},
            {"replay_sequence_entries_collapsed", semanticReadableCandidate ? semanticReadableCandidate->replay_sequence_entries_collapsed : 0},
            {"replay_bytes_removed", semanticReadableCandidate ? semanticReadableCandidate->replay_bytes_removed : 0},
            {"replay_targets_inlined", semanticReadableCandidate ? semanticReadableCandidate->replay_targets_inlined : 0},
            {"high_register_replay_patches_removed", semanticReadableCandidate ? semanticReadableCandidate->high_register_replay_patches_removed : 0},
            {"cleared_replay_metadata_patches_removed", semanticReadableCandidate ? semanticReadableCandidate->cleared_replay_metadata_patches_removed : 0},
            {"low_register_replay_patches_removed", semanticReadableCandidate ? semanticReadableCandidate->low_register_replay_patches_removed : 0},
            {"replay_branches_collapsed", semanticReadableCandidate ? semanticReadableCandidate->replay_branches_collapsed : 0},
            {"linear_replay_metadata_patches_removed", semanticReadableCandidate ? semanticReadableCandidate->linear_replay_metadata_patches_removed : 0},
            {"direct_closure_calls_recovered", semanticReadableCandidate ? semanticReadableCandidate->direct_closure_calls_recovered : 0},
            {"trace_instrumentation_removed", semanticReadableCandidate ? semanticReadableCandidate->trace_instrumentation_removed : 0},
            {"unreachable_prototypes_removed", semanticReadableCandidate ? semanticReadableCandidate->unreachable_prototypes_removed : 0},
            {"alias_reloads_eliminated", semanticReadableCandidate ? semanticReadableCandidate->alias_reloads_eliminated : 0},
            {"producer_aliases_coalesced", semanticReadableCandidate ? semanticReadableCandidate->producer_aliases_coalesced : 0},
            {"function_locals_promoted", semanticReadableCandidate ? semanticReadableCandidate->function_locals_promoted : 0},
            {"unused_local_declarations_removed", semanticReadableCandidate ? semanticReadableCandidate->unused_local_declarations_removed : 0},
            {"guard_clauses_flattened", semanticReadableCandidate ? semanticReadableCandidate->guard_clauses_flattened : 0},
            {"redundant_parentheses_removed", semanticReadableCandidate ? semanticReadableCandidate->redundant_parentheses_removed : 0},
            {"refinement_passes", semanticReadableCandidate ? semanticReadableCandidate->refinement_passes : 0},
        });
        report["passes"].push_back({
            {"stage", "payload_slice"},
            {"ok", payloadClosureMetrics->prototypes > 0},
            {"activations", payloadClosureMetrics->activations},
            {"activated_prototypes", payloadClosureMetrics->activated_prototypes},
            {"closure_expanded_prototypes", payloadClosureMetrics->closure_expanded_prototypes},
            {"closure_expansion_edges", payloadClosureMetrics->closure_expansion_edges},
            {"prototypes", payloadClosureMetrics->prototypes},
            {"instructions", payloadClosureMetrics->instructions},
            {"static_semantic_lifted", payloadClosureMetrics->statically_lifted},
            {"static_semantic_unresolved", payloadClosureMetrics->instructions - payloadClosureMetrics->statically_lifted},
            {"source_semantic_instructions", payloadClosureMetrics->source_semantic},
            {"protector_internal_instructions", payloadClosureMetrics->protector_internal},
            {"unresolved_observed_instructions", payloadClosureMetrics->unresolved_observed},
            {"observed_steps", payloadClosureMetrics->observed_steps},
            {"observed_returns", payloadClosureMetrics->observed_returns},
            {"source_emitted", false},
        });
        report["passes"].push_back({
            {"stage", "payload_cfg"},
            {"ok", payloadCfgDocument->value("reachable_invalid_edges", size_t(0)) == 0},
            {"prototypes", payloadCfgDocument->value("prototype_count", size_t(0))},
            {"blocks", payloadCfgDocument->value("block_count", size_t(0))},
            {"reachable_blocks", payloadCfgDocument->value("reachable_blocks", size_t(0))},
            {"reachable_instructions", payloadCfgDocument->value("reachable_instructions", size_t(0))},
            {"edges", payloadCfgDocument->value("edge_count", size_t(0))},
            {"cyclic_regions", payloadCfgDocument->value("cyclic_regions", size_t(0))},
            {"irreducible_regions", payloadCfgDocument->value("irreducible_regions", size_t(0))},
            {"invalid_edges", payloadCfgDocument->value("invalid_edges", size_t(0))},
            {"reachable_invalid_edges", payloadCfgDocument->value("reachable_invalid_edges", size_t(0))},
            {"observed_edge_sites", payloadCfgDocument->value("observed_edge_sites", size_t(0))},
        });
        report["passes"].push_back({
            {"stage", "reachable_slice"},
            {"ok", payloadReachableIrDocument->value("instruction_count", size_t(0)) > 0},
            {"prototypes", payloadReachableIrDocument->value("prototype_count", size_t(0))},
            {"instructions", payloadReachableIrDocument->value("instruction_count", size_t(0))},
            {"source_semantic_instructions", payloadReachableIrDocument->value("source_semantic_instructions", size_t(0))},
            {"protector_internal_instructions", payloadReachableIrDocument->value("protector_internal_instructions", size_t(0))},
            {"dynamic_lane_sites", payloadReachableIrDocument->value("observed_lane_sequences", json::array()).size()},
        });
        report["passes"].push_back({
            {"stage", "explain"},
            {"ok", fs::exists(readableLiftPath) && fs::file_size(readableLiftPath) > 0},
            {"format", "plain-language-routine-guide"},
            {"prototypes", payloadReachableIrDocument->value("prototype_count", size_t(0))},
            {"instructions", payloadReachableIrDocument->value("instruction_count", size_t(0))},
            {"protector_noise_collapsed", payloadReachableIrDocument->value("protector_internal_instructions", size_t(0))},
        });
        report["passes"].push_back({
            {"stage", "semantic_emit"},
            {"ok", semanticCandidateCompiled},
            {"compiled", semanticCandidateCompiled},
            {"source_claim", false},
            {"representation", "trace-specialized-register-state-machine"},
            {"fully_rendered", semanticCandidate->fully_rendered()},
            {"prototypes", semanticCandidate->prototypes},
            {"blocks", semanticCandidate->blocks},
            {"operations", semanticCandidate->operations},
            {"unsupported_expressions", semanticCandidate->unsupported_expressions},
            {"unsupported_operations", semanticCandidate->unsupported_operations},
            {"symbolic_transitions", semanticCandidate->symbolic_transitions},
            {"dynamic_edge_sites", semanticCandidate->dynamic_edge_sites},
            {"replayed_dynamic_edge_sites", semanticCandidate->replayed_dynamic_edge_sites},
            {"activation_scoped_transition_sites", semanticCandidate->activation_scoped_transition_sites},
            {"dynamic_lane_replay_sites", semanticCandidate->dynamic_lane_replay_sites},
            {"replayed_dynamic_lane_values", semanticCandidate->replayed_dynamic_lane_values},
            {"specialized_stable_lanes", semanticCandidate->specialized_stable_lanes},
            {"specialized_stable_lane_values", semanticCandidate->specialized_stable_lane_values},
            {"stable_mutation_epoch_sites", semanticCandidate->stable_mutation_epoch_sites},
            {"steady_state_transition_sites", semanticCandidate->steady_state_transition_sites},
            {"periodic_transition_sites", semanticCandidate->periodic_transition_sites},
            {"unobserved_branch_arms", semanticCandidate->unobserved_branch_arms},
            {"runtime_specializations", semanticCandidate->runtime_specializations},
            {"direct_prototype_calls", semanticCandidate->direct_prototype_calls},
            {"fixed_register_calls", semanticCandidate->fixed_register_calls},
            {"open_register_calls", semanticCandidate->open_register_calls},
            {"observed_global_call_arguments", semanticCandidate->observed_global_call_arguments},
            {"inferred_root_slots", semanticCandidate->inferred_root_slots},
            {"root_argument_shared_prototypes", semanticCandidate->root_argument_shared_prototypes},
            {"root_argument_references_specialized", semanticCandidate->root_argument_references_specialized},
            {"absent_root_argument_references_specialized", semanticCandidate->absent_root_argument_references_specialized},
            {"root_argument_table_complete", semanticCandidate->root_argument_table_complete},
            {"root_call_frame_specialized", semanticCandidate->root_call_frame_specialized},
            {"closure_constructors", semanticCandidate->closure_constructors},
            {"unresolved_closure_descriptors", semanticCandidate->unresolved_closure_descriptors},
            {"capture_key_remaps", semanticCandidate->capture_key_remaps},
            {"unresolved_capture_keys", semanticCandidate->unresolved_capture_keys},
            {"observed_return_events", semanticCandidate->observed_return_events},
            {"verified_return_sites", semanticCandidate->verified_return_sites},
            {"return_arity_mismatches", semanticCandidate->return_arity_mismatches},
        });
        if (payloadRoot && dynamicTrace->calls.empty())
        {
            report["diagnostics"].insert(report["diagnostics"].begin(), json{
                {"stage", "structure"},
                {"severity", "warning"},
                {"code", "luraph_payload_structure_pending"},
                {"message", "The bootstrap-to-payload activation edge and its complete reached semantic closure were recovered, but multi-prototype source structuring is not complete yet."},
                {"details", {{"payload_activation", payloadRoot->payload_activation},
                    {"payload_prototype", payloadRoot->payload_prototype},
                    {"activations", payloadClosureMetrics->activations},
                    {"activated_prototypes", payloadClosureMetrics->activated_prototypes},
                    {"closure_expanded_prototypes", payloadClosureMetrics->closure_expanded_prototypes},
                    {"closure_expansion_edges", payloadClosureMetrics->closure_expansion_edges},
                    {"prototypes", payloadClosureMetrics->prototypes},
                    {"instructions", payloadClosureMetrics->instructions}}},
            });
        }
    }
    if (runtimeStructure && dynamicTrace && !dynamicTrace->calls.empty())
    {
        try
        {
            observedCandidate = buildLuraphObservedCandidate(*runtimeStructure, *dynamicTrace);
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string("observed candidate emission failed: ") + error.what());
        }
        observedCandidateCompiled = observedCandidate->complete && compiles(observedCandidate->source);
        if (observedCandidateCompiled)
        {
            writeFile(payloadCandidatePath, observedCandidate->source);
            writeJson(payloadCandidateProvenancePath, {
                {"version", 1},
                {"kind", "luraph-observed-payload-candidate-provenance"},
                {"source_claim", false},
                {"compiled", true},
                {"statements", observedCandidate->provenance},
            });
        }
        report["passes"].push_back({
            {"stage", "payload_candidate"},
            {"ok", observedCandidateCompiled},
            {"statements", observedCandidate->provenance.size()},
            {"compiled", observedCandidateCompiled},
            {"source_claim", false},
            {"promoted_to_reconstruction", false},
        });
    }

    if (payloadClosureDocument && observedCandidateCompiled && observedCandidate)
    {
        try
        {
            statementReconstruction = buildLuraphStatementReconstruction(
                *payloadClosureDocument, *observedCandidate);
            if (!statementReconstruction->complete)
                statementReconstruction = buildLuraphObservedOutputReconstruction(
                    *payloadClosureDocument, *observedCandidate, *dynamicTrace);
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string("statement reconstruction failed: ") + error.what());
        }
        report["passes"].push_back({
            {"stage", "source_map"},
            {"ok", statementReconstruction->complete},
            {"covered_instructions", statementReconstruction->covered_instructions},
            {"total_instructions", payloadClosureMetrics ? payloadClosureMetrics->instructions : 0},
            {"decoder_prototypes", statementReconstruction->decoder_prototypes.size()},
            {"statements", statementReconstruction->statements.size()},
            {"reason", statementReconstruction->reason},
            {"proof_scope", statementReconstruction->proof_scope},
            {"full_instruction_coverage", statementReconstruction->full_instruction_coverage},
        });
    }

    const bool runtimeSemanticPayloadComplete = payloadClosureMetrics && payloadClosureMetrics->instructions > 0 &&
        payloadClosureMetrics->statically_lifted == payloadClosureMetrics->instructions &&
        payloadClosureMetrics->unresolved_observed == 0;
    const bool sourceReconstructionComplete = statementReconstruction && statementReconstruction->complete;
    const bool observedOutputReconstructionComplete = sourceReconstructionComplete && statementReconstruction &&
        statementReconstruction->proof_scope == "completed-output-only-payload-trace";
    const bool reconstructionReady = sourceReconstructionComplete &&
        (runtimeSemanticPayloadComplete || observedOutputReconstructionComplete);
    if (dynamicTrace && !dynamicTrace->calls.empty() && dynamicTrace->payload_activation_complete &&
        !reconstructionReady)
    {
        report["diagnostics"].push_back({
            {"stage", "lift"},
            {"severity", "info"},
            {"code", "luraph_semantic_payload_incomplete"},
            {"message", "Confirmed calls and their complete activation/prototype trace were retained as observations, but unresolved reachable instructions prevent a source claim."},
        });
    }
    if (dynamicTrace && !dynamicTrace->calls.empty() && dynamicTrace->payload_activation_complete &&
        reconstructionReady)
    {
        const fs::path sourcePath = options.output_dir / "reconstructed.luau";
        std::string reconstructed;
        json operations = json::array();
        json constants = json::array();
        json mappings = json::array();
        json cfgNodes = json::array();
        bool observedOutputMatch = true;
        size_t line = 1;
        for (const LuraphTraceCall& call : dynamicTrace->calls)
        {
            const std::optional<std::string> statement = luraphTraceCallSource(call);
            if (!statement)
                continue;
            reconstructed += *statement + "\n";
            std::string expectedOutput;
            json argumentRows = json::array();
            for (size_t argumentIndex = 0; argumentIndex < call.arguments.size(); ++argumentIndex)
            {
                const LuraphTraceValue& argument = call.arguments[argumentIndex];
                if (argumentIndex > 0)
                    expectedOutput += '\t';
                if (argument.type == "nil")
                    expectedOutput += "nil";
                else
                    expectedOutput += argument.value;
                argumentRows.push_back({{"type", argument.type}, {"value", argument.value}});
                constants.push_back({
                    {"index", constants.size()},
                    {"type", argument.type},
                    {"value", argument.value},
                    {"provenance", "runtime_register"},
                });
            }
            const bool outputMatched = call.target != "print" ||
                std::find(dynamicTrace->output_lines.begin(), dynamicTrace->output_lines.end(), expectedOutput) != dynamicTrace->output_lines.end();
            observedOutputMatch = observedOutputMatch && outputMatched;
            operations.push_back({
                {"kind", "global_call"},
                {"target", call.target},
                {"arguments", argumentRows},
                {"result_arity", 0},
                {"trace", {{"vm_count", call.vm_count}, {"activation", call.activation}, {"pc", call.pc}, {"opcode", call.opcode}}},
            });
            mappings.push_back({
                {"line", line++},
                {"statement", *statement},
                {"vm_count", call.vm_count},
                {"activation", call.activation},
                {"pc", call.pc},
                {"opcode", call.opcode},
            });
            cfgNodes.push_back({
                {"id", "trace_call_" + std::to_string(cfgNodes.size() + 1)},
                {"kind", "global_call"},
                {"activation", call.activation},
                {"pc", call.pc},
            });
        }

        const bool structurallyMatched = statementReconstruction && reconstructed == statementReconstruction->source;
        const bool compiled = structurallyMatched && !reconstructed.empty() && compiles(reconstructed);
        if (compiled)
        {
            writeFile(sourcePath, reconstructed);
            writeJson(envelopePath, luraphEnvelopeArtifact(analysis));
            writeJson(irPath, {
                {"version", 2},
                {"kind", "luraph-trace-backed-semantic-ir"},
                {"status", "reconstructed"},
                {"adapter", luraphAdapterName(analysis)},
                {"exact_source", false},
                {"prototypes", json::array({{{"id", "payload_trace_root"}, {"operations", operations}}})},
                {"basic_blocks", json::array({{{"id", "entry"}, {"operations", operations}, {"terminator", "return"}}})},
            });
            writeJson(cfgPath, {
                {"version", 2},
                {"kind", "luraph-observed-payload-cfg"},
                {"entry", cfgNodes.empty() ? json(nullptr) : cfgNodes.front()["id"]},
                {"nodes", cfgNodes},
                {"edges", json::array()},
            });
            writeJson(constantsPath, {
                {"version", 2},
                {"encoding", "runtime-register-observation"},
                {"constants", constants},
            });
            writeJson(mapPath, {
                {"version", 2},
                {"output", sourcePath.filename().string()},
                {"verified", observedOutputMatch},
                {"statements", mappings},
                {"statement_coverage_complete", statementReconstruction->full_instruction_coverage},
                {"observed_behavior_coverage_complete", observedOutputReconstructionComplete},
                {"proof_scope", statementReconstruction->proof_scope},
                {"covered_instructions", statementReconstruction->covered_instructions},
                {"instruction_coverage", statementReconstruction->coverage},
                {"decoder_prototypes", statementReconstruction->decoder_prototypes},
            });
            std::ostringstream disassembly;
            disassembly << "Alex native Luraph v14.7 bounded payload trace\n";
            for (const LuraphTraceCall& call : dynamicTrace->calls)
            {
                disassembly << "vm=" << call.vm_count << " activation=" << call.activation << " pc=" << call.pc << " opcode=" << call.opcode
                            << " call=" << call.target << " arguments=[";
                for (size_t argumentIndex = 0; argumentIndex < call.arguments.size(); ++argumentIndex)
                {
                    if (argumentIndex > 0)
                        disassembly << ", ";
                    const LuraphTraceValue& argument = call.arguments[argumentIndex];
                    disassembly << argument.type << ':' << quoteLuau(argument.value);
                }
                disassembly << "]\n";
            }
            writeFile(disassemblyPath, disassembly.str());
            writeJson(graphPath, {
                {"version", 2},
                {"nodes", json::array({
                    {{"id", sha256(source)}, {"kind", "luau_source"}, {"bytes", source.size()}, {"provenance", "input"}},
                    {{"id", sha256(reconstructed)}, {"kind", "reconstructed_luau"}, {"bytes", reconstructed.size()}, {"provenance", "bounded_runtime_trace"}},
                })},
                {"edges", json::array({{{"from", sha256(source)}, {"to", sha256(reconstructed)}, {"relation", "trace_lift"}}})},
            });

            report["status"] = "reconstructed";
            report["analysis_scope"] = "source-envelope-and-bounded-runtime-trace";
            report["passes"].push_back({{"stage", "lift"}, {"ok", true}, {"operations", dynamicTrace->calls.size()}, {"source_emitted", true}});
            report["passes"].push_back({
                {"stage", "source_map"},
                {"ok", true},
                {"covered_instructions", statementReconstruction->covered_instructions},
                {"total_instructions", payloadClosureMetrics->instructions},
                {"decoder_prototypes", statementReconstruction->decoder_prototypes.size()},
                {"source_emitted", true},
                {"proof_scope", statementReconstruction->proof_scope},
                {"full_instruction_coverage", statementReconstruction->full_instruction_coverage},
            });
            report["passes"].push_back({{"stage", "compile"}, {"ok", true}});
            report["diagnostics"].push_back(observedOutputReconstructionComplete ? json{
                {"stage", "lift"},
                {"severity", "info"},
                {"code", "luraph_observed_output_payload_reconstructed"},
                {"message", "A completed output-only payload activation was reconstructed from confirmed call producers, matching output, and its terminal zero-value return. Protector instructions remain outside the source claim; the result is reconstructed behavior, not original text."},
            } : json{
                {"stage", "lift"},
                {"severity", "info"},
                {"code", "luraph_trace_payload_reconstructed"},
                {"message", "Every instruction in the confirmed payload closure was mapped to emitted Luau or a proven value-decoder/protector operation. The result is reconstructed Luau, not original source."},
            });
            report["coverage"] = {
                {"scope", "observed-payload-trace"},
                {"trace_events", dynamicTrace->event_count},
                {"vm_events", dynamicTrace->vm_events.size()},
                {"payload_activation_complete", true},
                {"payload_calls", {{"candidates", dynamicTrace->candidate_call_count}, {"observed", dynamicTrace->calls.size()},
                                      {"lifted", dynamicTrace->calls.size()}, {"unresolved", dynamicTrace->unresolved_call_count}}},
                {"constants", {{"observed", constants.size()}, {"lifted", constants.size()}}},
                {"runtime_decode", {{"available", runtimeStructure.has_value()},
                    {"complete", runtimeStructure ? json(runtimeStructure->complete) : json(nullptr)},
                    {"prototypes", runtimeStructure ? json(runtimeStructure->prototypes.size()) : json(0)},
                    {"instructions", runtimeStructure ? json(runtimeStructure->instruction_count) : json(0)},
                    {"observed_steps", runtimeStructure ? json(runtimeStructure->steps.size()) : json(0)},
                    {"effect_classified", runtimeEffectClassified},
                    {"trace_specialized_sites", runtimeTraceSpecialized},
                    {"observed_effect_classified_sites", runtimeTraceEffects},
                    {"trace_specialized_is_path_specific", true},
                    {"unresolved", runtimeUnresolved},
                    {"semantic_lifted", runtimeSemanticLifted},
                    {"semantic_unresolved", runtimeDecoded ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(0)}}},
                {"payload_closure", {{"available", true},
                    {"activations", payloadClosureMetrics->activations},
                    {"activated_prototypes", payloadClosureMetrics->activated_prototypes},
                    {"closure_expanded_prototypes", payloadClosureMetrics->closure_expanded_prototypes},
                    {"closure_expansion_edges", payloadClosureMetrics->closure_expansion_edges},
                    {"prototypes", payloadClosureMetrics->prototypes},
                    {"instructions", payloadClosureMetrics->instructions},
                    {"static_semantic_lifted", payloadClosureMetrics->statically_lifted},
                    {"static_semantic_unresolved", payloadClosureMetrics->instructions - payloadClosureMetrics->statically_lifted},
                    {"source_semantic_instructions", payloadClosureMetrics->source_semantic},
                    {"protector_internal_instructions", payloadClosureMetrics->protector_internal},
                    {"unresolved_observed_instructions", payloadClosureMetrics->unresolved_observed},
                    {"observed_path_coverage_complete", payloadClosureMetrics->instructions > 0 &&
                        payloadClosureMetrics->statically_lifted + payloadClosureMetrics->unresolved_observed ==
                            payloadClosureMetrics->instructions},
                    {"observed_steps", payloadClosureMetrics->observed_steps},
                    {"observed_returns", payloadClosureMetrics->observed_returns}}},
                {"source_emitted", true},
                {"statement_coverage", {{"complete", statementReconstruction->full_instruction_coverage},
                    {"observed_behavior_complete", observedOutputReconstructionComplete},
                    {"proof_scope", statementReconstruction->proof_scope},
                    {"covered_instructions", statementReconstruction->covered_instructions},
                    {"total_instructions", payloadClosureMetrics->instructions},
                    {"decoder_prototypes", statementReconstruction->decoder_prototypes.size()}}},
            };
            report["verification"] = {
                {"input_parsed", inputParsed},
                {"compiled", true},
                {"source_claim_accepted", false},
                {"output", {{"available", true}, {"compiled", true}, {"observed_stdout_match", observedOutputMatch}}},
                {"runtime", {{"attempted", false}, {"equivalent", nullptr}, {"reason", "reconstruction compilation and observed stdout were checked; differential rerun remains separate"}}},
            };
            report["artifacts"] = {
                {"source", sourcePath.filename().string()},
                {"envelope_analysis", envelopePath.filename().string()},
                {"disassembly", disassemblyPath.filename().string()},
                {"semantic_ir", irPath.filename().string()},
                {"cfg", cfgPath.filename().string()},
                {"constants", constantsPath.filename().string()},
                {"graph", graphPath.filename().string()},
                {"reconstruction_map", mapPath.filename().string()},
                {"trace_probe", traceProbeCompiled ? json(traceProbePath.filename().string()) : json(nullptr)},
                {"opcode_handlers", opcodeCatalog.available ? json(opcodeHandlersPath.filename().string()) : json(nullptr)},
                {"structure_probe", structureProbeCompiled ? json(structureProbePath.filename().string()) : json(nullptr)},
                {"runtime_prototypes", runtimeStructure && !runtimeStructure->prototypes.empty()
                    ? json(runtimePrototypesPath.filename().string()) : json(nullptr)},
                {"prototype_correspondence", prototypeCorrespondenceDocument
                    ? json(prototypeCorrespondencePath.filename().string()) : json(nullptr)},
                {"runtime_semantic_ir", runtimeStructure && !runtimeStructure->prototypes.empty()
                    ? json(runtimeSemanticPath.filename().string()) : json(nullptr)},
                {"payload_closure_ir", payloadClosureMetrics
                    ? json(payloadClosurePath.filename().string()) : json(nullptr)},
                {"readable_lift", fs::exists(readableLiftPath)
                    ? json(readableLiftPath.filename().string()) : json(nullptr)},
                {"semantic_candidate", semanticCandidateCompiled
                    ? json(semanticCandidatePath.filename().string()) : json(nullptr)},
                {"semantic_readable_candidate", semanticReadableCandidateCompiled
                    ? json(semanticReadablePath.filename().string()) : json(nullptr)},
                {"semantic_candidate_map", semanticCandidate
                    ? json(semanticCandidateMapPath.filename().string()) : json(nullptr)},
            };
            publishProgress(options, "trace", "done", "Bounded Luraph payload trace parsed",
                {{"events", dynamicTrace->event_count}, {"candidate_calls", dynamicTrace->candidate_call_count},
                    {"payload_calls", dynamicTrace->calls.size()}, {"unresolved_candidates", dynamicTrace->unresolved_call_count}});
            publishProgress(options, "lift", "done", "Observed Luraph payload calls lifted to compilable Luau",
                {{"operations", dynamicTrace->calls.size()}, {"exact_source", false}});
            writeJson(reportPath, report);
            result.exit_code = 0;
            result.report = std::move(report);
            return result;
        }
    }
    if (parsedContainer || runtimeDecoded)
    {
        const size_t structuralPrototypeCount = runtimeDecoded
            ? runtimeStructure->prototypes.size() : analysis.container_metrics.prototype_count;
        const size_t structuralInstructionCount = runtimeDecoded
            ? runtimeStructure->instruction_count : retainedInstructions;
        const bool reachedSemanticsComplete = runtimeSchemaComplete &&
            runtimeSemanticLifted == runtimeDeclaredInstructions;
        report["passes"].push_back({
            {"stage", "decode"},
            {"ok", true},
            {"attempted", true},
            {"scope", parsedContainer ? "lph-container-framing" : "lph-dollar-carrier-and-runtime-prototypes"},
            {"containers_decoded", analysis.container_metrics.decoded_count},
            {"containers_parsed", analysis.container_metrics.parsed_count},
            {"decoded_bytes", analysis.container_metrics.decoded_bytes},
            {"prototype_objects_decoded", runtimeDecoded},
            {"payload_semantics_decoded", reachedSemanticsComplete},
        });
        if (!parsedContainer)
            report["passes"].push_back({
                {"stage", "container_schema"},
                {"ok", true},
                {"attempted", true},
                {"scope", "runtime-deserialized-prototype-objects"},
                {"static_serialized_schema_recovered", false},
                {"runtime_prototype_schema_recovered", true},
                {"bypass", "protected-runtime-deserializer"},
            });
        report["passes"].push_back({
            {"stage", "disassemble"},
            {"ok", true},
            {"attempted", true},
            {"scope", parsedContainer ? "normalized-v14.7-instruction-lanes" : "runtime-decoded-prototype-lanes"},
            {"prototypes", structuralPrototypeCount},
            {"instructions", structuralInstructionCount},
            {"opcode_values_recovered", true},
            {"operand_lanes_recovered", true},
            {"opcode_semantics_recovered", reachedSemanticsComplete},
        });
        report["passes"].push_back({
            {"stage", "cfg"},
            {"ok", payloadCfgDocument.has_value() || observedCfgDocument.has_value()},
            {"attempted", runtimeDecoded},
            {"scope", payloadCfgDocument ? "reachable-runtime-activation-graph" :
                observedCfgDocument ? "bounded-observed-runtime-graph" : "runtime-prototype-index"},
            {"complete", payloadCfgDocument.has_value()},
            {"root_prototype_recovered", payloadRoot.has_value()},
            {"reason", payloadCfgDocument || observedCfgDocument
                ? json(nullptr) : json("runtime_control_edges_not_observed")},
        });
        report["passes"].push_back({
            {"stage", "lift"},
            {"ok", reachedSemanticsComplete},
            {"attempted", runtimeDecoded},
            {"scope", runtimeDecoded ? "runtime-decoded-prototypes" : "decoded-container"},
            {"semantic_lifted", runtimeSemanticLifted},
            {"semantic_unresolved", runtimeDecoded
                ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(retainedInstructions)},
            {"observational_sites", runtimeObservationalSites},
            {"observational_semantic_lifted", runtimeObservationalLifted},
            {"observational_semantic_unresolved", runtimeObservationalUnresolved},
            {"guard_replay_sites_validated", runtimeGuardReplaySitesValidated},
            {"guard_replay_sites_divergent", runtimeGuardReplaySitesDivergent},
            {"unobserved_instructions", runtimeUnobservedInstructions},
            {"observational_operation_counts", runtimeObservationalOperationCounts},
            {"observational_path_specific", true},
            {"write_origin_evidence", runtimeWriteOriginEvidence},
            {"reason", reachedSemanticsComplete
                ? json(dynamicTrace && dynamicTrace->calls.empty() && !payloadRoot
                    ? "payload_call_not_reached" : "source_structure_not_reconstructed")
                : json("randomized_opcode_semantics_unresolved")},
            {"source_emitted", false},
        });
        report["diagnostics"].push_back({
            {"stage", "decode"},
            {"severity", "info"},
            {"code", parsedContainer ? "luraph_container_decoded" : "luraph_runtime_container_decoded"},
            {"message", parsedContainer
                ? "Strict LPH& framing was decoded and its bounded constant and prototype records were parsed."
                : runtimeSchemaComplete
                    ? "The LPH$ carrier was decoded, then the protected runtime deserializer exposed a complete prototype and instruction corpus offline."
                    : "The LPH$ carrier was decoded, but the protected runtime deserializer exposed only a partial prototype or instruction corpus offline."},
            {"details", {{"containers", analysis.container_metrics.parsed_count},
                {"decoded_bytes", analysis.container_metrics.decoded_bytes},
                {"prototypes", structuralPrototypeCount}, {"instructions", structuralInstructionCount}}},
        });
        report["diagnostics"].push_back({
            {"stage", "disassemble"},
            {"severity", "info"},
            {"code", "luraph_container_disassembled"},
            {"message", parsedContainer
                ? "Every retained instruction was normalized to its runtime opcode and D/G/p operand lanes, including constant and prototype references."
                : "Every runtime-decoded prototype instruction was retained with its randomized opcode and complete observed lane values."},
            {"details", {{"prototypes", structuralPrototypeCount}, {"instructions", structuralInstructionCount}}},
        });
        report["diagnostics"].push_back(reachedSemanticsComplete ? json{
            {"stage", "lift"},
            {"severity", "info"},
            {"code", "luraph_reachable_semantics_lifted"},
            {"message", "Every instruction in the reached runtime prototypes was classified semantically; source remains withheld until the payload activation is reached and reconstructed."},
            {"details", {{"semantic_lifted", runtimeSemanticLifted}, {"semantic_unresolved", 0}}},
        } : json{
            {"stage", "lift"},
            {"severity", "warning"},
            {"code", "luraph_semantic_lift_incomplete"},
            {"message", "The decoded instruction lanes are available, but opcode handlers have not all been lifted into semantic operations; no source was emitted."},
            {"details", {
                {"static_semantic_lifted", runtimeSemanticLifted},
                {"static_semantic_unresolved", runtimeDecoded
                    ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(structuralInstructionCount)},
                {"observational_sites", runtimeObservationalSites},
                {"observational_semantic_lifted", runtimeObservationalLifted},
                {"observational_semantic_unresolved", runtimeObservationalUnresolved},
                {"guard_replay_sites_validated", runtimeGuardReplaySitesValidated},
                {"guard_replay_sites_divergent", runtimeGuardReplaySitesDivergent},
                {"unobserved_instructions", runtimeUnobservedInstructions},
                {"observational_path_specific", true},
            }},
        });
    }
    else if (decodedContainer)
    {
        report["passes"].push_back({
            {"stage", "decode"},
            {"ok", true},
            {"attempted", true},
            {"scope", "lph-dollar-carrier"},
            {"containers_decoded", analysis.container_metrics.decoded_count},
            {"containers_parsed", 0},
            {"decoded_bytes", analysis.container_metrics.decoded_bytes},
            {"decoded_artifact", decodedContainerWritten ? json(decodedContainerPath.filename().string()) : json(nullptr)},
            {"payload_semantics_decoded", false},
        });
        report["passes"].push_back({
            {"stage", "container_schema"},
            {"ok", false},
            {"attempted", false},
            {"scope", "lph-dollar-randomized-records"},
            {"reason", "version_specific_schema_not_recovered"},
        });
        report["passes"].push_back({{"stage", "cfg"}, {"ok", false}, {"attempted", false}, {"scope", "payload"}});
        report["passes"].push_back({
            {"stage", "lift"}, {"ok", false}, {"attempted", false},
            {"reason", "container_schema_required"}, {"source_emitted", false},
        });
        report["diagnostics"].push_back({
            {"stage", "container_schema"},
            {"severity", "warning"},
            {"code", "luraph_lph_dollar_schema_required"},
            {"message", "The complete LPH$ carrier was decoded and saved, but its randomized record schema must be recovered before prototypes or source can be claimed."},
            {"details", {{"decoded_bytes", analysis.container_metrics.decoded_bytes},
                {"decoded_artifact", decodedContainerWritten ? json(decodedContainerPath.filename().string()) : json(nullptr)}}},
        });
    }
    else
    {
        report["passes"].push_back({
            {"stage", "decode"},
            {"ok", false},
            {"attempted", false},
            {"reason", "payload_decoder_not_implemented"},
        });
        report["passes"].push_back({{"stage", "cfg"}, {"ok", false}, {"attempted", false}, {"scope", "payload"}});
        report["passes"].push_back({{"stage", "lift"}, {"ok", false}, {"attempted", false}, {"source_emitted", false}});
        report["diagnostics"].push_back({
            {"stage", (analysis.version_supported || analysis.generated_interpreter) ? "decode" : "detect"},
            {"severity", "error"},
            {"code", analysis.generated_interpreter ? "luraph_runtime_interpreter_trace_required" :
                (analysis.version_supported ? "luraph_payload_decode_unimplemented" : "unsupported_luraph_version")},
            {"message", analysis.generated_interpreter
                    ? "The runtime-generated Luraph interpreter was identified, but it must be instrumented inside the original wrapper so its hidden VM state is preserved."
                    : analysis.version_supported
                    ? "Luraph v14.7 was identified, but this bounded adapter currently recovers envelope structure only; no source was emitted."
                    : "A Luraph envelope was identified, but its version is outside the v14.7 adapter contract; no source was emitted."},
        });
    }
    for (const luraph::Diagnostic& diagnostic : analysis.diagnostics)
    {
        if (runtimeStructure && (diagnostic.code == "STRUCTURAL_ONLY" ||
            diagnostic.code == "VM_SEMANTICS_NOT_ATTEMPTED"))
            continue;
        report["diagnostics"].push_back({
            {"stage", "detect"},
            {"severity", std::string(luraph::toString(diagnostic.severity))},
            {"code", diagnostic.code},
            {"message", diagnostic.message},
            {"location", luraphRange(diagnostic.range)},
        });
    }
    if (guardHotspotDocument)
    {
        report["diagnostics"].insert(report["diagnostics"].begin(), json{
            {"stage", "guard_hotspot"},
            {"severity", "warning"},
            {"code", "luraph_payload_guard_not_cleared"},
            {"message", "The bounded offline run remained inside a repeated integrity/environment guard graph before entering the payload. Path-specific observational classifications were retained separately from unresolved static semantics."},
            {"details", {{"observed_steps", (*guardHotspotDocument)["observed_steps"]},
                {"observed_activations", (*guardHotspotDocument)["observed_activations"]},
                {"observed_prototypes", (*guardHotspotDocument)["observed_prototypes"]},
                {"observational_sites", runtimeObservationalSites},
                {"observational_semantic_lifted", runtimeObservationalLifted},
                {"observational_semantic_unresolved", runtimeObservationalUnresolved},
                {"guard_replay_sites_validated", runtimeGuardReplaySitesValidated},
                {"guard_replay_sites_divergent", runtimeGuardReplaySitesDivergent},
                {"unobserved_instructions", runtimeUnobservedInstructions},
                {"observational_path_specific", true}}},
        });
    }
    if (!inputParsed)
    {
        report["diagnostics"].push_back({
            {"stage", "parse"},
            {"severity", "warning"},
            {"code", "luraph_input_parse_failed"},
            {"message", "The recognized Luraph envelope did not parse as complete Luau; structural metadata remains available."},
            {"details", {{"error_count", parsed->result.errors.size()}}},
        });
    }
    const json envelope = luraphEnvelopeArtifact(analysis);
    writeJson(envelopePath, envelope);

    json stageNodes = json::array();
    json stageEdges = json::array();
    for (size_t index = 0; index < analysis.stages.size(); ++index)
    {
        const luraph::Stage& stage = analysis.stages[index];
        const std::string id = "stage_" + std::to_string(index + 1);
        stageNodes.push_back({
            {"id", id},
            {"kind", std::string(luraph::toString(stage.kind))},
            {"confidence", stage.confidence},
            {"range", luraphRange(stage.range)},
        });
        if (index > 0)
            stageEdges.push_back({{"from", "stage_" + std::to_string(index)}, {"to", id}, {"kind", "analysis_sequence"}});
    }
    json entryStates = json::array();
    if (parsedContainer)
    {
        for (size_t containerIndex = 0; containerIndex < analysis.containers.size(); ++containerIndex)
        {
            const luraph::ContainerAnalysis& container = analysis.containers[containerIndex];
            const luraph::vm::NormalizedContainer normalized = luraph::vm::normalizeContainer(container);
            if (!normalized.root_valid)
                continue;
            entryStates.push_back({
                {"container_index", containerIndex},
                {"prototype_wrapper_index", normalized.root_wrapper_index},
                {"prototype_metadata_index", *normalized.root_metadata_index},
                {"pc", 1},
            });
        }
    }
    json runtimePrototypeEntries = json::array();
    if (runtimeDecoded)
        for (const auto& [id, prototype] : runtimeStructure->prototypes)
            runtimePrototypeEntries.push_back({
                {"runtime_id", id},
                {"entry_pc", prototype.instructions.empty() ? json(nullptr) : json(prototype.instructions.begin()->first)},
                {"instruction_count", prototype.instructions.size()},
                {"complete", prototype.instructions.size() == prototype.declared_instruction_count},
            });
    writeJson(cfgPath, {
        {"version", 2},
        {"kind", "luraph-envelope-stage-graph"},
        {"scope", analysisScope},
        {"payload_cfg_recovered", false},
        {"root_entry_recovered", !entryStates.empty()},
        {"nodes", stageNodes},
        {"edges", stageEdges},
        {"entry_states", std::move(entryStates)},
        {"runtime_prototypes", std::move(runtimePrototypeEntries)},
        {"control_edges", json::array()},
        {"control_edges_recovered", false},
    });
    if (parsedContainer)
    {
        json prototypes = json::array();
        json constants = json::array();
        json normalizedContainers = json::array();
        for (size_t containerIndex = 0; containerIndex < analysis.containers.size(); ++containerIndex)
        {
            const luraph::ContainerAnalysis& container = analysis.containers[containerIndex];
            if (container.parse_status != luraph::ContainerParseStatus::Parsed)
                continue;
            const luraph::vm::NormalizedContainer normalized = luraph::vm::normalizeContainer(container);
            normalizedContainers.push_back({
                {"index", containerIndex},
                {"constant_pool_mode", normalized.constant_pool_mode},
                {"root_wrapper_index", normalized.root_wrapper_index},
                {"root_metadata_index", normalized.root_metadata_index ? json(*normalized.root_metadata_index) : json(nullptr)},
                {"root_valid", normalized.root_valid},
                {"entry_pc", normalized.root_valid ? json(1) : json(nullptr)},
            });
            for (const luraph::PrototypeMetadata& prototype : container.prototypes)
                prototypes.push_back(luraphPrototypeArtifact(
                    containerIndex,
                    prototype,
                    container.constants.size(),
                    container.prototypes.size()));
            for (const luraph::ConstantMetadata& constant : container.constants)
                constants.push_back(luraphConstantArtifact(containerIndex, constant));
        }
        writeJson(irPath, {
            {"version", 2},
            {"kind", "luraph-decoded-container-record-ir"},
            {"status", "instruction-lanes-normalized-not-semantically-lifted"},
            {"adapter", luraphAdapterName(analysis)},
            {"scope", "normalized-v14.7-instruction-lanes"},
            {"container_decoded", true},
            {"instructions_disassembled", true},
            {"opcode_values_recovered", true},
            {"operand_lanes_recovered", true},
            {"semantic_lifted", false},
            {"source_recovered", false},
            {"instruction_word_encoding", "signed-fold-integer"},
            {"containers", std::move(normalizedContainers)},
            {"prototypes", std::move(prototypes)},
            {"basic_blocks", json::array()},
        });
        writeJson(constantsPath, {
            {"version", 2},
            {"encoding", "luraph-v14.7-typed-constant-pool"},
            {"container_decoded", true},
            {"payload_decoded", false},
            {"constant_count", constants.size()},
            {"value_bytes_retained", true},
            {"values_available", true},
            {"constants", std::move(constants)},
            {"opaque_blob_candidates", envelope["blobs"]},
        });
    }
    else if (runtimeSemanticDocument)
    {
        json primaryRuntimeIr = luraphCompactObservedSemanticArtifact(*runtimeSemanticDocument);
        primaryRuntimeIr["status"] = runtimeSemanticLifted == runtimeStructure->instruction_count
            ? "runtime-prototypes-semantically-classified"
            : "bounded-observed-effects-static-semantics-incomplete";
        primaryRuntimeIr["adapter"] = luraphAdapterName(analysis);
        primaryRuntimeIr["scope"] = "bounded-observed-effects";
        primaryRuntimeIr["container_decoded"] = decodedContainer;
        primaryRuntimeIr["prototype_count"] = runtimeStructure->prototypes.size();
        primaryRuntimeIr["static_serialized_schema_recovered"] = false;
        primaryRuntimeIr["runtime_prototype_schema_recovered"] = true;
        primaryRuntimeIr["source_recovered"] = false;
        writeJson(irPath, primaryRuntimeIr);
        writeJson(constantsPath, {
            {"version", 2},
            {"encoding", "runtime-decoded-lane-values"},
            {"container_decoded", decodedContainer},
            {"payload_decoded", true},
            {"values_embedded_in", irPath.filename().string()},
            {"standalone_constant_pool_recovered", false},
            {"constants", json::array()},
            {"opaque_blob_candidates", envelope["blobs"]},
        });
    }
    else
    {
        writeJson(irPath, {
            {"version", 2},
            {"kind", "typed-semantic-ir"},
            {"status", "unavailable"},
            {"adapter", luraphAdapterName(analysis)},
            {"reason", decodedContainer ? "container_schema_unavailable" : "payload_not_decoded"},
            {"container_decoded", decodedContainer},
            {"prototypes", json::array()},
            {"basic_blocks", json::array()},
        });
        writeJson(constantsPath, {
            {"version", 2},
            {"encoding", decodedContainer ? "lph-dollar-decoded-container-schema-unknown" : "unknown-luraph-v14.7-carrier"},
            {"container_decoded", decodedContainer},
            {"payload_decoded", false},
            {"constants", json::array()},
            {"opaque_blob_candidates", envelope["blobs"]},
        });
    }
    writeJson(mapPath, {
        {"version", 2},
        {"output", nullptr},
        {"verified", false},
        {"statements", json::array()},
        {"reason", "no_source_recovered"},
    });

    std::ostringstream structuralReport;
    const auto appendLane = [&](std::string_view name, const luraph::vm::OperandLane& lane) {
        structuralReport << name << '=' << lane.base_value;
        if (lane.side_reference.kind != luraph::vm::ReferenceKind::None)
        {
            structuralReport << '<' << luraph::vm::toString(lane.side_reference.kind) << '#'
                             << lane.side_reference.wrapper_index;
            if (!lane.side_reference.valid)
                structuralReport << ":invalid";
            structuralReport << '>';
        }
    };
    if (parsedContainer)
    {
        structuralReport << "Alex native Luraph v14.7 decoded-container disassembly\n";
        structuralReport << "scope=normalized-v14.7-instruction-lanes container_decoded=true semantic_lifted=false source_recovered=false\n";
        structuralReport << "containers=" << analysis.container_metrics.parsed_count << " prototypes=" << analysis.container_metrics.prototype_count
                         << " instructions=" << retainedInstructions << " constants=" << analysis.container_metrics.constant_count << "\n\n";
        structuralReport << "Each row exposes the runtime opcode and D/G/p lanes. Side references use one-based wrapper indexes; handler semantics remain unresolved.\n\n";
        for (size_t containerIndex = 0; containerIndex < analysis.containers.size(); ++containerIndex)
        {
            const luraph::ContainerAnalysis& container = analysis.containers[containerIndex];
            if (container.parse_status != luraph::ContainerParseStatus::Parsed)
                continue;
            structuralReport << "container " << containerIndex << " carrier=" << container.carrier_index << " decoded_bytes=" << container.decoded_bytes
                             << " sha256=" << container.decoded_sha256 << " pool_mode=" << static_cast<unsigned int>(container.constant_pool_mode)
                             << " root_wrapper_index=" << container.root_selector << "\n";
            for (const luraph::PrototypeMetadata& prototype : container.prototypes)
            {
                structuralReport << "  prototype " << prototype.index << " wrapper_index=" << prototype.index + 1 << " meta=" << prototype.meta
                                 << " instructions=" << prototype.instructions.size() << " descriptors=" << prototype.descriptor_count
                                 << " register_capacity=" << prototype.final_value << " entry_pc=1 bytes=" << prototype.span.begin
                                 << ".." << prototype.span.end << "\n";
                for (const luraph::InstructionMetadata& instruction : prototype.instructions)
                {
                    const luraph::vm::NormalizedInstruction normalized = luraph::vm::normalizeInstruction(
                        instruction,
                        container.constants.size(),
                        container.prototypes.size());
                    structuralReport << "    pc=" << std::setw(6) << std::setfill('0') << normalized.pc << std::setfill(' ')
                                     << " opcode=" << normalized.opcode << ' ';
                    appendLane("D", normalized.D);
                    structuralReport << ' ';
                    appendLane("G", normalized.G);
                    structuralReport << ' ';
                    appendLane("p", normalized.p);
                    structuralReport << " raw=[";
                    for (size_t word = 0; word < instruction.words.size(); ++word)
                    {
                        if (word > 0)
                            structuralReport << ", ";
                        structuralReport << instruction.words[word].value;
                    }
                    structuralReport << "] bytes=" << instruction.span.begin << ".." << instruction.span.end << "\n";
                }
            }
            structuralReport << "  trailer_bytes=" << container.trailer_bytes.size() << " bytes=" << container.trailer_span.begin << ".."
                             << container.trailer_span.end << "\n\n";
        }
    }
    else if (runtimeDecoded)
    {
        structuralReport << "Alex native LuaAuth/Luraph runtime-decoded prototype disassembly\n";
        structuralReport << "scope=runtime-decoded-prototype-lanes container_decoded="
                         << (decodedContainer ? "true" : "false")
                         << " static_schema_parsed=false runtime_schema_recovered=true semantic_lifted="
                         << (runtimeSemanticLifted == runtimeStructure->instruction_count ? "true" : "false")
                         << " source_recovered=false\n";
        structuralReport << "prototypes=" << runtimeStructure->prototypes.size()
                         << " instructions=" << runtimeStructure->instruction_count
                         << " malformed_rows=" << runtimeStructure->malformed_rows
                         << " complete=" << (runtimeStructure->complete ? "true" : "false") << "\n\n";
        structuralReport << "Each row is emitted from the protected runtime's own deserialized prototype objects. "
                            "Opcode numbers are randomized and remain semantic labels until their handlers are classified.\n\n";
        for (const auto& [id, prototype] : runtimeStructure->prototypes)
        {
            structuralReport << "prototype " << id
                             << " instructions=" << prototype.instructions.size()
                             << '/' << prototype.declared_instruction_count << " lanes=[";
            for (size_t lane = 0; lane < prototype.lane_names.size(); ++lane)
            {
                if (lane > 0)
                    structuralReport << ',';
                structuralReport << prototype.lane_names[lane];
            }
            structuralReport << "]\n";
            for (const auto& [pc, instruction] : prototype.instructions)
                structuralReport << "  pc=" << std::setw(6) << std::setfill('0') << pc << std::setfill(' ')
                                 << " opcode=" << instruction.value("opcode", int64_t(-1))
                                 << " lanes=" << instruction.value("lanes", json::object()).dump() << "\n";
            structuralReport << "\n";
        }
    }
    else if (decodedContainer)
    {
        structuralReport << "Alex native LuaAuth/Luraph LPH$ decoded carrier\n";
        structuralReport << "scope=decoded-carrier container_decoded=true schema_parsed=false source_recovered=false\n";
        for (size_t containerIndex = 0; containerIndex < analysis.containers.size(); ++containerIndex)
        {
            const luraph::ContainerAnalysis& container = analysis.containers[containerIndex];
            if (container.decode_status != luraph::ContainerDecodeStatus::Decoded)
                continue;
            structuralReport << "container " << containerIndex << " marker=" << static_cast<char>(container.marker)
                             << " decoded_bytes=" << container.decoded_bytes << " sha256=" << container.decoded_sha256
                             << " radix85_groups=" << container.radix85_group_count
                             << " zero_groups=" << container.radix85_zero_group_count << "\n";
        }
        structuralReport << "\nThe exact binary container is available in decoded_lph_container.bin. "
                            "Prototype and instruction rows are withheld until this version's randomized record schema is recovered.\n";
    }
    else
    {
        structuralReport << "Alex native Luraph v14.7 bounded structural analysis\n";
        structuralReport << "scope=source-envelope-only payload_decoded=false source_recovered=false\n";
        structuralReport << "confidence=" << analysis.confidence.score << " version="
                         << (analysis.banner.version.empty() ? "unknown" : analysis.banner.version) << "\n\n";
        structuralReport << "No VM instruction disassembly was produced. Identified envelope stages:\n";
        for (const luraph::Stage& stage : analysis.stages)
        {
            structuralReport << "- " << luraph::toString(stage.kind) << " confidence=" << stage.confidence;
            if (stage.range)
                structuralReport << " bytes=" << stage.range->begin << ".." << stage.range->end;
            structuralReport << "\n";
        }
    }
    writeFile(disassemblyPath, structuralReport.str());

    json graphNodes = json::array();
    graphNodes.push_back({
        {"id", sha256(source)},
        {"kind", "luau_source"},
        {"bytes", source.size()},
        {"path", "input.luau"},
        {"provenance", "input"},
        {"source_bearing", true},
    });
    graphNodes.push_back(artifactNode(options.output_dir, envelopePath, "json", "luraph_envelope_scan", false));
    graphNodes.push_back(artifactNode(options.output_dir, cfgPath, "json", "luraph_stage_inference", false));
    graphNodes.push_back(artifactNode(options.output_dir, irPath, "json",
        parsedContainer ? "luraph_raw_instruction_records" :
            runtimeDecoded ? "luraph_runtime_decoded_instruction_ir" : "unavailable_payload_ir", false));
    const json sourceNodeId = graphNodes[0]["id"];
    const json envelopeNodeId = graphNodes[1]["id"];
    const json cfgNodeId = graphNodes[2]["id"];
    const json irNodeId = graphNodes[3]["id"];
    json graphEdges = json::array({
        {{"from", sourceNodeId}, {"to", envelopeNodeId}, {"relation", "bounded_structural_scan"}},
        {{"from", envelopeNodeId}, {"to", cfgNodeId}, {"relation", "stage_inference"}},
    });
    if (decodedContainerWritten)
    {
        json decodedNode = artifactNode(options.output_dir, decodedContainerPath, "binary", "lph_dollar_radix85_decode", false);
        const json decodedId = decodedNode["id"];
        graphNodes.push_back(std::move(decodedNode));
        graphEdges.push_back({{"from", envelopeNodeId}, {"to", decodedId}, {"relation", "decoded_carrier_bytes"}});
    }
    if (runtimeDecoded)
    {
        json prototypesNode = artifactNode(
            options.output_dir, runtimePrototypesPath, "json", "luraph_runtime_decoded_prototypes", false);
        const json prototypesId = prototypesNode["id"];
        graphNodes.push_back(std::move(prototypesNode));
        graphEdges.push_back({{"from", envelopeNodeId}, {"to", prototypesId},
            {"relation", "protected_runtime_deserializer"}});

        json semanticNode = artifactNode(
            options.output_dir, runtimeSemanticPath, "json", "luraph_runtime_semantic_dispatch_ir", false);
        const json semanticId = semanticNode["id"];
        graphNodes.push_back(std::move(semanticNode));
        graphEdges.push_back({{"from", prototypesId}, {"to", semanticId},
            {"relation", "randomized_opcode_materialization"}});

        if (!parsedContainer)
        {
            json disassemblyNode = artifactNode(
                options.output_dir, disassemblyPath, "text", "luraph_runtime_prototype_disassembly", false);
            const json disassemblyId = disassemblyNode["id"];
            graphNodes.push_back(std::move(disassemblyNode));
            graphEdges.push_back({{"from", prototypesId}, {"to", disassemblyId},
                {"relation", "runtime_instruction_disassembly"}});
        }
    }
    if (parsedContainer)
    {
        json constantsNode = artifactNode(options.output_dir, constantsPath, "json", "luraph_constant_metadata", false);
        const json constantsId = constantsNode["id"];
        graphNodes.push_back(std::move(constantsNode));
        json disassemblyNode = artifactNode(options.output_dir, disassemblyPath, "text", "luraph_raw_disassembly", false);
        const json disassemblyId = disassemblyNode["id"];
        graphNodes.push_back(std::move(disassemblyNode));
        graphEdges.push_back({{"from", envelopeNodeId}, {"to", irNodeId}, {"relation", "decoded_container_records"}});
        graphEdges.push_back({{"from", envelopeNodeId}, {"to", constantsId}, {"relation", "decoded_constant_metadata"}});
        graphEdges.push_back({{"from", irNodeId}, {"to", disassemblyId}, {"relation", "raw_instruction_disassembly"}});
        if (fs::exists(readableLiftPath))
        {
            json readableNode = artifactNode(options.output_dir, readableLiftPath, "text", "luraph_plain_language_lift", false);
            const json readableId = readableNode["id"];
            graphNodes.push_back(std::move(readableNode));
            graphEdges.push_back({{"from", irNodeId}, {"to", readableId}, {"relation", "semantic_explanation"}});
        }
    }
    writeJson(graphPath, {
        {"version", 2},
        {"nodes", graphNodes},
        {"edges", std::move(graphEdges)},
    });

    if (parsedContainer)
    {
        report["coverage"] = {
            {"scope", analysisScope},
            {"source", {{"bytes", analysis.counts.source_bytes}, {"structural_scan_complete", analysis.complete}}},
            {"tokens", {{"scanned", analysis.counts.token_count}}},
            {"stages", {{"identified", analysis.stages.size()}, {"known", 6}}},
            {"blobs", {{"candidates", analysis.counts.encoded_blob_candidate_count}, {"tracked", analysis.blobs.size()},
                          {"decoded", analysis.static_decode.carrier_decoded_count}}},
            {"carriers", {{"candidates", analysis.static_decode.carrier_candidate_count}, {"attempted", analysis.static_decode.carrier_attempt_count},
                             {"decoded", analysis.static_decode.carrier_decoded_count}, {"failed", analysis.static_decode.carrier_failure_count},
                             {"skipped", analysis.static_decode.carrier_skipped_count}}},
            {"containers", {{"candidates", analysis.container_metrics.candidate_count}, {"attempted", analysis.container_metrics.attempt_count},
                               {"decoded", analysis.container_metrics.decoded_count}, {"parsed", analysis.container_metrics.parsed_count},
                               {"failed", analysis.container_metrics.failure_count}, {"decoded_bytes", analysis.container_metrics.decoded_bytes}}},
            {"prototypes", {{"total", analysis.container_metrics.prototype_count},
                               {"disassembled", analysis.container_metrics.prototype_count}, {"reconstructed", 0}}},
            {"blocks", {{"total", nullptr}, {"recovered", 0}, {"lifted", 0}}},
            {"instructions", {{"total", runtimeDecoded ? json(runtimeDeclaredInstructions) : json(analysis.container_metrics.instruction_count)},
                                 {"declared", runtimeDecoded ? json(runtimeDeclaredInstructions) : json(analysis.container_metrics.instruction_count)},
                                 {"observed", runtimeDecoded ? json(runtimeObservedInstructions) : json(retainedInstructions)},
                                 {"retained", runtimeDecoded ? json(runtimeObservedInstructions) : json(retainedInstructions)},
                                 {"disassembled", runtimeDecoded ? json(runtimeObservedInstructions) : json(retainedInstructions)}, {"lifted", 0}}},
            {"constants", {{"total", analysis.container_metrics.constant_count},
                              {"metadata_recovered", analysis.container_metrics.constant_count},
                              {"values_recovered", analysis.container_metrics.constant_count},
                              {"decoded", analysis.container_metrics.constant_count}}},
            {"payload_decoded", false},
            {"container_decoded", true},
            {"semantic_lifted", false},
            {"semantic_lifting_complete", false},
            {"opcode_handlers", {{"resolved", opcodeCatalog.resolved}, {"total", 256}, {"unique", opcodeCatalog.unique_handlers}}},
            {"runtime_decode", {{"available", runtimeStructure.has_value()},
                {"complete", runtimeStructure ? json(runtimeStructure->complete) : json(nullptr)},
                {"prototypes", runtimeStructure ? json(runtimeStructure->prototypes.size()) : json(0)},
                {"instructions", runtimeStructure ? json(runtimeStructure->instruction_count) : json(0)},
                {"observed_steps", runtimeStructure ? json(runtimeStructure->steps.size()) : json(0)},
                {"effect_classified", runtimeEffectClassified},
                {"trace_specialized_sites", runtimeTraceSpecialized},
                {"observed_effect_classified_sites", runtimeTraceEffects},
                {"observational_sites", runtimeObservationalSites},
                {"observational_semantic_lifted", runtimeObservationalLifted},
                {"observational_semantic_unresolved", runtimeObservationalUnresolved},
                {"guard_replay_sites_validated", runtimeGuardReplaySitesValidated},
                {"guard_replay_sites_divergent", runtimeGuardReplaySitesDivergent},
                {"unobserved_instructions", runtimeUnobservedInstructions},
                {"observational_operation_counts", runtimeObservationalOperationCounts},
                {"trace_specialized_is_path_specific", true},
                {"write_origin_evidence", runtimeWriteOriginEvidence},
                {"unresolved", runtimeUnresolved},
                {"semantic_lifted", runtimeSemanticLifted},
                {"semantic_unresolved", runtimeDecoded ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(0)},
                {"semantic_declared_unresolved", runtimeDecoded ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(0)},
                {"semantic_lifting_complete", runtimeDecoded && runtimeSemanticLifted == runtimeDeclaredInstructions}}},
            {"static_container_instruction_records", retainedInstructions},
            {"unresolved_operations", runtimeDecoded
                ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(retainedInstructions)},
        };
    }
    else
    {
        report["coverage"] = {
            {"scope", analysisScope},
            {"source", {{"bytes", analysis.counts.source_bytes}, {"structural_scan_complete", analysis.complete}}},
            {"tokens", {{"scanned", analysis.counts.token_count}}},
            {"stages", {{"identified", analysis.stages.size()}, {"known", 6}}},
            {"blobs", {{"candidates", analysis.counts.encoded_blob_candidate_count}, {"tracked", analysis.blobs.size()},
                {"decoded", analysis.static_decode.carrier_decoded_count}}},
            {"containers", {{"candidates", analysis.container_metrics.candidate_count}, {"attempted", analysis.container_metrics.attempt_count},
                {"decoded", analysis.container_metrics.decoded_count}, {"parsed", analysis.container_metrics.parsed_count},
                {"decoded_bytes", analysis.container_metrics.decoded_bytes}}},
            {"prototypes", {{"total", runtimeDecoded ? json(runtimeStructure->prototypes.size()) : json(nullptr)},
                {"disassembled", runtimeDecoded ? json(runtimeStructure->prototypes.size()) : json(0)},
                {"reconstructed", 0}}},
            {"blocks", {{"total", nullptr}, {"recovered", 0}, {"lifted", 0}}},
            {"instructions", {{"total", runtimeDecoded ? json(runtimeDeclaredInstructions) : json(nullptr)},
                {"declared", runtimeDecoded ? json(runtimeDeclaredInstructions) : json(nullptr)},
                {"observed", runtimeDecoded ? json(runtimeObservedInstructions) : json(0)},
                {"retained", runtimeDecoded ? json(runtimeObservedInstructions) : json(0)},
                {"disassembled", runtimeDecoded ? json(runtimeObservedInstructions) : json(0)},
                {"lifted", runtimeSemanticLifted}}},
            {"constants", {{"total", nullptr}, {"decoded", 0}}},
            {"payload_decoded", runtimeDecoded},
            {"container_decoded", decodedContainer},
            {"runtime_prototype_schema_recovered", runtimeDecoded},
            {"runtime_prototype_schema_complete", runtimeSchemaComplete},
            {"static_serialized_schema_recovered", false},
            {"semantic_lifted", runtimeDecoded && runtimeSemanticLifted == runtimeDeclaredInstructions},
            {"semantic_lifting_complete", runtimeDecoded && runtimeSemanticLifted == runtimeDeclaredInstructions},
            {"opcode_handlers", {{"resolved", opcodeCatalog.resolved}, {"total", 256}, {"unique", opcodeCatalog.unique_handlers}}},
            {"runtime_decode", {{"available", runtimeStructure.has_value()},
                {"complete", runtimeStructure ? json(runtimeStructure->complete) : json(nullptr)},
                {"prototypes", runtimeStructure ? json(runtimeStructure->prototypes.size()) : json(0)},
                {"instructions", runtimeStructure ? json(runtimeStructure->instruction_count) : json(0)},
                {"observed_steps", runtimeStructure ? json(runtimeStructure->steps.size()) : json(0)},
                {"effect_classified", runtimeEffectClassified},
                {"trace_specialized_sites", runtimeTraceSpecialized},
                {"observed_effect_classified_sites", runtimeTraceEffects},
                {"observational_sites", runtimeObservationalSites},
                {"observational_semantic_lifted", runtimeObservationalLifted},
                {"observational_semantic_unresolved", runtimeObservationalUnresolved},
                {"guard_replay_sites_validated", runtimeGuardReplaySitesValidated},
                {"guard_replay_sites_divergent", runtimeGuardReplaySitesDivergent},
                {"unobserved_instructions", runtimeUnobservedInstructions},
                {"observational_operation_counts", runtimeObservationalOperationCounts},
                {"trace_specialized_is_path_specific", true},
                {"write_origin_evidence", runtimeWriteOriginEvidence},
                {"unresolved", runtimeUnresolved},
                {"semantic_lifted", runtimeSemanticLifted},
                {"semantic_unresolved", runtimeDecoded ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(0)},
                {"semantic_declared_unresolved", runtimeDecoded ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(0)},
                {"semantic_lifting_complete", runtimeDecoded && runtimeSemanticLifted == runtimeDeclaredInstructions}}},
            {"unresolved_operations", runtimeDecoded
                ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(nullptr)},
        };
    }
    if (runtimeSemanticDocument)
        report["coverage"]["semantic_coverage_partition"] =
            runtimeSemanticDocument->value("semantic_coverage_partition", json::object());
    else if (parsedContainer)
    {
        const size_t total = analysis.container_metrics.instruction_count;
        report["coverage"]["semantic_coverage_partition"] = {
            {"available", total > 0},
            {"scope", "static-decoded-container-instruction-sites"},
            {"total", total},
            {"declared_total", total},
            {"materialized_total", retainedInstructions},
            {"static_semantic", 0},
            {"runtime_validated_observational_semantic", 0},
            {"trace_evidence_only", 0},
            {"unresolved", total},
            {"partition_sum", total},
            {"disjoint", true},
            {"partition_complete", true},
            {"semantic_coverage_complete", false},
            {"runtime_validated_observational_semantic_is_path_specific", true},
            {"trace_evidence_only_is_semantic", false},
        };
    }
    else
        report["coverage"]["semantic_coverage_partition"] = {
            {"available", false},
            {"scope", "instruction-universe-unavailable"},
            {"total", nullptr},
            {"declared_total", nullptr},
            {"materialized_total", 0},
            {"static_semantic", 0},
            {"runtime_validated_observational_semantic", 0},
            {"trace_evidence_only", 0},
            {"unresolved", nullptr},
            {"partition_sum", nullptr},
            {"disjoint", true},
            {"partition_complete", false},
            {"semantic_coverage_complete", false},
            {"runtime_validated_observational_semantic_is_path_specific", true},
            {"trace_evidence_only_is_semantic", false},
        };
    report["coverage"]["opcode8_calls"] = runtimeOpcode8CallCoverage;
    report["coverage"]["opcode28_index_reads"] = runtimeOpcode28IndexReadCoverage;
    report["coverage"]["opcode89_range_clears"] = runtimeOpcode89RangeClearCoverage;
    const bool staticContainerCountsAvailable = decodedContainer &&
        (analysis.container_metrics.prototype_count > 0 || analysis.container_metrics.instruction_count > 0 ||
            analysis.container_metrics.constant_count > 0 || analysis.container_metrics.descriptor_count > 0);
    report["coverage"]["static_container"] = staticContainerCountsAvailable ? json({
        {"available", true},
        {"scope", "full-decoded-container-structural-scan"},
        {"container_decoded", true},
        {"schema_parsed", parsedContainer},
        {"structural_counts_recovered", true},
        {"prototypes", analysis.container_metrics.prototype_count},
        {"instructions", analysis.container_metrics.instruction_count},
        {"constants", analysis.container_metrics.constant_count},
        {"descriptors", analysis.container_metrics.descriptor_count},
        {"trailer_bytes", analysis.container_metrics.trailer_bytes},
        {"semantic_lifted", false},
        {"source_recovered", false},
    }) : json({{"available", false}});
    report["coverage"]["runtime_reachable"] = runtimeDecoded ? json({
        {"available", true},
        {"scope", "bounded-runtime-decoded-prototypes"},
        {"complete", runtimeSchemaComplete},
        {"prototypes", runtimeStructure->prototypes.size()},
        {"instructions", {
            {"declared", runtimeDeclaredInstructions},
            {"observed", runtimeObservedInstructions},
            {"observational_sites", runtimeObservationalSites},
            {"unobserved", runtimeUnobservedInstructions},
        }},
        {"static_semantic_lifted", runtimeSemanticLifted},
        {"static_semantic_unresolved", runtimeDeclaredInstructions - runtimeSemanticLifted},
        {"observational_semantic_lifted", runtimeObservationalLifted},
        {"observational_semantic_unresolved", runtimeObservationalUnresolved},
        {"guard_replay_sites_validated", runtimeGuardReplaySitesValidated},
        {"guard_replay_sites_divergent", runtimeGuardReplaySitesDivergent},
        {"observational_path_specific", true},
        {"source_recovered", false},
    }) : json({{"available", false}});
    report["coverage"]["payload_closure"] = payloadClosureMetrics ? json({
        {"available", true},
        {"activations", payloadClosureMetrics->activations},
        {"activated_prototypes", payloadClosureMetrics->activated_prototypes},
        {"closure_expanded_prototypes", payloadClosureMetrics->closure_expanded_prototypes},
        {"closure_expansion_edges", payloadClosureMetrics->closure_expansion_edges},
        {"prototypes", payloadClosureMetrics->prototypes},
        {"instructions", payloadClosureMetrics->instructions},
        {"static_semantic_lifted", payloadClosureMetrics->statically_lifted},
        {"static_semantic_unresolved", payloadClosureMetrics->instructions - payloadClosureMetrics->statically_lifted},
        {"source_semantic_instructions", payloadClosureMetrics->source_semantic},
        {"protector_internal_instructions", payloadClosureMetrics->protector_internal},
        {"unresolved_observed_instructions", payloadClosureMetrics->unresolved_observed},
        {"observed_path_coverage_complete", payloadClosureMetrics->instructions > 0 &&
            payloadClosureMetrics->statically_lifted + payloadClosureMetrics->unresolved_observed == payloadClosureMetrics->instructions},
        {"observed_steps", payloadClosureMetrics->observed_steps},
        {"observed_returns", payloadClosureMetrics->observed_returns},
    }) : json({{"available", false}});
    report["coverage"]["payload_root"] = payloadRoot ? json({
        {"available", true},
        {"evidence", payloadRoot->evidence},
        {"bootstrap_activation", payloadRoot->bootstrap_activation},
        {"bootstrap_prototype", payloadRoot->bootstrap_prototype},
        {"payload_activation", payloadRoot->payload_activation},
        {"payload_prototype", payloadRoot->payload_prototype},
        {"caller_pc", payloadRoot->caller_pc},
        {"caller_opcode", payloadRoot->caller_opcode},
        {"bootstrap_return_vm_count", payloadRoot->bootstrap_return_vm_count > 0
            ? json(payloadRoot->bootstrap_return_vm_count) : json(nullptr)},
        {"payload_entry_vm_count", payloadRoot->payload_entry_vm_count > 0
            ? json(payloadRoot->payload_entry_vm_count) : json(nullptr)},
    }) : json({{"available", false}});
    report["coverage"]["payload_cfg"] = payloadCfgDocument ? json({
        {"available", true},
        {"prototypes", payloadCfgDocument->value("prototype_count", size_t(0))},
        {"blocks", payloadCfgDocument->value("block_count", size_t(0))},
        {"reachable_blocks", payloadCfgDocument->value("reachable_blocks", size_t(0))},
        {"reachable_instructions", payloadCfgDocument->value("reachable_instructions", size_t(0))},
        {"edges", payloadCfgDocument->value("edge_count", size_t(0))},
        {"cyclic_regions", payloadCfgDocument->value("cyclic_regions", size_t(0))},
        {"irreducible_regions", payloadCfgDocument->value("irreducible_regions", size_t(0))},
        {"invalid_edges", payloadCfgDocument->value("invalid_edges", size_t(0))},
        {"reachable_invalid_edges", payloadCfgDocument->value("reachable_invalid_edges", size_t(0))},
        {"observed_edge_sites", payloadCfgDocument->value("observed_edge_sites", size_t(0))},
    }) : json({{"available", false}});
    report["coverage"]["observed_cfg"] = observedCfgDocument ? json({
        {"available", true},
        {"complete", false},
        {"scope", "bounded-offline-execution-window"},
        {"prototypes", observedCfgDocument->value("prototype_count", size_t(0))},
        {"nodes", observedCfgDocument->value("node_count", size_t(0))},
        {"edges", observedCfgDocument->value("edge_count", size_t(0))},
        {"observed_steps", observedCfgDocument->value("observed_step_count", size_t(0))},
        {"invalid_edge_targets", observedCfgDocument->value("invalid_edge_targets", size_t(0))},
    }) : json({{"available", false}});
    report["coverage"]["reachable_payload"] = payloadReachableIrDocument ? json({
        {"available", true},
        {"prototypes", payloadReachableIrDocument->value("prototype_count", size_t(0))},
        {"instructions", payloadReachableIrDocument->value("instruction_count", size_t(0))},
        {"source_semantic_instructions", payloadReachableIrDocument->value("source_semantic_instructions", size_t(0))},
        {"protector_internal_instructions", payloadReachableIrDocument->value("protector_internal_instructions", size_t(0))},
    }) : json({{"available", false}});
    report["coverage"]["guard_hotspot"] = guardHotspotDocument ? json({
        {"available", true},
        {"classification", (*guardHotspotDocument)["classification"]},
        {"classification_is_inference", (*guardHotspotDocument)["classification_is_inference"]},
        {"first_vm_count", (*guardHotspotDocument)["first_vm_count"]},
        {"last_vm_count", (*guardHotspotDocument)["last_vm_count"]},
        {"observed_steps", (*guardHotspotDocument)["observed_steps"]},
        {"observed_activations", (*guardHotspotDocument)["observed_activations"]},
        {"observed_prototypes", (*guardHotspotDocument)["observed_prototypes"]},
        {"semantic_lifted", runtimeSemanticLifted},
        {"semantic_unresolved", runtimeDecoded
            ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(0)},
        {"observational_sites", runtimeObservationalSites},
        {"observational_semantic_lifted", runtimeObservationalLifted},
        {"observational_semantic_unresolved", runtimeObservationalUnresolved},
        {"guard_replay_sites_validated", runtimeGuardReplaySitesValidated},
        {"guard_replay_sites_divergent", runtimeGuardReplaySitesDivergent},
        {"unobserved_instructions", runtimeUnobservedInstructions},
        {"observational_operation_counts", runtimeObservationalOperationCounts},
        {"observational_path_specific", true},
        {"write_origin_evidence", runtimeWriteOriginEvidence},
    }) : json({{"available", false}});
    report["verification"] = {
        {"input_parsed", inputParsed},
        {"compiled", false},
        {"source_claim_accepted", false},
        {"output", {{"available", false}, {"compiled", false}}},
        {"runtime", {{"attempted", false}, {"equivalent", nullptr}, {"reason", "no reconstructed source"}}},
        {"candidate", {{"available", observedCandidateCompiled}, {"compiled", observedCandidateCompiled},
            {"source_claim", false}, {"differentially_verified", false}}},
        {"semantic_candidate", {{"available", semanticCandidate.has_value()}, {"compiled", semanticCandidateCompiled},
            {"fully_rendered", semanticCandidate ? json(semanticCandidate->fully_rendered()) : json(nullptr)},
            {"source_claim", false}, {"differentially_verified", false}}},
        {"semantic_readable_candidate", {{"available", semanticReadableCandidateCompiled},
            {"compiled", semanticReadableCandidateCompiled}, {"source_claim", false},
            {"differentially_verified", false}}},
    };
    if (parsedContainer)
    {
        report["verification"]["decoded_container_records_available"] = true;
        report["verification"]["instruction_records_disassembled"] = true;
        report["verification"]["semantic_lift_verified"] = false;
    }
    else if (runtimeDecoded)
    {
        report["verification"]["decoded_container_records_available"] = false;
        report["verification"]["runtime_prototype_records_available"] = true;
        report["verification"]["instruction_records_disassembled"] = true;
        report["verification"]["runtime_prototype_decode_complete"] = runtimeStructure->complete;
        report["verification"]["semantic_lift_verified"] = false;
    }
    if (payloadCfgDocument)
        writeJson(cfgPath, *payloadCfgDocument);
    else if (observedCfgDocument)
        writeJson(cfgPath, *observedCfgDocument);
    if (payloadReachableIrDocument)
        writeJson(irPath, *payloadReachableIrDocument);
    report["artifacts"] = {
        {"source", nullptr},
        {"candidate", observedCandidateCompiled ? json(payloadCandidatePath.filename().string()) : json(nullptr)},
        {"candidate_provenance", observedCandidateCompiled
            ? json(payloadCandidateProvenancePath.filename().string()) : json(nullptr)},
        {"semantic_candidate", semanticCandidateCompiled
            ? json(semanticCandidatePath.filename().string()) : json(nullptr)},
        {"semantic_readable_candidate", semanticReadableCandidateCompiled
            ? json(semanticReadablePath.filename().string()) : json(nullptr)},
        {"semantic_candidate_map", semanticCandidate
            ? json(semanticCandidateMapPath.filename().string()) : json(nullptr)},
        {"internal_state_machine", nullptr},
        {"envelope_analysis", envelopePath.filename().string()},
        {"decoded_container", decodedContainerWritten ? json(decodedContainerPath.filename().string()) : json(nullptr)},
        {"disassembly", disassemblyPath.filename().string()},
        {"semantic_ir", irPath.filename().string()},
        {"cfg", cfgPath.filename().string()},
        {"constants", constantsPath.filename().string()},
        {"graph", graphPath.filename().string()},
        {"reconstruction_map", mapPath.filename().string()},
        {"trace_probe", traceProbeCompiled ? json(traceProbePath.filename().string()) : json(nullptr)},
        {"opcode_handlers", opcodeCatalog.available ? json(opcodeHandlersPath.filename().string()) : json(nullptr)},
        {"structure_probe", structureProbeCompiled ? json(structureProbePath.filename().string()) : json(nullptr)},
        {"runtime_prototypes", runtimeStructure && !runtimeStructure->prototypes.empty()
            ? json(runtimePrototypesPath.filename().string()) : json(nullptr)},
        {"prototype_correspondence", prototypeCorrespondenceDocument
            ? json(prototypeCorrespondencePath.filename().string()) : json(nullptr)},
        {"runtime_semantic_ir", runtimeStructure && !runtimeStructure->prototypes.empty()
            ? json(runtimeSemanticPath.filename().string()) : json(nullptr)},
        {"payload_closure_ir", payloadClosureMetrics
            ? json(payloadClosurePath.filename().string()) : json(nullptr)},
        {"payload_reachable_ir", payloadReachableIrDocument
            ? json(payloadReachableIrPath.filename().string()) : json(nullptr)},
        {"readable_lift", fs::exists(readableLiftPath)
            ? json(readableLiftPath.filename().string()) : json(nullptr)},
        {"guard_hotspot", guardHotspotDocument
            ? json(guardHotspotPath.filename().string()) : json(nullptr)},
    };

    if (traceRefinementRequired)
        publishProgress(options, "trace_refine", "running", "Capturing the complete Luraph payload activation around confirmed calls",
            {{"trace_probe", traceProbePath.filename().string()}});
    publishProgress(options, "detect", "done",
        analysis.luaauth_launcher.present ? "LuaAuth-wrapped LPH$ Luraph envelope identified" : "Luraph v14.7 envelope identified",
        {{"adapter", luraphAdapterName(analysis)}, {"confidence", analysis.confidence.score}, {"version_supported", analysis.version_supported},
            {"launcher_removed", analysis.luaauth_launcher.metadata_removed_from_body}});
    for (const luraph::Stage& stage : analysis.stages)
        publishProgress(options, std::string("luraph_") + std::string(luraph::toString(stage.kind)), "done", stage.summary,
            {{"confidence", stage.confidence}, {"scope", "source-envelope"}});
    if (parsedContainer || runtimeDecoded)
    {
        publishProgress(options, "decode", "done",
            parsedContainer ? "Luraph LPH& container framing decoded and parsed"
                : "Luraph LPH$ carrier and runtime prototype objects decoded",
            {{"containers_parsed", analysis.container_metrics.parsed_count}, {"decoded_bytes", analysis.container_metrics.decoded_bytes},
                {"runtime_schema_recovered", runtimeDecoded}, {"payload_semantics_decoded", false}, {"source_emitted", false}});
        if (!parsedContainer)
            publishProgress(options, "container_schema", "done",
                "Static LPH$ tags remain randomized; the runtime deserializer supplied the prototype schema",
                {{"static_schema_parsed", false}, {"runtime_schema_recovered", true},
                    {"prototypes", runtimeStructure->prototypes.size()}, {"instructions", runtimeStructure->instruction_count}});
        publishProgress(options, "disassemble", "done",
            parsedContainer ? "Raw Luraph prototype instruction words disassembled"
                : "Runtime-decoded Luraph prototype lanes disassembled",
            {{"prototypes", runtimeDecoded ? json(runtimeStructure->prototypes.size()) : json(analysis.container_metrics.prototype_count)},
                {"instructions", runtimeDecoded ? json(runtimeStructure->instruction_count) : json(retainedInstructions)},
                {"semantic_lifted", false}});
        const bool reachedSemanticsComplete = runtimeSchemaComplete &&
            runtimeSemanticLifted == runtimeDeclaredInstructions;
        publishProgress(options, "lift", reachedSemanticsComplete ? "done" : "failed",
            reachedSemanticsComplete
                ? "Every instruction in the reached Luraph runtime prototypes was semantically classified"
                : "Decoded Luraph instructions still need randomized opcode-handler semantics",
            {{"semantic_lifted", runtimeSemanticLifted},
                {"semantic_unresolved", runtimeDecoded
                    ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(retainedInstructions)},
                {"observational_sites", runtimeObservationalSites},
                {"observational_semantic_lifted", runtimeObservationalLifted},
                {"observational_semantic_unresolved", runtimeObservationalUnresolved},
                {"unobserved_instructions", runtimeUnobservedInstructions},
                {"observational_operation_counts", runtimeObservationalOperationCounts},
                {"observational_path_specific", true},
                {"write_origin_evidence", runtimeWriteOriginEvidence},
                {"source_emitted", false}});
        if (guardHotspotDocument)
            publishProgress(options, "guard_hotspot", "failed", "Execution remained inside the pre-payload integrity and environment guard graph",
                {{"observed_steps", (*guardHotspotDocument)["observed_steps"]},
                    {"observed_activations", (*guardHotspotDocument)["observed_activations"]},
                    {"observed_prototypes", (*guardHotspotDocument)["observed_prototypes"]},
                    {"semantic_lifted", runtimeSemanticLifted},
                    {"semantic_unresolved", runtimeDecoded
                        ? json(runtimeDeclaredInstructions - runtimeSemanticLifted) : json(0)},
                    {"observational_sites", runtimeObservationalSites},
                    {"observational_semantic_lifted", runtimeObservationalLifted},
                    {"observational_semantic_unresolved", runtimeObservationalUnresolved},
                    {"unobserved_instructions", runtimeUnobservedInstructions},
                    {"observational_operation_counts", runtimeObservationalOperationCounts},
                    {"observational_path_specific", true},
                    {"write_origin_evidence", runtimeWriteOriginEvidence}});
        if (options.mode == "disassemble")
        {
            report["status"] = "disassembled";
            result.exit_code = 0;
        }
        else
        {
            report["status"] = "blocked";
            result.exit_code = 2;
        }
    }
    else if (decodedContainer)
    {
        publishProgress(options, "decode", "done", "Luraph LPH$ carrier decoded to exact binary container bytes",
            {{"containers_decoded", analysis.container_metrics.decoded_count}, {"decoded_bytes", analysis.container_metrics.decoded_bytes},
                {"artifact", decodedContainerWritten ? json(decodedContainerPath.filename().string()) : json(nullptr)},
                {"schema_parsed", false}, {"source_emitted", false}});
        publishProgress(options, "container_schema", "failed", "This LPH$ version's randomized record schema still needs to be recovered",
            {{"container_decoded", true}, {"source_emitted", false}});
        result.exit_code = 2;
    }
    else
    {
        publishProgress(options, "decode", "failed", "Payload decoding is not implemented for the bounded Luraph v14.7 adapter",
            {{"payload_decoded", false}, {"source_emitted", false}});
        result.exit_code = 2;
    }
    writeJson(reportPath, report);
    result.report = std::move(report);
    return result;
}

} // namespace

Result analyze(const Options& options)
{
    Result result;
    if (options.mode != "auto" && options.mode != "exact" && options.mode != "reconstruct" && options.mode != "disassemble")
        throw std::runtime_error("invalid analysis mode");

    fs::create_directories(options.output_dir);
    const fs::path reportPath = options.output_dir / "deobfuscation_report.json";
    const fs::path irPath = options.output_dir / "semantic_ir.json";
    const fs::path cfgPath = options.output_dir / "cfg.json";
    const fs::path constantsPath = options.output_dir / "constants.json";
    const fs::path disassemblyPath = options.output_dir / "vm_disassembly.txt";
    const fs::path mapPath = options.output_dir / "reconstruction_map.json";
    const fs::path graphPath = options.output_dir / "artifact_graph.json";
    const fs::path candidatePath = options.output_dir / "reconstructed_candidate.luau";
    const fs::path semanticCandidatePath = options.output_dir / "semantic_state_machine_candidate.luau";
    const fs::path internalStateMachinePath = options.output_dir / "internal_state_machine.luau";

    json report = {
        {"report_version", 2},
        {"tool", "alex-native-deobfuscator"},
        {"backend", "native-cpp"},
        {"adapter", "wearedevs-v1"},
        {"mode", options.mode},
        {"status", "blocked"},
        {"exact_source", false},
        {"diagnostics", json::array()},
        {"passes", json::array()},
        {"network_policy", "offline"},
        {"fallback_used", false},
    };

    auto writeEmptyArtifacts = [&]() {
        if (!fs::exists(irPath))
            writeJson(irPath, {{"version", 2}, {"status", "unavailable"}, {"prototypes", json::array()}, {"basic_blocks", json::array()}});
        if (!fs::exists(cfgPath))
            writeJson(cfgPath, {{"version", 2}, {"nodes", json::array()}, {"edges", json::array()}, {"entry_states", json::array()}});
        if (!fs::exists(constantsPath))
            writeJson(constantsPath, {{"version", 2}, {"constants", json::array()}});
        if (!fs::exists(disassemblyPath))
            writeFile(disassemblyPath, "No VM disassembly was produced.\n");
        if (!fs::exists(mapPath))
            writeJson(mapPath, {{"version", 2}, {"output", nullptr}, {"statements", json::array()}});
        if (!fs::exists(graphPath))
            writeJson(graphPath, {{"version", 2}, {"nodes", json::array()}, {"edges", json::array()}});
    };

    try
    {
        std::string source = readFile(options.input);
        if (source.empty())
            throw std::runtime_error("input is empty");
        if (source.size() > kMaxInputBytes)
        {
            report["diagnostics"].push_back({{"stage", "input"}, {"code", "source_too_large"}, {"message", "source exceeds the 1.5 MiB limit"}});
            result.exit_code = 2;
            report["input"] = {{"sha256", sha256(source)}, {"bytes", source.size()}};
            writeEmptyArtifacts();
            writeJson(reportPath, report);
            result.report = report;
            return result;
        }
        report["input"] = {{"sha256", sha256(source)}, {"bytes", source.size()}};

        const luraph::EnvelopeAnalysis luraphAnalysis = luraph::analyzeEnvelope(source);
        if (luraphAnalysis.family_detected)
            return finishLuraphAnalysis(options, source, luraphAnalysis, std::move(report));

        publishProgress(options, "detect", "running", "Parsing Luau and identifying the protection family",
            {{"input_bytes", source.size()}});
        auto parsed = parseSource(source);
        report["passes"].push_back({{"stage", "parse"}, {"ok", parsed->result.errors.empty()}, {"lines", parsed->result.lines}});
        if (!parsed->result.errors.empty())
        {
            for (const auto& error : parseErrors(parsed->result))
            {
                json diagnostic = error;
                diagnostic["stage"] = "parse";
                report["diagnostics"].push_back(std::move(diagnostic));
            }
            result.exit_code = 2;
            writeEmptyArtifacts();
            writeJson(reportPath, report);
            result.report = report;
            return result;
        }

        AstMetrics inputMetrics;
        parsed->result.root->visit(&inputMetrics);
        const bool header = source.find("https://wearedevs.net/obfuscator") != std::string::npos;
        static const std::regex outerIifePattern(R"(return\s*\(\s*function\s*\(\s*\.\.\.\s*\))");
        static const std::regex executorEnvironmentPattern(
            R"(\)\s*\(\s*getfenv\s+and\s+getfenv\s*\(\s*\)\s*or\s+_ENV\s*,\s*unpack\s+or\s+table\s*\[)");
        const bool outerIife = std::regex_search(source, outerIifePattern);
        const bool encodedStrings = source.find("\\0") != std::string::npos || source.find("\\1") != std::string::npos;
        const bool flattenedDispatcher = inputMetrics.whiles > 0 && inputMetrics.conditionals >= 8;
        const bool executorEnvironment = std::regex_search(source, executorEnvironmentPattern);
        AlphabetCollector detectionAlphabet;
        parsed->result.root->visit(&detectionAlphabet);
        const bool customAlphabet = detectionAlphabet.alphabet.size() == 64;
        const int initialScore = static_cast<int>(header) * 15 + static_cast<int>(outerIife) * 20 + static_cast<int>(encodedStrings) * 15 +
            static_cast<int>(flattenedDispatcher) * 20 + static_cast<int>(inputMetrics.functions >= 4) * 5 +
            static_cast<int>(executorEnvironment) * 15 + static_cast<int>(customAlphabet) * 10;
        const bool compactStructuralMatch = outerIife && customAlphabet && flattenedDispatcher &&
            inputMetrics.functions >= 8 && inputMetrics.whiles >= 2;
        const int detectionScore = compactStructuralMatch ? std::max(initialScore, 80) : initialScore;
        report["detection"] = {
            {"confidence", detectionScore / 100.0},
            {"evidence", {{"header", header}, {"vararg_iife", outerIife}, {"escaped_strings", encodedStrings},
                              {"flattened_dispatcher", flattenedDispatcher}, {"executor_environment_tail", executorEnvironment},
                              {"custom_alphabet", customAlphabet}, {"compact_structural_match", compactStructuralMatch},
                              {"while_count", inputMetrics.whiles},
                              {"conditional_count", inputMetrics.conditionals}, {"function_count", inputMetrics.functions}}},
        };
        report["passes"].push_back({{"stage", "detect"}, {"ok", detectionScore >= 75}, {"score", detectionScore}});
        publishProgress(options, "detect", detectionScore >= 75 ? "done" : "failed",
            detectionScore >= 75 ? "WeAreDevs v1 envelope identified" : "No supported protection family was identified",
            {{"confidence", detectionScore / 100.0}, {"functions", inputMetrics.functions}, {"while_loops", inputMetrics.whiles},
                {"flattened_dispatcher", flattenedDispatcher}, {"executor_environment_tail", executorEnvironment},
                {"custom_alphabet", customAlphabet}, {"compact_structural_match", compactStructuralMatch}});
        if (detectionScore < 75)
        {
            report["adapter"] = "unsupported";
            report["diagnostics"].push_back(
                {{"stage", "detect"}, {"code", "unsupported_family"}, {"message", "input does not match the WeAreDevs v1 structural envelope"}});
            result.exit_code = 4;
            writeEmptyArtifacts();
            writeJson(reportPath, report);
            result.report = report;
            return result;
        }

        publishProgress(options, "decode", "running", "Decoding the string table, permutation, and lookup layer");
        Envelope envelope = decodeEnvelope(source);
        const fs::path decodedPath = options.output_dir / "decoded_wrapper.luau";
        const fs::path traceProbePath = options.output_dir / "trace_probe.luau";
        const std::string stateTraceMarker = traceMarker(source);
        const std::string cellSnapshotMarker = snapshotMarker(source);
        writeFile(decodedPath, envelope.rewritten);
        writeFile(traceProbePath, buildTraceProbe(envelope.rewritten, stateTraceMarker));
        report["passes"].push_back({
            {"stage", "decode"},
            {"ok", true},
            {"encoded_strings", envelope.encoded.size()},
            {"constants", envelope.constants.size()},
            {"lookup_replacements", envelope.replacements},
            {"reversal_ranges", envelope.reversal_ranges.size()},
        });
        publishProgress(options, "decode", "done", "Encoded constants and wrapper lookups decoded",
            {{"encoded_strings", envelope.encoded.size()}, {"constants", envelope.constants.size()},
                {"lookup_replacements", envelope.replacements}, {"reversal_ranges", envelope.reversal_ranges.size()}});
        report["passes"].push_back({{"stage", "trace_probe"}, {"ok", true}, {"line_preserving", true}, {"network_policy", "offline"}});

        const std::vector<int64_t> tracedStates = options.trace ? parseTraceStates(*options.trace, stateTraceMarker) : std::vector<int64_t>{};
        const std::set<int64_t> observedStates(tracedStates.begin(), tracedStates.end());
        const RuntimeSnapshot runtimeSnapshot = options.trace ? parseRuntimeSnapshot(*options.trace, cellSnapshotMarker) : RuntimeSnapshot{};
        report["passes"].push_back({
            {"stage", "trace_seed"},
            {"ok", !tracedStates.empty()},
            {"events", tracedStates.size()},
            {"unique_states", observedStates.size()},
        });

        auto rewrittenAst = parseSource(envelope.rewritten);
        if (!rewrittenAst->result.errors.empty())
            throw std::runtime_error("lookup-rewritten wrapper did not parse");
        AstMetrics decodedMetrics;
        rewrittenAst->result.root->visit(&decodedMetrics);

        WhileCollector whiles;
        rewrittenAst->result.root->visit(&whiles);
        auto best = std::max_element(whiles.candidates.begin(), whiles.candidates.end(), [](const WhileCandidate& left, const WhileCandidate& right) {
            return left.conditionals < right.conditionals;
        });
        if (best == whiles.candidates.end() || best->conditionals < 8)
            throw std::runtime_error("flattened dispatcher was not found");

        SourceView sourceView(envelope.rewritten);
        Luau::AstExprFunction* dispatcherFunction = findContainingFunction(rewrittenAst->result.root, best->node, sourceView);
        if (!dispatcherFunction)
            throw std::runtime_error("dispatcher function ownership was not resolved");
        IndexedWriteCollector indexedWrites;
        dispatcherFunction->body->visit(&indexedWrites);
        DispatcherBindingCollector dispatcherBinding(dispatcherFunction);
        rewrittenAst->result.root->visit(&dispatcherBinding);
        if (!dispatcherBinding.assignment || !dispatcherBinding.local)
            throw std::runtime_error("dispatcher binding was not resolved");
        std::set<Luau::AstLocal*> closureFactories = findClosureFactories(dispatcherBinding.assignment, dispatcherBinding.local);
        if (closureFactories.empty())
            throw std::runtime_error("virtual closure factories were not resolved");

        PrototypeEntryCollector rootEntries(closureFactories, dispatcherFunction);
        rewrittenAst->result.root->visit(&rootEntries);
        if (rootEntries.entries.empty())
            throw std::runtime_error("root virtual prototype was not resolved");

        publishProgress(options, "cfg", "running", "Recovering dispatcher states, prototype entries, and control-flow edges",
            {{"root_entries", rootEntries.entries.size()}, {"observed_states", observedStates.size()}});
        std::set<int64_t> prototypeEntries = rootEntries.entries;
        std::map<int64_t, BlockInfo> blocks = recoverBlocks(*best, prototypeEntries, observedStates);
        std::set<int64_t> reachable = reachableStates(blocks, prototypeEntries);
        size_t entryRounds = 0;
        for (; entryRounds < 64; ++entryRounds)
        {
            PrototypeEntryCollector nestedEntries(closureFactories);
            for (int64_t state : reachable)
            {
                auto block = blocks.find(state);
                if (block != blocks.end())
                    block->second.body->visit(&nestedEntries);
            }
            size_t before = prototypeEntries.size();
            prototypeEntries.insert(nestedEntries.entries.begin(), nestedEntries.entries.end());
            if (prototypeEntries.size() == before)
                break;
            blocks = recoverBlocks(*best, prototypeEntries, observedStates);
            reachable = reachableStates(blocks, prototypeEntries);
        }
        if (entryRounds == 64)
            throw std::runtime_error("virtual prototype discovery did not converge");
        publishProgress(options, "cfg", "done", "Reachable VM control flow recovered",
            {{"states", blocks.size()}, {"reachable_states", reachable.size()}, {"prototype_entries", prototypeEntries.size()},
                {"entry_discovery_rounds", entryRounds}});

        PrototypeEntryCollector reachableCalls(closureFactories);
        for (int64_t state : reachable)
        {
            auto block = blocks.find(state);
            if (block != blocks.end())
                block->second.body->visit(&reachableCalls);
        }
        const size_t prototypeCallCandidates = rootEntries.table_second_args + reachableCalls.table_second_args;
        if (dispatcherFunction->args.size < 4 || dispatcherFunction->args.data[0] != best->state)
            throw std::runtime_error("dispatcher frame parameters were not resolved");
        Luau::AstLocal* argumentsLocal = dispatcherFunction->args.data[1];
        Luau::AstLocal* capturesLocal = dispatcherFunction->args.data[2];
        Luau::AstLocal* ownerLocal = dispatcherFunction->args.data[3];
        CellStorageCollector cellStorage(capturesLocal);
        dispatcherFunction->body->visit(&cellStorage);
        Luau::AstLocal* cellsLocal = cellStorage.best();
        std::map<Luau::AstLocal*, size_t> environmentCounts;
        for (const auto& [state, block] : blocks)
        {
            (void)state;
            for (const IndexedKey& key : block.dynamic_index_reads)
                ++environmentCounts[key.base];
        }
        auto environmentFound = std::max_element(
            environmentCounts.begin(), environmentCounts.end(), [](const auto& left, const auto& right) { return left.second < right.second; });
        Luau::AstLocal* environmentLocal = environmentFound == environmentCounts.end() ? nullptr : environmentFound->first;
        Luau::AstExprFunction* wrapperFunction = findContainingFunction(rewrittenAst->result.root, dispatcherBinding.assignment, sourceView);
        Luau::AstLocal* returnPackLocal = findReturnPackLocal(dispatcherFunction);
        const std::map<Luau::AstLocal*, std::string> externalRoles = resolveExternalRoles(
            dispatcherBinding.assignment, wrapperFunction, dispatcherBinding.local, cellsLocal, closureFactories,
            compactStructuralMatch);
        if (!environmentLocal)
        {
            auto role = std::find_if(externalRoles.begin(), externalRoles.end(), [](const auto& item) {
                return item.second == "environment";
            });
            if (role != externalRoles.end())
                environmentLocal = role->first;
        }
        std::set<std::string> sentinelKeys;
        for (const auto& [state, block] : blocks)
        {
            (void)state;
            if (!isReturnSentinel(block, indexedWrites.writes))
                continue;
            for (const IndexedKey& key : block.dynamic_index_reads)
                if (key.base == environmentLocal)
                    sentinelKeys.insert(key.key);
        }
        SemanticNormalizer normalizer(
            best->state,
            argumentsLocal,
            capturesLocal,
            ownerLocal,
            cellsLocal,
            environmentLocal,
            closureFactories,
            externalRoles,
            returnPackLocal,
            std::move(sentinelKeys));
        report["passes"].push_back({
            {"stage", "roles"},
            {"ok", cellsLocal != nullptr && environmentLocal != nullptr},
            {"arguments", true},
            {"captures", true},
            {"owner", true},
            {"cell_storage", cellsLocal != nullptr},
            {"environment", environmentLocal != nullptr},
            {"closure_factories", closureFactories.size()},
            {"wrapper", wrapperFunction != nullptr},
            {"return_pack", returnPackLocal != nullptr},
            {"external_roles", externalRoles.size()},
        });

        const std::set<int64_t> rootReachable = reachableStates(blocks, rootEntries.entries);
        const RuntimeTraceAnalysis runtimeTrace = analyzeRuntimeTrace(tracedStates, rootReachable);
        report["runtime_trace"] = {
            {"available", runtimeTrace.available},
            {"phase_split", runtimeTrace.phase_split},
            {"total_events", runtimeTrace.total_events},
            {"root_events", runtimeTrace.root_events},
            {"protector_events", runtimeTrace.protector_events},
            {"payload_events", runtimeTrace.payload_events},
            {"hot_protector_states", runtimeTrace.hot_protector_states},
            {"payload_root_states", runtimeTrace.payload_root_states},
            {"payload_helper_states", runtimeTrace.payload_helper_states},
            {"first_payload_root", runtimeTrace.first_payload_root ? json(*runtimeTrace.first_payload_root) : json(nullptr)},
            {"snapshot_boundary_complete", runtimeSnapshot.boundaryComplete()},
            {"snapshot_rows", runtimeSnapshot.rows},
            {"snapshot_cells", runtimeSnapshot.cells.size()},
            {"snapshot_registers", runtimeSnapshot.registers.size()},
            {"evidence", runtimeTrace.phase_split ? "bounded_offline_state_trace" : "static_only"},
        };
        report["passes"].push_back({
            {"stage", "trace"},
            {"ok", runtimeTrace.phase_split},
            {"available", runtimeTrace.available},
            {"events", runtimeTrace.total_events},
            {"protector_events", runtimeTrace.protector_events},
            {"payload_events", runtimeTrace.payload_events},
        });

        auto blockClassification = [&](int64_t state) -> const char* {
            if (runtimeTrace.payload_root_states.contains(state))
                return "payload";
            if (runtimeTrace.payload_helper_states.contains(state))
                return "payload_helper";
            if (runtimeTrace.protector_states.contains(state))
                return "protector";
            return runtimeTrace.available ? "unobserved" : "unclassified";
        };

        json constantRows = json::array();
        for (size_t i = 0; i < envelope.constants.size(); ++i)
        {
            const std::string& value = envelope.constants[i];
            json row = {{"index", i + 1}, {"bytes", value.size()}, {"sha256", sha256(value)}, {"provenance", "decoded_constant_table"}};
            if (printableAscii(value))
                row["value"] = value;
            else
                row["hex"] = hexBytes(value);
            constantRows.push_back(std::move(row));
        }
        writeJson(constantsPath, {{"version", 2}, {"encoding", "wearedevs-custom-base64"}, {"constants", constantRows}});

        publishProgress(options, "normalize", "running", "Normalizing VM register operations, calls, branches, and return arity",
            {{"states", blocks.size()}, {"reachable_states", reachable.size()}, {"closure_factories", closureFactories.size()}});
        json nodes = json::array();
        json edges = json::array();
        json blockRows = json::array();
        std::map<int64_t, json> normalizedBlocks;
        size_t instructionCount = 0;
        size_t dynamicTransitions = 0;
        size_t returnSentinelTransitions = 0;
        size_t normalizedInstructionCount = 0;
        size_t unsupportedInstructionCount = 0;
        size_t protectorInstructionCount = 0;
        size_t payloadInstructionCount = 0;
        PrometheusTemplateRecoveryStats allTemplateRecoveries;
        PrometheusTemplateRecoveryStats reachableTemplateRecoveries;
        PrometheusTemplateRecoveryStats payloadTemplateRecoveries;
        for (const auto& [state, block] : blocks)
        {
            bool isReachable = reachable.contains(state);
            bool returnSentinel = isReturnSentinel(block, indexedWrites.writes);
            size_t normalizedBefore = normalizer.normalizedStatements();
            size_t unsupportedBefore = normalizer.unsupportedStatements();
            json normalizedInstructions = normalizer.block(block.body);
            const PrometheusTemplateRecoveryStats blockTemplateRecoveries = recoverPrometheusCompilerTemplates(normalizedInstructions);
            allTemplateRecoveries.add(blockTemplateRecoveries);
            if (isReachable)
                reachableTemplateRecoveries.add(blockTemplateRecoveries);
            const std::string_view classification = blockClassification(state);
            if (classification == "payload" || classification == "payload_helper")
                payloadTemplateRecoveries.add(blockTemplateRecoveries);
            normalizedBlocks[state] = normalizedInstructions;
            size_t normalizedInBlock = normalizer.normalizedStatements() - normalizedBefore;
            size_t unsupportedInBlock = normalizer.unsupportedStatements() - unsupportedBefore;
            nodes.push_back({
                {"id", std::to_string(state)},
                {"state", state},
                {"reachable", isReachable},
                {"classification", blockClassification(state)},
                {"line", block.body->location.begin.line + 1},
                {"column", block.body->location.begin.column + 1},
                {"statement_count", block.statements},
                {"dynamic_transitions", block.dynamic_transitions},
                {"return_sentinel", returnSentinel},
            });
            for (int64_t target : block.outgoing)
                edges.push_back({{"from", std::to_string(state)}, {"to", std::to_string(target)}, {"kind", "state_assignment"}, {"resolved", blocks.contains(target)}});
            if (block.dynamic_transitions)
                edges.push_back({{"from", std::to_string(state)}, {"to", nullptr},
                    {"kind", returnSentinel ? "return_sentinel" : "dynamic_state_assignment"}, {"resolved", returnSentinel}});
            std::string terminatorKind;
            if (returnSentinel && !block.outgoing.empty())
                terminatorKind = "branch_return";
            else if (returnSentinel)
                terminatorKind = "return";
            else if (block.dynamic_transitions && !block.outgoing.empty())
                terminatorKind = "branch_dynamic";
            else if (block.dynamic_transitions)
                terminatorKind = "dynamic";
            else if (block.outgoing.size() > 1)
                terminatorKind = "branch";
            else if (block.outgoing.size() == 1)
                terminatorKind = "jump";
            else
                terminatorKind = "exit";
            blockRows.push_back({
                {"id", std::to_string(state)},
                {"state", state},
                {"reachable", isReachable},
                {"classification", blockClassification(state)},
                {"instructions", normalizedInstructions},
                {"terminator", {{"kind", terminatorKind}, {"targets", block.outgoing},
                                   {"unresolved_targets", returnSentinel ? 0 : block.dynamic_transitions}, {"protector_return_sentinel", returnSentinel}}},
                {"location", {{"line", block.body->location.begin.line + 1}, {"column", block.body->location.begin.column + 1}}},
            });
            if (isReachable)
            {
                instructionCount += block.statements;
                normalizedInstructionCount += normalizedInBlock;
                unsupportedInstructionCount += unsupportedInBlock;
                dynamicTransitions += block.dynamic_transitions;
                if (returnSentinel)
                    returnSentinelTransitions += block.dynamic_transitions;
                if (classification == "payload" || classification == "payload_helper")
                    payloadInstructionCount += block.statements;
                else if (classification == "protector")
                    protectorInstructionCount += block.statements;
            }
        }
        writeJson(cfgPath, {
            {"version", 2},
            {"dispatcher_state", best->state->name.value ? best->state->name.value : "<anonymous>"},
            {"entry_states", prototypeEntries},
            {"root_entry_states", rootEntries.entries},
            {"closure_factory_count", closureFactories.size()},
            {"nodes", nodes},
            {"edges", edges},
            {"coverage", {{"known", reachable.size()}, {"total", blocks.size()}}},
        });
        publishProgress(options, "normalize", unsupportedInstructionCount == 0 ? "done" : "failed",
            unsupportedInstructionCount == 0 ? "Typed VM operations normalized" : "Some VM operations could not be normalized",
            {{"normalized_instructions", normalizedInstructionCount}, {"unsupported_instructions", unsupportedInstructionCount},
                {"payload_instruction_candidates", payloadInstructionCount}, {"protector_instructions", protectorInstructionCount},
                {"fixed_arity_calls_recovered", payloadTemplateRecoveries.fixed_arity_calls},
                {"variadic_expansions_recovered", payloadTemplateRecoveries.variadic_expansions}});
        report["passes"].push_back({
            {"stage", "prometheus_templates"},
            {"ok", true},
            {"scope", "normalized_vm_operations"},
            {"all_blocks", allTemplateRecoveries.toJson()},
            {"reachable_blocks", reachableTemplateRecoveries.toJson()},
            {"payload_blocks", payloadTemplateRecoveries.toJson()},
        });

        const std::set<std::string> payloadLiveIns = payloadLiveInRequirements(runtimeTrace, normalizedBlocks);
        const std::set<std::string> requiredPayloadCells = payloadCellRequirements(runtimeTrace, normalizedBlocks, payloadLiveIns);
        std::set<std::string> requiredPayloadRegisters;
        std::set_difference(
            payloadLiveIns.begin(),
            payloadLiveIns.end(),
            requiredPayloadCells.begin(),
            requiredPayloadCells.end(),
            std::inserter(requiredPayloadRegisters, requiredPayloadRegisters.end()));
        std::vector<SnapshotBinding> snapshotBindings;
        for (const std::string& normalizedName : payloadLiveIns)
            if (auto sourceName = normalizer.sourceNameFor(normalizedName))
                snapshotBindings.push_back({normalizedName, *sourceName, requiredPayloadCells.contains(normalizedName)});
        const bool snapshotComplete = snapshotSatisfies(runtimeSnapshot, requiredPayloadCells, requiredPayloadRegisters);
        bool snapshotProbeReady = false;
        if (runtimeTrace.phase_split && runtimeTrace.first_payload_root && cellsLocal && cellsLocal->name.value &&
            snapshotBindings.size() == payloadLiveIns.size())
        {
            writeFile(traceProbePath, buildSnapshotTraceProbe(
                envelope.rewritten,
                stateTraceMarker,
                cellSnapshotMarker,
                *runtimeTrace.first_payload_root,
                cellsLocal->name.value,
                snapshotBindings));
            snapshotProbeReady = true;
        }
        report["runtime_trace"]["snapshot_probe_ready"] = snapshotProbeReady;
        report["runtime_trace"]["snapshot_complete"] = snapshotComplete;
        report["runtime_trace"]["snapshot_required_live_ins"] = payloadLiveIns.size();
        report["runtime_trace"]["snapshot_required_cells"] = requiredPayloadCells.size();
        report["runtime_trace"]["snapshot_required_registers"] = requiredPayloadRegisters.size();
        report["passes"].push_back({
            {"stage", "snapshot"},
            {"ok", snapshotComplete},
            {"probe_ready", snapshotProbeReady},
            {"required_cells", requiredPayloadCells.size()},
            {"required_registers", requiredPayloadRegisters.size()},
            {"captured_cells", runtimeSnapshot.cells.size()},
            {"captured_registers", runtimeSnapshot.registers.size()},
            {"rows", runtimeSnapshot.rows},
        });

        json prototypeRows = json::array();
        std::map<int64_t, std::set<int64_t>> prototypeBlockSets;
        std::map<int64_t, std::set<int64_t>> prototypeNestedEntries;
        std::vector<int64_t> orderedPrototypeEntries;
        orderedPrototypeEntries.insert(orderedPrototypeEntries.end(), rootEntries.entries.begin(), rootEntries.entries.end());
        for (int64_t entry : prototypeEntries)
            if (!rootEntries.entries.contains(entry))
                orderedPrototypeEntries.push_back(entry);
        for (int64_t entry : orderedPrototypeEntries)
            if (blocks.contains(entry))
            {
                std::set<int64_t> prototypeReachable = reachableStates(blocks, {entry});
                json prototypeBlocks = json::array();
                json returnBlocks = json::array();
                PrototypeEntryCollector nested(closureFactories);
                for (int64_t state : prototypeReachable)
                {
                    prototypeBlocks.push_back(state);
                    auto block = blocks.find(state);
                    if (block == blocks.end())
                        continue;
                    if (isReturnSentinel(block->second, indexedWrites.writes))
                        returnBlocks.push_back(state);
                    block->second.body->visit(&nested);
                }
                nested.entries.erase(entry);
                prototypeBlockSets[entry] = prototypeReachable;
                prototypeNestedEntries[entry] = nested.entries;
                prototypeRows.push_back({
                    {"entry_state", entry},
                    {"name", "function_" + std::to_string(prototypeRows.size() + 1)},
                    {"root", rootEntries.entries.contains(entry)},
                    {"recovered", false},
                    {"normalized", true},
                    {"prototype_local_ssa", false},
                    {"block_count", prototypeReachable.size()},
                    {"blocks", prototypeBlocks},
                    {"return_blocks", returnBlocks},
                    {"nested_prototypes", nested.entries},
                });
            }

        std::optional<EmittedSource> stateMachineCandidate;
        std::optional<prometheus::LiftResult> structuredCandidate;
        std::optional<readable::RewriteResult> readableCandidate;
        std::optional<rbx::runtime::RegisterOverflowRewrite> emittedRegisterSpill;
        std::optional<state_fields::RefinementResult> stateFieldRefinement;
        bool candidateCompiled = false;
        size_t snapshotAssignmentCount = 0;
        const bool compactStaticRoot = !runtimeTrace.phase_split && compactStructuralMatch &&
            rootEntries.entries.size() == 1 && unsupportedInstructionCount == 0;
        const std::optional<int64_t> selectedPayloadEntry = runtimeTrace.phase_split && runtimeTrace.first_payload_root
            ? runtimeTrace.first_payload_root
            : (compactStaticRoot ? std::optional<int64_t>(*rootEntries.entries.begin()) : std::nullopt);
        if (selectedPayloadEntry && rootEntries.entries.size() == 1)
        {
            json rootSetup = runtimeTrace.phase_split
                ? recoverPayloadSetup(runtimeTrace, normalizedBlocks, requiredPayloadCells)
                : json::array();
            json snapshotAssignments = runtimeTrace.phase_split
                ? recoveredSnapshotAssignments(runtimeSnapshot, requiredPayloadCells, requiredPayloadRegisters)
                : json::array();
            snapshotAssignmentCount = snapshotAssignments.size();
            for (json& assignment : snapshotAssignments)
                rootSetup.push_back(std::move(assignment));
            const int64_t rootIdentity = *rootEntries.entries.begin();
            std::map<int64_t, std::set<int64_t>> selectedBlockSets;
            selectedBlockSets[rootIdentity] = reachableStates(blocks, {*selectedPayloadEntry});
            std::queue<int64_t> pendingPrototypes;
            pendingPrototypes.push(rootIdentity);
            while (!pendingPrototypes.empty())
            {
                int64_t identity = pendingPrototypes.front();
                pendingPrototypes.pop();
                std::set<int64_t> nestedEntries;
                for (int64_t state : selectedBlockSets[identity])
                {
                    auto normalized = normalizedBlocks.find(state);
                    if (normalized != normalizedBlocks.end())
                        collectMakeClosureEntries(normalized->second, nestedEntries);
                }
                for (int64_t nested : nestedEntries)
                    if (prototypeBlockSets.contains(nested) && !selectedBlockSets.contains(nested))
                    {
                        selectedBlockSets[nested] = prototypeBlockSets[nested];
                        pendingPrototypes.push(nested);
                    }
            }

            std::map<int64_t, std::string> functionNames;
            for (const json& row : prototypeRows)
            {
                const int64_t identity = row.value("entry_state", 0LL);
                if (selectedBlockSets.contains(identity))
                    functionNames[identity] = row.value("name", "function_unknown");
            }
            std::vector<EmittedFunction> emittedFunctions;
            for (const json& row : prototypeRows)
            {
                const int64_t identity = row.value("entry_state", 0LL);
                if (!selectedBlockSets.contains(identity))
                    continue;
                EmittedFunction function;
                function.identity_entry = identity;
                function.name = row.value("name", "function_unknown");
                if (row.value("root", false))
                {
                    function.start_state = *selectedPayloadEntry;
                    function.blocks = selectedBlockSets[identity];
                    function.setup = rootSetup;
                }
                else
                {
                    function.start_state = identity;
                    function.blocks = selectedBlockSets[identity];
                }
                emittedFunctions.push_back(std::move(function));
            }
            publishProgress(options, "lift", "running", "Lifting reachable VM operations into typed semantic Luau IR",
                {{"selected_prototypes", selectedBlockSets.size()}, {"payload_blocks", selectedBlockSets[rootIdentity].size()},
                    {"normalized_blocks", normalizedBlocks.size()}});
            std::map<int64_t, json> liftBlocks = normalizedBlocks;
            if (!rootSetup.empty())
            {
                json entryInstructions = json::array();
                for (const json& statement : rootSetup)
                    entryInstructions.push_back(statement);
                auto entryBlock = liftBlocks.find(*selectedPayloadEntry);
                if (entryBlock != liftBlocks.end())
                    for (const json& statement : entryBlock->second)
                        entryInstructions.push_back(statement);
                liftBlocks[*selectedPayloadEntry] = std::move(entryInstructions);
            }
            structuredCandidate = prometheus::lift({
                liftBlocks,
                prototypeRows,
                *selectedPayloadEntry,
                selectedBlockSets[rootIdentity],
            });
            const bool semanticLiftCompiled = structuredCandidate->complete && compiles(structuredCandidate->source);
            publishProgress(options, "lift", semanticLiftCompiled ? "done" : "failed",
                semanticLiftCompiled ? "Semantic lift compiled successfully" : "Semantic lift remains incomplete",
                {{"lifted_instructions", structuredCandidate->lifted_instructions},
                    {"reconstructed_prototypes", structuredCandidate->reconstructed_prototypes},
                    {"emitted_statements", structuredCandidate->emitted_statements},
                    {"decoded_strings", structuredCandidate->decoded_strings.size()},
                    {"candidate_compiled", semanticLiftCompiled}});
            if (structuredCandidate->complete)
            {
                writeFile(semanticCandidatePath, structuredCandidate->source);
                publishProgress(options, "structure_flow", "running", "Reconstructing flattened VM regions into source control flow",
                    {{"lifted_instructions", structuredCandidate->lifted_instructions},
                        {"reconstructed_prototypes", structuredCandidate->reconstructed_prototypes},
                        {"emitted_statements", structuredCandidate->emitted_statements}});
                readableCandidate = readable::rewriteStateMachines(structuredCandidate->source, structuredCandidate->mapping,
                    [&](std::string_view stage, std::string_view status, std::string_view message, const json& metrics) {
                        publishProgress(options, stage, status, message, metrics);
                    }, {.allow_register_overflow = true, .stabilize_residual_names = true});
                const bool rewriteChanged = readableCandidate->changed;
                const bool rewriteCompiled = !rewriteChanged || compiles(readableCandidate->source);
                const bool finalCandidateCompiled = rewriteChanged ? (rewriteCompiled || semanticLiftCompiled) : semanticLiftCompiled;
                if (rewriteChanged && rewriteCompiled)
                {
                    structuredCandidate->source = readableCandidate->source;
                    structuredCandidate->mapping = readableCandidate->mapping;
                }
                else if (rewriteChanged)
                    readableCandidate->changed = false;
                publishProgress(options, "structure_flow", rewriteCompiled ? "done" : "failed",
                    rewriteCompiled ? "Structured source rewrite completed" : "Structured source rewrite did not compile and was withheld",
                    {{"rewrite_changed", rewriteChanged},
                        {"rewrite_compiled", rewriteChanged ? json(rewriteCompiled) : json(nullptr)},
                        {"candidate_compiled", finalCandidateCompiled},
                        {"applied", readableCandidate->changed},
                        {"single_use_temporaries_inlined", readableCandidate->single_use_temporaries_inlined},
                        {"single_use_expressions_inlined", readableCandidate->single_use_expressions_inlined},
                        {"stable_capture_cells_scalarized", readableCandidate->stable_capture_cells_scalarized},
                        {"stable_capture_accesses_scalarized", readableCandidate->stable_capture_accesses_scalarized},
                        {"producer_aliases_coalesced", readableCandidate->producer_aliases_coalesced},
                        {"write_only_result_packs_removed", readableCandidate->write_only_result_packs_removed},
                        {"fixed_top_call_packs_expanded", readableCandidate->fixed_top_call_packs_expanded},
                        {"refinement_passes", readableCandidate->refinement_passes},
                        {"residual_bindings_renamed", readableCandidate->residual_bindings_renamed},
                        {"residual_semantic_role_names", readableCandidate->residual_semantic_role_names},
                        {"residual_generic_fallback_names", readableCandidate->residual_generic_fallback_names},
                        {"residual_generated_merge_names", readableCandidate->residual_generated_merge_names},
                        {"unused_local_declarations_removed", readableCandidate->unused_local_declarations_removed},
                        {"guard_clauses_flattened", readableCandidate->guard_clauses_flattened},
                        {"redundant_parentheses_removed", readableCandidate->redundant_parentheses_removed},
                        {"callback_aliases_promoted", readableCandidate->callback_aliases_promoted},
                        {"direct_closure_calls_recovered", readableCandidate->direct_closure_calls_recovered},
                        {"trace_instrumentation_removed", readableCandidate->trace_instrumentation_removed},
                        {"unreachable_prototypes_removed", readableCandidate->unreachable_prototypes_removed},
                        {"replay_targets_inlined", readableCandidate->replay_targets_inlined},
                        {"high_register_replay_patches_removed", readableCandidate->high_register_replay_patches_removed},
                        {"cleared_replay_metadata_patches_removed", readableCandidate->cleared_replay_metadata_patches_removed},
                        {"low_register_replay_patches_removed", readableCandidate->low_register_replay_patches_removed},
                        {"replay_branches_collapsed", readableCandidate->replay_branches_collapsed},
                        {"linear_replay_metadata_patches_removed", readableCandidate->linear_replay_metadata_patches_removed},
                        {"register_tables_scalarized", readableCandidate->register_tables_scalarized},
                        {"register_tables_fully_scalarized", readableCandidate->register_tables_fully_scalarized},
                        {"register_tables_partially_scalarized", readableCandidate->register_tables_partially_scalarized},
                        {"register_table_slots_scalarized", readableCandidate->register_table_slots_scalarized},
                        {"register_table_accesses_scalarized", readableCandidate->register_table_accesses_scalarized},
                        {"state_tables_scalarized", readableCandidate->state_tables_scalarized},
                        {"state_fields_scalarized", readableCandidate->state_fields_scalarized},
                        {"state_accesses_scalarized", readableCandidate->state_accesses_scalarized}});
            }
            std::optional<rbx::runtime::RegisterOverflowRewrite> preparedCandidate = structuredCandidate->complete
                ? prepareStandaloneSource(structuredCandidate->source)
                : std::nullopt;
            candidateCompiled = preparedCandidate.has_value();
            if (preparedCandidate)
            {
                if (preparedCandidate->applied)
                {
                    emittedRegisterSpill = *preparedCandidate;
                    stateFieldRefinement = state_fields::refineGeneratedCallbackFields(preparedCandidate->source);
                    const bool refinementFailed = !stateFieldRefinement->parse_succeeded ||
                        (stateFieldRefinement->compile_attempted && !stateFieldRefinement->candidate_compiled);
                    publishProgress(options, "refine_state_fields", refinementFailed ? "failed" : "done",
                        refinementFailed
                            ? "Generated semantic state field refinements were withheld"
                            : (stateFieldRefinement->committed
                                    ? "Generated semantic state callback fields received proven purpose names"
                                    : "No generated semantic state callback fields had a unique proven purpose"),
                        stateFieldRefinementMetrics(stateFieldRefinement));
                    if (stateFieldRefinement->committed)
                        preparedCandidate->source = std::move(stateFieldRefinement->source);
                }
                structuredCandidate->source = std::move(preparedCandidate->source);
                writeFile(candidatePath, structuredCandidate->source);
            }
            if (candidateCompiled)
            {
                report["reconstruction_candidate"] = {
                    {"available", true},
                    {"compiled", true},
                    {"kind", "structured_luau"},
                    {"source_claim_eligible", !compactStaticRoot},
                    {"internal_artifact", false},
                    {"payload_entry", *selectedPayloadEntry},
                    {"selection_evidence", compactStaticRoot ? "complete_static_root" : "bounded_runtime_phase_split"},
                    {"functions", structuredCandidate->reconstructed_prototypes},
                    {"root_blocks", selectedBlockSets[rootIdentity].size()},
                    {"statements", structuredCandidate->emitted_statements},
                    {"lifted_instructions", structuredCandidate->lifted_instructions},
                    {"decoded_strings", structuredCandidate->decoded_strings.size()},
                    {"compiler_templates", payloadTemplateRecoveries.toJson()},
                    {"register_spill", emittedRegisterSpill
                            ? json{{"applied", true},
                                  {"representation", "semantic_state_table"},
                                  {"functions_rewritten", emittedRegisterSpill->functionsRewritten},
                                  {"bindings_spilled", emittedRegisterSpill->bindingsSpilled},
                                  {"diagnostics", emittedRegisterSpill->diagnostics},
                                  {"state_field_refinement", stateFieldRefinementMetrics(stateFieldRefinement)}}
                            : json{{"applied", false},
                                  {"functions_rewritten", 0},
                                  {"bindings_spilled", 0},
                                  {"state_field_refinement", stateFieldRefinementMetrics(stateFieldRefinement)}}},
                    {"representation", readableCandidate && readableCandidate->changed
                            ? "structured_control_flow"
                            : (structuredCandidate->reason == "complete_straight_line_payload" ? "straight_line_lift" : "semantic_state_machine")},
                    {"readability", readableCandidate
                            ? json{{"regions_found", readableCandidate->regions_found},
                                  {"regions_structured", readableCandidate->regions_structured},
                                  {"blocks_structured", readableCandidate->blocks_structured},
                                  {"residual_state_machines", readableCandidate->residual_state_machines},
                                  {"dead_assignments_removed", readableCandidate->dead_assignments_removed},
                                  {"constants_propagated", readableCandidate->constants_propagated},
                                  {"aliases_propagated", readableCandidate->aliases_propagated},
                                  {"properties_recovered", readableCandidate->properties_recovered},
                                  {"methods_recovered", readableCandidate->methods_recovered},
                                  {"prototypes_nested", readableCandidate->prototypes_nested},
                                  {"capture_references_recovered", readableCandidate->capture_references_recovered},
                                  {"globals_recovered", readableCandidate->globals_recovered},
                                  {"numeric_loops_recovered", readableCandidate->numeric_loops_recovered},
                                  {"generic_loops_recovered", readableCandidate->generic_loops_recovered},
                                  {"unused_command_results_removed", readableCandidate->unused_command_results_removed},
                                  {"locals_promoted", readableCandidate->locals_promoted},
                                  {"declarations_pruned", readableCandidate->declarations_pruned},
                                  {"function_parameters_recovered", readableCandidate->function_parameters_recovered},
                                  {"unused_captures_removed", readableCandidate->unused_captures_removed},
                                  {"capture_factories_collapsed", readableCandidate->capture_factories_collapsed},
                                  {"dead_capture_factories_removed", readableCandidate->dead_capture_factories_removed},
                                  {"captured_cells_unboxed", readableCandidate->captured_cells_unboxed},
                                  {"returned_closures_recovered", readableCandidate->returned_closures_recovered},
                                  {"function_locals_promoted", readableCandidate->function_locals_promoted},
                                  {"leading_semicolons_removed", readableCandidate->leading_semicolons_removed},
                                  {"redundant_index_groupings_removed", readableCandidate->redundant_index_groupings_removed},
                                  {"captured_locals_named", readableCandidate->captured_locals_named},
                                  {"semantic_locals_promoted", readableCandidate->semantic_locals_promoted},
                                  {"semantic_lifetimes_split", readableCandidate->semantic_lifetimes_split},
                                  {"temporary_conditions_inlined", readableCandidate->temporary_conditions_inlined},
                                  {"semantic_initializers_coalesced", readableCandidate->semantic_initializers_coalesced},
                                  {"single_assignment_aliases_folded", readableCandidate->single_assignment_aliases_folded},
                                  {"blank_lines_removed", readableCandidate->blank_lines_removed},
                                  {"property_temporaries_inlined", readableCandidate->property_temporaries_inlined},
                                  {"unused_call_results_removed", readableCandidate->unused_call_results_removed},
                                  {"default_assignments_recovered", readableCandidate->default_assignments_recovered},
                                  {"unused_cell_allocations_removed", readableCandidate->unused_cell_allocations_removed},
                                  {"result_returns_collapsed", readableCandidate->result_returns_collapsed},
                                  {"result_packs_collapsed", readableCandidate->result_packs_collapsed},
                                  {"fixed_top_call_packs_expanded", readableCandidate->fixed_top_call_packs_expanded},
                                  {"empty_branches_removed", readableCandidate->empty_branches_removed},
                                  {"state_registers_renamed", readableCandidate->state_registers_renamed},
                                  {"alias_reloads_eliminated", readableCandidate->alias_reloads_eliminated},
                                  {"numeric_literals_normalized", readableCandidate->numeric_literals_normalized},
                                  {"register_tables_scalarized", readableCandidate->register_tables_scalarized},
                                  {"register_tables_fully_scalarized", readableCandidate->register_tables_fully_scalarized},
                                  {"register_tables_partially_scalarized", readableCandidate->register_tables_partially_scalarized},
                                  {"register_table_slots_scalarized", readableCandidate->register_table_slots_scalarized},
                                  {"register_table_accesses_scalarized", readableCandidate->register_table_accesses_scalarized},
                                  {"state_tables_scalarized", readableCandidate->state_tables_scalarized},
                                  {"state_fields_scalarized", readableCandidate->state_fields_scalarized},
                                  {"state_accesses_scalarized", readableCandidate->state_accesses_scalarized},
                                  {"single_use_temporaries_inlined", readableCandidate->single_use_temporaries_inlined},
                                  {"single_use_expressions_inlined", readableCandidate->single_use_expressions_inlined},
                                  {"stable_capture_cells_scalarized", readableCandidate->stable_capture_cells_scalarized},
                                  {"stable_capture_accesses_scalarized", readableCandidate->stable_capture_accesses_scalarized},
                                  {"producer_aliases_coalesced", readableCandidate->producer_aliases_coalesced},
                                  {"write_only_result_packs_removed", readableCandidate->write_only_result_packs_removed},
                                  {"direct_closure_calls_recovered", readableCandidate->direct_closure_calls_recovered},
                                  {"trace_instrumentation_removed", readableCandidate->trace_instrumentation_removed},
                                  {"unreachable_prototypes_removed", readableCandidate->unreachable_prototypes_removed},
                                  {"replay_targets_inlined", readableCandidate->replay_targets_inlined},
                                  {"high_register_replay_patches_removed", readableCandidate->high_register_replay_patches_removed},
                                  {"cleared_replay_metadata_patches_removed", readableCandidate->cleared_replay_metadata_patches_removed},
                                  {"low_register_replay_patches_removed", readableCandidate->low_register_replay_patches_removed},
                                  {"replay_branches_collapsed", readableCandidate->replay_branches_collapsed},
                                  {"linear_replay_metadata_patches_removed", readableCandidate->linear_replay_metadata_patches_removed},
                                  {"refinement_passes", readableCandidate->refinement_passes},
                                  {"residual_bindings_renamed", readableCandidate->residual_bindings_renamed},
                                  {"residual_generated_bindings_renamed", readableCandidate->residual_generated_bindings_renamed},
                                  {"residual_temporary_bindings_renamed", readableCandidate->residual_temporary_bindings_renamed},
                                  {"residual_semantic_role_names", readableCandidate->residual_semantic_role_names},
                                  {"residual_generic_fallback_names", readableCandidate->residual_generic_fallback_names},
                                  {"residual_generated_merge_names", readableCandidate->residual_generated_merge_names},
                                  {"residual_register_bindings_named", readableCandidate->residual_register_bindings_named},
                                  {"residual_mutable_cells_named", readableCandidate->residual_mutable_cells_named},
                                  {"residual_callbacks_named", readableCandidate->residual_callbacks_named},
                                  {"residual_vm_values_named", readableCandidate->residual_vm_values_named},
                                  {"residual_vm_temporaries_named", readableCandidate->residual_vm_temporaries_named},
                                  {"unused_local_declarations_removed", readableCandidate->unused_local_declarations_removed},
                                  {"residual_binding_diagnostics", readableCandidate->residual_binding_diagnostics},
                                  {"guard_clauses_flattened", readableCandidate->guard_clauses_flattened},
                                  {"redundant_parentheses_removed", readableCandidate->redundant_parentheses_removed},
                                  {"callback_aliases_promoted", readableCandidate->callback_aliases_promoted},
                                  {"residual_reasons", readableCandidate->residual_reasons},
                                  {"applied", readableCandidate->changed}}
                            : json(nullptr)},
                    {"runtime_verified", false},
                    {"path", candidatePath.filename().string()},
                };
            }
            else
            {
                report["reconstruction_candidate"] = {
                    {"available", false},
                    {"compiled", false},
                    {"kind", "structured_luau"},
                    {"source_claim_eligible", false},
                    {"runtime_verified", false},
                    {"reason", structuredCandidate->reason},
                    {"compiler_templates", payloadTemplateRecoveries.toJson()},
                    {"path", nullptr},
                };
            }

            LuauStateMachineEmitter emitter(functionNames, normalizedBlocks, normalizer.registerRows());
            stateMachineCandidate = emitter.emit(emittedFunctions, rootIdentity);
            const bool internalStateMachineCompiled = stateMachineCandidate->unsupported == 0 && compiles(stateMachineCandidate->source);
            if (internalStateMachineCompiled)
                writeFile(internalStateMachinePath, stateMachineCandidate->source);
            report["internal_analysis"] = {
                {"kind", "semantic_state_machine"},
                {"compiled", internalStateMachineCompiled},
                {"source_claim_eligible", false},
                {"path", internalStateMachineCompiled ? json(internalStateMachinePath.filename().string()) : json(nullptr)},
                {"functions", emittedFunctions.size()},
                {"setup_statements", emittedFunctions.empty() ? 0 : emittedFunctions.front().setup.size()},
                {"snapshot_assignments", snapshotAssignmentCount},
                {"statements", stateMachineCandidate->statements},
                {"unsupported", stateMachineCandidate->unsupported},
            };
            report["passes"].push_back({
                {"stage", "prometheus_inverse"},
                {"ok", candidateCompiled},
                {"family_recognized", structuredCandidate->family_recognized},
                {"reason", structuredCandidate->reason},
                {"decoded_strings", structuredCandidate->decoded_strings.size()},
                {"lifted_instructions", structuredCandidate->lifted_instructions},
            });
            report["passes"].push_back({
                {"stage", "structure"},
                {"ok", readableCandidate && readableCandidate->changed},
                {"regions_found", readableCandidate ? readableCandidate->regions_found : 0},
                {"regions_structured", readableCandidate ? readableCandidate->regions_structured : 0},
                {"blocks_structured", readableCandidate ? readableCandidate->blocks_structured : 0},
                {"residual_state_machines", readableCandidate ? readableCandidate->residual_state_machines : 0},
                {"dead_assignments_removed", readableCandidate ? readableCandidate->dead_assignments_removed : 0},
                {"constants_propagated", readableCandidate ? readableCandidate->constants_propagated : 0},
                {"aliases_propagated", readableCandidate ? readableCandidate->aliases_propagated : 0},
                {"properties_recovered", readableCandidate ? readableCandidate->properties_recovered : 0},
                {"methods_recovered", readableCandidate ? readableCandidate->methods_recovered : 0},
                {"prototypes_nested", readableCandidate ? readableCandidate->prototypes_nested : 0},
                {"capture_references_recovered", readableCandidate ? readableCandidate->capture_references_recovered : 0},
                {"globals_recovered", readableCandidate ? readableCandidate->globals_recovered : 0},
                {"numeric_loops_recovered", readableCandidate ? readableCandidate->numeric_loops_recovered : 0},
                {"generic_loops_recovered", readableCandidate ? readableCandidate->generic_loops_recovered : 0},
                {"unused_command_results_removed", readableCandidate ? readableCandidate->unused_command_results_removed : 0},
                {"locals_promoted", readableCandidate ? readableCandidate->locals_promoted : 0},
                {"declarations_pruned", readableCandidate ? readableCandidate->declarations_pruned : 0},
                {"function_parameters_recovered", readableCandidate ? readableCandidate->function_parameters_recovered : 0},
                {"unused_captures_removed", readableCandidate ? readableCandidate->unused_captures_removed : 0},
                {"capture_factories_collapsed", readableCandidate ? readableCandidate->capture_factories_collapsed : 0},
                {"dead_capture_factories_removed", readableCandidate ? readableCandidate->dead_capture_factories_removed : 0},
                {"captured_cells_unboxed", readableCandidate ? readableCandidate->captured_cells_unboxed : 0},
                {"returned_closures_recovered", readableCandidate ? readableCandidate->returned_closures_recovered : 0},
                {"function_locals_promoted", readableCandidate ? readableCandidate->function_locals_promoted : 0},
                {"leading_semicolons_removed", readableCandidate ? readableCandidate->leading_semicolons_removed : 0},
                {"redundant_index_groupings_removed", readableCandidate ? readableCandidate->redundant_index_groupings_removed : 0},
                {"captured_locals_named", readableCandidate ? readableCandidate->captured_locals_named : 0},
                {"semantic_locals_promoted", readableCandidate ? readableCandidate->semantic_locals_promoted : 0},
                {"semantic_lifetimes_split", readableCandidate ? readableCandidate->semantic_lifetimes_split : 0},
                {"temporary_conditions_inlined", readableCandidate ? readableCandidate->temporary_conditions_inlined : 0},
                {"semantic_initializers_coalesced", readableCandidate ? readableCandidate->semantic_initializers_coalesced : 0},
                {"single_assignment_aliases_folded", readableCandidate ? readableCandidate->single_assignment_aliases_folded : 0},
                {"blank_lines_removed", readableCandidate ? readableCandidate->blank_lines_removed : 0},
                {"property_temporaries_inlined", readableCandidate ? readableCandidate->property_temporaries_inlined : 0},
                {"unused_call_results_removed", readableCandidate ? readableCandidate->unused_call_results_removed : 0},
                {"default_assignments_recovered", readableCandidate ? readableCandidate->default_assignments_recovered : 0},
                {"unused_cell_allocations_removed", readableCandidate ? readableCandidate->unused_cell_allocations_removed : 0},
                {"result_returns_collapsed", readableCandidate ? readableCandidate->result_returns_collapsed : 0},
                {"result_packs_collapsed", readableCandidate ? readableCandidate->result_packs_collapsed : 0},
                {"fixed_top_call_packs_expanded", readableCandidate ? readableCandidate->fixed_top_call_packs_expanded : 0},
                {"empty_branches_removed", readableCandidate ? readableCandidate->empty_branches_removed : 0},
                {"state_registers_renamed", readableCandidate ? readableCandidate->state_registers_renamed : 0},
                {"alias_reloads_eliminated", readableCandidate ? readableCandidate->alias_reloads_eliminated : 0},
                {"numeric_literals_normalized", readableCandidate ? readableCandidate->numeric_literals_normalized : 0},
                {"register_tables_scalarized", readableCandidate ? readableCandidate->register_tables_scalarized : 0},
                {"register_tables_fully_scalarized", readableCandidate ? readableCandidate->register_tables_fully_scalarized : 0},
                {"register_tables_partially_scalarized", readableCandidate ? readableCandidate->register_tables_partially_scalarized : 0},
                {"register_table_slots_scalarized", readableCandidate ? readableCandidate->register_table_slots_scalarized : 0},
                {"register_table_accesses_scalarized", readableCandidate ? readableCandidate->register_table_accesses_scalarized : 0},
                {"state_tables_scalarized", readableCandidate ? readableCandidate->state_tables_scalarized : 0},
                {"state_fields_scalarized", readableCandidate ? readableCandidate->state_fields_scalarized : 0},
                {"state_accesses_scalarized", readableCandidate ? readableCandidate->state_accesses_scalarized : 0},
                {"single_use_temporaries_inlined", readableCandidate ? readableCandidate->single_use_temporaries_inlined : 0},
                {"single_use_expressions_inlined", readableCandidate ? readableCandidate->single_use_expressions_inlined : 0},
                {"stable_capture_cells_scalarized", readableCandidate ? readableCandidate->stable_capture_cells_scalarized : 0},
                {"stable_capture_accesses_scalarized", readableCandidate ? readableCandidate->stable_capture_accesses_scalarized : 0},
                {"producer_aliases_coalesced", readableCandidate ? readableCandidate->producer_aliases_coalesced : 0},
                {"write_only_result_packs_removed", readableCandidate ? readableCandidate->write_only_result_packs_removed : 0},
                {"direct_closure_calls_recovered", readableCandidate ? readableCandidate->direct_closure_calls_recovered : 0},
                {"trace_instrumentation_removed", readableCandidate ? readableCandidate->trace_instrumentation_removed : 0},
                {"unreachable_prototypes_removed", readableCandidate ? readableCandidate->unreachable_prototypes_removed : 0},
                {"replay_targets_inlined", readableCandidate ? readableCandidate->replay_targets_inlined : 0},
                {"high_register_replay_patches_removed", readableCandidate ? readableCandidate->high_register_replay_patches_removed : 0},
                {"cleared_replay_metadata_patches_removed", readableCandidate ? readableCandidate->cleared_replay_metadata_patches_removed : 0},
                {"low_register_replay_patches_removed", readableCandidate ? readableCandidate->low_register_replay_patches_removed : 0},
                {"replay_branches_collapsed", readableCandidate ? readableCandidate->replay_branches_collapsed : 0},
                {"linear_replay_metadata_patches_removed", readableCandidate ? readableCandidate->linear_replay_metadata_patches_removed : 0},
                {"refinement_passes", readableCandidate ? readableCandidate->refinement_passes : 0},
                {"residual_bindings_renamed", readableCandidate ? readableCandidate->residual_bindings_renamed : 0},
                {"residual_semantic_role_names", readableCandidate ? readableCandidate->residual_semantic_role_names : 0},
                {"residual_generic_fallback_names", readableCandidate ? readableCandidate->residual_generic_fallback_names : 0},
                {"residual_generated_merge_names", readableCandidate ? readableCandidate->residual_generated_merge_names : 0},
                {"unused_local_declarations_removed", readableCandidate ? readableCandidate->unused_local_declarations_removed : 0},
                {"guard_clauses_flattened", readableCandidate ? readableCandidate->guard_clauses_flattened : 0},
                {"redundant_parentheses_removed", readableCandidate ? readableCandidate->redundant_parentheses_removed : 0},
                {"callback_aliases_promoted", readableCandidate ? readableCandidate->callback_aliases_promoted : 0},
                {"residual_reasons", readableCandidate ? readableCandidate->residual_reasons : json::object()},
                {"fallback_available", fs::exists(semanticCandidatePath)},
            });
            if (!structuredCandidate->decoded_strings.empty())
                writeJson(constantsPath, {
                    {"version", 2},
                    {"encoding", "wearedevs-custom-base64"},
                    {"constants", constantRows},
                    {"prometheus_encrypted_strings", structuredCandidate->decoded_strings},
                });
        }
        else
            report["reconstruction_candidate"] = {{"available", false}, {"compiled", false}, {"runtime_verified", false}};

        writeJson(irPath, {
            {"version", 2},
            {"kind", "typed-semantic-ir"},
            {"status", runtimeTrace.phase_split ? "payload_isolated" : "vm_cfg_recovered"},
            {"prototypes", prototypeRows},
            {"basic_blocks", blockRows},
            {"registers", normalizer.registerRows()},
            {"upvalue_cells", cellsLocal ? json::array({{{"storage", "cells"}, {"capture_vector", "capture_ids"}}}) : json::array()},
            {"frame", {{"program_counter", "pc"}, {"arguments", "arguments"}, {"captures", "capture_ids"}, {"owner", "frame_owner"},
                          {"environment", environmentLocal ? json("environment") : json(nullptr)}}},
            {"template_recovery", {{"all_blocks", allTemplateRecoveries.toJson()},
                                      {"reachable_blocks", reachableTemplateRecoveries.toJson()},
                                      {"payload_blocks", payloadTemplateRecoveries.toJson()}}},
            {"trace", report["runtime_trace"]},
            {"notes", json::array({runtimeTrace.phase_split
                                       ? "A bounded offline trace isolated the hot fingerprint prelude from the payload phase."
                                       : "No validated runtime phase split was available; block classifications are conservative.",
                          "Dispatcher statements are normalized into typed operations; prototype-local SSA and structured emission are not complete.",
                          "Opaque environment reads used as clean-environment return sentinels are represented as returns."})},
        });

        std::ostringstream disassembly;
        disassembly << "Alex native WeAreDevs v1 structural disassembly\n";
        disassembly << "constants=" << envelope.constants.size() << " states=" << blocks.size() << " reachable=" << reachable.size() << " entries="
                    << prototypeRows.size() << "\n\n";
        for (const auto& [state, block] : blocks)
        {
            disassembly << "state " << state << (reachable.contains(state) ? " [reachable]" : "") << " ->";
            for (int64_t target : block.outgoing)
                disassembly << ' ' << target;
            if (block.dynamic_transitions)
                disassembly << " +" << block.dynamic_transitions << (isReturnSentinel(block, indexedWrites.writes) ? " return-sentinel" : " dynamic");
            disassembly << "\n  " << sourceView.slice(block.body->location, 1000) << "\n\n";
        }
        writeFile(disassemblyPath, disassembly.str());

        std::optional<std::string> exactSource;
        size_t sourceBearingCandidates = 0;
        for (const std::string& value : envelope.constants)
            if (plausibleSource(value) && compiles(value))
                ++sourceBearingCandidates;
        report["passes"].push_back({
            {"stage", "source_search"},
            {"ok", true},
            {"compilable_candidates", sourceBearingCandidates},
            {"vm_structure_matches", 0},
            {"promoted", false},
        });

        const size_t reachableEntries = static_cast<size_t>(std::count_if(prototypeEntries.begin(), prototypeEntries.end(), [&](int64_t entry) {
            return blocks.contains(entry);
        }));
        report["coverage"] = {
            {"prototypes", {{"total", reachableEntries}, {"reconstructed", exactSource ? 1 : 0}}},
            {"blocks", {{"total", reachable.size()}, {"recovered", reachable.size()}, {"lifted", 0}}},
            {"instructions", {{"total", instructionCount}, {"lifted", 0}}},
            {"normalized_instructions", normalizedInstructionCount},
            {"unsupported_normalized_instructions", unsupportedInstructionCount},
            {"constants", {{"total", envelope.constants.size()}, {"decoded", envelope.constants.size()}}},
            {"unresolved_operations", instructionCount},
            {"payload_instruction_candidates", payloadInstructionCount},
            {"protector_instructions_classified", protectorInstructionCount},
            {"phase_classification", runtimeTrace.phase_split ? "trace_backed" : "unavailable"},
            {"dynamic_transitions", dynamicTransitions},
            {"return_sentinels", returnSentinelTransitions},
            {"unresolved_control_edges", dynamicTransitions - returnSentinelTransitions},
            {"instruction_measurement", "reachable_ast_statements"},
            {"prometheus_templates", {{"scope", "payload_blocks"},
                                         {"recoveries", payloadTemplateRecoveries.toJson()},
                                         {"measurement", "compiler_transport_operations"}}},
        };
        report["passes"].push_back({{"stage", "cfg"}, {"ok", !blocks.empty()}, {"states", blocks.size()}, {"reachable", reachable.size()}});
        report["passes"].back()["prototype_call_candidates"] = prototypeCallCandidates;
        report["passes"].back()["closure_factories"] = closureFactories.size();
        report["passes"].back()["entry_discovery_rounds"] = entryRounds;
        report["passes"].push_back({{"stage", "lift"}, {"ok", exactSource.has_value()}, {"normalized_instructions", normalizedInstructionCount},
            {"unsupported_normalized_instructions", unsupportedInstructionCount}, {"lifted_instructions", candidateCompiled ? payloadInstructionCount : 0},
            {"candidate_compiled", candidateCompiled}, {"unresolved", candidateCompiled ? 0 : instructionCount},
            {"compiler_templates", payloadTemplateRecoveries.toJson()}});
        report["verification"] = {
            {"compiled", exactSource.has_value()},
            {"input_parsed", true},
            {"decoded_wrapper_compiled", compiles(envelope.rewritten)},
            {"output", {{"available", exactSource.has_value()}, {"compiled", exactSource.has_value()},
                           {"candidate_available", candidateCompiled}, {"candidate_compiled", candidateCompiled}}},
            {"runtime", {{"attempted", false}, {"equivalent", nullptr}, {"reason", "no complete reconstructed source"}}},
        };

        fs::path sourceOutput;
        if (exactSource && options.mode != "disassemble")
        {
            sourceOutput = options.output_dir / "source_exact.luau";
            writeFile(sourceOutput, *exactSource + (exactSource->ends_with('\n') ? "" : "\n"));
            report["status"] = "recovered_exact";
            report["exact_source"] = true;
            result.exit_code = 0;
        }
        else if (options.mode == "disassemble")
        {
            report["status"] = "disassembled";
            result.exit_code = 0;
        }
        else
        {
            report["status"] = "blocked";
            report["diagnostics"].push_back({
                {"stage", "lift"},
                {"code", "semantic_lift_incomplete"},
                {"message", runtimeTrace.phase_split
                                ? "the fingerprint prelude was isolated from the payload, but the payload has not yet been structured into verified Luau; no source was emitted"
                                : "the randomized VM CFG was recovered, but reachable VM operations remain unresolved; no source was emitted"},
                {"details", {{"reachable_blocks", reachable.size()}, {"unresolved_instructions", instructionCount}, {"dynamic_transitions", dynamicTransitions},
                                {"return_sentinels", returnSentinelTransitions},
                                {"unresolved_control_edges", dynamicTransitions - returnSentinelTransitions},
                                {"protector_events_collapsed", runtimeTrace.protector_events},
                                {"payload_events", runtimeTrace.payload_events},
                                {"payload_root_states", runtimeTrace.payload_root_states.size()}}},
            });
            result.exit_code = 2;
        }
        writeJson(mapPath, {
            {"version", 2},
            {"output", sourceOutput.empty() ? (candidateCompiled ? json(candidatePath.filename().string()) : json(nullptr)) : json(sourceOutput.filename().string())},
            {"verified", !sourceOutput.empty()},
            {"statements", structuredCandidate && candidateCompiled ? structuredCandidate->mapping : json::array()},
        });

        json graphNodes = json::array();
        graphNodes.push_back({{"id", sha256(source)}, {"kind", "luau_source"}, {"bytes", source.size()}, {"path", "input.luau"}, {"provenance", "input"},
                              {"source_bearing", true}});
        graphNodes.push_back(artifactNode(options.output_dir, decodedPath, "luau_source", "wearedevs_envelope_decode", false));
        graphNodes.push_back(artifactNode(options.output_dir, irPath, "json", "native_cfg_lift", false));
        if (!sourceOutput.empty())
            graphNodes.push_back(artifactNode(options.output_dir, sourceOutput, "luau_source", "decoded_source_bearing_constant", true));
        writeJson(graphPath, {
            {"version", 2},
            {"nodes", graphNodes},
            {"edges", json::array({{{"from", sha256(source)}, {"to", graphNodes[1]["id"]}, {"relation", "decode"}},
                                     {{"from", graphNodes[1]["id"]}, {"to", graphNodes[2]["id"]}, {"relation", "cfg_recovery"}}})},
        });
        report["artifacts"] = {
            {"source", sourceOutput.empty() ? json(nullptr) : json(sourceOutput.filename().string())},
            {"candidate", candidateCompiled ? json(candidatePath.filename().string()) : json(nullptr)},
            {"semantic_candidate", fs::exists(semanticCandidatePath) ? json(semanticCandidatePath.filename().string()) : json(nullptr)},
            {"internal_state_machine", fs::exists(internalStateMachinePath) ? json(internalStateMachinePath.filename().string()) : json(nullptr)},
            {"disassembly", disassemblyPath.filename().string()},
            {"semantic_ir", irPath.filename().string()},
            {"cfg", cfgPath.filename().string()},
            {"constants", constantsPath.filename().string()},
            {"graph", graphPath.filename().string()},
            {"reconstruction_map", mapPath.filename().string()},
            {"trace_probe", traceProbePath.filename().string()},
        };
        report["structural_metrics"] = {
            {"input", {{"nodes", inputMetrics.nodes}, {"functions", inputMetrics.functions}, {"whiles", inputMetrics.whiles}}},
            {"decoded", {{"nodes", decodedMetrics.nodes}, {"functions", decodedMetrics.functions}, {"whiles", decodedMetrics.whiles},
                             {"conditionals", decodedMetrics.conditionals}}},
        };
    }
    catch (const std::exception& error)
    {
        report["status"] = "blocked";
        report["diagnostics"].push_back({{"stage", "decode"}, {"code", "native_analysis_failed"}, {"message", error.what()}});
        result.exit_code = 2;
        writeEmptyArtifacts();
    }

    writeJson(reportPath, report);
    result.report = report;
    return result;
}

} // namespace alex::deobfuscator
