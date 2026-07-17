#include "passes/flow.hpp"
#include "passes/names.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <string_view>
#include <vector>

namespace alex::deobfuscator::readable
{
namespace
{

using json = nlohmann::json;

constexpr int64_t ExitState = std::numeric_limits<int64_t>::min();

struct SourceLine
{
    std::string text;
    size_t origin = 0;
};

struct OutputLine
{
    std::string text;
    std::optional<size_t> origin;
    std::set<int64_t> states;
};

struct ScalarFunctionSpan
{
    size_t opener = 0;
    size_t end = 0;
    size_t indent = 0;
};

struct LexicalCaptureIndex
{
    size_t topLevel = 0;
    std::vector<size_t> owner;
    std::vector<std::map<std::string, size_t>> earliest;

    bool capturedBefore(size_t line, std::string_view name, size_t before) const
    {
        if (line >= owner.size())
            return true;
        const auto found = earliest[owner[line]].find(std::string(name));
        return found != earliest[owner[line]].end() && found->second < before;
    }
};

std::optional<std::vector<ScalarFunctionSpan>> scalarFunctionSpans(const std::vector<OutputLine>& lines);
LexicalCaptureIndex buildLexicalCaptureIndex(
    const std::vector<OutputLine>& lines, const std::vector<ScalarFunctionSpan>& spans);

enum class TerminatorKind
{
    Goto,
    Branch,
    Return,
    Unknown,
};

struct Block
{
    int64_t state = 0;
    std::vector<SourceLine> body;
    TerminatorKind terminator = TerminatorKind::Unknown;
    int64_t first = ExitState;
    int64_t second = ExitState;
    std::string condition;
    bool explicitReturn = false;
    bool returnsResults = false;
};

struct Region
{
    size_t begin = 0;
    size_t end = 0;
    std::string indent;
    int64_t entry = 0;
    SourceLine stateDeclaration;
    std::map<int64_t, Block> blocks;
    bool needsEpilogue = false;
    bool emitStateDeclaration = true;
    bool discardSafeEmptyBranches = false;
    bool implicitExitReturnsNil = false;
    std::optional<int64_t> semanticPrototype;
};

struct LoopInfo
{
    int64_t header = 0;
    std::set<int64_t> nodes;
    std::optional<int64_t> exit;
    std::set<int64_t> exits;
};

std::string_view trimView(std::string_view value)
{
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r'))
        value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r'))
        value.remove_suffix(1);
    return value;
}

std::string trim(std::string_view value)
{
    return std::string(trimView(value));
}

size_t indentation(std::string_view value)
{
    size_t result = 0;
    while (result < value.size() && value[result] == ' ')
        ++result;
    return result;
}

std::optional<int64_t> parseInteger(std::string_view value)
{
    value = trimView(value);
    if (value.empty())
        return std::nullopt;
    int64_t result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size())
        return std::nullopt;
    return result;
}

std::optional<int64_t> parseBranchHeader(std::string_view value)
{
    value = trimView(value);
    constexpr std::string_view First = "if __state == ";
    constexpr std::string_view Next = "elseif __state == ";
    constexpr std::string_view Suffix = " then";
    if (value.size() <= Suffix.size() || !value.ends_with(Suffix))
        return std::nullopt;
    if (value.starts_with(First))
        value.remove_prefix(First.size());
    else if (value.starts_with(Next))
        value.remove_prefix(Next.size());
    else
        return std::nullopt;
    value.remove_suffix(Suffix.size());
    return parseInteger(value);
}

std::optional<int64_t> parseEqualityBranchHeader(
    std::string_view value, std::string_view variable, bool first)
{
    value = trimView(value);
    const std::string prefix = std::string(first ? "if " : "elseif ") + std::string(variable) + " == ";
    constexpr std::string_view Suffix = " then";
    if (!value.starts_with(prefix) || !value.ends_with(Suffix))
        return std::nullopt;
    value.remove_prefix(prefix.size());
    value.remove_suffix(Suffix.size());
    return parseInteger(value);
}

std::vector<SourceLine> splitLines(std::string_view source)
{
    std::vector<SourceLine> lines;
    size_t begin = 0;
    size_t number = 1;
    while (begin < source.size())
    {
        const size_t end = source.find('\n', begin);
        const size_t length = end == std::string_view::npos ? source.size() - begin : end - begin;
        std::string line(source.substr(begin, length));
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        lines.push_back({std::move(line), number++});
        if (end == std::string_view::npos)
            break;
        begin = end + 1;
    }
    if (source.empty())
        lines.push_back({"", 1});
    return lines;
}

bool parseTerminator(Block& block)
{
    while (!block.body.empty() && trimView(block.body.back().text).empty())
        block.body.pop_back();
    if (block.body.empty())
        return false;
    constexpr std::string_view InlineStop = "; __state = nil";
    constexpr std::string_view Assignment = "__state = ";
    std::optional<size_t> transitionIndex;
    bool inlineStop = false;
    for (size_t index = 0; index < block.body.size(); ++index)
    {
        const std::string statement = trim(block.body[index].text);
        if (statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' '))
        {
            block.body.resize(index + 1);
            block.terminator = TerminatorKind::Return;
            block.explicitReturn = true;
            return true;
        }
        if (statement.starts_with(Assignment) || statement.ends_with(InlineStop))
        {
            transitionIndex = index;
            inlineStop = statement.ends_with(InlineStop);
        }
    }
    if (!transitionIndex)
        return false;

    constexpr std::string_view SplitOrStatementPrefix = "__state = (__state or ";
    const std::string finalTransition = trim(block.body[*transitionIndex].text);
    if (finalTransition.starts_with(SplitOrStatementPrefix) && finalTransition.ends_with(')'))
    {
        auto resolveTarget = [&](std::string_view expression, size_t before) -> std::optional<int64_t> {
            expression = trimView(expression);
            if (auto value = parseInteger(expression))
                return value;
            const std::string prefix = std::string(expression) + " = ";
            for (size_t index = before; index > 0; --index)
            {
                const std::string statement = trim(block.body[index - 1].text);
                if (statement.starts_with(prefix))
                    return parseInteger(std::string_view(statement).substr(prefix.size()));
            }
            return std::nullopt;
        };
        auto second = resolveTarget(std::string_view(finalTransition).substr(
            SplitOrStatementPrefix.size(), finalTransition.size() - SplitOrStatementPrefix.size() - 1), *transitionIndex);
        if (!second)
            return false;
        for (size_t index = *transitionIndex; index > 0; --index)
        {
            const std::string previous = trim(block.body[index - 1].text);
            constexpr std::string_view SplitAndPrefix = "__state = (";
            if (!previous.starts_with(SplitAndPrefix) || !previous.ends_with(')'))
                continue;
            const std::string_view inner(previous.data() + SplitAndPrefix.size(), previous.size() - SplitAndPrefix.size() - 1);
            const size_t separator = inner.rfind(" and ");
            if (separator == std::string_view::npos)
                continue;
            auto first = resolveTarget(inner.substr(separator + 5), index - 1);
            if (!first)
                continue;
            block.body.erase(block.body.begin() + static_cast<std::ptrdiff_t>(*transitionIndex));
            block.body[index - 1].text = "__state = " + std::string(inner.substr(0, separator));
            block.terminator = TerminatorKind::Branch;
            block.condition = "__state";
            block.first = *first;
            block.second = *second;
            return true;
        }
        return false;
    }

    std::string transition = trim(block.body[*transitionIndex].text);
    if (inlineStop)
    {
        transition = "__state = nil";
        std::string prefix = trim(block.body[*transitionIndex].text);
        prefix.resize(prefix.size() - InlineStop.size());
        block.body[*transitionIndex].text = std::move(prefix);
    }
    else
    {
        bool usedAfterTransition = false;
        for (size_t index = *transitionIndex + 1; index < block.body.size(); ++index)
            if (block.body[index].text.find("__state") != std::string::npos)
                usedAfterTransition = true;
        if (!usedAfterTransition)
            block.body.erase(block.body.begin() + static_cast<std::ptrdiff_t>(*transitionIndex));
    }

    if (!transition.starts_with(Assignment))
        return false;
    std::string_view value(transition);
    value.remove_prefix(Assignment.size());
    if (trimView(value) == "nil")
    {
        block.terminator = TerminatorKind::Return;
        for (const SourceLine& line : block.body)
            if (trimView(line.text).starts_with("__results = "))
                block.returnsResults = true;
        return true;
    }
    const std::string renderedValue(value);
    constexpr std::string_view SplitOrPrefix = "(__state or ";
    if (renderedValue.starts_with(SplitOrPrefix) && renderedValue.ends_with(')'))
    {
        auto second = parseInteger(std::string_view(renderedValue).substr(SplitOrPrefix.size(), renderedValue.size() - SplitOrPrefix.size() - 1));
        if (!second)
            return false;
        for (size_t index = block.body.size(); index > 0; --index)
        {
            const std::string previous = trim(block.body[index - 1].text);
            constexpr std::string_view SplitAndPrefix = "__state = (";
            if (!previous.starts_with(SplitAndPrefix) || !previous.ends_with(')'))
                continue;
            const std::string_view inner(previous.data() + SplitAndPrefix.size(), previous.size() - SplitAndPrefix.size() - 1);
            const size_t separator = inner.rfind(" and ");
            if (separator == std::string_view::npos)
                continue;
            auto first = parseInteger(inner.substr(separator + 5));
            if (!first)
                continue;
            block.body.erase(block.body.begin() + static_cast<std::ptrdiff_t>(index - 1));
            block.terminator = TerminatorKind::Branch;
            block.condition = std::string(inner.substr(0, separator));
            block.first = *first;
            block.second = *second;
            return true;
        }
        return false;
    }
    if (auto target = parseInteger(value))
    {
        block.terminator = TerminatorKind::Goto;
        block.first = *target;
        return true;
    }

    static const std::regex Conditional(R"(^\(\((.+) and (-?[0-9]+)\) or (-?[0-9]+)\)$)");
    static const std::regex LooseConditional(R"(^\((.+) and (-?[0-9]+) or (-?[0-9]+)\)$)");
    std::smatch match;
    const std::string rendered(value);
    if (std::regex_match(rendered, match, Conditional) || std::regex_match(rendered, match, LooseConditional))
    {
        auto first = parseInteger(match[2].str());
        auto second = parseInteger(match[3].str());
        if (!first || !second)
            return false;
        block.terminator = TerminatorKind::Branch;
        block.condition = match[1].str();
        block.first = *first;
        block.second = *second;
        return true;
    }
    return false;
}

std::optional<int64_t> parseConstantIntegerExpression(std::string_view expression)
{
    size_t cursor = 0;
    const auto skipWhitespace = [&]() {
        while (cursor < expression.size() && std::isspace(static_cast<unsigned char>(expression[cursor])))
            ++cursor;
    };
    std::function<std::optional<int64_t>()> parseExpression;
    const auto parsePrimary = [&]() -> std::optional<int64_t> {
        skipWhitespace();
        if (cursor >= expression.size())
            return std::nullopt;
        if (expression[cursor] == '(')
        {
            ++cursor;
            const std::optional<int64_t> nested = parseExpression();
            skipWhitespace();
            if (!nested || cursor >= expression.size() || expression[cursor] != ')')
                return std::nullopt;
            ++cursor;
            return nested;
        }
        const size_t begin = cursor;
        if (expression[cursor] == '+' || expression[cursor] == '-')
            ++cursor;
        const size_t digits = cursor;
        while (cursor < expression.size() && std::isdigit(static_cast<unsigned char>(expression[cursor])))
            ++cursor;
        if (digits == cursor)
            return std::nullopt;
        return parseInteger(expression.substr(begin, cursor - begin));
    };
    parseExpression = [&]() -> std::optional<int64_t> {
        std::optional<int64_t> value = parsePrimary();
        if (!value)
            return std::nullopt;
        while (true)
        {
            skipWhitespace();
            if (cursor >= expression.size() || (expression[cursor] != '+' && expression[cursor] != '-'))
                return value;
            const char operation = expression[cursor++];
            const std::optional<int64_t> right = parsePrimary();
            if (!right)
                return std::nullopt;
            int64_t combined = 0;
            const bool overflow = operation == '+'
                ? __builtin_add_overflow(*value, *right, &combined)
                : __builtin_sub_overflow(*value, *right, &combined);
            if (overflow)
                return std::nullopt;
            value = combined;
        }
    };
    const std::optional<int64_t> result = parseExpression();
    skipWhitespace();
    return result && cursor == expression.size() ? result : std::nullopt;
}

std::optional<int64_t> parsePcTarget(std::string_view statement)
{
    statement = trimView(statement);
    constexpr std::string_view Assignment = "pc = ";
    if (!statement.starts_with(Assignment))
        return std::nullopt;
    statement.remove_prefix(Assignment.size());
    if (trimView(statement) == "nil")
        return ExitState;
    return parseConstantIntegerExpression(statement);
}

struct ReplayTransition
{
    std::string expression;
    std::vector<int64_t> targets;
};

std::optional<ReplayTransition> parseReplayTransition(std::string_view expression)
{
    expression = trimView(expression);
    constexpr std::string_view ActivationPrefix = "replay_activation_transition(";
    constexpr std::string_view TracePrefix = "replay_transition(";
    std::string_view prefix;
    size_t expectedFields = 0;
    size_t sequenceField = 0;
    if (expression.starts_with(ActivationPrefix))
    {
        prefix = ActivationPrefix;
        expectedFields = 5;
        sequenceField = 3;
    }
    else if (expression.starts_with(TracePrefix))
    {
        prefix = TracePrefix;
        expectedFields = 3;
        sequenceField = 2;
    }
    else
        return std::nullopt;
    if (!expression.ends_with(')'))
        return std::nullopt;

    std::string_view arguments = expression.substr(prefix.size(), expression.size() - prefix.size() - 1);
    std::vector<std::string_view> fields;
    size_t begin = 0;
    int depth = 0;
    for (size_t index = 0; index < arguments.size(); ++index)
    {
        const char ch = arguments[index];
        if (ch == '{' || ch == '[' || ch == '(')
            ++depth;
        else if (ch == '}' || ch == ']' || ch == ')')
            --depth;
        else if (ch == ',' && depth == 0)
        {
            fields.push_back(trimView(arguments.substr(begin, index - begin)));
            begin = index + 1;
        }
        if (depth < 0)
            return std::nullopt;
    }
    if (depth != 0)
        return std::nullopt;
    fields.push_back(trimView(arguments.substr(begin)));
    if (fields.size() != expectedFields || fields[sequenceField].size() < 2 ||
        fields[sequenceField].front() != '{' || fields[sequenceField].back() != '}')
        return std::nullopt;

    ReplayTransition result;
    result.expression.assign(expression);
    const std::string_view sequences = fields[sequenceField];
    for (size_t index = 0; index < sequences.size();)
    {
        const char ch = sequences[index];
        if (std::isdigit(static_cast<unsigned char>(ch)) ||
            (ch == '-' && index + 1 < sequences.size() && std::isdigit(static_cast<unsigned char>(sequences[index + 1]))))
        {
            int64_t target = 0;
            const char* first = sequences.data() + index;
            const char* last = sequences.data() + sequences.size();
            const auto parsed = std::from_chars(first, last, target);
            if (parsed.ec != std::errc{})
                return std::nullopt;
            index = static_cast<size_t>(parsed.ptr - sequences.data());
            if (std::find(result.targets.begin(), result.targets.end(), target) == result.targets.end())
                result.targets.push_back(target);
            continue;
        }
        if (ch != '{' && ch != '}' && ch != ',' && ch != ' ' && ch != '\t')
            return std::nullopt;
        ++index;
    }
    if (result.targets.empty() || result.targets.size() > 2)
        return std::nullopt;
    return result;
}

bool parseLuraphTerminator(Block& block)
{
    while (!block.body.empty() && trimView(block.body.back().text).empty())
        block.body.pop_back();
    if (block.body.empty())
        return false;

    const size_t count = block.body.size();
    if (count >= 5)
    {
        const SourceLine& opener = block.body[count - 5];
        const SourceLine& whenTrue = block.body[count - 4];
        const SourceLine& alternative = block.body[count - 3];
        const SourceLine& whenFalse = block.body[count - 2];
        const SourceLine& closer = block.body[count - 1];
        const std::string_view header = trimView(opener.text);
        if (indentation(opener.text) == 0 && header.starts_with("if ") && header.ends_with(" then") &&
            indentation(whenTrue.text) == 2 && indentation(alternative.text) == 0 &&
            trimView(alternative.text) == "else" && indentation(whenFalse.text) == 2 &&
            indentation(closer.text) == 0 && trimView(closer.text) == "end")
        {
            const auto first = parsePcTarget(whenTrue.text);
            const auto second = parsePcTarget(whenFalse.text);
            if (first && second)
            {
                const std::string condition(header.substr(3, header.size() - 3 - 5));
                block.body.resize(count - 5);
                block.terminator = TerminatorKind::Branch;
                block.condition = condition;
                block.first = *first;
                block.second = *second;
                return true;
            }
        }
    }

    const SourceLine& final = block.body.back();
    if (indentation(final.text) != 0)
        return false;
    const std::string statement = trim(final.text);
    if (statement == "return" || statement.starts_with("return "))
    {
        block.terminator = TerminatorKind::Return;
        block.explicitReturn = true;
        return true;
    }
    const auto target = parsePcTarget(statement);
    if (target)
    {
        block.body.pop_back();
        if (*target == ExitState)
            block.terminator = TerminatorKind::Return;
        else
        {
            block.terminator = TerminatorKind::Goto;
            block.first = *target;
        }
        return true;
    }

    constexpr std::string_view Assignment = "pc = ";
    if (!statement.starts_with(Assignment))
        return false;
    const auto replay = parseReplayTransition(std::string_view(statement).substr(Assignment.size()));
    if (!replay)
        return false;
    if (replay->targets.size() == 1)
    {
        block.body.back().text = replay->expression;
        block.terminator = TerminatorKind::Goto;
        block.first = replay->targets.front();
        return true;
    }

    const std::string targetName = "replay_target_" + std::to_string(block.state);
    block.body.back().text = "local " + targetName + " = " + replay->expression;
    block.terminator = TerminatorKind::Branch;
    block.condition = targetName + " == " + std::to_string(replay->targets.front());
    block.first = replay->targets.front();
    block.second = replay->targets.back();
    return true;
}

std::optional<int64_t> semanticStepPrototype(std::string_view statement)
{
    statement = trimView(statement);
    constexpr std::string_view Prefix = "semantic_step(";
    constexpr std::string_view Suffix = ", pc)";
    if (!statement.starts_with(Prefix) || !statement.ends_with(Suffix))
        return std::nullopt;
    statement.remove_prefix(Prefix.size());
    statement.remove_suffix(Suffix.size());
    return parseInteger(statement);
}

bool parseLuraphCases(const std::vector<SourceLine>& lines, size_t& cursor, Region& region,
    size_t caseIndent, size_t bodyIndent, std::optional<int64_t> bucket, std::string& failure)
{
    bool firstCase = true;
    while (cursor < lines.size() && indentation(lines[cursor].text) == caseIndent)
    {
        const auto state = parseEqualityBranchHeader(lines[cursor].text, "pc", firstCase);
        if (!state)
            break;
        if (*state < 0)
        {
            failure = "state_value";
            return false;
        }
        if (bucket && (*state == 0 ? 0 : (*state - 1) / 64) != *bucket)
        {
            failure = "bucket_case_mismatch";
            return false;
        }

        Block block;
        block.state = *state;
        ++cursor;
        while (cursor < lines.size())
        {
            if (indentation(lines[cursor].text) == caseIndent)
            {
                const std::string_view current = trimView(lines[cursor].text);
                if (parseEqualityBranchHeader(current, "pc", false) || current == "else")
                    break;
            }
            SourceLine line = lines[cursor++];
            if (trimView(line.text).empty())
                line.text.clear();
            else
            {
                if (indentation(line.text) < bodyIndent)
                {
                    failure = "case_indentation";
                    return false;
                }
                line.text.erase(0, bodyIndent);
            }
            block.body.push_back(std::move(line));
        }
        if (!parseLuraphTerminator(block))
        {
            failure = "terminator_" + std::to_string(block.state);
            return false;
        }
        if (!region.blocks.emplace(block.state, std::move(block)).second)
        {
            failure = "duplicate_state";
            return false;
        }
        firstCase = false;
    }
    if (firstCase || cursor + 2 >= lines.size() || indentation(lines[cursor].text) != caseIndent ||
        trimView(lines[cursor].text) != "else" || indentation(lines[cursor + 1].text) != bodyIndent ||
        trimView(lines[cursor + 1].text) != "return nil" || indentation(lines[cursor + 2].text) != caseIndent ||
        trimView(lines[cursor + 2].text) != "end")
    {
        failure = "case_fallback";
        return false;
    }
    cursor += 3;
    return true;
}

std::optional<Region> parseLuraphRegion(
    const std::vector<SourceLine>& lines, size_t begin, std::string* failure)
{
    auto reject = [&](std::string reason) -> std::optional<Region> {
        if (failure)
            *failure = std::move(reason);
        return std::nullopt;
    };
    if (begin + 8 >= lines.size())
        return reject("wrapper_end");

    constexpr std::string_view StatePrefix = "local pc = ";
    const std::string_view declaration = trimView(lines[begin].text);
    if (!declaration.starts_with(StatePrefix))
        return std::nullopt;
    const auto entry = parseInteger(declaration.substr(StatePrefix.size()));
    if (!entry || trimView(lines[begin + 1].text) != "while pc ~= nil do")
        return reject("header");

    Region region;
    region.begin = begin;
    region.indent.assign(indentation(lines[begin].text), ' ');
    region.entry = *entry;
    region.stateDeclaration = lines[begin];
    region.emitStateDeclaration = false;
    region.discardSafeEmptyBranches = true;
    region.implicitExitReturnsNil = true;

    const size_t wrapperIndent = region.indent.size() + 2;
    size_t cursor = begin + 2;
    const auto semanticPrototype = semanticStepPrototype(lines[cursor].text);
    if (indentation(lines[cursor].text) != wrapperIndent || !semanticPrototype || *semanticPrototype < 0)
        return reject("semantic_step");
    region.semanticPrototype = *semanticPrototype;
    ++cursor;
    if (cursor >= lines.size() || indentation(lines[cursor].text) != wrapperIndent)
        return reject("dispatcher");

    const bool bucketed = trimView(lines[cursor].text) == "local dispatch_bucket = math.floor((pc - 1) / 64)";
    if (!bucketed)
    {
        std::string parseFailure;
        if (!parseLuraphCases(lines, cursor, region, wrapperIndent, wrapperIndent + 2, std::nullopt, parseFailure))
            return reject(std::move(parseFailure));
        if (cursor + 1 >= lines.size() || indentation(lines[cursor].text) != region.indent.size() ||
            trimView(lines[cursor].text) != "end" || indentation(lines[cursor + 1].text) != region.indent.size() ||
            trimView(lines[cursor + 1].text) != "return nil")
            return reject("wrapper_end");
        cursor += 2;
    }
    else
    {
        const size_t caseIndent = wrapperIndent + 2;
        const size_t bodyIndent = caseIndent + 2;
        ++cursor;
        bool firstBucket = true;
        while (cursor < lines.size() && indentation(lines[cursor].text) == wrapperIndent)
        {
            const auto bucket = parseEqualityBranchHeader(lines[cursor].text, "dispatch_bucket", firstBucket);
            if (!bucket)
                break;
            if (*bucket < 0)
                return reject("bucket_value");
            ++cursor;

            std::string parseFailure;
            if (!parseLuraphCases(lines, cursor, region, caseIndent, bodyIndent, *bucket, parseFailure))
                return reject(std::move(parseFailure));
            firstBucket = false;
        }

        if (firstBucket || cursor + 4 >= lines.size() || indentation(lines[cursor].text) != wrapperIndent ||
            trimView(lines[cursor].text) != "else" || indentation(lines[cursor + 1].text) != caseIndent ||
            trimView(lines[cursor + 1].text) != "return nil" || indentation(lines[cursor + 2].text) != wrapperIndent ||
            trimView(lines[cursor + 2].text) != "end" || indentation(lines[cursor + 3].text) != region.indent.size() ||
            trimView(lines[cursor + 3].text) != "end" || indentation(lines[cursor + 4].text) != region.indent.size() ||
            trimView(lines[cursor + 4].text) != "return nil")
            return reject("wrapper_end");
        cursor += 5;
    }
    region.end = cursor;

    for (auto& [state, block] : region.blocks)
    {
        (void)state;
        if (block.terminator == TerminatorKind::Goto && !region.blocks.contains(block.first))
            block.first = ExitState;
        if (block.terminator == TerminatorKind::Branch && !region.blocks.contains(block.first))
            block.first = ExitState;
        if (block.terminator == TerminatorKind::Branch && !region.blocks.contains(block.second))
            block.second = ExitState;
    }
    return region;
}

std::optional<Region> parseRegion(const std::vector<SourceLine>& lines, size_t begin, std::string* failure = nullptr)
{
    if (begin + 4 >= lines.size())
        return std::nullopt;
    const std::string_view declaration = trimView(lines[begin].text);
    constexpr std::string_view StatePrefix = "local __state = ";
    if (declaration.starts_with("local pc = "))
        return parseLuraphRegion(lines, begin, failure);
    if (!declaration.starts_with(StatePrefix))
        return std::nullopt;
    auto entry = parseInteger(declaration.substr(StatePrefix.size()));
    if (!entry || trimView(lines[begin + 1].text) != "while __state ~= nil do")
        return std::nullopt;

    Region region;
    region.begin = begin;
    region.indent.assign(indentation(lines[begin].text), ' ');
    region.entry = *entry;
    region.stateDeclaration = lines[begin];
    const size_t branchIndent = region.indent.size() + 4;
    size_t cursor = begin + 2;
    while (cursor < lines.size())
    {
        if (indentation(lines[cursor].text) != branchIndent)
        {
            if (failure)
                *failure = "branch_indentation";
            return std::nullopt;
        }
        auto state = parseBranchHeader(lines[cursor].text);
        if (!state)
            break;
        Block block;
        block.state = *state;
        ++cursor;
        while (cursor < lines.size())
        {
            if (indentation(lines[cursor].text) == branchIndent)
            {
                const std::string_view current = trimView(lines[cursor].text);
                if (parseBranchHeader(current) || current == "else")
                    break;
            }
            SourceLine line = lines[cursor++];
            line.text = trimView(line.text).empty() ? std::string() : std::string(trimView(line.text));
            block.body.push_back(std::move(line));
        }
        if (!parseTerminator(block))
        {
            if (failure)
                *failure = "terminator_" + std::to_string(block.state);
            return std::nullopt;
        }
        if (!region.blocks.emplace(block.state, std::move(block)).second)
        {
            if (failure)
                *failure = "duplicate_state";
            return std::nullopt;
        }
    }
    if (region.blocks.empty() || cursor >= lines.size() || trimView(lines[cursor].text) != "else" ||
        indentation(lines[cursor].text) != branchIndent)
    {
        if (failure)
            *failure = "fallback_branch";
        return std::nullopt;
    }

    ++cursor;
    while (cursor < lines.size() && !(indentation(lines[cursor].text) == branchIndent && trimView(lines[cursor].text) == "end"))
        ++cursor;
    if (cursor + 1 >= lines.size() || trimView(lines[cursor].text) != "end" ||
        indentation(lines[cursor + 1].text) != region.indent.size() || trimView(lines[cursor + 1].text) != "end")
    {
        if (failure)
            *failure = "wrapper_end";
        return std::nullopt;
    }
    cursor += 2;

    if (cursor + 2 < lines.size() && indentation(lines[cursor].text) == region.indent.size() &&
        trimView(lines[cursor].text) == "if __results ~= nil then" &&
        trimView(lines[cursor + 1].text) == "return table.unpack(__results)" &&
        indentation(lines[cursor + 2].text) == region.indent.size() && trimView(lines[cursor + 2].text) == "end")
        cursor += 3;
    region.end = cursor;

    for (auto& [state, block] : region.blocks)
    {
        (void)state;
        if (block.terminator == TerminatorKind::Goto && !region.blocks.contains(block.first))
        {
            block.first = ExitState;
            region.needsEpilogue = true;
        }
        if (block.terminator == TerminatorKind::Branch &&
            !region.blocks.contains(block.first))
        {
            block.first = ExitState;
            region.needsEpilogue = true;
        }
        if (block.terminator == TerminatorKind::Branch && !region.blocks.contains(block.second))
        {
            block.second = ExitState;
            region.needsEpilogue = true;
        }
    }
    return region;
}

std::vector<int64_t> successors(const Block& block)
{
    if (block.terminator == TerminatorKind::Goto)
        return {block.first};
    if (block.terminator == TerminatorKind::Branch)
        return block.first == block.second ? std::vector<int64_t>{block.first} : std::vector<int64_t>{block.first, block.second};
    if (block.terminator == TerminatorKind::Return)
        return {ExitState};
    return {};
}

bool safelyDiscardableCondition(std::string_view condition)
{
    condition = trimView(condition);
    while (condition.size() >= 2 && condition.front() == '(' && condition.back() == ')')
    {
        condition.remove_prefix(1);
        condition.remove_suffix(1);
        condition = trimView(condition);
    }
    while (condition.starts_with("not "))
    {
        condition = trimView(condition.substr(4));
        while (condition.size() >= 2 && condition.front() == '(' && condition.back() == ')')
        {
            condition.remove_prefix(1);
            condition.remove_suffix(1);
            condition = trimView(condition);
        }
    }
    return condition == "true" || condition == "false" || condition == "nil" || parseInteger(condition).has_value();
}

class Structurer
{
public:
    explicit Structurer(const Region& region)
        : region(region)
    {
    }

    std::optional<std::vector<OutputLine>> run()
    {
        if (!analyze())
        {
            if (failureReason.empty())
                failureReason = "invalid_cfg";
            return std::nullopt;
        }
        if (region.emitStateDeclaration)
            output.push_back({region.stateDeclaration.text, region.stateDeclaration.origin, {}});
        if (!emitSequence(region.entry, std::nullopt, nullptr, region.indent, false))
        {
            if (failureReason.empty())
                failureReason = "branch_join_or_reentry";
            failureReason += "_region_" + std::to_string(region.begin + 1) +
                "_entry_" + std::to_string(region.entry);
            return std::nullopt;
        }
        if (emitted != reachable)
        {
            failureReason = "incomplete_reachable_emission";
            return std::nullopt;
        }
        if (region.needsEpilogue)
        {
            append(region.indent, "if __results ~= nil then");
            append(region.indent + "    ", "return table.unpack(__results)");
            append(region.indent, "end");
        }
        if (region.implicitExitReturnsNil &&
            (output.empty() || !trimView(output.back().text).starts_with("return")))
            append(region.indent, "return nil");
        for (const auto& [state, anchor] : stateAnchors)
            if (!output.empty())
                output[std::min(anchor, output.size() - 1)].states.insert(state);
        return output;
    }

    size_t blockCount() const
    {
        return reachable.size();
    }

    size_t nodeSplitCount() const
    {
        return nodeSplits;
    }

    const std::string& failure() const
    {
        return failureReason;
    }

private:
    struct LoopContext
    {
        int64_t header = 0;
        std::set<int64_t> exits;
        std::string exitSelector;
    };

    struct CloneContext
    {
        std::set<int64_t> path;
    };

    const Region& region;
    std::set<int64_t> reachable;
    std::map<int64_t, std::set<int64_t>> predecessors;
    std::map<int64_t, LoopInfo> loops;
    std::map<int64_t, int64_t> immediatePostdominators;
    std::set<int64_t> emitted;
    std::map<int64_t, size_t> stateAnchors;
    std::map<int64_t, std::vector<int64_t>> emissionBranchPaths;
    std::vector<int64_t> branchPath;
    std::vector<OutputLine> output;
    std::string failureReason;
    size_t nodeSplits = 0;
    size_t clonedBlocks = 0;

    bool fail(std::string reason)
    {
        if (failureReason.empty())
            failureReason = std::move(reason);
        return false;
    }

    static std::string formatPath(const std::vector<int64_t>& path)
    {
        if (path.empty())
            return "root";
        std::string result;
        for (int64_t state : path)
        {
            if (!result.empty())
                result += "-";
            result += std::to_string(state);
        }
        return result;
    }

    bool analyze()
    {
        std::deque<int64_t> pending{region.entry};
        while (!pending.empty())
        {
            const int64_t state = pending.front();
            pending.pop_front();
            if (!reachable.insert(state).second)
                continue;
            auto found = region.blocks.find(state);
            if (found == region.blocks.end() || found->second.terminator == TerminatorKind::Unknown)
                return false;
            for (int64_t next : successors(found->second))
                if (next != ExitState)
                    pending.push_back(next);
        }
        if (reachable.empty())
            return false;

        for (int64_t state : reachable)
        {
            const Block& block = region.blocks.at(state);
            for (int64_t next : successors(block))
                if (next != ExitState && reachable.contains(next))
                    predecessors[next].insert(state);
        }

        std::set<int64_t> postdomUniverse = reachable;
        postdomUniverse.insert(ExitState);
        std::map<int64_t, std::set<int64_t>> postdominators;
        postdominators[ExitState] = {ExitState};
        for (int64_t state : reachable)
            postdominators[state] = postdomUniverse;
        bool postdomChanged = true;
        while (postdomChanged)
        {
            postdomChanged = false;
            for (int64_t state : reachable)
            {
                const std::vector<int64_t> outgoing = successors(region.blocks.at(state));
                if (outgoing.empty())
                    continue;
                std::set<int64_t> next = postdominators.at(outgoing.front());
                for (size_t index = 1; index < outgoing.size(); ++index)
                {
                    std::set<int64_t> intersection;
                    std::set_intersection(next.begin(), next.end(), postdominators.at(outgoing[index]).begin(),
                        postdominators.at(outgoing[index]).end(), std::inserter(intersection, intersection.begin()));
                    next = std::move(intersection);
                }
                next.insert(state);
                if (next != postdominators[state])
                {
                    postdominators[state] = std::move(next);
                    postdomChanged = true;
                }
            }
        }
        for (int64_t state : reachable)
        {
            std::optional<int64_t> immediate;
            size_t largestSet = 0;
            for (int64_t candidate : postdominators[state])
            {
                if (candidate == state)
                    continue;
                const size_t size = postdominators[candidate].size();
                if (!immediate || size > largestSet)
                {
                    immediate = candidate;
                    largestSet = size;
                }
            }
            if (immediate)
                immediatePostdominators[state] = *immediate;
        }

        std::map<int64_t, std::set<int64_t>> dominators;
        for (int64_t state : reachable)
            dominators[state] = state == region.entry ? std::set<int64_t>{state} : reachable;
        bool changed = true;
        while (changed)
        {
            changed = false;
            for (int64_t state : reachable)
            {
                if (state == region.entry)
                    continue;
                std::set<int64_t> next = reachable;
                auto incoming = predecessors.find(state);
                if (incoming == predecessors.end() || incoming->second.empty())
                    return false;
                bool first = true;
                for (int64_t predecessor : incoming->second)
                {
                    if (first)
                    {
                        next = dominators.at(predecessor);
                        first = false;
                    }
                    else
                    {
                        std::set<int64_t> intersection;
                        std::set_intersection(next.begin(), next.end(), dominators.at(predecessor).begin(), dominators.at(predecessor).end(),
                            std::inserter(intersection, intersection.begin()));
                        next = std::move(intersection);
                    }
                }
                next.insert(state);
                if (next != dominators[state])
                {
                    dominators[state] = std::move(next);
                    changed = true;
                }
            }
        }

        for (int64_t source : reachable)
            for (int64_t target : successors(region.blocks.at(source)))
            {
                if (target == ExitState || !dominators.at(source).contains(target))
                    continue;
                LoopInfo& loop = loops[target];
                loop.header = target;
                loop.nodes.insert(target);
                loop.nodes.insert(source);
                std::vector<int64_t> stack{source};
                while (!stack.empty())
                {
                    const int64_t node = stack.back();
                    stack.pop_back();
                    for (int64_t predecessor : predecessors[node])
                        if (loop.nodes.insert(predecessor).second && predecessor != target)
                            stack.push_back(predecessor);
                }
            }

        for (auto& [header, loop] : loops)
        {
            for (int64_t node : loop.nodes)
                if (node != header)
                    for (int64_t predecessor : predecessors[node])
                        if (!loop.nodes.contains(predecessor))
                        {
                            failureReason = "irreducible_loop";
                            return false;
                        }
            std::set<int64_t> exits;
            for (int64_t node : loop.nodes)
                for (int64_t next : successors(region.blocks.at(node)))
                    if (!loop.nodes.contains(next))
                        exits.insert(next);
            loop.exits = exits;
            if (exits.size() == 1)
                loop.exit = *exits.begin();
        }

        for (auto left = loops.begin(); left != loops.end(); ++left)
            for (auto right = std::next(left); right != loops.end(); ++right)
            {
                std::vector<int64_t> overlap;
                std::set_intersection(left->second.nodes.begin(), left->second.nodes.end(), right->second.nodes.begin(), right->second.nodes.end(),
                    std::back_inserter(overlap));
                if (overlap.empty())
                    continue;
                const bool leftContains = std::includes(left->second.nodes.begin(), left->second.nodes.end(), right->second.nodes.begin(),
                    right->second.nodes.end());
                const bool rightContains = std::includes(right->second.nodes.begin(), right->second.nodes.end(), left->second.nodes.begin(),
                    left->second.nodes.end());
                if (!leftContains && !rightContains)
                {
                    failureReason = "overlapping_loops";
                    return false;
                }
            }
        return true;
    }

    std::map<int64_t, size_t> distances(int64_t start) const
    {
        std::map<int64_t, size_t> result;
        std::deque<int64_t> pending;
        result.emplace(start, 0);
        pending.push_back(start);
        while (!pending.empty())
        {
            const int64_t state = pending.front();
            pending.pop_front();
            if (state == ExitState)
                continue;
            auto found = region.blocks.find(state);
            if (found == region.blocks.end())
                continue;
            for (int64_t next : successors(found->second))
                if (!result.contains(next))
                {
                    result.emplace(next, result.at(state) + 1);
                    pending.push_back(next);
                }
        }
        return result;
    }

    std::optional<int64_t> nearestJoin(int64_t first, int64_t second, int64_t branch) const
    {
        if (first == second)
            return first;
        const auto left = distances(first);
        const auto right = distances(second);
        if (auto immediate = immediatePostdominators.find(branch); left.contains(ExitState) && right.contains(ExitState) &&
            immediate != immediatePostdominators.end() &&
            immediate->second != branch && left.contains(immediate->second) && right.contains(immediate->second))
            return immediate->second;
        std::optional<int64_t> best;
        size_t bestMaximum = std::numeric_limits<size_t>::max();
        size_t bestTotal = std::numeric_limits<size_t>::max();
        for (const auto& [state, leftDistance] : left)
        {
            auto other = right.find(state);
            if (other == right.end() || state == branch)
                continue;
            const size_t maximum = std::max(leftDistance, other->second);
            const size_t total = leftDistance + other->second;
            if (!best || maximum < bestMaximum || (maximum == bestMaximum && total < bestTotal) ||
                (maximum == bestMaximum && total == bestTotal && state == ExitState))
            {
                best = state;
                bestMaximum = maximum;
                bestTotal = total;
            }
        }
        return best;
    }

    void append(std::string_view indent, std::string text, std::optional<size_t> origin = std::nullopt)
    {
        output.push_back({std::string(indent) + std::move(text), origin, {}});
    }

    void emitBody(const Block& block, std::string_view indent)
    {
        for (const SourceLine& line : block.body)
            append(indent, line.text, line.origin);
    }

    bool emitReturn(const Block& block, std::string_view indent)
    {
        if (block.explicitReturn)
            return true;
        append(indent, block.returnsResults
                ? "return table.unpack(__results)"
                : (region.implicitExitReturnsNil ? "return nil" : "return"));
        return true;
    }

    bool emitLoop(const LoopInfo& loop, const LoopContext* outer, std::string_view indent,
        std::optional<CloneContext> clone = std::nullopt)
    {
        const std::string exitSelector = "loop_exit_" + std::to_string(loop.header);
        if (loop.exits.size() > 1)
            append(indent, "local " + exitSelector);
        append(indent, "while true do");
        const LoopContext context{loop.header, loop.exits, exitSelector};
        const std::string nested = std::string(indent) + "    ";
        if (region.semanticPrototype)
            append(nested, "semantic_step(" + std::to_string(*region.semanticPrototype) + ", " +
                std::to_string(loop.header) + ")");
        if (!emitSequence(loop.header, std::nullopt, &context, nested, true, std::move(clone)))
            return false;
        append(indent, "end");
        (void)outer;
        return true;
    }

    size_t exitOrdinal(const LoopContext& context, int64_t state) const
    {
        const auto found = context.exits.find(state);
        return found == context.exits.end()
            ? 0
            : static_cast<size_t>(std::distance(context.exits.begin(), found)) + 1;
    }

    bool emitSequence(int64_t state, std::optional<int64_t> stop, const LoopContext* context,
        std::string_view indent, bool allowHeader, std::optional<CloneContext> clone = std::nullopt)
    {
        while (true)
        {
            if (stop && state == *stop)
                return true;
            if (context && state == context->header && !allowHeader)
            {
                append(indent, "continue");
                return true;
            }
            if (context && context->exits.contains(state))
            {
                if (context->exits.size() > 1)
                    append(indent, context->exitSelector + " = " + std::to_string(exitOrdinal(*context, state)));
                append(indent, "break");
                return true;
            }
            if (state == ExitState)
                return true;
            allowHeader = false;

            auto loop = loops.find(state);
            if (loop != loops.end() && (!context || loop->first != context->header))
            {
                if (!emitLoop(loop->second, context, indent, clone))
                    return false;
                if (loop->second.exits.empty())
                    return true;
                if (loop->second.exits.size() == 1)
                {
                    state = *loop->second.exits.begin();
                    continue;
                }

                auto exit = loop->second.exits.begin();
                const int64_t firstExit = *exit++;
                const int64_t secondExit = *exit++;
                if (exit != loop->second.exits.end())
                    return fail("loop_exit_dispatch_arity_" + std::to_string(loop->first));
                auto join = nearestJoin(firstExit, secondExit, loop->first);
                if (!join)
                    return fail("loop_exit_missing_join_" + std::to_string(loop->first));
                const std::string selector = "loop_exit_" + std::to_string(loop->first);
                append(indent, "if " + selector + " == 1 then");
                const std::string nested = std::string(indent) + "    ";
                if (!emitSequence(firstExit, join, context, nested, false, clone))
                    return false;
                append(indent, "else");
                if (!emitSequence(secondExit, join, context, nested, false, clone))
                    return false;
                append(indent, "end");
                state = *join;
                continue;
            }

            auto found = region.blocks.find(state);
            if (found == region.blocks.end())
                return fail("emit_missing_state_" + std::to_string(state));
            if (clone)
            {
                if (!clone->path.insert(state).second)
                    return fail("node_split_cycle_" + std::to_string(state));
                ++clonedBlocks;
                if (clonedBlocks > std::max<size_t>(64, reachable.size() * 4))
                    return fail("node_split_budget");
            }
            else
            {
                if (!emitted.insert(state).second)
                {
                    ++nodeSplits;
                    return emitSequence(state, stop, context, indent, allowHeader, CloneContext{});
                }
                emissionBranchPaths.emplace(state, branchPath);
            }
            stateAnchors.emplace(state, output.size());
            const Block& block = found->second;
            emitBody(block, indent);
            if (block.terminator == TerminatorKind::Return)
                return emitReturn(block, indent);
            if (block.terminator == TerminatorKind::Goto)
            {
                state = block.first;
                continue;
            }
            if (block.terminator != TerminatorKind::Branch)
                return fail("emit_unknown_terminator_" + std::to_string(state));

            auto join = nearestJoin(block.first, block.second, state);
            if (!join)
                return fail("emit_missing_join_" + std::to_string(state) + "_" +
                    std::to_string(block.first) + "_" + std::to_string(block.second));
            if (region.discardSafeEmptyBranches && block.first == block.second &&
                safelyDiscardableCondition(block.condition))
            {
                state = block.first;
                continue;
            }
            const size_t branchBegin = output.size();
            append(indent, "if " + block.condition + " then");
            const std::string nested = std::string(indent) + "    ";
            branchPath.push_back(state * 2);
            if (!emitSequence(block.first, join, context, nested, false, clone))
                return false;
            branchPath.back() = state * 2 + 1;
            const bool emptyFirst = output.size() == branchBegin + 1;
            append(indent, "else");
            if (!emitSequence(block.second, join, context, nested, false, clone))
                return false;
            branchPath.pop_back();
            const bool emptySecond = output.size() == branchBegin + 2;
            if (region.discardSafeEmptyBranches && emptyFirst && emptySecond &&
                safelyDiscardableCondition(block.condition))
            {
                output.resize(branchBegin);
                state = *join;
                continue;
            }
            append(indent, "end");
            state = *join;
        }
    }
};

bool generatedLocal(std::string_view value)
{
    if (value == "__state" || value == "__results" || value == "temporary")
        return true;
    if (!value.starts_with("local_") || value.size() == 6)
        return false;
    return std::all_of(value.begin() + 6, value.end(), [](char ch) { return std::isdigit(static_cast<unsigned char>(ch)); });
}

bool generatedRegisterTable(std::string_view value)
{
    if (value == "registers")
        return true;
    if (generatedLocal(value) && value.starts_with("local_"))
        return true;
    constexpr std::string_view Prefix = "registers_";
    return value.starts_with(Prefix) && value.size() > Prefix.size() &&
        std::all_of(value.begin() + static_cast<std::ptrdiff_t>(Prefix.size()), value.end(),
            [](char ch) { return std::isdigit(static_cast<unsigned char>(ch)); });
}

bool capturedLocal(std::string_view value)
{
    constexpr std::string_view Prefix = "captured_value_";
    return value.starts_with(Prefix) && value.size() > Prefix.size() &&
        std::all_of(value.begin() + static_cast<std::ptrdiff_t>(Prefix.size()), value.end(),
            [](char ch) { return std::isdigit(static_cast<unsigned char>(ch)); });
}

std::set<std::string> generatedReads(std::string_view value)
{
    std::set<std::string> result;
    for (size_t index = 0; index < value.size();)
    {
        if (value[index] == '-' && index + 1 < value.size() && value[index + 1] == '-')
            break;
        if (value[index] == '\'' || value[index] == '"')
        {
            const char quote = value[index++];
            while (index < value.size())
            {
                if (value[index] == '\\')
                {
                    index += std::min<size_t>(2, value.size() - index);
                    continue;
                }
                if (value[index++] == quote)
                    break;
            }
            continue;
        }
        if (value[index] == '_' || std::isalpha(static_cast<unsigned char>(value[index])))
        {
            const size_t begin = index++;
            while (index < value.size() && (value[index] == '_' || std::isalnum(static_cast<unsigned char>(value[index]))))
                ++index;
            const std::string name(value.substr(begin, index - begin));
            if (generatedLocal(name))
                result.insert(name);
            continue;
        }
        ++index;
    }
    return result;
}

bool quotedLiteral(std::string_view value)
{
    value = trimView(value);
    if (value.size() < 2 || (value.front() != '"' && value.front() != '\'') || value.back() != value.front())
        return false;
    for (size_t index = 1; index + 1 < value.size(); ++index)
        if (value[index] == '\\')
            ++index;
        else if (value[index] == value.front())
            return false;
    return true;
}

bool bareReadableGlobal(std::string_view value)
{
    value = trimView(value);
    static const std::regex Identifier(R"(^[A-Za-z_][A-Za-z0-9_]*$)");
    return std::regex_match(std::string(value), Identifier) && !generatedLocal(value) && !capturedLocal(value) && !value.starts_with("cell_") &&
        !value.starts_with("upvalue_") && !value.starts_with("__");
}

bool safeDottedGlobal(std::string_view value);
std::string_view stripOuterParentheses(std::string_view value);
bool functionExpressionClosesOnLine(std::string_view line);
bool directlyWritesIdentifier(std::string_view line, std::string_view name);
size_t identifierOccurrences(std::string_view line, std::string_view name);
bool containsCallSyntax(std::string_view line);
std::set<std::string> lexicalIdentifiers(std::string_view line);

bool pureAssignmentValue(std::string_view value)
{
    value = stripOuterParentheses(trimView(value));
    if (value == "nil" || value == "true" || value == "false" || value == "{}" || value == "{nil}" || quotedLiteral(value) ||
        generatedLocal(value) || capturedLocal(value) || bareReadableGlobal(value) || safeDottedGlobal(value))
        return true;
    if ((value.starts_with("function(") || value.starts_with("(function(")) && functionExpressionClosesOnLine(value))
        return true;
    static const std::regex Number(R"(^-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$)");
    return std::regex_match(std::string(value), Number);
}

bool controlBoundary(std::string_view value)
{
    value = trimView(value);
    const bool functionBoundary = value.starts_with("function ") || value.starts_with("local function ") ||
        value.starts_with("return function(") || value.starts_with("end)(") ||
        value.find(" = function(") != std::string_view::npos || value.find(" = (function(") != std::string_view::npos;
    return value.empty() || value == "else" || value == "end" || value == "repeat" || value == "break" || value == "continue" ||
        value.starts_with("if ") || value.starts_with("elseif ") || value.starts_with("while ") || value.starts_with("for ") ||
        value.starts_with("until ") || (functionBoundary && !functionExpressionClosesOnLine(value));
}

bool scalarLiteral(std::string_view value)
{
    value = trimView(value);
    if (value == "nil" || value == "true" || value == "false" || quotedLiteral(value))
        return true;
    static const std::regex Number(R"(^-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$)");
    return std::regex_match(std::string(value), Number);
}

bool safeDottedGlobal(std::string_view value)
{
    value = trimView(value);
    const size_t separator = value.find('.');
    if (separator == std::string_view::npos || separator == 0)
        return false;
    static const std::set<std::string_view> Roots{
        "Axes", "BrickColor", "CFrame", "CatalogSearchParams", "Color3", "ColorSequence", "ColorSequenceKeypoint",
        "DateTime", "DockWidgetPluginGuiInfo", "Enum", "Faces", "Font", "Instance", "NumberRange", "NumberSequence",
        "NumberSequenceKeypoint", "OverlapParams", "PathWaypoint", "PhysicalProperties", "Random", "Ray", "RaycastParams",
        "Rect", "Region3", "TweenInfo", "UDim", "UDim2", "Vector2", "Vector3", "bit32", "buffer", "coroutine", "debug",
        "math", "os", "string", "table", "task", "utf8",
    };
    if (!Roots.contains(value.substr(0, separator)))
        return false;
    size_t index = 0;
    while (index < value.size())
    {
        if (value[index] != '_' && !std::isalpha(static_cast<unsigned char>(value[index])))
            return false;
        ++index;
        while (index < value.size() && (value[index] == '_' || std::isalnum(static_cast<unsigned char>(value[index]))))
            ++index;
        if (index == value.size())
            return true;
        if (value[index++] != '.' || index == value.size())
            return false;
    }
    return true;
}

bool pureAliasValue(std::string_view value)
{
    value = trimView(value);
    if (scalarLiteral(value) || (value.starts_with("local_") && generatedLocal(value)) || safeDottedGlobal(value))
        return true;
    if (bareReadableGlobal(value))
        return true;
    return false;
}

std::string replaceGeneratedLocals(std::string_view value, const std::map<std::string, std::string>& replacements,
    size_t& constantCount, size_t& aliasCount)
{
    std::string output;
    output.reserve(value.size());
    for (size_t index = 0; index < value.size();)
    {
        if (value[index] == '-' && index + 1 < value.size() && value[index + 1] == '-')
        {
            output.append(value.substr(index));
            break;
        }
        if (value[index] == '\'' || value[index] == '"')
        {
            const size_t begin = index;
            const char quote = value[index++];
            while (index < value.size())
            {
                if (value[index] == '\\')
                {
                    index += std::min<size_t>(2, value.size() - index);
                    continue;
                }
                if (value[index++] == quote)
                    break;
            }
            output.append(value.substr(begin, index - begin));
            continue;
        }
        if (value[index] == '_' || std::isalpha(static_cast<unsigned char>(value[index])))
        {
            const size_t begin = index++;
            while (index < value.size() && (value[index] == '_' || std::isalnum(static_cast<unsigned char>(value[index]))))
                ++index;
            const std::string name(value.substr(begin, index - begin));
            auto replacement = replacements.find(name);
            if (replacement != replacements.end())
            {
                size_t suffix = index;
                while (suffix < value.size() && std::isspace(static_cast<unsigned char>(value[suffix])))
                    ++suffix;
                const bool prefixExpressionSuffix = suffix < value.size() &&
                    (value[suffix] == '.' || value[suffix] == '[' || value[suffix] == ':' || value[suffix] == '(');
                if (prefixExpressionSuffix && scalarLiteral(replacement->second))
                    output += "(" + replacement->second + ")";
                else
                    output += replacement->second;
                if (generatedLocal(replacement->second))
                    ++aliasCount;
                else
                    ++constantCount;
            }
            else
                output += name;
            continue;
        }
        output.push_back(value[index++]);
    }
    return output;
}

size_t recoverProperties(std::string& line)
{
    static const std::regex Indexed(R"regex(\(([^()\n]+)\)\["([A-Za-z_][A-Za-z0-9_]*)"\])regex");
    static const std::regex Environment(R"regex(getfenv\(0\)\["([A-Za-z_][A-Za-z0-9_]*)"\])regex");
    size_t replacements = 0;
    std::smatch match;
    while (std::regex_search(line, match, Indexed))
    {
        line.replace(static_cast<size_t>(match.position()), static_cast<size_t>(match.length()), "(" + match[1].str() + ")." + match[2].str());
        ++replacements;
    }
    while (std::regex_search(line, match, Environment))
    {
        line.replace(static_cast<size_t>(match.position()), static_cast<size_t>(match.length()), "getfenv(0)." + match[1].str());
        ++replacements;
    }
    std::string output;
    output.reserve(line.size());
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
        {
            output.append(line, index, std::string::npos);
            break;
        }
        if (line[index] == '\'' || line[index] == '"')
        {
            const size_t begin = index;
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            output.append(line, begin, index - begin);
            continue;
        }
        if (line[index] == '(' && index + 1 < line.size() &&
            (line[index + 1] == '_' || std::isalpha(static_cast<unsigned char>(line[index + 1]))))
        {
            size_t end = index + 2;
            while (end < line.size() && (line[end] == '_' || std::isalnum(static_cast<unsigned char>(line[end]))))
                ++end;
            if (line.substr(end).starts_with(")."))
            {
                output.append(line, index + 1, end - index - 1);
                output.push_back('.');
                index = end + 2;
                ++replacements;
                continue;
            }
        }
        if (line[index] == '_' || std::isalpha(static_cast<unsigned char>(line[index])))
        {
            const size_t begin = index++;
            while (index < line.size() && (line[index] == '_' || std::isalnum(static_cast<unsigned char>(line[index]))))
                ++index;
            if (line.substr(index).starts_with("[\""))
            {
                size_t propertyEnd = index + 2;
                if (propertyEnd < line.size() && (line[propertyEnd] == '_' || std::isalpha(static_cast<unsigned char>(line[propertyEnd]))))
                {
                    ++propertyEnd;
                    while (propertyEnd < line.size() &&
                        (line[propertyEnd] == '_' || std::isalnum(static_cast<unsigned char>(line[propertyEnd]))))
                        ++propertyEnd;
                    if (line.substr(propertyEnd).starts_with("\"]"))
                    {
                        output.append(line, begin, index - begin);
                        output.push_back('.');
                        output.append(line, index + 2, propertyEnd - index - 2);
                        index = propertyEnd + 2;
                        ++replacements;
                        continue;
                    }
                }
            }
            output.append(line, begin, index - begin);
            continue;
        }
        output.push_back(line[index++]);
    }
    line = std::move(output);
    return replacements;
}

bool generatedNameCollision(std::string_view name)
{
    return generatedLocal(name) || capturedLocal(name) || name.starts_with("cell_") || name.starts_with("upvalue_") || name.starts_with("__");
}

size_t recoverEnvironmentGlobals(std::string& line)
{
    constexpr std::string_view Marker = "getfenv(0).";
    std::string output;
    output.reserve(line.size());
    size_t replacements = 0;
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '\'' || line[index] == '"')
        {
            const size_t begin = index;
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            output.append(line, begin, index - begin);
            continue;
        }
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
        {
            output.append(line, index, std::string::npos);
            break;
        }
        if (!std::string_view(line).substr(index).starts_with(Marker))
        {
            output.push_back(line[index++]);
            continue;
        }
        size_t end = index + Marker.size();
        if (end >= line.size() || (line[end] != '_' && !std::isalpha(static_cast<unsigned char>(line[end]))))
        {
            output.append(Marker);
            index = end;
            continue;
        }
        ++end;
        while (end < line.size() && (line[end] == '_' || std::isalnum(static_cast<unsigned char>(line[end]))))
            ++end;
        const std::string_view name(line.data() + index + Marker.size(), end - index - Marker.size());
        if (generatedNameCollision(name))
            output.append(line, index, end - index);
        else
        {
            output.append(name);
            ++replacements;
        }
        index = end;
    }
    if (replacements)
        line = std::move(output);
    return replacements;
}

struct PropagationStats
{
    size_t constants = 0;
    size_t aliases = 0;
    size_t properties = 0;
};

struct IdentifierAssignmentList
{
    size_t value_begin = 0;
    std::vector<std::string> targets;
};

std::optional<IdentifierAssignmentList> identifierAssignmentList(std::string_view line)
{
    size_t equals = std::string_view::npos;
    char quote = 0;
    int parentheses = 0;
    int brackets = 0;
    int braces = 0;
    for (size_t index = 0; index < line.size(); ++index)
    {
        const char ch = line[index];
        if (quote != 0)
        {
            if (ch == '\\')
                ++index;
            else if (ch == quote)
                quote = 0;
            continue;
        }
        if (ch == '\'' || ch == '"')
        {
            quote = ch;
            continue;
        }
        if (ch == '(')
            ++parentheses;
        else if (ch == ')')
            --parentheses;
        else if (ch == '[')
            ++brackets;
        else if (ch == ']')
            --brackets;
        else if (ch == '{')
            ++braces;
        else if (ch == '}')
            --braces;
        else if (ch == '=' && parentheses == 0 && brackets == 0 && braces == 0)
        {
            const char previous = index == 0 ? '\0' : line[index - 1];
            const char next = index + 1 < line.size() ? line[index + 1] : '\0';
            if (next != '=' && previous != '=' && previous != '~' && previous != '<' && previous != '>' &&
                previous != '+' && previous != '-' && previous != '*' && previous != '/' && previous != '%' &&
                previous != '^' && previous != '.')
            {
                equals = index;
                break;
            }
        }
    }
    if (equals == std::string_view::npos)
        return std::nullopt;

    std::string_view left = trimView(line.substr(0, equals));
    if (left.starts_with("local "))
        left = trimView(left.substr(6));
    if (left.empty())
        return std::nullopt;

    IdentifierAssignmentList assignment;
    assignment.value_begin = equals + 1;
    size_t begin = 0;
    while (begin < left.size())
    {
        const size_t comma = left.find(',', begin);
        const size_t end = comma == std::string_view::npos ? left.size() : comma;
        const std::string_view target = trimView(left.substr(begin, end - begin));
        if (target.empty() || (target.front() != '_' && !std::isalpha(static_cast<unsigned char>(target.front()))) ||
            !std::all_of(target.begin() + 1, target.end(), [](char ch) {
                return ch == '_' || std::isalnum(static_cast<unsigned char>(ch));
            }))
            return std::nullopt;
        assignment.targets.emplace_back(target);
        if (comma == std::string_view::npos)
            break;
        begin = comma + 1;
    }
    return assignment.targets.empty() ? std::nullopt : std::optional<IdentifierAssignmentList>(std::move(assignment));
}

PropagationStats propagateConstants(std::vector<OutputLine>& lines)
{
    std::map<std::string, std::string> constants;
    PropagationStats stats;
    for (OutputLine& line : lines)
    {
        const std::string original = line.text;
        if (auto assignment = identifierAssignmentList(original))
        {
            std::string value = replaceGeneratedLocals(
                std::string_view(original).substr(assignment->value_begin), constants, stats.constants, stats.aliases);
            line.text = original.substr(0, assignment->value_begin) + value;
            stats.properties += recoverProperties(line.text);
            for (const std::string& target : assignment->targets)
            {
                constants.erase(target);
                for (auto replacement = constants.begin(); replacement != constants.end();)
                    if (replacement->second == target)
                        replacement = constants.erase(replacement);
                    else
                        ++replacement;
            }
            const std::string normalized = trim(value);
            if (assignment->targets.size() == 1 && generatedLocal(assignment->targets.front()) &&
                normalized != assignment->targets.front() && pureAliasValue(normalized))
                constants.emplace(assignment->targets.front(), normalized);
        }
        else
        {
            line.text = replaceGeneratedLocals(line.text, constants, stats.constants, stats.aliases);
            stats.properties += recoverProperties(line.text);
        }
        const std::string_view statement = trimView(line.text);
        const bool returns = statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' ');
        if (controlBoundary(statement) || returns)
            constants.clear();
    }
    return stats;
}

size_t recoverDynamicMethodCalls(std::vector<OutputLine>& lines)
{
    static const std::regex MethodName(
        R"(^\s*((?:local_[0-9]+)|temporary)\s*=\s*\"([A-Za-z_][A-Za-z0-9_]*)\"$)");
    static const std::regex Lookup(
        R"(^\s*((?:local_[0-9]+)|temporary)\s*=\s*\(?([A-Za-z_][A-Za-z0-9_]*)\)?\[((?:local_[0-9]+)|temporary)\]$)");
    static const std::regex Call(
        R"(^\s*((?:local_[0-9]+)|temporary)\s*=\s*((?:local_[0-9]+)|temporary)\((.*)\)$)");
    std::vector<bool> remove(lines.size(), false);
    size_t recovered = 0;
    for (size_t index = 0; index + 2 < lines.size(); ++index)
    {
        std::smatch methodName;
        if (!std::regex_match(lines[index].text, methodName, MethodName))
            continue;
        const std::string target = methodName[1].str();
        const std::string method = methodName[2].str();
        std::smatch lookup;
        std::smatch call;
        if (!std::regex_match(lines[index + 1].text, lookup, Lookup) || !std::regex_match(lines[index + 2].text, call, Call) ||
            lookup[1].str() != target || lookup[3].str() != target || call[1].str() != target || call[2].str() != target)
            continue;
        const std::string receiver = lookup[2].str();
        const std::string arguments = call[3].str();
        std::string remaining;
        if (arguments == receiver)
            remaining.clear();
        else if (arguments.starts_with(receiver + ", "))
            remaining = arguments.substr(receiver.size() + 2);
        else
            continue;
        lines[index + 2].text = std::string(indentation(lines[index + 2].text), ' ') + target + " = " + receiver + ":" + method + "(" + remaining + ")";
        lines[index + 2].states.insert(lines[index].states.begin(), lines[index].states.end());
        lines[index + 2].states.insert(lines[index + 1].states.begin(), lines[index + 1].states.end());
        remove[index] = true;
        remove[index + 1] = true;
        recovered += 2;
        index += 2;
    }
    if (recovered == 0)
        return 0;
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - recovered);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return recovered / 2;
}

size_t recoverMethodCalls(std::vector<OutputLine>& lines, bool readableReceivers = false)
{
    static const std::regex Property(R"(^\s*((?:local_[0-9]+)|temporary|__state)\s*=\s*\(?((?:local_[0-9]+)|(?:argument_[0-9]+)|(?:captured_value_[0-9]+)|temporary|__state)\)?\.([A-Za-z_][A-Za-z0-9_]*)$)");
    static const std::regex ReadableProperty(
        R"(^\s*((?:local_[0-9]+)|temporary|__state)\s*=\s*\(?([A-Za-z_][A-Za-z0-9_]*)\)?\.([A-Za-z_][A-Za-z0-9_]*)$)");
    std::vector<bool> remove(lines.size(), false);
    size_t recovered = recoverDynamicMethodCalls(lines);
    remove.resize(lines.size());
    auto matchingCallClose = [](std::string_view line, size_t open) -> std::optional<size_t> {
        if (open >= line.size() || line[open] != '(')
            return std::nullopt;
        int depth = 0;
        char quote = 0;
        for (size_t index = open; index < line.size(); ++index)
        {
            const char ch = line[index];
            if (quote != 0)
            {
                if (ch == '\\')
                    ++index;
                else if (ch == quote)
                    quote = 0;
                continue;
            }
            if (ch == '\'' || ch == '"')
                quote = ch;
            else if (ch == '(')
                ++depth;
            else if (ch == ')' && --depth == 0)
                return index;
        }
        return std::nullopt;
    };
    for (size_t index = 0; index < lines.size(); ++index)
    {
        std::smatch property;
        if (!std::regex_match(lines[index].text, property, readableReceivers ? ReadableProperty : Property))
            continue;
        const std::string function = property[1].str();
        const std::string receiver = property[2].str();
        const std::string method = property[3].str();
        const size_t limit = std::min(lines.size(), index + 48);
        for (size_t callIndex = index + 1; callIndex < limit; ++callIndex)
        {
            const std::string_view statement = trimView(lines[callIndex].text);
            if (controlBoundary(statement) || statement.starts_with("return"))
                break;

            const std::string needle = function + "(";
            const size_t functionPosition = lines[callIndex].text.rfind(needle);
            const size_t callOpen = functionPosition == std::string::npos
                ? std::string::npos
                : functionPosition + function.size();
            const auto callClose = callOpen == std::string::npos
                ? std::nullopt
                : matchingCallClose(lines[callIndex].text, callOpen);
            if (functionPosition != std::string::npos && callClose)
            {
                const std::string prefix = lines[callIndex].text.substr(0, functionPosition);
                const std::string suffix = lines[callIndex].text.substr(*callClose + 1);
                const size_t prefixOccurrences = identifierOccurrences(prefix, function);
                const auto assignment = identifierAssignmentList(lines[callIndex].text);
                const bool targetOccurrence = prefixOccurrences == 1 && assignment &&
                    std::find(assignment->targets.begin(), assignment->targets.end(), function) != assignment->targets.end();
                if ((prefixOccurrences != 0 && !targetOccurrence) ||
                    identifierOccurrences(suffix, function) != 0)
                    break;
                const std::string arguments = lines[callIndex].text.substr(
                    callOpen + 1, *callClose - callOpen - 1);
                std::string remaining;
                if (arguments == receiver)
                    remaining.clear();
                else if (arguments.starts_with(receiver + ", "))
                    remaining = arguments.substr(receiver.size() + 2);
                else
                {
                    lines[callIndex].text = prefix + receiver + "." + method + "(" + arguments + ")" + suffix;
                    lines[callIndex].states.insert(lines[index].states.begin(), lines[index].states.end());
                    remove[index] = true;
                    ++recovered;
                    break;
                }
                lines[callIndex].text = prefix + receiver + ":" + method + "(" + remaining + ")" + suffix;
                lines[callIndex].states.insert(lines[index].states.begin(), lines[index].states.end());
                remove[index] = true;
                ++recovered;
                break;
            }

            // The VM commonly separates a method lookup from its call with unrelated
            // constructor calls and local declarations. Keep looking while the saved
            // function and receiver are stable, but never cross an escape or mutation.
            if (identifierOccurrences(lines[callIndex].text, function) != 0)
                break;

            if (auto assignment = identifierAssignmentList(lines[callIndex].text))
                if (std::find(assignment->targets.begin(), assignment->targets.end(), function) != assignment->targets.end() ||
                    std::find(assignment->targets.begin(), assignment->targets.end(), receiver) != assignment->targets.end())
                    break;

            const std::string propertyWrite = receiver + "." + method;
            const size_t propertyPosition = lines[callIndex].text.find(propertyWrite);
            if (propertyPosition != std::string::npos)
            {
                const std::string_view after = trimView(std::string_view(lines[callIndex].text).substr(
                    propertyPosition + propertyWrite.size()));
                if (after.starts_with("=") || after.starts_with("+=") || after.starts_with("-=") ||
                    after.starts_with("*=") || after.starts_with("/=") || after.starts_with("%=") ||
                    after.starts_with("^=") || after.starts_with("..="))
                    break;
            }

            if (directlyWritesIdentifier(lines[callIndex].text, function) ||
                directlyWritesIdentifier(lines[callIndex].text, receiver))
                break;
        }
    }
    if (recovered == 0)
        return 0;
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - recovered);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return recovered;
}

size_t collapseResultReturns(std::vector<OutputLine>& lines)
{
    static const std::regex Assignment(R"(^(\s*)__results\s*=\s*(.+)$)");
    std::vector<bool> remove(lines.size(), false);
    size_t collapsed = 0;
    for (size_t index = 0; index + 1 < lines.size(); ++index)
    {
        std::smatch assignment;
        if (!std::regex_match(lines[index].text, assignment, Assignment) ||
            trimView(lines[index + 1].text) != "return table.unpack(__results)" ||
            indentation(lines[index].text) != indentation(lines[index + 1].text))
            continue;
        const std::string value = assignment[2].str();
        lines[index].text = assignment[1].str() + (trimView(value) == "{}" ? "return" : "return table.unpack(" + value + ")");
        lines[index].states.insert(lines[index + 1].states.begin(), lines[index + 1].states.end());
        remove[index + 1] = true;
        ++collapsed;
        ++index;
    }
    if (collapsed == 0)
        return 0;
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - collapsed);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return collapsed;
}

bool structuredProbeContainsCall(std::string_view condition)
{
    for (size_t index = 0; index < condition.size(); ++index)
    {
        if (condition[index] != '(')
            continue;
        size_t previous = index;
        while (previous > 0 && std::isspace(static_cast<unsigned char>(condition[previous - 1])))
            --previous;
        if (previous == 0)
            continue;
        const char tail = condition[previous - 1];
        if (tail == ')' || tail == ']')
            return true;
        if (tail != '_' && !std::isalnum(static_cast<unsigned char>(tail)))
            continue;
        size_t begin = previous - 1;
        while (begin > 0 &&
            (condition[begin - 1] == '_' || std::isalnum(static_cast<unsigned char>(condition[begin - 1]))))
            --begin;
        if (condition.substr(begin, previous - begin) != "not")
            return true;
    }
    return false;
}

size_t simplifyEmptyBranches(std::vector<OutputLine>& lines)
{
    std::vector<bool> remove(lines.size(), false);
    size_t simplified = 0;
    for (size_t index = 0; index + 2 < lines.size(); ++index)
    {
        const std::string_view header = trimView(lines[index].text);
        if (!header.starts_with("if ") || !header.ends_with(" then") ||
            trimView(lines[index + 1].text) != "end" || trimView(lines[index + 2].text) != header ||
            indentation(lines[index].text) != indentation(lines[index + 1].text) ||
            indentation(lines[index].text) != indentation(lines[index + 2].text))
            continue;
        const std::string_view condition = header.substr(3, header.size() - 3 - 5);
        if (structuredProbeContainsCall(condition) ||
            (condition.find("registers") == std::string_view::npos && condition.find("state") == std::string_view::npos))
            continue;
        bool internal = true;
        for (const std::string& identifier : lexicalIdentifiers(condition))
            if (identifier != "registers" && identifier != "state" && identifier != "not" && identifier != "and" &&
                identifier != "or" && identifier != "true" && identifier != "false" && identifier != "nil" &&
                !generatedLocal(identifier))
                internal = false;
        if (!internal)
            continue;
        lines[index + 2].states.insert(lines[index].states.begin(), lines[index].states.end());
        lines[index + 2].states.insert(lines[index + 1].states.begin(), lines[index + 1].states.end());
        remove[index] = true;
        remove[index + 1] = true;
        ++simplified;
        index += 1;
    }
    for (size_t index = 0; index + 1 < lines.size(); ++index)
    {
        if (remove[index] || remove[index + 1])
            continue;
        const std::string_view header = trimView(lines[index].text);
        if (!header.starts_with("if ") || !header.ends_with(" then") ||
            trimView(lines[index + 1].text) != "end" ||
            indentation(lines[index].text) != indentation(lines[index + 1].text))
            continue;
        const std::string_view condition = header.substr(3, header.size() - 3 - 5);
        if (structuredProbeContainsCall(condition) ||
            (condition.find("registers") == std::string_view::npos && condition.find("state") == std::string_view::npos))
            continue;
        bool internal = true;
        for (const std::string& identifier : lexicalIdentifiers(condition))
            if (identifier != "registers" && identifier != "state" && identifier != "not" && identifier != "and" &&
                identifier != "or" && identifier != "true" && identifier != "false" && identifier != "nil" &&
                !generatedLocal(identifier))
                internal = false;
        if (!internal)
            continue;
        if (index + 2 < lines.size())
        {
            lines[index + 2].states.insert(lines[index].states.begin(), lines[index].states.end());
            lines[index + 2].states.insert(lines[index + 1].states.begin(), lines[index + 1].states.end());
            if (!lines[index + 2].origin)
                lines[index + 2].origin = lines[index].origin ? lines[index].origin : lines[index + 1].origin;
        }
        remove[index] = true;
        remove[index + 1] = true;
        ++simplified;
        ++index;
    }
    for (size_t index = 1; index + 1 < lines.size(); ++index)
    {
        if (remove[index - 1] || remove[index] || remove[index + 1])
            continue;
        if (trimView(lines[index].text) != "else")
            continue;
        const size_t indent = indentation(lines[index].text);
        const std::string_view previous = trimView(lines[index - 1].text);
        const std::string_view next = trimView(lines[index + 1].text);
        if (next == "end" && indentation(lines[index + 1].text) == indent)
        {
            lines[index + 1].states.insert(lines[index].states.begin(), lines[index].states.end());
            remove[index] = true;
            ++simplified;
            continue;
        }
        if (indentation(lines[index - 1].text) == indent && previous.starts_with("if ") && previous.ends_with(" then"))
        {
            std::string condition(previous.substr(3, previous.size() - 3 - 5));
            lines[index - 1].text = std::string(indent, ' ') + "if not (" + condition + ") then";
            lines[index - 1].states.insert(lines[index].states.begin(), lines[index].states.end());
            remove[index] = true;
            ++simplified;
        }
    }
    if (simplified == 0)
        return 0;
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - static_cast<size_t>(std::count(remove.begin(), remove.end(), true)));
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return simplified;
}

size_t flattenTerminatingElseBranches(std::vector<OutputLine>& lines)
{
    size_t flattened = 0;
    for (size_t opener = lines.size(); opener > 0; --opener)
    {
        const size_t ifLine = opener - 1;
        const std::string_view statement = trimView(lines[ifLine].text);
        if (!statement.starts_with("if ") || !statement.ends_with(" then"))
            continue;
        const size_t indent = indentation(lines[ifLine].text);
        std::optional<size_t> elseLine;
        std::optional<size_t> endLine;
        for (size_t line = ifLine + 1; line < lines.size(); ++line)
        {
            if (trimView(lines[line].text).empty() || indentation(lines[line].text) != indent)
                continue;
            const std::string_view boundary = trimView(lines[line].text);
            if (!elseLine && boundary == "else")
            {
                elseLine = line;
                continue;
            }
            if (!elseLine && boundary.starts_with("elseif "))
                break;
            if (boundary == "end")
            {
                endLine = line;
                break;
            }
        }
        if (!elseLine || !endLine || *elseLine + 1 >= *endLine)
            continue;

        size_t terminator = *elseLine;
        while (terminator > ifLine + 1 && trimView(lines[terminator - 1].text).empty())
            --terminator;
        if (terminator <= ifLine + 1)
            continue;
        const std::string_view terminal = trimView(lines[terminator - 1].text);
        if (!(terminal == "return" || terminal.starts_with("return ")))
            continue;

        size_t next = *endLine + 1;
        while (next < lines.size() && trimView(lines[next].text).empty())
            ++next;
        if (next < lines.size())
        {
            const std::string_view boundary = trimView(lines[next].text);
            const bool closesScope = indentation(lines[next].text) < indent ||
                (indentation(lines[next].text) == indent &&
                    (boundary == "end" || boundary == "else" || boundary.starts_with("elseif ") ||
                        boundary.starts_with("until ")));
            if (!closesScope)
                continue;
        }

        size_t anchor = *elseLine + 1;
        while (anchor < *endLine && trimView(lines[anchor].text).empty())
            ++anchor;
        if (anchor >= *endLine)
            continue;
        lines[anchor].states.insert(lines[*endLine].states.begin(), lines[*endLine].states.end());
        if (!lines[anchor].origin && lines[*endLine].origin)
            lines[anchor].origin = lines[*endLine].origin;
        lines[*elseLine].text = std::string(indent, ' ') + "end";
        lines[*endLine].text.clear();
        for (size_t line = *elseLine + 1; line < *endLine; ++line)
            if (!trimView(lines[line].text).empty() && lines[line].text.size() >= 4)
                lines[line].text.erase(0, 4);
        ++flattened;
    }
    return flattened;
}

size_t renameStructuredStateRegisters(std::vector<OutputLine>& lines)
{
    size_t renamed = 0;
    for (size_t declaration = 0; declaration < lines.size(); ++declaration)
    {
        const std::string_view statement = trimView(lines[declaration].text);
        if (!statement.starts_with("local __state = "))
            continue;
        const size_t baseIndent = indentation(lines[declaration].text);
        size_t scopeEnd = lines.size();
        if (baseIndent > 0)
            for (size_t index = declaration + 1; index < lines.size(); ++index)
                if (indentation(lines[index].text) < baseIndent && trimView(lines[index].text) == "end")
                {
                    scopeEnd = index;
                    break;
                }
        bool residualDispatch = false;
        for (size_t index = declaration + 1; index < scopeEnd; ++index)
            if (trimView(lines[index].text) == "while __state ~= nil do")
                residualDispatch = true;
        if (residualDispatch)
        {
            declaration = scopeEnd == lines.size() ? declaration : scopeEnd;
            continue;
        }

        bool firstUseWrites = true;
        for (size_t index = declaration + 1; index < scopeEnd; ++index)
        {
            if (!generatedReads(lines[index].text).contains("__state"))
                continue;
            firstUseWrites = trimView(lines[index].text).starts_with("__state = ");
            break;
        }
        const std::string initial = firstUseWrites ? std::string() : " = " + std::string(statement.substr(std::string_view("local __state = ").size()));
        lines[declaration].text = std::string(baseIndent, ' ') + "local temporary" + initial;
        const std::map<std::string, std::string> replacement{{"__state", "temporary"}};
        size_t constants = 0;
        size_t aliases = 0;
        for (size_t index = declaration + 1; index < scopeEnd; ++index)
            lines[index].text = replaceGeneratedLocals(lines[index].text, replacement, constants, aliases);
        ++renamed;
        if (scopeEnd != lines.size())
            declaration = scopeEnd;
    }
    return renamed;
}

size_t removeUnusedResultDeclarations(std::vector<OutputLine>& lines)
{
    std::vector<bool> remove(lines.size(), false);
    size_t removed = 0;
    for (size_t declaration = 0; declaration < lines.size(); ++declaration)
    {
        if (trimView(lines[declaration].text) != "local __results")
            continue;
        const size_t baseIndent = indentation(lines[declaration].text);
        size_t scopeEnd = lines.size();
        if (baseIndent > 0)
            for (size_t index = declaration + 1; index < lines.size(); ++index)
                if (indentation(lines[index].text) < baseIndent && trimView(lines[index].text) == "end")
                {
                    scopeEnd = index;
                    break;
                }
        bool used = false;
        for (size_t index = declaration + 1; index < scopeEnd; ++index)
            if (generatedReads(lines[index].text).contains("__results"))
                used = true;
        if (!used)
        {
            remove[declaration] = true;
            ++removed;
        }
        if (scopeEnd != lines.size())
            declaration = scopeEnd;
    }
    if (removed == 0)
        return 0;
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return removed;
}

struct FlowNode
{
    enum class Kind
    {
        Statement,
        If,
        While,
        Block,
    };

    Kind kind = Kind::Statement;
    size_t line = 0;
    std::string condition;
    std::vector<FlowNode> first;
    std::vector<FlowNode> second;
};

bool parseFlowSequence(const std::vector<OutputLine>& lines, size_t& cursor, size_t end, size_t indent,
    std::vector<FlowNode>& nodes, const std::map<size_t, size_t>* skippedFunctions = nullptr)
{
    while (cursor < end)
    {
        const std::string_view statement = trimView(lines[cursor].text);
        if (statement.empty())
        {
            nodes.push_back({FlowNode::Kind::Statement, cursor++, {}, {}, {}});
            continue;
        }
        const size_t currentIndent = indentation(lines[cursor].text);
        if (currentIndent < indent || (currentIndent == indent &&
                (statement == "else" || statement == "end" || statement.starts_with("until "))))
            return true;
        if (currentIndent != indent)
            return false;

        if (skippedFunctions)
            if (auto skipped = skippedFunctions->find(cursor); skipped != skippedFunctions->end())
            {
                FlowNode nested{FlowNode::Kind::Statement, cursor, {}, {}, {}};
                std::set<std::string> captured;
                for (size_t line = cursor + 1; line < skipped->second; ++line)
                {
                    const std::set<std::string> reads = generatedReads(lines[line].text);
                    captured.insert(reads.begin(), reads.end());
                }
                for (const std::string& name : captured)
                {
                    nested.condition += name;
                    nested.condition.push_back(' ');
                }
                nodes.push_back(std::move(nested));
                cursor = skipped->second + 1;
                continue;
            }

        if (statement.starts_with("if ") && statement.ends_with(" then"))
        {
            FlowNode node;
            node.kind = FlowNode::Kind::If;
            node.line = cursor++;
            node.condition = std::string(statement.substr(3, statement.size() - 3 - 5));
            if (!parseFlowSequence(lines, cursor, end, indent + 4, node.first, skippedFunctions) || cursor >= end)
                return false;
            if (trimView(lines[cursor].text) == "else" && indentation(lines[cursor].text) == indent)
            {
                ++cursor;
                if (!parseFlowSequence(lines, cursor, end, indent + 4, node.second, skippedFunctions) || cursor >= end)
                    return false;
            }
            if (trimView(lines[cursor].text) != "end" || indentation(lines[cursor].text) != indent)
                return false;
            ++cursor;
            nodes.push_back(std::move(node));
            continue;
        }

        if (statement.starts_with("while ") && statement.ends_with(" do"))
        {
            FlowNode node;
            node.kind = FlowNode::Kind::While;
            node.line = cursor++;
            node.condition = std::string(statement.substr(6, statement.size() - 6 - 3));
            if (!parseFlowSequence(lines, cursor, end, indent + 4, node.first, skippedFunctions) || cursor >= end ||
                trimView(lines[cursor].text) != "end" || indentation(lines[cursor].text) != indent)
                return false;
            ++cursor;
            nodes.push_back(std::move(node));
            continue;
        }

        if (statement.starts_with("for ") && statement.ends_with(" do"))
        {
            FlowNode node;
            node.kind = FlowNode::Kind::While;
            node.line = cursor++;
            node.condition = std::string(statement);
            if (!parseFlowSequence(lines, cursor, end, indent + 4, node.first, skippedFunctions) || cursor >= end ||
                trimView(lines[cursor].text) != "end" || indentation(lines[cursor].text) != indent)
                return false;
            ++cursor;
            nodes.push_back(std::move(node));
            continue;
        }

        if (statement == "repeat")
        {
            FlowNode node;
            node.kind = FlowNode::Kind::While;
            node.line = cursor++;
            if (!parseFlowSequence(lines, cursor, end, indent + 4, node.first, skippedFunctions) || cursor >= end)
                return false;
            const std::string_view ending = trimView(lines[cursor].text);
            if (!ending.starts_with("until ") || indentation(lines[cursor].text) != indent)
                return false;
            node.condition = std::string(ending.substr(6));
            ++cursor;
            nodes.push_back(std::move(node));
            continue;
        }

        if (statement == "do")
        {
            FlowNode node;
            node.kind = FlowNode::Kind::Block;
            node.line = cursor++;
            if (!parseFlowSequence(lines, cursor, end, indent + 4, node.first, skippedFunctions) || cursor >= end ||
                trimView(lines[cursor].text) != "end" || indentation(lines[cursor].text) != indent)
                return false;
            ++cursor;
            nodes.push_back(std::move(node));
            continue;
        }

        nodes.push_back({FlowNode::Kind::Statement, cursor++, {}, {}, {}});
    }
    return true;
}

using LiveSet = std::set<std::string>;

bool followedByLeadingSemicolon(const std::vector<OutputLine>& lines, size_t line)
{
    for (size_t next = line + 1; next < lines.size(); ++next)
    {
        const std::string_view statement = trimView(lines[next].text);
        if (statement.empty())
            continue;
        return statement.starts_with(";");
    }
    return false;
}

void mergeLive(LiveSet& target, const LiveSet& source)
{
    target.insert(source.begin(), source.end());
}

LiveSet analyzeFlow(const std::vector<FlowNode>& nodes, LiveSet live, const std::vector<OutputLine>& lines,
    std::vector<bool>& remove, bool mark, const LexicalCaptureIndex* captures = nullptr,
    size_t captureBefore = std::numeric_limits<size_t>::max())
{
    static const std::regex Assignment(R"(^\s*((?:local_[0-9]+)|temporary|__results)\s*=\s*(.+)$)");
    for (auto iterator = nodes.rbegin(); iterator != nodes.rend(); ++iterator)
    {
        const FlowNode& node = *iterator;
        if (node.kind == FlowNode::Kind::Statement)
        {
            const std::string_view statement = trimView(lines[node.line].text);
            if (statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' '))
            {
                live = generatedReads(statement);
                continue;
            }
            std::smatch assignment;
            if (std::regex_match(lines[node.line].text, assignment, Assignment))
            {
                const std::string target = assignment[1].str();
                const std::string value = assignment[2].str();
                const bool captured = captures && captures->capturedBefore(node.line, target, captureBefore);
                if (mark && !captured && !followedByLeadingSemicolon(lines, node.line) &&
                    (trimView(value) == target || (!live.contains(target) && pureAssignmentValue(value))))
                    remove[node.line] = true;
                live.erase(target);
                mergeLive(live, generatedReads(value));
            }
            else
                mergeLive(live, generatedReads(statement));
            mergeLive(live, generatedReads(node.condition));
            continue;
        }

        if (node.kind == FlowNode::Kind::Block)
        {
            live = analyzeFlow(node.first, std::move(live), lines, remove, mark, captures, captureBefore);
            continue;
        }

        if (node.kind == FlowNode::Kind::If)
        {
            LiveSet first = analyzeFlow(node.first, live, lines, remove, mark, captures, captureBefore);
            LiveSet second = node.second.empty() ? live :
                analyzeFlow(node.second, live, lines, remove, mark, captures, captureBefore);
            mergeLive(first, second);
            mergeLive(first, generatedReads(node.condition));
            live = std::move(first);
            continue;
        }

        LiveSet fixed = live;
        mergeLive(fixed, generatedReads(node.condition));
        for (size_t iteration = 0; iteration < 128; ++iteration)
        {
            LiveSet body = analyzeFlow(node.first, fixed, lines, remove, false, captures, captureBefore);
            LiveSet next = live;
            mergeLive(next, generatedReads(node.condition));
            mergeLive(next, body);
            if (next == fixed)
                break;
            fixed = std::move(next);
        }
        analyzeFlow(node.first, fixed, lines, remove, mark, captures, captureBefore);
        live = std::move(fixed);
    }
    return live;
}

size_t eliminateStructuredDeadAssignments(std::vector<OutputLine>& lines)
{
    struct Scope
    {
        size_t begin = 0;
        size_t end = 0;
        size_t indent = 0;
    };

    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    std::map<size_t, size_t> skippedFunctions;
    for (const ScalarFunctionSpan& span : *spans)
        skippedFunctions[span.opener] = span.end;

    std::vector<Scope> scopes;
    if (!lines.empty())
    {
        size_t rootIndent = 0;
        for (const OutputLine& line : lines)
            if (!trimView(line.text).empty())
            {
                rootIndent = indentation(line.text);
                break;
            }
        scopes.push_back({0, lines.size(), rootIndent});
    }
    for (const ScalarFunctionSpan& span : *spans)
        scopes.push_back({span.opener + 1, span.end, span.indent + 4});

    std::vector<bool> remove(lines.size(), false);
    for (const Scope& scope : scopes)
    {
        bool residual = false;
        for (size_t index = scope.begin; index < scope.end; ++index)
            if (trimView(lines[index].text) == "while __state ~= nil do")
                residual = true;
        if (residual || scope.begin >= scope.end)
            continue;
        size_t cursor = scope.begin;
        std::vector<FlowNode> nodes;
        if (!parseFlowSequence(lines, cursor, scope.end, scope.indent, nodes, &skippedFunctions) ||
            cursor != scope.end)
            continue;
        analyzeFlow(nodes, {}, lines, remove, true, &captures, scope.end);
    }

    const size_t removed = static_cast<size_t>(std::count(remove.begin(), remove.end(), true));
    if (removed == 0)
        return 0;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        if (!remove[index] || lines[index].states.empty())
            continue;
        size_t anchor = index + 1;
        while (anchor < lines.size() && remove[anchor])
            ++anchor;
        if (anchor == lines.size())
        {
            anchor = index;
            while (anchor > 0 && remove[anchor])
                --anchor;
        }
        if (anchor < lines.size() && !remove[anchor])
            lines[anchor].states.insert(lines[index].states.begin(), lines[index].states.end());
    }
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return removed;
}

size_t eliminateDeadAssignments(std::vector<OutputLine>& lines)
{
    static const std::regex Assignment(R"(^\s*((?:local_[0-9]+)|__state|__results)\s*=\s*(.+)$)");
    std::map<std::string, size_t> pending;
    std::vector<bool> remove(lines.size(), false);
    for (size_t index = 0; index < lines.size(); ++index)
    {
        const std::string_view statement = trimView(lines[index].text);
        const bool returns = statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' ');
        if (returns)
        {
            const std::set<std::string> reads = generatedReads(statement);
            for (const auto& [name, definition] : pending)
                if (!reads.contains(name) && !followedByLeadingSemicolon(lines, definition))
                    remove[definition] = true;
            pending.clear();
            continue;
        }
        if (controlBoundary(statement))
        {
            pending.clear();
            continue;
        }

        std::smatch match;
        const std::string text(lines[index].text);
        if (!std::regex_match(text, match, Assignment))
        {
            for (const std::string& read : generatedReads(statement))
                pending.erase(read);
            continue;
        }

        const std::string target = match[1].str();
        const std::string value = match[2].str();
        if (trimView(value) == target)
        {
            remove[index] = true;
            continue;
        }
        for (const std::string& read : generatedReads(value))
            pending.erase(read);
        if (auto previous = pending.find(target); previous != pending.end())
            if (!followedByLeadingSemicolon(lines, previous->second))
                remove[previous->second] = true;
        pending.erase(target);
        if (pureAssignmentValue(value))
            pending.emplace(target, index);
    }

    size_t removed = static_cast<size_t>(std::count(remove.begin(), remove.end(), true));
    if (removed == 0)
        return 0;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        if (!remove[index] || lines[index].states.empty())
            continue;
        size_t anchor = index + 1;
        while (anchor < lines.size() && remove[anchor])
            ++anchor;
        if (anchor == lines.size())
        {
            anchor = index;
            while (anchor > 0 && remove[anchor])
                --anchor;
        }
        if (anchor < lines.size() && !remove[anchor])
            lines[anchor].states.insert(lines[index].states.begin(), lines[index].states.end());
    }
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return removed;
}

struct SimpleAssignment
{
    std::string target;
    std::string value;
};

std::optional<SimpleAssignment> simpleAssignment(std::string_view line)
{
    static const std::regex Assignment(R"(^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$)");
    std::smatch match;
    const std::string text(line);
    if (!std::regex_match(text, match, Assignment))
        return std::nullopt;
    return SimpleAssignment{match[1].str(), trim(match[2].str())};
}

std::string_view stripOuterParentheses(std::string_view value)
{
    value = trimView(value);
    while (value.size() >= 2 && value.front() == '(' && value.back() == ')')
    {
        int depth = 0;
        bool wraps = true;
        char quote = 0;
        for (size_t index = 0; index < value.size(); ++index)
        {
            const char ch = value[index];
            if (quote != 0)
            {
                if (ch == '\\')
                    ++index;
                else if (ch == quote)
                    quote = 0;
                continue;
            }
            if (ch == '\'' || ch == '"')
                quote = ch;
            else if (ch == '(')
                ++depth;
            else if (ch == ')')
            {
                --depth;
                if (depth == 0 && index + 1 != value.size())
                {
                    wraps = false;
                    break;
                }
            }
        }
        if (!wraps || depth != 0)
            break;
        value = trimView(value.substr(1, value.size() - 2));
    }
    return value;
}

std::optional<std::pair<std::string, std::string>> splitSimpleBinary(std::string_view value, std::string_view operation)
{
    value = stripOuterParentheses(value);
    int depth = 0;
    char quote = 0;
    for (size_t index = 0; index + operation.size() <= value.size(); ++index)
    {
        const char ch = value[index];
        if (quote != 0)
        {
            if (ch == '\\')
                ++index;
            else if (ch == quote)
                quote = 0;
            continue;
        }
        if (ch == '\'' || ch == '"')
            quote = ch;
        else if (ch == '(' || ch == '[' || ch == '{')
            ++depth;
        else if (ch == ')' || ch == ']' || ch == '}')
            --depth;
        else if (depth == 0 && value.substr(index).starts_with(operation))
            return std::pair{trim(value.substr(0, index)), trim(value.substr(index + operation.size()))};
    }
    return std::nullopt;
}

bool safeLoopExpression(std::string_view value)
{
    value = trimView(value);
    return scalarLiteral(value) || generatedLocal(value) || bareReadableGlobal(value);
}

std::optional<size_t> previousAssignment(
    const std::vector<OutputLine>& lines, size_t before, size_t indent, std::string_view target, size_t maximumDistance = 40)
{
    const size_t lower = before > maximumDistance ? before - maximumDistance : 0;
    for (size_t index = before; index > lower; --index)
    {
        const size_t candidate = index - 1;
        if (indentation(lines[candidate].text) != indent)
            continue;
        auto assignment = simpleAssignment(lines[candidate].text);
        if (assignment && assignment->target == target)
            return candidate;
    }
    return std::nullopt;
}

size_t recoverNumericForLoops(std::vector<OutputLine>& lines)
{
    static const std::regex Comparison(R"(^([A-Za-z_][A-Za-z0-9_]*)\s*(<=|>=)\s*([A-Za-z_][A-Za-z0-9_]*)$)");
    static const std::regex Identifier(R"(^[A-Za-z_][A-Za-z0-9_]*$)");
    size_t recovered = 0;
    size_t loopNumber = 0;
    for (size_t loop = 0; loop < lines.size(); ++loop)
    {
        if (trimView(lines[loop].text) != "while true do")
            continue;
        const size_t indent = indentation(lines[loop].text);
        size_t loopEnd = loop + 1;
        while (loopEnd < lines.size() && !(indentation(lines[loopEnd].text) == indent && trimView(lines[loopEnd].text) == "end"))
            ++loopEnd;
        if (loopEnd >= lines.size())
            continue;

        size_t branch = loop + 1;
        while (branch < loopEnd && !(indentation(lines[branch].text) == indent + 4 &&
                                       trimView(lines[branch].text).starts_with("if ") && trimView(lines[branch].text).ends_with(" then")))
            ++branch;
        if (branch == loop + 1 || branch >= loopEnd)
            continue;
        size_t branchEnd = branch + 1;
        while (branchEnd < loopEnd && !(indentation(lines[branchEnd].text) == indent + 4 && trimView(lines[branchEnd].text) == "end"))
            ++branchEnd;
        if (branchEnd >= loopEnd || branchEnd == branch + 1 || trimView(lines[branchEnd - 1].text) != "continue")
            continue;

        std::optional<std::string> current;
        std::optional<std::string> stepRegister;
        for (size_t index = loop + 1; index < branch; ++index)
        {
            auto assignment = simpleAssignment(lines[index].text);
            if (!assignment)
                continue;
            auto addition = splitSimpleBinary(assignment->value, " + ");
            if (!addition)
                continue;
            if (addition->first == assignment->target)
            {
                current = assignment->target;
                stepRegister = addition->second;
                break;
            }
            if (addition->second == assignment->target)
            {
                current = assignment->target;
                stepRegister = addition->first;
                break;
            }
        }
        if (!current || !stepRegister || !generatedLocal(*current) || !std::regex_match(*stepRegister, Identifier))
            continue;

        std::map<std::string, size_t> finalCandidates;
        for (size_t index = loop + 1; index < branch; ++index)
        {
            auto assignment = simpleAssignment(lines[index].text);
            if (!assignment)
                continue;
            const std::string comparisonText(stripOuterParentheses(assignment->value));
            std::smatch comparison;
            if (!std::regex_match(comparisonText, comparison, Comparison))
                continue;
            const std::string left = comparison[1].str();
            const std::string right = comparison[3].str();
            if (left == *current && right != *current)
                ++finalCandidates[right];
            else if (right == *current && left != *current)
                ++finalCandidates[left];
        }
        if (finalCandidates.empty())
            continue;
        const auto finalCandidate = std::max_element(finalCandidates.begin(), finalCandidates.end(),
            [](const auto& left, const auto& right) { return left.second < right.second; });
        if (finalCandidate->second < 2)
            continue;
        const std::string finalRegister = finalCandidate->first;

        auto currentDefinition = previousAssignment(lines, loop, indent, *current);
        auto stepDefinition = previousAssignment(lines, loop, indent, *stepRegister);
        auto finalDefinition = previousAssignment(lines, loop, indent, finalRegister);
        if (!currentDefinition || !stepDefinition || !finalDefinition)
            continue;
        auto currentAssignment = simpleAssignment(lines[*currentDefinition].text);
        auto stepAssignment = simpleAssignment(lines[*stepDefinition].text);
        auto finalAssignment = simpleAssignment(lines[*finalDefinition].text);
        if (!currentAssignment || !stepAssignment || !finalAssignment)
            continue;
        auto initialAndStep = splitSimpleBinary(currentAssignment->value, " - ");
        if (!initialAndStep || !safeLoopExpression(initialAndStep->first) || !safeLoopExpression(stepAssignment->value) ||
            !safeLoopExpression(finalAssignment->value))
            continue;
        const std::string initial = initialAndStep->first;
        const std::string step = stepAssignment->value;
        const std::string finalValue = finalAssignment->value;

        std::optional<std::string> negativeRegister;
        for (size_t index = loop + 1; index < branch; ++index)
        {
            auto assignment = simpleAssignment(lines[index].text);
            if (!assignment)
                continue;
            const std::string_view value = stripOuterParentheses(assignment->value);
            if (value.starts_with("not "))
            {
                const std::string candidate = trim(value.substr(4));
                if (std::regex_match(candidate, Identifier))
                {
                    negativeRegister = candidate;
                    break;
                }
            }
        }
        std::optional<size_t> negativeDefinition;
        if (negativeRegister)
            negativeDefinition = previousAssignment(lines, loop, indent, *negativeRegister);

        std::set<size_t> remove{*currentDefinition, *stepDefinition, *finalDefinition};
        if (negativeDefinition)
            remove.insert(*negativeDefinition);
        std::set<int64_t> headerStates = lines[loop].states;
        std::optional<size_t> headerOrigin = lines[loop].origin;
        for (size_t index = loop + 1; index <= branch; ++index)
        {
            headerStates.insert(lines[index].states.begin(), lines[index].states.end());
            if (!headerOrigin && lines[index].origin)
                headerOrigin = lines[index].origin;
        }
        for (size_t index : remove)
        {
            headerStates.insert(lines[index].states.begin(), lines[index].states.end());
            if (!headerOrigin && lines[index].origin)
                headerOrigin = lines[index].origin;
        }

        const std::string loopVariable = "index_" + std::to_string(++loopNumber);
        std::string header(indent, ' ');
        header += "for " + loopVariable + " = " + initial + ", " + finalValue;
        if (trimView(step) != "1")
            header += ", " + step;
        header += " do";

        std::vector<OutputLine> replacement;
        replacement.push_back({std::move(header), headerOrigin, std::move(headerStates)});
        std::map<std::string, std::string> variableReplacement{{*current, loopVariable}};
        for (size_t index = branch + 1; index + 1 < branchEnd; ++index)
        {
            OutputLine bodyLine = lines[index];
            if (bodyLine.text.size() >= 4)
                bodyLine.text.erase(0, 4);
            size_t constants = 0;
            size_t aliases = 0;
            bodyLine.text = replaceGeneratedLocals(bodyLine.text, variableReplacement, constants, aliases);
            replacement.push_back(std::move(bodyLine));
        }
        const size_t endingIndex = replacement.size();
        replacement.push_back({std::string(indent, ' ') + "end", lines[loopEnd].origin, lines[loopEnd].states});
        for (size_t index = branchEnd + 1; index < loopEnd; ++index)
        {
            // The false branch exits the synthetic while-loop. Once the loop is
            // reconstructed as a numeric for, that break is represented by the
            // for-loop ending and must not escape into the surrounding scope.
            if (trimView(lines[index].text) == "break")
            {
                replacement[endingIndex].states.insert(lines[index].states.begin(), lines[index].states.end());
                continue;
            }
            OutputLine continuation = lines[index];
            if (continuation.text.size() >= 4)
                continuation.text.erase(0, 4);
            replacement.push_back(std::move(continuation));
        }

        std::vector<OutputLine> rebuilt;
        rebuilt.reserve(lines.size() - (loopEnd - loop) + replacement.size());
        for (size_t index = 0; index < loop; ++index)
            if (!remove.contains(index))
                rebuilt.push_back(std::move(lines[index]));
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(replacement.begin()), std::make_move_iterator(replacement.end()));
        for (size_t index = loopEnd + 1; index < lines.size(); ++index)
            rebuilt.push_back(std::move(lines[index]));
        lines = std::move(rebuilt);
        ++recovered;
        loop = 0;
    }
    return recovered;
}

size_t recoverCanonicalStateNumericLoops(std::vector<OutputLine>& lines)
{
    static const std::regex InductionAssignment(R"(^\s*(.+?)\s*=\s*state\.f;?$)");
    static const std::array<std::string_view, 9> Prefix = {
        "state.l = false",
        "state.f += state.A",
        "if state.A <= 0 then",
        "state.l = state.f >= state.I",
        "else",
        "state.l = state.f <= state.I",
        "end",
        "if state.l then",
        "end",
    };

    size_t recovered = 0;
    size_t loopNumber = 0;
    auto canonicalStatement = [](std::string_view value) {
        value = trimView(value);
        if (value.ends_with(';'))
            value.remove_suffix(1);
        if (value.starts_with("state.l = (") && value.ends_with(')'))
        {
            value.remove_suffix(1);
            value.remove_prefix(std::string_view("state.l = (").size());
            static thread_local std::string normalized;
            normalized = "state.l = " + std::string(value);
            return std::string_view(normalized);
        }
        return value;
    };
    for (size_t loop = 0; loop < lines.size(); ++loop)
    {
        if (trimView(lines[loop].text) != "while true do")
            continue;
        const size_t indent = indentation(lines[loop].text);
        size_t loopEnd = loop + 1;
        while (loopEnd < lines.size() &&
            !(indentation(lines[loopEnd].text) == indent && trimView(lines[loopEnd].text) == "end"))
            ++loopEnd;
        if (loopEnd >= lines.size())
            continue;

        std::vector<size_t> bodyLines;
        for (size_t line = loop + 1; line < loopEnd; ++line)
            if (!trimView(lines[line].text).empty())
                bodyLines.push_back(line);
        if (bodyLines.size() < 12)
            continue;
        const size_t bodyIndent = indentation(lines[bodyLines.front()].text);
        if (bodyIndent <= indent)
            continue;
        bool prefixMatches = true;
        for (size_t index = 0; index < 8; ++index)
            if (canonicalStatement(lines[bodyLines[index]].text) != Prefix[index])
                prefixMatches = false;
        if (!prefixMatches || trimView(lines[bodyLines[9]].text) != Prefix[8])
            continue;
        std::smatch inductionMatch;
        const std::string inductionStatement(lines[bodyLines[8]].text);
        if (!std::regex_match(inductionStatement, inductionMatch, InductionAssignment))
            continue;
        const std::string inductionTarget = trim(inductionMatch[1].str());
        const size_t finalBreak = bodyLines.back();
        if (trimView(lines[finalBreak].text) != "break" || indentation(lines[finalBreak].text) != bodyIndent)
            continue;

        bool traceControlled = false;
        for (size_t line = bodyLines[10]; line < loopEnd; ++line)
            if (lines[line].text.find("replay_activation_transition") != std::string::npos ||
                lines[line].text.find("loop_exit_") != std::string::npos)
                traceControlled = true;
        if (traceControlled)
            continue;

        std::vector<size_t> setup;
        for (size_t line = loop; line > 0 && setup.size() < 5;)
        {
            --line;
            if (!trimView(lines[line].text).empty())
                setup.push_back(line);
        }
        if (setup.size() != 5)
            continue;
        std::reverse(setup.begin(), setup.end());
        if (canonicalStatement(lines[setup[0]].text) !=
                "state.s = {[4] = state.f, [3] = state.A, [5] = state.s, [1] = state.I}" ||
            !trimView(lines[setup[1]].text).starts_with("state.l = "))
            continue;
        auto stateValue = [&](size_t line, std::string_view prefix) -> std::optional<std::string> {
            std::string_view statement = canonicalStatement(lines[line].text);
            if (!statement.starts_with(prefix))
                return std::nullopt;
            return trim(statement.substr(prefix.size()));
        };
        const auto stepSetup = stateValue(setup[2], "state.A = ");
        const auto finalSetup = stateValue(setup[3], "state.I = ");
        const auto initialSetup = stateValue(setup[4], "state.f = ");
        if (!stepSetup || !finalSetup || !initialSetup)
            continue;
        const auto stepExpression = splitSimpleBinary(*stepSetup, " + ");
        const auto finalExpression = splitSimpleBinary(*finalSetup, " + ");
        const auto initialExpression = splitSimpleBinary(*initialSetup, " - ");
        if (!stepExpression || trimView(stepExpression->second) != "0" || !finalExpression ||
            trimView(finalExpression->second) != "0" || !initialExpression ||
            trimView(initialExpression->second) != "state.A")
            continue;
        const std::string step = trim(stepExpression->first);
        const std::string finalValue = trim(finalExpression->first);
        const std::string initial = trim(initialExpression->first);
        if (containsCallSyntax(step) || containsCallSyntax(finalValue) || containsCallSyntax(initial))
            continue;

        const std::string loopVariable = "numeric_index_" + std::to_string(++loopNumber);
        std::set<int64_t> headerStates = lines[loop].states;
        std::optional<size_t> headerOrigin = lines[loop].origin;
        for (size_t line : setup)
        {
            headerStates.insert(lines[line].states.begin(), lines[line].states.end());
            if (!headerOrigin && lines[line].origin)
                headerOrigin = lines[line].origin;
        }
        for (size_t index = 0; index < 10; ++index)
        {
            const size_t line = bodyLines[index];
            headerStates.insert(lines[line].states.begin(), lines[line].states.end());
            if (!headerOrigin && lines[line].origin)
                headerOrigin = lines[line].origin;
        }

        std::string header(indent, ' ');
        header += "for " + loopVariable + " = " + initial + ", " + finalValue;
        if (trimView(step) != "1")
            header += ", " + step;
        header += " do";
        OutputLine induction = lines[bodyLines[8]];
        induction.text = std::string(bodyIndent, ' ') + inductionTarget + " = " + loopVariable;

        std::vector<OutputLine> replacement;
        replacement.push_back({std::move(header), headerOrigin, std::move(headerStates)});
        replacement.push_back(std::move(induction));
        for (size_t line = bodyLines[9] + 1; line < finalBreak; ++line)
            replacement.push_back(lines[line]);
        replacement.push_back({std::string(indent, ' ') + "end", lines[loopEnd].origin, lines[loopEnd].states});
        replacement.back().states.insert(lines[finalBreak].states.begin(), lines[finalBreak].states.end());

        std::vector<OutputLine> rebuilt;
        rebuilt.reserve(lines.size() - (loopEnd - setup[1]) + replacement.size());
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(lines.begin()),
            std::make_move_iterator(lines.begin() + static_cast<std::ptrdiff_t>(setup[1])));
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(replacement.begin()),
            std::make_move_iterator(replacement.end()));
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(lines.begin() + static_cast<std::ptrdiff_t>(loopEnd + 1)),
            std::make_move_iterator(lines.end()));
        lines = std::move(rebuilt);
        ++recovered;
        loop = 0;
    }
    return recovered;
}

size_t recoverFixedRegisterCallPacks(std::vector<OutputLine>& lines)
{
    static const std::regex BaseSetup(R"(^state\.l = ([0-9]+);?$)");
    static const std::regex ArgumentSetup(R"(^state\.M = ([0-9]+);?$)");
    static const std::regex ResultSetup(R"(^state\.w = ([0-9]+);?$)");
    const std::array<std::string, 5> scratchFields = {"l", "M", "w", "K", "L"};

    auto statement = [](std::string_view text) {
        text = trimView(text);
        if (text.ends_with(';'))
            text.remove_suffix(1);
        return text;
    };
    auto stateScratchDead = [&](size_t after) {
        std::map<std::string, bool> overwritten;
        for (const std::string& field : scratchFields)
            overwritten[field] = false;
        for (size_t line = after; line < lines.size(); ++line)
        {
            const std::string_view current = statement(lines[line].text);
            if (indentation(lines[line].text) == 0 && current == "end")
                break;
            for (const std::string& field : scratchFields)
            {
                if (overwritten[field])
                    continue;
                const std::string name = "state." + field;
                if (current.find(name) == std::string_view::npos)
                    continue;
                bool directOverwrite = current.starts_with(name + " = ");
                if ((field == "K" || field == "L") && current.starts_with("state.K, state.L = "))
                    directOverwrite = true;
                if (!directOverwrite)
                    return false;
                const size_t equals = current.find('=');
                if (equals != std::string_view::npos && current.substr(equals + 1).find(name) != std::string_view::npos)
                    return false;
                overwritten[field] = true;
            }
        }
        return true;
    };

    size_t recovered = 0;
    for (size_t start = 0; start < lines.size(); ++start)
    {
        std::smatch baseMatch;
        const std::string first(statement(lines[start].text));
        if (!std::regex_match(first, baseMatch, BaseSetup))
            continue;
        std::vector<size_t> capsule;
        for (size_t line = start; line < lines.size() && capsule.size() < 28; ++line)
            if (!trimView(lines[line].text).empty())
                capsule.push_back(line);
        if (capsule.size() != 28)
            continue;
        std::smatch argumentMatch;
        std::smatch resultMatch;
        const std::string argumentLine(statement(lines[capsule[1]].text));
        const std::string resultLine(statement(lines[capsule[2]].text));
        if (!std::regex_match(argumentLine, argumentMatch, ArgumentSetup) ||
            !std::regex_match(resultLine, resultMatch, ResultSetup))
            continue;
        const auto base = parseInteger(baseMatch[1].str());
        const auto argumentCount = parseInteger(argumentMatch[1].str());
        const auto resultCode = parseInteger(resultMatch[1].str());
        if (!base || !argumentCount || !resultCode || *base < 1 || *argumentCount < 1 || *argumentCount > 16 ||
            *resultCode < 2 || *resultCode > 16)
            continue;

        const auto text = [&](size_t index) { return statement(lines[capsule[index]].text); };
        if (!text(3).starts_with("if not") || text(3).find("state.M == 0") == std::string_view::npos ||
            !text(4).starts_with("top = ") || text(5) != "end" || text(6) != "state.K, state.L = nil" ||
            text(7) != "if state.M ~= 1 then" || text(8).find("helper_values[53]") == std::string_view::npos ||
            text(8).find("helper_values[23]") == std::string_view::npos || text(8).find("registers[state.l]") == std::string_view::npos ||
            text(9) != "else" || text(10).find("helper_values[53]") == std::string_view::npos ||
            text(10).find("helper_values[23]") != std::string_view::npos || text(11) != "end" ||
            text(12) != "if state.w ~= 1 then" || text(13) != "if state.w == 0 then" ||
            !text(14).starts_with("state.K = ") || !text(15).starts_with("top = ") || text(16) != "else" ||
            !text(17).starts_with("state.K = ") || !text(18).starts_with("top = ") || text(19) != "end" ||
            text(20) != "state.M = 0" || text(21) != "for loop_index = state.l, state.K, 1 do" ||
            text(22) != "state.M += 1" || text(23) != "registers[loop_index] = state.L[state.M]" ||
            text(24) != "end" || text(25) != "else" || !text(26).starts_with("top = ") || text(27) != "end")
            continue;
        const size_t capsuleEnd = capsule.back();
        if (!stateScratchDead(capsuleEnd + 1))
            continue;

        const int64_t resultCount = *resultCode - 1;
        std::string direct(indentation(lines[start].text), ' ');
        for (int64_t index = 0; index < resultCount; ++index)
        {
            if (index)
                direct += ", ";
            direct += "registers[" + std::to_string(*base + index) + "]";
        }
        direct += " = registers[" + std::to_string(*base) + "](";
        for (int64_t index = 1; index < *argumentCount; ++index)
        {
            if (index > 1)
                direct += ", ";
            direct += "registers[" + std::to_string(*base + index) + "]";
        }
        direct += ")";
        OutputLine call{std::move(direct), lines[start].origin, lines[start].states};
        for (size_t line = start + 1; line <= capsuleEnd; ++line)
        {
            call.states.insert(lines[line].states.begin(), lines[line].states.end());
            if (!call.origin && lines[line].origin)
                call.origin = lines[line].origin;
        }
        OutputLine topLine{std::string(indentation(lines[start].text), ' ') + "top = " +
                std::to_string(*base + resultCount),
            lines[capsuleEnd].origin, lines[capsuleEnd].states};

        std::vector<OutputLine> rebuilt;
        rebuilt.reserve(lines.size() - (capsuleEnd - start + 1) + 2);
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(lines.begin()),
            std::make_move_iterator(lines.begin() + static_cast<std::ptrdiff_t>(start)));
        rebuilt.push_back(std::move(call));
        rebuilt.push_back(std::move(topLine));
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(lines.begin() + static_cast<std::ptrdiff_t>(capsuleEnd + 1)),
            std::make_move_iterator(lines.end()));
        lines = std::move(rebuilt);
        ++recovered;
        start = 0;
    }
    return recovered;
}

size_t simplifyConstantCallPacks(std::vector<OutputLine>& lines)
{
    auto compact = [](std::string_view value) {
        std::string result;
        result.reserve(value.size());
        for (char ch : value)
            if (!std::isspace(static_cast<unsigned char>(ch)) && ch != '(' && ch != ')' && ch != ';')
                result.push_back(ch);
        return result;
    };
    auto constantAssignment = [&](const OutputLine& line, std::string_view target) -> std::optional<int64_t> {
        std::string_view current = trimView(line.text);
        if (current.ends_with(';'))
            current.remove_suffix(1);
        const std::string prefix = std::string(target) + " = ";
        if (!current.starts_with(prefix))
            return std::nullopt;
        return parseInteger(trim(stripOuterParentheses(current.substr(prefix.size()))));
    };

    size_t simplified = 0;
    size_t packNumber = 0;
    for (size_t start = 0; start < lines.size(); ++start)
    {
        const auto base = constantAssignment(lines[start], "state.l");
        if (!base || *base < 1 || *base > 4096)
            continue;
        std::vector<size_t> statements;
        for (size_t line = start; line < lines.size() && statements.size() < 28; ++line)
            if (!trimView(lines[line].text).empty())
                statements.push_back(line);
        if (statements.size() != 28)
            continue;
        const auto argumentCount = constantAssignment(lines[statements[1]], "state.M");
        const auto wanted = constantAssignment(lines[statements[2]], "state.w");
        if (!argumentCount || !wanted || *argumentCount < 0 || *argumentCount > 4096 || *wanted < 0 || *wanted > 4096)
            continue;

        const std::array<std::pair<size_t, std::string_view>, 22> expected = {{
            {3, "ifnotstate.M==0then"},
            {4, "top=state.l+state.M-1"},
            {5, "end"},
            {6, "state.K,state.L=nil"},
            {7, "ifstate.M~=1then"},
            {9, "else"},
            {10, "state.K,state.L=helper_values[53]registers[state.l]"},
            {11, "end"},
            {12, "ifstate.w~=1then"},
            {13, "ifstate.w==0then"},
            {14, "state.K=state.K+state.l-1"},
            {15, "top=state.K"},
            {16, "else"},
            {17, "state.K=state.l+state.w-2"},
            {18, "top=state.K+1"},
            {19, "end"},
            {20, "state.M=0"},
            {21, "forloop_index=state.l,state.K,1do"},
            {22, "state.M+=1"},
            {23, "registers[loop_index]=state.L[state.M]"},
            {24, "end"},
            {25, "else"},
        }};
        bool valid = true;
        for (const auto& [index, value] : expected)
            if (compact(lines[statements[index]].text) != value)
                valid = false;
        if (!valid || compact(lines[statements[26]].text) != "top=state.l-1" ||
            compact(lines[statements[27]].text) != "end")
            continue;
        const std::string packedCall = compact(lines[statements[8]].text);
        if (*argumentCount != 1 && packedCall !=
            "state.K,state.L=helper_values[53]registers[state.l]helper_values[23]state.l+1,registers,top")
            continue;

        std::string call = "registers[" + std::to_string(*base) + "](";
        if (*argumentCount == 0)
            call += "unpack_values(registers, " + std::to_string(*base + 1) + ", top)";
        else
            for (int64_t index = 1; index < *argumentCount; ++index)
            {
                if (index > 1)
                    call += ", ";
                call += "registers[" + std::to_string(*base + index) + "]";
            }
        call += ")";

        const size_t indent = indentation(lines[start].text);
        const std::string padding(indent, ' ');
        const std::string bodyPadding(indent + 2, ' ');
        std::vector<OutputLine> replacement;
        if (*wanted == 1)
        {
            replacement.push_back({padding + call, std::nullopt, {}});
            replacement.push_back({padding + "top = " + std::to_string(*base - 1), std::nullopt, {}});
        }
        else if (*wanted >= 2 && *wanted <= 16)
        {
            std::string assignment = padding;
            for (int64_t index = 0; index < *wanted - 1; ++index)
            {
                if (index)
                    assignment += ", ";
                assignment += "registers[" + std::to_string(*base + index) + "]";
            }
            assignment += " = " + call;
            replacement.push_back({std::move(assignment), std::nullopt, {}});
            replacement.push_back({padding + "top = " + std::to_string(*base + *wanted - 1), std::nullopt, {}});
        }
        else
        {
            const std::string suffix = std::to_string(++packNumber);
            const std::string values = "packed_values_" + suffix;
            const std::string index = "packed_index_" + suffix;
            if (*wanted == 0)
            {
                const std::string count = "packed_count_" + suffix;
                replacement.push_back({padding + "local " + count + ", " + values + " = helper_values[53](" + call + ")",
                    std::nullopt, {}});
                replacement.push_back({padding + "top = " + count + " + " + std::to_string(*base - 1), std::nullopt, {}});
                replacement.push_back({padding + "for " + index + " = 1, " + count + " do", std::nullopt, {}});
            }
            else
            {
                replacement.push_back({padding + "local _, " + values + " = helper_values[53](" + call + ")",
                    std::nullopt, {}});
                replacement.push_back({padding + "top = " + std::to_string(*base + *wanted - 1), std::nullopt, {}});
                replacement.push_back({padding + "for " + index + " = 1, " + std::to_string(*wanted - 1) + " do",
                    std::nullopt, {}});
            }
            replacement.push_back({bodyPadding + "registers[" + std::to_string(*base - 1) + " + " + index + "] = " +
                    values + "[" + index + "]",
                std::nullopt, {}});
            replacement.push_back({padding + "end", std::nullopt, {}});
        }

        auto retained = replacement.begin();
        for (size_t line = start; line <= statements.back(); ++line)
        {
            retained->states.insert(lines[line].states.begin(), lines[line].states.end());
            if (!retained->origin && lines[line].origin)
                retained->origin = lines[line].origin;
        }
        std::vector<OutputLine> rebuilt;
        rebuilt.reserve(lines.size() - (statements.back() - start + 1) + replacement.size());
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(lines.begin()),
            std::make_move_iterator(lines.begin() + static_cast<std::ptrdiff_t>(start)));
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(replacement.begin()),
            std::make_move_iterator(replacement.end()));
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(lines.begin() + static_cast<std::ptrdiff_t>(statements.back() + 1)),
            std::make_move_iterator(lines.end()));
        lines = std::move(rebuilt);
        ++simplified;
        start = 0;
    }
    return simplified;
}

size_t expandFixedTopCallPacks(std::vector<OutputLine>& lines)
{
    static const std::regex PackedRange(
        R"(unpack_values\(registers,\s*\(\s*(-?[0-9]+)\s*\+\s*1\s*\),\s*top\))");
    size_t expanded = 0;
    for (size_t line = 0; line < lines.size(); ++line)
    {
        const std::string statement(trimView(lines[line].text));
        std::smatch range;
        if (!std::regex_search(statement, range, PackedRange))
            continue;
        const auto base = parseInteger(range[1].str());
        if (!base)
            continue;
        size_t previous = line;
        while (previous > 0 && trimView(lines[previous - 1].text).empty())
            --previous;
        if (previous == 0)
            continue;
        --previous;
        if (indentation(lines[previous].text) != indentation(lines[line].text))
            continue;
        std::string_view topAssignment = trimView(lines[previous].text);
        if (topAssignment.ends_with(';'))
            topAssignment.remove_suffix(1);
        constexpr std::string_view Prefix = "top = ";
        if (!topAssignment.starts_with(Prefix))
            continue;
        const auto top = parseConstantIntegerExpression(topAssignment.substr(Prefix.size()));
        if (!top || *top < *base || *top - *base > 32)
            continue;

        std::string arguments;
        for (int64_t slot = *base + 1; slot <= *top; ++slot)
        {
            if (!arguments.empty())
                arguments += ", ";
            arguments += "registers[" + std::to_string(slot) + "]";
        }
        const size_t matchOffset = static_cast<size_t>(range.position(0));
        const size_t sourceOffset = lines[line].text.find(statement);
        if (sourceOffset == std::string::npos)
            continue;
        lines[line].text.replace(sourceOffset + matchOffset, static_cast<size_t>(range.length(0)), arguments);
        ++expanded;
    }
    return expanded;
}

bool knownCommandCall(std::string_view value)
{
    value = trimView(value);
    return value.starts_with("print(") || value.starts_with("warn(");
}

size_t discardUnusedCommandResults(std::vector<OutputLine>& lines)
{
    static const std::regex Assignment(R"(^(\s*)((?:local_[0-9]+)|temporary)\s*=\s*(.+)$)");
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    std::map<size_t, size_t> functionEnds;
    for (const ScalarFunctionSpan& span : *spans)
        functionEnds.emplace(span.opener, span.end);
    size_t removed = 0;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        std::smatch assignment;
        if (!std::regex_match(lines[index].text, assignment, Assignment) || !knownCommandCall(assignment[3].str()))
            continue;
        const std::string target = assignment[2].str();
        bool used = false;
        bool bounded = false;
        for (size_t next = index + 1; next < lines.size(); ++next)
        {
            if (auto functionEnd = functionEnds.find(next); functionEnd != functionEnds.end())
            {
                for (size_t line = next; line <= functionEnd->second; ++line)
                    if (generatedReads(lines[line].text).contains(target))
                    {
                        used = true;
                        break;
                    }
                if (used)
                    break;
                next = functionEnd->second;
                continue;
            }
            const std::string_view statement = trimView(lines[next].text);
            if (auto writes = identifierAssignmentList(statement);
                writes && std::find(writes->targets.begin(), writes->targets.end(), target) != writes->targets.end())
            {
                if (generatedReads(statement.substr(writes->value_begin)).contains(target))
                    used = true;
                else
                    bounded = true;
                break;
            }
            if (generatedReads(statement).contains(target))
            {
                used = true;
                break;
            }
            auto nextAssignment = simpleAssignment(statement);
            if (nextAssignment && nextAssignment->target == target)
            {
                bounded = true;
                break;
            }
            if (statement.starts_with("return") || statement == "end")
            {
                bounded = true;
                break;
            }
            if (controlBoundary(statement))
                break;
        }
        if (used || !bounded)
            continue;
        lines[index].text = assignment[1].str() + assignment[3].str();
        ++removed;
    }
    return removed;
}

std::vector<std::string> splitCaptureExpressions(std::string_view source);

size_t collapseEmptyResultReturns(std::vector<OutputLine>& lines)
{
    static const std::regex EmptyAssignment(R"(^(\s*)__results\s*=\s*\{\}\s*$)");
    static const std::regex EmptyPackedReturn(
        R"(^(\s*)return\s+table\.unpack\(\{\s*(?:nil\s*)?\}\)\s*$)");
    static const std::regex LiteralPackedReturn(
        R"(^(\s*)return\s+table\.unpack\(\{\s*(.+)\s*\}\)\s*$)");
    std::vector<bool> remove(lines.size(), false);
    size_t collapsed = 0;
    for (OutputLine& line : lines)
    {
        std::smatch match;
        if (!std::regex_match(line.text, match, EmptyPackedReturn))
        {
            if (!std::regex_match(line.text, match, LiteralPackedReturn))
                continue;
            const std::vector<std::string> values = splitCaptureExpressions(match[2].str());
            if (values.size() != 1 || !scalarLiteral(trimView(values.front())) || trimView(values.front()) == "nil")
                continue;
            line.text = match[1].str() + "return " + trim(values.front());
            ++collapsed;
        }
        else
        {
            line.text = match[1].str() + "return";
            ++collapsed;
        }
    }
    for (size_t index = 0; index < lines.size(); ++index)
    {
        std::smatch assignment;
        if (!std::regex_match(lines[index].text, assignment, EmptyAssignment))
            continue;
        const size_t indent = assignment[1].str().size();
        for (size_t next = index + 1; next < lines.size() && next <= index + 24; ++next)
        {
            const std::string_view statement = trimView(lines[next].text);
            if (indentation(lines[next].text) != indent)
                break;
            if (statement == "return table.unpack(__results)")
            {
                lines[next].text = std::string(indent, ' ') + "return";
                lines[next].states.insert(lines[index].states.begin(), lines[index].states.end());
                remove[index] = true;
                ++collapsed;
                break;
            }
            if (statement.find("__results") != std::string_view::npos || controlBoundary(statement))
                break;
        }
    }
    if (collapsed == 0)
        return 0;
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - collapsed);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return collapsed;
}

struct ParsedBinding
{
    size_t begin = 0;
    size_t end = 0;
    int64_t prototype = 0;
    std::vector<std::string> captures;
};

std::vector<std::string> splitCaptureExpressions(std::string_view source)
{
    std::vector<std::string> values;
    size_t begin = 0;
    int parentheses = 0;
    int brackets = 0;
    int braces = 0;
    char quote = 0;
    for (size_t index = 0; index <= source.size(); ++index)
    {
        const char ch = index < source.size() ? source[index] : ',';
        if (quote != 0)
        {
            if (ch == '\\')
                ++index;
            else if (ch == quote)
                quote = 0;
            continue;
        }
        if (ch == '\'' || ch == '"')
        {
            quote = ch;
            continue;
        }
        if (ch == '(')
            ++parentheses;
        else if (ch == ')')
            --parentheses;
        else if (ch == '[')
            ++brackets;
        else if (ch == ']')
            --brackets;
        else if (ch == '{')
            ++braces;
        else if (ch == '}')
            --braces;
        else if (ch == ',' && parentheses == 0 && brackets == 0 && braces == 0)
        {
            const std::string value = trim(source.substr(begin, index - begin));
            if (!value.empty())
                values.push_back(value);
            begin = index + 1;
        }
    }
    return values;
}

std::optional<ParsedBinding> parsePrototypeBinding(std::string_view source)
{
    constexpr std::string_view Marker = "__bind(__prototypes[";
    const size_t begin = source.find(Marker);
    if (begin == std::string_view::npos)
        return std::nullopt;
    size_t cursor = begin + Marker.size();
    const size_t idBegin = cursor;
    while (cursor < source.size() && std::isdigit(static_cast<unsigned char>(source[cursor])))
        ++cursor;
    const auto prototype = parseInteger(source.substr(idBegin, cursor - idBegin));
    if (!prototype || cursor >= source.size() || source[cursor] != ']')
        return std::nullopt;
    ++cursor;
    while (cursor < source.size() && std::isspace(static_cast<unsigned char>(source[cursor])))
        ++cursor;
    if (cursor >= source.size() || source[cursor++] != ',')
        return std::nullopt;
    while (cursor < source.size() && std::isspace(static_cast<unsigned char>(source[cursor])))
        ++cursor;
    if (cursor >= source.size() || source[cursor] != '{')
        return std::nullopt;
    const size_t capturesBegin = ++cursor;
    int depth = 1;
    char quote = 0;
    for (; cursor < source.size() && depth > 0; ++cursor)
    {
        const char ch = source[cursor];
        if (quote != 0)
        {
            if (ch == '\\')
                ++cursor;
            else if (ch == quote)
                quote = 0;
            continue;
        }
        if (ch == '\'' || ch == '"')
            quote = ch;
        else if (ch == '{')
            ++depth;
        else if (ch == '}')
            --depth;
    }
    if (depth != 0)
        return std::nullopt;
    const size_t capturesEnd = cursor - 1;
    while (cursor < source.size() && std::isspace(static_cast<unsigned char>(source[cursor])))
        ++cursor;
    if (cursor >= source.size() || source[cursor] != ')')
        return std::nullopt;
    return ParsedBinding{
        begin,
        cursor + 1,
        *prototype,
        splitCaptureExpressions(source.substr(capturesBegin, capturesEnd - capturesBegin)),
    };
}

std::optional<std::string> substituteCaptureReferences(
    std::string_view source, const std::vector<std::string>& aliases, size_t& recovered)
{
    constexpr std::string_view Direct = "__captures";
    constexpr std::string_view Wrapped = "(__captures)";
    std::string output;
    output.reserve(source.size());
    for (size_t index = 0; index < source.size();)
    {
        if (source[index] == '\'' || source[index] == '"')
        {
            const size_t begin = index;
            const char quote = source[index++];
            while (index < source.size())
            {
                if (source[index] == '\\')
                    index += std::min<size_t>(2, source.size() - index);
                else if (source[index++] == quote)
                    break;
            }
            output.append(source.substr(begin, index - begin));
            continue;
        }
        if (source[index] == '-' && index + 1 < source.size() && source[index + 1] == '-')
        {
            output.append(source.substr(index));
            break;
        }

        size_t captureEnd = index;
        if (source.substr(index).starts_with(Wrapped))
            captureEnd += Wrapped.size();
        else if (source.substr(index).starts_with(Direct) &&
            (index == 0 || (!std::isalnum(static_cast<unsigned char>(source[index - 1])) && source[index - 1] != '_')))
            captureEnd += Direct.size();
        else
        {
            output.push_back(source[index++]);
            continue;
        }
        if (captureEnd >= source.size() || source[captureEnd] != '[')
        {
            output.append(source.substr(index, captureEnd - index));
            index = captureEnd;
            continue;
        }
        const size_t slotBegin = ++captureEnd;
        while (captureEnd < source.size() && std::isdigit(static_cast<unsigned char>(source[captureEnd])))
            ++captureEnd;
        const auto slot = parseInteger(source.substr(slotBegin, captureEnd - slotBegin));
        if (!slot || *slot <= 0 || static_cast<size_t>(*slot) > aliases.size() || captureEnd >= source.size() || source[captureEnd] != ']')
            return std::nullopt;
        output += aliases[static_cast<size_t>(*slot) - 1];
        index = captureEnd + 1;
        ++recovered;
    }
    return output;
}

struct PrototypeDefinition
{
    size_t begin = 0;
    size_t end = 0;
    size_t ordinal = 0;
    std::vector<OutputLine> body;
};

struct PrototypeNestingResult
{
    std::vector<OutputLine> lines;
    size_t prototypes = 0;
    size_t capture_references = 0;
};

class PrototypeNester
{
public:
    std::optional<PrototypeNestingResult> run(const std::vector<OutputLine>& source)
    {
        if (!collectDefinitions(source) || definitions.empty())
            return std::nullopt;
        std::map<int64_t, size_t> uses;
        for (const OutputLine& line : source)
        {
            if (line.text.find("__bind(__prototypes[") == std::string::npos)
                continue;
            auto binding = parsePrototypeBinding(line.text);
            if (!binding || !trimView(std::string_view(line.text).substr(binding->end)).empty() || !definitions.contains(binding->prototype))
                return std::nullopt;
            ++uses[binding->prototype];
        }
        if (uses.size() != definitions.size())
            return std::nullopt;
        for (const auto& [prototype, definition] : definitions)
        {
            (void)definition;
            if (uses[prototype] != 1)
                return std::nullopt;
        }

        std::vector<OutputLine> root;
        for (size_t index = 0; index < source.size();)
        {
            auto range = definitionRanges.find(index);
            if (range != definitionRanges.end())
            {
                index = range->second + 1;
                continue;
            }
            const std::string_view statement = trimView(source[index].text);
            if (statement == "local function __bind(__prototype, __captures) return function(...) return __prototype(__captures, ...) end end" ||
                statement == "local __prototypes = {}")
            {
                ++index;
                continue;
            }
            root.push_back(source[index++]);
        }
        while (root.size() > 2 && trimView(root[2].text).empty())
            root.erase(root.begin() + 2);

        auto nested = expand(root, 0);
        if (!nested || consumed.size() != definitions.size())
            return std::nullopt;
        for (const OutputLine& line : *nested)
            if (line.text.find("__bind(__prototypes[") != std::string::npos || line.text.find("__captures") != std::string::npos ||
                line.text.find("__prototypes") != std::string::npos)
                return std::nullopt;
        return PrototypeNestingResult{std::move(*nested), consumed.size(), captureReferences};
    }

private:
    std::map<int64_t, PrototypeDefinition> definitions;
    std::map<size_t, size_t> definitionRanges;
    std::set<int64_t> expanding;
    std::set<int64_t> consumed;
    size_t captureReferences = 0;

    bool collectDefinitions(const std::vector<OutputLine>& source)
    {
        static const std::regex Header(R"(^__prototypes\[([0-9]+)\] = function\(__captures, \.\.\.\)$)");
        size_t ordinal = 0;
        for (size_t index = 0; index < source.size(); ++index)
        {
            std::smatch match;
            if (!std::regex_match(source[index].text, match, Header))
                continue;
            const auto prototype = parseInteger(match[1].str());
            if (!prototype || definitions.contains(*prototype))
                return false;
            size_t end = index + 1;
            while (end < source.size() && !(indentation(source[end].text) == 0 && trimView(source[end].text) == "end"))
                ++end;
            if (end >= source.size())
                return false;
            definitions.emplace(*prototype, PrototypeDefinition{
                                                index,
                                                end,
                                                ++ordinal,
                                                std::vector<OutputLine>(source.begin() + static_cast<std::ptrdiff_t>(index + 1),
                                                    source.begin() + static_cast<std::ptrdiff_t>(end)),
                                            });
            definitionRanges[index] = end;
            index = end;
        }
        return true;
    }

    std::optional<std::vector<OutputLine>> expand(const std::vector<OutputLine>& source, size_t depth)
    {
        if (depth > definitions.size())
            return std::nullopt;
        std::vector<OutputLine> output;
        for (const OutputLine& line : source)
        {
            if (line.text.find("__bind(__prototypes[") == std::string::npos)
            {
                output.push_back(line);
                continue;
            }
            auto binding = parsePrototypeBinding(line.text);
            if (!binding || !trimView(std::string_view(line.text).substr(binding->end)).empty())
                return std::nullopt;
            auto definition = definitions.find(binding->prototype);
            if (definition == definitions.end() || expanding.contains(binding->prototype) || consumed.contains(binding->prototype))
                return std::nullopt;

            std::vector<std::string> aliases;
            aliases.reserve(binding->captures.size());
            for (size_t slot = 0; slot < binding->captures.size(); ++slot)
                aliases.push_back("upvalue_" + std::to_string(definition->second.ordinal) + "_" + std::to_string(slot + 1));
            std::vector<OutputLine> body = definition->second.body;
            for (OutputLine& bodyLine : body)
            {
                auto substituted = substituteCaptureReferences(bodyLine.text, aliases, captureReferences);
                if (!substituted)
                    return std::nullopt;
                bodyLine.text = std::move(*substituted);
            }

            expanding.insert(binding->prototype);
            auto nestedBody = expand(body, depth + 1);
            expanding.erase(binding->prototype);
            if (!nestedBody)
                return std::nullopt;
            consumed.insert(binding->prototype);

            const size_t baseWidth = indentation(line.text);
            const std::string baseIndent(baseWidth, ' ');
            const std::string prefix = line.text.substr(0, binding->begin);
            if (!aliases.empty())
            {
                std::string factory = prefix + "(function(";
                for (size_t slot = 0; slot < aliases.size(); ++slot)
                {
                    if (slot)
                        factory += ", ";
                    factory += aliases[slot];
                }
                factory += ")";
                output.push_back({std::move(factory), line.origin, line.states});
                output.push_back({baseIndent + "    return function(...)", line.origin, line.states});
                for (OutputLine bodyLine : *nestedBody)
                {
                    if (!bodyLine.text.empty())
                        bodyLine.text = baseIndent + "    " + bodyLine.text;
                    output.push_back(std::move(bodyLine));
                }
                output.push_back({baseIndent + "    end", line.origin, line.states});
                std::string factoryCall = baseIndent + "end)(";
                for (size_t slot = 0; slot < binding->captures.size(); ++slot)
                {
                    if (slot)
                        factoryCall += ", ";
                    factoryCall += binding->captures[slot];
                }
                factoryCall += ")";
                output.push_back({std::move(factoryCall), line.origin, line.states});
            }
            else
            {
                output.push_back({prefix + "function(...)", line.origin, line.states});
                for (OutputLine bodyLine : *nestedBody)
                {
                    if (!bodyLine.text.empty())
                        bodyLine.text = baseIndent + bodyLine.text;
                    output.push_back(std::move(bodyLine));
                }
                output.push_back({baseIndent + "end", line.origin, line.states});
            }
        }
        return output;
    }
};

std::optional<PrototypeNestingResult> nestPrototypeClosures(const std::vector<OutputLine>& lines)
{
    return PrototypeNester().run(lines);
}

struct DeclarationScope
{
    size_t declaration = 0;
    size_t end = 0;
    size_t indent = 0;
    std::vector<std::string> names;
};

std::optional<std::vector<std::string>> generatedDeclaration(std::string_view line)
{
    line = trimView(line);
    if (!line.starts_with("local ") || line.find('=') != std::string_view::npos)
        return std::nullopt;
    line.remove_prefix(6);
    std::vector<std::string> names = splitCaptureExpressions(line);
    if (names.empty())
        return std::nullopt;
    for (const std::string& name : names)
        if (!generatedLocal(name) && !capturedLocal(name) && !std::string_view(name).starts_with("cell_"))
            return std::nullopt;
    return names;
}

std::string snakeCase(std::string_view value)
{
    std::string result;
    for (size_t index = 0; index < value.size(); ++index)
    {
        const unsigned char ch = static_cast<unsigned char>(value[index]);
        if (std::isupper(ch))
        {
            const bool previousLower = index > 0 && (std::islower(static_cast<unsigned char>(value[index - 1])) ||
                std::isdigit(static_cast<unsigned char>(value[index - 1])));
            const bool acronymBoundary = index > 0 && std::isupper(static_cast<unsigned char>(value[index - 1])) &&
                index + 1 < value.size() && std::islower(static_cast<unsigned char>(value[index + 1]));
            if (!result.empty() && result.back() != '_' && (previousLower || acronymBoundary))
                result.push_back('_');
            result.push_back(static_cast<char>(std::tolower(ch)));
        }
        else if (std::isalnum(ch) || ch == '_')
            result.push_back(static_cast<char>(std::tolower(ch)));
        else if (!result.empty() && result.back() != '_')
            result.push_back('_');
    }
    while (!result.empty() && result.back() == '_')
        result.pop_back();
    return result.empty() ? "value" : result;
}

std::string semanticLocalBase(std::string_view value, bool compound)
{
    value = stripOuterParentheses(trimView(value));
    static const std::regex Service(R"regex(^game:GetService\("([A-Za-z0-9_]+)"\)$)regex");
    static const std::regex ChildLookup(
        R"regex(:(?:WaitForChild|FindFirstChild|FindFirstChildOfClass|FindFirstChildWhichIsA)\("([A-Za-z0-9_]+)"(?:,\s*[^)]*)?\)$)regex");
    static const std::regex Instance(R"regex(^Instance\.new\("([A-Za-z0-9_]+)")regex");
    static const std::regex Constructor(
        R"regex(^([A-Za-z][A-Za-z0-9_]*)\.(?:new|from[A-Za-z0-9_]*)(?:\(.*\))?$)regex");
    static const std::regex Property(R"regex(\.([A-Za-z][A-Za-z0-9_]*)$)regex");
    static const std::regex MethodReference(
        R"regex(\.(Create|Connect|FindFirstChild|FindFirstChildOfClass|GetPlayers|Destroy)$)regex");
    static const std::regex MethodCall(R"regex(:([A-Za-z][A-Za-z0-9_]*)\()regex");
    std::smatch match;
    const std::string text(value);
    if (value == "true" || value == "false")
        return "flag";
    if (quotedLiteral(value))
    {
        if (value.find("rbxassetid://") != std::string_view::npos)
            return "asset_id";
        if (value.size() > 20 && value.find('\\') != std::string_view::npos)
            return "encoded_value";
        return "text";
    }
    static const std::regex Number(R"(^-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$)");
    if (std::regex_match(text, Number))
        return "number";
    static const std::regex Comparison(R"((?:^|\s)(?:not\s+)|(?:==|~=|<=|>=|<|>))");
    if (std::regex_search(text, Comparison))
        return "condition";
    if (value.find(" .. ") != std::string_view::npos)
        return "text";
    static const std::regex Arithmetic(R"(\s(?:\+|-|\*|/|%|\^)\s)");
    if (std::regex_search(text, Arithmetic) || value.starts_with("math."))
        return "number";
    if (value.starts_with("tostring(") || value.starts_with("string.format(") ||
        value.find(":lower(") != std::string_view::npos || value.find(":upper(") != std::string_view::npos)
        return "text";
    if (value.starts_with("Enum."))
        return "enum_value";
    if (std::regex_match(text, match, Service))
        return snakeCase(match[1].str());
    if (std::regex_search(text, match, ChildLookup))
        return snakeCase(match[1].str());
    if (std::regex_search(text, match, Instance))
        return snakeCase(match[1].str());
    if (std::regex_match(text, match, Constructor))
    {
        const std::string type = snakeCase(match[1].str());
        static const std::map<std::string, std::string> Names{
            {"brick_color", "brick_color"}, {"c_frame", "cframe"}, {"color3", "color"},
            {"tween_info", "tween_info"}, {"u_dim", "udim"}, {"u_dim2", "udim2"},
            {"vector2", "vector2"}, {"vector3", "vector3"},
        };
        if (auto found = Names.find(type); found != Names.end())
            return found->second;
        return type;
    }
    if (value.ends_with(".LocalPlayer") || value.ends_with(").LocalPlayer"))
        return "local_player";
    if (value.ends_with(":GetPlayers()"))
        return "players";
    if (value.find(":Connect(") != std::string_view::npos)
        return "connection";
    if (std::regex_search(text, match, MethodCall))
    {
        static const std::map<std::string, std::string> Names{
            {"Clone", "clone"},
            {"Create", "tween"},
            {"FindFirstAncestor", "ancestor"},
            {"FindFirstAncestorOfClass", "ancestor"},
            {"FindFirstAncestorWhichIsA", "ancestor"},
            {"FindFirstChild", "child"},
            {"FindFirstChildOfClass", "child"},
            {"FindFirstChildWhichIsA", "child"},
            {"GetAttribute", "attribute_value"},
            {"GetAttributes", "attributes"},
            {"GetChildren", "children"},
            {"GetDescendants", "descendants"},
            {"GetFullName", "full_name"},
            {"GetMouse", "mouse"},
            {"GetPlayerFromCharacter", "player"},
            {"GetPropertyChangedSignal", "property_changed_signal"},
            {"GetTagged", "tagged_instances"},
            {"GetTags", "tags"},
            {"Invoke", "response"},
            {"InvokeServer", "response"},
            {"IsA", "condition"},
            {"IsAncestorOf", "condition"},
            {"IsDescendantOf", "condition"},
            {"JSONDecode", "decoded_value"},
            {"JSONEncode", "json"},
            {"LoadAnimation", "animation_track"},
            {"Once", "connection"},
            {"Raycast", "raycast_result"},
            {"WaitForChild", "child"},
        };
        if (auto found = Names.find(match[1].str()); found != Names.end())
            return found->second;
    }
    if (value.starts_with("function(") || value.starts_with("(function("))
        return "callback";
    if (value.starts_with('{'))
        return value.starts_with("{ipairs(") ? "iterator_values" : "values";
    if (std::regex_search(text, match, MethodReference))
        return snakeCase(match[1].str()) + "_method";
    if (std::regex_search(text, match, Property))
    {
        static const std::map<std::string, std::string> Names{
            {"Activated", "activated_signal"},
            {"AncestryChanged", "ancestry_changed_signal"},
            {"CFrame", "cframe"},
            {"Changed", "changed_signal"},
            {"Character", "character"},
            {"CharacterAdded", "character_added_signal"},
            {"ChildAdded", "child_added_signal"},
            {"ChildRemoved", "child_removed_signal"},
            {"CurrentCamera", "current_camera"},
            {"DescendantAdded", "descendant_added_signal"},
            {"DescendantRemoving", "descendant_removing_signal"},
            {"Died", "died_signal"},
            {"Enabled", "enabled"},
            {"FocusLost", "focus_lost_signal"},
            {"Focused", "focused_signal"},
            {"Font", "font"},
            {"Heartbeat", "heartbeat_signal"},
            {"Health", "health"},
            {"InputBegan", "input_began_signal"},
            {"InputChanged", "input_changed_signal"},
            {"InputEnded", "input_ended_signal"},
            {"KeyCode", "key_code"},
            {"LocalPlayer", "local_player"},
            {"Magnitude", "magnitude"},
            {"MouseButton1Click", "clicked_signal"},
            {"MouseButton1Down", "mouse_button_down_signal"},
            {"MouseButton1Up", "mouse_button_up_signal"},
            {"MouseEnter", "mouse_enter_signal"},
            {"MouseLeave", "mouse_leave_signal"},
            {"Name", "name"},
            {"Parent", "parent"},
            {"Position", "position"},
            {"PostSimulation", "post_simulation_signal"},
            {"PreRender", "pre_render_signal"},
            {"PreSimulation", "pre_simulation_signal"},
            {"RenderStepped", "render_stepped_signal"},
            {"Touched", "touched_signal"},
            {"Unit", "unit_vector"},
            {"UserInputType", "user_input_type"},
            {"X", "x"},
            {"Y", "y"},
        };
        if (auto found = Names.find(match[1].str()); found != Names.end())
            return found->second;
    }
    if (compound)
        return "result";
    if (value == "nil")
        return "value";
    if (value == "game" || value == "workspace" || value == "script" || value == "shared" || value == "_G")
        return snakeCase(value);
    if (bareReadableGlobal(value))
    {
        static const std::set<std::string_view> Functions{
            "assert", "error", "getmetatable", "ipairs", "loadstring", "newproxy", "next", "pairs", "pcall",
            "print", "rawequal", "rawget", "rawlen", "rawset", "require", "select", "setmetatable", "tonumber",
            "tostring", "type", "typeof", "unpack", "warn", "xpcall",
        };
        if (Functions.contains(value))
            return snakeCase(value) + "_function";
    }
    return "value";
}

bool tokenBeforeAssignment(std::string_view line, std::string_view name)
{
    const size_t assignment = line.find('=');
    if (assignment == std::string_view::npos)
        return false;
    const std::set<std::string> names = generatedReads(line.substr(0, assignment));
    return names.contains(std::string(name));
}

bool compoundTarget(std::string_view line, std::string_view name)
{
    line = trimView(line);
    if (!line.starts_with(name))
        return false;
    line.remove_prefix(name.size());
    line = trimView(line);
    return line.starts_with("+=") || line.starts_with("-=") || line.starts_with("*=") || line.starts_with("/=") ||
        line.starts_with("%=") || line.starts_with("^=") || line.starts_with("..=");
}

bool containsIdentifier(std::string_view line, std::string_view name);
std::set<std::string> collectIdentifiers(const std::vector<OutputLine>& lines);
std::optional<std::vector<std::string>> plainLocalDeclaration(std::string_view line);
bool plainIdentifier(std::string_view value);

size_t promoteStableLocals(std::vector<OutputLine>& lines)
{
    std::vector<DeclarationScope> scopes;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        auto names = generatedDeclaration(lines[index].text);
        if (!names || std::none_of(names->begin(), names->end(), [&](const std::string& name) {
                return std::string_view(name).starts_with("local_") || std::string_view(name).starts_with("cell_");
            }))
            continue;
        const size_t indent = indentation(lines[index].text);
        size_t end = lines.size();
        if (indent > 0)
            for (size_t candidate = index + 1; candidate < lines.size(); ++candidate)
                if (indentation(lines[candidate].text) == indent - 4 && trimView(lines[candidate].text) == "end")
                {
                    end = candidate;
                    break;
                }
        scopes.push_back({index, end, indent, std::move(*names)});
    }
    if (scopes.empty())
        return 0;
    std::vector<size_t> owner(lines.size(), std::numeric_limits<size_t>::max());
    std::vector<size_t> order(scopes.size());
    for (size_t index = 0; index < scopes.size(); ++index)
        order[index] = index;
    std::sort(order.begin(), order.end(), [&](size_t left, size_t right) { return scopes[left].indent < scopes[right].indent; });
    for (size_t scopeIndex : order)
        for (size_t line = scopes[scopeIndex].declaration; line < scopes[scopeIndex].end && line < owner.size(); ++line)
            owner[line] = scopeIndex;

    std::set<std::string> occupied = collectIdentifiers(lines);
    size_t promoted = 0;
    for (size_t scopeIndex = 0; scopeIndex < scopes.size(); ++scopeIndex)
    {
        DeclarationScope& scope = scopes[scopeIndex];
        std::set<std::string> promotedNames;
        std::map<std::string, size_t> semanticCounts;
        for (const std::string& name : scope.names)
        {
            if (!std::string_view(name).starts_with("local_") || !generatedLocal(name))
                continue;
            std::vector<size_t> assignments;
            bool otherWrite = false;
            bool compound = false;
            for (size_t index = scope.declaration + 1; index < scope.end && index < lines.size(); ++index)
            {
                if (owner[index] != scopeIndex)
                    continue;
                auto assignment = simpleAssignment(lines[index].text);
                if (assignment && assignment->target == name)
                    assignments.push_back(index);
                else if (compoundTarget(lines[index].text, name))
                    compound = true;
                else if (tokenBeforeAssignment(lines[index].text, name))
                    otherWrite = true;
            }
            if (assignments.size() != 1 || otherWrite || indentation(lines[assignments[0]].text) != scope.indent)
                continue;
            bool nestedReference = false;
            for (size_t index = scope.declaration + 1; index < scope.end && index < lines.size(); ++index)
                if (owner[index] != scopeIndex && containsIdentifier(lines[index].text, name))
                {
                    nestedReference = true;
                    break;
                }
            if (nestedReference)
                continue;
            const size_t assignmentIndex = assignments[0];
            bool readBefore = false;
            for (size_t index = scope.declaration + 1; index < assignmentIndex; ++index)
                if (owner[index] == scopeIndex && generatedReads(lines[index].text).contains(name))
                {
                    readBefore = true;
                    break;
                }
            if (readBefore)
                continue;
            auto assignment = simpleAssignment(lines[assignmentIndex].text);
            if (!assignment || generatedReads(assignment->value).contains(name))
                continue;
            std::string base = semanticLocalBase(assignment->value, compound);
            if (base == "value" || base == "result")
                continue;
            size_t& count = semanticCounts[base];
            std::string replacement;
            do
            {
                ++count;
                replacement = count == 1 ? base : base + "_" + std::to_string(count);
            } while (occupied.contains(replacement));
            occupied.insert(replacement);
            std::map<std::string, std::string> replacements{{name, replacement}};
            for (size_t index = assignmentIndex; index < scope.end && index < lines.size(); ++index)
            {
                if (owner[index] != scopeIndex)
                    continue;
                size_t constants = 0;
                size_t aliases = 0;
                lines[index].text = replaceGeneratedLocals(lines[index].text, replacements, constants, aliases);
            }
            lines[assignmentIndex].text.insert(scope.indent, "local ");
            promotedNames.insert(name);
            ++promoted;
        }
        if (!promotedNames.empty())
        {
            std::vector<std::string> remaining;
            for (const std::string& name : scope.names)
                if (!promotedNames.contains(name))
                    remaining.push_back(name);
            if (remaining.empty())
                lines[scope.declaration].text.clear();
            else
            {
                std::string declaration(scope.indent, ' ');
                declaration += "local ";
                for (size_t index = 0; index < remaining.size(); ++index)
                {
                    if (index)
                        declaration += ", ";
                    declaration += remaining[index];
                }
                lines[scope.declaration].text = std::move(declaration);
            }
        }
    }
    return promoted;
}

bool directlyWritesIdentifier(std::string_view line, std::string_view name)
{
    line = trimView(line);
    if (line.starts_with(';'))
        line = trimView(line.substr(1));
    if (!line.starts_with(name) || (line.size() > name.size() &&
            (line[name.size()] == '_' || std::isalnum(static_cast<unsigned char>(line[name.size()])))))
        return false;
    line.remove_prefix(name.size());
    line = trimView(line);
    if (line.empty() || line.front() == '.' || line.front() == '[')
        return false;
    return line.front() == '=' || line.front() == ',' || line.starts_with("+=") || line.starts_with("-=") ||
        line.starts_with("*=") || line.starts_with("/=") || line.starts_with("%=") || line.starts_with("^=") ||
        line.starts_with("..=");
}

PropagationStats propagateStableCapturedAliases(std::vector<OutputLine>& lines)
{
    static const std::regex CapturedWrite(
        R"(^\s*;?\s*(captured_value_[0-9]+)\s*(?:=|\+=|-=|\*=|/=|%=|\^=|\.\.=))");
    std::map<std::string, size_t> writes;
    for (const OutputLine& line : lines)
    {
        std::smatch write;
        if (std::regex_search(line.text, write, CapturedWrite))
            ++writes[write[1].str()];
    }
    std::set<std::string> stable;
    for (const auto& [name, count] : writes)
        if (count == 1)
            stable.insert(name);

    static const std::regex GeneratedAssignment(R"(^(\s*)((?:local_[0-9]+))\s*=\s*(.+)$)");
    std::set<std::string> initialized;
    std::map<std::string, std::string> aliases;
    PropagationStats stats;
    for (OutputLine& line : lines)
    {
        std::string_view assignmentText = trimView(line.text);
        if (assignmentText.starts_with(';'))
            assignmentText = trimView(assignmentText.substr(1));
        auto assignment = simpleAssignment(assignmentText);
        if (assignment && capturedLocal(assignment->target))
        {
            size_t constants = 0;
            size_t aliasCount = 0;
            const std::string value = replaceGeneratedLocals(assignment->value, aliases, constants, aliasCount);
            line.text = std::string(indentation(line.text), ' ') + assignment->target + " = " + value;
            stats.aliases += constants + aliasCount;
            for (auto iterator = aliases.begin(); iterator != aliases.end();)
                if (iterator->second == assignment->target)
                    iterator = aliases.erase(iterator);
                else
                    ++iterator;
            initialized.insert(assignment->target);
        }
        else
        {
            const auto writes = identifierAssignmentList(line.text);
            for (auto iterator = aliases.begin(); iterator != aliases.end();)
                if ((writes && std::find(writes->targets.begin(), writes->targets.end(), iterator->first) != writes->targets.end()) ||
                    directlyWritesIdentifier(line.text, iterator->first))
                    iterator = aliases.erase(iterator);
                else
                    ++iterator;

            std::smatch generated;
            if (writes && writes->targets.size() > 1)
            {
                size_t constants = 0;
                size_t aliasCount = 0;
                const std::string original = line.text;
                const std::string value = replaceGeneratedLocals(
                    std::string_view(original).substr(writes->value_begin), aliases, constants, aliasCount);
                line.text = original.substr(0, writes->value_begin) + value;
                stats.aliases += constants + aliasCount;
                for (const std::string& target : writes->targets)
                {
                    aliases.erase(target);
                    for (auto iterator = aliases.begin(); iterator != aliases.end();)
                        if (iterator->second == target)
                            iterator = aliases.erase(iterator);
                        else
                            ++iterator;
                }
            }
            else if (std::regex_match(line.text, generated, GeneratedAssignment))
            {
                const std::string target = generated[2].str();
                size_t constants = 0;
                size_t aliasCount = 0;
                const std::string value = replaceGeneratedLocals(generated[3].str(), aliases, constants, aliasCount);
                line.text = generated[1].str() + target + " = " + value;
                stats.aliases += constants + aliasCount;
                aliases.erase(target);
                for (auto iterator = aliases.begin(); iterator != aliases.end();)
                    if (iterator->second == target)
                        iterator = aliases.erase(iterator);
                    else
                        ++iterator;
                const std::string_view normalized = trimView(value);
                if ((capturedLocal(normalized) && stable.contains(std::string(normalized)) && initialized.contains(std::string(normalized))) ||
                    safeDottedGlobal(normalized))
                    aliases[target] = std::string(normalized);
            }
            else
            {
                size_t constants = 0;
                size_t aliasCount = 0;
                line.text = replaceGeneratedLocals(line.text, aliases, constants, aliasCount);
                stats.aliases += constants + aliasCount;
            }
        }
        stats.properties += recoverProperties(line.text);
        const std::string_view statement = trimView(line.text);
        const bool returns = statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' ');
        if (controlBoundary(statement) || returns)
            aliases.clear();
    }
    return stats;
}

bool containsIdentifier(std::string_view line, std::string_view name)
{
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
            return false;
        if (line[index] == '\'' || line[index] == '"')
        {
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            continue;
        }
        if (line[index] == '_' || std::isalpha(static_cast<unsigned char>(line[index])))
        {
            const size_t begin = index++;
            while (index < line.size() && (line[index] == '_' || std::isalnum(static_cast<unsigned char>(line[index]))))
                ++index;
            if (line.substr(begin, index - begin) == name)
                return true;
            continue;
        }
        ++index;
    }
    return false;
}

std::set<std::string> collectIdentifiers(const std::vector<OutputLine>& lines)
{
    std::set<std::string> identifiers;
    for (const OutputLine& line : lines)
        for (size_t index = 0; index < line.text.size();)
        {
            if (line.text[index] == '-' && index + 1 < line.text.size() && line.text[index + 1] == '-')
                break;
            if (line.text[index] == '\'' || line.text[index] == '"')
            {
                const char quote = line.text[index++];
                while (index < line.text.size())
                {
                    if (line.text[index] == '\\')
                        index += std::min<size_t>(2, line.text.size() - index);
                    else if (line.text[index++] == quote)
                        break;
                }
                continue;
            }
            if (line.text[index] == '_' || std::isalpha(static_cast<unsigned char>(line.text[index])))
            {
                const size_t begin = index++;
                while (index < line.text.size() &&
                    (line.text[index] == '_' || std::isalnum(static_cast<unsigned char>(line.text[index]))))
                    ++index;
                identifiers.insert(line.text.substr(begin, index - begin));
                continue;
            }
            ++index;
        }
    return identifiers;
}

bool functionExpressionClosesOnLine(std::string_view line)
{
    bool started = false;
    size_t depth = 0;
    size_t pendingDo = 0;
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
            break;
        if (line[index] == '\'' || line[index] == '"')
        {
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            continue;
        }
        if (line[index] != '_' && !std::isalpha(static_cast<unsigned char>(line[index])))
        {
            ++index;
            continue;
        }
        const size_t begin = index++;
        while (index < line.size() && (line[index] == '_' || std::isalnum(static_cast<unsigned char>(line[index]))))
            ++index;
        const std::string_view token = line.substr(begin, index - begin);
        if (!started)
        {
            if (token == "function")
            {
                started = true;
                depth = 1;
            }
            continue;
        }
        if (token == "function" || token == "if" || token == "repeat")
            ++depth;
        else if (token == "for" || token == "while")
        {
            ++depth;
            ++pendingDo;
        }
        else if (token == "do")
        {
            if (pendingDo)
                --pendingDo;
            else
                ++depth;
        }
        else if (token == "end" || token == "until")
        {
            if (depth == 0)
                return false;
            --depth;
            if (depth == 0)
                return true;
        }
    }
    return false;
}

size_t foldSingleAssignmentAliases(std::vector<OutputLine>& lines)
{
    struct LexicalScope
    {
        size_t begin = 0;
        size_t end = 0;
    };
    std::vector<LexicalScope> scopes{{0, lines.size()}};
    std::vector<size_t> owner(lines.size(), 0);
    for (size_t index = 0; index < lines.size(); ++index)
    {
        const std::string_view statement = trimView(lines[index].text);
        const bool functionOpener = statement.starts_with("local function ") || statement.starts_with("return function(") ||
            statement.find(" = function(") != std::string_view::npos;
        if (!functionOpener || functionExpressionClosesOnLine(statement))
            continue;
        const size_t indent = indentation(lines[index].text);
        size_t end = index + 1;
        while (end < lines.size() && !(indentation(lines[end].text) == indent && trimView(lines[end].text) == "end"))
            ++end;
        if (end < lines.size())
            scopes.push_back({index + 1, end});
    }
    std::vector<size_t> order(scopes.size() - 1);
    for (size_t index = 1; index < scopes.size(); ++index)
        order[index - 1] = index;
    std::sort(order.begin(), order.end(), [&](size_t left, size_t right) { return scopes[left].begin < scopes[right].begin; });
    for (size_t scopeIndex : order)
        for (size_t index = scopes[scopeIndex].begin; index < scopes[scopeIndex].end; ++index)
            owner[index] = scopeIndex;

    size_t folded = 0;
    for (size_t scopeIndex = 0; scopeIndex < scopes.size(); ++scopeIndex)
    {
        std::map<std::string, std::vector<size_t>> assignments;
        for (size_t index = scopes[scopeIndex].begin; index < scopes[scopeIndex].end; ++index)
        {
            if (owner[index] != scopeIndex)
                continue;
            auto assignment = simpleAssignment(lines[index].text);
            if (assignment && generatedLocal(assignment->target))
                assignments[assignment->target].push_back(index);
        }
        for (const auto& [target, definitions] : assignments)
        {
            if (definitions.size() != 1)
                continue;
            const size_t definition = definitions.front();
            bool otherWrite = false;
            for (size_t index = scopes[scopeIndex].begin; index < scopes[scopeIndex].end; ++index)
                if (owner[index] == scopeIndex && index != definition && directlyWritesIdentifier(lines[index].text, target))
                {
                    otherWrite = true;
                    break;
                }
            if (otherWrite)
                continue;
            auto assignment = simpleAssignment(lines[definition].text);
            if (!assignment)
                continue;
            const std::string value = trim(assignment->value);
            static const std::regex Argument(R"(^argument_[0-9]+$)");
            bool immutable = false;
            if (std::regex_match(value, Argument))
            {
                immutable = true;
                for (size_t index = scopes[scopeIndex].begin; index < scopes[scopeIndex].end; ++index)
                    if (owner[index] == scopeIndex && directlyWritesIdentifier(lines[index].text, value))
                        immutable = false;
            }
            if (!immutable || containsIdentifier(value, target))
                continue;
            bool readBefore = false;
            for (size_t index = scopes[scopeIndex].begin; index < definition; ++index)
            {
                if (owner[index] != scopeIndex || !containsIdentifier(lines[index].text, target))
                    continue;
                auto declaration = generatedDeclaration(lines[index].text);
                if (declaration && std::find(declaration->begin(), declaration->end(), target) != declaration->end())
                    continue;
                readBefore = true;
            }
            if (readBefore)
                continue;

            bool replaced = false;
            for (size_t index = definition + 1; index < scopes[scopeIndex].end; ++index)
            {
                if (owner[index] != scopeIndex || !containsIdentifier(lines[index].text, target))
                    continue;
                size_t constants = 0;
                size_t aliases = 0;
                lines[index].text = replaceGeneratedLocals(lines[index].text, {{target, value}}, constants, aliases);
                if (!replaced)
                {
                    lines[index].states.insert(lines[definition].states.begin(), lines[definition].states.end());
                    replaced = true;
                }
            }
            if (!replaced)
            {
                size_t anchor = definition + 1;
                while (anchor < scopes[scopeIndex].end && owner[anchor] != scopeIndex)
                    ++anchor;
                if (anchor < scopes[scopeIndex].end)
                    lines[anchor].states.insert(lines[definition].states.begin(), lines[definition].states.end());
            }
            lines[definition].text.clear();
            ++folded;
        }
    }
    return folded;
}

std::optional<size_t> selectArgumentAt(std::string_view line, size_t begin, size_t& end)
{
    constexpr std::string_view Prefix = "select(";
    if (!line.substr(begin).starts_with(Prefix))
        return std::nullopt;
    size_t cursor = begin + Prefix.size();
    const size_t numberBegin = cursor;
    while (cursor < line.size() && std::isdigit(static_cast<unsigned char>(line[cursor])))
        ++cursor;
    const auto slot = parseInteger(line.substr(numberBegin, cursor - numberBegin));
    if (!slot || *slot <= 0 || !line.substr(cursor).starts_with(", ...)") )
        return std::nullopt;
    end = cursor + 6;
    return static_cast<size_t>(*slot);
}

std::string replaceSelectArguments(std::string_view line, size_t& maximum, size_t& replacements)
{
    std::string output;
    output.reserve(line.size());
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '\'' || line[index] == '"')
        {
            const size_t begin = index;
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            output.append(line.substr(begin, index - begin));
            continue;
        }
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
        {
            output.append(line.substr(index));
            break;
        }
        size_t end = index;
        if (auto slot = selectArgumentAt(line, index, end))
        {
            output += "argument_" + std::to_string(*slot);
            maximum = std::max(maximum, *slot);
            ++replacements;
            index = end;
            continue;
        }
        output.push_back(line[index++]);
    }
    return output;
}

size_t recoverFunctionParameters(std::vector<OutputLine>& lines)
{
    std::vector<DeclarationScope> scopes;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        auto names = generatedDeclaration(lines[index].text);
        if (!names || std::none_of(names->begin(), names->end(), [](const std::string& name) {
                return std::string_view(name).starts_with("local_") || std::string_view(name).starts_with("cell_");
            }))
            continue;
        const size_t indent = indentation(lines[index].text);
        if (indent == 0)
            continue;
        size_t end = lines.size();
        for (size_t candidate = index + 1; candidate < lines.size(); ++candidate)
            if (indentation(lines[candidate].text) == indent - 4 && trimView(lines[candidate].text) == "end")
            {
                end = candidate;
                break;
            }
        if (end < lines.size())
            scopes.push_back({index, end, indent, std::move(*names)});
    }
    if (scopes.empty())
        return 0;
    std::vector<size_t> owner(lines.size(), std::numeric_limits<size_t>::max());
    std::vector<size_t> order(scopes.size());
    for (size_t index = 0; index < scopes.size(); ++index)
        order[index] = index;
    std::sort(order.begin(), order.end(), [&](size_t left, size_t right) { return scopes[left].indent < scopes[right].indent; });
    for (size_t scopeIndex : order)
        for (size_t line = scopes[scopeIndex].declaration; line < scopes[scopeIndex].end; ++line)
            owner[line] = scopeIndex;

    size_t recovered = 0;
    for (size_t scopeIndex = 0; scopeIndex < scopes.size(); ++scopeIndex)
    {
        const DeclarationScope& scope = scopes[scopeIndex];
        size_t opener = scope.declaration;
        bool foundOpener = false;
        for (size_t distance = 1; distance <= 4 && distance <= scope.declaration; ++distance)
        {
            const size_t candidate = scope.declaration - distance;
            if (indentation(lines[candidate].text) == scope.indent - 4 && lines[candidate].text.find("function(...)") != std::string::npos)
            {
                opener = candidate;
                foundOpener = true;
                break;
            }
        }
        if (!foundOpener)
            continue;
        bool usesArgumentPack = false;
        for (size_t index = scope.declaration; index < scope.end; ++index)
            if (owner[index] == scopeIndex && trimView(lines[index].text) != "local __arguments = {...}" &&
                containsIdentifier(lines[index].text, "__arguments"))
            {
                usesArgumentPack = true;
                break;
            }
        if (usesArgumentPack)
            continue;

        size_t maximum = 0;
        size_t replacements = 0;
        std::vector<std::string> rewritten(scope.end - scope.declaration);
        for (size_t index = scope.declaration; index < scope.end; ++index)
            if (owner[index] == scopeIndex)
                rewritten[index - scope.declaration] = replaceSelectArguments(lines[index].text, maximum, replacements);
        if (maximum == 0 || replacements == 0)
            continue;
        std::string arguments;
        for (size_t slot = 1; slot <= maximum; ++slot)
        {
            if (slot > 1)
                arguments += ", ";
            arguments += "argument_" + std::to_string(slot);
        }
        const size_t signature = lines[opener].text.find("function(...)");
        lines[opener].text.replace(signature, std::string_view("function(...)").size(), "function(" + arguments + ")");
        for (size_t index = opener + 1; index < scope.declaration; ++index)
            if (trimView(lines[index].text) == "local __arguments = {...}")
                lines[index].text.clear();
        for (size_t index = scope.declaration; index < scope.end; ++index)
            if (owner[index] == scopeIndex && !rewritten[index - scope.declaration].empty())
                lines[index].text = std::move(rewritten[index - scope.declaration]);
        recovered += replacements;
    }
    return recovered;
}

struct CaptureFactoryRegion
{
    size_t opener = 0;
    size_t inner = 0;
    size_t inner_end = 0;
    size_t close = 0;
    std::vector<std::string> parameters;
    std::vector<std::string> arguments;
};

std::vector<CaptureFactoryRegion> findCaptureFactories(
    const std::vector<OutputLine>& lines, bool requireAlignedArguments = true)
{
    std::vector<CaptureFactoryRegion> factories;
    for (size_t opener = 0; opener < lines.size(); ++opener)
    {
        constexpr std::string_view Marker = "(function(";
        const size_t marker = lines[opener].text.find(Marker);
        if (marker == std::string::npos)
            continue;
        const size_t parametersBegin = marker + Marker.size();
        const size_t parametersEnd = lines[opener].text.find(')', parametersBegin);
        if (parametersEnd == std::string::npos)
            continue;
        std::vector<std::string> parameters = splitCaptureExpressions(
            std::string_view(lines[opener].text).substr(parametersBegin, parametersEnd - parametersBegin));
        if (parameters.empty())
            continue;

        const size_t indent = indentation(lines[opener].text);
        size_t inner = opener + 1;
        while (inner < lines.size() && trimView(lines[inner].text).empty())
            ++inner;
        if (inner >= lines.size() || indentation(lines[inner].text) != indent + 4 ||
            !trimView(lines[inner].text).starts_with("return function("))
            continue;
        size_t innerEnd = inner + 1;
        while (innerEnd < lines.size() && !(indentation(lines[innerEnd].text) == indent + 4 && trimView(lines[innerEnd].text) == "end"))
            ++innerEnd;
        if (innerEnd >= lines.size())
            continue;
        size_t close = innerEnd + 1;
        while (close < lines.size() && trimView(lines[close].text).empty())
            ++close;
        if (close >= lines.size() || indentation(lines[close].text) != indent || !trimView(lines[close].text).starts_with("end)("))
            continue;
        const std::string_view closeText = trimView(lines[close].text);
        if (!closeText.ends_with(')'))
            continue;
        std::vector<std::string> arguments = splitCaptureExpressions(closeText.substr(5, closeText.size() - 6));
        if (requireAlignedArguments && arguments.size() != parameters.size())
            continue;
        factories.push_back({opener, inner, innerEnd, close, std::move(parameters), std::move(arguments)});
    }
    return factories;
}

size_t identifierOccurrences(std::string_view line, std::string_view name)
{
    size_t occurrences = 0;
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
            break;
        if (line[index] == '\'' || line[index] == '"')
        {
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            continue;
        }
        if (line[index] == '_' || std::isalpha(static_cast<unsigned char>(line[index])))
        {
            const size_t begin = index++;
            while (index < line.size() && (line[index] == '_' || std::isalnum(static_cast<unsigned char>(line[index]))))
                ++index;
            if (line.substr(begin, index - begin) == name)
                ++occurrences;
            continue;
        }
        ++index;
    }
    return occurrences;
}

std::string replaceIdentifier(std::string_view line, std::string_view name, std::string_view replacement)
{
    std::string output;
    output.reserve(line.size());
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
        {
            output.append(line.substr(index));
            break;
        }
        if (line[index] == '\'' || line[index] == '"')
        {
            const size_t begin = index;
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            output.append(line.substr(begin, index - begin));
            continue;
        }
        if (line[index] == '_' || std::isalpha(static_cast<unsigned char>(line[index])))
        {
            const size_t begin = index++;
            while (index < line.size() && (line[index] == '_' || std::isalnum(static_cast<unsigned char>(line[index]))))
                ++index;
            if (line.substr(begin, index - begin) == name)
                output += replacement;
            else
                output.append(line.substr(begin, index - begin));
            continue;
        }
        output.push_back(line[index++]);
    }
    return output;
}

size_t recoverGenericForLoops(std::vector<OutputLine>& lines)
{
    static const std::regex IteratorCall(
        R"(^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\(([A-Za-z_][A-Za-z0-9_]*(?:\[[0-9]+\])?)\s*,\s*([A-Za-z_][A-Za-z0-9_]*(?:\[[0-9]+\])?)\)$)");
    size_t recovered = 0;
    size_t ordinal = 0;
    for (size_t loop = 0; loop < lines.size(); ++loop)
    {
        if (trimView(lines[loop].text) != "while true do")
            continue;
        const size_t indent = indentation(lines[loop].text);
        size_t loopEnd = loop + 1;
        while (loopEnd < lines.size() && !(indentation(lines[loopEnd].text) == indent && trimView(lines[loopEnd].text) == "end"))
            ++loopEnd;
        if (loopEnd >= lines.size())
            continue;
        size_t callLine = loop + 1;
        while (callLine < loopEnd && trimView(lines[callLine].text).empty())
            ++callLine;
        std::smatch call;
        if (callLine >= loopEnd || indentation(lines[callLine].text) != indent + 4 ||
            !std::regex_match(lines[callLine].text, call, IteratorCall))
            continue;
        const std::string control = call[1].str();
        const std::string value = call[2].str();
        const std::string iterator = call[3].str();
        const std::string state = call[4].str();
        if (call[5].str() != control)
            continue;
        size_t branch = callLine + 1;
        while (branch < loopEnd && trimView(lines[branch].text).empty())
            ++branch;
        if (branch >= loopEnd || indentation(lines[branch].text) != indent + 4 ||
            trimView(lines[branch].text) != "if " + control + " then")
            continue;
        size_t branchEnd = branch + 1;
        while (branchEnd < loopEnd && !(indentation(lines[branchEnd].text) == indent + 4 && trimView(lines[branchEnd].text) == "end"))
            ++branchEnd;
        if (branchEnd >= loopEnd || branchEnd == branch + 1 || trimView(lines[branchEnd - 1].text) != "continue")
            continue;

        std::string iteratorExpression = iterator + ", " + state + ", " + control;
        std::set<size_t> setupLines;
        auto indexedSlot = [](std::string_view expression) -> std::optional<std::pair<std::string, int>> {
            static const std::regex Indexed(R"(^\(?([A-Za-z_][A-Za-z0-9_]*)\)?\[([123])\]$)");
            std::smatch indexed;
            const std::string text(trimView(expression));
            if (!std::regex_match(text, indexed, Indexed))
                return std::nullopt;
            return std::pair{indexed[1].str(), std::stoi(indexed[2].str())};
        };
        const auto controlDefinition = previousAssignment(lines, loop, indent, control, 80);
        const auto stateDefinition = previousAssignment(lines, loop, indent, state, 80);
        const auto iteratorDefinition = previousAssignment(lines, loop, indent, iterator, 80);
        bool terminalContinuation = false;
        bool terminalBreak = false;
        for (size_t index = branchEnd + 1; index < loopEnd; ++index)
        {
            const std::string_view statement = trimView(lines[index].text);
            if (statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' '))
                terminalContinuation = true;
            if (statement == "break")
                terminalBreak = true;
        }
        const bool implicitIteratorExit = !terminalContinuation && !terminalBreak && branchEnd + 1 == loopEnd;
        if (!terminalContinuation && !terminalBreak && !implicitIteratorExit)
            continue;
        if (terminalContinuation && controlDefinition && stateDefinition && iteratorDefinition)
        {
            const auto controlAssignment = simpleAssignment(lines[*controlDefinition].text);
            const auto stateAssignment = simpleAssignment(lines[*stateDefinition].text);
            const auto iteratorAssignment = simpleAssignment(lines[*iteratorDefinition].text);
            const auto controlSlot = controlAssignment ? indexedSlot(controlAssignment->value) : std::nullopt;
            const auto stateSlot = stateAssignment ? indexedSlot(stateAssignment->value) : std::nullopt;
            const auto iteratorSlot = iteratorAssignment ? indexedSlot(iteratorAssignment->value) : std::nullopt;
            if (controlSlot && stateSlot && iteratorSlot && controlSlot->first == stateSlot->first &&
                controlSlot->first == iteratorSlot->first && controlSlot->second == 3 && stateSlot->second == 2 && iteratorSlot->second == 1)
            {
                const std::string pack = controlSlot->first;
                const size_t firstDefinition = std::min({*controlDefinition, *stateDefinition, *iteratorDefinition});
                const auto packDefinition = previousAssignment(lines, firstDefinition, indent, pack, 80);
                const auto packAssignment = packDefinition ? simpleAssignment(lines[*packDefinition].text) : std::nullopt;
                if (packAssignment)
                {
                    const std::string_view packed = trimView(packAssignment->value);
                    if (packed.size() >= 2 && packed.front() == '{' && packed.back() == '}')
                    {
                        const std::vector<std::string> fields = splitCaptureExpressions(packed.substr(1, packed.size() - 2));
                        bool safe = fields.size() == 1;
                        const std::set<size_t> allowed{*packDefinition, *controlDefinition, *stateDefinition, *iteratorDefinition, callLine};
                        for (size_t index = *packDefinition; safe && index < loop; ++index)
                            if (!allowed.contains(index) && containsIdentifier(lines[index].text, pack))
                                safe = false;
                        for (size_t index = branch + 1; safe && index < loopEnd; ++index)
                            if ((containsIdentifier(lines[index].text, iterator) || containsIdentifier(lines[index].text, state)) &&
                                index != branchEnd - 1)
                                safe = false;
                        if (safe)
                        {
                            iteratorExpression = fields.front();
                            setupLines = {*packDefinition, *controlDefinition, *stateDefinition, *iteratorDefinition};
                        }
                    }
                }
            }
        }

        std::string keyName;
        std::string valueName;
        do
        {
            ++ordinal;
            keyName = "key_" + std::to_string(ordinal);
            valueName = "value_" + std::to_string(ordinal);
        } while (std::any_of(lines.begin(), lines.end(), [&](const OutputLine& line) {
            return containsIdentifier(line.text, keyName) || containsIdentifier(line.text, valueName);
        }));

        std::set<int64_t> headerStates = lines[loop].states;
        headerStates.insert(lines[callLine].states.begin(), lines[callLine].states.end());
        headerStates.insert(lines[branch].states.begin(), lines[branch].states.end());
        std::optional<size_t> headerOrigin = lines[loop].origin;
        if (!headerOrigin)
            headerOrigin = lines[callLine].origin ? lines[callLine].origin : lines[branch].origin;
        std::vector<OutputLine> replacement;
        for (size_t setup : setupLines)
        {
            headerStates.insert(lines[setup].states.begin(), lines[setup].states.end());
            if (!headerOrigin && lines[setup].origin)
                headerOrigin = lines[setup].origin;
        }
        replacement.push_back({std::string(indent, ' ') + "for " + keyName + ", " + valueName + " in " + iteratorExpression + " do",
            headerOrigin, std::move(headerStates)});
        for (size_t index = branch + 1; index + 1 < branchEnd; ++index)
        {
            OutputLine body = lines[index];
            if (body.text.size() >= 4)
                body.text.erase(0, 4);
            body.text = replaceIdentifier(body.text, control, keyName);
            body.text = replaceIdentifier(body.text, value, valueName);
            replacement.push_back(std::move(body));
        }
        OutputLine ending{std::string(indent, ' ') + "end", lines[loopEnd].origin, lines[loopEnd].states};
        ending.states.insert(lines[branchEnd - 1].states.begin(), lines[branchEnd - 1].states.end());
        replacement.push_back(std::move(ending));
        for (size_t index = branchEnd + 1; index < loopEnd; ++index)
        {
            if (terminalBreak && trimView(lines[index].text) == "break")
            {
                ending.states.insert(lines[index].states.begin(), lines[index].states.end());
                continue;
            }
            OutputLine continuation = lines[index];
            if (continuation.text.size() >= 4)
                continuation.text.erase(0, 4);
            replacement.push_back(std::move(continuation));
        }

        std::vector<OutputLine> rebuilt;
        rebuilt.reserve(lines.size() - (loopEnd - loop) + replacement.size());
        for (size_t index = 0; index < loop; ++index)
            if (!setupLines.contains(index))
                rebuilt.push_back(std::move(lines[index]));
        rebuilt.insert(rebuilt.end(), std::make_move_iterator(replacement.begin()), std::make_move_iterator(replacement.end()));
        for (size_t index = loopEnd + 1; index < lines.size(); ++index)
            rebuilt.push_back(std::move(lines[index]));
        lines = std::move(rebuilt);
        ++recovered;
        loop = 0;
    }
    return recovered;
}

size_t inlineGenericForIteratorSetup(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    const size_t topLevel = spans->size();

    size_t recovered = 0;
    for (size_t loop = 0; loop < lines.size(); ++loop)
    {
        const std::string_view header = trimView(lines[loop].text);
        if (!header.starts_with("for ") || !header.ends_with(" do"))
            continue;
        const size_t separator = header.find(" in ");
        if (separator == std::string_view::npos)
            continue;
        const std::string variables = trim(header.substr(4, separator - 4));
        const std::string iteratorText = trim(header.substr(separator + 4, header.size() - separator - 4 - 3));
        const std::vector<std::string> iteratorParts = splitCaptureExpressions(iteratorText);
        if (iteratorParts.size() != 3 ||
            std::any_of(iteratorParts.begin(), iteratorParts.end(), [](const std::string& value) {
                return !plainIdentifier(trimView(value));
            }))
            continue;

        size_t adjacentSetup = loop;
        while (adjacentSetup > 0 && trimView(lines[adjacentSetup - 1].text).empty())
            --adjacentSetup;
        if (adjacentSetup == 0)
            continue;
        --adjacentSetup;

        size_t setupLine = adjacentSetup;
        std::optional<size_t> aliasLine;
        auto setup = identifierAssignmentList(lines[setupLine].text);
        std::vector<std::string> transportTargets = iteratorParts;
        if (!setup || setup->targets != iteratorParts)
        {
            const auto alias = simpleAssignment(lines[adjacentSetup].text);
            const std::string source = alias ? trim(alias->value) : std::string();
            if (!alias || alias->target != iteratorParts[0] || !plainIdentifier(source) ||
                trimView(lines[adjacentSetup].text).starts_with("local "))
                continue;
            size_t previous = adjacentSetup;
            while (previous > 0 && trimView(lines[previous - 1].text).empty())
                --previous;
            if (previous == 0)
                continue;
            --previous;
            auto originalSetup = identifierAssignmentList(lines[previous].text);
            const std::vector<std::string> expected{source, iteratorParts[1], iteratorParts[2]};
            if (!originalSetup || originalSetup->targets != expected)
                continue;
            setupLine = previous;
            aliasLine = adjacentSetup;
            setup = std::move(originalSetup);
            transportTargets.push_back(source);
        }
        if (indentation(lines[setupLine].text) != indentation(lines[loop].text) ||
            captures.owner[setupLine] != captures.owner[loop] ||
            (aliasLine && (indentation(lines[*aliasLine].text) != indentation(lines[loop].text) ||
                              captures.owner[*aliasLine] != captures.owner[loop])))
            continue;
        const std::string expressions = trim(std::string_view(lines[setupLine].text).substr(setup->value_begin));
        if (expressions.empty())
            continue;
        bool selfReferential = false;
        for (const std::string& target : transportTargets)
            if (containsIdentifier(expressions, target))
                selfReferential = true;
        if (selfReferential)
            continue;

        const size_t indent = indentation(lines[loop].text);
        size_t loopEnd = loop + 1;
        while (loopEnd < lines.size() &&
            !(indentation(lines[loopEnd].text) == indent && trimView(lines[loopEnd].text) == "end"))
            ++loopEnd;
        if (loopEnd >= lines.size())
            continue;
        const size_t scope = captures.owner[setupLine];
        bool usedInBody = false;
        for (const std::string& target : transportTargets)
            for (size_t line = loop + 1; line < loopEnd; ++line)
            {
                if (captures.owner[line] != scope)
                    continue;
                if (!containsIdentifier(lines[line].text, target))
                    continue;
                const auto overwrite = identifierAssignmentList(lines[line].text);
                usedInBody = !overwrite ||
                    std::find(overwrite->targets.begin(), overwrite->targets.end(), target) == overwrite->targets.end() ||
                    containsIdentifier(std::string_view(lines[line].text).substr(overwrite->value_begin), target);
                break;
            }
        if (usedInBody)
            continue;

        const size_t scopeEnd = scope == topLevel ? lines.size() : (*spans)[scope].end;
        bool deadAfter = true;
        for (const std::string& target : transportTargets)
        {
            size_t lifetimeEnd = scopeEnd;
            for (size_t line = loopEnd + 1; line < scopeEnd; ++line)
            {
                if (captures.owner[line] != scope || !containsIdentifier(lines[line].text, target))
                    continue;
                lifetimeEnd = line;
                const auto overwrite = identifierAssignmentList(lines[line].text);
                deadAfter = overwrite &&
                    std::find(overwrite->targets.begin(), overwrite->targets.end(), target) != overwrite->targets.end() &&
                    !containsIdentifier(std::string_view(lines[line].text).substr(overwrite->value_begin), target);
                break;
            }
            if (!deadAfter || captures.capturedBefore(setupLine, target, lifetimeEnd))
                break;
        }
        if (!deadAfter)
            continue;

        lines[loop].text = std::string(indent, ' ') + "for " + variables + " in " + expressions + " do";
        lines[loop].states.insert(lines[setupLine].states.begin(), lines[setupLine].states.end());
        if (aliasLine)
            lines[loop].states.insert(lines[*aliasLine].states.begin(), lines[*aliasLine].states.end());
        if (!lines[loop].origin && lines[setupLine].origin)
            lines[loop].origin = lines[setupLine].origin;
        lines[setupLine].text.clear();
        if (aliasLine)
            lines[*aliasLine].text.clear();
        ++recovered;
    }
    return recovered;
}

size_t inlinePropertyTemporaries(std::vector<OutputLine>& lines)
{
    static const std::regex PropertyAssignment(
        R"(^(\s*)([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)$)");
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    std::vector<bool> remove(lines.size(), false);
    size_t inlined = 0;
    for (size_t index = 0; index + 1 < lines.size(); ++index)
    {
        auto definition = simpleAssignment(lines[index].text);
        size_t consumerLine = index + 1;
        while (consumerLine < lines.size() && trimView(lines[consumerLine].text).empty())
            ++consumerLine;
        std::smatch consumer;
        if (!definition || !generatedLocal(definition->target) ||
            consumerLine >= lines.size() || !std::regex_match(lines[consumerLine].text, consumer, PropertyAssignment) ||
            std::count(consumer[2].first, consumer[2].second, '.') != 1 || consumer[3].str() != definition->target ||
            containsIdentifier(consumer[2].str(), definition->target) || containsIdentifier(definition->value, definition->target))
            continue;

        bool safelyOverwritten = false;
        size_t lifetimeEnd = lines.size();
        for (size_t next = consumerLine + 1; next < lines.size(); ++next)
        {
            const std::string_view statement = trimView(lines[next].text);
            if (containsIdentifier(lines[next].text, definition->target))
            {
                auto overwrite = simpleAssignment(lines[next].text);
                safelyOverwritten = overwrite && overwrite->target == definition->target &&
                    !containsIdentifier(overwrite->value, definition->target);
                lifetimeEnd = next;
                break;
            }
            const bool returns = statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' ');
            if (returns)
            {
                safelyOverwritten = true;
                lifetimeEnd = next;
                break;
            }
            if (!statement.empty() && (statement == "else" || statement == "end" || statement == "repeat" ||
                    statement.starts_with("if ") || statement.starts_with("elseif ") || statement.starts_with("while ") ||
                    statement.starts_with("for ") || statement.starts_with("until ") || statement.starts_with("local function ") ||
                    statement.starts_with("return function(") || statement.find(" = function(") != std::string_view::npos))
                break;
        }
        if (!safelyOverwritten || captures.capturedBefore(index, definition->target, lifetimeEnd))
            continue;
        lines[consumerLine].text = consumer[1].str() + consumer[2].str() + " = " + definition->value;
        lines[consumerLine].states.insert(lines[index].states.begin(), lines[index].states.end());
        remove[index] = true;
        ++inlined;
        index = consumerLine;
    }
    if (inlined == 0)
        return 0;
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - inlined);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return inlined;
}

size_t discardProvenUnusedCallResults(std::vector<OutputLine>& lines)
{
    static const std::regex CallExpression(
        R"(^[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|:)[A-Za-z_][A-Za-z0-9_]*)*\(.*\)$)");
    size_t discarded = 0;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        auto assignment = simpleAssignment(lines[index].text);
        if (!assignment || assignment->target != "temporary" || assignment->value.find(':') == std::string::npos ||
            !std::regex_match(std::string(trimView(assignment->value)), CallExpression))
            continue;
        bool unused = false;
        const size_t limit = std::min(lines.size(), index + 20);
        for (size_t next = index + 1; next < limit; ++next)
        {
            const std::string_view statement = trimView(lines[next].text);
            if (containsIdentifier(lines[next].text, assignment->target))
            {
                auto overwrite = simpleAssignment(lines[next].text);
                unused = overwrite && overwrite->target == assignment->target &&
                    !containsIdentifier(overwrite->value, assignment->target);
                break;
            }
            const bool returns = statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' ');
            if (returns)
            {
                unused = true;
                break;
            }
            if (statement == "else" || statement == "repeat" || statement.starts_with("if ") || statement.starts_with("elseif ") ||
                statement.starts_with("while ") || statement.starts_with("for ") || statement.starts_with("until ") ||
                statement.starts_with("local function ") || statement.starts_with("return function(") ||
                statement.find(" = function(") != std::string_view::npos)
                break;
        }
        if (!unused)
            continue;
        lines[index].text = std::string(indentation(lines[index].text), ' ') + assignment->value;
        ++discarded;
    }
    return discarded;
}

bool logicalSemanticTemporary(std::string_view name)
{
    static const std::regex Pattern(R"(^(?:condition|flag)(?:_[0-9]+)?$)");
    return std::regex_match(std::string(name), Pattern);
}

struct CollapsedBranchValue
{
    std::string expression;
    std::vector<size_t> assignment_lines;
};

std::optional<CollapsedBranchValue> collapseLinearBranchValue(
    const std::vector<OutputLine>& lines,
    size_t begin,
    size_t end,
    std::string_view final_target)
{
    std::vector<std::pair<size_t, SimpleAssignment>> assignments;
    for (size_t line = begin; line < end; ++line)
    {
        if (trimView(lines[line].text).empty())
            continue;
        auto assignment = simpleAssignment(lines[line].text);
        if (!assignment)
            return std::nullopt;
        assignments.emplace_back(line, std::move(*assignment));
    }
    if (assignments.empty() || assignments.back().second.target != final_target ||
        trimView(lines[assignments.back().first].text).starts_with("local "))
        return std::nullopt;

    CollapsedBranchValue result;
    result.expression = assignments.back().second.value;
    result.assignment_lines.push_back(assignments.back().first);
    for (size_t item = assignments.size() - 1; item > 0; --item)
    {
        const auto& [line, producer] = assignments[item - 1];
        if (!plainIdentifier(producer.target) || producer.target == final_target ||
            containsIdentifier(producer.value, producer.target) ||
            identifierOccurrences(result.expression, producer.target) != 1)
            return std::nullopt;

        // Accept only a strict producer chain. Independent producers can be reordered by substitution.
        for (size_t earlier = 0; earlier + 1 < item; ++earlier)
            if (containsIdentifier(result.expression, assignments[earlier].second.target))
                return std::nullopt;

        bool dead_after = true;
        for (size_t next = end + 1; next < lines.size(); ++next)
        {
            if (!containsIdentifier(lines[next].text, producer.target))
                continue;
            auto overwrite = simpleAssignment(lines[next].text);
            dead_after = overwrite && overwrite->target == producer.target &&
                !containsIdentifier(overwrite->value, producer.target);
            break;
        }
        if (!dead_after)
            return std::nullopt;

        result.expression = replaceIdentifier(
            result.expression, producer.target, "(" + producer.value + ")");
        result.assignment_lines.push_back(line);
    }
    return result;
}

size_t recoverDefaultAssignments(std::vector<OutputLine>& lines)
{
    size_t recovered = 0;
    for (size_t assignmentLine = 0; assignmentLine + 2 < lines.size(); ++assignmentLine)
    {
        auto initial = simpleAssignment(lines[assignmentLine].text);
        const bool localInitial = initial && trimView(lines[assignmentLine].text).starts_with("local ");
        if (!initial || (!generatedLocal(initial->target) && !logicalSemanticTemporary(initial->target) && !localInitial))
            continue;
        const std::string source = trim(initial->value);
        size_t branch = assignmentLine + 1;
        while (branch < lines.size() && trimView(lines[branch].text).empty())
            ++branch;
        if (branch >= lines.size() || indentation(lines[branch].text) != indentation(lines[assignmentLine].text))
            continue;
        const std::string_view condition = trimView(lines[branch].text);
        const bool checks_source = plainIdentifier(source) &&
            (condition == "if not (" + source + ") then" || condition == "if not " + source + " then");
        const bool checks_target = condition == "if not (" + initial->target + ") then" ||
            condition == "if not " + initial->target + " then";
        if (!checks_source && !checks_target)
            continue;
        const std::string gate = checks_target && !checks_source ? "(" + source + ")" : source;
        const size_t indent = indentation(lines[branch].text);
        size_t branchEnd = branch + 1;
        while (branchEnd < lines.size() && !(indentation(lines[branchEnd].text) == indent && trimView(lines[branchEnd].text) == "end"))
            ++branchEnd;
        if (branchEnd >= lines.size())
            continue;

        std::optional<std::string> fallback;
        bool safe = true;
        for (size_t index = branch + 1; index < branchEnd; ++index)
        {
            if (trimView(lines[index].text).empty())
                continue;
            auto bodyAssignment = simpleAssignment(lines[index].text);
            if (fallback || !bodyAssignment || bodyAssignment->target != initial->target ||
                trimView(lines[index].text).starts_with("local ") ||
                containsIdentifier(bodyAssignment->value, initial->target))
            {
                safe = false;
                break;
            }
            fallback = bodyAssignment->value;
        }
        if (!safe || !fallback)
        {
            std::optional<CollapsedBranchValue> collapsed =
                collapseLinearBranchValue(lines, branch + 1, branchEnd, initial->target);
            if (!collapsed)
                continue;
            fallback = std::move(collapsed->expression);
        }
        if (checks_target && !checks_source)
        {
            lines[branch].text = std::string(indentation(lines[branch].text), ' ') +
                initial->target + " = " + initial->target + " or (" + *fallback + ")";
            lines[branch].states.insert(lines[assignmentLine].states.begin(), lines[assignmentLine].states.end());
            for (size_t index = branch + 1; index <= branchEnd; ++index)
            {
                lines[branch].states.insert(lines[index].states.begin(), lines[index].states.end());
                lines[index].text.clear();
            }
            ++recovered;
            continue;
        }
        lines[assignmentLine].text = std::string(indentation(lines[assignmentLine].text), ' ') +
            (localInitial ? "local " : "") + initial->target + " = " + gate + " or (" + *fallback + ")";
        for (size_t index = branch; index <= branchEnd; ++index)
            lines[assignmentLine].states.insert(lines[index].states.begin(), lines[index].states.end());
        lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(branch), lines.begin() + static_cast<std::ptrdiff_t>(branchEnd + 1));
        ++recovered;
    }
    return recovered;
}

size_t recoverTruthyConditionalAssignments(std::vector<OutputLine>& lines)
{
    size_t recovered = 0;
    for (size_t assignmentLine = lines.size(); assignmentLine > 0; --assignmentLine)
    {
        const size_t initialLine = assignmentLine - 1;
        auto initial = simpleAssignment(lines[initialLine].text);
        if (!initial || containsIdentifier(initial->value, initial->target))
            continue;
        const std::string source = trim(initial->value);
        size_t branch = initialLine + 1;
        while (branch < lines.size() && trimView(lines[branch].text).empty())
            ++branch;
        if (branch >= lines.size() || indentation(lines[branch].text) != indentation(lines[initialLine].text))
            continue;
        const std::string_view header = trimView(lines[branch].text);
        if (!header.starts_with("if ") || !header.ends_with(" then"))
            continue;
        const std::string_view condition = stripOuterParentheses(
            trimView(header.substr(3, header.size() - 3 - 5)));
        const bool checks_source = plainIdentifier(source) && condition == source;
        const bool checks_target = condition == initial->target;
        if (!checks_source && !checks_target)
            continue;
        const std::string gate = checks_target && !checks_source ? "(" + source + ")" : source;

        const size_t indent = indentation(lines[branch].text);
        size_t end = branch + 1;
        while (end < lines.size() &&
            !(indentation(lines[end].text) == indent && trimView(lines[end].text) == "end"))
        {
            if (indentation(lines[end].text) == indent && trimView(lines[end].text) == "else")
                break;
            ++end;
        }
        if (end >= lines.size() || trimView(lines[end].text) != "end")
            continue;
        std::optional<size_t> bodyLine;
        std::optional<std::string> bodyValue;
        bool safe = true;
        for (size_t line = branch + 1; line < end; ++line)
        {
            if (trimView(lines[line].text).empty())
                continue;
            auto body = simpleAssignment(lines[line].text);
            if (bodyLine || !body || body->target != initial->target ||
                trimView(lines[line].text).starts_with("local ") ||
                containsIdentifier(body->value, initial->target))
            {
                safe = false;
                break;
            }
            bodyLine = line;
        }
        if (safe && bodyLine)
            bodyValue = simpleAssignment(lines[*bodyLine].text)->value;
        else
        {
            std::optional<CollapsedBranchValue> collapsed =
                collapseLinearBranchValue(lines, branch + 1, end, initial->target);
            if (!collapsed)
                continue;
            bodyValue = std::move(collapsed->expression);
        }
        if (checks_target && !checks_source)
        {
            lines[branch].text = std::string(indentation(lines[branch].text), ' ') +
                initial->target + " = " + initial->target + " and (" + *bodyValue + ")";
            for (size_t line = branch + 1; line <= end; ++line)
            {
                lines[branch].states.insert(lines[line].states.begin(), lines[line].states.end());
                if (!lines[branch].origin && lines[line].origin)
                    lines[branch].origin = lines[line].origin;
                lines[line].text.clear();
            }
            ++recovered;
            continue;
        }
        const bool localInitial = trimView(lines[initialLine].text).starts_with("local ");
        lines[initialLine].text = std::string(indentation(lines[initialLine].text), ' ') +
            (localInitial ? "local " : "") + initial->target + " = " + gate + " and (" + *bodyValue + ")";
        for (size_t line = branch; line <= end; ++line)
        {
            lines[initialLine].states.insert(lines[line].states.begin(), lines[line].states.end());
            if (!lines[initialLine].origin && lines[line].origin)
                lines[initialLine].origin = lines[line].origin;
            lines[line].text.clear();
        }
        ++recovered;
    }
    return recovered;
}

std::string replaceCellValue(std::string_view line, std::string_view name, std::string_view replacement, size_t& replacements)
{
    const std::string parenthesized = "(" + std::string(name) + ")[1]";
    const std::string indexed = std::string(name) + "[1]";
    std::string output;
    output.reserve(line.size());
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
        {
            output.append(line.substr(index));
            break;
        }
        if (line[index] == '\'' || line[index] == '"')
        {
            const size_t begin = index;
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            output.append(line.substr(begin, index - begin));
            continue;
        }
        if (line.substr(index).starts_with(parenthesized))
        {
            output += replacement;
            index += parenthesized.size();
            ++replacements;
            continue;
        }
        const bool boundary = index == 0 || (line[index - 1] != '_' && !std::isalnum(static_cast<unsigned char>(line[index - 1])));
        if (boundary && line.substr(index).starts_with(indexed))
        {
            output += replacement;
            index += indexed.size();
            ++replacements;
            continue;
        }
        output.push_back(line[index++]);
    }
    return output;
}

struct CapturedCellSlot
{
    const CaptureFactoryRegion* factory = nullptr;
    size_t index = 0;
};

bool collectForwardedCellSlots(const std::vector<OutputLine>& lines, const std::vector<CaptureFactoryRegion>& factories,
    const CaptureFactoryRegion& factory, size_t slot, std::set<std::pair<size_t, size_t>>& active,
    std::set<std::pair<size_t, size_t>>& complete, std::vector<CapturedCellSlot>& slots, size_t& indexedUses)
{
    const std::pair<size_t, size_t> key{factory.opener, slot};
    if (complete.contains(key))
        return true;
    if (!active.insert(key).second)
        return false;

    const std::string& parameter = factory.parameters[slot];
    for (size_t line = factory.inner + 1; line < factory.inner_end; ++line)
    {
        size_t replacements = 0;
        const std::string rewritten = replaceCellValue(lines[line].text, parameter, "captured_value", replacements);
        indexedUses += replacements;
        if (!containsIdentifier(rewritten, parameter))
            continue;

        size_t forwarded = 0;
        for (const CaptureFactoryRegion& nested : factories)
        {
            if (nested.close != line)
                continue;
            for (size_t nestedSlot = 0; nestedSlot < nested.arguments.size(); ++nestedSlot)
            {
                if (trimView(nested.arguments[nestedSlot]) != parameter)
                    continue;
                ++forwarded;
                if (!collectForwardedCellSlots(lines, factories, nested, nestedSlot, active, complete, slots, indexedUses))
                {
                    active.erase(key);
                    return false;
                }
            }
        }
        if (identifierOccurrences(rewritten, parameter) != forwarded)
        {
            active.erase(key);
            return false;
        }
    }

    active.erase(key);
    complete.insert(key);
    slots.push_back({&factory, slot});
    return true;
}

size_t unboxCapturedCells(std::vector<OutputLine>& lines, bool allowForwarded = false)
{
    std::vector<DeclarationScope> scopes;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        auto names = generatedDeclaration(lines[index].text);
        if (!names || std::none_of(names->begin(), names->end(), [](const std::string& name) {
                return std::string_view(name).starts_with("cell_");
            }))
            continue;
        const size_t indent = indentation(lines[index].text);
        size_t end = lines.size();
        if (indent > 0)
            for (size_t candidate = index + 1; candidate < lines.size(); ++candidate)
                if (indentation(lines[candidate].text) == indent - 4 && trimView(lines[candidate].text) == "end")
                {
                    end = candidate;
                    break;
                }
        scopes.push_back({index, end, indent, std::move(*names)});
    }
    if (scopes.empty())
        return 0;

    std::vector<size_t> owner(lines.size(), std::numeric_limits<size_t>::max());
    std::vector<size_t> order(scopes.size());
    for (size_t index = 0; index < scopes.size(); ++index)
        order[index] = index;
    std::sort(order.begin(), order.end(), [&](size_t left, size_t right) { return scopes[left].indent < scopes[right].indent; });
    for (size_t scopeIndex : order)
        for (size_t line = scopes[scopeIndex].declaration; line < scopes[scopeIndex].end && line < owner.size(); ++line)
            owner[line] = scopeIndex;

    const std::vector<CaptureFactoryRegion> factories = findCaptureFactories(lines);
    constexpr std::string_view CapturedPrefix = "captured_value_";
    std::set<size_t> usedCapturedOrdinals;
    for (const OutputLine& line : lines)
        for (size_t search = 0; search < line.text.size();)
        {
            const size_t prefix = line.text.find(CapturedPrefix, search);
            if (prefix == std::string::npos)
                break;
            const bool leadingBoundary = prefix == 0 ||
                (line.text[prefix - 1] != '_' && !std::isalnum(static_cast<unsigned char>(line.text[prefix - 1])));
            size_t end = prefix + CapturedPrefix.size();
            const size_t digits = end;
            while (end < line.text.size() && std::isdigit(static_cast<unsigned char>(line.text[end])))
                ++end;
            const bool trailingBoundary = end == line.text.size() ||
                (line.text[end] != '_' && !std::isalnum(static_cast<unsigned char>(line.text[end])));
            if (leadingBoundary && end > digits && trailingBoundary)
                if (const auto ordinal = parseInteger(std::string_view(line.text).substr(digits, end - digits));
                    ordinal && *ordinal > 0)
                    usedCapturedOrdinals.insert(static_cast<size_t>(*ordinal));
            search = std::max(end, prefix + CapturedPrefix.size());
        }
    size_t nameOrdinal = 0;
    size_t unboxed = 0;
    for (size_t scopeIndex = 0; scopeIndex < scopes.size(); ++scopeIndex)
    {
        const DeclarationScope& scope = scopes[scopeIndex];
        for (const std::string& cell : scope.names)
        {
            // Register-backed captures are emitted as local_N before semantic naming.
            // Treat them like explicit cell_N values when every use proves the same
            // single-slot box shape; the checks below reject ordinary register tables.
            if (!std::string_view(cell).starts_with("cell_") && !generatedLocal(cell))
                continue;
            std::vector<CapturedCellSlot> slots;
            std::map<size_t, size_t> closeOccurrences;
            bool safe = true;
            size_t indexedUses = 0;
            std::set<std::pair<size_t, size_t>> activeSlots;
            std::set<std::pair<size_t, size_t>> completeSlots;
            for (const CaptureFactoryRegion& factory : factories)
            {
                if (factory.opener >= owner.size() || owner[factory.opener] != scopeIndex)
                    continue;
                for (size_t slot = 0; slot < factory.arguments.size(); ++slot)
                {
                    if (trimView(factory.arguments[slot]) != cell)
                        continue;
                    if (allowForwarded)
                    {
                        if (!collectForwardedCellSlots(
                                lines, factories, factory, slot, activeSlots, completeSlots, slots, indexedUses))
                        {
                            safe = false;
                            break;
                        }
                    }
                    else
                    {
                        size_t parameterUses = 0;
                        for (size_t line = factory.inner + 1; line < factory.inner_end; ++line)
                        {
                            size_t replacements = 0;
                            const std::string rewritten = replaceCellValue(
                                lines[line].text, factory.parameters[slot], "captured_value", replacements);
                            parameterUses += replacements;
                            if (containsIdentifier(rewritten, factory.parameters[slot]))
                            {
                                safe = false;
                                break;
                            }
                        }
                        indexedUses += parameterUses;
                        slots.push_back({&factory, slot});
                    }
                    if (!safe)
                        break;
                    ++closeOccurrences[factory.close];
                }
                if (!safe)
                    break;
            }
            if (!safe || slots.empty())
                continue;

            std::vector<size_t> allocations;
            for (size_t index = scope.declaration + 1; index < scope.end && index < lines.size(); ++index)
            {
                if (owner[index] != scopeIndex || !containsIdentifier(lines[index].text, cell))
                    continue;
                if (trimView(lines[index].text) == cell + " = {nil}")
                {
                    allocations.push_back(index);
                    continue;
                }
                auto close = closeOccurrences.find(index);
                if (close != closeOccurrences.end() && identifierOccurrences(lines[index].text, cell) == close->second)
                    continue;
                size_t replacements = 0;
                const std::string rewritten = replaceCellValue(lines[index].text, cell, "captured_value", replacements);
                indexedUses += replacements;
                if (containsIdentifier(rewritten, cell))
                {
                    safe = false;
                    break;
                }
            }
            if (!safe || indexedUses == 0 || allocations.size() != 1)
                continue;

            std::string captured;
            do
            {
                captured = "captured_value_" + std::to_string(++nameOrdinal);
            } while (usedCapturedOrdinals.contains(nameOrdinal));
            usedCapturedOrdinals.insert(nameOrdinal);

            lines[scope.declaration].text = replaceIdentifier(lines[scope.declaration].text, cell, captured);
            for (size_t index = scope.declaration + 1; index < scope.end && index < lines.size(); ++index)
            {
                if (owner[index] != scopeIndex)
                    continue;
                size_t replacements = 0;
                lines[index].text = replaceCellValue(lines[index].text, cell, captured, replacements);
            }
            for (size_t allocation : allocations)
                lines[allocation].text.clear();
            for (const CapturedCellSlot& slot : slots)
                for (size_t line = slot.factory->inner + 1; line < slot.factory->inner_end; ++line)
                {
                    size_t replacements = 0;
                    lines[line].text = replaceCellValue(lines[line].text, slot.factory->parameters[slot.index], captured, replacements);
                }
            ++unboxed;
        }
    }
    return unboxed;
}

size_t removeShadowedCellAllocations(std::vector<OutputLine>& lines)
{
    std::vector<DeclarationScope> scopes;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        auto names = generatedDeclaration(lines[index].text);
        if (!names || std::none_of(names->begin(), names->end(), [](const std::string& name) {
                return std::string_view(name).starts_with("cell_");
            }))
            continue;
        const size_t indent = indentation(lines[index].text);
        size_t end = lines.size();
        if (indent > 0)
            for (size_t candidate = index + 1; candidate < lines.size(); ++candidate)
                if (indentation(lines[candidate].text) == indent - 4 && trimView(lines[candidate].text) == "end")
                {
                    end = candidate;
                    break;
                }
        scopes.push_back({index, end, indent, std::move(*names)});
    }

    std::vector<size_t> owner(lines.size(), std::numeric_limits<size_t>::max());
    std::vector<size_t> order(scopes.size());
    for (size_t index = 0; index < scopes.size(); ++index)
        order[index] = index;
    std::sort(order.begin(), order.end(), [&](size_t left, size_t right) { return scopes[left].indent < scopes[right].indent; });
    for (size_t scopeIndex : order)
        for (size_t line = scopes[scopeIndex].declaration; line < scopes[scopeIndex].end && line < owner.size(); ++line)
            owner[line] = scopeIndex;

    std::vector<bool> remove(lines.size(), false);
    size_t removed = 0;
    for (size_t scopeIndex = 0; scopeIndex < scopes.size(); ++scopeIndex)
    {
        const DeclarationScope& scope = scopes[scopeIndex];
        for (const std::string& name : scope.names)
        {
            if (!std::string_view(name).starts_with("cell_"))
                continue;
            std::vector<size_t> pending;
            const std::string allocation = name + " = {nil}";
            const std::string slot = name + "[1]";
            for (size_t index = scope.declaration + 1; index < scope.end && index < lines.size(); ++index)
            {
                if (owner[index] != scopeIndex || !containsIdentifier(lines[index].text, name))
                    continue;
                if (trimView(lines[index].text) == allocation)
                {
                    if (!pending.empty())
                    {
                        for (size_t line : pending)
                            if (!remove[line])
                            {
                                remove[line] = true;
                                ++removed;
                            }
                    }
                    pending = {index};
                }
                else
                {
                    const std::string_view statement = trimView(lines[index].text);
                    if (!pending.empty() && statement.starts_with(slot))
                    {
                        const std::string_view remainder = trimView(statement.substr(slot.size()));
                        if (remainder.starts_with('=') && !remainder.starts_with("=="))
                        {
                            const std::string_view value = trimView(remainder.substr(1));
                            const bool isolatedTableLiteral = value == "{}" || value == "{nil}";
                            if (!value.empty() && !containsIdentifier(value, name) &&
                                (isolatedTableLiteral || pureAssignmentValue(value)))
                            {
                                pending.push_back(index);
                                continue;
                            }
                        }
                    }
                    pending.clear();
                }
            }
        }
    }
    if (removed == 0)
        return 0;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        if (!remove[index] || lines[index].states.empty())
            continue;
        size_t anchor = index + 1;
        while (anchor < lines.size() && remove[anchor])
            ++anchor;
        if (anchor < lines.size())
            lines[anchor].states.insert(lines[index].states.begin(), lines[index].states.end());
    }
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return removed;
}

bool safeCaptureArgument(std::string_view value)
{
    value = trimView(value);
    if (scalarLiteral(value))
        return true;
    static const std::regex Safe(R"(^\(?[A-Za-z_][A-Za-z0-9_]*(?:\)?\[[0-9]+\])?$)");
    return std::regex_match(std::string(value), Safe);
}

size_t removeDeadPureCaptureFactories(std::vector<OutputLine>& lines)
{
    static const std::regex IndexedCell(R"(^((?:captured_value|cell|upvalue_cell)_[0-9]+)\[1\]$)");
    static const std::regex IndexedFactoryAssignment(
        R"(^\s*((?:captured_value|cell|upvalue_cell)_[0-9]+\[1\])\s*=\s*(\(function\(.*)$)");
    size_t removed = 0;
    while (true)
    {
        const std::vector<CaptureFactoryRegion> factories = findCaptureFactories(lines);
        std::optional<std::pair<CaptureFactoryRegion, size_t>> candidate;
        for (const CaptureFactoryRegion& factory : factories)
        {
            auto assignment = simpleAssignment(lines[factory.opener].text);
            if (!assignment)
            {
                std::smatch match;
                if (std::regex_match(lines[factory.opener].text, match, IndexedFactoryAssignment))
                    assignment = SimpleAssignment{match[1].str(), trim(match[2].str())};
            }
            std::optional<std::string> indexedCell;
            if (assignment)
            {
                std::smatch match;
                if (std::regex_match(assignment->target, match, IndexedCell))
                    indexedCell = match[1].str();
            }
            if (!assignment ||
                (!capturedLocal(assignment->target) && !generatedLocal(assignment->target) && !indexedCell) ||
                !trimView(assignment->value).starts_with("(function(") ||
                !std::all_of(factory.arguments.begin(), factory.arguments.end(), safeCaptureArgument))
                continue;

            const size_t indent = indentation(lines[factory.opener].text);
            for (size_t index = factory.close + 1; index < lines.size(); ++index)
            {
                const std::string& observed = indexedCell ? *indexedCell : assignment->target;
                if (!containsIdentifier(lines[index].text, observed))
                    continue;
                auto overwrite = simpleAssignment(lines[index].text);
                const bool overwritesTarget = overwrite && (overwrite->target == assignment->target ||
                    (indexedCell && overwrite->target == *indexedCell));
                if (overwritesTarget && indentation(lines[index].text) == indent &&
                    !containsIdentifier(overwrite->value, observed))
                    candidate = std::make_pair(factory, index);
                break;
            }
            if (candidate)
                break;
        }
        if (!candidate)
            break;

        const CaptureFactoryRegion& factory = candidate->first;
        OutputLine& anchor = lines[candidate->second];
        for (size_t index = factory.opener; index <= factory.close; ++index)
        {
            anchor.states.insert(lines[index].states.begin(), lines[index].states.end());
            if (!anchor.origin && lines[index].origin)
                anchor.origin = lines[index].origin;
        }
        lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(factory.opener),
            lines.begin() + static_cast<std::ptrdiff_t>(factory.close + 1));
        ++removed;
    }
    return removed;
}

struct CaptureFactoryStats
{
    size_t captures = 0;
    size_t factories = 0;
};

CaptureFactoryStats collapseUnusedCaptureFactories(std::vector<OutputLine>& lines)
{
    CaptureFactoryStats stats;
    for (size_t opener = 0; opener < lines.size(); ++opener)
    {
        constexpr std::string_view Marker = "(function(";
        const size_t marker = lines[opener].text.find(Marker);
        if (marker == std::string::npos)
            continue;
        const size_t parametersBegin = marker + Marker.size();
        const size_t parametersEnd = lines[opener].text.find(')', parametersBegin);
        if (parametersEnd == std::string::npos)
            continue;
        std::vector<std::string> parameters = splitCaptureExpressions(
            std::string_view(lines[opener].text).substr(parametersBegin, parametersEnd - parametersBegin));
        if (parameters.empty())
            continue;
        const size_t indent = indentation(lines[opener].text);
        size_t inner = opener + 1;
        while (inner < lines.size() && trimView(lines[inner].text).empty())
            ++inner;
        if (inner >= lines.size() || indentation(lines[inner].text) != indent + 4 ||
            !trimView(lines[inner].text).starts_with("return function("))
            continue;
        size_t innerEnd = inner + 1;
        while (innerEnd < lines.size() && !(indentation(lines[innerEnd].text) == indent + 4 && trimView(lines[innerEnd].text) == "end"))
            ++innerEnd;
        if (innerEnd >= lines.size())
            continue;
        size_t close = innerEnd + 1;
        while (close < lines.size() && trimView(lines[close].text).empty())
            ++close;
        if (close >= lines.size() || indentation(lines[close].text) != indent || !trimView(lines[close].text).starts_with("end)("))
            continue;
        const std::string_view closeText = trimView(lines[close].text);
        if (!closeText.ends_with(')'))
            continue;
        std::vector<std::string> arguments = splitCaptureExpressions(closeText.substr(5, closeText.size() - 6));
        if (arguments.size() != parameters.size())
            continue;

        std::vector<size_t> keep;
        size_t removed = 0;
        for (size_t slot = 0; slot < parameters.size(); ++slot)
        {
            bool used = false;
            for (size_t index = inner + 1; index < innerEnd; ++index)
                if (containsIdentifier(lines[index].text, parameters[slot]))
                {
                    used = true;
                    break;
                }
            if (used || !safeCaptureArgument(arguments[slot]))
                keep.push_back(slot);
            else
                ++removed;
        }
        if (removed == 0)
            continue;
        stats.captures += removed;
        if (keep.empty())
        {
            const std::string prefix = lines[opener].text.substr(0, marker);
            const std::string innerSignature = trim(std::string_view(lines[inner].text).substr(indentation(lines[inner].text) + 7));
            std::vector<OutputLine> replacement;
            OutputLine first{prefix + innerSignature, lines[opener].origin, lines[opener].states};
            first.states.insert(lines[inner].states.begin(), lines[inner].states.end());
            replacement.push_back(std::move(first));
            for (size_t index = inner + 1; index < innerEnd; ++index)
            {
                OutputLine body = lines[index];
                if (body.text.size() >= 4)
                    body.text.erase(0, 4);
                replacement.push_back(std::move(body));
            }
            OutputLine ending{std::string(indent, ' ') + "end", lines[close].origin, lines[close].states};
            ending.states.insert(lines[innerEnd].states.begin(), lines[innerEnd].states.end());
            replacement.push_back(std::move(ending));
            lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(opener), lines.begin() + static_cast<std::ptrdiff_t>(close + 1));
            lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(opener), std::make_move_iterator(replacement.begin()),
                std::make_move_iterator(replacement.end()));
            ++stats.factories;
            if (opener > 0)
                --opener;
            continue;
        }

        std::string parameterList;
        std::string argumentList;
        for (size_t index = 0; index < keep.size(); ++index)
        {
            if (index)
            {
                parameterList += ", ";
                argumentList += ", ";
            }
            parameterList += parameters[keep[index]];
            argumentList += arguments[keep[index]];
        }
        lines[opener].text.replace(parametersBegin, parametersEnd - parametersBegin, parameterList);
        lines[close].text = std::string(indent, ' ') + "end)(" + argumentList + ")";
    }
    return stats;
}

size_t lowerCaptureFactoriesToSnapshots(std::vector<OutputLine>& lines)
{
    std::set<std::string> occupied = collectIdentifiers(lines);

    size_t snapshotOrdinal = 0;
    size_t lowered = 0;
    while (true)
    {
        const std::vector<CaptureFactoryRegion> factories = findCaptureFactories(lines, false);
        std::optional<CaptureFactoryRegion> selected;
        for (auto iterator = factories.rbegin(); iterator != factories.rend(); ++iterator)
        {
            const CaptureFactoryRegion& factory = *iterator;
            auto assignment = simpleAssignment(lines[factory.opener].text);
            constexpr size_t SnapshotLocalBudget = 12;
            if (!assignment || factory.parameters.empty() || factory.parameters.size() > SnapshotLocalBudget ||
                !trimView(assignment->value).starts_with("(function("))
                continue;
            const std::string_view opener = trimView(lines[factory.opener].text);
            const bool localTarget = opener.starts_with("local ");
            bool safe = true;
            if (localTarget)
            {
                for (const std::string& argument : factory.arguments)
                    if (containsIdentifier(argument, assignment->target))
                    {
                        safe = false;
                        break;
                    }
                for (size_t line = factory.inner; safe && line < factory.inner_end; ++line)
                    if (containsIdentifier(lines[line].text, assignment->target))
                        safe = false;
            }
            if (!safe)
                continue;

            for (const std::string& parameter : factory.parameters)
            {
                if (!plainIdentifier(parameter))
                {
                    safe = false;
                    break;
                }
            }
            if (safe)
            {
                selected = factory;
                break;
            }
        }
        if (!selected)
            break;

        const CaptureFactoryRegion factory = *selected;
        const auto assignment = simpleAssignment(lines[factory.opener].text);
        const size_t indent = indentation(lines[factory.opener].text);
        const bool localTarget = trimView(lines[factory.opener].text).starts_with("local ");
        std::vector<std::string> snapshots;
        snapshots.reserve(factory.parameters.size());
        for (size_t slot = 0; slot < factory.parameters.size(); ++slot)
        {
            std::string snapshot;
            do
            {
                snapshot = "snapshot_" + std::to_string(++snapshotOrdinal);
            } while (occupied.contains(snapshot));
            occupied.insert(snapshot);
            snapshots.push_back(std::move(snapshot));
        }

        std::vector<OutputLine> replacement;
        if (localTarget)
            replacement.push_back({std::string(indent, ' ') + "local " + assignment->target,
                lines[factory.opener].origin, lines[factory.opener].states});
        replacement.push_back({std::string(indent, ' ') + "do", std::nullopt, {}});

        std::string snapshotLine(indent + 4, ' ');
        snapshotLine += "local ";
        for (size_t slot = 0; slot < snapshots.size(); ++slot)
        {
            if (slot)
                snapshotLine += ", ";
            snapshotLine += snapshots[slot];
        }
        if (!factory.arguments.empty())
        {
            snapshotLine += " = ";
            for (size_t slot = 0; slot < factory.arguments.size(); ++slot)
            {
                if (slot)
                    snapshotLine += ", ";
                snapshotLine += factory.arguments[slot];
            }
        }
        replacement.push_back({std::move(snapshotLine), lines[factory.close].origin, lines[factory.close].states});

        const std::string_view inner = trimView(lines[factory.inner].text);
        std::string functionLine(indent + 4, ' ');
        functionLine += assignment->target;
        functionLine += " = ";
        functionLine += std::string(inner.substr(std::string_view("return ").size()));
        OutputLine functionOutput{std::move(functionLine), lines[factory.inner].origin, lines[factory.inner].states};
        if (!localTarget)
        {
            functionOutput.states.insert(lines[factory.opener].states.begin(), lines[factory.opener].states.end());
            if (!functionOutput.origin && lines[factory.opener].origin)
                functionOutput.origin = lines[factory.opener].origin;
        }
        replacement.push_back(std::move(functionOutput));

        for (size_t line = factory.inner + 1; line < factory.inner_end; ++line)
        {
            OutputLine body = lines[line];
            for (size_t slot = 0; slot < factory.parameters.size(); ++slot)
                body.text = replaceIdentifier(body.text, factory.parameters[slot], snapshots[slot]);
            replacement.push_back(std::move(body));
        }
        replacement.push_back({std::string(indent + 4, ' ') + "end", lines[factory.inner_end].origin,
            lines[factory.inner_end].states});
        replacement.push_back({std::string(indent, ' ') + "end", std::nullopt, {}});

        lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(factory.opener),
            lines.begin() + static_cast<std::ptrdiff_t>(factory.close + 1));
        lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(factory.opener),
            std::make_move_iterator(replacement.begin()), std::make_move_iterator(replacement.end()));
        ++lowered;
    }
    return lowered;
}

size_t removeUnusedCellAllocations(std::vector<OutputLine>& lines)
{
    std::vector<DeclarationScope> scopes;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        auto names = generatedDeclaration(lines[index].text);
        if (!names || std::none_of(names->begin(), names->end(), [](const std::string& name) {
                return std::string_view(name).starts_with("cell_");
            }))
            continue;
        const size_t indent = indentation(lines[index].text);
        size_t end = lines.size();
        if (indent > 0)
            for (size_t candidate = index + 1; candidate < lines.size(); ++candidate)
                if (indentation(lines[candidate].text) == indent - 4 && trimView(lines[candidate].text) == "end")
                {
                    end = candidate;
                    break;
                }
        scopes.push_back({index, end, indent, std::move(*names)});
    }
    if (scopes.empty())
        return 0;
    std::vector<size_t> owner(lines.size(), std::numeric_limits<size_t>::max());
    std::vector<size_t> order(scopes.size());
    for (size_t index = 0; index < scopes.size(); ++index)
        order[index] = index;
    std::sort(order.begin(), order.end(), [&](size_t left, size_t right) { return scopes[left].indent < scopes[right].indent; });
    for (size_t scopeIndex : order)
        for (size_t line = scopes[scopeIndex].declaration; line < scopes[scopeIndex].end && line < owner.size(); ++line)
            owner[line] = scopeIndex;

    std::vector<bool> remove(lines.size(), false);
    size_t removed = 0;
    for (size_t scopeIndex = 0; scopeIndex < scopes.size(); ++scopeIndex)
    {
        const DeclarationScope& scope = scopes[scopeIndex];
        for (const std::string& name : scope.names)
        {
            if (!std::string_view(name).starts_with("cell_"))
                continue;
            std::vector<size_t> allocations;
            bool meaningful = false;
            const std::string allocation = name + " = {nil}";
            for (size_t index = scope.declaration + 1; index < scope.end && index < lines.size(); ++index)
            {
                if (owner[index] != scopeIndex || !containsIdentifier(lines[index].text, name))
                    continue;
                if (trimView(lines[index].text) == allocation)
                    allocations.push_back(index);
                else
                {
                    meaningful = true;
                    break;
                }
            }
            if (meaningful)
                continue;
            for (size_t allocationIndex : allocations)
            {
                remove[allocationIndex] = true;
                ++removed;
            }
        }
    }
    if (removed == 0)
        return 0;
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return removed;
}

size_t recoverReturnedClosures(std::vector<OutputLine>& lines)
{
    size_t recovered = 0;
    for (size_t opener = 0; opener < lines.size(); ++opener)
    {
        auto assignment = simpleAssignment(lines[opener].text);
        if (!assignment || !generatedLocal(assignment->target) || !trimView(assignment->value).starts_with("function(") ||
            functionExpressionClosesOnLine(assignment->value))
            continue;
        const size_t indent = indentation(lines[opener].text);
        size_t functionEnd = opener + 1;
        while (functionEnd < lines.size() && !(indentation(lines[functionEnd].text) == indent && trimView(lines[functionEnd].text) == "end"))
            ++functionEnd;
        if (functionEnd >= lines.size())
            continue;
        size_t resultAssignment = functionEnd + 1;
        while (resultAssignment < lines.size() && trimView(lines[resultAssignment].text).empty())
            ++resultAssignment;
        if (resultAssignment >= lines.size() || indentation(lines[resultAssignment].text) != indent ||
            trimView(lines[resultAssignment].text) != "__results = {" + assignment->target + "}")
            continue;
        size_t returnLine = resultAssignment + 1;
        while (returnLine < lines.size() &&
            !(indentation(lines[returnLine].text) == indent && trimView(lines[returnLine].text) == "return table.unpack(__results)"))
        {
            const std::string_view statement = trimView(lines[returnLine].text);
            if (indentation(lines[returnLine].text) != indent || controlBoundary(statement) ||
                containsIdentifier(statement, assignment->target) || containsIdentifier(statement, "__results"))
                break;
            ++returnLine;
        }
        if (returnLine >= lines.size() || indentation(lines[returnLine].text) != indent ||
            trimView(lines[returnLine].text) != "return table.unpack(__results)")
            continue;

        std::vector<OutputLine> replacement;
        replacement.reserve(returnLine - opener - 1);
        for (size_t index = resultAssignment + 1; index < returnLine; ++index)
        {
            OutputLine statement = lines[index];
            const size_t first = statement.text.find_first_not_of(' ');
            if (first != std::string::npos && statement.text[first] == ';')
                statement.text.erase(first, 1);
            replacement.push_back(std::move(statement));
        }
        OutputLine first = lines[opener];
        first.text = std::string(indent, ' ') + "return " + assignment->value;
        first.states.insert(lines[resultAssignment].states.begin(), lines[resultAssignment].states.end());
        first.states.insert(lines[returnLine].states.begin(), lines[returnLine].states.end());
        replacement.push_back(std::move(first));
        for (size_t index = opener + 1; index <= functionEnd; ++index)
            replacement.push_back(lines[index]);

        lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(opener), lines.begin() + static_cast<std::ptrdiff_t>(returnLine + 1));
        lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(opener), std::make_move_iterator(replacement.begin()),
            std::make_move_iterator(replacement.end()));
        ++recovered;
        opener += replacement.size() - 1;
    }
    return recovered;
}

size_t promoteFunctionLocals(std::vector<OutputLine>& lines)
{
    std::vector<DeclarationScope> scopes;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        auto names = generatedDeclaration(lines[index].text);
        if (!names || std::none_of(names->begin(), names->end(), [](const std::string& name) {
                return std::string_view(name).starts_with("local_");
            }))
            continue;
        const size_t indent = indentation(lines[index].text);
        size_t end = lines.size();
        if (indent > 0)
            for (size_t candidate = index + 1; candidate < lines.size(); ++candidate)
                if (indentation(lines[candidate].text) == indent - 4 && trimView(lines[candidate].text) == "end")
                {
                    end = candidate;
                    break;
                }
        scopes.push_back({index, end, indent, std::move(*names)});
    }
    if (scopes.empty())
        return 0;

    std::vector<size_t> owner(lines.size(), std::numeric_limits<size_t>::max());
    std::vector<size_t> order(scopes.size());
    for (size_t index = 0; index < scopes.size(); ++index)
        order[index] = index;
    std::sort(order.begin(), order.end(), [&](size_t left, size_t right) { return scopes[left].indent < scopes[right].indent; });
    for (size_t scopeIndex : order)
        for (size_t line = scopes[scopeIndex].declaration; line < scopes[scopeIndex].end && line < owner.size(); ++line)
            owner[line] = scopeIndex;

    size_t ordinal = 0;
    size_t promoted = 0;
    for (size_t scopeIndex = 0; scopeIndex < scopes.size(); ++scopeIndex)
    {
        DeclarationScope& scope = scopes[scopeIndex];
        std::set<std::string> promotedNames;
        for (const std::string& name : scope.names)
        {
            if (!std::string_view(name).starts_with("local_") || !generatedLocal(name))
                continue;
            std::optional<size_t> assignmentLine;
            bool unsafeWrite = false;
            for (size_t index = scope.declaration + 1; index < scope.end && index < lines.size(); ++index)
            {
                if (owner[index] != scopeIndex)
                    continue;
                auto assignment = simpleAssignment(lines[index].text);
                if (assignment && assignment->target == name)
                {
                    if (assignmentLine || !trimView(assignment->value).starts_with("function(") ||
                        functionExpressionClosesOnLine(assignment->value) || indentation(lines[index].text) != scope.indent)
                        unsafeWrite = true;
                    else
                        assignmentLine = index;
                }
                else if (compoundTarget(lines[index].text, name) || tokenBeforeAssignment(lines[index].text, name))
                    unsafeWrite = true;
            }
            if (unsafeWrite || !assignmentLine)
                continue;
            bool readBefore = false;
            for (size_t index = scope.declaration + 1; index < *assignmentLine; ++index)
                if (owner[index] == scopeIndex && containsIdentifier(lines[index].text, name))
                    readBefore = true;
            if (readBefore)
                continue;

            size_t functionEnd = *assignmentLine + 1;
            while (functionEnd < scope.end && !(indentation(lines[functionEnd].text) == scope.indent && trimView(lines[functionEnd].text) == "end"))
                ++functionEnd;
            if (functionEnd >= scope.end)
                continue;
            bool recursiveReference = false;
            for (size_t index = *assignmentLine + 1; index < functionEnd; ++index)
                if (containsIdentifier(lines[index].text, name))
                    recursiveReference = true;
            if (recursiveReference)
                continue;

            std::string functionName;
            do
            {
                functionName = "function_" + std::to_string(++ordinal);
            } while (std::any_of(lines.begin(), lines.end(), [&](const OutputLine& line) { return containsIdentifier(line.text, functionName); }));
            auto assignment = simpleAssignment(lines[*assignmentLine].text);
            const std::string_view value = trimView(assignment->value);
            lines[*assignmentLine].text = std::string(scope.indent, ' ') + "local function " + functionName + std::string(value.substr(8));
            for (size_t index = *assignmentLine + 1; index < scope.end && index < lines.size(); ++index)
                if (owner[index] == scopeIndex)
                    lines[index].text = replaceIdentifier(lines[index].text, name, functionName);
            promotedNames.insert(name);
            ++promoted;
        }
        if (promotedNames.empty())
            continue;
        std::vector<std::string> remaining;
        for (const std::string& name : scope.names)
            if (!promotedNames.contains(name))
                remaining.push_back(name);
        if (remaining.empty())
            lines[scope.declaration].text.clear();
        else
        {
            std::string declaration(scope.indent, ' ');
            declaration += "local ";
            for (size_t index = 0; index < remaining.size(); ++index)
            {
                if (index)
                    declaration += ", ";
                declaration += remaining[index];
            }
            lines[scope.declaration].text = std::move(declaration);
        }
    }
    return promoted;
}

size_t promoteInitializedFunctionLocals(std::vector<OutputLine>& lines)
{
    static const std::regex InitializedFunction(
        R"(^(\s*)local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*function\((.*)\)\s*$)");
    size_t promoted = 0;
    for (size_t opener = 0; opener < lines.size(); ++opener)
    {
        std::smatch match;
        if (!std::regex_match(lines[opener].text, match, InitializedFunction))
            continue;
        const size_t indent = indentation(lines[opener].text);
        size_t functionEnd = opener + 1;
        while (functionEnd < lines.size() &&
            !(indentation(lines[functionEnd].text) == indent && trimView(lines[functionEnd].text) == "end"))
            ++functionEnd;
        if (functionEnd >= lines.size())
            continue;

        const std::string name = match[2].str();
        bool referencesInitializerBinding = false;
        for (size_t line = opener + 1; line < functionEnd; ++line)
            if (containsIdentifier(lines[line].text, name))
            {
                referencesInitializerBinding = true;
                break;
            }
        if (referencesInitializerBinding)
            continue;

        lines[opener].text = match[1].str() + "local function " + name + "(" + match[3].str() + ")";
        ++promoted;
    }
    return promoted;
}

size_t removeSafeLeadingSemicolons(std::vector<OutputLine>& lines)
{
    size_t removed = 0;
    for (OutputLine& line : lines)
    {
        const size_t first = line.text.find_first_not_of(' ');
        if (first == std::string::npos || line.text[first] != ';' || first + 1 >= line.text.size())
            continue;
        const char next = line.text[first + 1];
        if (next != '_' && !std::isalpha(static_cast<unsigned char>(next)))
            continue;
        line.text.erase(first, 1);
        ++removed;
    }
    return removed;
}

size_t removeEmbeddedExpressionSemicolons(std::vector<OutputLine>& lines)
{
    size_t removed = 0;
    for (OutputLine& output : lines)
    {
        std::string& line = output.text;
        char quote = 0;
        for (size_t index = 0; index < line.size();)
        {
            const char ch = line[index];
            if (quote != 0)
            {
                if (ch == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else
                {
                    if (ch == quote)
                        quote = 0;
                    ++index;
                }
                continue;
            }
            if (ch == '-' && index + 1 < line.size() && line[index + 1] == '-')
                break;
            if (ch == '\'' || ch == '"')
            {
                quote = ch;
                ++index;
                continue;
            }
            if (ch != ';')
            {
                ++index;
                continue;
            }
            size_t next = index + 1;
            while (next < line.size() && std::isspace(static_cast<unsigned char>(line[next])))
                ++next;
            if (next < line.size() && (line[next] == ')' || line[next] == ']' || line[next] == '}' || line[next] == ','))
            {
                line.erase(index, 1);
                ++removed;
                continue;
            }
            ++index;
        }
    }
    return removed;
}

size_t removeRedundantIdentifierIndexGroupings(std::vector<OutputLine>& lines)
{
    size_t removed = 0;
    for (OutputLine& output : lines)
    {
        bool changed = true;
        while (changed)
        {
            changed = false;
            std::string& line = output.text;
            char quote = 0;
            for (size_t open = 0; open < line.size(); ++open)
            {
                const char ch = line[open];
                if (quote != 0)
                {
                    if (ch == '\\')
                        ++open;
                    else if (ch == quote)
                        quote = 0;
                    continue;
                }
                if (ch == '-' && open + 1 < line.size() && line[open + 1] == '-')
                    break;
                if (ch == '\'' || ch == '"')
                {
                    quote = ch;
                    continue;
                }
                if (ch != '(')
                    continue;

                size_t previous = open;
                while (previous > 0 && std::isspace(static_cast<unsigned char>(line[previous - 1])))
                    --previous;
                if (previous > 0)
                {
                    const char leading = line[previous - 1];
                    if (leading == '_' || std::isalnum(static_cast<unsigned char>(leading)) || leading == ')' ||
                        leading == ']' || leading == '\'' || leading == '"')
                        continue;
                }

                const size_t close = line.find(')', open + 1);
                if (close == std::string::npos)
                    break;
                const std::string_view grouped = trimView(std::string_view(line).substr(open + 1, close - open - 1));
                if (!plainIdentifier(grouped))
                    continue;
                size_t next = close + 1;
                while (next < line.size() && std::isspace(static_cast<unsigned char>(line[next])))
                    ++next;
                if (next >= line.size() || line[next] != '[')
                    continue;

                line.replace(open, close - open + 1, grouped);
                ++removed;
                changed = true;
                break;
            }
        }
    }
    return removed;
}

std::optional<size_t> topLevelAssignmentEquals(std::string_view line);

size_t removeRedundantExpressionParentheses(std::vector<OutputLine>& lines)
{
    auto matchingClose = [](std::string_view text, size_t open) -> std::optional<size_t> {
        int depth = 0;
        char quote = 0;
        for (size_t index = open; index < text.size(); ++index)
        {
            const char ch = text[index];
            if (quote != 0)
            {
                if (ch == '\\')
                    ++index;
                else if (ch == quote)
                    quote = 0;
                continue;
            }
            if (ch == '\'' || ch == '"')
                quote = ch;
            else if (ch == '(')
                ++depth;
            else if (ch == ')' && --depth == 0)
                return index;
        }
        return std::nullopt;
    };

    size_t removed = 0;
    for (OutputLine& output : lines)
    {
        bool progress = true;
        while (progress)
        {
            progress = false;
            std::string& text = output.text;
            char quote = 0;
            for (size_t open = 0; open < text.size(); ++open)
            {
                const char ch = text[open];
                if (quote != 0)
                {
                    if (ch == '\\')
                        ++open;
                    else if (ch == quote)
                        quote = 0;
                    continue;
                }
                if (ch == '-' && open + 1 < text.size() && text[open + 1] == '-')
                    break;
                if (ch == '\'' || ch == '"')
                {
                    quote = ch;
                    continue;
                }
                if (ch != '(')
                    continue;
                size_t previous = open;
                while (previous > 0 && std::isspace(static_cast<unsigned char>(text[previous - 1])))
                    --previous;
                if (previous > 0)
                {
                    const char leading = text[previous - 1];
                    // Parentheses in a call argument or receiver position can force
                    // a single Luau result. Removing even one nested layer there can
                    // re-enable final-expression expansion.
                    if (leading == '_' || std::isalnum(static_cast<unsigned char>(leading)) ||
                        leading == ')' || leading == ']' || leading == '\'' || leading == '"')
                        continue;
                }
                size_t innerOpen = open + 1;
                while (innerOpen < text.size() && std::isspace(static_cast<unsigned char>(text[innerOpen])))
                    ++innerOpen;
                if (innerOpen >= text.size() || text[innerOpen] != '(')
                    continue;
                const auto outerClose = matchingClose(text, open);
                const auto innerClose = matchingClose(text, innerOpen);
                if (!outerClose || !innerClose || *innerClose >= *outerClose)
                    continue;
                bool onlySpace = true;
                for (size_t index = *innerClose + 1; index < *outerClose; ++index)
                    if (!std::isspace(static_cast<unsigned char>(text[index])))
                        onlySpace = false;
                if (!onlySpace)
                    continue;
                text.erase(*outerClose, 1);
                text.erase(open, 1);
                ++removed;
                progress = true;
                break;
            }
        }

        static const std::regex Atomic(
            R"(^[A-Za-z_][A-Za-z0-9_]*(?:(?:\.[A-Za-z_][A-Za-z0-9_]*)|(?:\[[0-9]+\]))*$)");
        progress = true;
        while (progress)
        {
            progress = false;
            std::string& text = output.text;
            char quote = 0;
            for (size_t open = 0; open < text.size(); ++open)
            {
                const char ch = text[open];
                if (quote != 0)
                {
                    if (ch == '\\')
                        ++open;
                    else if (ch == quote)
                        quote = 0;
                    continue;
                }
                if (ch == '-' && open + 1 < text.size() && text[open + 1] == '-')
                    break;
                if (ch == '\'' || ch == '"')
                {
                    quote = ch;
                    continue;
                }
                if (ch != '(')
                    continue;
                size_t previous = open;
                while (previous > 0 && std::isspace(static_cast<unsigned char>(text[previous - 1])))
                    --previous;
                if (previous > 0)
                {
                    const char leading = text[previous - 1];
                    if (leading == '_' || std::isalnum(static_cast<unsigned char>(leading)) ||
                        leading == ')' || leading == ']' || leading == '\'' || leading == '"')
                        continue;
                }
                const auto close = matchingClose(text, open);
                if (!close)
                    continue;
                const std::string atom = trim(
                    std::string_view(text).substr(open + 1, *close - open - 1));
                if (!std::regex_match(atom, Atomic))
                    continue;
                text.replace(open, *close - open + 1, atom);
                ++removed;
                progress = true;
                break;
            }
        }

        const size_t indent = indentation(output.text);
        const std::string_view statement = trimView(output.text);
        if (statement.starts_with("if ") && statement.ends_with(" then"))
        {
            const std::string_view expression = trimView(statement.substr(3, statement.size() - 3 - 5));
            const std::string_view stripped = stripOuterParentheses(expression);
            if (stripped.size() < expression.size())
            {
                output.text = std::string(indent, ' ') + "if " + std::string(stripped) + " then";
                ++removed;
            }
            continue;
        }
        const auto equals = topLevelAssignmentEquals(output.text);
        if (!equals)
            continue;
        std::string_view targets = trimView(std::string_view(output.text).substr(0, *equals));
        if (targets.starts_with("local "))
            targets = trimView(targets.substr(6));
        if (splitCaptureExpressions(targets).size() != 1)
            continue;
        const std::string_view expression = trimView(std::string_view(output.text).substr(*equals + 1));
        const std::string_view stripped = stripOuterParentheses(expression);
        if (stripped.size() == expression.size())
            continue;
        output.text = output.text.substr(0, *equals + 1) + " " + std::string(stripped);
        ++removed;
    }
    return removed;
}

size_t parenthesizeKeywordLiteralPrefixes(std::vector<OutputLine>& lines)
{
    size_t repaired = 0;
    for (OutputLine& output : lines)
    {
        std::string& text = output.text;
        char quote = 0;
        for (size_t index = 0; index < text.size();)
        {
            const char ch = text[index];
            if (quote != 0)
            {
                if (ch == '\\')
                    index += std::min<size_t>(2, text.size() - index);
                else
                {
                    if (ch == quote)
                        quote = 0;
                    ++index;
                }
                continue;
            }
            if (ch == '-' && index + 1 < text.size() && text[index + 1] == '-')
                break;
            if (ch == '\'' || ch == '"')
            {
                quote = ch;
                ++index;
                continue;
            }
            if (ch != '_' && !std::isalpha(static_cast<unsigned char>(ch)))
            {
                ++index;
                continue;
            }

            const size_t begin = index++;
            while (index < text.size() &&
                (text[index] == '_' || std::isalnum(static_cast<unsigned char>(text[index]))))
                ++index;
            const std::string_view keyword(text.data() + begin, index - begin);
            if (keyword != "nil" && keyword != "true" && keyword != "false")
                continue;

            size_t previous = begin;
            while (previous > 0 && std::isspace(static_cast<unsigned char>(text[previous - 1])))
                --previous;
            if (previous > 0 && (text[previous - 1] == '.' || text[previous - 1] == ':' ||
                                    text[previous - 1] == '_' || std::isalnum(static_cast<unsigned char>(text[previous - 1]))))
                continue;
            size_t suffix = index;
            while (suffix < text.size() && std::isspace(static_cast<unsigned char>(text[suffix])))
                ++suffix;
            if (suffix >= text.size() ||
                (text[suffix] != '.' && text[suffix] != '[' && text[suffix] != ':' && text[suffix] != '('))
                continue;

            text.insert(index, ")");
            text.insert(begin, "(");
            index += 2;
            ++repaired;
        }
    }
    return repaired;
}

bool containsCallSyntax(std::string_view line);

size_t addRequiredLeadingSemicolons(std::vector<OutputLine>& lines)
{
    size_t added = 0;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        OutputLine& line = lines[index];
        const size_t first = line.text.find_first_not_of(' ');
        if (first == std::string::npos || line.text[first] != '(')
            continue;
        size_t previous = index;
        while (previous > 0 && trimView(lines[previous - 1].text).empty())
            --previous;
        if (previous == 0 || indentation(lines[previous - 1].text) != indentation(line.text))
            continue;
        const std::string_view prior = trimView(lines[previous - 1].text);
        if (prior == "end" || prior == "else" || prior == "repeat" || prior == "break" || prior == "continue" ||
            prior.ends_with(" then") || prior.ends_with(" do") || prior.starts_with("local function ") ||
            prior.starts_with("return function(") || prior.find(" = function(") != std::string_view::npos)
            continue;
        line.text.insert(first, 1, ';');
        ++added;
    }
    return added;
}

size_t nameSemanticCapturedLocals(std::vector<OutputLine>& lines)
{
    static const std::regex CapturedWrite(
        R"(^\s*;?\s*(captured_value_[0-9]+)\s*(?:=|\+=|-=|\*=|/=|%=|\^=|\.\.=))");
    std::map<std::string, size_t> writes;
    std::map<std::string, std::vector<size_t>> definitions;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        std::smatch write;
        if (!std::regex_search(lines[index].text, write, CapturedWrite))
            continue;
        const std::string name = write[1].str();
        ++writes[name];
        if (auto assignment = simpleAssignment(lines[index].text); assignment && assignment->target == name)
            definitions[name].push_back(index);
    }

    auto resolveDefinition = [&](size_t before, std::string value) {
        const size_t indent = indentation(lines[before].text);
        for (size_t depth = 0; depth < 4 && generatedLocal(trimView(value)); ++depth)
        {
            const std::string target = trim(value);
            std::optional<std::string> resolved;
            const size_t lower = before > 80 ? before - 80 : 0;
            for (size_t index = before; index > lower; --index)
            {
                const size_t candidate = index - 1;
                if (indentation(lines[candidate].text) != indent)
                    continue;
                auto assignment = simpleAssignment(lines[candidate].text);
                if (assignment && assignment->target == target)
                {
                    resolved = assignment->value;
                    before = candidate;
                    break;
                }
            }
            if (!resolved)
                break;
            value = std::move(*resolved);
        }
        return value;
    };

    auto resolveCapturedSource = [&](size_t before, std::string value) {
        const size_t indent = indentation(lines[before].text);
        for (size_t depth = 0; depth < 4; ++depth)
        {
            value = trim(stripOuterParentheses(value));
            if (capturedLocal(value))
                return value;
            if (!generatedLocal(value))
                break;
            std::optional<std::string> resolved;
            const size_t lower = before > 80 ? before - 80 : 0;
            for (size_t index = before; index > lower; --index)
            {
                const size_t candidate = index - 1;
                if (indentation(lines[candidate].text) != indent)
                    continue;
                auto assignment = simpleAssignment(lines[candidate].text);
                if (assignment && assignment->target == value)
                {
                    resolved = assignment->value;
                    before = candidate;
                    break;
                }
            }
            if (!resolved)
                break;
            value = std::move(*resolved);
        }
        return std::string();
    };

    static const std::regex NamedField(
        R"regex(\["([A-Za-z_][A-Za-z0-9_]*)"\]\s*=\s*([A-Za-z_][A-Za-z0-9_]*))regex");
    static const std::set<std::string> Reserved{
        "and", "break", "continue", "do", "else", "elseif", "end", "export", "false", "for", "function",
        "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "type", "until", "while"};
    std::map<std::string, std::set<std::string>> usageBases;
    for (size_t line = 0; line < lines.size(); ++line)
    {
        std::string remaining = lines[line].text;
        std::smatch field;
        while (std::regex_search(remaining, field, NamedField))
        {
            const std::string captured = resolveCapturedSource(line, field[2].str());
            if (!captured.empty())
            {
                std::string role = snakeCase(field[1].str());
                if (role == "class")
                    role = "class_name";
                else if (Reserved.contains(role))
                    role += "_value";
                usageBases[captured].insert(std::move(role));
            }
            remaining = field.suffix().str();
        }
    }

    std::map<std::string, std::set<std::string>> shapeBases;
    for (const auto& [name, count] : writes)
    {
        (void)count;
        for (const OutputLine& output : lines)
        {
            if (!containsIdentifier(output.text, name))
                continue;
            const std::string& line = output.text;
            auto has = [&](std::string_view suffix) { return line.find(name + std::string(suffix)) != std::string::npos; };
            if (has(".selection") || has(".hrp"))
                shapeBases[name].insert("target");
            if (has(".CharacterAdded") || has(".CharacterRemoving") || has(".UserId"))
                shapeBases[name].insert("player");
            if (has(".UserInputType") || has(".UserInputState") || has(".KeyCode"))
                shapeBases[name].insert("input");
            if (has(".CanCollide") || has(".CanTouch") || has(".CanQuery") || has(".CustomPhysicalProperties"))
                shapeBases[name].insert("part");
            if (has(":Disconnect") || has(".Disconnect"))
                shapeBases[name].insert("connection");
            if ((has(":IsA(\"Beam\")") || has(":IsA(\"Trail\")")) && has(":IsA"))
                shapeBases[name].insert("effect");
            if (has(".AnimationPlayed") || has(".GetPlayingAnimationTracks"))
                shapeBases[name].insert("animator");
            if (line.find("readfile(") != std::string::npos)
                shapeBases[name].insert("file_path");
            if (line.find("pcall(" + name) != std::string::npos || line.find(name + "(") != std::string::npos)
                shapeBases[name].insert("callback");

            const size_t clamp = line.find("math.clamp(");
            if (clamp != std::string::npos)
            {
                const size_t begin = clamp + std::string_view("math.clamp(").size();
                const size_t end = line.rfind(')');
                if (end != std::string::npos && end > begin)
                {
                    const std::vector<std::string> arguments =
                        splitCaptureExpressions(std::string_view(line).substr(begin, end - begin));
                    if (arguments.size() >= 3)
                    {
                        if (trimView(arguments[1]) == name)
                            shapeBases[name].insert("min_value");
                        if (trimView(arguments[2]) == name)
                            shapeBases[name].insert("max_value");
                    }
                }
            }
            if (line.find(name + " .. \"f\"") != std::string::npos)
                shapeBases[name].insert("decimal_places");
        }
    }

    std::map<std::string, std::string> replacements;
    std::map<std::string, size_t> ordinals;
    std::set<std::string> occupied = collectIdentifiers(lines);
    for (const auto& [name, count] : writes)
    {
        auto definition = definitions.find(name);
        if (definition == definitions.end() || definition->second.empty())
            continue;
        std::set<std::string> semanticBases;
        for (size_t line : definition->second)
        {
            auto assignment = simpleAssignment(lines[line].text);
            if (!assignment)
                continue;
            const std::string_view raw = stripOuterParentheses(trimView(assignment->value));
            const bool placeholder = raw == "{}" || raw == "{nil}" || scalarLiteral(raw);
            if (count > 1 && placeholder)
                continue;
            const std::string expression = resolveDefinition(line, assignment->value);
            const std::string base = semanticLocalBase(expression, false);
            if (base != "value" && base != "result")
                semanticBases.insert(base);
        }
        std::string base;
        if (auto usage = usageBases.find(name); usage != usageBases.end() && usage->second.size() == 1)
            base = *usage->second.begin();
        else if (auto shape = shapeBases.find(name); shape != shapeBases.end() && shape->second.size() == 1)
            base = *shape->second.begin();
        else if (semanticBases.size() == 1)
            base = *semanticBases.begin();
        else
            continue;
        size_t& ordinal = ordinals[base];
        std::string candidate;
        do
        {
            ++ordinal;
            candidate = ordinal == 1 ? base : base + "_" + std::to_string(ordinal);
        } while (occupied.contains(candidate));
        occupied.insert(candidate);
        replacements[name] = std::move(candidate);
    }
    for (OutputLine& line : lines)
    {
        size_t constants = 0;
        size_t aliases = 0;
        line.text = replaceGeneratedLocals(line.text, replacements, constants, aliases);
    }
    return replacements.size();
}

std::optional<std::vector<std::string>> plainLocalDeclaration(std::string_view line)
{
    line = trimView(line);
    if (!line.starts_with("local ") || line.find('=') != std::string_view::npos)
        return std::nullopt;
    std::vector<std::string> names = splitCaptureExpressions(line.substr(6));
    if (names.empty() || std::any_of(names.begin(), names.end(), [](const std::string& name) {
            static const std::regex IdentifierPattern(R"(^[A-Za-z_][A-Za-z0-9_]*$)");
            return !std::regex_match(name, IdentifierPattern);
        }))
        return std::nullopt;
    return names;
}

size_t promoteSemanticLocals(std::vector<OutputLine>& lines)
{
    size_t promoted = 0;
    for (size_t declaration = 0; declaration < lines.size(); ++declaration)
    {
        auto names = plainLocalDeclaration(lines[declaration].text);
        if (!names)
            continue;
        const size_t indent = indentation(lines[declaration].text);
        size_t scopeEnd = lines.size();
        if (indent > 0)
            for (size_t candidate = declaration + 1; candidate < lines.size(); ++candidate)
                if (indentation(lines[candidate].text) == indent - 4 && trimView(lines[candidate].text) == "end")
                {
                    scopeEnd = candidate;
                    break;
                }

        std::set<std::string> promotedNames;
        std::optional<size_t> provenanceAnchor;
        for (const std::string& name : *names)
        {
            if (!bareReadableGlobal(name))
                continue;
            std::optional<size_t> assignmentLine;
            bool unsafe = false;
            for (size_t index = declaration + 1; index < scopeEnd; ++index)
            {
                if (!directlyWritesIdentifier(lines[index].text, name))
                    continue;
                auto assignment = simpleAssignment(lines[index].text);
                if (assignmentLine || !assignment || assignment->target != name ||
                    indentation(lines[index].text) != indent || containsIdentifier(assignment->value, name))
                {
                    unsafe = true;
                    break;
                }
                assignmentLine = index;
            }
            if (unsafe || !assignmentLine)
                continue;
            for (size_t index = declaration + 1; index < *assignmentLine; ++index)
                if (containsIdentifier(lines[index].text, name))
                {
                    unsafe = true;
                    break;
                }
            if (unsafe)
                continue;

            const size_t first = lines[*assignmentLine].text.find_first_not_of(' ');
            lines[*assignmentLine].text.insert(first, "local ");
            promotedNames.insert(name);
            provenanceAnchor = provenanceAnchor.value_or(*assignmentLine);
            ++promoted;
        }
        if (promotedNames.empty())
            continue;

        if (provenanceAnchor)
            lines[*provenanceAnchor].states.insert(lines[declaration].states.begin(), lines[declaration].states.end());
        std::vector<std::string> remaining;
        for (const std::string& name : *names)
            if (!promotedNames.contains(name))
                remaining.push_back(name);
        if (remaining.empty())
            lines[declaration].text.clear();
        else
        {
            std::string rewritten(indent, ' ');
            rewritten += "local ";
            for (size_t index = 0; index < remaining.size(); ++index)
            {
                if (index)
                    rewritten += ", ";
                rewritten += remaining[index];
            }
            lines[declaration].text = std::move(rewritten);
        }
    }
    return promoted;
}

std::map<std::string, size_t> closedFunctionReferenceEnds(const std::vector<OutputLine>& lines)
{
    std::map<std::string, size_t> earliestEnd;
    for (size_t opener = 0; opener < lines.size(); ++opener)
    {
        const std::string_view statement = trimView(lines[opener].text);
        const bool functionOpener = statement.starts_with("local function ") || statement.starts_with("return function(") ||
            statement.find(" = function(") != std::string_view::npos || statement.find(" = (function(") != std::string_view::npos;
        if (!functionOpener || functionExpressionClosesOnLine(statement))
            continue;
        const size_t indent = indentation(lines[opener].text);
        size_t functionEnd = opener + 1;
        while (functionEnd < lines.size())
        {
            const std::string_view ending = trimView(lines[functionEnd].text);
            if (indentation(lines[functionEnd].text) == indent && (ending == "end" || ending.starts_with("end)(")))
                break;
            ++functionEnd;
        }
        if (functionEnd >= lines.size())
            continue;
        for (size_t line = opener + 1; line < functionEnd; ++line)
            for (const std::string& name : generatedReads(lines[line].text))
            {
                auto [position, inserted] = earliestEnd.emplace(name, functionEnd);
                if (!inserted)
                    position->second = std::min(position->second, functionEnd);
            }
    }
    return earliestEnd;
}

size_t coalesceSemanticInitializers(std::vector<OutputLine>& lines)
{
    const std::map<std::string, size_t> closedReferences = closedFunctionReferenceEnds(lines);
    size_t coalesced = 0;
    for (size_t aliasLine = 0; aliasLine < lines.size(); ++aliasLine)
    {
        auto alias = simpleAssignment(lines[aliasLine].text);
        if (!alias || !trimView(lines[aliasLine].text).starts_with("local ") || !bareReadableGlobal(alias->target) ||
            !generatedLocal(trimView(alias->value)))
            continue;
        const std::string source = trim(alias->value);
        size_t definitionLine = aliasLine;
        while (definitionLine > 0 && trimView(lines[definitionLine - 1].text).empty())
            --definitionLine;
        if (definitionLine == 0)
            continue;
        --definitionLine;
        auto definition = simpleAssignment(lines[definitionLine].text);
        const auto closedReference = closedReferences.find(source);
        if (!definition || definition->target != source || indentation(lines[definitionLine].text) != indentation(lines[aliasLine].text) ||
            containsIdentifier(definition->value, source) ||
            (closedReference != closedReferences.end() && closedReference->second < definitionLine))
            continue;

        bool sourceUnused = true;
        for (size_t index = aliasLine + 1; index < lines.size(); ++index)
        {
            if (!containsIdentifier(lines[index].text, source))
                continue;
            auto overwrite = simpleAssignment(lines[index].text);
            sourceUnused = overwrite && overwrite->target == source &&
                indentation(lines[index].text) == indentation(lines[aliasLine].text) &&
                !containsIdentifier(overwrite->value, source);
            break;
        }
        if (!sourceUnused)
            continue;

        lines[definitionLine].text = std::string(indentation(lines[definitionLine].text), ' ') +
            "local " + alias->target + " = " + definition->value;
        lines[definitionLine].states.insert(lines[aliasLine].states.begin(), lines[aliasLine].states.end());
        if (!lines[definitionLine].origin && lines[aliasLine].origin)
            lines[definitionLine].origin = lines[aliasLine].origin;
        lines[aliasLine].text.clear();
        ++coalesced;
    }
    return coalesced;
}

bool plainIdentifier(std::string_view value)
{
    value = trimView(value);
    if (value.empty() || (value.front() != '_' && !std::isalpha(static_cast<unsigned char>(value.front()))))
        return false;
    return std::all_of(value.begin() + 1, value.end(), [](char ch) {
        return ch == '_' || std::isalnum(static_cast<unsigned char>(ch));
    });
}

bool containsCallSyntax(std::string_view line)
{
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
            return false;
        if (line[index] == '\'' || line[index] == '"')
        {
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            continue;
        }
        if (line[index] != '(')
        {
            ++index;
            continue;
        }
        size_t previous = index;
        while (previous > 0 && std::isspace(static_cast<unsigned char>(line[previous - 1])))
            --previous;
        if (previous > 0)
        {
            const char ch = line[previous - 1];
            if (ch == '_' || std::isalnum(static_cast<unsigned char>(ch)) || ch == ')' || ch == ']')
                return true;
        }
        ++index;
    }
    return false;
}

void mergeRemovedProvenance(std::vector<OutputLine>& lines, size_t removed)
{
    size_t anchor = removed + 1;
    while (anchor < lines.size() && trimView(lines[anchor].text).empty())
        ++anchor;
    if (anchor == lines.size())
    {
        anchor = removed;
        while (anchor > 0 && trimView(lines[anchor - 1].text).empty())
            --anchor;
        if (anchor > 0)
            --anchor;
    }
    if (anchor >= lines.size() || anchor == removed)
        return;
    lines[anchor].states.insert(lines[removed].states.begin(), lines[removed].states.end());
    if (!lines[anchor].origin && lines[removed].origin)
        lines[anchor].origin = lines[removed].origin;
}

struct RegisterTableScalarStats
{
    size_t tables = 0;
    size_t fullTables = 0;
    size_t partialTables = 0;
    size_t slots = 0;
    size_t accesses = 0;
    std::set<std::string> fullTableNames;
    std::set<std::string> partialTableNames;
};

struct ConstantSlotScan
{
    bool valid = true;
    size_t accesses = 0;
    std::set<int64_t> slots;
    std::map<int64_t, size_t> frequencies;
    std::string rewritten;
};

ConstantSlotScan scanConstantSlotAccesses(
    std::string_view line, std::string_view table, const std::map<int64_t, std::string>* replacements = nullptr)
{
    ConstantSlotScan result;
    std::string output;
    if (replacements)
        output.reserve(line.size());
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
        {
            if (replacements)
                output.append(line.substr(index));
            break;
        }
        if (line[index] == '\'' || line[index] == '"')
        {
            const size_t begin = index;
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            if (replacements)
                output.append(line.substr(begin, index - begin));
            continue;
        }
        if (line[index] != '_' && !std::isalpha(static_cast<unsigned char>(line[index])))
        {
            if (replacements)
                output.push_back(line[index]);
            ++index;
            continue;
        }

        const size_t begin = index++;
        while (index < line.size() && (line[index] == '_' || std::isalnum(static_cast<unsigned char>(line[index]))))
            ++index;
        if (line.substr(begin, index - begin) != table)
        {
            if (replacements)
                output.append(line.substr(begin, index - begin));
            continue;
        }

        size_t preceding = begin;
        while (preceding > 0 && std::isspace(static_cast<unsigned char>(line[preceding - 1])))
            --preceding;
        size_t cursor = index;
        while (cursor < line.size() && std::isspace(static_cast<unsigned char>(line[cursor])))
            ++cursor;
        bool wrapped = false;
        size_t wrapperBegin = begin;
        if (preceding > 0 && line[preceding - 1] == '(' && cursor < line.size() && line[cursor] == ')')
        {
            wrapped = true;
            wrapperBegin = preceding - 1;
            ++cursor;
            while (cursor < line.size() && std::isspace(static_cast<unsigned char>(line[cursor])))
                ++cursor;
        }
        else if (preceding > 0 && (line[preceding - 1] == '.' || line[preceding - 1] == ':'))
        {
            result.valid = false;
            return result;
        }
        if (cursor >= line.size() || line[cursor] != '[')
        {
            result.valid = false;
            return result;
        }
        const size_t expressionBegin = ++cursor;
        int parentheses = 0;
        while (cursor < line.size())
        {
            if (line[cursor] == '(')
                ++parentheses;
            else if (line[cursor] == ')')
                --parentheses;
            else if (line[cursor] == ']' && parentheses == 0)
                break;
            if (parentheses < 0)
                break;
            ++cursor;
        }
        if (cursor >= line.size() || line[cursor] != ']')
        {
            result.valid = false;
            return result;
        }
        const auto slot = parseConstantIntegerExpression(line.substr(expressionBegin, cursor - expressionBegin));
        if (!slot)
        {
            result.valid = false;
            return result;
        }
        ++cursor;
        result.slots.insert(*slot);
        ++result.frequencies[*slot];
        ++result.accesses;
        if (replacements)
        {
            const auto replacement = replacements->find(*slot);
            if (replacement == replacements->end())
            {
                output.append(line.substr(begin, cursor - begin));
                index = cursor;
                continue;
            }
            if (wrapped)
            {
                const size_t wrapperSize = begin - wrapperBegin;
                if (output.size() < wrapperSize)
                {
                    result.valid = false;
                    return result;
                }
                output.resize(output.size() - wrapperSize);
            }
            output += replacement->second;
        }
        index = cursor;
    }
    result.rewritten = replacements ? std::move(output) : std::string(line);
    return result;
}

std::optional<std::pair<int64_t, int64_t>> boundedRegisterClearRange(
    const std::vector<OutputLine>& lines, size_t clearLine)
{
    if (clearLine >= lines.size() || trimView(lines[clearLine].text) !=
            "for register_index = clear_range.from, clear_range.to do registers[register_index] = nil end")
        return std::nullopt;
    static const std::regex Alias(R"(^local clear_range = ([A-Za-z_][A-Za-z0-9_.]*)$)");
    static const std::regex Range(
        R"(^(?:local )?([A-Za-z_][A-Za-z0-9_.]*) = \{ from = (-?[0-9]+), to = (-?[0-9]+) \};?$)");
    std::optional<std::pair<std::string, size_t>> alias;
    for (size_t cursor = clearLine; cursor > 0 && clearLine - cursor < 12; --cursor)
    {
        const size_t candidate = cursor - 1;
        std::smatch match;
        const std::string statement(trimView(lines[candidate].text));
        if (std::regex_match(statement, match, Alias))
        {
            alias = std::pair<std::string, size_t>{match[1].str(), candidate};
            break;
        }
    }
    if (!alias)
        return std::nullopt;
    for (size_t cursor = alias->second; cursor > 0 && alias->second - cursor < 16; --cursor)
    {
        const size_t candidate = cursor - 1;
        std::smatch match;
        const std::string statement(trimView(lines[candidate].text));
        if (!std::regex_match(statement, match, Range) || match[1].str() != alias->first)
            continue;
        const auto first = parseInteger(match[2].str());
        const auto last = parseInteger(match[3].str());
        if (!first || !last || *first > *last || *last - *first > 4096)
            return std::nullopt;
        return std::pair<int64_t, int64_t>{*first, *last};
    }
    return std::nullopt;
}

std::optional<std::vector<ScalarFunctionSpan>> scalarFunctionSpans(const std::vector<OutputLine>& lines)
{
    std::vector<ScalarFunctionSpan> spans;
    for (size_t opener = 0; opener < lines.size(); ++opener)
    {
        const std::string_view statement = trimView(lines[opener].text);
        const bool functionOpener = statement.starts_with("local function ") || statement.starts_with("return function(") ||
            statement.find(" = function(") != std::string_view::npos || statement.find(" = (function(") != std::string_view::npos;
        if (!functionOpener || functionExpressionClosesOnLine(statement))
            continue;
        const size_t indent = indentation(lines[opener].text);
        size_t end = opener + 1;
        while (end < lines.size())
        {
            const std::string_view ending = trimView(lines[end].text);
            if (indentation(lines[end].text) == indent && (ending == "end" || ending.starts_with("end)(")))
                break;
            ++end;
        }
        if (end >= lines.size())
            return std::nullopt;
        spans.push_back({opener, end, indent});
    }
    return spans;
}

std::set<std::string> lexicalIdentifiers(std::string_view line)
{
    std::set<std::string> identifiers;
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
            break;
        if (line[index] == '\'' || line[index] == '"')
        {
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            continue;
        }
        if (line[index] == '_' || std::isalpha(static_cast<unsigned char>(line[index])))
        {
            const size_t begin = index++;
            while (index < line.size() && (line[index] == '_' || std::isalnum(static_cast<unsigned char>(line[index]))))
                ++index;
            identifiers.emplace(line.substr(begin, index - begin));
            continue;
        }
        ++index;
    }
    return identifiers;
}

LexicalCaptureIndex buildLexicalCaptureIndex(
    const std::vector<OutputLine>& lines, const std::vector<ScalarFunctionSpan>& spans)
{
    LexicalCaptureIndex result;
    result.topLevel = spans.size();
    result.owner.assign(lines.size(), result.topLevel);
    result.earliest.resize(spans.size() + 1);
    std::map<size_t, size_t> openerToSpan;
    for (size_t index = 0; index < spans.size(); ++index)
        openerToSpan[spans[index].opener] = index;
    std::vector<size_t> parent(spans.size(), result.topLevel);
    std::vector<size_t> stack;
    for (size_t line = 0; line < lines.size(); ++line)
    {
        while (!stack.empty() && spans[stack.back()].end <= line)
            stack.pop_back();
        result.owner[line] = stack.empty() ? result.topLevel : stack.back();
        if (auto opening = openerToSpan.find(line); opening != openerToSpan.end())
        {
            parent[opening->second] = result.owner[line];
            stack.push_back(opening->second);
        }
    }

    std::vector<std::set<std::string>> declarations(spans.size() + 1);
    std::vector<std::set<std::string>> freeNames(spans.size() + 1);
    for (size_t scope = 0; scope <= result.topLevel; ++scope)
    {
        const size_t begin = scope == result.topLevel ? 0 : spans[scope].opener + 1;
        const size_t end = scope == result.topLevel ? lines.size() : spans[scope].end;
        const size_t scopeIndent = scope == result.topLevel ? 0 : spans[scope].indent + 4;
        if (scope != result.topLevel)
        {
            const std::string_view opener = trimView(lines[spans[scope].opener].text);
            const size_t function = opener.find("function");
            const size_t open = function == std::string_view::npos ? std::string_view::npos : opener.find('(', function + 8);
            const size_t close = open == std::string_view::npos ? std::string_view::npos : opener.find(')', open + 1);
            if (close != std::string_view::npos)
                for (const std::string& parameter : splitCaptureExpressions(opener.substr(open + 1, close - open - 1)))
                    if (plainIdentifier(parameter))
                        declarations[scope].insert(parameter);
        }
        for (size_t line = begin; line < end; ++line)
        {
            if (result.owner[line] != scope)
                continue;
            const std::set<std::string> mentions = lexicalIdentifiers(lines[line].text);
            freeNames[scope].insert(mentions.begin(), mentions.end());
            if (indentation(lines[line].text) != scopeIndent)
                continue;
            if (auto names = plainLocalDeclaration(lines[line].text))
                declarations[scope].insert(names->begin(), names->end());
            const std::string_view statement = trimView(lines[line].text);
            if (statement.starts_with("local "))
                if (auto assignment = identifierAssignmentList(lines[line].text))
                    declarations[scope].insert(assignment->targets.begin(), assignment->targets.end());
            if (statement.starts_with("local function "))
            {
                std::string_view name = statement.substr(15);
                if (const size_t open = name.find('('); open != std::string_view::npos)
                    declarations[scope].insert(std::string(trimView(name.substr(0, open))));
            }
        }
    }

    for (size_t reversed = spans.size(); reversed > 0; --reversed)
    {
        const size_t scope = reversed - 1;
        for (const std::string& declaration : declarations[scope])
            freeNames[scope].erase(declaration);
        const size_t enclosing = parent[scope];
        for (const std::string& name : freeNames[scope])
        {
            if (declarations[enclosing].contains(name))
            {
                auto [position, inserted] = result.earliest[enclosing].emplace(name, spans[scope].opener);
                if (!inserted)
                    position->second = std::min(position->second, spans[scope].opener);
            }
            else
                freeNames[enclosing].insert(name);
        }
    }
    return result;
}

std::optional<int64_t> dominatingStateInteger(const std::vector<OutputLine>& lines, size_t useLine,
    size_t scopeBegin, size_t ownerScope, const LexicalCaptureIndex& captures, std::string_view property)
{
    const std::string reference = "state." + std::string(property);
    const std::regex assignment("^state\\." + std::string(property) + R"(\s*=\s*(-?[0-9]+)\s*;?$)");
    const size_t useIndent = indentation(lines[useLine].text);
    for (size_t cursor = useLine; cursor > scopeBegin; --cursor)
    {
        const size_t candidate = cursor - 1;
        if (captures.owner[candidate] != ownerScope)
            continue;
        const std::string_view statement = trimView(lines[candidate].text);
        const size_t candidateIndent = indentation(lines[candidate].text);
        if ((statement == "else" || statement.starts_with("elseif ") || statement == "end" ||
                statement.starts_with("until ")) &&
            candidateIndent <= useIndent)
            return std::nullopt;
        if (lines[candidate].text.find(reference) == std::string::npos)
            continue;
        if (candidateIndent > useIndent)
            return std::nullopt;
        std::smatch match;
        const std::string text(statement);
        if (!std::regex_match(text, match, assignment))
            return std::nullopt;
        return parseInteger(match[1].str());
    }
    return std::nullopt;
}

size_t specializeDominatedRegisterIndices(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    size_t rewrittenCount = 0;
    static const std::regex StateIndex(
        R"(^\(?\s*state\.([A-Za-z_][A-Za-z0-9_]*)\s*(?:([+-])\s*([0-9]+))?\s*\)?$)");
    for (size_t line = 0; line < lines.size(); ++line)
    {
        const size_t ownerScope = captures.owner[line];
        if (ownerScope == captures.topLevel)
            continue;
        const size_t scopeBegin = (*spans)[ownerScope].opener + 1;
        const std::string& source = lines[line].text;
        std::vector<std::tuple<size_t, size_t, std::string>> edits;
        for (size_t index = 0; index < source.size();)
        {
            if (source[index] == '-' && index + 1 < source.size() && source[index + 1] == '-')
                break;
            if (source[index] == '\'' || source[index] == '"')
            {
                const char quote = source[index++];
                while (index < source.size())
                {
                    if (source[index] == '\\')
                        index += std::min<size_t>(2, source.size() - index);
                    else if (source[index++] == quote)
                        break;
                }
                continue;
            }
            constexpr std::string_view Registers = "registers";
            if (source.compare(index, Registers.size(), Registers) != 0 ||
                (index > 0 && (source[index - 1] == '_' || std::isalnum(static_cast<unsigned char>(source[index - 1])))) ||
                (index + Registers.size() < source.size() &&
                    (source[index + Registers.size()] == '_' ||
                        std::isalnum(static_cast<unsigned char>(source[index + Registers.size()])))))
            {
                ++index;
                continue;
            }
            size_t open = index + Registers.size();
            while (open < source.size() && std::isspace(static_cast<unsigned char>(source[open])))
                ++open;
            if (open >= source.size() || source[open] != '[')
            {
                index += Registers.size();
                continue;
            }
            size_t close = open + 1;
            int parentheses = 0;
            for (; close < source.size(); ++close)
            {
                if (source[close] == '(')
                    ++parentheses;
                else if (source[close] == ')')
                    --parentheses;
                else if (source[close] == ']' && parentheses == 0)
                    break;
                if (parentheses < 0)
                    break;
            }
            if (close >= source.size() || source[close] != ']')
            {
                index += Registers.size();
                continue;
            }
            std::smatch match;
            const std::string expression(trimView(
                std::string_view(source).substr(open + 1, close - open - 1)));
            if (!std::regex_match(expression, match, StateIndex))
            {
                index = close + 1;
                continue;
            }
            const auto base = dominatingStateInteger(
                lines, line, scopeBegin, ownerScope, captures, match[1].str());
            if (!base)
            {
                index = close + 1;
                continue;
            }
            int64_t offset = 0;
            if (match[2].matched)
            {
                const auto magnitude = parseInteger(match[3].str());
                if (!magnitude)
                {
                    index = close + 1;
                    continue;
                }
                offset = match[2].str() == "-" ? -*magnitude : *magnitude;
            }
            const __int128 resolved = static_cast<__int128>(*base) + static_cast<__int128>(offset);
            if (resolved < std::numeric_limits<int64_t>::min() || resolved > std::numeric_limits<int64_t>::max())
            {
                index = close + 1;
                continue;
            }
            edits.emplace_back(open + 1, close, std::to_string(static_cast<int64_t>(resolved)));
            index = close + 1;
        }
        if (edits.empty())
            continue;
        std::string rewritten = source;
        for (auto edit = edits.rbegin(); edit != edits.rend(); ++edit)
        {
            const auto& [begin, end, replacement] = *edit;
            rewritten.replace(begin, end - begin, replacement);
        }
        lines[line].text = std::move(rewritten);
        rewrittenCount += edits.size();
    }
    return rewrittenCount;
}

size_t lowerImmediateRegisterAliases(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    static const std::regex AliasAssignment(R"(^state\.([A-Za-z_][A-Za-z0-9_]*) = registers;?$)");
    static const std::regex IntegerAssignment(R"(^state\.([A-Za-z_][A-Za-z0-9_]*) = (-?[0-9]+);?$)");
    size_t lowered = 0;
    for (size_t line = 0; line < lines.size(); ++line)
    {
        std::smatch aliasMatch;
        const std::string aliasStatement(trimView(lines[line].text));
        if (!std::regex_match(aliasStatement, aliasMatch, AliasAssignment))
            continue;
        const size_t ownerScope = captures.owner[line];
        if (ownerScope == captures.topLevel)
            continue;
        const std::string property = aliasMatch[1].str();
        const std::string reference = "state." + property;
        const size_t aliasIndent = indentation(lines[line].text);
        std::map<std::string, int64_t> stateIntegers;
        std::optional<size_t> useLine;
        std::optional<int64_t> useSlot;
        bool writeUse = false;
        std::string writeValue;
        for (size_t candidate = line + 1;
             candidate < (*spans)[ownerScope].end && candidate <= line + 16;
             ++candidate)
        {
            if (captures.owner[candidate] != ownerScope)
                break;
            const std::string_view statement = trimView(lines[candidate].text);
            if (statement.empty())
                continue;
            const size_t candidateIndent = indentation(lines[candidate].text);
            if (candidateIndent != aliasIndent || statement == "else" || statement.starts_with("elseif ") ||
                statement == "end" || statement == "do" || statement.starts_with("if ") ||
                statement.starts_with("for ") || statement.starts_with("while ") ||
                statement.starts_with("repeat") || statement.starts_with("until "))
                break;

            std::smatch integerMatch;
            const std::string text(statement);
            if (std::regex_match(text, integerMatch, IntegerAssignment))
            {
                const auto value = parseInteger(integerMatch[2].str());
                if (value)
                    stateIntegers[integerMatch[1].str()] = *value;
                continue;
            }

            const std::regex ReadAlias("^state\\." + property + " = state\\." + property +
                R"(\[state\.([A-Za-z_][A-Za-z0-9_]*)\];?$)");
            const std::regex WriteAlias("^state\\." + property +
                R"(\[state\.([A-Za-z_][A-Za-z0-9_]*)\] = (.+);?$)");
            std::smatch accessMatch;
            if (std::regex_match(text, accessMatch, ReadAlias))
            {
                if (const auto index = stateIntegers.find(accessMatch[1].str()); index != stateIntegers.end())
                {
                    useLine = candidate;
                    useSlot = index->second;
                }
                break;
            }
            if (std::regex_match(text, accessMatch, WriteAlias))
            {
                if (const auto index = stateIntegers.find(accessMatch[1].str()); index != stateIntegers.end())
                {
                    useLine = candidate;
                    useSlot = index->second;
                    writeUse = true;
                    writeValue = trim(accessMatch[2].str());
                    if (!writeValue.empty() && writeValue.back() == ';')
                        writeValue.pop_back();
                }
                break;
            }
            if (lines[candidate].text.find(reference) != std::string::npos)
                break;
        }
        if (!useLine || !useSlot)
            continue;

        if (writeUse)
        {
            bool aliasObservedAgain = false;
            for (size_t candidate = *useLine + 1; candidate < (*spans)[ownerScope].end; ++candidate)
            {
                if (captures.owner[candidate] != ownerScope)
                    continue;
                const std::string_view statement = trimView(lines[candidate].text);
                if (statement.starts_with(reference + " ="))
                    break;
                if (lines[candidate].text.find(reference) != std::string::npos ||
                    lines[candidate].text.find(", state,") != std::string::npos)
                {
                    aliasObservedAgain = true;
                    break;
                }
            }
            if (aliasObservedAgain)
                continue;
        }

        const std::string indent(aliasIndent, ' ');
        if (writeUse)
            lines[*useLine].text = indent + "registers[" + std::to_string(*useSlot) + "] = " + writeValue;
        else
            lines[*useLine].text = indent + "state." + property + " = registers[" + std::to_string(*useSlot) + "]";
        lines[*useLine].states.insert(lines[line].states.begin(), lines[line].states.end());
        if (!lines[*useLine].origin && lines[line].origin)
            lines[*useLine].origin = lines[line].origin;
        lines[line].text.clear();
        ++lowered;
    }
    return lowered;
}

size_t scalarTopLevelLocalCount(const std::vector<OutputLine>& lines, size_t scopeBegin, size_t scopeEnd,
    size_t indent, const std::optional<ScalarFunctionSpan>& owner)
{
    size_t count = 0;
    if (owner)
    {
        const std::string_view opener = trimView(lines[owner->opener].text);
        const size_t function = opener.find("function(");
        if (function != std::string_view::npos)
        {
            const size_t begin = function + std::string_view("function(").size();
            const size_t end = opener.find(')', begin);
            if (end != std::string_view::npos)
                for (const std::string& parameter : splitCaptureExpressions(opener.substr(begin, end - begin)))
                    if (plainIdentifier(parameter))
                        ++count;
        }
    }
    for (size_t index = scopeBegin; index < scopeEnd; ++index)
    {
        if (indentation(lines[index].text) != indent)
            continue;
        const std::string_view statement = trimView(lines[index].text);
        if (statement.starts_with("local function "))
        {
            ++count;
            continue;
        }
        if (auto names = generatedDeclaration(lines[index].text))
        {
            count += names->size();
            continue;
        }
        if (auto names = plainLocalDeclaration(lines[index].text))
        {
            count += names->size();
            continue;
        }
        if (statement.starts_with("local "))
            if (auto assignment = identifierAssignmentList(lines[index].text))
                count += assignment->targets.size();
    }
    return count;
}

struct ConstantSlotWrite
{
    std::string table;
    int64_t slot = 0;
    std::string value;
};

std::optional<ConstantSlotWrite> constantSlotWrite(std::string_view line)
{
    static const std::regex Assignment(
        R"(^\s*;?\s*\(?([A-Za-z_][A-Za-z0-9_]*)\)?\s*\[\s*(-?[0-9]+)\s*\]\s*=\s*(.+)$)");
    std::smatch match;
    const std::string text(line);
    if (!std::regex_match(text, match, Assignment))
        return std::nullopt;
    const auto slot = parseInteger(match[2].str());
    if (!slot)
        return std::nullopt;
    return ConstantSlotWrite{match[1].str(), *slot, trim(match[3].str())};
}

size_t recoverImmediateClosureCalls(std::vector<OutputLine>& lines)
{
    struct ClosureSlot
    {
        int64_t prototype = 0;
        size_t definition = 0;
    };

    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    std::map<size_t, std::map<int64_t, size_t>> lastWrites;
    std::map<size_t, std::map<int64_t, ClosureSlot>> closureSlots;
    static const std::regex ClosureAssignment(
        R"(^registers\[(-?[0-9]+)\] = function\(\.\.\.\);?$)");
    static const std::regex ClosureReturn(
        R"(^return recovered_routine_([0-9]+)\(callback_captures, \.\.\.\);?$)");
    for (size_t line = 0; line < lines.size(); ++line)
    {
        const size_t owner = captures.owner[line];
        if (owner == captures.topLevel)
            continue;
        if (const auto write = constantSlotWrite(lines[line].text); write && write->table == "registers")
            lastWrites[owner][write->slot] = line;

        std::smatch assignmentMatch;
        const std::string statement(trimView(lines[line].text));
        if (!std::regex_match(statement, assignmentMatch, ClosureAssignment))
            continue;
        const auto slot = parseInteger(assignmentMatch[1].str());
        if (!slot)
            continue;
        for (size_t next = line + 1; next < lines.size() && next <= line + 3; ++next)
        {
            std::smatch returnMatch;
            const std::string nextStatement(trimView(lines[next].text));
            if (!std::regex_match(nextStatement, returnMatch, ClosureReturn))
                continue;
            const auto prototype = parseInteger(returnMatch[1].str());
            if (prototype)
                closureSlots[owner][*slot] = ClosureSlot{*prototype, line};
            break;
        }
    }
    for (auto& [owner, slots] : closureSlots)
        for (auto slot = slots.begin(); slot != slots.end();)
            if (lastWrites[owner][slot->first] != slot->second.definition)
                slot = slots.erase(slot);
            else
                ++slot;

    size_t recovered = 0;
    static const std::regex RegisterValue(R"(^registers\[(-?[0-9]+)\]$)");
    static const std::regex RoutineValue(R"(^recovered_routine_([0-9]+)$)");
    for (size_t line = 0; line < lines.size(); ++line)
    {
        const size_t call = lines[line].text.find("call_recovered(");
        if (call == std::string::npos)
            continue;
        const size_t owner = captures.owner[line];
        if (owner == captures.topLevel)
            continue;
        const size_t open = call + std::string_view("call_recovered").size();
        size_t close = open + 1;
        int depth = 1;
        char quote = 0;
        for (; close < lines[line].text.size() && depth > 0; ++close)
        {
            const char ch = lines[line].text[close];
            if (quote != 0)
            {
                if (ch == '\\')
                    ++close;
                else if (ch == quote)
                    quote = 0;
                continue;
            }
            if (ch == '\'' || ch == '"')
                quote = ch;
            else if (ch == '(')
                ++depth;
            else if (ch == ')')
                --depth;
        }
        if (depth != 0 || close <= open + 1)
            continue;
        --close;
        std::vector<std::string> arguments = splitCaptureExpressions(
            std::string_view(lines[line].text).substr(open + 1, close - open - 1));
        if (arguments.size() < 3)
            continue;
        std::smatch callRegisterMatch;
        std::smatch fallbackMatch;
        const std::string callableArgument = trim(arguments[0]);
        const std::string fallbackArgument = trim(arguments[1]);
        if (!std::regex_match(callableArgument, callRegisterMatch, RegisterValue) ||
            !std::regex_match(fallbackArgument, fallbackMatch, RoutineValue))
            continue;
        const auto callSlot = parseInteger(callRegisterMatch[1].str());
        const auto fallback = parseInteger(fallbackMatch[1].str());
        if (!callSlot || !fallback)
            continue;

        bool proven = false;
        for (size_t previous = line; previous > 0 && line - previous < 9; --previous)
        {
            const size_t candidate = previous - 1;
            if (captures.owner[candidate] != owner)
                break;
            const std::string_view statement = trimView(lines[candidate].text);
            if (controlBoundary(statement) || statement == "else" || statement.starts_with("elseif "))
                break;
            const auto write = constantSlotWrite(lines[candidate].text);
            if (!write || write->table != "registers" || write->slot != *callSlot)
                continue;
            std::smatch sourceMatch;
            std::string value = trim(write->value);
            if (!value.empty() && value.back() == ';')
                value.pop_back();
            if (std::regex_match(value, sourceMatch, RegisterValue))
            {
                const auto sourceSlot = parseInteger(sourceMatch[1].str());
                if (sourceSlot)
                    if (const auto known = closureSlots[owner].find(*sourceSlot);
                        known != closureSlots[owner].end() && known->second.prototype == *fallback &&
                        known->second.definition < candidate)
                        proven = true;
            }
            break;
        }
        if (!proven)
            continue;

        std::string direct = trim(arguments[0]) + "(";
        for (size_t argument = 3; argument < arguments.size(); ++argument)
        {
            if (argument > 3)
                direct += ", ";
            direct += arguments[argument];
        }
        direct += ")";
        lines[line].text.replace(call, close - call + 1, direct);
        ++recovered;
    }
    return recovered;
}

size_t simplifyIgnoredCallScopes(std::vector<OutputLine>& lines)
{
    static const std::regex IgnoredCall(R"(^(\s*)do local _ = (.+) end;?$)");
    size_t simplified = 0;
    for (OutputLine& line : lines)
    {
        std::smatch match;
        if (!std::regex_match(line.text, match, IgnoredCall))
            continue;
        const std::string expression = trim(match[2].str());
        const bool identifierCallee = !expression.empty() &&
            ((expression.front() >= 'A' && expression.front() <= 'Z') ||
                (expression.front() >= 'a' && expression.front() <= 'z') || expression.front() == '_');
        if (!identifierCallee || expression.back() != ')' || !containsCallSyntax(expression))
            continue;
        line.text = match[1].str() + expression;
        ++simplified;
    }
    return simplified;
}

size_t inlineReplayTargetConditions(std::vector<OutputLine>& lines)
{
    static const std::regex Assignment(
        R"(^(\s*)local (replay_target_[0-9]+) = (replay_(?:activation_)?transition\(.*\))$)");
    size_t inlined = 0;
    for (size_t line = 0; line + 1 < lines.size(); ++line)
    {
        std::smatch assignment;
        if (!std::regex_match(lines[line].text, assignment, Assignment))
            continue;
        const std::string expected = assignment[1].str() + "if " + assignment[2].str() + " == ";
        if (!lines[line + 1].text.starts_with(expected) || !trimView(lines[line + 1].text).ends_with(" then"))
            continue;
        lines[line + 1].text.replace(assignment[1].length() + 3, assignment[2].length(), assignment[3].str());
        lines[line + 1].states.insert(lines[line].states.begin(), lines[line].states.end());
        if (!lines[line + 1].origin && lines[line].origin)
            lines[line + 1].origin = lines[line].origin;
        lines[line].text.clear();
        ++inlined;
    }
    return inlined;
}

size_t removeClearedReplayMetadataPatches(std::vector<OutputLine>& lines, int64_t minimumSlot)
{
    static const std::regex MetadataAlias(
        R"(^registers\[(-?[0-9]+)\] = (?:operand_values|opcode_values);?$)");
    static const std::regex MetadataWrite(
        R"(^registers\[(-?[0-9]+)\]\[-?[0-9]+\] = (-?[0-9]+|true|false|nil|registers\[(-?[0-9]+)\]);?$)");
    static const std::regex ScratchWrite(
        R"(^registers\[(-?[0-9]+)\] = (?:-?[0-9]+|true|false|nil);?$)");
    static const std::regex ClearLoop(R"(^for loop_index = (-?[0-9]+), (-?[0-9]+), 1 do$)");
    static const std::regex ClearWrite(R"(^registers\[loop_index\] = nil;?$)");
    static const std::regex ClearRange(
        R"(^state\.register_clear_range_3 = \{ from = (-?[0-9]+), to = (-?[0-9]+) \};?$)");
    static const std::regex ClearRangeLoop(
        R"(^for register_index = clear_range\.from, clear_range\.to do registers\[register_index\] = nil end$)");

    std::vector<bool> remove(lines.size(), false);
    size_t removed = 0;
    for (size_t opener = 0; opener < lines.size(); ++opener)
    {
        const std::string_view header = trimView(lines[opener].text);
        if (!header.starts_with("if replay_activation_transition(") || !header.ends_with(" then"))
            continue;
        const size_t indent = indentation(lines[opener].text);
        size_t closing = opener + 1;
        while (closing < lines.size() &&
            !(indentation(lines[closing].text) == indent && trimView(lines[closing].text) == "end"))
            ++closing;
        if (closing == lines.size())
            continue;

        bool valid = true;
        bool metadataWrite = false;
        std::set<int64_t> aliases;
        std::set<int64_t> scratchSlots;
        std::vector<std::pair<int64_t, int64_t>> clearRanges;
        for (size_t line = opener + 1; line < closing && valid; ++line)
        {
            const std::string statement(trimView(lines[line].text));
            if (statement.empty())
                continue;
            std::smatch match;
            if (std::regex_match(statement, match, MetadataAlias))
            {
                const auto slot = parseInteger(match[1].str());
                if (!slot || *slot < minimumSlot)
                    valid = false;
                else
                    aliases.insert(*slot);
                continue;
            }
            if (std::regex_match(statement, match, MetadataWrite))
            {
                const auto slot = parseInteger(match[1].str());
                if (!slot || !aliases.contains(*slot))
                    valid = false;
                else
                {
                    metadataWrite = true;
                    if (match[3].matched)
                    {
                        const auto source = parseInteger(match[3].str());
                        if (!source)
                            valid = false;
                        else
                            scratchSlots.insert(*source);
                    }
                }
                continue;
            }
            if (std::regex_match(statement, match, ScratchWrite))
            {
                const auto slot = parseInteger(match[1].str());
                if (!slot || *slot < minimumSlot)
                    valid = false;
                else
                    scratchSlots.insert(*slot);
                continue;
            }
            if (std::regex_match(statement, match, ClearLoop) && line + 2 < closing &&
                std::regex_match(std::string(trimView(lines[line + 1].text)), ClearWrite) &&
                trimView(lines[line + 2].text) == "end")
            {
                const auto from = parseInteger(match[1].str());
                const auto to = parseInteger(match[2].str());
                if (!from || !to || *from < minimumSlot || *to < *from)
                    valid = false;
                else
                    clearRanges.emplace_back(*from, *to);
                line += 2;
                continue;
            }
            if (std::regex_match(statement, match, ClearRange) && line + 6 < closing &&
                trimView(lines[line + 1].text) == "do" &&
                trimView(lines[line + 2].text) == "local clear_range = state.register_clear_range_3" &&
                trimView(lines[line + 3].text) == "if clear_range then" &&
                std::regex_match(std::string(trimView(lines[line + 4].text)), ClearRangeLoop) &&
                trimView(lines[line + 5].text) == "end" && trimView(lines[line + 6].text) == "end")
            {
                const auto from = parseInteger(match[1].str());
                const auto to = parseInteger(match[2].str());
                if (!from || !to || *from < minimumSlot || *to < *from)
                    valid = false;
                else
                    clearRanges.emplace_back(*from, *to);
                line += 6;
                continue;
            }
            valid = false;
        }
        if (!valid || !metadataWrite || aliases.empty() || clearRanges.empty())
            continue;
        for (int64_t alias : aliases)
            if (std::none_of(clearRanges.begin(), clearRanges.end(), [&](const auto& range) {
                    return range.first <= alias && alias <= range.second;
                }))
                valid = false;
        for (int64_t scratch : scratchSlots)
            if (std::none_of(clearRanges.begin(), clearRanges.end(), [&](const auto& range) {
                    return range.first <= scratch && scratch <= range.second;
                }))
                valid = false;
        if (!valid)
            continue;

        for (size_t line = opener; line <= closing; ++line)
            remove[line] = true;
        ++removed;
        opener = closing;
    }
    if (removed == 0)
        return 0;
    for (size_t line = 0; line < lines.size(); ++line)
        if (remove[line])
            mergeRemovedProvenance(lines, line);
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size());
    for (size_t line = 0; line < lines.size(); ++line)
        if (!remove[line])
            compacted.push_back(std::move(lines[line]));
    lines = std::move(compacted);
    return removed;
}

size_t collapseEquivalentReplayBranches(std::vector<OutputLine>& lines)
{
    static const std::regex MetadataAlias(
        R"(^registers\[(-?[0-9]+)\] = (?:operand_values|opcode_values);?$)");
    static const std::regex MetadataWrite(
        R"(^registers\[(-?[0-9]+)\]\[-?[0-9]+\] = (-?[0-9]+|true|false|nil|registers\[(-?[0-9]+)\]);?$)");
    static const std::regex ScratchWrite(
        R"(^registers\[(-?[0-9]+)\] = (?:-?[0-9]+|true|false|nil);?$)");
    static const std::regex ScratchGuard(
        R"(^if (?:not |[() ])*registers\[(-?[0-9]+)\](?:[() ])* then$)");
    static const std::regex ClearLoop(R"(^for loop_index = (-?[0-9]+), (-?[0-9]+), 1 do$)");
    static const std::regex ClearWrite(R"(^registers\[loop_index\] = nil;?$)");
    static const std::regex ClearRange(
        R"(^state\.register_clear_range_3 = \{ from = (-?[0-9]+), to = (-?[0-9]+) \};?$)");
    static const std::regex ClearRangeLoop(
        R"(^for register_index = clear_range\.from, clear_range\.to do registers\[register_index\] = nil end$)");

    auto metadataEnvelope = [&](size_t begin, size_t payloadBegin, size_t payloadEnd, size_t end) {
        bool metadataWrite = false;
        size_t guardDepth = 0;
        std::set<int64_t> aliases;
        std::set<int64_t> scratchSlots;
        std::map<int64_t, size_t> lastWrite;
        std::map<int64_t, size_t> lastClear;

        auto recordClear = [&](int64_t from, int64_t to, size_t line) {
            for (int64_t slot : aliases)
                if (from <= slot && slot <= to)
                    lastClear[slot] = line;
            for (int64_t slot : scratchSlots)
                if (from <= slot && slot <= to)
                    lastClear[slot] = line;
        };

        for (size_t line = begin; line < payloadBegin; ++line)
        {
            const std::string statement(trimView(lines[line].text));
            if (statement.empty())
                continue;
            std::smatch match;
            if (std::regex_match(statement, match, MetadataAlias))
            {
                const auto slot = parseInteger(match[1].str());
                if (!slot || *slot < 3)
                    return false;
                aliases.insert(*slot);
                lastWrite[*slot] = line;
                continue;
            }
            if (std::regex_match(statement, match, MetadataWrite))
            {
                const auto slot = parseInteger(match[1].str());
                if (!slot || !aliases.contains(*slot))
                    return false;
                metadataWrite = true;
                lastWrite[*slot] = line;
                if (match[3].matched)
                {
                    const auto source = parseInteger(match[3].str());
                    if (!source || *source < 3)
                        return false;
                    scratchSlots.insert(*source);
                }
                continue;
            }
            if (std::regex_match(statement, match, ScratchWrite))
            {
                const auto slot = parseInteger(match[1].str());
                if (!slot || *slot < 3 || aliases.contains(*slot))
                    return false;
                scratchSlots.insert(*slot);
                lastWrite[*slot] = line;
                continue;
            }
            if (std::regex_match(statement, match, ScratchGuard))
            {
                const auto slot = parseInteger(match[1].str());
                if (!slot || !scratchSlots.contains(*slot))
                    return false;
                ++guardDepth;
                continue;
            }
            if (statement == "end")
            {
                if (guardDepth == 0)
                    return false;
                --guardDepth;
                continue;
            }
            if (std::regex_match(statement, match, ClearLoop) && line + 2 < payloadBegin &&
                std::regex_match(std::string(trimView(lines[line + 1].text)), ClearWrite) &&
                trimView(lines[line + 2].text) == "end")
            {
                const auto from = parseInteger(match[1].str());
                const auto to = parseInteger(match[2].str());
                if (!from || !to || *from < 3 || *to < *from)
                    return false;
                recordClear(*from, *to, line + 2);
                line += 2;
                continue;
            }
            if (std::regex_match(statement, match, ClearRange) && line + 6 < payloadBegin &&
                trimView(lines[line + 1].text) == "do" &&
                trimView(lines[line + 2].text) == "local clear_range = state.register_clear_range_3" &&
                trimView(lines[line + 3].text) == "if clear_range then" &&
                std::regex_match(std::string(trimView(lines[line + 4].text)), ClearRangeLoop) &&
                trimView(lines[line + 5].text) == "end" && trimView(lines[line + 6].text) == "end")
            {
                const auto from = parseInteger(match[1].str());
                const auto to = parseInteger(match[2].str());
                if (!from || !to || *from < 3 || *to < *from)
                    return false;
                recordClear(*from, *to, line + 6);
                line += 6;
                continue;
            }
            return false;
        }

        size_t closingGuards = 0;
        for (size_t line = payloadEnd; line < end; ++line)
        {
            const std::string_view statement = trimView(lines[line].text);
            if (statement.empty())
                continue;
            if (statement != "end")
                return false;
            ++closingGuards;
        }
        if (!metadataWrite || aliases.empty() || guardDepth != closingGuards)
            return false;
        for (const auto& [slot, write] : lastWrite)
        {
            const auto clear = lastClear.find(slot);
            if (clear == lastClear.end() || clear->second <= write)
                return false;
        }
        return true;
    };

    size_t collapsed = 0;
    for (;;)
    {
        bool changed = false;
        for (size_t opener = 0; opener < lines.size() && !changed; ++opener)
        {
            const std::string_view header = trimView(lines[opener].text);
            if (!header.starts_with("if replay_activation_transition(") || !header.ends_with(" then"))
                continue;
            const size_t indent = indentation(lines[opener].text);
            size_t alternate = lines.size();
            size_t closing = lines.size();
            for (size_t line = opener + 1; line < lines.size(); ++line)
                if (indentation(lines[line].text) == indent)
                {
                    const std::string_view statement = trimView(lines[line].text);
                    if (statement == "else" && alternate == lines.size())
                        alternate = line;
                    else if (statement == "end")
                    {
                        closing = line;
                        break;
                    }
                }
            if (alternate == lines.size() || closing == lines.size())
                continue;

            std::vector<size_t> thenLines;
            std::vector<size_t> elseLines;
            for (size_t line = opener + 1; line < alternate; ++line)
                if (!trimView(lines[line].text).empty())
                    thenLines.push_back(line);
            for (size_t line = alternate + 1; line < closing; ++line)
                if (!trimView(lines[line].text).empty())
                    elseLines.push_back(line);
            if (elseLines.empty() || thenLines.size() < elseLines.size())
                continue;

            size_t matchOffset = thenLines.size();
            for (size_t offset = 0; offset + elseLines.size() <= thenLines.size(); ++offset)
            {
                bool equal = true;
                for (size_t index = 0; index < elseLines.size(); ++index)
                    if (trimView(lines[thenLines[offset + index]].text) != trimView(lines[elseLines[index]].text))
                    {
                        equal = false;
                        break;
                    }
                if (equal && metadataEnvelope(opener + 1, thenLines[offset], thenLines[offset + elseLines.size() - 1] + 1,
                                 alternate))
                {
                    matchOffset = offset;
                    break;
                }
            }
            if (matchOffset == thenLines.size())
                continue;

            std::vector<OutputLine> replacement;
            replacement.reserve(closing - alternate - 1);
            for (size_t line = alternate + 1; line < closing; ++line)
            {
                OutputLine kept = lines[line];
                if (!kept.text.empty() && kept.text.size() >= 4)
                    kept.text.erase(0, 4);
                replacement.push_back(std::move(kept));
            }
            auto retained = std::find_if(replacement.begin(), replacement.end(), [](const OutputLine& line) {
                return !trimView(line.text).empty();
            });
            if (retained == replacement.end())
                continue;
            for (size_t line = opener; line <= closing; ++line)
            {
                retained->states.insert(lines[line].states.begin(), lines[line].states.end());
                if (!retained->origin && lines[line].origin)
                    retained->origin = lines[line].origin;
            }

            std::vector<OutputLine> rewritten;
            rewritten.reserve(lines.size() - (closing - opener + 1) + replacement.size());
            rewritten.insert(rewritten.end(), std::make_move_iterator(lines.begin()),
                std::make_move_iterator(lines.begin() + static_cast<std::ptrdiff_t>(opener)));
            rewritten.insert(rewritten.end(), std::make_move_iterator(replacement.begin()),
                std::make_move_iterator(replacement.end()));
            rewritten.insert(rewritten.end(), std::make_move_iterator(lines.begin() + static_cast<std::ptrdiff_t>(closing + 1)),
                std::make_move_iterator(lines.end()));
            lines = std::move(rewritten);
            ++collapsed;
            changed = true;
        }
        if (!changed)
            break;
    }
    return collapsed;
}

size_t removeLinearReplayMetadataPatches(std::vector<OutputLine>& lines, int64_t minimumSlot)
{
    static const std::regex MetadataAlias(
        R"(^registers\[(-?[0-9]+)\] = (?:operand_values|opcode_values);?$)");
    static const std::regex MetadataWrite(
        R"(^registers\[(-?[0-9]+)\]\[-?[0-9]+\] = (-?[0-9]+|true|false|nil|registers\[(-?[0-9]+)\]);?$)");
    static const std::regex ScratchWrite(
        R"(^registers\[(-?[0-9]+)\] = (?:-?[0-9]+|true|false|nil);?$)");
    static const std::regex ClearLoop(R"(^for loop_index = (-?[0-9]+), (-?[0-9]+), 1 do$)");
    static const std::regex ClearWrite(R"(^registers\[loop_index\] = nil;?$)");
    static const std::regex ClearRange(
        R"(^state\.register_clear_range_3 = \{ from = (-?[0-9]+), to = (-?[0-9]+) \};?$)");
    static const std::regex ClearRangeLoop(
        R"(^for register_index = clear_range\.from, clear_range\.to do registers\[register_index\] = nil end$)");

    std::vector<bool> remove(lines.size(), false);
    size_t removed = 0;
    for (size_t start = 0; start < lines.size(); ++start)
    {
        std::smatch first;
        const std::string initial(trimView(lines[start].text));
        if (!std::regex_match(initial, first, MetadataAlias))
            continue;
        const auto firstSlot = parseInteger(first[1].str());
        if (!firstSlot || *firstSlot < minimumSlot)
            continue;

        std::set<int64_t> aliases;
        std::set<int64_t> scratchSlots;
        std::map<int64_t, size_t> lastWrite;
        std::map<int64_t, size_t> lastClear;
        bool metadataWrite = false;
        std::optional<size_t> candidateEnd;
        auto recordClear = [&](int64_t from, int64_t to, size_t line) {
            for (int64_t slot : aliases)
                if (from <= slot && slot <= to)
                    lastClear[slot] = line;
            for (int64_t slot : scratchSlots)
                if (from <= slot && slot <= to)
                    lastClear[slot] = line;
        };
        auto fullyCleared = [&]() {
            if (!metadataWrite || aliases.empty())
                return false;
            for (const auto& [slot, write] : lastWrite)
            {
                const auto clear = lastClear.find(slot);
                if (clear == lastClear.end() || clear->second <= write)
                    return false;
            }
            return true;
        };

        for (size_t line = start; line < lines.size(); ++line)
        {
            const std::string statement(trimView(lines[line].text));
            if (statement.empty())
                continue;
            std::smatch match;
            if (std::regex_match(statement, match, MetadataAlias))
            {
                const auto slot = parseInteger(match[1].str());
                if (!slot || *slot < minimumSlot)
                    break;
                aliases.insert(*slot);
                lastWrite[*slot] = line;
                continue;
            }
            if (std::regex_match(statement, match, MetadataWrite))
            {
                const auto slot = parseInteger(match[1].str());
                if (!slot || !aliases.contains(*slot))
                    break;
                if (match[3].matched)
                {
                    const auto source = parseInteger(match[3].str());
                    if (!source || !scratchSlots.contains(*source))
                        break;
                }
                metadataWrite = true;
                lastWrite[*slot] = line;
                continue;
            }
            if (std::regex_match(statement, match, ScratchWrite))
            {
                const auto slot = parseInteger(match[1].str());
                if (!slot || *slot < minimumSlot || aliases.contains(*slot))
                    break;
                scratchSlots.insert(*slot);
                lastWrite[*slot] = line;
                continue;
            }
            if (std::regex_match(statement, match, ClearLoop) && line + 2 < lines.size() &&
                std::regex_match(std::string(trimView(lines[line + 1].text)), ClearWrite) &&
                trimView(lines[line + 2].text) == "end")
            {
                const auto from = parseInteger(match[1].str());
                const auto to = parseInteger(match[2].str());
                if (!from || !to || *from < minimumSlot || *to < *from)
                    break;
                recordClear(*from, *to, line + 2);
                line += 2;
                if (fullyCleared())
                    candidateEnd = line;
                break;
            }
            if (std::regex_match(statement, match, ClearRange) && line + 6 < lines.size() &&
                trimView(lines[line + 1].text) == "do" &&
                trimView(lines[line + 2].text) == "local clear_range = state.register_clear_range_3" &&
                trimView(lines[line + 3].text) == "if clear_range then" &&
                std::regex_match(std::string(trimView(lines[line + 4].text)), ClearRangeLoop) &&
                trimView(lines[line + 5].text) == "end" && trimView(lines[line + 6].text) == "end")
            {
                const auto from = parseInteger(match[1].str());
                const auto to = parseInteger(match[2].str());
                if (!from || !to || *from < minimumSlot || *to < *from)
                    break;
                recordClear(*from, *to, line + 6);
                line += 6;
                if (fullyCleared())
                    candidateEnd = line;
                break;
            }
            break;
        }
        if (!candidateEnd)
            continue;
        for (size_t line = start; line <= *candidateEnd; ++line)
            remove[line] = true;
        ++removed;
        start = *candidateEnd;
    }
    if (removed == 0)
        return 0;
    for (size_t line = 0; line < lines.size(); ++line)
        if (remove[line])
            mergeRemovedProvenance(lines, line);
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size());
    for (size_t line = 0; line < lines.size(); ++line)
        if (!remove[line])
            compacted.push_back(std::move(lines[line]));
    lines = std::move(compacted);
    return removed;
}

size_t removeDiscardedAnonymousFunctionStatements(std::vector<OutputLine>& lines)
{
    std::vector<bool> remove(lines.size(), false);
    size_t removed = 0;
    for (size_t opener = 0; opener < lines.size(); ++opener)
    {
        const std::string_view statement = trimView(lines[opener].text);
        if (!statement.starts_with("function("))
            continue;
        const size_t indent = indentation(lines[opener].text);
        size_t functionEnd = opener + 1;
        while (functionEnd < lines.size() &&
            !(indentation(lines[functionEnd].text) == indent && trimView(lines[functionEnd].text) == "end"))
            ++functionEnd;
        if (functionEnd >= lines.size())
            continue;

        size_t begin = opener;
        size_t end = functionEnd;
        if (indent >= 2 && functionEnd + 1 < lines.size() &&
            indentation(lines[functionEnd + 1].text) == indent - 2 &&
            trimView(lines[functionEnd + 1].text) == "end")
        {
            size_t blockOpen = opener;
            while (blockOpen > 0)
            {
                --blockOpen;
                if (trimView(lines[blockOpen].text).empty())
                    continue;
                if (indentation(lines[blockOpen].text) <= indent - 2)
                    break;
            }
            bool capturePrelude = blockOpen < opener && indentation(lines[blockOpen].text) == indent - 2 &&
                trimView(lines[blockOpen].text) == "do";
            bool sawCaptureTable = false;
            for (size_t line = blockOpen + 1; capturePrelude && line < opener; ++line)
            {
                const std::string_view prelude = trimView(lines[line].text);
                if (prelude.empty())
                    continue;
                if (!sawCaptureTable)
                {
                    sawCaptureTable = prelude == "local callback_captures = {";
                    capturePrelude = sawCaptureTable;
                }
                else if (prelude != "}" && !(prelude.starts_with('[') && prelude.ends_with(',')))
                    capturePrelude = false;
            }
            if (capturePrelude && sawCaptureTable)
            {
                begin = blockOpen;
                end = functionEnd + 1;
            }
        }

        for (size_t line = begin; line <= end; ++line)
            remove[line] = true;
        ++removed;
        opener = end;
    }
    if (removed == 0)
        return 0;
    for (size_t line = 0; line < lines.size(); ++line)
        if (remove[line])
            mergeRemovedProvenance(lines, line);
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size());
    for (size_t line = 0; line < lines.size(); ++line)
        if (!remove[line])
            compacted.push_back(std::move(lines[line]));
    lines = std::move(compacted);
    return removed;
}

size_t removeTraceInstrumentation(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;

    std::vector<bool> remove(lines.size(), false);
    static const std::regex StepCall(R"(^semantic_step\(-?[0-9]+, -?[0-9]+\);?$)");
    static const std::regex RuntimeLaneObservation(
        R"(^local (runtime_lanes_[0-9]+) = replay_runtime_lanes\(.*\)$)");
    std::map<std::string, std::vector<size_t>> laneDeclarations;
    size_t removed = 0;
    for (size_t line = 0; line < lines.size(); ++line)
    {
        const std::string_view statement = trimView(lines[line].text);
        if (statement == "local semantic_step_count = 0" || statement == "local semantic_site_counts = {}" ||
            std::regex_match(std::string(statement), StepCall))
            remove[line] = true;
        std::smatch laneMatch;
        const std::string text(statement);
        if (std::regex_match(text, laneMatch, RuntimeLaneObservation))
            laneDeclarations[laneMatch[1].str()].push_back(line);
    }
    for (const auto& [name, declarations] : laneDeclarations)
    {
        bool read = false;
        for (size_t line = 0; line < lines.size() && !read; ++line)
        {
            if (!containsIdentifier(lines[line].text, name))
                continue;
            if (std::find(declarations.begin(), declarations.end(), line) == declarations.end())
                read = true;
        }
        if (!read)
            for (size_t declaration : declarations)
                remove[declaration] = true;
    }

    bool retainedLaneObservation = false;
    for (size_t line = 0; line < lines.size(); ++line)
        if (!remove[line] && trimView(lines[line].text).find("replay_runtime_lanes(") != std::string_view::npos &&
            !trimView(lines[line].text).starts_with("local function replay_runtime_lanes("))
            retainedLaneObservation = true;
    for (const ScalarFunctionSpan& span : *spans)
        if (trimView(lines[span.opener].text).starts_with("local function semantic_step(") ||
            (!retainedLaneObservation &&
                trimView(lines[span.opener].text).starts_with("local function replay_runtime_lanes(")))
            for (size_t line = span.opener; line <= span.end && line < remove.size(); ++line)
                remove[line] = true;
    if (!retainedLaneObservation)
        for (size_t line = 0; line < lines.size(); ++line)
            if (trimView(lines[line].text) == "local lane_activation_positions = {}")
                remove[line] = true;

    for (size_t line = 0; line < lines.size(); ++line)
        if (remove[line])
        {
            mergeRemovedProvenance(lines, line);
            ++removed;
        }
    if (removed == 0)
        return 0;

    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t line = 0; line < lines.size(); ++line)
        if (!remove[line])
            compacted.push_back(std::move(lines[line]));
    lines = std::move(compacted);
    return removed;
}

size_t removeUnreferencedRecoveredFunctions(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;

    struct Candidate
    {
        std::string name;
        size_t opener = 0;
        size_t end = 0;
    };
    std::vector<Candidate> candidates;
    static const std::regex LocalRecovered(
        R"(^local function (recovered_routine_[0-9]+)\(.*$)");
    for (const ScalarFunctionSpan& span : *spans)
    {
        std::smatch match;
        const std::string statement(trimView(lines[span.opener].text));
        if (std::regex_match(statement, match, LocalRecovered))
            candidates.push_back({match[1].str(), span.opener, span.end});
    }
    if (candidates.empty())
        return 0;

    std::vector<bool> remove(lines.size(), false);
    size_t removed = 0;
    for (const Candidate& candidate : candidates)
    {
        size_t occurrences = 0;
        for (const OutputLine& line : lines)
            occurrences += identifierOccurrences(line.text, candidate.name);
        if (occurrences != 1)
            continue;
        for (size_t line = candidate.opener; line <= candidate.end && line < remove.size(); ++line)
            remove[line] = true;
        ++removed;
    }
    if (removed == 0)
        return 0;

    for (size_t line = 0; line < lines.size(); ++line)
        if (remove[line])
            mergeRemovedProvenance(lines, line);
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size());
    for (size_t line = 0; line < lines.size(); ++line)
        if (!remove[line])
            compacted.push_back(std::move(lines[line]));
    lines = std::move(compacted);
    return removed;
}

size_t removeUnreferencedTopLevelHelpers(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    std::vector<bool> remove(lines.size(), false);
    size_t removed = 0;
    static const std::regex LocalFunction(R"(^local function ([A-Za-z_][A-Za-z0-9_]*)\(.*$)");
    for (const ScalarFunctionSpan& span : *spans)
    {
        if (indentation(lines[span.opener].text) != 0)
            continue;
        std::smatch match;
        const std::string statement(trimView(lines[span.opener].text));
        if (!std::regex_match(statement, match, LocalFunction))
            continue;
        const std::string name = match[1].str();
        if (name.starts_with("replay_") || name == "expand_replay_runs" || name == "semantic_trace_tail")
            continue;
        size_t occurrences = 0;
        for (const OutputLine& line : lines)
            occurrences += identifierOccurrences(line.text, name);
        if (occurrences != 1)
            continue;
        for (size_t line = span.opener; line <= span.end && line < remove.size(); ++line)
            remove[line] = true;
        ++removed;
    }

    static const std::regex HelperAssignment(R"(^helper_values\[([0-9]+)\] = .*$)");
    for (size_t line = 0; line < lines.size(); ++line)
    {
        std::smatch match;
        const std::string statement(trimView(lines[line].text));
        if (!std::regex_match(statement, match, HelperAssignment))
            continue;
        const std::string needle = "helper_values[" + match[1].str() + "]";
        size_t occurrences = 0;
        for (const OutputLine& candidate : lines)
        {
            size_t position = 0;
            while ((position = candidate.text.find(needle, position)) != std::string::npos)
            {
                ++occurrences;
                position += needle.size();
            }
        }
        if (occurrences != 1)
            continue;
        remove[line] = true;
        ++removed;
    }
    if (removed == 0)
        return 0;
    for (size_t line = 0; line < lines.size(); ++line)
        if (remove[line])
            mergeRemovedProvenance(lines, line);
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size());
    for (size_t line = 0; line < lines.size(); ++line)
        if (!remove[line])
            compacted.push_back(std::move(lines[line]));
    lines = std::move(compacted);
    return removed;
}

size_t eliminateOverwrittenPrivateRegisterSlots(std::vector<OutputLine>& lines)
{
    struct Table
    {
        std::string name;
        size_t declaration = 0;
        size_t allocation = 0;
        size_t scopeBegin = 0;
        size_t scopeEnd = 0;
        size_t ownerScope = 0;
    };

    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    std::set<size_t> functionBoundaryLines;
    for (const ScalarFunctionSpan& span : *spans)
    {
        functionBoundaryLines.insert(span.opener);
        functionBoundaryLines.insert(span.end);
    }
    std::map<std::string, std::vector<size_t>> declarations;
    for (size_t line = 0; line < lines.size(); ++line)
        if (auto names = plainLocalDeclaration(lines[line].text))
            for (const std::string& name : *names)
                if (generatedRegisterTable(name))
                    declarations[name].push_back(line);

    std::vector<Table> tables;
    for (const auto& [name, declarationLines] : declarations)
    {
        if (declarationLines.size() != 1)
            continue;
        const size_t declaration = declarationLines.front();
        size_t scopeBegin = 0;
        size_t scopeEnd = lines.size();
        size_t expectedIndent = 0;
        std::optional<ScalarFunctionSpan> owner;
        size_t ownerScope = spans->size();
        for (size_t spanIndex = 0; spanIndex < spans->size(); ++spanIndex)
        {
            const ScalarFunctionSpan& span = (*spans)[spanIndex];
            if (span.opener < declaration && declaration < span.end && (!owner || span.opener > owner->opener))
            {
                owner = span;
                ownerScope = spanIndex;
            }
        }
        if (owner)
        {
            scopeBegin = owner->opener + 1;
            scopeEnd = owner->end;
            expectedIndent = indentation(lines[declaration].text);
        }
        if (indentation(lines[declaration].text) != expectedIndent)
            continue;

        bool valid = true;
        std::optional<size_t> allocation;
        for (size_t line = 0; line < lines.size() && valid; ++line)
        {
            if (identifierOccurrences(lines[line].text, name) == 0 || line == declaration)
                continue;
            if (line < scopeBegin || line >= scopeEnd)
            {
                valid = false;
                break;
            }
            if (auto assignment = simpleAssignment(lines[line].text);
                assignment && assignment->target == name && trimView(assignment->value) == "{}" &&
                !trimView(lines[line].text).starts_with("local ") && indentation(lines[line].text) == expectedIndent)
            {
                if (allocation)
                    valid = false;
                else
                    allocation = line;
                continue;
            }
            const ConstantSlotScan scan = scanConstantSlotAccesses(lines[line].text, name);
            if (!scan.valid || scan.accesses == 0)
            {
                if (name == "registers" && boundedRegisterClearRange(lines, line))
                    continue;
                valid = false;
            }
        }
        if (valid && allocation && declaration < *allocation)
            tables.push_back({name, declaration, *allocation, scopeBegin, scopeEnd, ownerScope});
    }

    std::vector<bool> remove(lines.size(), false);
    for (const Table& table : tables)
    {
        std::set<int64_t> capturedSlots;
        for (size_t line = table.allocation + 1; line < table.scopeEnd; ++line)
        {
            if (captures.owner[line] == table.ownerScope)
                continue;
            const ConstantSlotScan scan = scanConstantSlotAccesses(lines[line].text, table.name);
            if (scan.valid)
                capturedSlots.insert(scan.slots.begin(), scan.slots.end());
        }

        std::set<int64_t> readSlots;
        std::map<int64_t, std::vector<size_t>> slotWrites;
        for (size_t line = table.allocation + 1; line < table.scopeEnd; ++line)
        {
            const auto write = constantSlotWrite(lines[line].text);
            const bool writesThisTable = write && write->table == table.name;
            const ConstantSlotScan scan = scanConstantSlotAccesses(lines[line].text, table.name);
            if (!scan.valid)
                continue;
            for (const auto& [slot, count] : scan.frequencies)
            {
                const size_t targetOccurrence = writesThisTable && write->slot == slot ? 1 : 0;
                if (count > targetOccurrence)
                    readSlots.insert(slot);
            }
            if (writesThisTable)
                slotWrites[write->slot].push_back(line);
        }
        for (const auto& [slot, writes] : slotWrites)
            if (!readSlots.contains(slot))
                for (size_t line : writes)
                {
                    const auto write = constantSlotWrite(lines[line].text);
                    if (write && pureAssignmentValue(write->value))
                        remove[line] = true;
                }

        std::map<int64_t, size_t> pending;
        for (size_t line = table.allocation + 1; line < table.scopeEnd; ++line)
        {
            if (remove[line])
                continue;
            if (captures.owner[line] != table.ownerScope)
                continue;
            const std::string_view statement = trimView(lines[line].text);
            if (statement.empty())
                continue;
            const auto write = constantSlotWrite(lines[line].text);
            const bool writesThisTable = write && write->table == table.name;
            const bool pureWrite = writesThisTable && pureAssignmentValue(write->value);
            // Creating a closure is straight-line execution; its body is skipped
            // above because it has a different lexical owner. Do not let the
            // textual opener/closing `end` hide dead private-slot stores.
            if (controlBoundary(statement) && !functionBoundaryLines.contains(line))
            {
                pending.clear();
                continue;
            }
            if (containsCallSyntax(statement) && !pureWrite)
                for (int64_t slot : capturedSlots)
                    pending.erase(slot);

            const ConstantSlotScan scan = scanConstantSlotAccesses(lines[line].text, table.name);
            if (!scan.valid)
            {
                pending.clear();
                continue;
            }
            for (const auto& [slot, count] : scan.frequencies)
                if (!writesThisTable || write->slot != slot || count > 1)
                    pending.erase(slot);

            if (!writesThisTable)
            {
                if (const auto equals = topLevelAssignmentEquals(lines[line].text))
                {
                    const std::string_view target = trimView(std::string_view(lines[line].text).substr(0, *equals));
                    if (target.find('.') != std::string_view::npos || target.find('[') != std::string_view::npos)
                        for (int64_t slot : capturedSlots)
                            pending.erase(slot);
                }
                continue;
            }

            if (auto previous = pending.find(write->slot); previous != pending.end())
                remove[previous->second] = true;
            pending.erase(write->slot);
            if (pureWrite)
                pending[write->slot] = line;
        }
    }

    const size_t removed = static_cast<size_t>(std::count(remove.begin(), remove.end(), true));
    if (removed == 0)
        return 0;
    for (size_t line = 0; line < lines.size(); ++line)
        if (remove[line])
            mergeRemovedProvenance(lines, line);
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t line = 0; line < lines.size(); ++line)
        if (!remove[line])
            compacted.push_back(std::move(lines[line]));
    lines = std::move(compacted);
    return removed;
}

size_t eliminateDeadRegisterFrameAliases(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    std::vector<bool> remove(lines.size(), false);
    size_t removed = 0;
    for (size_t definition = 0; definition < lines.size(); ++definition)
    {
        const auto alias = simpleAssignment(lines[definition].text);
        if (!alias || !plainIdentifier(alias->target) || !generatedRegisterTable(trimView(alias->value)) ||
            alias->target == trimView(alias->value))
            continue;
        const size_t scope = captures.owner[definition];
        const size_t indent = indentation(lines[definition].text);
        for (size_t line = definition + 1; line < lines.size(); ++line)
        {
            if (captures.owner[line] != scope)
                continue;
            const std::string_view statement = trimView(lines[line].text);
            if (statement.empty())
                continue;
            if (indentation(lines[line].text) < indent ||
                (indentation(lines[line].text) == indent && controlBoundary(statement)))
                break;
            if (!containsIdentifier(statement, alias->target))
                continue;
            const auto overwrite = simpleAssignment(lines[line].text);
            if (overwrite && overwrite->target == alias->target &&
                indentation(lines[line].text) == indent &&
                !trimView(lines[line].text).starts_with("local ") &&
                !containsIdentifier(overwrite->value, alias->target) &&
                !captures.capturedBefore(definition, alias->target, line))
            {
                remove[definition] = true;
                ++removed;
            }
            break;
        }
    }
    if (removed == 0)
        return 0;
    for (size_t line = 0; line < lines.size(); ++line)
        if (remove[line])
            mergeRemovedProvenance(lines, line);
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t line = 0; line < lines.size(); ++line)
        if (!remove[line])
            compacted.push_back(std::move(lines[line]));
    lines = std::move(compacted);
    return removed;
}

RegisterTableScalarStats scalarReplaceRegisterTables(std::vector<OutputLine>& lines, bool allowRegisterOverflow)
{
    struct Plan
    {
        std::string table;
        size_t declaration = 0;
        size_t allocation = 0;
        size_t scopeBegin = 0;
        size_t scopeEnd = 0;
        size_t ownerScope = 0;
        size_t activeLocals = 0;
        size_t maxResultArity = 0;
        bool full = false;
        bool hasDynamicFrameAccess = false;
        bool hasVarargInitialization = false;
        std::set<int64_t> slots;
        std::set<int64_t> excludedSlots;
        std::vector<int64_t> excludedFromSlots;
        std::set<int64_t> selectedSlots;
        std::map<int64_t, size_t> frequencies;
        std::vector<size_t> accessLines;
        std::map<int64_t, std::string> replacements;
    };

    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return {};
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    std::vector<std::pair<std::string, size_t>> declarations;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        if (auto names = plainLocalDeclaration(lines[index].text))
            for (const std::string& name : *names)
                if (generatedRegisterTable(name))
                    declarations.emplace_back(name, index);
        const std::string_view statement = trimView(lines[index].text);
        if (statement.starts_with("local "))
            if (auto assignment = simpleAssignment(lines[index].text);
                assignment && generatedRegisterTable(assignment->target))
                declarations.emplace_back(assignment->target, index);
    }

    std::vector<Plan> plans;
    for (const auto& [name, declaration] : declarations)
    {
        size_t scopeBegin = 0;
        size_t scopeEnd = lines.size();
        size_t expectedIndent = 0;
        std::optional<ScalarFunctionSpan> owner;
        size_t ownerScope = spans->size();
        for (size_t spanIndex = 0; spanIndex < spans->size(); ++spanIndex)
        {
            const ScalarFunctionSpan& span = (*spans)[spanIndex];
            if (span.opener < declaration && declaration < span.end &&
                (!owner || span.opener > owner->opener))
            {
                owner = span;
                ownerScope = spanIndex;
            }
        }
        if (owner)
        {
            scopeBegin = owner->opener + 1;
            scopeEnd = owner->end;
            expectedIndent = indentation(lines[declaration].text);
        }
        if (indentation(lines[declaration].text) != expectedIndent)
            continue;

        Plan plan;
        plan.table = name;
        plan.declaration = declaration;
        plan.scopeBegin = scopeBegin;
        plan.scopeEnd = scopeEnd;
        plan.ownerScope = ownerScope;
        plan.activeLocals = scalarTopLevelLocalCount(lines, scopeBegin, scopeEnd, expectedIndent, owner);
        for (size_t line = scopeBegin; line < scopeEnd; ++line)
        {
            if (captures.owner[line] != ownerScope)
                continue;
            const std::string_view statement = trimView(lines[line].text);
            if (!statement.starts_with("return") || (statement.size() > 6 && statement[6] != ' '))
                continue;
            const std::string_view values = trimView(statement.substr(6));
            plan.maxResultArity = std::max(
                plan.maxResultArity,
                values.empty() ? size_t{0} : splitCaptureExpressions(values).size());
        }
        bool valid = true;
        std::optional<size_t> allocation;
        if (auto assignment = simpleAssignment(lines[declaration].text);
            assignment && assignment->target == name && trimView(assignment->value) == "{}")
            allocation = declaration;
        size_t firstAccess = lines.size();
        for (size_t index = scopeBegin; index < scopeEnd && valid; ++index)
        {
            if (identifierOccurrences(lines[index].text, name) == 0)
                continue;
            if (index == declaration)
                continue;
            if (auto names = plainLocalDeclaration(lines[index].text);
                names && std::find(names->begin(), names->end(), name) != names->end())
            {
                valid = false;
                break;
            }
            if (auto assignment = simpleAssignment(lines[index].text);
                assignment && assignment->target == name && trimView(assignment->value) == "{}" &&
                !trimView(lines[index].text).starts_with("local ") && indentation(lines[index].text) == expectedIndent)
            {
                if (allocation)
                    valid = false;
                else
                    allocation = index;
                continue;
            }
            ConstantSlotScan scan = scanConstantSlotAccesses(lines[index].text, name);
            if (!scan.valid || scan.accesses == 0)
            {
                const std::string_view statement = trimView(lines[index].text);
                static const std::regex ArgumentInitialization(
                    R"(^for argument_index = 1, argument_count do registers\[argument_index\] = select_value\(argument_index, \.\.\.\) end$)");
                if (name == "registers" && std::regex_match(std::string(statement), ArgumentInitialization))
                {
                    plan.hasDynamicFrameAccess = true;
                    plan.hasVarargInitialization = true;
                    continue;
                }

                if (name == "registers")
                {
                    const std::string text(statement);
                    std::smatch helperMatch;
                    static const std::regex CaptureCell(
                        R"(^.*capture_register_cell\(open_cells, registers, (-?[0-9]+)\).*$)");
                    static const std::regex CloseCaptured(
                        R"(^close_captured_values\(open_cells, registers, (-?[0-9]+)\);?$)");
                    static const std::regex UnpackValues(
                        R"(^return unpack_values\(registers, (-?[0-9]+), [A-Za-z_][A-Za-z0-9_]*\);?$)");
                    static const std::regex PrepareIterator(
                        R"(^prepare_generic_iterator\(registers, state, (-?[0-9]+)\);?$)");
                    if (identifierOccurrences(statement, name) == 1 &&
                        std::regex_match(text, helperMatch, CaptureCell))
                    {
                        if (const auto slot = parseInteger(helperMatch[1].str()))
                        {
                            plan.hasDynamicFrameAccess = true;
                            plan.excludedSlots.insert(*slot);
                            continue;
                        }
                    }
                    if (identifierOccurrences(statement, name) == 1 &&
                        std::regex_match(text, helperMatch, CloseCaptured))
                    {
                        if (const auto first = parseInteger(helperMatch[1].str()))
                        {
                            plan.hasDynamicFrameAccess = true;
                            plan.excludedFromSlots.push_back(*first);
                            continue;
                        }
                    }
                    if (identifierOccurrences(statement, name) == 1 &&
                        std::regex_match(text, helperMatch, UnpackValues))
                    {
                        if (const auto first = parseInteger(helperMatch[1].str()))
                        {
                            plan.hasDynamicFrameAccess = true;
                            plan.excludedFromSlots.push_back(*first);
                            continue;
                        }
                    }
                    if (identifierOccurrences(statement, name) == 1 &&
                        std::regex_match(text, helperMatch, PrepareIterator))
                    {
                        if (const auto first = parseInteger(helperMatch[1].str()))
                        {
                            plan.hasDynamicFrameAccess = true;
                            plan.excludedSlots.insert(*first);
                            plan.excludedSlots.insert(*first + 1);
                            plan.excludedSlots.insert(*first + 2);
                            continue;
                        }
                    }
                }

                if (name == "registers" && statement.find("registers[loop_index]") != std::string_view::npos)
                {
                    const size_t bodyIndent = indentation(lines[index].text);
                    static const std::regex ConstantLoop(
                        R"(^for loop_index = (-?[0-9]+), (-?[0-9]+), 1 do$)");
                    std::optional<std::pair<int64_t, int64_t>> bounds;
                    for (size_t opener = index; opener > scopeBegin; --opener)
                    {
                        const size_t candidate = opener - 1;
                        if (indentation(lines[candidate].text) >= bodyIndent)
                            continue;
                        std::smatch loopMatch;
                        const std::string loopStatement(trimView(lines[candidate].text));
                        if (std::regex_match(loopStatement, loopMatch, ConstantLoop))
                        {
                            const auto first = parseInteger(loopMatch[1].str());
                            const auto last = parseInteger(loopMatch[2].str());
                            if (first && last)
                                bounds = std::pair<int64_t, int64_t>{*first, *last};
                        }
                        break;
                    }
                    if (bounds)
                    {
                        plan.hasDynamicFrameAccess = true;
                        for (int64_t slot = bounds->first; slot <= bounds->second; ++slot)
                        {
                            plan.excludedSlots.insert(slot);
                            if (slot == std::numeric_limits<int64_t>::max())
                                break;
                        }
                        continue;
                    }
                }
                if (name == "registers" && statement ==
                        "for register_index = clear_range.from, clear_range.to do registers[register_index] = nil end")
                {
                    const std::optional<std::pair<int64_t, int64_t>> bounds =
                        boundedRegisterClearRange(lines, index);
                    if (bounds)
                    {
                        plan.hasDynamicFrameAccess = true;
                        for (int64_t slot = bounds->first; slot <= bounds->second; ++slot)
                        {
                            plan.excludedSlots.insert(slot);
                            if (slot == std::numeric_limits<int64_t>::max())
                                break;
                        }
                        continue;
                    }
                }
                valid = false;
                break;
            }
            plan.slots.insert(scan.slots.begin(), scan.slots.end());
            for (const auto& [slot, count] : scan.frequencies)
                plan.frequencies[slot] += count;
            plan.accessLines.push_back(index);
            firstAccess = std::min(firstAccess, index);
        }
        if (!valid || !allocation || plan.slots.empty() || declaration > *allocation || *allocation >= firstAccess)
            continue;
        for (int64_t slot : plan.excludedSlots)
        {
            plan.slots.erase(slot);
            plan.frequencies.erase(slot);
        }
        for (int64_t first : plan.excludedFromSlots)
            for (auto slot = plan.slots.lower_bound(first); slot != plan.slots.end();)
            {
                plan.frequencies.erase(*slot);
                slot = plan.slots.erase(slot);
            }
        if (plan.slots.empty())
            continue;
        plan.allocation = *allocation;

        const size_t LocalLimit = allowRegisterOverflow ? 1000 : 200;
        constexpr size_t ReservedLocals = 2;
        const size_t RegisterLimit = allowRegisterOverflow ? 1000 : 255;
        constexpr size_t ReservedRegisters = 10;
        const size_t localBudget = LocalLimit - ReservedLocals;
        const size_t registerBudget = plan.maxResultArity + ReservedRegisters >= RegisterLimit
            ? 0
            : RegisterLimit - ReservedRegisters - plan.maxResultArity;
        const size_t usableLocals = std::min(localBudget, registerBudget);
        const bool allFit = plan.activeLocals > 0 && plan.activeLocals - 1 + plan.slots.size() <= usableLocals;
        plan.full = allFit && !plan.hasDynamicFrameAccess;
        size_t slotBudget = 0;
        if (allFit)
            slotBudget = plan.slots.size();
        else if (plan.activeLocals < usableLocals)
            slotBudget = std::min(plan.slots.size(), usableLocals - plan.activeLocals);
        if (slotBudget == 0)
            continue;
        std::vector<std::pair<int64_t, size_t>> ranked(plan.frequencies.begin(), plan.frequencies.end());
        std::sort(ranked.begin(), ranked.end(), [](const auto& left, const auto& right) {
            if (left.second != right.second)
                return left.second > right.second;
            return left.first < right.first;
        });
        for (size_t index = 0; index < slotBudget; ++index)
            plan.selectedSlots.insert(ranked[index].first);
        plans.push_back(std::move(plan));
    }
    if (plans.empty())
        return {};

    size_t nextLocal = 0;
    for (const OutputLine& line : lines)
        for (const std::string& name : generatedReads(line.text))
            if (std::string_view(name).starts_with("local_"))
                if (auto value = parseInteger(std::string_view(name).substr(6)); value && *value >= 0)
                    nextLocal = std::max(nextLocal, static_cast<size_t>(*value) + 1);
    for (Plan& plan : plans)
        for (int64_t slot : plan.selectedSlots)
            plan.replacements.emplace(slot, "local_" + std::to_string(nextLocal++));

    std::vector<OutputLine> rewritten = lines;
    for (Plan& plan : plans)
    {
        for (size_t index : plan.accessLines)
        {
            ConstantSlotScan scan = scanConstantSlotAccesses(rewritten[index].text, plan.table, &plan.replacements);
            if (!scan.valid || scan.accesses == 0)
                return {};
            rewritten[index].text = std::move(scan.rewritten);
        }

        auto names = plainLocalDeclaration(rewritten[plan.declaration].text);
        if (!names)
        {
            const auto assignment = simpleAssignment(rewritten[plan.declaration].text);
            if (!assignment || assignment->target != plan.table)
                return {};
            names = std::vector<std::string>{plan.table};
        }
        if (plan.full)
            names->erase(std::remove(names->begin(), names->end(), plan.table), names->end());
        for (const auto& [slot, replacement] : plan.replacements)
        {
            (void)slot;
            names->push_back(replacement);
        }
        std::string declaration(indentation(rewritten[plan.declaration].text), ' ');
        declaration += "local ";
        for (size_t index = 0; index < names->size(); ++index)
        {
            if (index)
                declaration += ", ";
            declaration += (*names)[index];
        }
        if (!plan.full && plan.allocation == plan.declaration)
        {
            declaration += " = {}";
            if (plan.table == "registers" && plan.hasVarargInitialization)
                for (const auto& [slot, replacement] : plan.replacements)
                {
                    (void)replacement;
                    declaration += ", select_value(" + std::to_string(slot) + ", ...)";
                }
        }
        rewritten[plan.declaration].text = std::move(declaration);

        if (plan.full)
        {
            const size_t anchor = plan.accessLines.front();
            rewritten[anchor].states.insert(
                rewritten[plan.allocation].states.begin(), rewritten[plan.allocation].states.end());
            if (!rewritten[anchor].origin && rewritten[plan.allocation].origin)
                rewritten[anchor].origin = rewritten[plan.allocation].origin;
            if (plan.allocation != plan.declaration)
                rewritten[plan.allocation].text.clear();
        }
    }
    for (const Plan& plan : plans)
        if (plan.full)
        {
            for (size_t line = plan.scopeBegin; line < plan.scopeEnd; ++line)
                if (identifierOccurrences(rewritten[line].text, plan.table) != 0)
                    return {};
        }
        else
        {
            for (size_t index : plan.accessLines)
            {
                ConstantSlotScan scan = scanConstantSlotAccesses(rewritten[index].text, plan.table);
                if (!scan.valid)
                    return {};
                for (int64_t selected : plan.selectedSlots)
                    if (scan.slots.contains(selected))
                        return {};
            }
        }

    RegisterTableScalarStats stats;
    stats.tables = plans.size();
    for (const Plan& plan : plans)
    {
        if (plan.full)
        {
            ++stats.fullTables;
            stats.fullTableNames.insert(plan.table + "@" + std::to_string(plan.declaration));
        }
        else
        {
            ++stats.partialTables;
            stats.partialTableNames.insert(plan.table + "@" + std::to_string(plan.declaration));
        }
        stats.slots += plan.selectedSlots.size();
        for (int64_t slot : plan.selectedSlots)
            stats.accesses += plan.frequencies.at(slot);
    }
    lines = std::move(rewritten);
    return stats;
}

struct StateTableScalarStats
{
    size_t tables = 0;
    size_t fields = 0;
    size_t accesses = 0;
};

struct StateFieldAccess
{
    size_t begin = 0;
    size_t end = 0;
    std::string field;
};

struct StateFieldScan
{
    std::vector<StateFieldAccess> accesses;
    size_t bare = 0;
};

StateFieldScan scanStateFieldAccesses(std::string_view source)
{
    StateFieldScan result;
    for (size_t index = 0; index < source.size();)
    {
        if (source[index] == '-' && index + 1 < source.size() && source[index + 1] == '-')
            break;
        if (source[index] == '\'' || source[index] == '"')
        {
            const char quote = source[index++];
            while (index < source.size())
            {
                if (source[index] == '\\')
                    index += std::min<size_t>(2, source.size() - index);
                else if (source[index++] == quote)
                    break;
            }
            continue;
        }
        if (source[index] != '_' && !std::isalpha(static_cast<unsigned char>(source[index])))
        {
            ++index;
            continue;
        }
        const size_t begin = index++;
        while (index < source.size() &&
            (source[index] == '_' || std::isalnum(static_cast<unsigned char>(source[index]))))
            ++index;
        if (source.substr(begin, index - begin) != "state")
            continue;
        if (index >= source.size() || source[index] != '.' || index + 1 >= source.size() ||
            (source[index + 1] != '_' && !std::isalpha(static_cast<unsigned char>(source[index + 1]))))
        {
            ++result.bare;
            continue;
        }
        const size_t fieldBegin = ++index;
        ++index;
        while (index < source.size() &&
            (source[index] == '_' || std::isalnum(static_cast<unsigned char>(source[index]))))
            ++index;
        result.accesses.push_back({begin, index, std::string(source.substr(fieldBegin, index - fieldBegin))});
    }
    return result;
}

StateTableScalarStats scalarReplacePrivateStateTables(std::vector<OutputLine>& lines)
{
    static const std::regex Declaration(R"(^local state = \{ Q = environment \};?$)");
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return {};
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    std::set<std::string> occupied = collectIdentifiers(lines);
    size_t localOrdinal = 1;
    auto allocateLocal = [&]() {
        std::string name;
        do
        {
            name = "local_" + std::to_string(localOrdinal++);
        } while (occupied.contains(name));
        occupied.insert(name);
        return name;
    };

    StateTableScalarStats stats;
    for (size_t declaration = 0; declaration < lines.size(); ++declaration)
    {
        if (!std::regex_match(std::string(trimView(lines[declaration].text)), Declaration) ||
            declaration >= captures.owner.size())
            continue;
        const size_t owner = captures.owner[declaration];
        if (owner >= spans->size())
            continue;
        const ScalarFunctionSpan& scope = (*spans)[owner];
        std::set<std::string> fields;
        bool safe = true;
        size_t accessCount = 0;
        for (size_t line = declaration + 1; line < scope.end && line < lines.size(); ++line)
        {
            const StateFieldScan scan = scanStateFieldAccesses(lines[line].text);
            if (scan.accesses.empty() && scan.bare == 0)
                continue;
            if (captures.owner[line] != owner || scan.bare > 0)
            {
                safe = false;
                break;
            }
            accessCount += scan.accesses.size();
            for (const StateFieldAccess& access : scan.accesses)
                fields.insert(access.field);
        }
        if (!safe || fields.empty())
            continue;

        std::map<std::string, std::string> replacements;
        for (const std::string& field : fields)
            replacements[field] = allocateLocal();
        for (size_t line = declaration + 1; line < scope.end && line < lines.size(); ++line)
        {
            StateFieldScan scan = scanStateFieldAccesses(lines[line].text);
            for (auto access = scan.accesses.rbegin(); access != scan.accesses.rend(); ++access)
                lines[line].text.replace(access->begin, access->end - access->begin, replacements[access->field]);
        }

        std::string rewritten(indentation(lines[declaration].text), ' ');
        rewritten += "local ";
        size_t fieldIndex = 0;
        for (const auto& [field, name] : replacements)
        {
            (void)field;
            if (fieldIndex++)
                rewritten += ", ";
            rewritten += name;
        }
        rewritten += " = ";
        fieldIndex = 0;
        for (const auto& [field, name] : replacements)
        {
            (void)name;
            if (fieldIndex++)
                rewritten += ", ";
            rewritten += field == "Q" ? "environment" : "nil";
        }
        lines[declaration].text = std::move(rewritten);
        ++stats.tables;
        stats.fields += replacements.size();
        stats.accesses += accessCount;
    }
    return stats;
}

struct StableCaptureCellStats
{
    size_t cells = 0;
    size_t accesses = 0;
};

StableCaptureCellStats scalarizeStableCaptureCells(std::vector<OutputLine>& lines)
{
    const auto functionSpans = scalarFunctionSpans(lines);
    if (!functionSpans)
        return {};
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *functionSpans);
    struct Alias
    {
        size_t line = 0;
        std::string target;
        std::string source;
    };
    struct Plan
    {
        std::string root;
        size_t allocation = 0;
        size_t end = 0;
        std::set<std::string> family;
        std::set<size_t> aliasLines;
        std::map<std::string, size_t> aliasBegins;
    };

    auto snapshotName = [](std::string_view name) {
        constexpr std::string_view Prefix = "snapshot_";
        return name.starts_with(Prefix) && name.size() > Prefix.size() &&
            std::all_of(name.begin() + static_cast<std::ptrdiff_t>(Prefix.size()), name.end(), [](char ch) {
                return std::isdigit(static_cast<unsigned char>(ch));
            });
    };

    std::map<std::string, std::vector<size_t>> allocations;
    std::vector<Alias> aliases;
    std::map<std::string, size_t> aliasDefinitions;
    for (size_t line = 0; line < lines.size(); ++line)
    {
        if (auto assignment = simpleAssignment(lines[line].text);
            assignment && generatedLocal(assignment->target) &&
            std::string_view(assignment->target).starts_with("local_") &&
            trimView(assignment->value) == "{nil}")
            allocations[assignment->target].push_back(line);

        const auto assignment = identifierAssignmentList(lines[line].text);
        if (!assignment)
            continue;
        const std::vector<std::string> values = splitCaptureExpressions(
            trimView(std::string_view(lines[line].text).substr(assignment->value_begin)));
        if (values.size() != assignment->targets.size())
            continue;
        for (size_t index = 0; index < values.size(); ++index)
        {
            const std::string_view value = stripOuterParentheses(trimView(values[index]));
            if (!snapshotName(assignment->targets[index]) || !plainIdentifier(value))
                continue;
            aliases.push_back({line, assignment->targets[index], std::string(value)});
            ++aliasDefinitions[assignment->targets[index]];
        }
    }

    std::vector<Plan> plans;
    std::set<std::string> claimedAliases;
    for (const auto& [root, allocationLines] : allocations)
    {
        for (const size_t allocation : allocationLines)
        {
            size_t expectedIndent = 0;
            std::optional<ScalarFunctionSpan> owner;
            for (const ScalarFunctionSpan& span : *functionSpans)
                if (span.opener < allocation && allocation < span.end &&
                    (!owner || span.opener > owner->opener))
                    owner = span;
            if (owner)
                expectedIndent = owner->indent + 4;
            if (indentation(lines[allocation].text) != expectedIndent)
                continue;
            const size_t ownerScope = captures.owner[allocation];

            size_t rootEnd = owner ? owner->end : lines.size();
            for (size_t line = allocation + 1; line < rootEnd; ++line)
                if (captures.owner[line] == ownerScope)
                    if (auto assignment = simpleAssignment(lines[line].text);
                    assignment && assignment->target == root)
                    {
                        rootEnd = line;
                        break;
                    }
            Plan plan{root, allocation, rootEnd, {root}, {}, {}};
            bool expanded = true;
            while (expanded)
            {
                expanded = false;
                for (const Alias& alias : aliases)
                {
                    const bool sourceActive = alias.source == root
                        ? alias.line > plan.allocation && alias.line < plan.end
                        : (plan.aliasBegins.contains(alias.source) && alias.line > plan.aliasBegins.at(alias.source));
                    if (!plan.family.contains(alias.source) || !sourceActive || plan.family.contains(alias.target) ||
                        aliasDefinitions[alias.target] != 1)
                        continue;
                    plan.family.insert(alias.target);
                    plan.aliasLines.insert(alias.line);
                    plan.aliasBegins[alias.target] = alias.line;
                    expanded = true;
                }
            }
            if (std::any_of(plan.family.begin(), plan.family.end(), [&](const std::string& name) {
                    return name != root && claimedAliases.contains(name);
                }))
                continue;

            const size_t firstAlias = plan.aliasLines.empty() ? lines.size() : *plan.aliasLines.begin();
            bool safe = true;
            size_t writes = 0;
            size_t firstAccess = lines.size();
            size_t firstRootWrite = lines.size();
            for (size_t line = 0; line < lines.size() && safe; ++line)
            {
                auto active = [&](const std::string& name) {
                    if (name == root)
                        return line >= plan.allocation && line < plan.end;
                    auto begin = plan.aliasBegins.find(name);
                    return begin != plan.aliasBegins.end() && line >= begin->second;
                };
                bool mentioned = false;
                for (const std::string& name : plan.family)
                    if (active(name) && containsIdentifier(lines[line].text, name))
                    {
                        mentioned = true;
                        break;
                    }
                if (!mentioned)
                    continue;
                if (line == plan.allocation || plan.aliasLines.contains(line))
                    continue;
                if (auto names = plainLocalDeclaration(lines[line].text);
                    names && std::any_of(names->begin(), names->end(), [&](const std::string& name) {
                        return plan.family.contains(name);
                    }))
                    continue;
                if (captures.owner[line] != ownerScope && active(root) &&
                    containsIdentifier(lines[line].text, root))
                {
                    safe = false;
                    break;
                }

                if (const auto write = constantSlotWrite(lines[line].text);
                    write && plan.family.contains(write->table) && active(write->table))
                {
                    if (write->slot != 1 || (firstAlias != lines.size() &&
                            (write->table != root || line >= firstAlias)))
                    {
                        safe = false;
                        break;
                    }
                    if (write->table == root)
                        firstRootWrite = std::min(firstRootWrite, line);
                    ++writes;
                }

                std::string rewritten = lines[line].text;
                size_t replacements = 0;
                for (const std::string& name : plan.family)
                {
                    if (!active(name))
                        continue;
                    size_t current = 0;
                    rewritten = replaceCellValue(rewritten, name, "__alex_stable_cell_value", current);
                    replacements += current;
                }
                if (replacements > 0)
                    firstAccess = std::min(firstAccess, line);
                if (replacements == 0 || std::any_of(plan.family.begin(), plan.family.end(), [&](const std::string& name) {
                        return active(name) && containsIdentifier(rewritten, name);
                    }))
                    safe = false;
            }
            if (!safe || writes == 0 || firstRootWrite != firstAccess || firstRootWrite == lines.size() ||
                indentation(lines[firstRootWrite].text) != expectedIndent)
                continue;
            for (const std::string& name : plan.family)
                if (name != root)
                    claimedAliases.insert(name);
            plans.push_back(std::move(plan));
        }
    }

    StableCaptureCellStats stats;
    for (const Plan& plan : plans)
    {
        const bool localAllocation = trimView(lines[plan.allocation].text).starts_with("local ");
        if (localAllocation)
            lines[plan.allocation].text = std::string(indentation(lines[plan.allocation].text), ' ') +
                "local " + plan.root;
        else
            lines[plan.allocation].text.clear();
        for (size_t line = 0; line < lines.size(); ++line)
        {
            if (line == plan.allocation)
                continue;
            for (const std::string& name : plan.family)
            {
                const bool active = name == plan.root
                    ? line >= plan.allocation && line < plan.end
                    : (plan.aliasBegins.contains(name) && line >= plan.aliasBegins.at(name));
                if (!active)
                    continue;
                size_t replacements = 0;
                lines[line].text = replaceCellValue(lines[line].text, name, name, replacements);
                stats.accesses += replacements;
            }
        }
        ++stats.cells;
    }
    return stats;
}

bool rejectedInlineLexicalConstruct(std::string_view line)
{
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
            return true;
        if (line[index] == '\'' || line[index] == '"')
        {
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            continue;
        }
        if (line[index] == '[')
        {
            size_t cursor = index + 1;
            while (cursor < line.size() && line[cursor] == '=')
                ++cursor;
            if (cursor < line.size() && line[cursor] == '[')
                return true;
        }
        ++index;
    }
    return false;
}

bool hasTopLevelComma(std::string_view value)
{
    int parentheses = 0;
    int brackets = 0;
    int braces = 0;
    char quote = 0;
    for (size_t index = 0; index < value.size(); ++index)
    {
        const char ch = value[index];
        if (quote != 0)
        {
            if (ch == '\\')
                ++index;
            else if (ch == quote)
                quote = 0;
            continue;
        }
        if (ch == '\'' || ch == '"')
            quote = ch;
        else if (ch == '(')
            ++parentheses;
        else if (ch == ')')
            --parentheses;
        else if (ch == '[')
            ++brackets;
        else if (ch == ']')
            --brackets;
        else if (ch == '{')
            ++braces;
        else if (ch == '}')
            --braces;
        else if (ch == ',' && parentheses == 0 && brackets == 0 && braces == 0)
            return true;
        if (parentheses < 0 || brackets < 0 || braces < 0)
            return true;
    }
    return quote != 0 || parentheses != 0 || brackets != 0 || braces != 0;
}

std::optional<size_t> soleIdentifierPosition(std::string_view line, std::string_view name)
{
    std::optional<size_t> result;
    for (size_t index = 0; index < line.size();)
    {
        if (line[index] == '-' && index + 1 < line.size() && line[index + 1] == '-')
            break;
        if (line[index] == '\'' || line[index] == '"')
        {
            const char quote = line[index++];
            while (index < line.size())
            {
                if (line[index] == '\\')
                    index += std::min<size_t>(2, line.size() - index);
                else if (line[index++] == quote)
                    break;
            }
            continue;
        }
        if (line[index] == '_' || std::isalpha(static_cast<unsigned char>(line[index])))
        {
            const size_t begin = index++;
            while (index < line.size() && (line[index] == '_' || std::isalnum(static_cast<unsigned char>(line[index]))))
                ++index;
            if (line.substr(begin, index - begin) == name)
            {
                if (result)
                    return std::nullopt;
                result = begin;
            }
            continue;
        }
        ++index;
    }
    return result;
}

std::optional<size_t> topLevelAssignmentEquals(std::string_view line)
{
    int parentheses = 0;
    int brackets = 0;
    int braces = 0;
    char quote = 0;
    for (size_t index = 0; index < line.size(); ++index)
    {
        const char ch = line[index];
        if (quote != 0)
        {
            if (ch == '\\')
                ++index;
            else if (ch == quote)
                quote = 0;
            continue;
        }
        if (ch == '\'' || ch == '"')
            quote = ch;
        else if (ch == '(')
            ++parentheses;
        else if (ch == ')')
            --parentheses;
        else if (ch == '[')
            ++brackets;
        else if (ch == ']')
            --brackets;
        else if (ch == '{')
            ++braces;
        else if (ch == '}')
            --braces;
        else if (ch == '=' && parentheses == 0 && brackets == 0 && braces == 0)
        {
            const char previous = index == 0 ? '\0' : line[index - 1];
            const char next = index + 1 < line.size() ? line[index + 1] : '\0';
            if (next != '=' && previous != '=' && previous != '~' && previous != '<' && previous != '>' &&
                previous != '+' && previous != '-' && previous != '*' && previous != '/' && previous != '%' &&
                previous != '^' && previous != '.')
                return index;
        }
    }
    return std::nullopt;
}

size_t enclosingFunctionEnd(const std::vector<ScalarFunctionSpan>& spans, size_t line, size_t fallback)
{
    size_t result = fallback;
    size_t owner = 0;
    bool found = false;
    for (const ScalarFunctionSpan& span : spans)
        if (span.opener < line && line < span.end && (!found || span.opener > owner))
        {
            result = span.end;
            owner = span.opener;
            found = true;
        }
    return result;
}

bool functionParameterShadows(const OutputLine& opener, std::string_view name)
{
    const std::string_view statement = trimView(opener.text);
    const size_t function = statement.find("function");
    const size_t begin = function == std::string_view::npos ? std::string_view::npos : statement.find('(', function + 8);
    const size_t end = begin == std::string_view::npos ? std::string_view::npos : statement.find(')', begin + 1);
    if (end == std::string_view::npos)
        return false;
    const std::vector<std::string> parameters = splitCaptureExpressions(statement.substr(begin + 1, end - begin - 1));
    return std::find(parameters.begin(), parameters.end(), name) != parameters.end();
}

struct TemporaryBindingAnalysis
{
    struct Scope
    {
        std::optional<size_t> declaration;
        bool duplicateDeclaration = false;
        std::set<size_t> capturingChildren;
        std::set<size_t> temporaryOccurrences;
    };

    std::vector<std::optional<size_t>> owners;
    std::map<size_t, Scope> scopes;
};

size_t temporaryScopeKey(std::optional<size_t> owner)
{
    return owner ? *owner + 1 : 0;
}

TemporaryBindingAnalysis analyzeTemporaryBindings(
    const std::vector<OutputLine>& lines, const std::vector<ScalarFunctionSpan>& spans)
{
    TemporaryBindingAnalysis result;
    result.owners.resize(lines.size());
    std::map<size_t, size_t> openerToSpan;
    for (size_t span = 0; span < spans.size(); ++span)
        openerToSpan[spans[span].opener] = span;

    std::vector<size_t> stack;
    std::vector<std::optional<size_t>> parents(spans.size());
    for (size_t line = 0; line < lines.size(); ++line)
    {
        while (!stack.empty() && spans[stack.back()].end <= line)
            stack.pop_back();
        result.owners[line] = stack.empty() ? std::nullopt : std::optional<size_t>(stack.back());
        auto opening = openerToSpan.find(line);
        if (opening != openerToSpan.end())
        {
            parents[opening->second] = result.owners[line];
            stack.push_back(opening->second);
        }
    }

    for (size_t line = 0; line < lines.size(); ++line)
    {
        const std::optional<size_t> owner = result.owners[line];
        if (containsIdentifier(lines[line].text, "temporary"))
            result.scopes[temporaryScopeKey(owner)].temporaryOccurrences.insert(line);
        const size_t scopeIndent = owner ? spans[*owner].indent + 4 : 0;
        if (indentation(lines[line].text) != scopeIndent)
            continue;
        auto names = plainLocalDeclaration(lines[line].text);
        if (!names || std::find(names->begin(), names->end(), "temporary") == names->end())
            continue;
        TemporaryBindingAnalysis::Scope& scope = result.scopes[temporaryScopeKey(owner)];
        if (scope.declaration)
            scope.duplicateDeclaration = true;
        else
            scope.declaration = line;
    }

    std::vector<bool> capturesOuterTemporary(spans.size(), false);
    for (size_t reversed = spans.size(); reversed > 0; --reversed)
    {
        const size_t spanIndex = reversed - 1;
        const ScalarFunctionSpan& span = spans[spanIndex];
        bool shadowed = functionParameterShadows(lines[span.opener], "temporary");
        for (size_t line = span.opener + 1; line < span.end; ++line)
        {
            auto child = openerToSpan.find(line);
            if (child != openerToSpan.end() && parents[child->second] == std::optional<size_t>(spanIndex))
            {
                if (!shadowed && capturesOuterTemporary[child->second])
                    capturesOuterTemporary[spanIndex] = true;
                line = spans[child->second].end;
                continue;
            }
            if (indentation(lines[line].text) == span.indent + 4)
            {
                bool declaresTemporary = false;
                if (auto declarations = plainLocalDeclaration(lines[line].text))
                    declaresTemporary =
                        std::find(declarations->begin(), declarations->end(), "temporary") != declarations->end();
                if (trimView(lines[line].text).starts_with("local "))
                    if (auto assignment = identifierAssignmentList(lines[line].text);
                        assignment && std::find(assignment->targets.begin(), assignment->targets.end(), "temporary") !=
                                assignment->targets.end())
                    {
                        declaresTemporary = true;
                        if (!shadowed && containsIdentifier(
                                             std::string_view(lines[line].text).substr(assignment->value_begin), "temporary"))
                            capturesOuterTemporary[spanIndex] = true;
                    }
                if (declaresTemporary)
                {
                    shadowed = true;
                    continue;
                }
            }
            if (!shadowed && containsIdentifier(lines[line].text, "temporary"))
                capturesOuterTemporary[spanIndex] = true;
        }
        if (capturesOuterTemporary[spanIndex])
            result.scopes[temporaryScopeKey(parents[spanIndex])].capturingChildren.insert(spanIndex);
    }
    return result;
}

bool provenTemporaryBinding(const std::vector<OutputLine>& lines, const std::vector<ScalarFunctionSpan>& spans,
    const TemporaryBindingAnalysis& analysis, size_t line, std::optional<size_t> ignoredNestedOpener = std::nullopt)
{
    if (line >= analysis.owners.size())
        return false;
    const std::optional<size_t> owner = analysis.owners[line];
    const size_t scopeIndent = owner ? spans[*owner].indent + 4 : 0;
    if (indentation(lines[line].text) != scopeIndent)
        return false;
    auto found = analysis.scopes.find(temporaryScopeKey(owner));
    if (found == analysis.scopes.end() || found->second.duplicateDeclaration || !found->second.declaration ||
        *found->second.declaration >= line)
        return false;
    for (size_t child : found->second.capturingChildren)
        if (!ignoredNestedOpener || spans[child].opener != *ignoredNestedOpener)
            return false;
    return true;
}

size_t eliminateDeadTemporaryAssignments(
    std::vector<OutputLine>& lines, const TemporaryBindingAnalysis& analysis)
{
    std::map<size_t, size_t> pending;
    std::vector<bool> remove(lines.size(), false);
    auto canRemove = [&](size_t definition) {
        size_t next = definition + 1;
        while (next < lines.size() && trimView(lines[next].text).empty())
            ++next;
        return next == lines.size() || !trimView(lines[next].text).starts_with(";(");
    };
    for (size_t index = 0; index < lines.size(); ++index)
    {
        if (index >= analysis.owners.size())
            break;
        const size_t scopeKey = temporaryScopeKey(analysis.owners[index]);
        const auto scope = analysis.scopes.find(scopeKey);
        if (scope == analysis.scopes.end() || !scope->second.declaration || scope->second.duplicateDeclaration ||
            !scope->second.capturingChildren.empty() || index <= *scope->second.declaration)
            continue;

        const std::string_view statement = trimView(lines[index].text);
        if (statement.empty())
            continue;
        const bool returns = statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' ');
        if (controlBoundary(statement) || returns)
        {
            if (returns && !containsIdentifier(statement, "temporary"))
                if (auto found = pending.find(scopeKey); found != pending.end())
                    remove[found->second] = canRemove(found->second);
            pending.erase(scopeKey);
            continue;
        }

        auto assignment = simpleAssignment(lines[index].text);
        if (assignment && assignment->target == "temporary")
        {
            if (containsIdentifier(assignment->value, "temporary"))
            {
                pending.erase(scopeKey);
                continue;
            }
            if (auto found = pending.find(scopeKey); found != pending.end())
                remove[found->second] = canRemove(found->second);
            pending.erase(scopeKey);
            if (pureAssignmentValue(assignment->value))
                pending.emplace(scopeKey, index);
            continue;
        }
        if (containsIdentifier(statement, "temporary"))
            pending.erase(scopeKey);
    }
    for (const auto& [scopeKey, definition] : pending)
    {
        (void)scopeKey;
        remove[definition] = canRemove(definition);
    }
    for (const auto& [scopeKey, scope] : analysis.scopes)
    {
        (void)scopeKey;
        if (!scope.declaration || scope.duplicateDeclaration || !scope.capturingChildren.empty())
            continue;
        for (auto occurrence = scope.temporaryOccurrences.rbegin();
             occurrence != scope.temporaryOccurrences.rend(); ++occurrence)
        {
            if (*occurrence <= *scope.declaration)
                break;
            auto assignment = simpleAssignment(lines[*occurrence].text);
            if (assignment && assignment->target == "temporary" && pureAssignmentValue(assignment->value) &&
                canRemove(*occurrence))
                remove[*occurrence] = true;
            break;
        }
    }

    const size_t removed = static_cast<size_t>(std::count(remove.begin(), remove.end(), true));
    if (removed == 0)
        return 0;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        if (!remove[index] || lines[index].states.empty())
            continue;
        size_t anchor = index + 1;
        while (anchor < lines.size() && remove[anchor])
            ++anchor;
        if (anchor < lines.size())
            lines[anchor].states.insert(lines[index].states.begin(), lines[index].states.end());
    }
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return removed;
}

bool temporaryValueDeadAfter(
    const std::vector<OutputLine>& lines, const TemporaryBindingAnalysis& analysis, size_t after, size_t indent)
{
    if (after >= analysis.owners.size())
        return false;
    const auto scope = analysis.scopes.find(temporaryScopeKey(analysis.owners[after]));
    if (scope == analysis.scopes.end())
        return true;
    for (auto occurrence = scope->second.temporaryOccurrences.upper_bound(after);
         occurrence != scope->second.temporaryOccurrences.end(); ++occurrence)
    {
        const size_t index = *occurrence;
        if (!containsIdentifier(lines[index].text, "temporary"))
            continue;
        auto overwrite = simpleAssignment(lines[index].text);
        return indentation(lines[index].text) == indent && overwrite &&
            overwrite->target == "temporary" && !containsIdentifier(overwrite->value, "temporary");
    }
    return true;
}

LiveSet inlineTemporaryConditionsInFlow(std::vector<FlowNode>& nodes, LiveSet live,
    std::vector<OutputLine>& lines, std::vector<bool>& remove, const std::vector<ScalarFunctionSpan>& spans,
    const TemporaryBindingAnalysis& bindings, size_t& inlined)
{
    static const std::regex Assignment(R"(^\s*((?:local_[0-9]+)|temporary|__results)\s*=\s*(.+)$)");
    for (size_t reversed = nodes.size(); reversed > 0; --reversed)
    {
        const size_t nodeIndex = reversed - 1;
        FlowNode& node = nodes[nodeIndex];
        if (node.kind == FlowNode::Kind::Statement)
        {
            if (remove[node.line])
                continue;
            const std::string_view statement = trimView(lines[node.line].text);
            if (statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' '))
            {
                live = generatedReads(statement);
                continue;
            }
            std::smatch assignment;
            if (std::regex_match(lines[node.line].text, assignment, Assignment))
            {
                live.erase(assignment[1].str());
                mergeLive(live, generatedReads(assignment[2].str()));
            }
            else
                mergeLive(live, generatedReads(statement));
            continue;
        }

        if (node.kind == FlowNode::Kind::If)
        {
            LiveSet first = inlineTemporaryConditionsInFlow(
                node.first, live, lines, remove, spans, bindings, inlined);
            LiveSet second = node.second.empty()
                ? live
                : inlineTemporaryConditionsInFlow(node.second, live, lines, remove, spans, bindings, inlined);

            size_t previous = nodeIndex;
            while (previous > 0)
            {
                --previous;
                if (nodes[previous].kind != FlowNode::Kind::Statement ||
                    !trimView(lines[nodes[previous].line].text).empty())
                    break;
            }
            if (previous < nodeIndex && nodes[previous].kind == FlowNode::Kind::Statement &&
                !remove[nodes[previous].line] && identifierOccurrences(node.condition, "temporary") == 1 &&
                !first.contains("temporary") && !second.contains("temporary"))
            {
                const size_t definition = nodes[previous].line;
                auto assignment = simpleAssignment(lines[definition].text);
                const std::string_view expression = assignment ? trimView(assignment->value) : std::string_view{};
                if (assignment && assignment->target == "temporary" &&
                    !trimView(lines[definition].text).starts_with("local ") && !expression.empty() &&
                    !expression.starts_with("function(") && !expression.starts_with("(function(") &&
                    !hasTopLevelComma(expression) && provenTemporaryBinding(lines, spans, bindings, definition))
                {
                    node.condition = replaceIdentifier(node.condition, "temporary", "(" + std::string(expression) + ")");
                    lines[node.line].text = std::string(indentation(lines[node.line].text), ' ') +
                        "if " + node.condition + " then";
                    lines[node.line].states.insert(
                        lines[definition].states.begin(), lines[definition].states.end());
                    if (!lines[node.line].origin && lines[definition].origin)
                        lines[node.line].origin = lines[definition].origin;
                    remove[definition] = true;
                    ++inlined;
                }
            }

            mergeLive(first, second);
            mergeLive(first, generatedReads(node.condition));
            live = std::move(first);
            continue;
        }

        LiveSet fixed = live;
        mergeLive(fixed, generatedReads(node.condition));
        for (size_t iteration = 0; iteration < 128; ++iteration)
        {
            LiveSet body = analyzeFlow(node.first, fixed, lines, remove, false);
            LiveSet next = live;
            mergeLive(next, generatedReads(node.condition));
            mergeLive(next, body);
            if (next == fixed)
                break;
            fixed = std::move(next);
        }
        inlineTemporaryConditionsInFlow(node.first, fixed, lines, remove, spans, bindings, inlined);
        live = std::move(fixed);
    }
    return live;
}

size_t inlineTemporaryConditions(std::vector<OutputLine>& lines,
    const std::vector<ScalarFunctionSpan>& spans, const TemporaryBindingAnalysis& bindings)
{
    std::vector<bool> remove(lines.size(), false);
    size_t inlined = 0;
    std::map<size_t, size_t> skippedFunctions;
    for (const ScalarFunctionSpan& nested : spans)
        skippedFunctions[nested.opener] = nested.end;
    for (const ScalarFunctionSpan& span : spans)
    {
        size_t cursor = span.opener + 1;
        std::vector<FlowNode> nodes;
        if (!parseFlowSequence(lines, cursor, span.end, span.indent + 4, nodes, &skippedFunctions) || cursor != span.end)
            continue;
        inlineTemporaryConditionsInFlow(nodes, {}, lines, remove, spans, bindings, inlined);
    }
    if (inlined == 0)
        return 0;

    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - inlined);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return inlined;
}

size_t inlineAdjacentSingleUseTemporaries(std::vector<OutputLine>& lines,
    const std::vector<ScalarFunctionSpan>& spans, const TemporaryBindingAnalysis& bindings)
{
    size_t inlined = 0;
    for (size_t definition = 0; definition < lines.size(); ++definition)
    {
        auto assignment = simpleAssignment(lines[definition].text);
        if (!assignment || assignment->target != "temporary" || trimView(lines[definition].text).starts_with("local ") ||
            rejectedInlineLexicalConstruct(lines[definition].text))
            continue;
        const std::string expression = trim(assignment->value);
        const std::string_view normalized = trimView(expression);
        if (normalized.empty() || normalized.starts_with("function(") || normalized.starts_with("(function(") ||
            hasTopLevelComma(normalized) || !provenTemporaryBinding(lines, spans, bindings, definition))
            continue;

        size_t consumer = definition + 1;
        while (consumer < lines.size() && trimView(lines[consumer].text).empty())
            ++consumer;
        const size_t indent = indentation(lines[definition].text);
        if (consumer >= lines.size() || consumer >= enclosingFunctionEnd(spans, definition, lines.size()) ||
            indentation(lines[consumer].text) != indent || rejectedInlineLexicalConstruct(lines[consumer].text) ||
            (controlBoundary(trimView(lines[consumer].text)) && !trimView(lines[consumer].text).starts_with("if ")) ||
            directlyWritesIdentifier(lines[consumer].text, "temporary"))
            continue;
        const auto position = soleIdentifierPosition(lines[consumer].text, "temporary");
        if (!position || identifierOccurrences(lines[consumer].text, "temporary") != 1)
            continue;
        if (auto writes = identifierAssignmentList(lines[consumer].text);
            writes && std::find(writes->targets.begin(), writes->targets.end(), "temporary") != writes->targets.end())
            continue;
        if (auto equals = topLevelAssignmentEquals(lines[consumer].text); equals && *position < *equals)
            continue;
        if (!temporaryValueDeadAfter(lines, bindings, consumer, indent))
            continue;

        const std::string replacement = "(" + expression + ")";
        const std::string rewritten = replaceIdentifier(lines[consumer].text, "temporary", replacement);
        if (rewritten == lines[consumer].text)
            continue;
        lines[consumer].text = rewritten;
        lines[consumer].states.insert(lines[definition].states.begin(), lines[definition].states.end());
        if (!lines[consumer].origin && lines[definition].origin)
            lines[consumer].origin = lines[definition].origin;
        lines[definition].text.clear();
        ++inlined;
    }
    return inlined;
}

size_t promoteCallbackAliases(std::vector<OutputLine>& lines,
    const std::vector<ScalarFunctionSpan>& spans, const TemporaryBindingAnalysis& bindings)
{
    size_t promoted = 0;
    for (size_t opener = 0; opener < lines.size(); ++opener)
    {
        auto functionAssignment = simpleAssignment(lines[opener].text);
        if (!functionAssignment || functionAssignment->target != "temporary" ||
            !trimView(functionAssignment->value).starts_with("function(") || rejectedInlineLexicalConstruct(lines[opener].text))
            continue;
        if (!provenTemporaryBinding(lines, spans, bindings, opener, opener))
            continue;
        const size_t indent = indentation(lines[opener].text);
        size_t functionEnd = opener + 1;
        while (functionEnd < lines.size() &&
            !(indentation(lines[functionEnd].text) == indent && trimView(lines[functionEnd].text) == "end"))
            ++functionEnd;
        if (functionEnd >= lines.size())
            continue;
        size_t aliasLine = functionEnd + 1;
        while (aliasLine < lines.size() && trimView(lines[aliasLine].text).empty())
            ++aliasLine;
        auto alias = aliasLine < lines.size() ? simpleAssignment(lines[aliasLine].text) : std::nullopt;
        if (!alias || indentation(lines[aliasLine].text) != indent || !trimView(lines[aliasLine].text).starts_with("local ") ||
            trimView(alias->value) != "temporary" || !bareReadableGlobal(alias->target) ||
            rejectedInlineLexicalConstruct(lines[aliasLine].text))
            continue;

        bool temporaryShadowed = false;
        bool bodySafe = true;
        for (size_t index = opener + 1; index < functionEnd; ++index)
        {
            if (containsIdentifier(lines[index].text, alias->target))
            {
                bodySafe = false;
                break;
            }
            if (indentation(lines[index].text) == indent + 4)
                if (auto declarations = plainLocalDeclaration(lines[index].text);
                    declarations && std::find(declarations->begin(), declarations->end(), "temporary") != declarations->end())
                {
                    temporaryShadowed = true;
                    continue;
                }
            if (!temporaryShadowed && containsIdentifier(lines[index].text, "temporary"))
            {
                bodySafe = false;
                break;
            }
        }
        if (!bodySafe || !temporaryValueDeadAfter(lines, bindings, aliasLine, indent))
            continue;

        const std::string_view value = trimView(functionAssignment->value);
        lines[opener].text = std::string(indent, ' ') + "local function " + alias->target + std::string(value.substr(8));
        lines[opener].states.insert(lines[aliasLine].states.begin(), lines[aliasLine].states.end());
        if (!lines[opener].origin && lines[aliasLine].origin)
            lines[opener].origin = lines[aliasLine].origin;
        lines[aliasLine].text.clear();
        ++promoted;
        opener = functionEnd;
    }
    return promoted;
}

size_t promoteNamedCallbackAliases(
    std::vector<OutputLine>& lines, const std::vector<ScalarFunctionSpan>& spans)
{
    size_t promoted = 0;
    for (const ScalarFunctionSpan& function : spans)
    {
        const size_t opener = function.opener;
        if (opener >= lines.size() || function.end >= lines.size())
            continue;
        const std::string_view statement = trimView(lines[opener].text);
        auto assignment = simpleAssignment(lines[opener].text);
        if (!assignment || !statement.starts_with("local ") ||
            !trimView(assignment->value).starts_with("function(") ||
            !(assignment->target.starts_with("callback_") || assignment->target.starts_with("function_") ||
                generatedLocal(assignment->target)))
            continue;

        size_t aliasLine = function.end + 1;
        while (aliasLine < lines.size() && trimView(lines[aliasLine].text).empty())
            ++aliasLine;
        auto alias = aliasLine < lines.size() ? simpleAssignment(lines[aliasLine].text) : std::nullopt;
        if (!alias || indentation(lines[aliasLine].text) != function.indent ||
            !trimView(lines[aliasLine].text).starts_with("local ") ||
            trimView(alias->value) != assignment->target || alias->target == assignment->target ||
            !bareReadableGlobal(alias->target))
            continue;

        bool bodySafe = true;
        for (size_t line = opener + 1; line < function.end; ++line)
            if (containsIdentifier(lines[line].text, assignment->target) ||
                containsIdentifier(lines[line].text, alias->target))
            {
                bodySafe = false;
                break;
            }
        if (!bodySafe)
            continue;

        size_t scopeEnd = lines.size();
        for (const ScalarFunctionSpan& owner : spans)
            if (owner.opener < opener && owner.end > function.end)
                scopeEnd = std::min(scopeEnd, owner.end);
        bool oldNameDead = true;
        for (size_t line = aliasLine + 1; line < scopeEnd; ++line)
            if (containsIdentifier(lines[line].text, assignment->target))
            {
                oldNameDead = false;
                break;
            }
        if (!oldNameDead)
            continue;

        const std::string_view value = trimView(assignment->value);
        lines[opener].text = std::string(function.indent, ' ') + "local function " + alias->target +
            std::string(value.substr(std::string_view("function").size()));
        lines[opener].states.insert(lines[aliasLine].states.begin(), lines[aliasLine].states.end());
        if (!lines[opener].origin && lines[aliasLine].origin)
            lines[opener].origin = lines[aliasLine].origin;
        lines[aliasLine].text.clear();
        ++promoted;
    }
    return promoted;
}

size_t scopeSingleUseSnapshotCallbacks(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    std::set<std::string> occupied = collectIdentifiers(lines);
    std::map<std::string, size_t> ordinals;

    auto allocateName = [&](std::string base) {
        size_t& ordinal = ordinals[base];
        std::string name;
        do
        {
            ++ordinal;
            name = ordinal == 1 ? base : base + "_" + std::to_string(ordinal);
        } while (occupied.contains(name));
        occupied.insert(name);
        return name;
    };

    auto roleForConsumer = [](std::string_view statement) {
        if (statement.find("pcall(") != std::string_view::npos ||
            statement.find("xpcall(") != std::string_view::npos)
            return std::string("protected_action");
        if (statement.find("task.spawn(") != std::string_view::npos ||
            statement.find("task.defer(") != std::string_view::npos ||
            statement.find("task.delay(") != std::string_view::npos ||
            statement.find(".spawn(") != std::string_view::npos ||
            statement.find(".defer(") != std::string_view::npos ||
            statement.find(".delay(") != std::string_view::npos)
            return std::string("task_callback");
        if (statement.find(":Connect(") != std::string_view::npos ||
            statement.find(".Connect(") != std::string_view::npos)
            return std::string("event_handler");
        return std::string("callback");
    };

    size_t scoped = 0;
    // Work from the bottom so line identities used by earlier candidates remain stable.
    for (size_t spanIndex = spans->size(); spanIndex > 0; --spanIndex)
    {
        const ScalarFunctionSpan& function = (*spans)[spanIndex - 1];
        if (function.opener >= lines.size() || function.end >= lines.size() || function.indent < 4)
            continue;
        auto assignment = simpleAssignment(lines[function.opener].text);
        if (!assignment || (!generatedLocal(assignment->target) && assignment->target != "temporary") ||
            !trimView(assignment->value).starts_with("function(") ||
            containsIdentifier(std::string_view(assignment->value).substr(8), assignment->target))
            continue;

        size_t blockOpen = function.opener;
        while (blockOpen > 0)
        {
            --blockOpen;
            const std::string_view statement = trimView(lines[blockOpen].text);
            const size_t indent = indentation(lines[blockOpen].text);
            if (indent < function.indent - 4)
                break;
            if (indent == function.indent - 4)
            {
                if (statement != "do")
                    blockOpen = function.opener;
                break;
            }
        }
        if (blockOpen >= function.opener || trimView(lines[blockOpen].text) != "do")
            continue;

        bool preludeSafe = true;
        for (size_t line = blockOpen + 1; line < function.opener; ++line)
        {
            const std::string_view statement = trimView(lines[line].text);
            if (statement.empty())
                continue;
            if (indentation(lines[line].text) != function.indent || !statement.starts_with("local snapshot_"))
            {
                preludeSafe = false;
                break;
            }
        }
        if (!preludeSafe)
            continue;

        size_t blockEnd = function.end + 1;
        while (blockEnd < lines.size() && trimView(lines[blockEnd].text).empty())
            ++blockEnd;
        if (blockEnd >= lines.size() || indentation(lines[blockEnd].text) != function.indent - 4 ||
            trimView(lines[blockEnd].text) != "end")
            continue;
        bool tailSafe = true;
        for (size_t line = function.end + 1; line < blockEnd; ++line)
            if (!trimView(lines[line].text).empty())
            {
                tailSafe = false;
                break;
            }
        if (!tailSafe)
            continue;

        size_t consumer = blockEnd + 1;
        while (consumer < lines.size() && trimView(lines[consumer].text).empty())
            ++consumer;
        if (consumer >= lines.size() || indentation(lines[consumer].text) != function.indent - 4 ||
            identifierOccurrences(lines[consumer].text, assignment->target) != 1 ||
            directlyWritesIdentifier(lines[consumer].text, assignment->target))
            continue;
        if (auto writes = identifierAssignmentList(lines[consumer].text);
            writes && std::find(writes->targets.begin(), writes->targets.end(), assignment->target) != writes->targets.end())
            continue;
        bool recursive = false;
        for (size_t line = function.opener + 1; line < function.end; ++line)
            if (containsIdentifier(lines[line].text, assignment->target))
            {
                recursive = true;
                break;
            }
        if (recursive)
            continue;

        const size_t scopeEnd = enclosingFunctionEnd(*spans, consumer, lines.size());
        size_t lifetimeEnd = scopeEnd;
        bool deadAfterConsumer = true;
        for (size_t line = consumer + 1; line < scopeEnd; ++line)
        {
            if (!containsIdentifier(lines[line].text, assignment->target))
                continue;
            auto overwrite = simpleAssignment(lines[line].text);
            deadAfterConsumer = overwrite && overwrite->target == assignment->target &&
                !trimView(lines[line].text).starts_with("local ") &&
                !containsIdentifier(overwrite->value, assignment->target);
            lifetimeEnd = line;
            break;
        }
        if (!deadAfterConsumer || captures.capturedBefore(blockOpen, assignment->target, lifetimeEnd))
            continue;

        const std::string callback = allocateName(roleForConsumer(lines[consumer].text));
        const std::string_view functionValue = trimView(assignment->value);
        lines[function.opener].text = std::string(function.indent, ' ') + "local function " + callback +
            std::string(functionValue.substr(std::string_view("function").size()));
        lines[blockEnd].text = std::string(function.indent, ' ') +
            trim(replaceIdentifier(lines[consumer].text, assignment->target, callback));
        lines[blockEnd].states.insert(lines[consumer].states.begin(), lines[consumer].states.end());
        if (!lines[blockEnd].origin && lines[consumer].origin)
            lines[blockEnd].origin = lines[consumer].origin;
        lines[consumer].text = std::string(function.indent - 4, ' ') + "end";
        ++scoped;
    }
    return scoped;
}

size_t eliminateRedundantAliasReloads(std::vector<OutputLine>& lines)
{
    struct Alias
    {
        std::string source;
    };
    std::map<std::string, Alias> active;
    size_t eliminated = 0;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        const std::string_view statement = trimView(lines[index].text);
        if (statement.empty())
            continue;
        const bool returns = statement.starts_with("return") && (statement.size() == 6 || statement[6] == ' ');
        if (controlBoundary(statement) || returns)
        {
            active.clear();
            continue;
        }

        auto assignment = simpleAssignment(lines[index].text);
        const bool aliasAssignment = assignment && generatedLocal(assignment->target) &&
            plainIdentifier(assignment->value) && assignment->target != trimView(assignment->value);
        if (aliasAssignment)
        {
            const std::string source = trim(assignment->value);
            auto previous = active.find(assignment->target);
            if (previous != active.end() && previous->second.source == source)
            {
                mergeRemovedProvenance(lines, index);
                lines[index].text.clear();
                ++eliminated;
                continue;
            }
        }

        if (assignment)
        {
            for (auto alias = active.begin(); alias != active.end();)
                if (alias->first == assignment->target || alias->second.source == assignment->target)
                    alias = active.erase(alias);
                else
                    ++alias;
        }
        else
        {
            for (auto alias = active.begin(); alias != active.end();)
                if (directlyWritesIdentifier(lines[index].text, alias->first) ||
                    directlyWritesIdentifier(lines[index].text, alias->second.source))
                    alias = active.erase(alias);
                else
                    ++alias;
        }

        if (aliasAssignment)
            active[assignment->target] = {trim(assignment->value)};

        // Calls can invoke closures that write captured locals, so aliases do not survive them.
        if (containsCallSyntax(lines[index].text) ||
            (statement.starts_with("local ") && statement.find('=') == std::string_view::npos))
            active.clear();
    }
    return eliminated;
}

bool identifierEvaluatedBeforeEffects(std::string_view line, std::string_view target)
{
    const auto position = soleIdentifierPosition(line, target);
    if (!position)
        return false;
    if (const auto equals = topLevelAssignmentEquals(line))
    {
        if (*position < *equals)
            return true;
        std::string_view value = trimView(line.substr(*equals + 1));
        while (value.starts_with('('))
            value = trimView(value.substr(1));
        return value.starts_with(target) &&
            (value.size() == target.size() ||
                (value[target.size()] != '_' && !std::isalnum(static_cast<unsigned char>(value[target.size()]))));
    }
    std::string_view statement = trimView(line);
    if (statement.starts_with(';'))
        statement = trimView(statement.substr(1));
    if (statement.starts_with("if ") && statement.ends_with(" then"))
    {
        statement = trimView(statement.substr(3, statement.size() - 3 - 5));
        while (statement.starts_with('('))
            statement = trimView(statement.substr(1));
        if (statement.starts_with("not "))
        {
            statement = trimView(statement.substr(4));
            while (statement.starts_with('('))
                statement = trimView(statement.substr(1));
        }
    }
    return (statement.starts_with(target) &&
               (statement.size() == target.size() ||
                   (statement[target.size()] != '_' && !std::isalnum(static_cast<unsigned char>(statement[target.size()]))))) ||
        (statement.starts_with("return ") && trimView(statement.substr(7)).starts_with(target));
}

bool literalTableFieldKey(std::string_view key)
{
    key = trimView(key);
    if (plainIdentifier(key))
        return true;
    if (key.size() < 2 || key.front() != '[' || key.back() != ']')
        return false;
    return scalarLiteral(trimView(key.substr(1, key.size() - 2)));
}

std::vector<std::string_view> topLevelTableFields(std::string_view body)
{
    std::vector<std::string_view> fields;
    size_t begin = 0;
    int parentheses = 0;
    int brackets = 0;
    int braces = 0;
    char quote = 0;
    bool escaped = false;
    for (size_t index = 0; index < body.size(); ++index)
    {
        const char ch = body[index];
        if (quote)
        {
            if (escaped)
                escaped = false;
            else if (ch == '\\')
                escaped = true;
            else if (ch == quote)
                quote = 0;
            continue;
        }
        if (ch == '\'' || ch == '"')
        {
            quote = ch;
            continue;
        }
        if (ch == '(')
            ++parentheses;
        else if (ch == ')')
            --parentheses;
        else if (ch == '[')
            ++brackets;
        else if (ch == ']')
            --brackets;
        else if (ch == '{')
            ++braces;
        else if (ch == '}')
            --braces;
        else if ((ch == ',' || ch == ';') && parentheses == 0 && brackets == 0 && braces == 0)
        {
            fields.push_back(trimView(body.substr(begin, index - begin)));
            begin = index + 1;
        }
        if (parentheses < 0 || brackets < 0 || braces < 0)
            return {};
    }
    if (quote || parentheses != 0 || brackets != 0 || braces != 0)
        return {};
    fields.push_back(trimView(body.substr(begin)));
    return fields;
}

bool identifierFollowsOnlyLiteralTableFields(std::string_view line, std::string_view target)
{
    const auto equals = topLevelAssignmentEquals(line);
    if (!equals)
        return false;
    std::string_view value = trimView(line.substr(*equals + 1));
    value = stripOuterParentheses(value);
    if (value.size() < 2 || value.front() != '{' || value.back() != '}')
        return false;

    for (std::string_view field : topLevelTableFields(value.substr(1, value.size() - 2)))
    {
        if (field.empty())
            continue;
        const auto fieldEquals = topLevelAssignmentEquals(field);
        const std::string_view fieldValue = fieldEquals ? trimView(field.substr(*fieldEquals + 1)) : field;
        if (fieldEquals && !literalTableFieldKey(field.substr(0, *fieldEquals)))
            return false;

        const size_t occurrences = identifierOccurrences(fieldValue, target);
        if (occurrences != 0)
            return occurrences == 1 && stripOuterParentheses(fieldValue) == target;
        if (!scalarLiteral(stripOuterParentheses(fieldValue)))
            return false;
    }
    return false;
}

size_t inlineAdjacentSingleUseGeneratedExpressions(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    const std::vector<size_t>& owner = captures.owner;
    const size_t topLevel = spans->size();
    const TemporaryBindingAnalysis temporaryBindings = analyzeTemporaryBindings(lines, *spans);

    size_t inlined = 0;
    for (size_t definition = 0; definition < lines.size(); ++definition)
    {
        auto assignment = simpleAssignment(lines[definition].text);
        const bool temporaryTarget = assignment && assignment->target == "temporary";
        const std::string_view target = assignment ? std::string_view(assignment->target) : std::string_view{};
        const bool registerTarget = assignment && target.starts_with("local_") && generatedLocal(target);
        const bool valueTarget = assignment && target.starts_with("value_") && target.size() > 6 &&
            std::all_of(target.begin() + 6, target.end(), [](char ch) {
                return std::isdigit(static_cast<unsigned char>(ch));
            });
        static const std::regex GenericSemanticEphemeral(
            R"(^(?:condition|number|flag|text|color|enum_value|encoded_value|asset_id)(?:_[0-9]+)?$)");
        const bool semanticEphemeralTarget = assignment &&
            (std::regex_match(std::string(target), GenericSemanticEphemeral) || target == "health");
        const bool localDefinition = trimView(lines[definition].text).starts_with("local ");
        const bool readableAliasTarget = assignment && localDefinition && plainIdentifier(trimView(assignment->value)) &&
            !target.starts_with("snapshot_") && target != trimView(assignment->value);
        if (!assignment || (!temporaryTarget && !registerTarget && !valueTarget && !semanticEphemeralTarget &&
                               !readableAliasTarget) ||
            (valueTarget && !localDefinition) ||
            (!valueTarget && !semanticEphemeralTarget && !readableAliasTarget && localDefinition) ||
            (!valueTarget && !semanticEphemeralTarget && !readableAliasTarget && !generatedLocal(assignment->target)) ||
            rejectedInlineLexicalConstruct(lines[definition].text) ||
            containsIdentifier(assignment->value, assignment->target))
            continue;
        if (temporaryTarget)
        {
            const auto binding = temporaryBindings.scopes.find(
                temporaryScopeKey(temporaryBindings.owners[definition]));
            if (binding == temporaryBindings.scopes.end() || !binding->second.declaration ||
                binding->second.duplicateDeclaration || *binding->second.declaration >= definition)
                continue;
        }
        const std::string expression = trim(assignment->value);
        const std::string_view normalized = trimView(expression);
        if (normalized.empty() || normalized.starts_with("function(") || normalized.starts_with("(function(") ||
            hasTopLevelComma(normalized))
            continue;

        size_t consumer = definition + 1;
        while (consumer < lines.size() && trimView(lines[consumer].text).empty())
            ++consumer;
        if (consumer >= lines.size() || owner[consumer] != owner[definition] ||
            indentation(lines[consumer].text) != indentation(lines[definition].text) ||
            rejectedInlineLexicalConstruct(lines[consumer].text))
            continue;
        const std::string_view consumerStatement = trimView(lines[consumer].text);
        if ((controlBoundary(consumerStatement) && !consumerStatement.starts_with("if ")) ||
            directlyWritesIdentifier(lines[consumer].text, assignment->target) ||
            identifierOccurrences(lines[consumer].text, assignment->target) != 1 ||
            (!identifierEvaluatedBeforeEffects(lines[consumer].text, assignment->target) &&
                !identifierFollowsOnlyLiteralTableFields(lines[consumer].text, assignment->target)))
            continue;
        if (auto writes = identifierAssignmentList(lines[consumer].text);
            writes && std::find(writes->targets.begin(), writes->targets.end(), assignment->target) != writes->targets.end())
            continue;

        const size_t scope = owner[definition];
        const size_t scopeEnd = scope == topLevel ? lines.size() : (*spans)[scope].end;
        size_t lifetimeEnd = scopeEnd;
        bool deadAfter = true;
        for (size_t line = consumer + 1; line < scopeEnd; ++line)
        {
            if (owner[line] != scope || !containsIdentifier(lines[line].text, assignment->target))
                continue;
            lifetimeEnd = line;
            auto overwrite = simpleAssignment(lines[line].text);
            deadAfter = overwrite && overwrite->target == assignment->target &&
                indentation(lines[line].text) == indentation(lines[definition].text) &&
                !trimView(lines[line].text).starts_with("local ") &&
                !containsIdentifier(overwrite->value, assignment->target);
            break;
        }
        if (!deadAfter || captures.capturedBefore(definition, assignment->target, lifetimeEnd))
            continue;

        const std::string rewritten = replaceIdentifier(
            lines[consumer].text, assignment->target, "(" + expression + ")");
        if (rewritten == lines[consumer].text)
            continue;
        lines[consumer].text = rewritten;
        lines[consumer].states.insert(lines[definition].states.begin(), lines[definition].states.end());
        if (!lines[consumer].origin && lines[definition].origin)
            lines[consumer].origin = lines[definition].origin;
        lines[definition].text.clear();
        ++inlined;
    }
    return inlined;
}

size_t inlineAdjacentLexicalAliases(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);

    size_t eliminated = 0;
    for (size_t definition = 0; definition < lines.size(); ++definition)
    {
        auto assignment = simpleAssignment(lines[definition].text);
        if (!assignment || !generatedLocal(assignment->target) || !plainIdentifier(trimView(assignment->value)) ||
            assignment->target == trimView(assignment->value) ||
            trimView(lines[definition].text).starts_with("local ") || rejectedInlineLexicalConstruct(lines[definition].text))
            continue;
        const std::string source = trim(assignment->value);
        const size_t indent = indentation(lines[definition].text);
        size_t consumer = definition + 1;
        while (consumer < lines.size() && trimView(lines[consumer].text).empty())
            ++consumer;
        if (consumer >= lines.size() || consumer >= enclosingFunctionEnd(*spans, definition, lines.size()) ||
            indentation(lines[consumer].text) != indent || rejectedInlineLexicalConstruct(lines[consumer].text) ||
            directlyWritesIdentifier(lines[consumer].text, assignment->target) ||
            directlyWritesIdentifier(lines[consumer].text, source) ||
            identifierOccurrences(lines[consumer].text, assignment->target) != 1)
            continue;
        if (auto writes = identifierAssignmentList(lines[consumer].text);
            writes && std::find(writes->targets.begin(), writes->targets.end(), assignment->target) != writes->targets.end())
            continue;

        if (!identifierEvaluatedBeforeEffects(lines[consumer].text, assignment->target))
            continue;

        bool deadAfter = true;
        const size_t scopeEnd = enclosingFunctionEnd(*spans, consumer, lines.size());
        size_t lifetimeEnd = scopeEnd;
        for (size_t next = consumer + 1; next < scopeEnd; ++next)
        {
            if (!containsIdentifier(lines[next].text, assignment->target))
                continue;
            lifetimeEnd = next;
            auto overwrite = simpleAssignment(lines[next].text);
            deadAfter = indentation(lines[next].text) == indent && overwrite &&
                overwrite->target == assignment->target && !containsIdentifier(overwrite->value, assignment->target);
            break;
        }
        if (!deadAfter)
            continue;
        if (captures.capturedBefore(definition, assignment->target, lifetimeEnd))
            continue;

        const std::string rewritten = replaceIdentifier(lines[consumer].text, assignment->target, source);
        if (rewritten == lines[consumer].text)
            continue;
        lines[consumer].text = rewritten;
        lines[consumer].states.insert(lines[definition].states.begin(), lines[definition].states.end());
        if (!lines[consumer].origin && lines[definition].origin)
            lines[consumer].origin = lines[definition].origin;
        lines[definition].text.clear();
        ++eliminated;
    }
    return eliminated;
}

size_t coalesceAdjacentProducerAliases(std::vector<OutputLine>& lines)
{
    std::map<std::string, size_t> mentionedLines;
    for (const OutputLine& line : lines)
        for (const std::string& name : lexicalIdentifiers(line.text))
            ++mentionedLines[name];

    size_t coalesced = 0;
    for (size_t definition = 0; definition < lines.size(); ++definition)
    {
        const auto producer = simpleAssignment(lines[definition].text);
        if (!producer || !trimView(lines[definition].text).starts_with("local ") ||
            containsIdentifier(producer->value, producer->target))
            continue;
        size_t aliasLine = definition + 1;
        while (aliasLine < lines.size() && trimView(lines[aliasLine].text).empty())
            ++aliasLine;
        if (aliasLine >= lines.size() || indentation(lines[aliasLine].text) != indentation(lines[definition].text))
            continue;
        const auto alias = simpleAssignment(lines[aliasLine].text);
        if (!alias || !trimView(lines[aliasLine].text).starts_with("local ") ||
            !plainIdentifier(alias->target) || trimView(alias->value) != producer->target ||
            alias->target == producer->target || containsIdentifier(producer->value, alias->target))
            continue;

        if (mentionedLines[producer->target] != 2)
            continue;

        lines[definition].text = std::string(indentation(lines[definition].text), ' ') +
            "local " + alias->target + " = " + producer->value;
        lines[definition].states.insert(lines[aliasLine].states.begin(), lines[aliasLine].states.end());
        if (!lines[definition].origin && lines[aliasLine].origin)
            lines[definition].origin = lines[aliasLine].origin;
        lines[aliasLine].text.clear();
        ++coalesced;
    }
    return coalesced;
}

size_t collapseGuardedReceiverSnapshots(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;

    size_t collapsed = 0;
    for (size_t aliasLine = 0; aliasLine < lines.size(); ++aliasLine)
    {
        const auto alias = simpleAssignment(lines[aliasLine].text);
        if (!alias || !trimView(lines[aliasLine].text).starts_with("local ") ||
            !plainIdentifier(alias->target) || !plainIdentifier(trimView(alias->value)) ||
            alias->target == trimView(alias->value))
            continue;
        const std::string source = trim(alias->value);
        const size_t indent = indentation(lines[aliasLine].text);
        size_t opener = aliasLine + 1;
        while (opener < lines.size() && trimView(lines[opener].text).empty())
            ++opener;
        if (opener >= lines.size() || indentation(lines[opener].text) != indent ||
            trimView(lines[opener].text) != "if " + source + " then")
            continue;

        size_t body = opener + 1;
        while (body < lines.size() && trimView(lines[body].text).empty())
            ++body;
        if (body >= lines.size() || indentation(lines[body].text) != indent + 4)
            continue;
        const auto update = simpleAssignment(lines[body].text);
        if (!update || !containsIdentifier(update->value, alias->target) ||
            containsIdentifier(update->value, source) || containsIdentifier(update->value, update->target))
            continue;

        size_t outputLine = aliasLine;
        if (update->target != source)
        {
            size_t initializer = aliasLine;
            while (initializer > 0)
            {
                --initializer;
                if (!trimView(lines[initializer].text).empty())
                    break;
            }
            const auto initial = simpleAssignment(lines[initializer].text);
            if (!initial || indentation(lines[initializer].text) != indent ||
                initial->target != update->target || trimView(initial->value) != source)
                continue;
            outputLine = initializer;
        }

        size_t closing = body + 1;
        while (closing < lines.size() && trimView(lines[closing].text).empty())
            ++closing;
        if (closing >= lines.size() || indentation(lines[closing].text) != indent ||
            trimView(lines[closing].text) != "end")
            continue;

        const size_t scopeEnd = enclosingFunctionEnd(*spans, closing, lines.size());
        bool aliasUsedLater = false;
        for (size_t line = closing + 1; line < scopeEnd && !aliasUsedLater; ++line)
            aliasUsedLater = containsIdentifier(lines[line].text, alias->target);
        if (aliasUsedLater)
            continue;

        const std::string guardedValue = replaceIdentifier(update->value, alias->target, source);
        lines[outputLine].text = std::string(indent, ' ') + update->target + " = " + source + " and (" + guardedValue + ")";
        lines[outputLine].states.insert(lines[aliasLine].states.begin(), lines[aliasLine].states.end());
        lines[outputLine].states.insert(lines[opener].states.begin(), lines[opener].states.end());
        lines[outputLine].states.insert(lines[body].states.begin(), lines[body].states.end());
        lines[outputLine].states.insert(lines[closing].states.begin(), lines[closing].states.end());
        if (outputLine != aliasLine)
            lines[aliasLine].text.clear();
        lines[opener].text.clear();
        lines[body].text.clear();
        lines[closing].text.clear();
        ++collapsed;
    }
    return collapsed;
}

size_t eliminateGuardedReceiverAliases(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    size_t eliminated = 0;
    for (size_t aliasLine = 0; aliasLine < lines.size(); ++aliasLine)
    {
        const auto alias = simpleAssignment(lines[aliasLine].text);
        if (!alias || !trimView(lines[aliasLine].text).starts_with("local ") ||
            !plainIdentifier(alias->target) || !plainIdentifier(trimView(alias->value)))
            continue;
        const std::string source = trim(alias->value);
        const size_t indent = indentation(lines[aliasLine].text);
        size_t opener = aliasLine + 1;
        while (opener < lines.size() && trimView(lines[opener].text).empty())
            ++opener;
        if (opener >= lines.size() || indentation(lines[opener].text) != indent ||
            trimView(lines[opener].text) != "if " + source + " then")
            continue;

        size_t closing = opener + 1;
        bool valid = true;
        bool sourceWritten = false;
        bool sawAliasRead = false;
        std::vector<size_t> rewrites;
        for (; closing < lines.size(); ++closing)
        {
            const std::string_view statement = trimView(lines[closing].text);
            if (statement.empty())
                continue;
            if (indentation(lines[closing].text) == indent && statement == "end")
                break;
            if (indentation(lines[closing].text) != indent + 4 || controlBoundary(statement))
            {
                valid = false;
                break;
            }
            const size_t aliasReads = identifierOccurrences(lines[closing].text, alias->target);
            if (aliasReads != 0)
            {
                if (sourceWritten || directlyWritesIdentifier(lines[closing].text, alias->target))
                {
                    valid = false;
                    break;
                }
                sawAliasRead = true;
                rewrites.push_back(closing);
            }
            if (directlyWritesIdentifier(lines[closing].text, source))
                sourceWritten = true;
        }
        if (!valid || !sawAliasRead || closing >= lines.size())
            continue;

        const size_t scopeEnd = enclosingFunctionEnd(*spans, closing, lines.size());
        bool usedLater = false;
        for (size_t line = closing + 1; line < scopeEnd && !usedLater; ++line)
            usedLater = containsIdentifier(lines[line].text, alias->target);
        if (usedLater)
            continue;

        for (size_t line : rewrites)
            lines[line].text = replaceIdentifier(lines[line].text, alias->target, source);
        lines[opener].states.insert(lines[aliasLine].states.begin(), lines[aliasLine].states.end());
        lines[aliasLine].text.clear();
        ++eliminated;
    }
    return eliminated;
}

size_t coalesceStraightLineAliases(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);

    size_t eliminated = 0;
    for (size_t definition = 0; definition < lines.size(); ++definition)
    {
        auto assignment = simpleAssignment(lines[definition].text);
        if (!assignment || !generatedLocal(assignment->target) || !plainIdentifier(trimView(assignment->value)) ||
            assignment->target == trimView(assignment->value) || trimView(lines[definition].text).starts_with("local ") ||
            rejectedInlineLexicalConstruct(lines[definition].text))
            continue;
        const std::string source = trim(assignment->value);
        const size_t indent = indentation(lines[definition].text);
        const size_t scopeEnd = enclosingFunctionEnd(*spans, definition, lines.size());
        if (captures.capturedBefore(definition, assignment->target, scopeEnd))
            continue;
        std::vector<std::pair<size_t, std::string>> rewrites;
        bool provenDead = false;
        bool rejected = false;

        for (size_t index = definition + 1; index < scopeEnd; ++index)
        {
            const std::string_view statement = trimView(lines[index].text);
            if (statement.empty())
                continue;
            const auto writes = identifierAssignmentList(lines[index].text);
            auto nextAssignment = simpleAssignment(lines[index].text);
            if (nextAssignment && nextAssignment->target == assignment->target)
            {
                provenDead = !containsIdentifier(nextAssignment->value, assignment->target) &&
                    indentation(lines[index].text) == indent;
                rejected = !provenDead;
                break;
            }

            const size_t occurrences = identifierOccurrences(lines[index].text, assignment->target);
            if (occurrences != 0)
            {
                if (occurrences != 1 || directlyWritesIdentifier(lines[index].text, assignment->target) ||
                    (writes && std::find(writes->targets.begin(), writes->targets.end(), assignment->target) !=
                            writes->targets.end()) ||
                    !identifierEvaluatedBeforeEffects(lines[index].text, assignment->target))
                {
                    rejected = true;
                    break;
                }
                rewrites.emplace_back(index, replaceIdentifier(lines[index].text, assignment->target, source));
            }

            const bool sourceWrite = (nextAssignment && nextAssignment->target == source) ||
                directlyWritesIdentifier(lines[index].text, source) ||
                (writes && std::find(writes->targets.begin(), writes->targets.end(), source) != writes->targets.end());
            const bool barrier = controlBoundary(statement) || containsCallSyntax(statement) || sourceWrite;
            if (!barrier)
                continue;

            provenDead = true;
            for (size_t next = index + 1; next < scopeEnd; ++next)
            {
                if (!containsIdentifier(lines[next].text, assignment->target))
                    continue;
                auto overwrite = simpleAssignment(lines[next].text);
                provenDead = indentation(lines[next].text) == indent && overwrite &&
                    overwrite->target == assignment->target && !containsIdentifier(overwrite->value, assignment->target);
                break;
            }
            rejected = !provenDead;
            break;
        }
        if (!rejected && !provenDead)
            provenDead = true;
        if (!provenDead || rejected || rewrites.empty())
            continue;

        size_t next = definition + 1;
        while (next < lines.size() && trimView(lines[next].text).empty())
            ++next;
        if (next < lines.size() && trimView(lines[next].text).starts_with(";("))
            continue;
        for (auto& [line, rewritten] : rewrites)
            lines[line].text = std::move(rewritten);
        const size_t provenance = rewrites.empty() ? next : rewrites.front().first;
        if (provenance < lines.size())
        {
            lines[provenance].states.insert(lines[definition].states.begin(), lines[definition].states.end());
            if (!lines[provenance].origin && lines[definition].origin)
                lines[provenance].origin = lines[definition].origin;
        }
        lines[definition].text.clear();
        ++eliminated;
    }
    return eliminated;
}

size_t propagateStableReadableAliases(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const size_t topLevel = spans->size();
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    const std::vector<size_t>& owner = captures.owner;

    std::vector<std::map<std::string, size_t>> declaredAt(spans->size() + 1);
    for (size_t scope = 0; scope <= topLevel; ++scope)
    {
        const size_t begin = scope == topLevel ? 0 : (*spans)[scope].opener + 1;
        const size_t end = scope == topLevel ? lines.size() : (*spans)[scope].end;
        const size_t scopeIndent = scope == topLevel ? 0 : (*spans)[scope].indent + 4;
        if (scope != topLevel)
        {
            const std::string_view opener = trimView(lines[(*spans)[scope].opener].text);
            const size_t function = opener.find("function");
            const size_t open = function == std::string_view::npos ? std::string_view::npos : opener.find('(', function + 8);
            const size_t close = open == std::string_view::npos ? std::string_view::npos : opener.find(')', open + 1);
            if (close != std::string_view::npos)
                for (const std::string& parameter : splitCaptureExpressions(opener.substr(open + 1, close - open - 1)))
                    if (plainIdentifier(parameter))
                        declaredAt[scope].emplace(parameter, begin);
        }
        for (size_t line = begin; line < end; ++line)
        {
            if (owner[line] != scope || indentation(lines[line].text) != scopeIndent)
                continue;
            if (auto declarations = plainLocalDeclaration(lines[line].text))
                for (const std::string& name : *declarations)
                    declaredAt[scope].emplace(name, line);
            const std::string_view statement = trimView(lines[line].text);
            if (statement.starts_with("local "))
                if (auto declaration = identifierAssignmentList(lines[line].text))
                    for (const std::string& name : declaration->targets)
                        declaredAt[scope].emplace(name, line);
            if (statement.starts_with("local function "))
            {
                std::string_view name = statement.substr(15);
                const size_t open = name.find('(');
                if (open != std::string_view::npos && plainIdentifier(trimView(name.substr(0, open))))
                    declaredAt[scope].emplace(std::string(trimView(name.substr(0, open))), line);
            }
        }
    }

    size_t eliminated = 0;
    for (size_t definition = 0; definition < lines.size(); ++definition)
    {
        auto assignment = simpleAssignment(lines[definition].text);
        const std::string_view target = assignment ? std::string_view(assignment->target) : std::string_view{};
        const bool registerTarget = assignment && target.starts_with("local_") && generatedLocal(target);
        const bool valueTarget = assignment && target.starts_with("value_") && target.size() > 6 &&
            std::all_of(target.begin() + 6, target.end(), [](char ch) {
                return std::isdigit(static_cast<unsigned char>(ch));
            });
        const bool localDefinition = trimView(lines[definition].text).starts_with("local ");
        if (!assignment || (!registerTarget && !valueTarget) || valueTarget != localDefinition ||
            !plainIdentifier(trimView(assignment->value)) ||
            generatedLocal(trimView(assignment->value)) || capturedLocal(trimView(assignment->value)) ||
            (!valueTarget && localDefinition))
            continue;
        const size_t scope = owner[definition];
        const std::string source = trim(assignment->value);
        const auto declaration = declaredAt[scope].find(source);
        const size_t indent = indentation(lines[definition].text);
        const size_t scopeIndent = scope == topLevel ? 0 : (*spans)[scope].indent + 4;
        size_t blockEnd = scope == topLevel ? lines.size() : (*spans)[scope].end;
        if (indent > scopeIndent)
            for (size_t line = definition + 1; line < blockEnd; ++line)
                if (owner[line] == scope && !trimView(lines[line].text).empty() &&
                    indentation(lines[line].text) < indent)
                {
                    blockEnd = line;
                    break;
                }
        bool sameBlockDeclaration = false;
        if (declaration == declaredAt[scope].end() || declaration->second > definition)
        {
            for (size_t previous = definition; previous > 0;)
            {
                --previous;
                if (owner[previous] != scope)
                    continue;
                const std::string_view previousStatement = trimView(lines[previous].text);
                const size_t previousIndent = indentation(lines[previous].text);
                if (previousIndent < indent &&
                    (previousStatement == "else" || previousStatement.starts_with("elseif ") ||
                        previousStatement.starts_with("until ")))
                    break;
                if (previousIndent != indent || !previousStatement.starts_with("local "))
                    continue;
                if (auto declarations = plainLocalDeclaration(lines[previous].text);
                    declarations && std::find(declarations->begin(), declarations->end(), source) != declarations->end())
                    sameBlockDeclaration = true;
                if (auto assignments = identifierAssignmentList(lines[previous].text);
                    assignments && std::find(assignments->targets.begin(), assignments->targets.end(), source) !=
                            assignments->targets.end())
                    sameBlockDeclaration = true;
                if (sameBlockDeclaration)
                    break;
            }
            if (!sameBlockDeclaration)
                continue;
        }
        size_t lifetimeEnd = blockEnd;
        size_t reads = 0;
        bool unsafe = false;
        for (size_t line = definition + 1; line < blockEnd; ++line)
        {
            if (owner[line] != scope)
                continue;
            if (auto overwrite = simpleAssignment(lines[line].text);
                overwrite && overwrite->target == assignment->target)
            {
                if (indentation(lines[line].text) != indent || trimView(lines[line].text).starts_with("local ") ||
                    containsIdentifier(overwrite->value, assignment->target))
                    unsafe = true;
                lifetimeEnd = line;
                break;
            }
            if (directlyWritesIdentifier(lines[line].text, source) || compoundTarget(lines[line].text, assignment->target))
            {
                unsafe = true;
                break;
            }
            if (auto writes = identifierAssignmentList(lines[line].text))
            {
                if (std::find(writes->targets.begin(), writes->targets.end(), assignment->target) != writes->targets.end() ||
                    std::find(writes->targets.begin(), writes->targets.end(), source) != writes->targets.end())
                {
                    unsafe = true;
                    break;
                }
            }
            reads += identifierOccurrences(lines[line].text, assignment->target);
        }
        if (unsafe || reads == 0)
            continue;
        if (captures.capturedBefore(definition, assignment->target, lifetimeEnd) ||
            captures.capturedBefore(definition, source, lifetimeEnd))
            continue;
        for (size_t line = definition + 1; line < lifetimeEnd; ++line)
            if (owner[line] == scope)
                lines[line].text = replaceIdentifier(lines[line].text, assignment->target, source);
        size_t anchor = definition + 1;
        while (anchor < lifetimeEnd && trimView(lines[anchor].text).empty())
            ++anchor;
        if (anchor < lines.size())
        {
            lines[anchor].states.insert(lines[definition].states.begin(), lines[definition].states.end());
            if (!lines[anchor].origin && lines[definition].origin)
                lines[anchor].origin = lines[definition].origin;
        }
        lines[definition].text.clear();
        ++eliminated;
    }
    return eliminated;
}

size_t eliminateUnobservedPureVersions(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const size_t topLevel = spans->size();
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    const std::vector<size_t>& owner = captures.owner;

    std::vector<bool> remove(lines.size(), false);
    size_t removed = 0;
    size_t callsDiscarded = 0;
    static const std::regex StandaloneCall(
        R"(^[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|:)[A-Za-z_][A-Za-z0-9_]*)*\(.*\)$)");
    for (size_t definition = 0; definition < lines.size(); ++definition)
    {
        auto assignment = simpleAssignment(lines[definition].text);
        const bool standaloneCall = assignment &&
            std::regex_match(std::string(trimView(assignment->value)), StandaloneCall);
        if (!assignment || !std::string_view(assignment->target).starts_with("local_") ||
            !generatedLocal(assignment->target) || trimView(lines[definition].text).starts_with("local ") ||
            (!pureAssignmentValue(assignment->value) && !standaloneCall))
            continue;
        const size_t scope = owner[definition];
        const size_t scopeEnd = scope == topLevel ? lines.size() : (*spans)[scope].end;
        size_t lifetimeEnd = scopeEnd;
        bool dead = true;
        for (size_t line = definition + 1; line < scopeEnd; ++line)
        {
            if (owner[line] != scope || !containsIdentifier(lines[line].text, assignment->target))
                continue;
            lifetimeEnd = line;
            auto overwrite = simpleAssignment(lines[line].text);
            dead = overwrite && overwrite->target == assignment->target &&
                indentation(lines[line].text) == indentation(lines[definition].text) &&
                !trimView(lines[line].text).starts_with("local ") &&
                !containsIdentifier(overwrite->value, assignment->target);
            break;
        }
        if (!dead || captures.capturedBefore(definition, assignment->target, lifetimeEnd))
            continue;
        size_t next = definition + 1;
        while (next < lines.size() && trimView(lines[next].text).empty())
            ++next;
        if (next < lines.size() && trimView(lines[next].text).starts_with(";("))
            continue;
        if (standaloneCall && !pureAssignmentValue(assignment->value))
        {
            lines[definition].text = std::string(indentation(lines[definition].text), ' ') + assignment->value;
            ++callsDiscarded;
            continue;
        }
        remove[definition] = true;
        ++removed;
    }
    if (removed == 0)
        return callsDiscarded;
    for (size_t line = 0; line < lines.size(); ++line)
    {
        if (!remove[line] || lines[line].states.empty())
            continue;
        size_t anchor = line + 1;
        while (anchor < lines.size() && remove[anchor])
            ++anchor;
        if (anchor < lines.size())
        {
            lines[anchor].states.insert(lines[line].states.begin(), lines[line].states.end());
            if (!lines[anchor].origin && lines[line].origin)
                lines[anchor].origin = lines[line].origin;
        }
    }
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t line = 0; line < lines.size(); ++line)
        if (!remove[line])
            compacted.push_back(std::move(lines[line]));
    lines = std::move(compacted);
    return removed + callsDiscarded;
}

size_t eliminateWriteOnlyResultPacks(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    const size_t topLevel = spans->size();
    static const std::regex StandaloneCall(
        R"(^[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|:)[A-Za-z_][A-Za-z0-9_]*)*\(.*\)$)");

    auto pureTable = [](std::string_view value) {
        value = stripOuterParentheses(trimView(value));
        if (value.size() < 2 || value.front() != '{' || value.back() != '}')
            return false;
        for (std::string entry : splitCaptureExpressions(value.substr(1, value.size() - 2)))
        {
            std::string_view expression = trimView(entry);
            if (const size_t equals = expression.find('='); equals != std::string_view::npos)
                expression = trimView(expression.substr(equals + 1));
            if (!expression.empty() && !pureAssignmentValue(expression))
                return false;
        }
        return true;
    };

    size_t removed = 0;
    for (size_t scope = 0; scope <= topLevel; ++scope)
    {
        const size_t begin = scope == topLevel ? 0 : (*spans)[scope].opener + 1;
        const size_t end = scope == topLevel ? lines.size() : (*spans)[scope].end;
        std::vector<size_t> declarations;
        std::vector<std::pair<size_t, std::string>> assignments;
        bool read = false;
        for (size_t line = begin; line < end; ++line)
        {
            if (captures.owner[line] != scope)
                continue;
            if (trimView(lines[line].text) == "local __results")
            {
                declarations.push_back(line);
                continue;
            }
            if (!containsIdentifier(lines[line].text, "__results"))
                continue;
            if (auto assignment = simpleAssignment(lines[line].text);
                assignment && assignment->target == "__results")
            {
                if (containsIdentifier(assignment->value, "__results"))
                    read = true;
                assignments.emplace_back(line, assignment->value);
            }
            else
                read = true;
        }
        if (read || declarations.size() != 1)
            continue;

        struct Replacement
        {
            size_t line = 0;
            std::string text;
        };
        std::vector<Replacement> replacements;
        bool safe = true;
        for (const auto& [line, valueText] : assignments)
        {
            const std::string_view value = stripOuterParentheses(trimView(valueText));
            if (pureTable(value))
            {
                replacements.push_back({line, {}});
                continue;
            }
            if (value.size() >= 2 && value.front() == '{' && value.back() == '}')
            {
                const std::vector<std::string> entries =
                    splitCaptureExpressions(value.substr(1, value.size() - 2));
                if (entries.size() == 1 &&
                    std::regex_match(std::string(trimView(entries.front())), StandaloneCall))
                {
                    replacements.push_back(
                        {line, std::string(indentation(lines[line].text), ' ') + trim(entries.front())});
                    continue;
                }
            }
            safe = false;
            break;
        }
        if (!safe)
            continue;
        lines[declarations.front()].text.clear();
        for (Replacement& replacement : replacements)
        {
            lines[replacement.line].text = std::move(replacement.text);
            ++removed;
        }
    }
    return removed;
}

struct ResultProjection
{
    std::string table;
    int64_t slot = 0;
};

struct ConstantLvaluePath
{
    std::string base;
    std::vector<int64_t> indices;

    std::string rendered() const
    {
        std::string result = base;
        for (int64_t index : indices)
            result += "[" + std::to_string(index) + "]";
        return result;
    }
};

std::optional<ConstantLvaluePath> constantLvaluePath(std::string_view value)
{
    value = stripOuterParentheses(trimView(value));
    auto identifierStart = [](char ch) {
        return ch == '_' || std::isalpha(static_cast<unsigned char>(ch));
    };
    auto identifier = [](char ch) {
        return ch == '_' || std::isalnum(static_cast<unsigned char>(ch));
    };
    if (value.empty() || !identifierStart(value.front()))
        return std::nullopt;
    size_t cursor = 1;
    while (cursor < value.size() && identifier(value[cursor]))
        ++cursor;
    ConstantLvaluePath result{std::string(value.substr(0, cursor)), {}};
    while (cursor < value.size())
    {
        while (cursor < value.size() && std::isspace(static_cast<unsigned char>(value[cursor])))
            ++cursor;
        if (cursor >= value.size() || value[cursor++] != '[')
            return std::nullopt;
        while (cursor < value.size() && std::isspace(static_cast<unsigned char>(value[cursor])))
            ++cursor;
        const size_t begin = cursor;
        if (cursor < value.size() && value[cursor] == '-')
            ++cursor;
        const size_t digits = cursor;
        while (cursor < value.size() && std::isdigit(static_cast<unsigned char>(value[cursor])))
            ++cursor;
        if (cursor == digits)
            return std::nullopt;
        const auto index = parseInteger(value.substr(begin, cursor - begin));
        if (!index)
            return std::nullopt;
        while (cursor < value.size() && std::isspace(static_cast<unsigned char>(value[cursor])))
            ++cursor;
        if (cursor >= value.size() || value[cursor++] != ']')
            return std::nullopt;
        result.indices.push_back(*index);
    }
    return result;
}

struct ConstantPathAssignment
{
    ConstantLvaluePath target;
    std::string value;
    bool local = false;
};

std::optional<ConstantPathAssignment> constantPathAssignment(std::string_view line)
{
    const auto equals = topLevelAssignmentEquals(line);
    if (!equals)
        return std::nullopt;
    std::string_view target = trimView(line.substr(0, *equals));
    bool local = false;
    if (target.starts_with("local "))
    {
        local = true;
        target = trimView(target.substr(6));
    }
    const auto path = constantLvaluePath(target);
    if (!path)
        return std::nullopt;
    return ConstantPathAssignment{*path, trim(line.substr(*equals + 1)), local};
}

bool pathExtendsByOneSlot(const ConstantLvaluePath& value, const ConstantLvaluePath& prefix, int64_t& slot)
{
    if (value.base != prefix.base || value.indices.size() != prefix.indices.size() + 1 ||
        !std::equal(prefix.indices.begin(), prefix.indices.end(), value.indices.begin()))
        return false;
    slot = value.indices.back();
    return slot > 0;
}

bool provenPrivateConstantTable(
    const std::vector<OutputLine>& lines, const std::vector<ScalarFunctionSpan>& spans, std::string_view table)
{
    std::vector<size_t> declarations;
    for (size_t line = 0; line < lines.size(); ++line)
        if (auto names = plainLocalDeclaration(lines[line].text);
            names && std::find(names->begin(), names->end(), table) != names->end())
            declarations.push_back(line);
    if (declarations.size() != 1)
        return false;

    const size_t declaration = declarations.front();
    size_t scopeBegin = 0;
    size_t scopeEnd = lines.size();
    size_t expectedIndent = 0;
    std::optional<ScalarFunctionSpan> owner;
    for (const ScalarFunctionSpan& span : spans)
        if (span.opener < declaration && declaration < span.end && (!owner || span.opener > owner->opener))
            owner = span;
    if (owner)
    {
        scopeBegin = owner->opener + 1;
        scopeEnd = owner->end;
        expectedIndent = owner->indent + 4;
    }
    if (indentation(lines[declaration].text) != expectedIndent)
        return false;

    size_t allocations = 0;
    size_t allocationLine = lines.size();
    size_t firstAccess = lines.size();
    for (size_t line = 0; line < lines.size(); ++line)
    {
        if (!containsIdentifier(lines[line].text, table) || line == declaration)
            continue;
        if (line < scopeBegin || line >= scopeEnd)
            return false;
        if (auto assignment = simpleAssignment(lines[line].text);
            assignment && assignment->target == table && trimView(assignment->value) == "{}" &&
            !trimView(lines[line].text).starts_with("local ") && indentation(lines[line].text) == expectedIndent)
        {
            ++allocations;
            allocationLine = line;
            continue;
        }
        const ConstantSlotScan scan = scanConstantSlotAccesses(lines[line].text, table);
        if (!scan.valid || scan.accesses == 0)
            return false;
        firstAccess = std::min(firstAccess, line);
    }
    return allocations == 1 && declaration < allocationLine && allocationLine < firstAccess;
}

size_t collapseResultPacksIntoSafeLvalues(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    std::map<std::string, bool> privateTables;
    auto privateTable = [&](const std::string& name) {
        auto [found, inserted] = privateTables.emplace(name, false);
        if (inserted)
            found->second = provenPrivateConstantTable(lines, *spans, name);
        return found->second;
    };

    size_t collapsed = 0;
    for (size_t packLine = 0; packLine < lines.size(); ++packLine)
    {
        const auto pack = constantPathAssignment(lines[packLine].text);
        if (!pack || pack->local)
            continue;
        const bool plainPack = pack->target.indices.empty() &&
            (generatedLocal(pack->target.base) || pack->target.base.starts_with("values_") ||
                pack->target.base.starts_with("iterator_values_"));
        const bool indexedPack = pack->target.indices.size() == 1 && privateTable(pack->target.base);
        if (!plainPack && !indexedPack)
            continue;
        const std::string_view constructor = stripOuterParentheses(trimView(pack->value));
        if (constructor.size() < 3 || constructor.front() != '{' || constructor.back() != '}')
            continue;
        const std::vector<std::string> values =
            splitCaptureExpressions(constructor.substr(1, constructor.size() - 2));
        if (values.size() != 1 || !containsCallSyntax(values.front()))
            continue;

        struct Projection
        {
            ConstantLvaluePath destination;
            size_t line = 0;
        };
        std::map<int64_t, Projection> projections;
        std::set<std::string> destinations;
        std::set<std::string> interveningAliasTargets;
        size_t cursor = packLine + 1;
        size_t lastProjection = packLine;
        bool rejected = false;
        while (cursor < lines.size())
        {
            const std::string_view statement = trimView(lines[cursor].text);
            if (statement.empty() || statement == "end")
            {
                ++cursor;
                continue;
            }
            const auto projection = constantPathAssignment(lines[cursor].text);
            const auto source = projection ? constantLvaluePath(projection->value) : std::nullopt;
            int64_t slot = 0;
            if (!projection || projection->local || !source || !pathExtendsByOneSlot(*source, pack->target, slot))
            {
                const auto alias = constantPathAssignment(lines[cursor].text);
                const auto aliasSource = alias ? constantLvaluePath(alias->value) : std::nullopt;
                if (alias && !alias->local && alias->target.indices.empty() && aliasSource &&
                    destinations.contains(aliasSource->rendered()) &&
                    interveningAliasTargets.insert(alias->target.rendered()).second)
                {
                    ++cursor;
                    continue;
                }
                break;
            }
            if (projections.contains(slot) || projection->target.rendered() == pack->target.rendered())
            {
                rejected = true;
                break;
            }
            if (!projection->target.indices.empty() &&
                (projection->target.indices.size() != 1 || !privateTable(projection->target.base)))
            {
                rejected = true;
                break;
            }
            const std::string destination = projection->target.rendered();
            if (interveningAliasTargets.contains(destination) || !destinations.insert(destination).second)
            {
                rejected = true;
                break;
            }
            for (const auto& [existingSlot, existing] : projections)
            {
                (void)existingSlot;
                if ((projection->target.indices.empty() && projection->target.base == existing.destination.base) ||
                    (existing.destination.indices.empty() && existing.destination.base == projection->target.base))
                {
                    rejected = true;
                    break;
                }
            }
            if (rejected)
                break;
            projections.emplace(slot, Projection{projection->target, cursor});
            lastProjection = cursor;
            ++cursor;
        }
        if (rejected || projections.empty())
            continue;
        const int64_t maximum = projections.rbegin()->first;
        if (maximum <= 0 || static_cast<size_t>(maximum) != projections.size())
            continue;
        bool contiguous = true;
        for (int64_t slot = 1; slot <= maximum; ++slot)
            contiguous = contiguous && projections.contains(slot);
        if (!contiguous)
            continue;

        const size_t scopeEnd = enclosingFunctionEnd(*spans, packLine, lines.size());
        const std::string carrier = pack->target.rendered();
        size_t lifetimeEnd = scopeEnd;
        bool deadAfter = true;
        for (size_t line = lastProjection + 1; line < scopeEnd; ++line)
        {
            const bool mentions = pack->target.indices.empty()
                ? containsIdentifier(lines[line].text, pack->target.base)
                : lines[line].text.find(carrier) != std::string::npos;
            if (!mentions)
                continue;
            const auto overwrite = constantPathAssignment(lines[line].text);
            deadAfter = overwrite && !overwrite->local && overwrite->target.rendered() == carrier &&
                overwrite->value.find(carrier) == std::string::npos;
            if (!deadAfter && pack->target.indices.empty())
                if (auto writes = identifierAssignmentList(lines[line].text);
                    writes && std::find(writes->targets.begin(), writes->targets.end(), pack->target.base) != writes->targets.end())
                    deadAfter = !containsIdentifier(
                        std::string_view(lines[line].text).substr(writes->value_begin), pack->target.base);
            lifetimeEnd = line;
            break;
        }
        if (!deadAfter || (pack->target.indices.empty() &&
                              captures.capturedBefore(packLine, pack->target.base, lifetimeEnd)))
            continue;

        std::string replacement(indentation(lines[packLine].text), ' ');
        for (int64_t slot = 1; slot <= maximum; ++slot)
        {
            if (slot > 1)
                replacement += ", ";
            replacement += projections.at(slot).destination.rendered();
        }
        replacement += " = " + trim(values.front());
        lines[packLine].text = std::move(replacement);
        for (const auto& [slot, projection] : projections)
        {
            (void)slot;
            lines[packLine].states.insert(lines[projection.line].states.begin(), lines[projection.line].states.end());
            if (!lines[packLine].origin && lines[projection.line].origin)
                lines[packLine].origin = lines[projection.line].origin;
            lines[projection.line].text.clear();
        }
        ++collapsed;
    }
    return collapsed;
}

std::optional<ResultProjection> resultProjection(std::string_view value)
{
    static const std::regex Projection(
        R"(^\s*\(?([A-Za-z_][A-Za-z0-9_]*)\)?\s*\[\s*([1-9][0-9]*)\s*\]\s*$)");
    std::smatch match;
    const std::string text(value);
    if (!std::regex_match(text, match, Projection))
        return std::nullopt;
    const auto slot = parseInteger(match[2].str());
    if (!slot)
        return std::nullopt;
    return ResultProjection{match[1].str(), *slot};
}

size_t collapseContiguousResultPacks(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);

    size_t collapsed = 0;
    for (size_t packLine = 0; packLine < lines.size(); ++packLine)
    {
        auto pack = simpleAssignment(lines[packLine].text);
        const std::string_view packName = pack ? std::string_view(pack->target) : std::string_view{};
        const bool generatedPack = pack && generatedLocal(pack->target) && packName.starts_with("local_");
        const bool semanticPack = pack && (packName.starts_with("values_") || packName.starts_with("iterator_values_"));
        if (!pack || (!generatedPack && !semanticPack))
            continue;
        std::string_view constructor = stripOuterParentheses(trimView(pack->value));
        if (constructor.size() < 3 || constructor.front() != '{' || constructor.back() != '}')
            continue;
        const std::vector<std::string> values =
            splitCaptureExpressions(constructor.substr(1, constructor.size() - 2));
        if (values.size() != 1 || !containsCallSyntax(values.front()))
            continue;

        const size_t indent = indentation(lines[packLine].text);
        std::map<int64_t, std::pair<std::string, size_t>> projections;
        std::set<std::string> targets;
        std::optional<bool> localTargets;
        size_t cursor = packLine + 1;
        size_t lastProjection = packLine;
        while (cursor < lines.size())
        {
            if (trimView(lines[cursor].text).empty())
            {
                ++cursor;
                continue;
            }
            if (indentation(lines[cursor].text) != indent)
                break;
            auto assignment = simpleAssignment(lines[cursor].text);
            auto projection = assignment ? resultProjection(assignment->value) : std::nullopt;
            if (!assignment || !projection || projection->table != pack->target || assignment->target == pack->target ||
                projections.contains(projection->slot) || targets.contains(assignment->target))
                break;
            const bool local = trimView(lines[cursor].text).starts_with("local ");
            if (localTargets && *localTargets != local)
                break;
            localTargets = local;
            projections[projection->slot] = {assignment->target, cursor};
            targets.insert(assignment->target);
            lastProjection = cursor;
            ++cursor;
        }
        if (projections.empty() || !localTargets)
            continue;
        const int64_t maximum = projections.rbegin()->first;
        if (maximum <= 0 || static_cast<size_t>(maximum) != projections.size())
            continue;
        bool contiguous = true;
        for (int64_t slot = 1; slot <= maximum; ++slot)
            if (!projections.contains(slot))
                contiguous = false;
        if (!contiguous)
            continue;

        const size_t scopeEnd = enclosingFunctionEnd(*spans, packLine, lines.size());
        size_t lifetimeEnd = scopeEnd;
        bool deadAfter = true;
        for (size_t line = lastProjection + 1; line < scopeEnd; ++line)
        {
            if (!containsIdentifier(lines[line].text, pack->target))
                continue;
            auto overwrite = simpleAssignment(lines[line].text);
            deadAfter = overwrite && overwrite->target == pack->target && indentation(lines[line].text) == indent &&
                !trimView(lines[line].text).starts_with("local ") &&
                !containsIdentifier(overwrite->value, pack->target);
            lifetimeEnd = line;
            break;
        }
        if (!deadAfter || captures.capturedBefore(packLine, pack->target, lifetimeEnd))
            continue;

        std::string replacement(indent, ' ');
        if (*localTargets)
            replacement += "local ";
        for (int64_t slot = 1; slot <= maximum; ++slot)
        {
            if (slot > 1)
                replacement += ", ";
            replacement += projections.at(slot).first;
        }
        replacement += " = ";
        replacement += values.front();
        lines[packLine].text = std::move(replacement);
        for (const auto& [slot, projection] : projections)
        {
            (void)slot;
            const size_t line = projection.second;
            lines[packLine].states.insert(lines[line].states.begin(), lines[line].states.end());
            if (!lines[packLine].origin && lines[line].origin)
                lines[packLine].origin = lines[line].origin;
            lines[line].text.clear();
        }
        ++collapsed;
    }
    return collapsed;
}

size_t scalarizeSparseResultPacks(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    std::set<std::string> occupied = collectIdentifiers(lines);
    size_t resultOrdinal = 0;
    size_t scalarized = 0;

    for (size_t packLine = 0; packLine < lines.size(); ++packLine)
    {
        auto pack = simpleAssignment(lines[packLine].text);
        if (!pack || !plainIdentifier(pack->target))
            continue;
        const std::string_view packName = pack->target;
        const bool generatedPack = generatedLocal(packName);
        const bool semanticPack = packName.starts_with("values_") || packName.starts_with("iterator_values_") ||
            packName == "values" || packName == "iterator_values" || packName == "children";
        if (!generatedPack && !semanticPack)
            continue;

        std::string_view constructor = stripOuterParentheses(trimView(pack->value));
        if (constructor.size() < 3 || constructor.front() != '{' || constructor.back() != '}')
            continue;
        const std::vector<std::string> values =
            splitCaptureExpressions(constructor.substr(1, constructor.size() - 2));
        if (values.size() != 1 || !containsCallSyntax(values.front()))
            continue;

        const size_t scope = captures.owner[packLine];
        const size_t scopeEnd = scope == spans->size() ? lines.size() : (*spans)[scope].end;
        const size_t indent = indentation(lines[packLine].text);
        size_t blockEnd = scopeEnd;
        for (size_t line = packLine + 1; line < scopeEnd; ++line)
            if (captures.owner[line] == scope && !trimView(lines[line].text).empty() &&
                indentation(lines[line].text) < indent)
            {
                blockEnd = line;
                break;
            }

        struct ProjectionUse
        {
            size_t line = 0;
            int64_t slot = 0;
        };
        std::vector<ProjectionUse> projections;
        int64_t maximum = 0;
        bool safe = true;
        size_t lifetimeEnd = blockEnd;
        for (size_t line = packLine + 1; line < blockEnd; ++line)
        {
            if (!containsIdentifier(lines[line].text, pack->target))
                continue;
            if (captures.owner[line] != scope)
            {
                safe = false;
                break;
            }
            if (auto overwrite = simpleAssignment(lines[line].text);
                overwrite && overwrite->target == pack->target &&
                !containsIdentifier(overwrite->value, pack->target))
            {
                lifetimeEnd = line;
                break;
            }
            auto assignment = simpleAssignment(lines[line].text);
            auto projection = assignment ? resultProjection(assignment->value) : std::nullopt;
            if (!assignment || !projection || projection->table != pack->target ||
                assignment->target == pack->target)
            {
                safe = false;
                break;
            }
            projections.push_back({line, projection->slot});
            maximum = std::max(maximum, projection->slot);
        }
        if (!safe || projections.empty() || maximum <= 0 || maximum > 32 ||
            captures.capturedBefore(packLine, pack->target, lifetimeEnd))
            continue;

        // Mentions after the lexical block would resolve to a different table
        // lifetime only after an explicit overwrite. Otherwise the fresh locals
        // introduced below would not be visible there.
        if (lifetimeEnd == blockEnd)
            for (size_t line = blockEnd; line < scopeEnd; ++line)
                if (containsIdentifier(lines[line].text, pack->target))
                {
                    safe = false;
                    break;
                }
        if (!safe)
            continue;

        const size_t scopeBegin = scope == spans->size() ? 0 : (*spans)[scope].opener + 1;
        const size_t scopeIndent = scope == spans->size() ? 0 : (*spans)[scope].indent + 4;
        const std::optional<ScalarFunctionSpan> owner =
            scope == spans->size() ? std::nullopt : std::optional((*spans)[scope]);
        const size_t activeLocals = scalarTopLevelLocalCount(lines, scopeBegin, scopeEnd, scopeIndent, owner);
        const bool localPack = trimView(lines[packLine].text).starts_with("local ");
        const size_t addedLocals = static_cast<size_t>(maximum) - (localPack ? 1 : 0);
        if (activeLocals + addedLocals > 195)
            continue;

        std::vector<std::string> resultNames;
        resultNames.reserve(static_cast<size_t>(maximum));
        for (int64_t slot = 1; slot <= maximum; ++slot)
        {
            std::string name;
            do
            {
                ++resultOrdinal;
                name = resultOrdinal == 1 ? "call_result" : "call_result_" + std::to_string(resultOrdinal);
            } while (occupied.contains(name));
            occupied.insert(name);
            resultNames.push_back(std::move(name));
        }

        std::string replacement(indent, ' ');
        replacement += "local ";
        for (size_t index = 0; index < resultNames.size(); ++index)
        {
            if (index)
                replacement += ", ";
            replacement += resultNames[index];
        }
        replacement += " = ";
        replacement += trim(values.front());
        lines[packLine].text = std::move(replacement);

        for (const ProjectionUse& projection : projections)
        {
            const auto equals = topLevelAssignmentEquals(lines[projection.line].text);
            if (!equals)
                continue;
            lines[projection.line].text = lines[projection.line].text.substr(0, *equals + 1) + " " +
                resultNames[static_cast<size_t>(projection.slot - 1)];
        }
        ++scalarized;
    }
    return scalarized;
}

size_t nameStableCapturedBindings(std::vector<OutputLine>& lines)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;
    const size_t topLevel = spans->size();
    std::map<size_t, size_t> openerToSpan;
    for (size_t index = 0; index < spans->size(); ++index)
        openerToSpan[(*spans)[index].opener] = index;

    std::vector<size_t> owner(lines.size(), topLevel);
    std::vector<size_t> parent(spans->size(), topLevel);
    std::vector<size_t> stack;
    for (size_t line = 0; line < lines.size(); ++line)
    {
        while (!stack.empty() && (*spans)[stack.back()].end <= line)
            stack.pop_back();
        owner[line] = stack.empty() ? topLevel : stack.back();
        if (auto opening = openerToSpan.find(line); opening != openerToSpan.end())
        {
            parent[opening->second] = owner[line];
            stack.push_back(opening->second);
        }
    }

    std::vector<std::set<std::string>> declarations(spans->size() + 1);
    std::vector<std::vector<std::pair<size_t, std::vector<std::string>>>> declarationLines(spans->size() + 1);
    for (size_t scope = 0; scope <= topLevel; ++scope)
    {
        const size_t begin = scope == topLevel ? 0 : (*spans)[scope].opener + 1;
        const size_t end = scope == topLevel ? lines.size() : (*spans)[scope].end;
        const size_t scopeIndent = scope == topLevel ? 0 : (*spans)[scope].indent + 4;
        if (scope != topLevel)
        {
            const std::string_view opener = trimView(lines[(*spans)[scope].opener].text);
            const size_t function = opener.find("function");
            const size_t open = function == std::string_view::npos ? std::string_view::npos : opener.find('(', function + 8);
            const size_t close = open == std::string_view::npos ? std::string_view::npos : opener.find(')', open + 1);
            if (close != std::string_view::npos)
                for (const std::string& parameter : splitCaptureExpressions(opener.substr(open + 1, close - open - 1)))
                    if (plainIdentifier(parameter))
                        declarations[scope].insert(parameter);
        }
        for (size_t line = begin; line < end; ++line)
        {
            if (owner[line] != scope || indentation(lines[line].text) != scopeIndent)
                continue;
            if (auto names = plainLocalDeclaration(lines[line].text))
            {
                declarations[scope].insert(names->begin(), names->end());
                declarationLines[scope].emplace_back(line, *names);
            }
            const std::string_view statement = trimView(lines[line].text);
            if (statement.starts_with("local "))
                if (auto assignment = identifierAssignmentList(lines[line].text))
                    declarations[scope].insert(assignment->targets.begin(), assignment->targets.end());
        }
    }

    auto descendsFrom = [&](size_t candidate, size_t ancestor) {
        while (candidate != topLevel && candidate != ancestor)
            candidate = parent[candidate];
        return candidate == ancestor;
    };
    auto resolvesBinding = [&](size_t candidate, size_t ancestor, const std::string& name) {
        if (candidate == ancestor)
            return true;
        if (!descendsFrom(candidate, ancestor))
            return false;
        while (candidate != ancestor)
        {
            if (declarations[candidate].contains(name))
                return false;
            candidate = parent[candidate];
        }
        return true;
    };

    std::set<std::string> occupied = collectIdentifiers(lines);
    std::map<std::string, std::vector<size_t>> identifierLines;
    for (size_t line = 0; line < lines.size(); ++line)
        for (const std::string& identifier : lexicalIdentifiers(lines[line].text))
            identifierLines[identifier].push_back(line);
    std::map<std::pair<size_t, std::string>, size_t> ordinals;
    size_t renamed = 0;
    for (size_t scope = 0; scope <= topLevel; ++scope)
    {
        const size_t begin = scope == topLevel ? 0 : (*spans)[scope].opener + 1;
        const size_t end = scope == topLevel ? lines.size() : (*spans)[scope].end;
        for (const auto& [declarationLine, declaredNames] : declarationLines[scope])
            for (const std::string& name : declaredNames)
            {
                if (!std::string_view(name).starts_with("local_") || !generatedLocal(name))
                    continue;
                const auto mentions = identifierLines.find(name);
                if (mentions == identifierLines.end())
                    continue;
                std::vector<size_t> definitions;
                bool unsafeWrite = false;
                for (size_t line : mentions->second)
                {
                    if (line < begin || line >= end)
                        continue;
                    if (!resolvesBinding(owner[line], scope, name))
                        continue;
                    auto assignment = simpleAssignment(lines[line].text);
                    if (assignment && assignment->target == name &&
                        !trimView(lines[line].text).starts_with("local ") &&
                        !containsIdentifier(assignment->value, name))
                    {
                        definitions.push_back(line);
                        continue;
                    }
                    if (line != declarationLine && directlyWritesIdentifier(lines[line].text, name))
                        unsafeWrite = true;
                    if (auto writes = identifierAssignmentList(lines[line].text);
                        writes && std::find(writes->targets.begin(), writes->targets.end(), name) != writes->targets.end() &&
                        line != declarationLine)
                        unsafeWrite = true;
                }
                if (definitions.empty() || unsafeWrite)
                    continue;
                const bool capturedInDescendant = std::any_of(
                    mentions->second.begin(), mentions->second.end(), [&](size_t line) {
                        return line >= begin && line < end && owner[line] != scope &&
                            resolvesBinding(owner[line], scope, name);
                    });
                if (capturedInDescendant && definitions.size() > 1)
                    continue;
                std::set<int64_t> indexedSlots;
                for (size_t line : mentions->second)
                {
                    if (line < begin || line >= end)
                        continue;
                    if (!resolvesBinding(owner[line], scope, name))
                        continue;
                    const ConstantSlotScan scan = scanConstantSlotAccesses(lines[line].text, name);
                    if (scan.valid)
                        indexedSlots.insert(scan.slots.begin(), scan.slots.end());
                }
                if (indexedSlots.size() >= 8)
                    continue;
                std::set<std::string> semanticBases;
                size_t unknownDefinitions = 0;
                static const std::set<std::string_view> RejectedAliasBases{
                    "and", "break", "continue", "do", "else", "elseif", "end", "false", "for", "function",
                    "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
                    "temporary", "snapshot", "upvalue", "value", "result"};
                for (size_t definition : definitions)
                {
                    auto assignment = simpleAssignment(lines[definition].text);
                    if (!assignment || containsIdentifier(assignment->value, name))
                    {
                        unsafeWrite = true;
                        break;
                    }
                    std::string base = semanticLocalBase(assignment->value, false);
                    const std::string_view alias = stripOuterParentheses(trimView(assignment->value));
                    if ((base == "value" || base == "result") && plainIdentifier(alias) &&
                        bareReadableGlobal(alias) && alias != "temporary")
                    {
                        base = std::string(alias);
                        const size_t suffix = base.rfind('_');
                        if (suffix != std::string::npos && suffix + 1 < base.size() &&
                            std::all_of(base.begin() + static_cast<std::ptrdiff_t>(suffix + 1), base.end(),
                                [](char ch) { return std::isdigit(static_cast<unsigned char>(ch)); }))
                            base.erase(suffix);
                    }
                    if (RejectedAliasBases.contains(base))
                        base = "value";
                    if (base != "value" && base != "result")
                        semanticBases.insert(std::move(base));
                    else if (alias != "nil" && alias != "{}" && alias != "{nil}")
                        ++unknownDefinitions;
                }
                if (unsafeWrite || semanticBases.size() > 1 ||
                    (definitions.size() > 1 && unknownDefinitions > 0))
                    continue;

                std::set<std::string> usageBases;
                for (size_t line : mentions->second)
                {
                    if (line < begin || line >= end || !resolvesBinding(owner[line], scope, name))
                        continue;
                    const std::string& text = lines[line].text;
                    auto has = [&](std::string_view fragment) {
                        return text.find(name + std::string(fragment)) != std::string::npos;
                    };
                    if (has(":Disconnect") || has(".Disconnect"))
                        usageBases.insert("connection");
                    if (text.find(":Connect(" + name) != std::string::npos ||
                        text.find("pcall(" + name) != std::string::npos ||
                        text.find("task.spawn(" + name) != std::string::npos ||
                        text.find("task.defer(" + name) != std::string::npos || has("("))
                        usageBases.insert("callback");
                    if (has(".Character") || has(".CharacterAdded") || has(".UserId"))
                        usageBases.insert("player");
                    if (has(".Health") || has(".WalkSpeed") || has(":ChangeState"))
                        usageBases.insert("humanoid");
                    if (has(":FireServer") || has(":FireClient") || has(":FireAllClients"))
                        usageBases.insert("remote_event");
                    if (text.find("ipairs(" + name) != std::string::npos ||
                        text.find("pairs(" + name) != std::string::npos ||
                        text.find("table.insert(" + name) != std::string::npos)
                        usageBases.insert("values");
                }

                std::string base;
                if (semanticBases.size() == 1)
                {
                    base = *semanticBases.begin();
                    if (!usageBases.empty() && !usageBases.contains(base) &&
                        !(base == "callback" && usageBases.contains("connection")))
                        continue;
                }
                else if (usageBases.size() == 1)
                    base = *usageBases.begin();
                else
                    continue;

                size_t& ordinal = ordinals[{scope, base}];
                std::string replacement;
                do
                {
                    ++ordinal;
                    replacement = ordinal == 1 ? base : base + "_" + std::to_string(ordinal);
                } while (occupied.contains(replacement));
                occupied.insert(replacement);
                for (size_t line : mentions->second)
                    if (line >= declarationLine && line < end && resolvesBinding(owner[line], scope, name))
                        lines[line].text = replaceIdentifier(lines[line].text, name, replacement);
                declarations[scope].erase(name);
                declarations[scope].insert(replacement);
                ++renamed;
            }
    }
    return renamed;
}

size_t renameResidualCaptureArtifacts(std::vector<OutputLine>& lines)
{
    std::set<std::string> candidates;
    for (const OutputLine& line : lines)
        for (const std::string& identifier : lexicalIdentifiers(line.text))
        {
            const bool cell = std::string_view(identifier).starts_with("cell_") && identifier.size() > 5 &&
                std::all_of(identifier.begin() + 5, identifier.end(), [](char ch) {
                    return std::isdigit(static_cast<unsigned char>(ch));
                });
            if (capturedLocal(identifier) || cell)
                candidates.insert(identifier);
        }
    if (candidates.empty())
        return 0;

    std::set<std::string> occupied = collectIdentifiers(lines);
    std::map<std::string, std::string> replacements;
    for (const std::string& candidate : candidates)
    {
        const bool cell = std::string_view(candidate).starts_with("cell_");
        const std::string suffix = cell
            ? candidate.substr(5)
            : candidate.substr(std::string_view("captured_value_").size());
        const std::string base = cell ? "upvalue_cell_" + suffix : "upvalue_" + suffix;
        std::string replacement = base;
        size_t ordinal = 1;
        while (occupied.contains(replacement))
            replacement = base + "_" + std::to_string(++ordinal);
        occupied.insert(replacement);
        replacements.emplace(candidate, std::move(replacement));
    }
    for (OutputLine& line : lines)
        for (const auto& [name, replacement] : replacements)
            line.text = replaceIdentifier(line.text, name, replacement);
    return replacements.size();
}

std::vector<std::string> declaredBlockLocals(std::string_view line)
{
    const std::string_view statement = trimView(line);
    if (statement.starts_with("local function "))
    {
        std::string_view declared = trimView(statement.substr(15));
        if (const size_t open = declared.find('('); open != std::string_view::npos)
            declared = trimView(declared.substr(0, open));
        return plainIdentifier(declared) ? std::vector<std::string>{std::string(declared)} : std::vector<std::string>{};
    }

    if (statement.starts_with("local "))
    {
        if (auto declarations = plainLocalDeclaration(line))
            return *declarations;
        if (auto assignment = identifierAssignmentList(line))
            return assignment->targets;
    }

    if (!statement.starts_with("for "))
        return {};
    std::string_view variables = trimView(statement.substr(4));
    size_t separator = variables.find(" in ");
    if (separator == std::string_view::npos)
        separator = variables.find('=');
    if (separator == std::string_view::npos)
        return {};
    std::vector<std::string> result;
    for (std::string variable : splitCaptureExpressions(variables.substr(0, separator)))
        if (plainIdentifier(variable))
            result.push_back(std::move(variable));
    return result;
}

bool declaresBlockLocal(std::string_view line, std::string_view name)
{
    const std::vector<std::string> declarations = declaredBlockLocals(line);
    return std::find(declarations.begin(), declarations.end(), name) != declarations.end();
}

bool residualVmLocal(std::string_view value)
{
    constexpr std::array<std::string_view, 2> Prefixes{"vm_value_", "vm_temporary_"};
    for (std::string_view prefix : Prefixes)
        if (value.starts_with(prefix) && value.size() > prefix.size() &&
            std::all_of(value.begin() + static_cast<std::ptrdiff_t>(prefix.size()), value.end(), [](char ch) {
                return std::isdigit(static_cast<unsigned char>(ch));
            }))
            return true;
    return false;
}

size_t splitSemanticLocalLifetimes(
    std::vector<OutputLine>& lines,
    bool allowScopedLifetimes,
    bool includeResidualVmLocals = false)
{
    const auto spans = scalarFunctionSpans(lines);
    if (!spans)
        return 0;

    const size_t topLevel = spans->size();
    const LexicalCaptureIndex captures = buildLexicalCaptureIndex(lines, *spans);
    const std::vector<size_t>& owner = captures.owner;

    std::vector<std::map<std::string, size_t>> declarationCounts(topLevel + 1);
    for (size_t line = 0; line < lines.size(); ++line)
        for (const std::string& declaration : declaredBlockLocals(lines[line].text))
            ++declarationCounts[owner[line]][declaration];
    for (size_t scope = 0; scope < topLevel; ++scope)
    {
        const std::string_view opener = trimView(lines[(*spans)[scope].opener].text);
        const size_t function = opener.find("function");
        const size_t open = function == std::string_view::npos ? std::string_view::npos : opener.find('(', function + 8);
        const size_t close = open == std::string_view::npos ? std::string_view::npos : opener.find(')', open + 1);
        if (close == std::string_view::npos)
            continue;
        for (const std::string& parameter : splitCaptureExpressions(opener.substr(open + 1, close - open - 1)))
            if (plainIdentifier(parameter))
                ++declarationCounts[scope][parameter];
    }

    struct Plan
    {
        size_t scope = 0;
        size_t definition = 0;
        size_t end = 0;
        size_t declarationEnd = 0;
        std::string target;
        std::string base;
        int priority = 0;
        bool scoped = false;
        bool boundaryRead = false;
    };
    std::vector<Plan> plans;
    for (size_t scope = 0; scope <= topLevel; ++scope)
    {
        const size_t begin = scope == topLevel ? 0 : (*spans)[scope].opener + 1;
        const size_t end = scope == topLevel ? lines.size() : (*spans)[scope].end;
        const size_t scopeIndent = scope == topLevel ? 0 : (*spans)[scope].indent + 4;
        for (size_t definition = begin; definition < end; ++definition)
        {
            const size_t definitionIndent = indentation(lines[definition].text);
            if (owner[definition] != scope || definitionIndent < scopeIndent ||
                trimView(lines[definition].text).starts_with("local "))
                continue;
            auto assignment = simpleAssignment(lines[definition].text);
            const bool eligibleTarget = assignment &&
                (generatedLocal(assignment->target) ||
                    (includeResidualVmLocals && residualVmLocal(assignment->target)));
            if (!assignment || !eligibleTarget || containsIdentifier(assignment->value, assignment->target))
                continue;
            if (declarationCounts[scope][assignment->target] > 1)
                continue;

            std::string base = semanticLocalBase(assignment->value, false);
            if (base == "result")
                base = "value";

            size_t declarationEnd = end;
            const bool nestedBlock = definitionIndent > scopeIndent;
            if (nestedBlock)
                for (size_t line = definition + 1; line < end; ++line)
                    if (owner[line] == scope && !trimView(lines[line].text).empty() &&
                        indentation(lines[line].text) < definitionIndent)
                    {
                        declarationEnd = line;
                        break;
                    }

            size_t lifetimeEnd = declarationEnd;
            size_t reads = 0;
            bool unsafe = false;
            bool foundOverwrite = false;
            bool boundaryRead = false;
            for (size_t line = definition + 1; line < declarationEnd; ++line)
            {
                if (owner[line] != scope)
                    continue;
                const std::string_view statement = trimView(lines[line].text);
                if (nestedBlock && (statement == "break" || statement == "continue"))
                {
                    unsafe = true;
                    break;
                }
                if (declaresBlockLocal(lines[line].text, assignment->target))
                {
                    unsafe = true;
                    break;
                }
                if (auto overwrite = simpleAssignment(lines[line].text);
                    overwrite && overwrite->target == assignment->target)
                {
                    if (indentation(lines[line].text) != definitionIndent ||
                        trimView(lines[line].text).starts_with("local "))
                        unsafe = true;
                    boundaryRead = containsIdentifier(overwrite->value, assignment->target);
                    lifetimeEnd = line;
                    foundOverwrite = true;
                    break;
                }
                if (compoundTarget(lines[line].text, assignment->target))
                {
                    unsafe = true;
                    break;
                }
                if (auto writes = identifierAssignmentList(lines[line].text);
                    writes && std::find(writes->targets.begin(), writes->targets.end(), assignment->target) !=
                            writes->targets.end())
                {
                    unsafe = true;
                    break;
                }
                reads += identifierOccurrences(lines[line].text, assignment->target);
            }
            // A nested definition may become a lexical local only when its value
            // is dead after the block. Otherwise the assignment is a real branch
            // join that must continue updating the outer local.
            bool readAfterNestedBlock = false;
            if (nestedBlock && !foundOverwrite)
                for (size_t line = declarationEnd; line < end && !readAfterNestedBlock; ++line)
                    if (owner[line] == scope && containsIdentifier(lines[line].text, assignment->target))
                        readAfterNestedBlock = true;
            if (unsafe || reads == 0 || readAfterNestedBlock ||
                captures.capturedBefore(definition, assignment->target, lifetimeEnd))
                continue;
            int priority = 70;
            if (base == "value")
                priority = 5;
            else if (base == "callback")
                priority = 20;
            else if (base == "values" || base == "iterator_values")
                priority = 15;
            else if (base.ends_with("_method"))
                priority = 50;
            else if (base == "connection" || base.ends_with("_signal"))
                priority = 90;
            else if (base == "flag" || base == "number" || base == "text" || base == "encoded_value" ||
                base == "enum_value" || base == "asset_id")
                priority = 30;
            else if (base == "game" || base == "workspace" || base == "script")
                priority = 40;

            bool scoped = allowScopedLifetimes && foundOverwrite && !boundaryRead && lifetimeEnd < declarationEnd;
            if (scoped)
                for (size_t line = definition + 1; line < lifetimeEnd && scoped; ++line)
                {
                    if (owner[line] != scope || indentation(lines[line].text) != definitionIndent)
                        continue;
                    for (const std::string& declared : declaredBlockLocals(lines[line].text))
                        for (size_t later = lifetimeEnd; later < declarationEnd; ++later)
                            if (containsIdentifier(lines[later].text, declared))
                            {
                                scoped = false;
                                break;
                            }
                }

            plans.push_back(
                {scope, definition, lifetimeEnd, declarationEnd, assignment->target, base, priority, scoped,
                    boundaryRead});
        }
    }
    if (plans.empty())
        return 0;

    std::vector<bool> selected(plans.size(), false);
    for (size_t scope = 0; scope <= topLevel; ++scope)
    {
        const size_t begin = scope == topLevel ? 0 : (*spans)[scope].opener + 1;
        const size_t end = scope == topLevel ? lines.size() : (*spans)[scope].end;
        const size_t scopeIndent = scope == topLevel ? 0 : (*spans)[scope].indent + 4;
        const std::optional<ScalarFunctionSpan> function = scope == topLevel ? std::nullopt : std::optional((*spans)[scope]);
        const size_t activeLocals = scalarTopLevelLocalCount(lines, begin, end, scopeIndent, function);
        constexpr size_t SemanticLocalLimit = 185;
        const size_t budget = activeLocals < SemanticLocalLimit ? SemanticLocalLimit - activeLocals : 0;
        std::vector<size_t> activeExtra(end - begin + 1, 0);
        std::vector<size_t> candidates;
        for (size_t index = 0; index < plans.size(); ++index)
            if (plans[index].scope == scope)
                candidates.push_back(index);
        std::sort(candidates.begin(), candidates.end(), [&](size_t left, size_t right) {
            if (plans[left].priority != plans[right].priority)
                return plans[left].priority > plans[right].priority;
            return plans[left].definition < plans[right].definition;
        });
        for (size_t candidate : candidates)
        {
            if (budget == 0)
                break;
            const Plan& plan = plans[candidate];
            bool fits = true;
            const size_t activeEnd = plan.scoped ? plan.end : plan.declarationEnd;
            for (size_t selectedPlan = 0; selectedPlan < plans.size() && fits; ++selectedPlan)
            {
                if (!selected[selectedPlan])
                    continue;
                const Plan& other = plans[selectedPlan];
                const size_t planActiveEnd = plan.scoped ? plan.end : plan.declarationEnd;
                const size_t otherActiveEnd = other.scoped ? other.end : other.declarationEnd;
                const bool crosses = (plan.definition < other.definition && other.definition < planActiveEnd &&
                                         planActiveEnd < otherActiveEnd) ||
                    (other.definition < plan.definition && plan.definition < otherActiveEnd &&
                        otherActiveEnd < planActiveEnd);
                if (crosses)
                    fits = false;
            }
            for (size_t line = plan.definition; line < activeEnd && fits; ++line)
                if (activeExtra[line - begin] >= budget)
                {
                    fits = false;
                    break;
                }
            if (!fits)
                continue;
            selected[candidate] = true;
            for (size_t line = plan.definition; line < activeEnd; ++line)
                ++activeExtra[line - begin];
        }
    }

    std::set<std::string> occupied = collectIdentifiers(lines);
    std::map<std::string, size_t> ordinals;
    std::vector<size_t> scopedPlans;
    size_t split = 0;
    for (size_t planIndex = 0; planIndex < plans.size(); ++planIndex)
    {
        if (!selected[planIndex])
            continue;
        const Plan& plan = plans[planIndex];
        auto assignment = simpleAssignment(lines[plan.definition].text);
        if (!assignment || assignment->target != plan.target)
            continue;
        size_t& ordinal = ordinals[plan.base];
        std::string replacement;
        do
        {
            ++ordinal;
            replacement = ordinal == 1 ? plan.base : plan.base + "_" + std::to_string(ordinal);
        } while (occupied.contains(replacement));
        occupied.insert(replacement);

        lines[plan.definition].text = std::string(indentation(lines[plan.definition].text), ' ') +
            "local " + replacement + " = " + assignment->value;
        for (size_t line = plan.definition + 1; line < plan.end; ++line)
            if (owner[line] == plan.scope)
                lines[line].text = replaceIdentifier(lines[line].text, plan.target, replacement);
        if (plan.boundaryRead && plan.end < lines.size())
            if (auto boundary = simpleAssignment(lines[plan.end].text);
                boundary && boundary->target == plan.target)
                lines[plan.end].text = std::string(indentation(lines[plan.end].text), ' ') + plan.target + " = " +
                    replaceIdentifier(boundary->value, plan.target, replacement);
        if (plan.scoped)
            scopedPlans.push_back(planIndex);
        ++split;
    }

    if (!scopedPlans.empty())
    {
        std::vector<size_t> depth(lines.size(), 0);
        std::map<size_t, std::vector<size_t>> openings;
        std::map<size_t, std::vector<size_t>> closings;
        std::map<size_t, size_t> baseIndent;
        for (size_t planIndex : scopedPlans)
        {
            const Plan& plan = plans[planIndex];
            openings[plan.definition].push_back(planIndex);
            closings[plan.end].push_back(planIndex);
            baseIndent[planIndex] = indentation(lines[plan.definition].text);
            for (size_t line = plan.definition; line < plan.end; ++line)
                ++depth[line];
        }
        for (auto& [line, ending] : closings)
        {
            (void)line;
            std::sort(ending.begin(), ending.end(), [&](size_t left, size_t right) {
                return plans[left].definition > plans[right].definition;
            });
        }

        std::vector<OutputLine> scoped;
        scoped.reserve(lines.size() + scopedPlans.size() * 2);
        for (size_t line = 0; line < lines.size(); ++line)
        {
            if (auto ending = closings.find(line); ending != closings.end())
                for (size_t planIndex : ending->second)
                {
                    const size_t outerDepth = depth[line];
                    scoped.push_back({std::string(baseIndent.at(planIndex) + outerDepth * 4, ' ') + "end",
                        lines[line].origin, {}});
                }
            if (auto opening = openings.find(line); opening != openings.end())
                for (size_t planIndex : opening->second)
                {
                    (void)planIndex;
                    const size_t outerDepth = depth[line] - 1;
                    scoped.push_back({std::string(indentation(lines[line].text) + outerDepth * 4, ' ') + "do",
                        lines[line].origin, {}});
                }
            if (!trimView(lines[line].text).empty() && depth[line] != 0)
                lines[line].text.insert(0, depth[line] * 4, ' ');
            scoped.push_back(std::move(lines[line]));
        }
        lines = std::move(scoped);
    }
    return split;
}

std::optional<size_t> longBracketLevel(std::string_view line, size_t begin)
{
    if (begin >= line.size() || line[begin] != '[')
        return std::nullopt;
    size_t cursor = begin + 1;
    while (cursor < line.size() && line[cursor] == '=')
        ++cursor;
    if (cursor >= line.size() || line[cursor] != '[')
        return std::nullopt;
    return cursor - begin - 1;
}

std::string longBracketDelimiter(size_t level, bool closing)
{
    return std::string(1, closing ? ']' : '[') + std::string(level, '=') + (closing ? "]" : "[");
}

std::optional<std::string> shortestRoundTripDecimal(std::string_view token, char following)
{
    double value = 0.0;
    const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value, std::chars_format::general);
    if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size() || !std::isfinite(value))
        return std::nullopt;

    char buffer[128];
    const auto rendered = std::to_chars(buffer, buffer + sizeof(buffer), value, std::chars_format::general);
    if (rendered.ec != std::errc{})
        return std::nullopt;
    std::string candidate(buffer, rendered.ptr);
    if (const size_t exponent = candidate.find_first_of("eE"); exponent != std::string::npos)
    {
        size_t digits = exponent + 1;
        if (digits < candidate.size() && (candidate[digits] == '+' || candidate[digits] == '-'))
        {
            if (candidate[digits] == '+')
                candidate.erase(digits, 1);
            else
                ++digits;
        }
        while (digits + 1 < candidate.size() && candidate[digits] == '0')
            candidate.erase(digits, 1);
    }
    if (following == '.' && candidate.find_first_of(".eE") == std::string::npos)
        candidate += ".0";
    if (candidate.size() >= token.size())
        return std::nullopt;

    double roundTrip = 0.0;
    const auto reparsed = std::from_chars(
        candidate.data(), candidate.data() + candidate.size(), roundTrip, std::chars_format::general);
    if (reparsed.ec != std::errc{} || reparsed.ptr != candidate.data() + candidate.size() ||
        std::bit_cast<uint64_t>(roundTrip) != std::bit_cast<uint64_t>(value))
        return std::nullopt;
    return candidate;
}

size_t normalizeNumericLiterals(std::vector<OutputLine>& lines)
{
    std::optional<size_t> longLiteral;
    size_t normalized = 0;
    for (OutputLine& line : lines)
    {
        std::string output;
        output.reserve(line.text.size());
        size_t index = 0;
        while (index < line.text.size())
        {
            if (longLiteral)
            {
                const std::string closing = longBracketDelimiter(*longLiteral, true);
                const size_t close = line.text.find(closing, index);
                if (close == std::string::npos)
                {
                    output.append(line.text, index, std::string::npos);
                    index = line.text.size();
                    continue;
                }
                output.append(line.text, index, close + closing.size() - index);
                index = close + closing.size();
                longLiteral.reset();
                continue;
            }
            if (line.text[index] == '-' && index + 1 < line.text.size() && line.text[index + 1] == '-')
            {
                if (auto level = longBracketLevel(line.text, index + 2))
                {
                    const std::string opening = longBracketDelimiter(*level, false);
                    output.append(line.text, index, 2 + opening.size());
                    index += 2 + opening.size();
                    longLiteral = *level;
                    continue;
                }
                output.append(line.text, index, std::string::npos);
                break;
            }
            if (line.text[index] == '\'' || line.text[index] == '"')
            {
                const size_t begin = index;
                const char quote = line.text[index++];
                while (index < line.text.size())
                {
                    if (line.text[index] == '\\')
                        index += std::min<size_t>(2, line.text.size() - index);
                    else if (line.text[index++] == quote)
                        break;
                }
                output.append(line.text, begin, index - begin);
                continue;
            }
            if (auto level = longBracketLevel(line.text, index))
            {
                const std::string opening = longBracketDelimiter(*level, false);
                output += opening;
                index += opening.size();
                longLiteral = *level;
                continue;
            }
            if (line.text[index] == '_' || std::isalpha(static_cast<unsigned char>(line.text[index])))
            {
                const size_t begin = index++;
                while (index < line.text.size() &&
                    (line.text[index] == '_' || std::isalnum(static_cast<unsigned char>(line.text[index]))))
                    ++index;
                output.append(line.text, begin, index - begin);
                continue;
            }
            if (!std::isdigit(static_cast<unsigned char>(line.text[index])))
            {
                output.push_back(line.text[index++]);
                continue;
            }

            const size_t begin = index;
            if (index + 1 < line.text.size() && line.text[index] == '0' &&
                (line.text[index + 1] == 'x' || line.text[index + 1] == 'X' ||
                    line.text[index + 1] == 'b' || line.text[index + 1] == 'B'))
            {
                index += 2;
                while (index < line.text.size() &&
                    (line.text[index] == '_' || std::isalnum(static_cast<unsigned char>(line.text[index]))))
                    ++index;
                output.append(line.text, begin, index - begin);
                continue;
            }
            while (index < line.text.size() && std::isdigit(static_cast<unsigned char>(line.text[index])))
                ++index;
            bool fractional = false;
            bool exponent = false;
            if (index < line.text.size() && line.text[index] == '.' &&
                !(index + 1 < line.text.size() && line.text[index + 1] == '.'))
            {
                fractional = true;
                ++index;
                while (index < line.text.size() && std::isdigit(static_cast<unsigned char>(line.text[index])))
                    ++index;
            }
            if (index < line.text.size() && (line.text[index] == 'e' || line.text[index] == 'E'))
            {
                size_t cursor = index + 1;
                if (cursor < line.text.size() && (line.text[cursor] == '+' || line.text[cursor] == '-'))
                    ++cursor;
                const size_t digits = cursor;
                while (cursor < line.text.size() && std::isdigit(static_cast<unsigned char>(line.text[cursor])))
                    ++cursor;
                if (cursor > digits)
                {
                    exponent = true;
                    index = cursor;
                }
            }
            const std::string_view token(line.text.data() + begin, index - begin);
            const char following = index < line.text.size() ? line.text[index] : '\0';
            if ((fractional || exponent) &&
                (following != '_' && !std::isalpha(static_cast<unsigned char>(following))))
            {
                if (auto replacement = shortestRoundTripDecimal(token, following))
                {
                    output += *replacement;
                    ++normalized;
                    continue;
                }
            }
            output.append(token);
        }
        line.text = std::move(output);
    }
    return normalized;
}

size_t compactGeneratedBlankLines(std::vector<OutputLine>& lines)
{
    std::vector<bool> remove(lines.size(), false);
    bool previousBlank = true;
    size_t removed = 0;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        const bool blank = trimView(lines[index].text).empty();
        if (blank && previousBlank)
        {
            remove[index] = true;
            ++removed;
        }
        previousBlank = blank;
    }
    for (size_t index = lines.size(); index > 0 && trimView(lines[index - 1].text).empty(); --index)
        if (!remove[index - 1])
        {
            remove[index - 1] = true;
            ++removed;
        }
    if (removed == 0)
        return 0;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        if (!remove[index] || (lines[index].states.empty() && !lines[index].origin))
            continue;
        size_t anchor = index + 1;
        while (anchor < lines.size() && remove[anchor])
            ++anchor;
        if (anchor == lines.size())
        {
            anchor = index;
            while (anchor > 0 && remove[anchor])
                --anchor;
        }
        if (anchor < lines.size() && !remove[anchor])
        {
            lines[anchor].states.insert(lines[index].states.begin(), lines[index].states.end());
            if (!lines[anchor].origin && lines[index].origin)
                lines[anchor].origin = lines[index].origin;
        }
    }
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size() - removed);
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return removed;
}

size_t pruneUnusedDeclarations(std::vector<OutputLine>& lines)
{
    struct LexicalScope
    {
        size_t begin = 0;
        size_t end = 0;
    };
    std::vector<LexicalScope> lexicalScopes{{0, lines.size()}};
    std::vector<size_t> lexicalOwner(lines.size(), 0);
    for (size_t index = 0; index < lines.size(); ++index)
    {
        const std::string_view statement = trimView(lines[index].text);
        const bool functionOpener = statement.starts_with("local function ") || statement.starts_with("return function(") ||
            statement.find(" = function(") != std::string_view::npos;
        if (!functionOpener || functionExpressionClosesOnLine(statement))
            continue;
        const size_t indent = indentation(lines[index].text);
        size_t end = lines.size();
        for (size_t candidate = index + 1; candidate < lines.size(); ++candidate)
            if (indentation(lines[candidate].text) == indent && trimView(lines[candidate].text) == "end")
            {
                end = candidate;
                break;
            }
        if (end < lines.size())
            lexicalScopes.push_back({index + 1, end});
    }
    std::vector<size_t> scopeOrder(lexicalScopes.size() - 1);
    for (size_t index = 1; index < lexicalScopes.size(); ++index)
        scopeOrder[index - 1] = index;
    std::sort(scopeOrder.begin(), scopeOrder.end(), [&](size_t left, size_t right) {
        return lexicalScopes[left].begin < lexicalScopes[right].begin;
    });
    for (size_t scopeIndex : scopeOrder)
        for (size_t line = lexicalScopes[scopeIndex].begin; line < lexicalScopes[scopeIndex].end && line < lexicalOwner.size(); ++line)
            lexicalOwner[line] = scopeIndex;

    std::vector<bool> remove(lines.size(), false);
    size_t pruned = 0;
    for (size_t declaration = 0; declaration < lines.size(); ++declaration)
    {
        auto names = generatedDeclaration(lines[declaration].text);
        if (!names)
            continue;
        const size_t scopeIndex = lexicalOwner[declaration];
        const size_t scopeEnd = lexicalScopes[scopeIndex].end;
        std::vector<std::string> remaining;
        for (const std::string& name : *names)
        {
            bool used = false;
            for (size_t index = declaration + 1; index < scopeEnd && index < lines.size(); ++index)
                if (lexicalOwner[index] == scopeIndex && containsIdentifier(lines[index].text, name))
                {
                    used = true;
                    break;
                }
            if (used)
                remaining.push_back(name);
            else
                ++pruned;
        }
        if (remaining.empty())
            remove[declaration] = true;
        else if (remaining != *names)
        {
            std::string rewritten(indentation(lines[declaration].text), ' ');
            rewritten += "local ";
            for (size_t index = 0; index < remaining.size(); ++index)
            {
                if (index)
                    rewritten += ", ";
                rewritten += remaining[index];
            }
            lines[declaration].text = std::move(rewritten);
        }
    }

    static const std::regex Synthetic(R"(^\s*local\s+(__arguments|__results|temporary)(?:\s*=.*)?$)");
    for (size_t index = 0; index < lines.size(); ++index)
    {
        std::smatch match;
        if (!std::regex_match(lines[index].text, match, Synthetic))
            continue;
        const std::string name = match[1].str();
        const size_t scopeIndex = lexicalOwner[index];
        bool used = false;
        for (size_t candidate = index + 1; candidate < lexicalScopes[scopeIndex].end && candidate < lines.size(); ++candidate)
            if (lexicalOwner[candidate] == scopeIndex && containsIdentifier(lines[candidate].text, name))
            {
                used = true;
                break;
            }
        if (!used && !remove[index])
        {
            remove[index] = true;
            ++pruned;
        }
    }
    if (std::none_of(remove.begin(), remove.end(), [](bool value) { return value; }))
        return pruned;
    for (size_t index = 0; index < lines.size(); ++index)
    {
        if (!remove[index] || lines[index].states.empty())
            continue;
        size_t anchor = index + 1;
        while (anchor < lines.size() && remove[anchor])
            ++anchor;
        if (anchor < lines.size())
            lines[anchor].states.insert(lines[index].states.begin(), lines[index].states.end());
    }
    std::vector<OutputLine> compacted;
    compacted.reserve(lines.size());
    for (size_t index = 0; index < lines.size(); ++index)
        if (!remove[index])
            compacted.push_back(std::move(lines[index]));
    lines = std::move(compacted);
    return pruned;
}

json remapStatements(const json& mapping, const std::vector<OutputLine>& lines)
{
    if (!mapping.is_array())
        return mapping;
    std::map<size_t, std::vector<json>> byLine;
    for (const json& row : mapping)
        if (row.is_object() && row.contains("line") && row["line"].is_number_unsigned())
            byLine[row["line"].get<size_t>()].push_back(row);
        else if (row.is_object() && row.contains("line") && row["line"].is_number_integer())
            byLine[static_cast<size_t>(std::max<int64_t>(0, row["line"].get<int64_t>()))].push_back(row);
    json result = json::array();
    for (size_t index = 0; index < lines.size(); ++index)
    {
        std::set<int64_t> mappedStates;
        if (lines[index].origin)
        {
            auto found = byLine.find(*lines[index].origin);
            if (found != byLine.end())
                for (json row : found->second)
                {
                    row["line"] = index + 1;
                    if (row.contains("state") && row["state"].is_number_integer())
                        mappedStates.insert(row["state"].get<int64_t>());
                    result.push_back(std::move(row));
                }
        }
        for (int64_t state : lines[index].states)
            if (!mappedStates.contains(state))
                result.push_back({{"line", index + 1}, {"state", state}, {"generated", "structured_control_flow"}});
    }
    return result;
}

} // namespace

RewriteResult rewriteStateMachinesOnce(
    std::string_view source, const nlohmann::json& mapping, const ProgressCallback& progress,
    bool allowScopedLifetimes, bool allowRegisterOverflow)
{
    RewriteResult result;
    const bool trailingNewline = !source.empty() && source.back() == '\n';
    const std::vector<SourceLine> lines = splitLines(source);
    std::vector<OutputLine> output;
    for (size_t index = 0; index < lines.size();)
    {
        const std::string_view declaration = trimView(lines[index].text);
        const bool prometheusMarker = declaration.starts_with("local __state = ") && index + 1 < lines.size() &&
            trimView(lines[index + 1].text) == "while __state ~= nil do";
        const bool luraphMarker = declaration.starts_with("local pc = ") && index + 1 < lines.size() &&
            trimView(lines[index + 1].text) == "while pc ~= nil do";
        const bool stateMachineMarker = prometheusMarker || luraphMarker;
        std::string parseFailure;
        auto region = parseRegion(lines, index, &parseFailure);
        if (!region)
        {
            if (stateMachineMarker)
            {
                ++result.regions_found;
                ++result.residual_state_machines;
                const std::string reason = parseFailure.empty() ? "parse" : "parse_" + parseFailure;
                result.residual_reasons[reason] = result.residual_reasons.value(reason, 0) + 1;
            }
            output.push_back({lines[index].text, lines[index].origin, {}});
            ++index;
            continue;
        }
        ++result.regions_found;
        Structurer structurer(*region);
        auto structured = structurer.run();
        if (!structured)
        {
            ++result.residual_state_machines;
            const std::string reason = structurer.failure().empty() ? "unknown" : structurer.failure();
            result.residual_reasons[reason] = result.residual_reasons.value(reason, 0) + 1;
            for (size_t line = region->begin; line < region->end; ++line)
                output.push_back({lines[line].text, lines[line].origin, {}});
            index = region->end;
            continue;
        }
        ++result.regions_structured;
        result.blocks_structured += structurer.blockCount();
        result.reentry_nodes_split += structurer.nodeSplitCount();
        output.insert(output.end(), std::make_move_iterator(structured->begin()), std::make_move_iterator(structured->end()));
        index = region->end;
    }

    const PropagationStats propagation = propagateConstants(output);
    result.constants_propagated = propagation.constants;
    result.aliases_propagated = propagation.aliases;
    result.properties_recovered = propagation.properties;
    result.methods_recovered = recoverMethodCalls(output);
    result.dead_assignments_removed = eliminateDeadAssignments(output);
    result.result_returns_collapsed = collapseResultReturns(output);
    result.empty_branches_removed = simplifyEmptyBranches(output);
    result.state_registers_renamed = renameStructuredStateRegisters(output);
    removeUnusedResultDeclarations(output);
    result.dead_assignments_removed += eliminateDeadAssignments(output);
    result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
    removeUnusedResultDeclarations(output);
    if (progress)
    {
        progress("structure_flow", "done", "Flattened VM regions reconstructed into validated control flow",
            {{"regions_found", result.regions_found}, {"regions_structured", result.regions_structured},
                {"blocks_structured", result.blocks_structured}, {"reentry_nodes_split", result.reentry_nodes_split},
                {"residual_state_machines", result.residual_state_machines}, {"residual_reasons", result.residual_reasons}});
        progress("structure_closures", "running", "Recovering prototypes, lexical captures, parameters, and closure factories", json::object());
    }
    if (auto nested = nestPrototypeClosures(output))
    {
        output = std::move(nested->lines);
        result.prototypes_nested = nested->prototypes;
        result.capture_references_recovered = nested->capture_references;
    }
    result.trace_instrumentation_removed = removeTraceInstrumentation(output);
    result.unreachable_prototypes_removed = removeUnreferencedRecoveredFunctions(output);
    std::set<std::string> fullyScalarizedTables;
    std::set<std::string> partiallyScalarizedTables;
    auto accumulateRegisterTables = [&](const RegisterTableScalarStats& stats) {
        for (const std::string& table : stats.fullTableNames)
        {
            fullyScalarizedTables.insert(table);
            partiallyScalarizedTables.erase(table);
        }
        for (const std::string& table : stats.partialTableNames)
            if (!fullyScalarizedTables.contains(table))
                partiallyScalarizedTables.insert(table);
        result.register_tables_fully_scalarized = fullyScalarizedTables.size();
        result.register_tables_partially_scalarized = partiallyScalarizedTables.size();
        result.register_tables_scalarized = fullyScalarizedTables.size() + partiallyScalarizedTables.size();
        result.register_table_slots_scalarized += stats.slots;
        result.register_table_accesses_scalarized += stats.accesses;
    };
    result.result_packs_collapsed = collapseContiguousResultPacks(output);
    result.result_packs_collapsed += collapseResultPacksIntoSafeLvalues(output);
    result.result_packs_collapsed += scalarizeSparseResultPacks(output);
    result.direct_closure_calls_recovered = recoverImmediateClosureCalls(output);
    result.fixed_top_call_packs_expanded = expandFixedTopCallPacks(output);
    result.dead_assignments_removed += eliminateDeadRegisterFrameAliases(output);
    result.dead_assignments_removed += eliminateOverwrittenPrivateRegisterSlots(output);
    result.aliases_propagated += lowerImmediateRegisterAliases(output);
    result.constants_propagated += specializeDominatedRegisterIndices(output);
    const RegisterTableScalarStats registerTables = scalarReplaceRegisterTables(output, allowRegisterOverflow);
    accumulateRegisterTables(registerTables);
    for (OutputLine& line : output)
        result.globals_recovered += recoverEnvironmentGlobals(line.text);
    const PropagationStats sourcePropagation = propagateConstants(output);
    result.constants_propagated += sourcePropagation.constants;
    result.aliases_propagated += sourcePropagation.aliases;
    result.properties_recovered += sourcePropagation.properties;
    result.methods_recovered += recoverMethodCalls(output);
    result.dead_assignments_removed += eliminateDeadAssignments(output);
    result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
    removeUnusedResultDeclarations(output);
    result.function_parameters_recovered = recoverFunctionParameters(output);
    if (result.function_parameters_recovered)
    {
        const PropagationStats parameterPropagation = propagateConstants(output);
        result.constants_propagated += parameterPropagation.constants;
        result.aliases_propagated += parameterPropagation.aliases;
        result.properties_recovered += parameterPropagation.properties;
        result.dead_assignments_removed += eliminateDeadAssignments(output);
        result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
        removeUnusedResultDeclarations(output);
    }
    result.dead_capture_factories_removed = removeDeadPureCaptureFactories(output);
    result.unused_cell_allocations_removed = removeShadowedCellAllocations(output);
    result.captured_cells_unboxed = unboxCapturedCells(output);
    const size_t postUnboxDeadFactories = removeDeadPureCaptureFactories(output);
    result.dead_capture_factories_removed += postUnboxDeadFactories;
    if (postUnboxDeadFactories)
        result.captured_cells_unboxed += unboxCapturedCells(output);
    const PropagationStats capturedPropagation = propagateStableCapturedAliases(output);
    result.constants_propagated += capturedPropagation.constants;
    result.aliases_propagated += capturedPropagation.aliases;
    result.properties_recovered += capturedPropagation.properties;
    result.methods_recovered += recoverMethodCalls(output);
    result.dead_assignments_removed += eliminateDeadAssignments(output);
    result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
    removeUnusedResultDeclarations(output);
    const CaptureFactoryStats factoryStats = collapseUnusedCaptureFactories(output);
    result.unused_captures_removed = factoryStats.captures;
    result.capture_factories_collapsed = factoryStats.factories;
    result.returned_closures_recovered = recoverReturnedClosures(output);
    result.single_assignment_aliases_folded = foldSingleAssignmentAliases(output);
    result.methods_recovered += recoverMethodCalls(output);
    result.dead_assignments_removed += eliminateDeadAssignments(output);
    result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
    removeUnusedResultDeclarations(output);
    result.function_locals_promoted = promoteFunctionLocals(output);
    result.leading_semicolons_removed = removeSafeLeadingSemicolons(output);
    result.unused_cell_allocations_removed += removeUnusedCellAllocations(output);
    if (progress)
    {
        progress("structure_closures", "done", "Prototype and capture topology reconstructed",
            {{"prototypes_nested", result.prototypes_nested}, {"capture_references_recovered", result.capture_references_recovered},
                {"captured_cells_unboxed", result.captured_cells_unboxed}, {"capture_factories_collapsed", result.capture_factories_collapsed},
                {"function_parameters_recovered", result.function_parameters_recovered},
                {"direct_closure_calls_recovered", result.direct_closure_calls_recovered},
                {"trace_instrumentation_removed", result.trace_instrumentation_removed},
                {"unreachable_prototypes_removed", result.unreachable_prototypes_removed},
                {"register_tables_scalarized", result.register_tables_scalarized},
                {"register_tables_fully_scalarized", result.register_tables_fully_scalarized},
                {"register_tables_partially_scalarized", result.register_tables_partially_scalarized},
                {"register_table_slots_scalarized", result.register_table_slots_scalarized},
                {"register_table_accesses_scalarized", result.register_table_accesses_scalarized}});
        progress("structure_dataflow", "running", "Simplifying register lifetimes, loops, calls, constants, and assignments", json::object());
    }
    result.numeric_loops_recovered = recoverCanonicalStateNumericLoops(output);
    result.numeric_loops_recovered += recoverNumericForLoops(output);
    result.result_packs_collapsed += recoverFixedRegisterCallPacks(output);
    result.generic_loops_recovered = 0;
    if (result.numeric_loops_recovered)
    {
        result.dead_assignments_removed += eliminateDeadAssignments(output);
        result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
        removeUnusedResultDeclarations(output);
    }
    result.unused_command_results_removed = discardUnusedCommandResults(output);
    result.result_returns_collapsed += collapseEmptyResultReturns(output);
    removeUnusedResultDeclarations(output);
    result.locals_promoted = promoteStableLocals(output);
    result.numeric_loops_recovered += recoverNumericForLoops(output);
    result.generic_loops_recovered += recoverGenericForLoops(output);
    result.default_assignments_recovered = recoverDefaultAssignments(output);
    if (result.default_assignments_recovered)
    {
        const PropagationStats defaultPropagation = propagateConstants(output);
        result.constants_propagated += defaultPropagation.constants;
        result.aliases_propagated += defaultPropagation.aliases;
        result.properties_recovered += defaultPropagation.properties;
        result.methods_recovered += recoverMethodCalls(output);
        result.dead_assignments_removed += eliminateDeadAssignments(output);
        result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
        removeUnusedResultDeclarations(output);
    }
    result.unused_command_results_removed += discardUnusedCommandResults(output);
    result.result_returns_collapsed += collapseEmptyResultReturns(output);
    result.property_temporaries_inlined = inlinePropertyTemporaries(output);
    result.unused_call_results_removed = discardProvenUnusedCallResults(output);
    result.unused_call_results_removed += simplifyIgnoredCallScopes(output);
    result.dead_assignments_removed += eliminateDeadAssignments(output);
    result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
    removeUnusedResultDeclarations(output);
    result.declarations_pruned = pruneUnusedDeclarations(output);
    result.declarations_pruned += pruneUnusedDeclarations(output);
    const size_t lateDeadFactories = removeDeadPureCaptureFactories(output);
    result.dead_capture_factories_removed += lateDeadFactories;
    if (lateDeadFactories)
    {
        result.unused_cell_allocations_removed += removeShadowedCellAllocations(output);
        result.captured_cells_unboxed += unboxCapturedCells(output, true);
        while (true)
        {
            const CaptureFactoryStats lateFactoryStats = collapseUnusedCaptureFactories(output);
            result.unused_captures_removed += lateFactoryStats.captures;
            result.capture_factories_collapsed += lateFactoryStats.factories;
            if (lateFactoryStats.captures == 0 && lateFactoryStats.factories == 0)
                break;
        }
        const PropagationStats latePropagation = propagateStableCapturedAliases(output);
        result.constants_propagated += latePropagation.constants;
        result.aliases_propagated += latePropagation.aliases;
        result.properties_recovered += latePropagation.properties;
        result.methods_recovered += recoverMethodCalls(output);
        result.dead_assignments_removed += eliminateDeadAssignments(output);
        result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
        removeUnusedResultDeclarations(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
    }
    result.capture_factories_collapsed += lowerCaptureFactoriesToSnapshots(output);
    {
        const StableCaptureCellStats stableCells = scalarizeStableCaptureCells(output);
        result.stable_capture_cells_scalarized += stableCells.cells;
        result.stable_capture_accesses_scalarized += stableCells.accesses;
    }
    const size_t scopedSnapshotCallbacks = scopeSingleUseSnapshotCallbacks(output);
    result.callback_aliases_promoted += scopedSnapshotCallbacks;
    if (scopedSnapshotCallbacks)
    {
        result.declarations_pruned += pruneUnusedDeclarations(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
    }
    if (progress)
    {
        progress("structure_dataflow", "done", "Register dataflow and source expressions simplified",
            {{"dead_assignments_removed", result.dead_assignments_removed}, {"constants_propagated", result.constants_propagated},
                {"aliases_propagated", result.aliases_propagated}, {"methods_recovered", result.methods_recovered},
                {"numeric_loops_recovered", result.numeric_loops_recovered}, {"generic_loops_recovered", result.generic_loops_recovered},
                {"default_assignments_recovered", result.default_assignments_recovered},
                {"state_tables_scalarized", result.state_tables_scalarized},
                {"state_fields_scalarized", result.state_fields_scalarized},
                {"state_accesses_scalarized", result.state_accesses_scalarized}});
        progress("structure_source", "running", "Assigning semantic local names and emitting stable Luau source", json::object());
    }
    result.alias_reloads_eliminated = eliminateRedundantAliasReloads(output);
    result.captured_locals_named = nameSemanticCapturedLocals(output);
    result.semantic_locals_promoted = promoteSemanticLocals(output);
    result.semantic_initializers_coalesced = coalesceSemanticInitializers(output);
    for (size_t iteration = 0; iteration < 8; ++iteration)
    {
        const RegisterTableScalarStats lateRegisterTables = scalarReplaceRegisterTables(output, allowRegisterOverflow);
        if (lateRegisterTables.tables == 0)
            break;
        accumulateRegisterTables(lateRegisterTables);

        const PropagationStats lateScalarPropagation = propagateConstants(output);
        result.constants_propagated += lateScalarPropagation.constants;
        result.aliases_propagated += lateScalarPropagation.aliases;
        result.properties_recovered += lateScalarPropagation.properties;
        const PropagationStats lateScalarCapturedPropagation = propagateStableCapturedAliases(output);
        result.constants_propagated += lateScalarCapturedPropagation.constants;
        result.aliases_propagated += lateScalarCapturedPropagation.aliases;
        result.properties_recovered += lateScalarCapturedPropagation.properties;
        result.methods_recovered += recoverMethodCalls(output);
        result.dead_assignments_removed += eliminateDeadAssignments(output);
        result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
        removeUnusedResultDeclarations(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
        result.alias_reloads_eliminated += eliminateRedundantAliasReloads(output);
        result.captured_locals_named += nameSemanticCapturedLocals(output);
        result.semantic_locals_promoted += promoteSemanticLocals(output);
        result.semantic_initializers_coalesced += coalesceSemanticInitializers(output);
    }
    const StateTableScalarStats stateTables = allowScopedLifetimes
        ? scalarReplacePrivateStateTables(output) : StateTableScalarStats{};
    result.state_tables_scalarized += stateTables.tables;
    result.state_fields_scalarized += stateTables.fields;
    result.state_accesses_scalarized += stateTables.accesses;
    if (stateTables.tables > 0)
    {
        const PropagationStats statePropagation = propagateConstants(output);
        result.constants_propagated += statePropagation.constants;
        result.aliases_propagated += statePropagation.aliases;
        result.properties_recovered += statePropagation.properties;
        result.dead_assignments_removed += eliminateDeadAssignments(output);
        result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
    }
    const size_t lateStableBindings = nameStableCapturedBindings(output);
    result.locals_promoted += lateStableBindings;
    if (lateStableBindings)
    {
        result.semantic_locals_promoted += promoteSemanticLocals(output);
        result.semantic_initializers_coalesced += coalesceSemanticInitializers(output);
    }
    const size_t sourceMethods = recoverMethodCalls(output, true);
    result.methods_recovered += sourceMethods;
    if (sourceMethods)
    {
        const PropagationStats sourcePropagation = propagateConstants(output);
        result.constants_propagated += sourcePropagation.constants;
        result.aliases_propagated += sourcePropagation.aliases;
        result.properties_recovered += sourcePropagation.properties;
        result.dead_assignments_removed += eliminateDeadAssignments(output);
        result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
        removeUnusedResultDeclarations(output);
    }
    result.generic_loops_recovered += inlineGenericForIteratorSetup(output);
    result.semantic_lifetimes_split = splitSemanticLocalLifetimes(output, false);
    if (result.semantic_lifetimes_split)
    {
        result.declarations_pruned += pruneUnusedDeclarations(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
    }
    const size_t sourceLocals = promoteStableLocals(output);
    result.locals_promoted += sourceLocals;
    if (sourceLocals)
    {
        result.semantic_locals_promoted += promoteSemanticLocals(output);
        result.semantic_initializers_coalesced += coalesceSemanticInitializers(output);
    }
    for (size_t iteration = 0; iteration < 8; ++iteration)
    {
        const size_t guards = flattenTerminatingElseBranches(output);
        result.guard_clauses_flattened += guards;
        if (guards == 0)
            break;
    }
    for (size_t iteration = 0; iteration < 8; ++iteration)
    {
        const size_t defaults = recoverDefaultAssignments(output);
        const size_t conditionals = recoverTruthyConditionalAssignments(output);
        result.default_assignments_recovered += defaults + conditionals;
        if (defaults == 0 && conditionals == 0)
            break;
    }
    for (size_t iteration = 0; iteration < 2; ++iteration)
    {
        const auto conditionSpans = scalarFunctionSpans(output);
        if (!conditionSpans)
            break;
        const TemporaryBindingAnalysis conditionBindings = analyzeTemporaryBindings(output, *conditionSpans);
        const size_t conditions = inlineTemporaryConditions(output, *conditionSpans, conditionBindings);
        result.temporary_conditions_inlined += conditions;
        if (conditions == 0)
            break;
    }
    if (const auto deadTemporarySpans = scalarFunctionSpans(output))
    {
        const TemporaryBindingAnalysis deadTemporaryBindings = analyzeTemporaryBindings(output, *deadTemporarySpans);
        result.dead_assignments_removed += eliminateDeadTemporaryAssignments(output, deadTemporaryBindings);
    }
    for (size_t iteration = 0; iteration < 12; ++iteration)
    {
        const size_t expressions = inlineAdjacentSingleUseGeneratedExpressions(output);
        const size_t aliases = inlineAdjacentLexicalAliases(output);
        result.single_use_expressions_inlined += expressions;
        result.alias_reloads_eliminated += aliases;
        if (expressions == 0 && aliases == 0)
            break;
    }
    result.alias_reloads_eliminated += coalesceStraightLineAliases(output);
    size_t stableReadableAliases = 0;
    for (size_t iteration = 0; iteration < 2; ++iteration)
    {
        const size_t aliases = propagateStableReadableAliases(output);
        stableReadableAliases += aliases;
        if (aliases == 0)
            break;
    }
    result.alias_reloads_eliminated += stableReadableAliases;
    if (stableReadableAliases)
    {
        result.declarations_pruned += pruneUnusedDeclarations(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
    }
    for (size_t iteration = 0; iteration < 2; ++iteration)
    {
        const size_t deadVersions = eliminateUnobservedPureVersions(output);
        result.dead_assignments_removed += deadVersions;
        if (deadVersions == 0)
            break;
    }
    for (size_t iteration = 0; iteration < 8; ++iteration)
    {
        const auto temporarySpans = scalarFunctionSpans(output);
        if (!temporarySpans)
            break;
        const TemporaryBindingAnalysis temporaryBindings = analyzeTemporaryBindings(output, *temporarySpans);
        const size_t callbackAliases = promoteCallbackAliases(output, *temporarySpans, temporaryBindings);
        const size_t namedCallbackAliases = promoteNamedCallbackAliases(output, *temporarySpans);
        const size_t singleUseTemporaries =
            inlineAdjacentSingleUseTemporaries(output, *temporarySpans, temporaryBindings);
        result.callback_aliases_promoted += callbackAliases + namedCallbackAliases;
        result.single_use_temporaries_inlined += singleUseTemporaries;
        if (callbackAliases == 0 && namedCallbackAliases == 0 && singleUseTemporaries == 0)
            break;
    }
    result.result_packs_collapsed += collapseContiguousResultPacks(output);
    result.result_packs_collapsed += collapseResultPacksIntoSafeLvalues(output);
    result.result_packs_collapsed += scalarizeSparseResultPacks(output);
    result.generic_loops_recovered += inlineGenericForIteratorSetup(output);
    result.capture_factories_collapsed += lowerCaptureFactoriesToSnapshots(output);
    {
        const StableCaptureCellStats stableCells = scalarizeStableCaptureCells(output);
        result.stable_capture_cells_scalarized += stableCells.cells;
        result.stable_capture_accesses_scalarized += stableCells.accesses;
    }
    const size_t finalScopedSnapshotCallbacks = scopeSingleUseSnapshotCallbacks(output);
    result.callback_aliases_promoted += finalScopedSnapshotCallbacks;
    if (finalScopedSnapshotCallbacks)
    {
        result.declarations_pruned += pruneUnusedDeclarations(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
    }
    const size_t finalUnusedCells = removeUnusedCellAllocations(output);
    result.unused_cell_allocations_removed += finalUnusedCells;
    if (finalUnusedCells)
    {
        result.declarations_pruned += pruneUnusedDeclarations(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
    }
    if (const auto loweredFactorySpans = scalarFunctionSpans(output))
        result.callback_aliases_promoted += promoteNamedCallbackAliases(output, *loweredFactorySpans);
    if (const auto finalTemporarySpans = scalarFunctionSpans(output))
    {
        const TemporaryBindingAnalysis finalTemporaryBindings =
            analyzeTemporaryBindings(output, *finalTemporarySpans);
        result.dead_assignments_removed += eliminateDeadTemporaryAssignments(output, finalTemporaryBindings);
    }
    for (size_t iteration = 0; iteration < 4; ++iteration)
    {
        const size_t expressions = inlineAdjacentSingleUseGeneratedExpressions(output);
        result.single_use_expressions_inlined += expressions;
        if (expressions == 0)
            break;
    }
    result.dead_assignments_removed += eliminateDeadAssignments(output);
    result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
    result.dead_assignments_removed += eliminateOverwrittenPrivateRegisterSlots(output);
    for (size_t iteration = 0; iteration < 4; ++iteration)
    {
        const size_t simplified = simplifyEmptyBranches(output);
        result.empty_branches_removed += simplified;
        if (simplified == 0)
            break;
        result.dead_assignments_removed += eliminateDeadAssignments(output);
        result.dead_assignments_removed += eliminateStructuredDeadAssignments(output);
    }
    result.captured_locals_named += nameSemanticCapturedLocals(output);
    const size_t finalStableBindings = nameStableCapturedBindings(output);
    result.locals_promoted += finalStableBindings;
    if (finalStableBindings)
    {
        result.semantic_locals_promoted += promoteSemanticLocals(output);
        result.semantic_initializers_coalesced += coalesceSemanticInitializers(output);
    }
    result.producer_aliases_coalesced += coalesceAdjacentProducerAliases(output);
    result.alias_reloads_eliminated += collapseGuardedReceiverSnapshots(output);
    result.alias_reloads_eliminated += eliminateGuardedReceiverAliases(output);
    for (size_t iteration = 0; iteration < 8; ++iteration)
    {
        const size_t expressions = inlineAdjacentSingleUseGeneratedExpressions(output);
        const size_t aliases = inlineAdjacentLexicalAliases(output);
        result.single_use_expressions_inlined += expressions;
        result.alias_reloads_eliminated += aliases;
        if (expressions == 0 && aliases == 0)
            break;
    }
    result.methods_recovered += recoverMethodCalls(output, true);
    for (size_t iteration = 0; iteration < 8; ++iteration)
    {
        const size_t defaults = recoverDefaultAssignments(output);
        const size_t conditionals = recoverTruthyConditionalAssignments(output);
        const size_t expressions = inlineAdjacentSingleUseGeneratedExpressions(output);
        const size_t aliases = inlineAdjacentLexicalAliases(output);
        result.default_assignments_recovered += defaults + conditionals;
        result.single_use_expressions_inlined += expressions;
        result.alias_reloads_eliminated += aliases;
        if (defaults == 0 && conditionals == 0 && expressions == 0 && aliases == 0)
            break;
    }
    result.write_only_result_packs_removed += eliminateWriteOnlyResultPacks(output);
    result.property_temporaries_inlined += inlinePropertyTemporaries(output);
    removeUnusedResultDeclarations(output);
    result.declarations_pruned += pruneUnusedDeclarations(output);
    result.function_locals_promoted += promoteInitializedFunctionLocals(output);
    const size_t scopedLifetimes = allowScopedLifetimes ? splitSemanticLocalLifetimes(output, true) : 0;
    result.semantic_lifetimes_split += scopedLifetimes;
    if (scopedLifetimes)
    {
        result.declarations_pruned += pruneUnusedDeclarations(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
    }
    result.captured_locals_named += renameResidualCaptureArtifacts(output);
    result.replay_targets_inlined += inlineReplayTargetConditions(output);
    result.high_register_replay_patches_removed += removeClearedReplayMetadataPatches(output, 64);
    result.cleared_replay_metadata_patches_removed += removeClearedReplayMetadataPatches(output, 16);
    result.low_register_replay_patches_removed += removeClearedReplayMetadataPatches(output, 3);
    result.replay_branches_collapsed += collapseEquivalentReplayBranches(output);
    result.linear_replay_metadata_patches_removed += removeLinearReplayMetadataPatches(output, 3);
    result.discarded_anonymous_functions_removed += removeDiscardedAnonymousFunctionStatements(output);
    if (result.discarded_anonymous_functions_removed)
    {
        result.declarations_pruned += pruneUnusedDeclarations(output);
        result.empty_branches_removed += simplifyEmptyBranches(output);
    }
    result.result_packs_collapsed += simplifyConstantCallPacks(output);
    result.numeric_loops_recovered += recoverCanonicalStateNumericLoops(output);
    if (allowScopedLifetimes)
    {
        result.declarations_pruned += removeUnreferencedTopLevelHelpers(output);
        result.declarations_pruned += pruneUnusedDeclarations(output);
    }
    result.leading_semicolons_removed += removeEmbeddedExpressionSemicolons(output);
    result.redundant_parentheses_removed += removeRedundantExpressionParentheses(output);
    result.result_packs_collapsed += simplifyConstantCallPacks(output);
    for (size_t iteration = 0; iteration < 4; ++iteration)
    {
        const size_t simplified = simplifyEmptyBranches(output);
        result.empty_branches_removed += simplified;
        if (simplified == 0)
            break;
    }
    parenthesizeKeywordLiteralPrefixes(output);
    result.redundant_index_groupings_removed += removeRedundantIdentifierIndexGroupings(output);
    result.leading_semicolons_removed += removeSafeLeadingSemicolons(output);
    addRequiredLeadingSemicolons(output);
    result.numeric_literals_normalized = normalizeNumericLiterals(output);
    result.blank_lines_removed = compactGeneratedBlankLines(output);
    if (output.size() > 1 && trimView(output[1].text) == "-- This is a semantic payload state machine; protector setup has been removed.")
        output[1].text = "-- Control flow, closures, globals, properties, and method calls were reconstructed conservatively.";
    std::string rewritten;
    for (size_t index = 0; index < output.size(); ++index)
    {
        if (index)
            rewritten.push_back('\n');
        rewritten += output[index].text;
    }
    if (trailingNewline)
        rewritten.push_back('\n');
    result.changed = (result.regions_structured > 0 || result.dead_assignments_removed > 0 || result.constants_propagated > 0 ||
                         result.aliases_propagated > 0 || result.properties_recovered > 0 || result.methods_recovered > 0 ||
                         result.prototypes_nested > 0 || result.capture_references_recovered > 0 ||
                         result.globals_recovered > 0 ||
                         result.numeric_loops_recovered > 0 ||
                         result.generic_loops_recovered > 0 ||
                         result.unused_command_results_removed > 0 ||
                         result.locals_promoted > 0 ||
                         result.declarations_pruned > 0 ||
                         result.function_parameters_recovered > 0 ||
                         result.unused_captures_removed > 0 || result.capture_factories_collapsed > 0 ||
                         result.dead_capture_factories_removed > 0 ||
                         result.captured_cells_unboxed > 0 ||
                         result.stable_capture_cells_scalarized > 0 ||
                         result.returned_closures_recovered > 0 || result.function_locals_promoted > 0 ||
                         result.callback_aliases_promoted > 0 ||
                         result.direct_closure_calls_recovered > 0 ||
                         result.trace_instrumentation_removed > 0 ||
                         result.unreachable_prototypes_removed > 0 ||
                         result.replay_targets_inlined > 0 ||
                         result.high_register_replay_patches_removed > 0 ||
                         result.cleared_replay_metadata_patches_removed > 0 ||
                         result.low_register_replay_patches_removed > 0 ||
                         result.replay_branches_collapsed > 0 ||
                         result.linear_replay_metadata_patches_removed > 0 ||
                         result.discarded_anonymous_functions_removed > 0 ||
                         result.producer_aliases_coalesced > 0 ||
                         result.single_use_temporaries_inlined > 0 ||
                         result.single_use_expressions_inlined > 0 ||
                         result.redundant_parentheses_removed > 0 ||
                         result.leading_semicolons_removed > 0 ||
                         result.captured_locals_named > 0 ||
                         result.semantic_locals_promoted > 0 ||
                         result.semantic_lifetimes_split > 0 ||
                         result.temporary_conditions_inlined > 0 ||
                         result.guard_clauses_flattened > 0 ||
                         result.semantic_initializers_coalesced > 0 ||
                         result.single_assignment_aliases_folded > 0 ||
                         result.blank_lines_removed > 0 ||
                         result.property_temporaries_inlined > 0 ||
                         result.unused_call_results_removed > 0 ||
                         result.default_assignments_recovered > 0 ||
                         result.unused_cell_allocations_removed > 0 ||
                         result.result_returns_collapsed > 0 || result.result_packs_collapsed > 0 ||
                         result.fixed_top_call_packs_expanded > 0 ||
                         result.empty_branches_removed > 0 ||
                         result.write_only_result_packs_removed > 0 ||
                         result.state_registers_renamed > 0 ||
                         result.alias_reloads_eliminated > 0 ||
                         result.numeric_literals_normalized > 0 ||
                         result.register_tables_scalarized > 0 ||
                         result.state_tables_scalarized > 0) &&
        rewritten != source;
    result.source = result.changed ? std::move(rewritten) : std::string(source);
    if (progress)
    {
        progress("structure_source", "done", "Readable Luau source emitted",
            {{"captured_locals_named", result.captured_locals_named}, {"semantic_locals_promoted", result.semantic_locals_promoted},
                {"semantic_lifetimes_split", result.semantic_lifetimes_split},
                {"temporary_conditions_inlined", result.temporary_conditions_inlined},
                {"guard_clauses_flattened", result.guard_clauses_flattened},
                {"semantic_initializers_coalesced", result.semantic_initializers_coalesced}, {"blank_lines_removed", result.blank_lines_removed},
                {"alias_reloads_eliminated", result.alias_reloads_eliminated},
                {"single_use_temporaries_inlined", result.single_use_temporaries_inlined},
                {"single_use_expressions_inlined", result.single_use_expressions_inlined},
                {"stable_capture_cells_scalarized", result.stable_capture_cells_scalarized},
                {"stable_capture_accesses_scalarized", result.stable_capture_accesses_scalarized},
                {"producer_aliases_coalesced", result.producer_aliases_coalesced},
                {"write_only_result_packs_removed", result.write_only_result_packs_removed},
                {"callback_aliases_promoted", result.callback_aliases_promoted},
                {"direct_closure_calls_recovered", result.direct_closure_calls_recovered},
                {"trace_instrumentation_removed", result.trace_instrumentation_removed},
                {"unreachable_prototypes_removed", result.unreachable_prototypes_removed},
                {"replay_targets_inlined", result.replay_targets_inlined},
                {"high_register_replay_patches_removed", result.high_register_replay_patches_removed},
                {"cleared_replay_metadata_patches_removed", result.cleared_replay_metadata_patches_removed},
                {"low_register_replay_patches_removed", result.low_register_replay_patches_removed},
                {"replay_branches_collapsed", result.replay_branches_collapsed},
                {"linear_replay_metadata_patches_removed", result.linear_replay_metadata_patches_removed},
                {"numeric_literals_normalized", result.numeric_literals_normalized},
                {"redundant_parentheses_removed", result.redundant_parentheses_removed},
                {"register_tables_scalarized", result.register_tables_scalarized},
                {"register_tables_fully_scalarized", result.register_tables_fully_scalarized},
                {"register_tables_partially_scalarized", result.register_tables_partially_scalarized},
                {"register_table_slots_scalarized", result.register_table_slots_scalarized},
                {"register_table_accesses_scalarized", result.register_table_accesses_scalarized},
                {"state_tables_scalarized", result.state_tables_scalarized},
                {"state_fields_scalarized", result.state_fields_scalarized},
                {"state_accesses_scalarized", result.state_accesses_scalarized},
                {"output_lines", output.size()}, {"output_bytes", result.source.size()}});
        progress("provenance", "running", "Mapping reconstructed statements back to VM states and obfuscated locations", json::object());
    }
    result.mapping = result.changed ? remapStatements(mapping, output) : mapping;
    if (progress)
        progress("provenance", "done", "Statement provenance map completed",
            {{"mapped_statements", result.mapping.is_array() ? result.mapping.size() : 0}, {"output_lines", output.size()}});
    return result;
}

size_t splitResidualVmLifetimes(std::string& source)
{
    const bool trailingNewline = !source.empty() && source.back() == '\n';
    const std::vector<SourceLine> sourceLines = splitLines(source);
    std::vector<OutputLine> output;
    output.reserve(sourceLines.size());
    for (const SourceLine& line : sourceLines)
        output.push_back({line.text, line.origin, {}});

    size_t total = 0;
    for (size_t iteration = 0; iteration < 3; ++iteration)
    {
        const size_t split = splitSemanticLocalLifetimes(output, false, true);
        const size_t aliases = eliminateGuardedReceiverAliases(output);
        total += split + aliases;
        if (split == 0 && aliases == 0)
            break;
    }
    if (total == 0)
        return 0;

    std::string rewritten;
    for (size_t index = 0; index < output.size(); ++index)
    {
        if (index)
            rewritten.push_back('\n');
        rewritten += output[index].text;
    }
    if (trailingNewline)
        rewritten.push_back('\n');
    source = std::move(rewritten);
    return total;
}

void applyResidualBindingNames(RewriteResult& result, const ProgressCallback& progress, bool stabilizeResidualNames)
{
    const alex::deobfuscator::ResidualBindingRenameResult renamed =
        alex::deobfuscator::renameResidualBindings(result.source);
    result.residual_binding_diagnostics = json::array();
    for (const alex::deobfuscator::ResidualBindingDiagnostic& diagnostic : renamed.diagnostics)
        result.residual_binding_diagnostics.push_back({
            {"code", diagnostic.code},
            {"message", diagnostic.message},
            {"line", diagnostic.line},
            {"column", diagnostic.column},
        });

    if (!renamed.committed)
    {
        if (progress)
            progress("structure_names", "failed", "Residual binding names were left unchanged",
                {{"diagnostics", result.residual_binding_diagnostics.size()}});
        return;
    }

    result.residual_bindings_renamed = renamed.renamed;
    result.alias_reloads_eliminated += renamed.lexical_alias_versions_eliminated;
    result.residual_generated_bindings_renamed = renamed.generated_bindings_renamed;
    result.residual_temporary_bindings_renamed = renamed.temporary_bindings_renamed;
    result.residual_semantic_role_names = renamed.semantic_role_names;
    result.residual_generic_fallback_names = renamed.generic_fallback_names;
    result.residual_register_bindings_named = renamed.role_counts.registers;
    result.residual_mutable_cells_named = renamed.role_counts.mutable_cells;
    result.residual_callbacks_named = renamed.role_counts.callbacks;
    result.residual_vm_values_named = renamed.role_counts.vm_values;
    result.residual_vm_temporaries_named = renamed.role_counts.vm_temporaries;
    result.unused_local_declarations_removed = renamed.unused_declarations_removed;
    if (renamed.changed)
    {
        result.source = renamed.source;
        result.changed = true;
    }
    const size_t residualLifetimes = splitResidualVmLifetimes(result.source);
    result.semantic_lifetimes_split += residualLifetimes;
    if (residualLifetimes)
        result.changed = true;

    size_t postSplitAliases = 0;
    if (residualLifetimes)
    {
        for (size_t iteration = 0; iteration < 3; ++iteration)
        {
            const alex::deobfuscator::ResidualBindingRenameResult refined =
                alex::deobfuscator::renameResidualBindings(result.source);
            if (!refined.committed || !refined.changed || refined.source == result.source)
                break;
            result.source = refined.source;
            postSplitAliases += refined.lexical_alias_versions_eliminated;

            const size_t split = splitResidualVmLifetimes(result.source);
            result.semantic_lifetimes_split += split;
            if (split == 0 && refined.lexical_alias_versions_eliminated == 0)
                break;
        }
        result.alias_reloads_eliminated += postSplitAliases;
        result.changed = result.changed || postSplitAliases != 0;
    }

    size_t postSplitSemanticNames = 0;
    for (size_t iteration = 0; iteration < 4; ++iteration)
    {
        const alex::deobfuscator::ResidualBindingRenameResult semanticRefinement =
            alex::deobfuscator::refineResidualBindingNames(result.source);
        if (!semanticRefinement.committed || !semanticRefinement.changed || semanticRefinement.source == result.source)
            break;
        result.source = semanticRefinement.source;
        postSplitSemanticNames += semanticRefinement.renamed;
        result.residual_bindings_renamed += semanticRefinement.renamed;
        result.residual_generated_bindings_renamed += semanticRefinement.generated_bindings_renamed;
        result.residual_temporary_bindings_renamed += semanticRefinement.temporary_bindings_renamed;
        result.residual_semantic_role_names += semanticRefinement.semantic_role_names;
        result.residual_register_bindings_named += semanticRefinement.role_counts.registers;
        result.residual_mutable_cells_named += semanticRefinement.role_counts.mutable_cells;
        result.residual_callbacks_named += semanticRefinement.role_counts.callbacks;
        result.unused_local_declarations_removed += semanticRefinement.unused_declarations_removed;
        result.changed = true;
    }

    size_t straightLineVersions = 0;
    const alex::deobfuscator::ResidualBindingRenameResult straightLine =
        alex::deobfuscator::splitStraightLineResidualRoles(result.source);
    if (straightLine.committed && straightLine.changed && straightLine.source != result.source)
    {
        result.source = straightLine.source;
        straightLineVersions = straightLine.renamed;
        result.residual_bindings_renamed += straightLine.renamed;
        result.residual_generated_bindings_renamed += straightLine.generated_bindings_renamed;
        result.residual_temporary_bindings_renamed += straightLine.temporary_bindings_renamed;
        result.residual_semantic_role_names += straightLine.semantic_role_names;
        result.residual_callbacks_named += straightLine.role_counts.callbacks;
        result.changed = true;

        const alex::deobfuscator::ResidualBindingRenameResult cleanup =
            alex::deobfuscator::refineResidualBindingNames(result.source);
        if (cleanup.committed && cleanup.changed && cleanup.source != result.source)
        {
            result.source = cleanup.source;
            result.residual_bindings_renamed += cleanup.renamed;
            result.residual_generated_bindings_renamed += cleanup.generated_bindings_renamed;
            result.residual_temporary_bindings_renamed += cleanup.temporary_bindings_renamed;
            result.residual_semantic_role_names += cleanup.semantic_role_names;
            result.unused_local_declarations_removed += cleanup.unused_declarations_removed;
        }
    }

    const alex::deobfuscator::ResidualBindingRenameResult stabilized = stabilizeResidualNames
        ? alex::deobfuscator::stabilizeResidualBindingNames(result.source)
        : alex::deobfuscator::ResidualBindingRenameResult{};
    if (stabilizeResidualNames && stabilized.committed && stabilized.changed && stabilized.source != result.source)
    {
        result.source = stabilized.source;
        result.residual_bindings_renamed += stabilized.renamed;
        result.residual_generated_bindings_renamed += stabilized.generated_bindings_renamed;
        result.residual_temporary_bindings_renamed += stabilized.temporary_bindings_renamed;
        result.residual_semantic_role_names += stabilized.semantic_role_names;
        result.residual_generated_merge_names += stabilized.generated_merge_names;
        result.unused_local_declarations_removed += stabilized.unused_declarations_removed;
        result.changed = true;
    }

    const alex::deobfuscator::ResidualBindingRenameResult callbackPurposes =
        alex::deobfuscator::renameGeneratedCallbackPurposes(result.source);
    size_t callbackPurposeNames = 0;
    if (callbackPurposes.committed && callbackPurposes.changed && callbackPurposes.source != result.source)
    {
        result.source = callbackPurposes.source;
        callbackPurposeNames = callbackPurposes.renamed;
        result.residual_bindings_renamed += callbackPurposes.renamed;
        result.residual_semantic_role_names += callbackPurposes.semantic_role_names;
        result.changed = true;
    }

    if (progress)
        progress("structure_names", "done", "Residual bindings received scope-safe structural names",
            {{"bindings_renamed", result.residual_bindings_renamed},
                {"lexical_alias_versions_eliminated", renamed.lexical_alias_versions_eliminated},
                {"post_split_aliases_eliminated", postSplitAliases},
                {"post_split_semantic_names", postSplitSemanticNames},
                {"straight_line_semantic_versions", straightLineVersions},
                {"residual_lifetimes_split", residualLifetimes},
                {"semantic_roles", result.residual_semantic_role_names},
                {"generic_fallbacks", result.residual_generic_fallback_names},
                {"generated_merge_names", result.residual_generated_merge_names},
                {"callback_purpose_names", callbackPurposeNames},
                {"unused_declarations_removed", result.unused_local_declarations_removed},
                {"registers", result.residual_register_bindings_named},
                {"mutable_cells", result.residual_mutable_cells_named},
                {"callbacks", result.residual_callbacks_named},
                {"vm_values", result.residual_vm_values_named},
                {"vm_temporaries", result.residual_vm_temporaries_named},
                {"output_bytes", result.source.size()}});
}

struct ReplayCompressionStats
{
    size_t calls = 0;
    size_t entries = 0;
    size_t bytes = 0;
};

ReplayCompressionStats compressReplaySequenceTables(std::string& source)
{
    ReplayCompressionStats stats;
    const bool trailingNewline = !source.empty() && source.back() == '\n';
    std::vector<std::string> lines;
    for (size_t begin = 0; begin < source.size();)
    {
        const size_t end = source.find('\n', begin);
        lines.push_back(source.substr(begin, end == std::string::npos ? source.size() - begin : end - begin));
        if (end == std::string::npos)
            break;
        begin = end + 1;
    }
    if (trailingNewline && !lines.empty() && lines.back().empty())
        lines.pop_back();

    constexpr std::array<std::string_view, 2> ReplayFunctions{
        "replay_runtime_lanes", "replay_activation_transition"};
    for (std::string& line : lines)
    {
        size_t function = std::string::npos;
        std::string_view functionName;
        for (std::string_view candidate : ReplayFunctions)
            if (const size_t position = line.find(std::string(candidate) + "("); position != std::string::npos)
            {
                function = position;
                functionName = candidate;
                break;
            }
        if (function == std::string::npos)
            continue;
        const size_t open = function + functionName.size();
        size_t close = open + 1;
        int depth = 1;
        char quote = 0;
        for (; close < line.size() && depth > 0; ++close)
        {
            const char ch = line[close];
            if (quote != 0)
            {
                if (ch == '\\')
                    ++close;
                else if (ch == quote)
                    quote = 0;
                continue;
            }
            if (ch == '\'' || ch == '"')
                quote = ch;
            else if (ch == '(')
                ++depth;
            else if (ch == ')')
                --depth;
        }
        if (depth != 0 || close <= open + 1)
            continue;
        --close;
        std::vector<std::string> arguments =
            splitCaptureExpressions(std::string_view(line).substr(open + 1, close - open - 1));
        if (arguments.size() != 5)
            continue;
        std::string_view sequences = trimView(arguments[3]);
        if (sequences.size() < 2 || sequences.front() != '{' || sequences.back() != '}')
            continue;
        const std::vector<std::string> entries =
            splitCaptureExpressions(sequences.substr(1, sequences.size() - 2));
        if (entries.size() < 2)
            continue;

        std::string runs = "expand_replay_runs({";
        size_t runCount = 0;
        for (size_t entry = 0; entry < entries.size();)
        {
            size_t runEnd = entry + 1;
            while (runEnd < entries.size() && trimView(entries[runEnd]) == trimView(entries[entry]))
                ++runEnd;
            if (runCount++)
                runs += ", ";
            runs += "{" + std::to_string(runEnd - entry) + ", " + trim(entries[entry]) + "}";
            entry = runEnd;
        }
        runs += "})";
        if (runCount == entries.size() || runs.size() >= arguments[3].size())
            continue;
        arguments[3] = std::move(runs);
        std::string replacement;
        for (size_t argument = 0; argument < arguments.size(); ++argument)
        {
            if (argument)
                replacement += ", ";
            replacement += arguments[argument];
        }
        const size_t oldSize = close - open - 1;
        if (replacement.size() >= oldSize)
            continue;
        line.replace(open + 1, oldSize, replacement);
        ++stats.calls;
        stats.entries += entries.size() - runCount;
        stats.bytes += oldSize - replacement.size();
    }

    std::string compressed;
    for (size_t line = 0; line < lines.size(); ++line)
    {
        if (line)
            compressed.push_back('\n');
        compressed += lines[line];
    }
    if (trailingNewline)
        compressed.push_back('\n');
    source = std::move(compressed);
    return stats;
}

void finalizeReplayCompression(RewriteResult& result, const ProgressCallback& progress = {})
{
    const ReplayCompressionStats stats = compressReplaySequenceTables(result.source);
    result.replay_sequences_compressed += stats.calls;
    result.replay_sequence_entries_collapsed += stats.entries;
    result.replay_bytes_removed += stats.bytes;
    if (progress && stats.calls > 0)
        progress("structure_replay", "done", "Repeated trace activations compressed after CFG recovery",
            {{"sequences_compressed", stats.calls},
                {"entries_collapsed", stats.entries},
                {"bytes_removed", stats.bytes},
                {"output_bytes", result.source.size()}});
}

RewriteResult rewriteStateMachines(
    std::string_view source, const nlohmann::json& mapping, const ProgressCallback& progress,
    const RewriteOptions& options)
{
    RewriteResult result = rewriteStateMachinesOnce(source, mapping, progress, false, options.allow_register_overflow);
    if (!result.changed)
    {
        applyResidualBindingNames(result, progress, options.stabilize_residual_names);
        finalizeReplayCompression(result, progress);
        return result;
    }

    RewriteResult refined = rewriteStateMachinesOnce(result.source, result.mapping, {}, true, options.allow_register_overflow);
    if (!refined.changed || refined.source == result.source)
    {
        applyResidualBindingNames(result, progress, options.stabilize_residual_names);
        finalizeReplayCompression(result, progress);
        return result;
    }

#define ACCUMULATE_REWRITE_METRIC(field) result.field += refined.field
    ACCUMULATE_REWRITE_METRIC(regions_found);
    ACCUMULATE_REWRITE_METRIC(regions_structured);
    ACCUMULATE_REWRITE_METRIC(blocks_structured);
    ACCUMULATE_REWRITE_METRIC(reentry_nodes_split);
    ACCUMULATE_REWRITE_METRIC(residual_state_machines);
    ACCUMULATE_REWRITE_METRIC(dead_assignments_removed);
    ACCUMULATE_REWRITE_METRIC(constants_propagated);
    ACCUMULATE_REWRITE_METRIC(aliases_propagated);
    ACCUMULATE_REWRITE_METRIC(properties_recovered);
    ACCUMULATE_REWRITE_METRIC(methods_recovered);
    ACCUMULATE_REWRITE_METRIC(prototypes_nested);
    ACCUMULATE_REWRITE_METRIC(capture_references_recovered);
    ACCUMULATE_REWRITE_METRIC(globals_recovered);
    ACCUMULATE_REWRITE_METRIC(numeric_loops_recovered);
    ACCUMULATE_REWRITE_METRIC(generic_loops_recovered);
    ACCUMULATE_REWRITE_METRIC(unused_command_results_removed);
    ACCUMULATE_REWRITE_METRIC(locals_promoted);
    ACCUMULATE_REWRITE_METRIC(declarations_pruned);
    ACCUMULATE_REWRITE_METRIC(function_parameters_recovered);
    ACCUMULATE_REWRITE_METRIC(unused_captures_removed);
    ACCUMULATE_REWRITE_METRIC(capture_factories_collapsed);
    ACCUMULATE_REWRITE_METRIC(dead_capture_factories_removed);
    ACCUMULATE_REWRITE_METRIC(captured_cells_unboxed);
    ACCUMULATE_REWRITE_METRIC(stable_capture_cells_scalarized);
    ACCUMULATE_REWRITE_METRIC(stable_capture_accesses_scalarized);
    ACCUMULATE_REWRITE_METRIC(returned_closures_recovered);
    ACCUMULATE_REWRITE_METRIC(function_locals_promoted);
    ACCUMULATE_REWRITE_METRIC(leading_semicolons_removed);
    ACCUMULATE_REWRITE_METRIC(redundant_index_groupings_removed);
    ACCUMULATE_REWRITE_METRIC(redundant_parentheses_removed);
    ACCUMULATE_REWRITE_METRIC(captured_locals_named);
    ACCUMULATE_REWRITE_METRIC(semantic_locals_promoted);
    ACCUMULATE_REWRITE_METRIC(semantic_initializers_coalesced);
    ACCUMULATE_REWRITE_METRIC(single_assignment_aliases_folded);
    ACCUMULATE_REWRITE_METRIC(blank_lines_removed);
    ACCUMULATE_REWRITE_METRIC(property_temporaries_inlined);
    ACCUMULATE_REWRITE_METRIC(unused_call_results_removed);
    ACCUMULATE_REWRITE_METRIC(default_assignments_recovered);
    ACCUMULATE_REWRITE_METRIC(unused_cell_allocations_removed);
    ACCUMULATE_REWRITE_METRIC(result_returns_collapsed);
    ACCUMULATE_REWRITE_METRIC(result_packs_collapsed);
    ACCUMULATE_REWRITE_METRIC(fixed_top_call_packs_expanded);
    ACCUMULATE_REWRITE_METRIC(write_only_result_packs_removed);
    ACCUMULATE_REWRITE_METRIC(empty_branches_removed);
    ACCUMULATE_REWRITE_METRIC(state_registers_renamed);
    ACCUMULATE_REWRITE_METRIC(alias_reloads_eliminated);
    ACCUMULATE_REWRITE_METRIC(producer_aliases_coalesced);
    ACCUMULATE_REWRITE_METRIC(numeric_literals_normalized);
    ACCUMULATE_REWRITE_METRIC(register_table_slots_scalarized);
    ACCUMULATE_REWRITE_METRIC(register_table_accesses_scalarized);
    ACCUMULATE_REWRITE_METRIC(state_tables_scalarized);
    ACCUMULATE_REWRITE_METRIC(state_fields_scalarized);
    ACCUMULATE_REWRITE_METRIC(state_accesses_scalarized);
    ACCUMULATE_REWRITE_METRIC(replay_sequences_compressed);
    ACCUMULATE_REWRITE_METRIC(replay_sequence_entries_collapsed);
    ACCUMULATE_REWRITE_METRIC(replay_bytes_removed);
    ACCUMULATE_REWRITE_METRIC(replay_targets_inlined);
    ACCUMULATE_REWRITE_METRIC(high_register_replay_patches_removed);
    ACCUMULATE_REWRITE_METRIC(cleared_replay_metadata_patches_removed);
    ACCUMULATE_REWRITE_METRIC(low_register_replay_patches_removed);
    ACCUMULATE_REWRITE_METRIC(replay_branches_collapsed);
    ACCUMULATE_REWRITE_METRIC(linear_replay_metadata_patches_removed);
    ACCUMULATE_REWRITE_METRIC(discarded_anonymous_functions_removed);
    ACCUMULATE_REWRITE_METRIC(single_use_temporaries_inlined);
    ACCUMULATE_REWRITE_METRIC(single_use_expressions_inlined);
    ACCUMULATE_REWRITE_METRIC(callback_aliases_promoted);
    ACCUMULATE_REWRITE_METRIC(direct_closure_calls_recovered);
    ACCUMULATE_REWRITE_METRIC(trace_instrumentation_removed);
    ACCUMULATE_REWRITE_METRIC(unreachable_prototypes_removed);
    ACCUMULATE_REWRITE_METRIC(semantic_lifetimes_split);
    ACCUMULATE_REWRITE_METRIC(temporary_conditions_inlined);
    ACCUMULATE_REWRITE_METRIC(guard_clauses_flattened);
#undef ACCUMULATE_REWRITE_METRIC
    result.register_tables_scalarized = std::max(result.register_tables_scalarized, refined.register_tables_scalarized);
    result.register_tables_fully_scalarized =
        std::max(result.register_tables_fully_scalarized, refined.register_tables_fully_scalarized);
    result.register_tables_partially_scalarized =
        std::max(result.register_tables_partially_scalarized, refined.register_tables_partially_scalarized);
    for (auto item = refined.residual_reasons.begin(); item != refined.residual_reasons.end(); ++item)
        result.residual_reasons[item.key()] = result.residual_reasons.value(item.key(), 0) + item.value().get<size_t>();
    result.source = std::move(refined.source);
    result.mapping = std::move(refined.mapping);
    result.refinement_passes = 1;
    if (progress)
    {
        const size_t outputLines = result.source.empty()
            ? 0
            : static_cast<size_t>(std::count(result.source.begin(), result.source.end(), '\n')) +
                (result.source.back() == '\n' ? 0 : 1);
        progress("structure_refine", "done", "Second readability refinement completed",
            {{"passes", result.refinement_passes},
                {"dead_assignments_removed", refined.dead_assignments_removed},
                {"declarations_pruned", refined.declarations_pruned},
                {"semantic_lifetimes_split", refined.semantic_lifetimes_split},
                {"register_tables_scalarized", result.register_tables_scalarized},
                {"register_tables_fully_scalarized", result.register_tables_fully_scalarized},
                {"register_tables_partially_scalarized", result.register_tables_partially_scalarized},
                {"register_table_slots_scalarized", result.register_table_slots_scalarized},
                {"register_table_accesses_scalarized", result.register_table_accesses_scalarized},
                {"state_tables_scalarized", result.state_tables_scalarized},
                {"state_fields_scalarized", result.state_fields_scalarized},
                {"state_accesses_scalarized", result.state_accesses_scalarized},
                {"direct_closure_calls_recovered", result.direct_closure_calls_recovered},
                {"trace_instrumentation_removed", result.trace_instrumentation_removed},
                {"unreachable_prototypes_removed", result.unreachable_prototypes_removed},
                {"replay_targets_inlined", result.replay_targets_inlined},
                {"high_register_replay_patches_removed", result.high_register_replay_patches_removed},
                {"cleared_replay_metadata_patches_removed", result.cleared_replay_metadata_patches_removed},
                {"low_register_replay_patches_removed", result.low_register_replay_patches_removed},
                {"replay_branches_collapsed", result.replay_branches_collapsed},
                {"linear_replay_metadata_patches_removed", result.linear_replay_metadata_patches_removed},
                {"discarded_anonymous_functions_removed", result.discarded_anonymous_functions_removed},
                {"output_lines", outputLines},
                {"output_bytes", result.source.size()}});
    }
    applyResidualBindingNames(result, progress, options.stabilize_residual_names);
    finalizeReplayCompression(result, progress);
    return result;
}

RewriteResult rewriteStateMachinesSinglePass(
    std::string_view source, const nlohmann::json& mapping, const ProgressCallback& progress)
{
    RewriteResult result = rewriteStateMachinesOnce(source, mapping, progress, true, false);
    finalizeReplayCompression(result, progress);
    return result;
}

} // namespace alex::deobfuscator::readable
