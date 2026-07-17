#include "prometheus/lift.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace alex::deobfuscator::prometheus
{
namespace
{

using json = nlohmann::json;

constexpr int64_t kStateModulus = 35184372088832LL;
constexpr int64_t kWordModulus = 4294967296LL;

bool identifier(std::string_view value)
{
    if (value.empty() || !(value.front() == '_' || std::isalpha(static_cast<unsigned char>(value.front()))))
        return false;
    return std::all_of(value.begin() + 1, value.end(), [](unsigned char ch) { return ch == '_' || std::isalnum(ch); });
}

std::string quote(std::string_view value)
{
    std::string result = "\"";
    for (unsigned char ch : value)
    {
        switch (ch)
        {
        case '\\': result += "\\\\"; break;
        case '\"': result += "\\\""; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (ch < 32 || ch == 127 || ch >= 128)
            {
                char escaped[5];
                std::snprintf(escaped, sizeof(escaped), "\\%03u", static_cast<unsigned int>(ch));
                result += escaped;
            }
            else
                result.push_back(static_cast<char>(ch));
        }
    }
    result.push_back('\"');
    return result;
}

std::string bytesFromHex(std::string_view hex)
{
    if (hex.size() % 2 != 0)
        return {};
    std::string result;
    result.reserve(hex.size() / 2);
    for (size_t index = 0; index < hex.size(); index += 2)
    {
        unsigned int value = 0;
        auto parsed = std::from_chars(hex.data() + index, hex.data() + index + 2, value, 16);
        if (parsed.ec != std::errc{})
            return {};
        result.push_back(static_cast<char>(value));
    }
    return result;
}

std::optional<double> number(const json& expression, size_t depth = 0)
{
    if (depth > 64 || !expression.is_object())
        return std::nullopt;
    const std::string op = expression.value("op", "");
    if (op == "constant" && expression.contains("value") && expression["value"].is_number())
        return expression["value"].get<double>();
    if (op == "group")
        return number(expression.value("value", json::object()), depth + 1);
    if (op == "unary" && expression.value("operator", "") == "-")
    {
        auto value = number(expression.value("value", json::object()), depth + 1);
        return value ? std::optional<double>(-*value) : std::nullopt;
    }
    if (op != "binary")
        return std::nullopt;
    auto left = number(expression.value("left", json::object()), depth + 1);
    auto right = number(expression.value("right", json::object()), depth + 1);
    if (!left || !right)
        return std::nullopt;
    const std::string binary = expression.value("operator", "");
    if (binary == "+") return *left + *right;
    if (binary == "-") return *left - *right;
    if (binary == "*") return *left * *right;
    if (binary == "/" && *right != 0) return *left / *right;
    if (binary == "//" && *right != 0) return std::floor(*left / *right);
    if (binary == "%" && *right != 0) return std::fmod(*left, *right);
    if (binary == "^") return std::pow(*left, *right);
    return std::nullopt;
}

std::optional<int64_t> integer(const json& expression)
{
    auto value = number(expression);
    if (!value || !std::isfinite(*value) || std::abs(*value - std::round(*value)) > 1e-7 ||
        *value < static_cast<double>(std::numeric_limits<int64_t>::min()) ||
        *value > static_cast<double>(std::numeric_limits<int64_t>::max()))
        return std::nullopt;
    return static_cast<int64_t>(std::llround(*value));
}

std::optional<std::string> constantString(const json& expression)
{
    if (!expression.is_object() || expression.value("op", "") != "constant")
        return std::nullopt;
    if (expression.value("kind", "") == "bytes")
        return bytesFromHex(expression.value("hex", ""));
    if (expression.value("kind", "") == "string")
        return expression.value("value", "");
    if (expression.contains("value") && expression["value"].is_string())
        return expression["value"].get<std::string>();
    return std::nullopt;
}

std::optional<std::string> localRead(const json& expression)
{
    if (expression.is_object() && expression.value("op", "") == "local_read")
        return expression.value("name", "");
    return std::nullopt;
}

std::optional<std::string> singleLocalTarget(const json& statement)
{
    if (!statement.is_object() || (statement.value("op", "") != "assign" && statement.value("op", "") != "local_assign"))
        return std::nullopt;
    const json targets = statement.value("targets", json::array());
    if (targets.size() != 1 || targets[0].value("kind", "") != "local")
        return std::nullopt;
    return targets[0].value("name", "");
}

std::optional<std::string> singleNamedTarget(const json& statement)
{
    if (!statement.is_object() || (statement.value("op", "") != "assign" && statement.value("op", "") != "local_assign"))
        return std::nullopt;
    const json targets = statement.value("targets", json::array());
    if (targets.size() != 1 || (targets[0].value("kind", "") != "local" && targets[0].value("kind", "") != "program_counter"))
        return std::nullopt;
    return targets[0].value("name", "");
}

std::optional<json> singleValue(const json& statement)
{
    const json values = statement.value("values", json::array());
    if (values.size() != 1)
        return std::nullopt;
    return values[0];
}

void walk(const json& value, const std::function<void(const json&)>& visitor)
{
    if (value.is_array())
    {
        for (const json& item : value)
            walk(item, visitor);
        return;
    }
    if (!value.is_object())
        return;
    visitor(value);
    for (const auto& [key, item] : value.items())
    {
        (void)key;
        walk(item, visitor);
    }
}

bool containsInteger(const json& value, int64_t wanted)
{
    bool found = false;
    walk(value, [&](const json& item) {
        if (!found)
            if (auto candidate = integer(item); candidate && *candidate == wanted)
                found = true;
    });
    return found;
}

bool containsString(const json& value, std::string_view wanted)
{
    bool found = false;
    walk(value, [&](const json& item) {
        if (!found)
            if (auto candidate = constantString(item); candidate && *candidate == wanted)
                found = true;
    });
    return found;
}

json resolveLocalsBounded(
    const json& expression,
    const std::unordered_map<std::string, json>& values,
    std::unordered_set<std::string>& active,
    size_t& budget,
    size_t depth)
{
    if (budget == 0 || depth > 32 || !expression.is_object())
        return expression;
    --budget;
    if (auto name = localRead(expression))
    {
        auto found = values.find(*name);
        if (found != values.end() && active.insert(*name).second)
        {
            json resolved = resolveLocalsBounded(found->second, values, active, budget, depth + 1);
            active.erase(*name);
            return resolved;
        }
        return expression;
    }
    json result = expression;
    for (auto& [key, item] : result.items())
    {
        (void)key;
        if (item.is_object())
            item = resolveLocalsBounded(item, values, active, budget, depth + 1);
        else if (item.is_array())
            for (json& child : item)
                if (child.is_object())
                    child = resolveLocalsBounded(child, values, active, budget, depth + 1);
    }
    return result;
}

json resolveLocals(const json& expression, const std::unordered_map<std::string, json>& values)
{
    size_t budget = 4096;
    std::unordered_set<std::string> active;
    return resolveLocalsBounded(expression, values, active, budget, 0);
}

struct Cipher
{
    int64_t decrypt_entry = 0;
    int64_t multiply_45 = 0;
    int64_t add_45 = 0;
    int64_t multiply_8 = 0;
    int64_t initial_byte = -1;

    bool complete() const
    {
        return decrypt_entry != 0 && multiply_45 > 0 && add_45 > 0 && multiply_8 > 0 && initial_byte >= 0 && initial_byte <= 255;
    }
};

std::vector<int64_t> prototypeBlocks(const json& prototype)
{
    std::vector<int64_t> result;
    for (const json& state : prototype.value("blocks", json::array()))
        if (state.is_number_integer())
            result.push_back(state.get<int64_t>());
    return result;
}

json joinedInstructions(const LiftRequest& request, const json& prototype)
{
    json result = json::array();
    for (int64_t state : prototypeBlocks(prototype))
    {
        auto found = request.blocks.find(state);
        if (found != request.blocks.end())
            for (const json& statement : found->second)
                result.push_back(statement);
    }
    return result;
}

std::optional<int64_t> multiplicationFactor(const json& expression)
{
    if (!expression.is_object() || expression.value("op", "") != "binary" || expression.value("operator", "") != "*")
        return std::nullopt;
    auto left = integer(expression.value("left", json::object()));
    auto right = integer(expression.value("right", json::object()));
    if (left && !right)
        return left;
    if (right && !left)
        return right;
    return std::nullopt;
}

void recoverGeneratorFormula(const json& instructions, Cipher& cipher)
{
    for (const json& block : instructions)
    {
        if (!block.is_array())
            continue;
        std::unordered_map<std::string, json> values;
        for (const json& statement : block)
        {
            auto target = singleNamedTarget(statement);
            auto rawValue = singleValue(statement);
            if (!target || !rawValue)
                continue;
            json value = resolveLocals(*rawValue, values);
            if (value.value("op", "") == "binary" && value.value("operator", "") == "%")
            {
                auto divisor = integer(value.value("right", json::object()));
                const json numerator = value.value("left", json::object());
                if (divisor && *divisor == kStateModulus && numerator.value("op", "") == "binary" && numerator.value("operator", "") == "+")
                {
                    const json left = numerator.value("left", json::object());
                    const json right = numerator.value("right", json::object());
                    auto leftFactor = multiplicationFactor(left);
                    auto rightFactor = multiplicationFactor(right);
                    auto leftNumber = integer(left);
                    auto rightNumber = integer(right);
                    if (leftFactor && rightNumber)
                    {
                        cipher.multiply_45 = *leftFactor;
                        cipher.add_45 = *rightNumber;
                    }
                    else if (rightFactor && leftNumber)
                    {
                        cipher.multiply_45 = *rightFactor;
                        cipher.add_45 = *leftNumber;
                    }
                }
                else if (divisor && *divisor == 257)
                    if (auto factor = multiplicationFactor(numerator))
                        cipher.multiply_8 = *factor;
            }
            values[*target] = std::move(value);
        }
    }
}

Cipher recoverCipher(const LiftRequest& request)
{
    Cipher result;
    json generatorBlocks = json::array();
    json decryptBlocks = json::array();
    json decryptInstructions = json::array();
    for (const json& prototype : request.prototypes)
    {
        json instructions = joinedInstructions(request, prototype);
        const bool generator = containsInteger(instructions, kStateModulus) && containsInteger(instructions, kWordModulus) &&
            containsInteger(instructions, 65536) && containsInteger(instructions, 257);
        const bool decryptorModuli = containsInteger(instructions, kStateModulus) && containsInteger(instructions, 255) &&
            containsInteger(instructions, 256);
        const bool decryptorNames = containsString(instructions, "byte") && containsString(instructions, "len");
        const bool decryptor = decryptorModuli && (decryptorNames || !generator);
        if (generator)
            for (int64_t state : prototypeBlocks(prototype))
            {
                auto found = request.blocks.find(state);
                if (found != request.blocks.end())
                    generatorBlocks.push_back(found->second);
            }
        if (decryptor)
        {
            result.decrypt_entry = prototype.value("entry_state", 0LL);
            decryptInstructions = std::move(instructions);
            for (int64_t state : prototypeBlocks(prototype))
            {
                auto found = request.blocks.find(state);
                if (found != request.blocks.end())
                    decryptBlocks.push_back(found->second);
            }
        }
    }
    recoverGeneratorFormula(generatorBlocks, result);
    if (!result.decrypt_entry || decryptInstructions.empty())
        return result;

    struct AssignmentPair
    {
        std::string target;
        json value;
    };
    auto assignmentPairs = [](const json& statement) {
        std::vector<AssignmentPair> pairs;
        if (!statement.is_object() || (statement.value("op", "") != "assign" && statement.value("op", "") != "local_assign"))
            return pairs;
        const json targets = statement.value("targets", json::array());
        const json values = statement.value("values", json::array());
        for (size_t index = 0; index < std::min(targets.size(), values.size()); ++index)
        {
            const std::string kind = targets[index].value("kind", "");
            if (kind == "local" || kind == "program_counter")
                pairs.push_back({targets[index].value("name", ""), values[index]});
        }
        return pairs;
    };

    std::set<std::string> moduloOutputs;
    for (const json& block : decryptBlocks)
    {
        std::unordered_map<std::string, json> values;
        for (const json& statement : block)
        {
            std::vector<AssignmentPair> pairs = assignmentPairs(statement);
            std::vector<AssignmentPair> resolved;
            for (const AssignmentPair& pair : pairs)
            {
                json value = resolveLocals(pair.value, values);
                if (value.value("op", "") == "binary" && value.value("operator", "") == "%")
                    if (auto divisor = integer(value.value("right", json::object())); divisor && *divisor == 256)
                        moduloOutputs.insert(pair.target);
                resolved.push_back({pair.target, std::move(value)});
            }
            for (AssignmentPair& pair : resolved)
                values[pair.target] = std::move(pair.value);
        }
    }

    std::set<std::string> previousByteVariables = moduloOutputs;
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (const json& statement : decryptInstructions)
            for (const AssignmentPair& pair : assignmentPairs(statement))
                if (auto source = localRead(pair.value); source && previousByteVariables.contains(*source))
                    changed = previousByteVariables.insert(pair.target).second || changed;
    }
    for (const json& statement : decryptInstructions)
    {
        for (const AssignmentPair& pair : assignmentPairs(statement))
        {
            if (!previousByteVariables.contains(pair.target))
                continue;
            if (auto candidate = integer(pair.value); candidate && *candidate >= 0 && *candidate <= 255)
                result.initial_byte = *candidate;
        }
    }
    return result;
}

std::string decrypt(const Cipher& cipher, std::string_view encrypted, int64_t seed)
{
    double state45 = std::fmod(static_cast<double>(seed), static_cast<double>(kStateModulus));
    double state8 = std::fmod(static_cast<double>(seed), 255.0) + 2.0;
    std::vector<double> previous;
    auto randomByte = [&]() -> int {
        if (previous.empty())
        {
            state45 = std::fmod(state45 * static_cast<double>(cipher.multiply_45) + static_cast<double>(cipher.add_45),
                static_cast<double>(kStateModulus));
            do
                state8 = std::fmod(state8 * static_cast<double>(cipher.multiply_8), 257.0);
            while (state8 == 1.0);
            const double r = std::fmod(state8, 32.0);
            const double exponent = 13.0 - (state8 - r) / 32.0;
            const double n = std::fmod(std::floor(state45 / std::pow(2.0, exponent)), static_cast<double>(kWordModulus)) / std::pow(2.0, r);
            const double random = std::floor(std::fmod(n, 1.0) * static_cast<double>(kWordModulus)) + std::floor(n);
            const double low = std::fmod(random, 65536.0);
            const double high = (random - low) / 65536.0;
            const double first = std::fmod(low, 256.0);
            const double second = (low - first) / 256.0;
            const double third = std::fmod(high, 256.0);
            const double fourth = (high - third) / 256.0;
            previous = {first, second, third, fourth};
        }
        const int value = static_cast<int>(std::llround(previous.back()));
        previous.pop_back();
        return value;
    };

    std::string output;
    output.reserve(encrypted.size());
    int previousByte = static_cast<int>(cipher.initial_byte);
    for (unsigned char byte : encrypted)
    {
        previousByte = (static_cast<int>(byte) + randomByte() + previousByte) % 256;
        output.push_back(static_cast<char>(previousByte));
    }
    return output;
}

bool callNamed(const json& expression, std::string_view name)
{
    if (!expression.is_object() || expression.value("op", "") != "call")
        return false;
    const json function = expression.value("function", json::object());
    return function.value("op", "") == "local_read" && function.value("name", "") == name;
}

bool containsCallNamed(const json& value, std::string_view name)
{
    bool found = false;
    walk(value, [&](const json& item) {
        if (!found && callNamed(item, name))
            found = true;
    });
    return found;
}

bool readsLocal(const json& value, std::string_view name)
{
    bool found = false;
    walk(value, [&](const json& item) {
        if (!found && item.value("op", "") == "local_read" && item.value("name", "") == name)
            found = true;
    });
    return found;
}

bool writesLocal(const json& statement, std::string_view name)
{
    if (statement.value("op", "") != "assign" && statement.value("op", "") != "local_assign")
        return false;
    for (const json& target : statement.value("targets", json::array()))
        if (target.value("kind", "") == "local" && target.value("name", "") == name)
            return true;
    return false;
}

size_t futureReads(const json& instructions, size_t start, std::string_view name)
{
    size_t result = 0;
    for (size_t index = start; index < instructions.size(); ++index)
    {
        if (readsLocal(instructions[index], name))
            ++result;
        if (writesLocal(instructions[index], name))
            break;
    }
    return result;
}

class StraightLineLifter
{
public:
    StraightLineLifter(
        const Cipher& cipher,
        int64_t state,
        const json& instructions,
        const std::map<int64_t, json>& allBlocks,
        const json& prototypes)
        : cipher(cipher)
        , state(state)
        , instructions(instructions)
        , allBlocks(allBlocks)
        , prototypes(prototypes)
    {
        std::vector<int64_t> entries;
        for (const json& prototype : prototypes)
        {
            const int64_t entry = prototype.value("entry_state", 0LL);
            if (entry != 0)
                entries.push_back(entry);
        }
        std::sort(entries.begin(), entries.end());
        entries.erase(std::unique(entries.begin(), entries.end()), entries.end());
        for (size_t index = 0; index < entries.size(); ++index)
            prototypeNames.emplace(entries[index], "function_" + std::to_string(index + 1));
    }

    LiftResult run()
    {
        LiftResult result;
        result.family_recognized = cipher.complete();
        if (!cipher.complete())
        {
            result.reason = "prometheus_string_cipher_unresolved";
            return result;
        }

        size_t decryptBinding = instructions.size();
        size_t bootstrapEnd = instructions.size();
        for (size_t index = 0; index < instructions.size(); ++index)
        {
            walk(instructions[index], [&](const json& expression) {
                if (expression.value("op", "") != "make_closure")
                    return;
                auto entry = integer(expression.value("entry", json::object()));
                if (entry && *entry == cipher.decrypt_entry)
                    decryptBinding = std::min(decryptBinding, index);
            });
            processBinding(instructions[index]);
            auto value = singleValue(instructions[index]);
            if (value)
            {
                json resolved = resolve(*value);
                if (resolved.value("op", "") == "prometheus_decrypt_function")
                    decryptBinding = std::min(decryptBinding, index);
            }
            if (decryptBinding != instructions.size() && containsCallNamed(instructions[index], "release_cell"))
                bootstrapEnd = index + 1;
        }
        if (decryptBinding == instructions.size() || bootstrapEnd == instructions.size())
        {
            result.reason = "prometheus_bootstrap_boundary_unresolved";
            return result;
        }

        bindings.clear();
        cellBindings.clear();
        decodedStrings = json::array();
        for (size_t index = 0; index < bootstrapEnd; ++index)
            processBinding(instructions[index]);

        std::ostringstream output;
        output << "-- Reconstructed from the Prometheus register VM used by WeAreDevs v1.\n";
        output << "-- Original comments, formatting, and local names were not recoverable.\n";
        size_t outputLine = 3;
        size_t emitted = 0;
        size_t lifted = 0;

        struct PreludeValue
        {
            size_t definition = 0;
            std::string name;
            json value;
            json statement;
        };
        std::vector<PreludeValue> preludeValues;
        for (const auto& [name, boundValue] : bindings)
        {
            if (futureReads(instructions, bootstrapEnd, name) == 0)
                continue;
            json resolved = resolve(boundValue);
            const std::string op = resolved.value("op", "");
            if (op != "table" && op != "call")
                continue;
            std::optional<size_t> definition;
            for (size_t index = 0; index < bootstrapEnd; ++index)
                if (auto target = singleLocalTarget(instructions[index]); target && *target == name)
                    definition = index;
            if (definition)
                preludeValues.push_back({*definition, name, std::move(resolved), instructions[*definition]});
        }
        std::sort(preludeValues.begin(), preludeValues.end(), [](const PreludeValue& left, const PreludeValue& right) {
            return left.definition == right.definition ? left.name < right.name : left.definition < right.definition;
        });
        for (const PreludeValue& prelude : preludeValues)
        {
            const std::string generated = "local_" + std::to_string(++nextLocal);
            appendStatement(output, "local " + generated + " = " + render(prelude.value), prelude.statement, outputLine, result.mapping);
            bindings[prelude.name] = {{"op", "emitted_local"}, {"name", generated}};
            ++emitted;
            ++lifted;
        }
        for (size_t index = bootstrapEnd; index < instructions.size(); ++index)
        {
            const json& statement = instructions[index];
            const std::string op = statement.value("op", "");
            if (op == "assign" || op == "local_assign")
            {
                const json targets = statement.value("targets", json::array());
                const json values = statement.value("values", json::array());
                if (targets.size() != 1 || values.size() != 1)
                {
                    result.reason = "multi_assignment_not_lifted";
                    return result;
                }
                const json& target = targets[0];
                json value;
                if (auto folded = number(values[0]))
                    value = {{"op", "constant"}, {"value", *folded}};
                else
                    value = resolve(values[0]);
                if (target.value("kind", "") == "program_counter")
                {
                    ++lifted;
                    continue;
                }
                if (target.value("kind", "") == "local")
                {
                    const std::string targetName = target.value("name", "");
                    if (targetName == "results" && values[0].value("op", "") == "table")
                    {
                        ++lifted;
                        continue;
                    }
                    if (value.value("op", "") == "prometheus_decrypt_token" || value.value("op", "") == "prometheus_string_proxy")
                    {
                        bindings[targetName] = value;
                        ++lifted;
                        continue;
                    }
                    if (callNamed(value, "release_cell") || callNamed(value, "release_captures"))
                    {
                        bindings.erase(targetName);
                        ++lifted;
                        continue;
                    }
                    if (value.value("op", "") == "make_closure" || value.value("op", "") == "prometheus_decrypt_function" ||
                        value.value("op", "") == "cell_read" || value.value("op", "") == "upvalue_read")
                    {
                        result.reason = "payload_closure_or_upvalue_not_lifted";
                        return result;
                    }
                    const size_t reads = futureReads(instructions, index + 1, targetName);
                    const bool call = value.value("op", "") == "call";
                    const bool identityValue = value.value("op", "") == "table";
                    const bool shouldMaterialize = identityValue || (reads > 0 && (call || reads > 1));
                    if (call && reads == 0)
                    {
                        appendStatement(output, render(value), statement, outputLine, result.mapping);
                        ++emitted;
                        bindings.erase(targetName);
                    }
                    else if (shouldMaterialize)
                    {
                        const std::string generated = "local_" + std::to_string(++nextLocal);
                        appendStatement(output, "local " + generated + " = " + render(value), statement, outputLine, result.mapping);
                        ++emitted;
                        bindings[targetName] = {{"op", "emitted_local"}, {"name", generated}};
                    }
                    else
                        bindings[targetName] = std::move(value);
                    ++lifted;
                    continue;
                }
                if (target.value("kind", "") == "index" || target.value("kind", "") == "global")
                {
                    appendStatement(output, renderTarget(target) + " = " + render(value), statement, outputLine, result.mapping);
                    ++emitted;
                    ++lifted;
                    continue;
                }
                result.reason = "assignment_target_not_lifted";
                return result;
            }
            if (op == "expression")
            {
                appendStatement(output, render(resolve(statement.value("value", json::object()))), statement, outputLine, result.mapping);
                ++emitted;
                ++lifted;
                continue;
            }
            if (op == "return")
            {
                std::vector<std::string> values;
                for (const json& item : statement.value("values", json::array()))
                    values.push_back(render(resolve(item)));
                appendStatement(output, values.empty() ? "return" : "return " + join(values), statement, outputLine, result.mapping);
                ++emitted;
                ++lifted;
                continue;
            }
            result.reason = "structured_statement_not_lifted";
            return result;
        }
        if (emitted == 0)
        {
            result.reason = "empty_payload_after_bootstrap";
            return result;
        }
        if (renderFailed)
        {
            result.reason = renderFailure.empty() ? "payload_expression_not_lifted" : renderFailure;
            return result;
        }
        result.complete = true;
        result.reason = "complete_straight_line_payload";
        result.source = output.str();
        result.decoded_strings = decodedStrings;
        result.lifted_instructions = lifted;
        result.emitted_statements = emitted;
        result.reconstructed_prototypes = 1;
        return result;
    }

    LiftResult runStateMachine(const std::map<int64_t, json>& blocks, const std::set<int64_t>& payloadBlocks)
    {
        stateMachineMode = true;
        activeHelperCells.clear();
        LiftResult result;
        result.family_recognized = cipher.complete();
        if (!cipher.complete())
        {
            result.reason = "prometheus_string_cipher_unresolved";
            return result;
        }

        auto boundary = bootstrapBoundary();
        if (!boundary)
        {
            result.reason = "prometheus_bootstrap_boundary_unresolved";
            return result;
        }

        bindings.clear();
        cellBindings.clear();
        decodedStrings = json::array();
        for (size_t index = 0; index < *boundary; ++index)
            processBinding(instructions[index]);

        std::map<int64_t, json> payloadInstructions;
        for (int64_t blockState : payloadBlocks)
        {
            auto found = blocks.find(blockState);
            if (found == blocks.end())
            {
                result.reason = "payload_block_missing";
                return result;
            }
            payloadInstructions.emplace(blockState, found->second);
        }
        auto entry = payloadInstructions.find(state);
        if (entry == payloadInstructions.end() || *boundary > entry->second.size())
        {
            result.reason = "payload_entry_missing";
            return result;
        }
        const json originalEntry = entry->second;
        entry->second.erase(entry->second.begin(), entry->second.begin() + static_cast<json::difference_type>(*boundary));

        auto writesProgramCounter = [](const json& statement) {
            if (statement.value("op", "") != "assign" && statement.value("op", "") != "local_assign")
                return false;
            for (const json& target : statement.value("targets", json::array()))
                if (target.value("kind", "") == "program_counter")
                    return true;
            return false;
        };
        if (std::none_of(entry->second.begin(), entry->second.end(), writesProgramCounter))
        {
            std::optional<json> movedTerminator;
            for (size_t index = 0; index < *boundary; ++index)
                if (writesProgramCounter(originalEntry[index]))
                    movedTerminator = originalEntry[index];
            if (movedTerminator)
                entry->second.push_back(*movedTerminator);
        }

        // Statement shuffling can move helper-cell initialization across the
        // protector boundary. Analyze the suffix once to recover those cells,
        // then restore the root register bindings for normal emission.
        const auto initialBindings = bindings;
        const auto initialCellBindings = cellBindings;
        for (const json& statement : entry->second)
            processBinding(statement);
        const auto analyzedCells = cellBindings;
        bindings = initialBindings;
        cellBindings = initialCellBindings;
        for (const auto& [name, value] : analyzedCells)
            cellBindings.try_emplace(name, value);

        std::set<std::string> payloadLocals;
        std::set<std::string> payloadReads;
        std::set<std::string> payloadCellIds;
        for (const auto& [blockState, blockInstructions] : payloadInstructions)
        {
            (void)blockState;
            for (const json& statement : blockInstructions)
            {
                walk(statement, [&](const json& expression) {
                    if (expression.value("op", "") == "local_read")
                    {
                        const std::string name = expression.value("name", "");
                        if (!name.empty())
                            payloadReads.insert(name);
                    }
                    const std::string expressionOp = expression.value("op", "");
                    const std::string expressionKind = expression.value("kind", "");
                    if (expressionOp == "cell_read" || expressionKind == "cell")
                        if (auto name = localRead(expression.value("id", json::object())))
                            payloadCellIds.insert(*name);
                    if (expressionOp == "make_closure")
                        walk(expression.value("captures", json::object()), [&](const json& capture) {
                            if (auto name = localRead(capture))
                                payloadCellIds.insert(*name);
                        });
                });
                const std::string op = statement.value("op", "");
                if (op == "assign" || op == "local_assign")
                {
                    for (const json& target : statement.value("targets", json::array()))
                    {
                        if (target.value("kind", "") != "local")
                            continue;
                        const std::string name = target.value("name", "");
                        const json values = statement.value("values", json::array());
                        const bool returnPack = name == "results" && values.size() == 1 && values[0].value("op", "") == "table";
                        if (!name.empty() && !returnPack)
                            payloadLocals.insert(name);
                    }
                }
                else if (op == "compound_assign")
                {
                    const json target = statement.value("target", json::object());
                    if (target.value("kind", "") == "local")
                    {
                        const std::string name = target.value("name", "");
                        if (!name.empty())
                            payloadLocals.insert(name);
                    }
                }
            }
        }

        std::set<std::string> entryDefinitions;
        std::set<std::string> seedNames;
        for (const json& statement : entry->second)
        {
            walk(statement, [&](const json& expression) {
                if (expression.value("op", "") != "local_read")
                    return;
                const std::string name = expression.value("name", "");
                if (!name.empty() && !entryDefinitions.contains(name))
                    seedNames.insert(name);
            });
            const std::string op = statement.value("op", "");
            if (op == "assign" || op == "local_assign")
                for (const json& target : statement.value("targets", json::array()))
                    if (target.value("kind", "") == "local")
                        entryDefinitions.insert(target.value("name", ""));
            if (op == "compound_assign")
            {
                const json target = statement.value("target", json::object());
                if (target.value("kind", "") == "local")
                    entryDefinitions.insert(target.value("name", ""));
            }
        }
        for (const std::string& name : payloadReads)
            if (!entryDefinitions.contains(name))
                seedNames.insert(name);

        std::map<std::string, json> seedValues;
        std::set<std::string> seedCells;
        for (const std::string& name : seedNames)
        {
            auto found = bindings.find(name);
            if (payloadCellIds.contains(name) && cellBindings.contains(name))
                seedCells.insert(name);
            if (found == bindings.end())
                continue;
            json resolved = resolve(found->second);
            const std::string op = resolved.value("op", "");
            if (op == "prometheus_decrypt_function" || op == "prometheus_string_proxy" || op == "prometheus_decrypt_token")
            {
                found->second = std::move(resolved);
                continue;
            }
            seedValues.emplace(name, std::move(resolved));
            payloadLocals.insert(name);
        }
        std::set<std::string> capturedCellDependencies;
        for (const auto& [seedName, value] : seedValues)
        {
            (void)seedName;
            walk(value, [&](const json& expression) {
                if (auto name = localRead(expression); name && cellBindings.contains(*name) && !seedValues.contains(*name))
                    capturedCellDependencies.insert(*name);
            });
        }
        for (const std::string& name : capturedCellDependencies)
        {
            seedCells.insert(name);
        }
        activeHelperCells.clear();
        for (const std::string& name : payloadCellIds)
        {
            auto found = cellBindings.find(name);
            if (found == cellBindings.end())
                continue;
            const json value = resolve(found->second);
            const std::string valueOp = value.value("op", "");
            if (valueOp == "prometheus_decrypt_function" || valueOp == "prometheus_string_proxy" ||
                valueOp == "prometheus_decrypt_token")
                activeHelperCells.insert(name);
        }
        std::set<std::string> cellContentWritten;
        std::set<std::string> cellReadBeforeWrite;
        for (const json& statement : entry->second)
        {
            auto recordReads = [&](const json& value) {
                walk(value, [&](const json& expression) {
                    if (expression.value("op", "") != "cell_read")
                        return;
                    auto name = localRead(expression.value("id", json::object()));
                    if (name && !cellContentWritten.contains(*name))
                        cellReadBeforeWrite.insert(*name);
                });
            };
            const std::string op = statement.value("op", "");
            if (op == "assign" || op == "local_assign")
            {
                recordReads(statement.value("values", json::array()));
                for (const json& target : statement.value("targets", json::array()))
                    if (target.value("kind", "") == "cell")
                        if (auto name = localRead(target.value("id", json::object())))
                            cellContentWritten.insert(*name);
            }
            else if (op == "compound_assign")
            {
                const json target = statement.value("target", json::object());
                if (target.value("kind", "") == "cell")
                    if (auto name = localRead(target.value("id", json::object())))
                    {
                        if (!cellContentWritten.contains(*name))
                            cellReadBeforeWrite.insert(*name);
                        cellContentWritten.insert(*name);
                    }
                recordReads(statement.value("value", json::object()));
            }
            else
                recordReads(statement);
        }
        std::map<std::string, json> seedCellValues;
        for (const std::string& name : seedCells)
        {
            auto found = cellBindings.find(name);
            if (found == cellBindings.end())
                continue;
            json value = resolve(found->second);
            const std::string valueOp = value.value("op", "");
            if (valueOp == "prometheus_decrypt_function" || valueOp == "prometheus_string_proxy" ||
                valueOp == "prometheus_decrypt_token" || (valueOp == "constant" && value.value("value", json()).is_null()))
                continue;
            seedCellValues.emplace(name, std::move(value));
        }

        materialized.clear();
        cellMaterialized.clear();
        for (const std::string& name : payloadLocals)
        {
            auto found = bindings.find(name);
            if (found == bindings.end())
                continue;
            if (seedValues.contains(name))
            {
                found->second = seedValues.at(name);
                continue;
            }
            const json resolved = resolve(found->second);
            const std::string op = resolved.value("op", "");
            if (op != "prometheus_decrypt_function" && op != "prometheus_string_proxy" && op != "prometheus_decrypt_token")
                bindings.erase(found);
            else
                found->second = resolved;
        }
        size_t localIndex = 0;
        for (const std::string& name : payloadLocals)
            materialized.emplace(name, "local_" + std::to_string(++localIndex));
        size_t cellIndex = 0;
        payloadCellIds.insert(seedCells.begin(), seedCells.end());
        for (const std::string& name : payloadCellIds)
            if (!name.empty())
                cellMaterialized.emplace(name, "cell_" + std::to_string(++cellIndex));

        std::map<int64_t, json> closureDiscoveryBlocks = payloadInstructions;
        for (const auto& [seedName, value] : seedValues)
        {
            (void)seedName;
            closureDiscoveryBlocks[state].push_back({{"op", "expression"}, {"value", value}});
        }
        for (const auto& [seedName, value] : seedCellValues)
        {
            (void)seedName;
            closureDiscoveryBlocks[state].push_back({{"op", "expression"}, {"value", value}});
        }
        requiredClosures = discoverClosures(closureDiscoveryBlocks);
        discoverPrototypeHelperCaptures();

        std::ostringstream output;
        output << "-- Reconstructed from the Prometheus register VM used by WeAreDevs v1.\n";
        output << "-- This is a semantic payload state machine; protector setup has been removed.\n";
        size_t outputLine = 3;
        if (!requiredClosures.empty())
        {
            output << "local function __bind(__prototype, __captures) return function(...) return __prototype(__captures, ...) end end\n";
            ++outputLine;
            output << "local __prototypes = {}\n\n";
            outputLine += 2;
            for (int64_t entryState : requiredClosures)
                if (!emitPrototypeFunction(output, outputLine, entryState, result))
                    return result;
        }
        if (!materialized.empty() || !cellMaterialized.empty())
        {
            std::vector<std::string> declarations;
            declarations.reserve(materialized.size() + cellMaterialized.size());
            for (const auto& [sourceName, generatedName] : materialized)
            {
                (void)sourceName;
                declarations.push_back(generatedName);
            }
            for (const auto& [sourceName, generatedName] : cellMaterialized)
            {
                (void)sourceName;
                declarations.push_back(generatedName);
            }
            output << "local " << join(declarations) << "\n";
            ++outputLine;
        }
        size_t seedStatementCount = 0;
        for (const auto& [sourceName, generatedName] : cellMaterialized)
        {
            (void)sourceName;
            output << generatedName << " = {nil}\n";
            ++outputLine;
            ++seedStatementCount;
        }
        auto emitSeedValues = [&](bool closures) {
            for (const auto& [sourceName, value] : seedValues)
            {
                if ((value.value("op", "") == "make_closure") != closures)
                    continue;
                output << materialized.at(sourceName) << " = " << render(resolve(value)) << "\n";
                ++outputLine;
                ++seedStatementCount;
            }
        };
        auto emitSeedCells = [&](bool closures) {
            for (const auto& [sourceName, value] : seedCellValues)
            {
                if ((value.value("op", "") == "make_closure") != closures)
                    continue;
                auto target = cellMaterialized.find(sourceName);
                if (target == cellMaterialized.end())
                    continue;
                output << target->second << "[1] = " << render(resolve(value)) << "\n";
                ++outputLine;
                ++seedStatementCount;
            }
        };
        emitSeedValues(false);
        emitSeedCells(false);
        emitSeedValues(true);
        emitSeedCells(true);
        output << "local __results\n";
        output << "local __arguments = {...}\n";
        output << "local __state = " << state << "\n";
        output << "while __state ~= nil do\n";
        outputLine += 4;

        const std::vector<int64_t> orderedStates = orderedBlockStates(payloadInstructions, payloadBlocks, state);

        size_t emitted = seedStatementCount;
        size_t lifted = seedStatementCount;
        for (size_t blockIndex = 0; blockIndex < orderedStates.size(); ++blockIndex)
        {
            const int64_t blockState = orderedStates[blockIndex];
            output << (blockIndex == 0 ? "    if " : "    elseif ") << "__state == " << blockState << " then\n";
            ++outputLine;
            const json& blockInstructions = payloadInstructions.at(blockState);
            size_t branchStatements = 0;
            for (const json& statement : blockInstructions)
            {
                const std::string op = statement.value("op", "");
                if (op == "assign" || op == "local_assign")
                {
                    const json targets = statement.value("targets", json::array());
                    const json values = statement.value("values", json::array());
                    if (targets.empty() || values.empty())
                    {
                        result.reason = "empty_assignment_not_lifted";
                        return result;
                    }

                    if (targets.size() == 1 && targets[0].value("kind", "") == "program_counter")
                    {
                        json value = resolve(values[0]);
                        const std::string rendered = value.value("op", "") == "protector_return_sentinel" ? "nil" : render(value);
                        appendStatement(output, "        __state = " + rendered, statement, outputLine, result.mapping, blockState);
                        ++emitted;
                        ++branchStatements;
                        ++lifted;
                        continue;
                    }
                    if (targets.size() == 1 && targets[0].value("kind", "") == "local" &&
                        targets[0].value("name", "") == "results" && values.size() == 1 && values[0].value("op", "") == "table")
                    {
                        json value = resolve(values[0]);
                        appendStatement(output, "        __results = " + render(value), statement, outputLine, result.mapping, blockState);
                        ++emitted;
                        ++branchStatements;
                        ++lifted;
                        continue;
                    }
                    if (targets.size() == 1 && values.size() == 1 && targets[0].value("kind", "") == "local")
                    {
                        const std::string targetName = targets[0].value("name", "");
                        json resolved = resolve(values[0]);
                        auto cell = cellMaterialized.find(targetName);
                        if (cell != cellMaterialized.end() && callNamed(resolved, "allocate_cell"))
                        {
                            bindings.erase(targetName);
                            appendStatement(output, "        " + cell->second + " = {nil}", statement, outputLine, result.mapping, blockState);
                            ++emitted;
                            ++branchStatements;
                            ++lifted;
                            continue;
                        }
                    }

                    if (targets.size() == 1 && values.size() == 1 && targets[0].value("kind", "") == "local")
                    {
                        const std::string targetName = targets[0].value("name", "");
                        json resolved = resolve(values[0]);
                        if (callNamed(resolved, "release_cell") || callNamed(resolved, "release_captures"))
                        {
                            ++lifted;
                            continue;
                        }
                        const std::string resolvedOp = resolved.value("op", "");
                        if (resolvedOp == "prometheus_decrypt_function" || resolvedOp == "prometheus_string_proxy" ||
                            resolvedOp == "prometheus_decrypt_token")
                        {
                            bindings[targetName] = std::move(resolved);
                            ++lifted;
                            continue;
                        }
                        if (auto folded = number(resolved))
                            bindings[targetName] = {{"op", "constant"}, {"value", *folded}};
                        else if (resolvedOp == "constant")
                            bindings[targetName] = std::move(resolved);
                        else
                            bindings.erase(targetName);
                    }

                    std::vector<std::string> renderedTargets;
                    std::vector<std::string> renderedValues;
                    std::vector<json> resolvedValues;
                    renderedTargets.reserve(targets.size());
                    renderedValues.reserve(values.size());
                    resolvedValues.reserve(values.size());
                    bool protectorCleanup = false;
                    bool protectorHelperPlumbing = false;
                    for (const json& value : values)
                    {
                        json resolved = resolve(value);
                        protectorCleanup = protectorCleanup || callNamed(resolved, "release_cell") || callNamed(resolved, "release_captures");
                        const std::string resolvedOp = resolved.value("op", "");
                        protectorHelperPlumbing = protectorHelperPlumbing || resolvedOp == "prometheus_decrypt_function" ||
                            resolvedOp == "prometheus_string_proxy" || resolvedOp == "prometheus_decrypt_token";
                        resolvedValues.push_back(std::move(resolved));
                    }
                    for (size_t index = 0; index < targets.size(); ++index)
                    {
                        if (targets[index].value("kind", "") != "local")
                            continue;
                        const std::string targetName = targets[index].value("name", "");
                        json resolved = index < resolvedValues.size() ? resolvedValues[index] : json{{"op", "constant"}, {"value", nullptr}};
                        const std::string resolvedOp = resolved.value("op", "");
                        if (resolvedOp == "prometheus_decrypt_function" || resolvedOp == "prometheus_string_proxy" ||
                            resolvedOp == "prometheus_decrypt_token" || resolvedOp == "constant")
                            bindings[targetName] = std::move(resolved);
                        else if (auto folded = number(resolved))
                            bindings[targetName] = {{"op", "constant"}, {"value", *folded}};
                        else
                            bindings.erase(targetName);
                    }
                    if (protectorCleanup || protectorHelperPlumbing)
                    {
                        ++lifted;
                        continue;
                    }
                    for (const json& value : resolvedValues)
                        renderedValues.push_back(render(value));
                    for (const json& target : targets)
                        renderedTargets.push_back(renderAssignmentTarget(target));
                    appendStatement(
                        output, "        " + join(renderedTargets) + " = " + join(renderedValues), statement, outputLine, result.mapping, blockState);
                    ++emitted;
                    ++branchStatements;
                    ++lifted;
                    continue;
                }
                if (op == "compound_assign")
                {
                    const std::string text = renderAssignmentTarget(statement.value("target", json::object())) + " " +
                        statement.value("operator", "+") + "= " + render(resolve(statement.value("value", json::object())));
                    appendStatement(output, "        " + text, statement, outputLine, result.mapping, blockState);
                    ++emitted;
                    ++branchStatements;
                    ++lifted;
                    continue;
                }
                if (op == "expression")
                {
                    appendStatement(output, "        " + render(resolve(statement.value("value", json::object()))), statement, outputLine, result.mapping,
                        blockState);
                    ++emitted;
                    ++branchStatements;
                    ++lifted;
                    continue;
                }
                if (op == "return")
                {
                    std::vector<std::string> values;
                    for (const json& value : statement.value("values", json::array()))
                        values.push_back(render(resolve(value)));
                    appendStatement(output, "        return" + (values.empty() ? std::string() : " " + join(values)), statement, outputLine,
                        result.mapping, blockState);
                    ++emitted;
                    ++branchStatements;
                    ++lifted;
                    continue;
                }
                result.reason = "structured_statement_not_lifted";
                return result;
            }
            if (branchStatements == 0)
            {
                output << "        error(\"empty recovered payload block\")\n";
                ++outputLine;
            }
        }
        output << "    else\n";
        output << "        error(\"invalid recovered payload state: \" .. tostring(__state))\n";
        output << "    end\n";
        output << "end\n";
        output << "if __results ~= nil then\n";
        output << "    return table.unpack(__results)\n";
        output << "end\n";

        if (renderFailed)
        {
            result.reason = renderFailure.empty() ? "payload_expression_not_lifted" : renderFailure;
            return result;
        }
        if (emitted == 0)
        {
            result.reason = "empty_payload_after_bootstrap";
            return result;
        }
        result.complete = true;
        result.reason = "complete_semantic_state_machine_payload";
        result.source = output.str();
        result.decoded_strings = decodedStrings;
        result.lifted_instructions += lifted;
        result.emitted_statements += emitted;
        result.reconstructed_prototypes = 1 + requiredClosures.size();
        return result;
    }

private:
    const Cipher& cipher;
    int64_t state;
    const json& instructions;
    const std::map<int64_t, json>& allBlocks;
    const json& prototypes;
    std::map<int64_t, std::string> prototypeNames;
    std::set<int64_t> requiredClosures;
    std::map<int64_t, json> prototypeCaptures;
    std::map<int64_t, int64_t> prototypeParents;
    std::map<int64_t, std::map<int, json>> prototypeHelperCaptures;
    std::map<int, json> activeCaptureHelpers;
    std::set<std::string> activeHelperCells;
    std::set<std::string> activeScratchFrames;
    std::unordered_map<std::string, std::map<int64_t, json>> scratchBindings;
    std::unordered_map<std::string, json> bindings;
    std::unordered_map<std::string, json> cellBindings;
    std::map<std::string, std::string> materialized;
    std::map<std::string, std::string> cellMaterialized;
    json decodedStrings = json::array();
    size_t nextLocal = 0;
    bool renderFailed = false;
    std::string renderFailure;
    bool stateMachineMode = false;

    std::optional<size_t> bootstrapBoundary()
    {
        bindings.clear();
        cellBindings.clear();
        size_t decryptBinding = instructions.size();
        for (size_t index = 0; index < instructions.size(); ++index)
        {
            walk(instructions[index], [&](const json& expression) {
                if (expression.value("op", "") != "make_closure")
                    return;
                auto entry = integer(expression.value("entry", json::object()));
                if (entry && *entry == cipher.decrypt_entry)
                    decryptBinding = std::min(decryptBinding, index);
            });
            processBinding(instructions[index]);
            auto value = singleValue(instructions[index]);
            if (value)
            {
                json resolved = resolve(*value);
                if (resolved.value("op", "") == "prometheus_decrypt_function")
                    decryptBinding = std::min(decryptBinding, index);
            }
            if (decryptBinding != instructions.size() && containsCallNamed(instructions[index], "release_cell"))
                return index + 1;
        }
        if (decryptBinding != instructions.size())
            return decryptBinding + 1;
        return std::nullopt;
    }

    const json* prototypeForEntry(int64_t entry) const
    {
        for (const json& prototype : prototypes)
            if (prototype.value("entry_state", 0LL) == entry)
                return &prototype;
        return nullptr;
    }

    std::set<int64_t> discoverClosures(const std::map<int64_t, json>& rootBlocks)
    {
        std::set<int64_t> discovered;
        std::vector<int64_t> pending;
        auto collect = [&](const json& value, int64_t parentEntry) {
            walk(value, [&](const json& expression) {
                if (expression.value("op", "") != "make_closure")
                    return;
                auto entry = integer(expression.value("entry", json::object()));
                if (entry && *entry != cipher.decrypt_entry && prototypeNames.contains(*entry))
                {
                    prototypeCaptures.try_emplace(*entry, expression.value("captures", json::object()));
                    prototypeParents.try_emplace(*entry, parentEntry);
                    if (discovered.insert(*entry).second)
                        pending.push_back(*entry);
                }
            });
        };
        for (const auto& [blockState, block] : rootBlocks)
        {
            (void)blockState;
            collect(block, state);
        }
        while (!pending.empty())
        {
            const int64_t entry = pending.back();
            pending.pop_back();
            const json* prototype = prototypeForEntry(entry);
            if (!prototype)
                continue;
            for (int64_t blockState : prototypeBlocks(*prototype))
            {
                auto found = allBlocks.find(blockState);
                if (found != allBlocks.end())
                    collect(found->second, entry);
            }
        }
        return discovered;
    }

    void discoverPrototypeHelperCaptures()
    {
        prototypeHelperCaptures.clear();
        std::set<int64_t> processed;
        while (processed.size() < requiredClosures.size())
        {
            bool advanced = false;
            for (int64_t entry : requiredClosures)
            {
                if (processed.contains(entry))
                    continue;
                auto parent = prototypeParents.find(entry);
                auto captures = prototypeCaptures.find(entry);
                if (parent == prototypeParents.end() || captures == prototypeCaptures.end())
                {
                    processed.insert(entry);
                    advanced = true;
                    continue;
                }
                if (parent->second != state && !processed.contains(parent->second))
                    continue;

                std::map<int, json> helpers;
                int slot = 0;
                for (const json& item : captures->second.value("items", json::array()))
                {
                    ++slot;
                    const json value = item.value("value", json::object());
                    if (parent->second == state)
                    {
                        auto name = localRead(value);
                        auto cell = name ? cellBindings.find(*name) : cellBindings.end();
                        if (cell == cellBindings.end())
                            continue;
                        json helper = resolve(cell->second);
                        const std::string op = helper.value("op", "");
                        if (op == "prometheus_decrypt_function" || op == "prometheus_string_proxy" ||
                            op == "prometheus_decrypt_token")
                            helpers.emplace(slot, std::move(helper));
                        continue;
                    }
                    if (value.value("op", "") != "index_read")
                        continue;
                    const json table = value.value("table", json::object());
                    if (table.value("op", "") != "local_read" || table.value("name", "") != "capture_ids")
                        continue;
                    auto parentSlot = integer(value.value("index", json::object()));
                    auto parentHelpers = prototypeHelperCaptures.find(parent->second);
                    if (!parentSlot || parentHelpers == prototypeHelperCaptures.end())
                        continue;
                    auto inherited = parentHelpers->second.find(static_cast<int>(*parentSlot));
                    if (inherited != parentHelpers->second.end())
                        helpers.emplace(slot, inherited->second);
                }
                prototypeHelperCaptures.emplace(entry, std::move(helpers));
                processed.insert(entry);
                advanced = true;
            }
            if (!advanced)
                break;
        }
    }

    std::vector<int64_t> orderedBlockStates(
        const std::map<int64_t, json>& blocks,
        const std::set<int64_t>& allowed,
        int64_t entry) const
    {
        std::vector<int64_t> ordered;
        std::set<int64_t> visited;
        std::function<void(int64_t)> visit = [&](int64_t blockState) {
            if (!allowed.contains(blockState) || !visited.insert(blockState).second)
                return;
            ordered.push_back(blockState);
            auto block = blocks.find(blockState);
            if (block == blocks.end())
                return;
            std::vector<int64_t> successors;
            for (const json& statement : block->second)
            {
                if (statement.value("op", "") != "assign" && statement.value("op", "") != "local_assign")
                    continue;
                const json targets = statement.value("targets", json::array());
                const json values = statement.value("values", json::array());
                if (targets.size() != 1 || values.size() != 1 || targets[0].value("kind", "") != "program_counter")
                    continue;
                walk(values[0], [&](const json& expression) {
                    auto target = integer(expression);
                    if (target && allowed.contains(*target) && std::find(successors.begin(), successors.end(), *target) == successors.end())
                        successors.push_back(*target);
                });
            }
            for (int64_t successor : successors)
                visit(successor);
        };
        visit(entry);
        for (int64_t blockState : allowed)
            visit(blockState);
        return ordered;
    }

    bool emitPrototypeFunction(std::ostringstream& output, size_t& outputLine, int64_t entry, LiftResult& result)
    {
        const json* prototype = prototypeForEntry(entry);
        auto functionName = prototypeNames.find(entry);
        if (!prototype || functionName == prototypeNames.end())
        {
            result.reason = "payload_closure_entry_unresolved";
            return false;
        }

        const std::vector<int64_t> prototypeStateList = prototypeBlocks(*prototype);
        if (prototypeStateList.empty())
        {
            result.reason = "payload_closure_blocks_missing";
            return false;
        }
        const std::set<int64_t> prototypeStateSet(prototypeStateList.begin(), prototypeStateList.end());
        const std::vector<int64_t> states = orderedBlockStates(allBlocks, prototypeStateSet, entry);

        const auto savedBindings = bindings;
        const auto savedMaterialized = materialized;
        const auto savedCellMaterialized = cellMaterialized;
        const auto savedCaptureHelpers = activeCaptureHelpers;
        const auto savedHelperCells = activeHelperCells;
        const auto savedScratchFrames = activeScratchFrames;
        const auto savedScratchBindings = scratchBindings;
        const bool savedRenderFailed = renderFailed;
        const std::string savedRenderFailure = renderFailure;
        activeCaptureHelpers.clear();
        activeHelperCells.clear();
        activeScratchFrames.clear();
        scratchBindings.clear();
        if (auto helpers = prototypeHelperCaptures.find(entry); helpers != prototypeHelperCaptures.end())
            activeCaptureHelpers = helpers->second;
        bindings.clear();
        materialized.clear();
        cellMaterialized.clear();
        renderFailed = false;
        renderFailure.clear();

        std::set<std::string> locals;
        std::set<std::string> cellIds;
        std::set<std::string> directlyDefinedLocals;
        std::set<std::string> payloadDefinedLocals;
        std::set<std::string> indexedContainers;
        for (int64_t blockState : states)
        {
            auto found = allBlocks.find(blockState);
            if (found == allBlocks.end())
                continue;
            for (const json& statement : found->second)
            {
                walk(statement, [&](const json& expression) {
                    const std::string expressionOp = expression.value("op", "");
                    const std::string expressionKind = expression.value("kind", "");
                    if (expressionOp == "cell_read" || expressionKind == "cell")
                        if (auto name = localRead(expression.value("id", json::object())))
                            cellIds.insert(*name);
                    if (expressionOp == "make_closure")
                        walk(expression.value("captures", json::object()), [&](const json& capture) {
                            if (auto name = localRead(capture))
                                cellIds.insert(*name);
                        });
                });
                const std::string op = statement.value("op", "");
                if (op == "assign" || op == "local_assign")
                    for (const json& target : statement.value("targets", json::array()))
                    {
                        if (target.value("kind", "") == "local")
                        {
                            const std::string name = target.value("name", "");
                            const json values = statement.value("values", json::array());
                            const bool returnPack = name == "results" && values.size() == 1 && values[0].value("op", "") == "table";
                            if (!returnPack)
                            {
                                locals.insert(name);
                                directlyDefinedLocals.insert(name);
                                if (values.size() == 1 && callNamed(values[0], "allocate_cell"))
                                    cellIds.insert(name);
                                if (values.size() != 1 ||
                                    (values[0].value("op", "") != "upvalue_read" &&
                                        values[0].value("op", "") != "cell_read" &&
                                        values[0].value("op", "") != "make_closure"))
                                    payloadDefinedLocals.insert(name);
                            }
                        }
                        else if (target.value("kind", "") == "index")
                            if (auto name = localRead(target.value("table", json::object())); name && name->rfind("temporary_", 0) == 0)
                                indexedContainers.insert(*name);
                    }
                if (op == "compound_assign")
                {
                    const json target = statement.value("target", json::object());
                    if (target.value("kind", "") == "local")
                        locals.insert(target.value("name", ""));
                }
            }
        }
        std::set<std::string> scratchFrames;
        for (const std::string& name : indexedContainers)
            if (!directlyDefinedLocals.contains(name))
            {
                locals.insert(name);
                scratchFrames.insert(name);
            }
        activeScratchFrames = scratchFrames;
        size_t generatedIndex = 0;
        for (const std::string& name : locals)
            if (!name.empty())
                materialized.emplace(name, "local_" + std::to_string(++generatedIndex));
        size_t generatedCellIndex = 0;
        for (const std::string& name : cellIds)
            if (!name.empty())
                cellMaterialized.emplace(name, "cell_" + std::to_string(++generatedCellIndex));

        output << "__prototypes[" << entry << "] = function(__captures, ...)\n";
        ++outputLine;
        output << "    local __arguments = {...}\n";
        ++outputLine;
        if (!materialized.empty() || !cellMaterialized.empty())
        {
            std::vector<std::string> declarations;
            for (const auto& [sourceName, generatedName] : materialized)
            {
                (void)sourceName;
                declarations.push_back(generatedName);
            }
            for (const auto& [sourceName, generatedName] : cellMaterialized)
            {
                (void)sourceName;
                declarations.push_back(generatedName);
            }
            output << "    local " << join(declarations) << "\n";
            ++outputLine;
        }
        for (const auto& [sourceName, generatedName] : cellMaterialized)
        {
            (void)sourceName;
            output << "    " << generatedName << " = {nil}\n";
            ++outputLine;
        }
        for (const std::string& name : scratchFrames)
        {
            output << "    " << materialized.at(name) << " = {}\n";
            ++outputLine;
        }
        output << "    local __results\n";
        output << "    local __state = " << entry << "\n";
        output << "    while __state ~= nil do\n";
        outputLine += 3;

        auto emitMapped = [&](std::string text, const json& statement, int64_t blockState) {
            output << "            " << statementSafe(std::move(text)) << "\n";
            result.mapping.push_back({
                {"line", outputLine++},
                {"state", blockState},
                {"function", functionName->second},
                {"source_location", statement.value("location", json::object())},
            });
            ++result.emitted_statements;
        };

        for (size_t stateIndex = 0; stateIndex < states.size(); ++stateIndex)
        {
            const int64_t blockState = states[stateIndex];
            // A helper-valued assignment in one CFG sibling must not rewrite a
            // payload local read in another sibling. The emitted local carries
            // the actual predecessor value; block-local helper aliases are
            // rediscovered by assignments within the current block.
            for (const std::string& name : payloadDefinedLocals)
                bindings.erase(name);
            output << (stateIndex == 0 ? "        if " : "        elseif ") << "__state == " << blockState << " then\n";
            ++outputLine;
            auto found = allBlocks.find(blockState);
            if (found == allBlocks.end())
            {
                output << "            __state = nil\n";
                ++outputLine;
                continue;
            }
            for (const json& statement : found->second)
            {
                const std::string op = statement.value("op", "");
                if (op == "assign" || op == "local_assign")
                {
                    const json targets = statement.value("targets", json::array());
                    const json values = statement.value("values", json::array());
                    if (targets.empty() || values.empty())
                    {
                        result.reason = "empty_assignment_not_lifted";
                        break;
                    }
                    if (targets.size() == 1 && targets[0].value("kind", "") == "program_counter")
                    {
                        json value = resolve(values[0]);
                        emitMapped("__state = " + (value.value("op", "") == "protector_return_sentinel" ? std::string("nil") : render(value)),
                            statement, blockState);
                        ++result.lifted_instructions;
                        continue;
                    }
                    if (targets.size() == 1 && targets[0].value("kind", "") == "local" && targets[0].value("name", "") == "results" &&
                        values.size() == 1 && values[0].value("op", "") == "table")
                    {
                        emitMapped("__results = " + render(resolve(values[0])), statement, blockState);
                        ++result.lifted_instructions;
                        continue;
                    }
                    if (targets.size() == 1 && values.size() == 1 && targets[0].value("kind", "") == "local")
                    {
                        const std::string targetName = targets[0].value("name", "");
                        json value = resolve(values[0]);
                        auto cell = cellMaterialized.find(targetName);
                        if (cell != cellMaterialized.end() && callNamed(value, "allocate_cell"))
                        {
                            bindings.erase(targetName);
                            emitMapped(cell->second + " = {nil}", statement, blockState);
                            ++result.lifted_instructions;
                            continue;
                        }
                    }

                    if (targets.size() == 1 && values.size() == 1 && targets[0].value("kind", "") == "local")
                    {
                        const std::string targetName = targets[0].value("name", "");
                        json value = resolve(values[0]);
                        if (callNamed(value, "release_cell") || callNamed(value, "release_captures"))
                        {
                            ++result.lifted_instructions;
                            continue;
                        }
                        const std::string valueOp = value.value("op", "");
                        if (valueOp == "prometheus_decrypt_function" || valueOp == "prometheus_string_proxy" ||
                            valueOp == "prometheus_decrypt_token")
                        {
                            bindings[targetName] = std::move(value);
                            ++result.lifted_instructions;
                            continue;
                        }
                        if (auto folded = number(value))
                            bindings[targetName] = {{"op", "constant"}, {"value", *folded}};
                        else if (value.value("op", "") == "constant")
                            bindings[targetName] = value;
                        else
                            bindings.erase(targetName);
                    }

                    std::vector<json> resolvedValues;
                    bool cleanup = false;
                    for (const json& value : values)
                    {
                        json resolved = resolve(value);
                        cleanup = cleanup || callNamed(resolved, "release_cell") || callNamed(resolved, "release_captures");
                        resolvedValues.push_back(std::move(resolved));
                    }
                    if (targets.size() == 1 && resolvedValues.size() == 1)
                        rememberScratchBinding(targets[0], resolvedValues[0]);
                    if (cleanup)
                    {
                        ++result.lifted_instructions;
                        continue;
                    }
                    std::vector<std::string> renderedTargets;
                    std::vector<std::string> renderedValues;
                    for (const json& target : targets)
                        renderedTargets.push_back(renderAssignmentTarget(target));
                    for (const json& value : resolvedValues)
                        renderedValues.push_back(render(value));
                    emitMapped(join(renderedTargets) + " = " + join(renderedValues), statement, blockState);
                    ++result.lifted_instructions;
                    continue;
                }
                if (op == "compound_assign")
                {
                    emitMapped(renderAssignmentTarget(statement.value("target", json::object())) + " " + statement.value("operator", "+") +
                            "= " + render(resolve(statement.value("value", json::object()))),
                        statement, blockState);
                    ++result.lifted_instructions;
                    continue;
                }
                if (op == "expression")
                {
                    emitMapped(render(resolve(statement.value("value", json::object()))), statement, blockState);
                    ++result.lifted_instructions;
                    continue;
                }
                if (op == "return")
                {
                    std::vector<std::string> values;
                    for (const json& value : statement.value("values", json::array()))
                        values.push_back(render(resolve(value)));
                    emitMapped("__results = {" + join(values) + "}; __state = nil", statement, blockState);
                    ++result.lifted_instructions;
                    continue;
                }
                result.reason = "structured_statement_not_lifted";
                break;
            }
            if (!result.reason.empty())
                break;
        }
        output << "        else\n";
        output << "            __state = nil\n";
        output << "        end\n";
        output << "    end\n";
        output << "    if __results ~= nil then\n";
        output << "        return table.unpack(__results)\n";
        output << "    end\n";
        output << "end\n\n";
        outputLine += 8;

        const bool localFailure = renderFailed || !result.reason.empty();
        const std::string localReason = !result.reason.empty() ? result.reason : renderFailure;
        bindings = savedBindings;
        materialized = savedMaterialized;
        cellMaterialized = savedCellMaterialized;
        activeCaptureHelpers = savedCaptureHelpers;
        activeHelperCells = savedHelperCells;
        activeScratchFrames = savedScratchFrames;
        scratchBindings = savedScratchBindings;
        renderFailed = savedRenderFailed || localFailure;
        renderFailure = localFailure ? localReason : savedRenderFailure;
        if (localFailure && result.reason.empty())
            result.reason = localReason.empty() ? "payload_closure_not_lifted" : localReason;
        return !localFailure;
    }

    void processBinding(const json& statement)
    {
        auto value = singleValue(statement);
        if (!value)
            return;
        auto resolvedValue = [&]() -> json {
            if (auto folded = number(*value))
                return {{"op", "constant"}, {"value", *folded}};
            return resolve(*value);
        };
        if (auto target = singleLocalTarget(statement))
        {
            json resolved = resolvedValue();
            if (callNamed(resolved, "release_cell") || callNamed(resolved, "release_captures"))
                return;
            bindings[*target] = std::move(resolved);
            return;
        }
        if (statement.value("op", "") != "assign" && statement.value("op", "") != "local_assign")
            return;
        const json targets = statement.value("targets", json::array());
        if (targets.size() != 1 || targets[0].value("kind", "") != "cell")
            return;
        if (auto id = localRead(targets[0].value("id", json::object())))
            cellBindings[*id] = resolvedValue();
    }

    void rememberScratchBinding(const json& target, const json& value)
    {
        if (target.value("kind", "") != "index")
            return;
        auto tableName = localRead(target.value("table", json::object()));
        auto index = integer(target.value("index", json::object()));
        if (!tableName || !index || !activeScratchFrames.contains(*tableName))
            return;
        if (auto folded = number(value))
            scratchBindings[*tableName][*index] = {{"op", "constant"}, {"value", *folded}};
        else
            scratchBindings[*tableName][*index] = value;
    }

    json resolveStaticBounded(
        const json& expression,
        std::unordered_set<std::string>& active,
        size_t& budget,
        size_t depth)
    {
        if (budget == 0 || depth > 64 || !expression.is_object())
            return expression;
        --budget;
        if (auto name = localRead(expression))
        {
            auto found = bindings.find(*name);
            const std::string key = "local:" + *name;
            if (found == bindings.end() || !active.insert(key).second)
                return expression;
            json result = resolveStaticBounded(found->second, active, budget, depth + 1);
            active.erase(key);
            return result;
        }
        json result = expression;
        for (auto& [key, item] : result.items())
        {
            if (key == "location")
                continue;
            if (item.is_object())
                item = resolveStaticBounded(item, active, budget, depth + 1);
            else if (item.is_array())
                for (json& child : item)
                    if (child.is_object())
                        child = resolveStaticBounded(child, active, budget, depth + 1);
        }
        return result;
    }

    json resolveStatic(const json& expression)
    {
        size_t budget = 4096;
        std::unordered_set<std::string> active;
        return resolveStaticBounded(expression, active, budget, 0);
    }

    json resolveBounded(
        const json& expression,
        std::unordered_set<std::string>& active,
        size_t& budget,
        size_t depth)
    {
        if (budget == 0 || depth > 64 || !expression.is_object())
            return expression;
        --budget;
        const std::string op = expression.value("op", "");
        if (op == "index_read")
        {
            auto tableName = localRead(expression.value("table", json::object()));
            auto index = integer(expression.value("index", json::object()));
            if (tableName && index && activeScratchFrames.contains(*tableName))
            {
                auto frame = scratchBindings.find(*tableName);
                auto slot = frame == scratchBindings.end() ? std::map<int64_t, json>::const_iterator{} : frame->second.find(*index);
                if (frame != scratchBindings.end() && slot != frame->second.end())
                {
                    const std::string key = "scratch:" + *tableName + ":" + std::to_string(*index);
                    if (!active.insert(key).second)
                        return expression;
                    json value = resolveBounded(slot->second, active, budget, depth + 1);
                    active.erase(key);
                    const std::string valueOp = value.value("op", "");
                    if (valueOp == "constant" || valueOp == "prometheus_decrypt_function" || valueOp == "prometheus_string_proxy" ||
                        valueOp == "prometheus_decrypt_token")
                        return value;
                }
            }
        }
        if (auto name = localRead(expression))
        {
            auto found = bindings.find(*name);
            if (found != bindings.end())
            {
                const std::string key = "local:" + *name;
                if (active.insert(key).second)
                {
                    json bound = resolveBounded(found->second, active, budget, depth + 1);
                    active.erase(key);
                    const std::string boundOp = bound.value("op", "");
                    if (boundOp == "prometheus_decrypt_function" || boundOp == "prometheus_string_proxy" ||
                        boundOp == "prometheus_decrypt_token")
                        return bound;
                    auto materializedLocal = materialized.find(*name);
                    if (materializedLocal == materialized.end())
                        return bound;
                }
            }
            auto materializedLocal = materialized.find(*name);
            if (materializedLocal != materialized.end())
                return {{"op", "emitted_local"}, {"name", materializedLocal->second}};
            return expression;
        }
        if (op == "upvalue_read")
        {
            auto helper = activeCaptureHelpers.find(expression.value("slot", 0));
            if (helper != activeCaptureHelpers.end())
                return helper->second;
        }
        if (op == "cell_read")
        {
            auto cellName = localRead(expression.value("id", json::object()));
            const bool helperCell = cellName && activeHelperCells.contains(*cellName);
            auto cell = cellName && (helperCell || !cellMaterialized.contains(*cellName)) ? cellBindings.find(*cellName) : cellBindings.end();
            if (cell != cellBindings.end())
            {
                const std::string key = "cell:" + *cellName;
                if (active.insert(key).second)
                {
                    json helper = resolveBounded(cell->second, active, budget, depth + 1);
                    active.erase(key);
                    const std::string helperOp = helper.value("op", "");
                    if (helperOp == "prometheus_decrypt_function" || helperOp == "prometheus_string_proxy" ||
                        helperOp == "prometheus_decrypt_token")
                        return helper;
                }
            }
            return expression;
        }
        if (op == "make_closure")
        {
            auto entry = integer(expression.value("entry", json::object()));
            if (entry && *entry == cipher.decrypt_entry)
                return {{"op", "prometheus_decrypt_function"}};
            return expression;
        }
        if (op == "call")
        {
            const json function = resolveBounded(expression.value("function", json::object()), active, budget, depth + 1);
            if (function.value("op", "") == "prometheus_decrypt_function")
            {
                const json arguments = expression.value("arguments", json::array());
                if (arguments.size() == 2)
                {
                    const json encryptedArgument = resolveStatic(arguments[0]);
                    const json seedArgument = resolveStatic(arguments[1]);
                    auto encrypted = constantString(encryptedArgument);
                    auto seed = integer(seedArgument);
                    if (encrypted && seed)
                    {
                        const std::string plain = decrypt(cipher, *encrypted, *seed);
                        decodedStrings.push_back({
                            {"seed", *seed},
                            {"encrypted_hex", hex(*encrypted)},
                            {"value", plain},
                        });
                        return {{"op", "prometheus_decrypt_token"}, {"seed", *seed}, {"value", plain}};
                    }
                }
            }
        }
        json result = expression;
        for (auto& [key, item] : result.items())
        {
            if (key == "location")
                continue;
            if (item.is_object())
                item = resolveBounded(item, active, budget, depth + 1);
            else if (item.is_array())
                for (json& child : item)
                    if (child.is_object())
                        child = resolveBounded(child, active, budget, depth + 1);
        }
        if (op == "call" && result.value("function", json::object()).value("op", "") == "prometheus_decrypt_function")
        {
            const json arguments = result.value("arguments", json::array());
            if (arguments.size() == 2)
            {
                const json originalArguments = expression.value("arguments", json::array());
                const json encryptedArgument = originalArguments.size() == 2 ? resolveStatic(originalArguments[0]) : arguments[0];
                const json seedArgument = originalArguments.size() == 2 ? resolveStatic(originalArguments[1]) : arguments[1];
                auto encrypted = constantString(encryptedArgument);
                auto seed = integer(seedArgument);
                if (!encrypted)
                    encrypted = constantString(arguments[0]);
                if (!seed)
                    seed = integer(arguments[1]);
                if (encrypted && seed)
                {
                    const std::string plain = decrypt(cipher, *encrypted, *seed);
                    decodedStrings.push_back({
                        {"seed", *seed},
                        {"encrypted_hex", hex(*encrypted)},
                        {"value", plain},
                    });
                    return {{"op", "prometheus_decrypt_token"}, {"seed", *seed}, {"value", plain}};
                }
            }
        }
        if (op == "call" && result.value("function", json::object()).value("op", "") == "global_read" &&
            result.value("function", json::object()).value("name", "") == "setmetatable")
        {
            const json arguments = result.value("arguments", json::array());
            if (arguments.size() == 2 && arguments[0].value("op", "") == "table" && arguments[1].value("op", "") == "table")
                return {{"op", "prometheus_string_proxy"}};
        }
        if (op == "index_read" && result.value("index", json::object()).value("op", "") == "prometheus_decrypt_token")
            return {{"op", "constant"}, {"kind", "string"}, {"value", result["index"].value("value", "")}};
        if (op == "index_read")
        {
            const json table = result.value("table", json::object());
            auto index = constantString(result.value("index", json::object()));
            if (table.value("op", "") == "local_read" && table.value("name", "") == "environment" && index)
                return {{"op", "global_read"}, {"name", *index}};
        }
        return result;
    }

    json resolve(const json& expression)
    {
        size_t budget = 8192;
        std::unordered_set<std::string> active;
        return resolveBounded(expression, active, budget, 0);
    }

    static std::string hex(std::string_view value)
    {
        std::ostringstream output;
        output << std::hex << std::setfill('0');
        for (unsigned char ch : value)
            output << std::setw(2) << static_cast<unsigned int>(ch);
        return output.str();
    }

    std::string renderCellId(const json& id, size_t depth = 0)
    {
        if (auto name = localRead(id))
        {
            auto found = cellMaterialized.find(*name);
            if (found != cellMaterialized.end())
                return found->second;
        }
        return render(resolve(id), depth + 1);
    }

    std::string renderCaptures(const json& captures, size_t depth = 0)
    {
        if (captures.value("op", "") != "table")
            return render(resolve(captures), depth + 1);
        std::vector<std::string> items;
        for (const json& item : captures.value("items", json::array()))
        {
            const json value = item.value("value", json::object());
            std::string rendered;
            if (auto name = localRead(value); name && cellMaterialized.contains(*name))
                rendered = cellMaterialized.at(*name);
            else
                rendered = render(resolve(value), depth + 1);
            if (item.value("kind", "list") != "list")
                rendered = "[" + render(resolve(item.value("key", json::object())), depth + 1) + "] = " + rendered;
            items.push_back(std::move(rendered));
        }
        return "{" + join(items) + "}";
    }

    std::string render(const json& expression, size_t depth = 0)
    {
        if (depth > 96 || !expression.is_object())
        {
            renderFailed = true;
            renderFailure = "payload_expression_depth_exceeded";
            return "nil";
        }
        if (auto folded = number(expression))
        {
            if (std::isfinite(*folded) && std::abs(*folded - std::round(*folded)) < 1e-7)
                return std::to_string(static_cast<int64_t>(std::llround(*folded)));
            std::ostringstream value;
            value << std::setprecision(17) << *folded;
            return value.str();
        }
        const std::string op = expression.value("op", "");
        const std::string kind = expression.value("kind", "");
        if (op == "constant")
        {
            if (auto text = constantString(expression))
                return quote(*text);
            if (!expression.contains("value") || expression["value"].is_null())
                return "nil";
            if (expression["value"].is_boolean())
                return expression["value"].get<bool>() ? "true" : "false";
            if (expression["value"].is_number())
            {
                auto value = number(expression);
                if (value && std::isfinite(*value) && std::abs(*value - std::round(*value)) < 1e-7)
                    return std::to_string(static_cast<int64_t>(std::llround(*value)));
                return expression["value"].dump();
            }
        }
        if (op == "emitted_local" || op == "local_read")
        {
            const std::string name = expression.value("name", "unknown_local");
            if (name == "unpack_values")
                return "table.unpack";
            if (name == "environment")
                return "getfenv(0)";
            if (name == "pc" && stateMachineMode)
                return "__state";
            if (name == "arguments" || name == "outer_arguments")
                return "__arguments";
            if (name == "capture_ids")
                return "__captures";
            if (name == "select_value")
                return "select";
            if (name == "setmetatable_value")
                return "setmetatable";
            if (name == "getmetatable_value")
                return "getmetatable";
            if (name == "newproxy_value")
                return "getfenv(0).newproxy";
            return name;
        }
        if (op == "global_read")
        {
            const std::string name = expression.value("name", "");
            return identifier(name) ? name : "_G[" + quote(name) + "]";
        }
        if (op == "group")
            return "(" + render(expression.value("value", json::object()), depth + 1) + ")";
        if (op == "unary")
            return "(" + expression.value("operator", "not") + " " + render(expression.value("value", json::object()), depth + 1) + ")";
        if (op == "binary")
            return "(" + render(expression.value("left", json::object()), depth + 1) + " " + expression.value("operator", "+") + " " +
                render(expression.value("right", json::object()), depth + 1) + ")";
        if (op == "if_expression")
            return "(if " + render(expression.value("condition", json::object()), depth + 1) + " then " +
                render(expression.value("then", json::object()), depth + 1) + " else " + render(expression.value("else", json::object()), depth + 1) + ")";
        if (op == "index_read")
        {
            const json tableExpression = expression.value("table", json::object());
            const json indexExpression = expression.value("index", json::object());
            if (tableExpression.value("op", "") == "local_read" && tableExpression.value("name", "") == "environment")
            {
                if (auto index = constantString(indexExpression); index && identifier(*index))
                    return *index;
                return "getfenv(0)[" + render(indexExpression, depth + 1) + "]";
            }
            const std::string table = render(tableExpression, depth + 1);
            if (auto index = constantString(indexExpression); index && identifier(*index))
                return "(" + table + ")." + *index;
            return "(" + table + ")[" + render(indexExpression, depth + 1) + "]";
        }
        if (op == "call")
        {
            const json function = expression.value("function", json::object());
            if (function.value("op", "") == "local_read" && function.value("name", "") == "allocate_cell")
                return "{nil}";
            if (function.value("op", "") == "local_read" &&
                (function.value("name", "") == "release_cell" || function.value("name", "") == "release_captures"))
                return "nil";
            std::vector<std::string> arguments;
            for (const json& argument : expression.value("arguments", json::array()))
                arguments.push_back(render(argument, depth + 1));
            return render(function, depth + 1) + "(" + join(arguments) + ")";
        }
        if (op == "table")
        {
            std::vector<std::string> items;
            for (const json& item : expression.value("items", json::array()))
            {
                std::string value = render(item.value("value", json::object()), depth + 1);
                if (item.value("kind", "list") != "list")
                    value = "[" + render(item.value("key", json::object()), depth + 1) + "] = " + value;
                items.push_back(std::move(value));
            }
            return "{" + join(items) + "}";
        }
        if (op == "argument_read")
            return "select(" + render(expression.value("index", json::object()), depth + 1) + ", ...)";
        if (op == "varargs")
            return "...";
        if (op == "prometheus_decrypt_token")
            return std::to_string(expression.value("seed", 0LL));
        if (op == "prometheus_decrypt_function")
            return "(function(_, seed) return seed end)";
        if (op == "prometheus_string_proxy")
            return "({})";
        if (op == "identity_byte_table")
            return "(function() local values = {} for index = 0, 255 do values[index + 1] = string.char(index) end return values end)()";
        if (op == "cell_read")
        {
            if (!stateMachineMode)
            {
                renderFailed = true;
                renderFailure = "payload_closure_or_upvalue_not_lifted";
                return "nil";
            }
            return "(" + renderCellId(expression.value("id", json::object()), depth + 1) + ")[1]";
        }
        if (op == "make_closure")
        {
            if (!stateMachineMode)
            {
                renderFailed = true;
                renderFailure = "payload_closure_not_lifted";
                return "nil";
            }
            auto entry = integer(expression.value("entry", json::object()));
            auto found = entry ? prototypeNames.find(*entry) : prototypeNames.end();
            if (found == prototypeNames.end())
            {
                renderFailed = true;
                renderFailure = "payload_closure_entry_unresolved";
                return "nil";
            }
            requiredClosures.insert(*entry);
            return "__bind(__prototypes[" + std::to_string(*entry) + "], " +
                   renderCaptures(expression.value("captures", json::object()), depth + 1) + ")";
        }
        if (op == "upvalue_read")
            return "__captures[" + std::to_string(expression.value("slot", 0)) + "][1]";
        if (op == "protector_return_sentinel")
            return "nil";
        if (kind == "string")
            return quote(expression.value("value", ""));
        renderFailed = true;
        renderFailure = "payload_expression_not_lifted:" + op;
        return "nil";
    }

    std::string renderAssignmentTarget(const json& target)
    {
        const std::string kind = target.value("kind", "");
        if (kind == "local")
        {
            const std::string name = target.value("name", "");
            auto found = materialized.find(name);
            if (found != materialized.end())
                return found->second;
            return name;
        }
        if (kind == "cell")
            return "(" + renderCellId(target.value("id", json::object())) + ")[1]";
        if (kind == "upvalue")
            return "__captures[" + std::to_string(target.value("slot", 0)) + "][1]";
        if (kind == "program_counter")
            return "__state";
        if (kind == "index" || kind == "global")
            return renderTarget(target);
        renderFailed = true;
        renderFailure = "assignment_target_not_lifted:" + kind;
        return "unknown_target";
    }

    std::string renderTarget(const json& target)
    {
        if (target.value("kind", "") == "global")
        {
            const std::string name = target.value("name", "");
            return identifier(name) ? name : "_G[" + quote(name) + "]";
        }
        if (target.value("kind", "") == "index")
        {
            json table = resolve(target.value("table", json::object()));
            json index = resolve(target.value("index", json::object()));
            if (auto name = constantString(index); name && identifier(*name))
                return render(table) + "." + *name;
            return render(table) + "[" + render(index) + "]";
        }
        return "unknown_target";
    }

    static std::string join(const std::vector<std::string>& values)
    {
        std::string result;
        for (size_t index = 0; index < values.size(); ++index)
        {
            if (index)
                result += ", ";
            result += values[index];
        }
        return result;
    }

    static std::string statementSafe(std::string text)
    {
        const size_t first = text.find_first_not_of(" \t");
        if (first != std::string::npos && text[first] == '(')
            text.insert(first, ";");
        return text;
    }

    void appendStatement(
        std::ostringstream& output,
        const std::string& text,
        const json& statement,
        size_t& line,
        json& mapping,
        std::optional<int64_t> mappingState = std::nullopt)
    {
        output << statementSafe(text) << "\n";
        mapping.push_back({
            {"line", line++},
            {"state", mappingState.value_or(state)},
            {"source_location", statement.value("location", json::object())},
        });
    }
};

} // namespace

LiftResult lift(const LiftRequest& request)
{
    LiftResult result;
    const Cipher cipher = recoverCipher(request);
    result.family_recognized = cipher.decrypt_entry != 0;
    if (!cipher.complete())
    {
        result.reason = "prometheus_string_cipher_unresolved";
        return result;
    }
    auto block = request.blocks.find(request.payload_entry);
    if (block == request.blocks.end())
    {
        result.reason = "payload_entry_missing";
        return result;
    }
    if (request.payload_blocks.size() == 1 && request.payload_blocks.contains(request.payload_entry))
    {
        LiftResult direct = StraightLineLifter(cipher, request.payload_entry, block->second, request.blocks, request.prototypes).run();
        LiftResult semantic = StraightLineLifter(cipher, request.payload_entry, block->second, request.blocks, request.prototypes)
                                  .runStateMachine(request.blocks, request.payload_blocks);
        if (semantic.complete && semantic.source.find("local function __bind") != std::string::npos)
            return semantic;
        if (direct.complete)
            return direct;
        if (semantic.complete)
            return semantic;
        return semantic.reason.empty() ? direct : semantic;
    }
    if (!request.payload_blocks.contains(request.payload_entry))
    {
        result.reason = "payload_entry_missing";
        return result;
    }
    return StraightLineLifter(cipher, request.payload_entry, block->second, request.blocks, request.prototypes)
        .runStateMachine(request.blocks, request.payload_blocks);
}

} // namespace alex::deobfuscator::prometheus
