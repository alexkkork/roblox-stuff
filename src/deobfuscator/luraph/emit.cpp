#include "emit.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <initializer_list>
#include <limits>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>
#include <vector>

namespace alex::deobfuscator::luraph
{
namespace
{

using json = nlohmann::json;

std::string quoteLuau(std::string_view value)
{
    std::string result = "\"";
    for (unsigned char ch : value)
    {
        switch (ch)
        {
        case '\\': result += "\\\\"; break;
        case '"': result += "\\\""; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (ch < 32 || ch == 127 || ch >= 128)
            {
                char buffer[5];
                std::snprintf(buffer, sizeof(buffer), "\\%03u", static_cast<unsigned int>(ch));
                result += buffer;
            }
            else
                result += static_cast<char>(ch);
        }
    }
    return result + '"';
}

std::string identifier(std::string value)
{
    if (value.empty())
        return "value";
    for (char& ch : value)
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_')
            ch = '_';
    if (std::isdigit(static_cast<unsigned char>(value.front())))
        value.insert(value.begin(), '_');
    static const std::set<std::string> reserved = {
        "and", "break", "continue", "do", "else", "elseif", "end", "export", "false", "for", "function",
        "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "type", "typeof",
        "until", "while",
    };
    if (reserved.contains(value))
        value += "_value";
    return value;
}

std::string numberLiteral(std::string value)
{
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (lower == "nan" || lower == "+nan" || lower == "-nan")
        return "(0 / 0)";
    if (lower == "inf" || lower == "+inf" || lower == "infinity" || lower == "+infinity")
        return "math.huge";
    if (lower == "-inf" || lower == "-infinity")
        return "-math.huge";
    static const std::regex decimal(R"(^[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?)|(?:\.[0-9]+))(?:[eE][+-]?[0-9]+)?$)");
    return std::regex_match(value, decimal) ? value : "0";
}

std::string jsonStringOr(const json& object, std::string_view key, std::string fallback = {})
{
    if (!object.is_object())
        return fallback;
    auto value = object.find(std::string(key));
    return value != object.end() && value->is_string() ? value->get<std::string>() : fallback;
}

std::optional<std::string> decodeHexBytes(std::string_view encoded);

std::string primitiveLiteral(const json& value)
{
    if (value.is_null())
        return "nil";
    if (value.is_boolean())
        return value.get<bool>() ? "true" : "false";
    if (value.is_number())
        return value.dump();
    if (value.is_string())
        return quoteLuau(value.get<std::string>());
    if (!value.is_object())
        return "nil";
    const std::string type = jsonStringOr(value, "type");
    if (type == "nil")
        return "nil";
    if (type == "boolean")
    {
        if (value.contains("value") && value["value"].is_boolean())
            return value["value"].get<bool>() ? "true" : "false";
        return jsonStringOr(value, "value", "false") == "true" ? "true" : "false";
    }
    if (type == "number")
    {
        if (value.contains("value") && value["value"].is_number())
            return value["value"].dump();
        return numberLiteral(jsonStringOr(value, "value", "0"));
    }
    if (type == "string")
    {
        if (value.contains("value") && value["value"].is_string())
            return quoteLuau(value["value"].get<std::string>());
        if (value.contains("bytes_hex") && value["bytes_hex"].is_string())
            if (const std::optional<std::string> decoded = decodeHexBytes(value["bytes_hex"].get<std::string>()))
                return quoteLuau(*decoded);
        return "nil";
    }
    return "nil";
}

bool supportedPrimitive(const json& value)
{
    if (value.is_null() || value.is_boolean() || value.is_number() || value.is_string())
        return true;
    if (!value.is_object())
        return false;
    const std::string type = jsonStringOr(value, "type");
    return type == "nil" || type == "boolean" || type == "number" || type == "string";
}

std::optional<std::string> specializationPrimitiveLiteral(const json& value)
{
    if (value.is_null() || value.is_boolean() || value.is_number() || value.is_string())
        return primitiveLiteral(value);
    if (!value.is_object())
        return std::nullopt;

    const std::string type = value.value("type", "");
    if (type == "nil")
        return "nil";
    if (!value.contains("value"))
        return std::nullopt;
    const json& primitive = value["value"];
    if (type == "boolean")
    {
        if (primitive.is_boolean())
            return primitive.get<bool>() ? "true" : "false";
        if (primitive.is_string() && (primitive == "true" || primitive == "false"))
            return primitive.get<std::string>();
        return std::nullopt;
    }
    if (type == "string")
        return primitive.is_string() ? std::optional<std::string>(quoteLuau(primitive.get<std::string>())) :
                                       std::nullopt;
    if (type != "number")
        return std::nullopt;
    if (primitive.is_number())
        return primitive.dump();
    if (!primitive.is_string())
        return std::nullopt;

    const std::string text = primitive.get<std::string>();
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (lower == "nan" || lower == "+nan" || lower == "-nan" || lower == "inf" || lower == "+inf" ||
        lower == "-inf" || lower == "infinity" || lower == "+infinity" || lower == "-infinity")
        return numberLiteral(text);
    static const std::regex decimal(R"(^[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?)|(?:\.[0-9]+))(?:[eE][+-]?[0-9]+)?$)");
    return std::regex_match(text, decimal) ? std::optional<std::string>(text) : std::nullopt;
}

std::optional<std::string> decodeHexBytes(std::string_view encoded)
{
    if (encoded.size() % 2 != 0)
        return std::nullopt;
    const auto digit = [](char ch) -> int {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        return -1;
    };
    std::string decoded;
    decoded.reserve(encoded.size() / 2);
    for (size_t index = 0; index < encoded.size(); index += 2)
    {
        const int high = digit(encoded[index]);
        const int low = digit(encoded[index + 1]);
        if (high < 0 || low < 0)
            return std::nullopt;
        decoded.push_back(static_cast<char>((high << 4) | low));
    }
    return decoded;
}

std::optional<std::string> globalReferenceExpression(std::string_view path)
{
    std::vector<std::string> components;
    size_t begin = 0;
    while (begin <= path.size())
    {
        const size_t end = path.find('.', begin);
        const std::string component(path.substr(begin,
            (end == std::string_view::npos ? path.size() : end) - begin));
        if (component.empty() || (!std::isalpha(static_cast<unsigned char>(component.front())) && component.front() != '_') ||
            !std::all_of(component.begin() + 1, component.end(), [](unsigned char ch) {
                return std::isalnum(ch) || ch == '_';
            }))
            return std::nullopt;
        components.push_back(component);
        if (end == std::string_view::npos)
            break;
        begin = end + 1;
    }
    if (components.empty())
        return std::nullopt;
    std::string expression = components.front() == "_G"
        ? "(environment._G or environment)"
        : "environment[" + quoteLuau(components.front()) + "]";
    for (size_t index = 1; index < components.size(); ++index)
        expression += "[" + quoteLuau(components[index]) + "]";
    return expression;
}

std::optional<std::string> observedBootstrapExpression(const json& value)
{
    if (!value.is_object())
        return std::nullopt;
    const std::string type = value.value("type", "");
    if (type == "nil" || type == "boolean" || type == "number")
        return primitiveLiteral(value);
    if (type == "string")
    {
        if (value.contains("value") && value["value"].is_string())
            return quoteLuau(value["value"].get<std::string>());
        if (value.contains("bytes_hex") && value["bytes_hex"].is_string())
            if (const std::optional<std::string> decoded = decodeHexBytes(value["bytes_hex"].get<std::string>()))
                return quoteLuau(*decoded);
        return std::nullopt;
    }
    if (type == "function" && value.contains("name") && value["name"].is_string() &&
        !value["name"].get<std::string>().empty())
        return "resolve_named_function(" + quoteLuau(value["name"].get<std::string>()) + ")";
    if (type == "global_reference" && value.contains("path") && value["path"].is_string())
        return globalReferenceExpression(value["path"].get<std::string>());
    return std::nullopt;
}

std::optional<int64_t> integerValue(const json& expression)
{
    if (!expression.is_object())
        return std::nullopt;
    const std::string kind = expression.value("kind", "");
    if (kind != "constant" && kind != "immediate")
        return std::nullopt;
    const json value = expression.value("value", json(nullptr));
    if (value.is_number_integer())
        return value.get<int64_t>();
    if (value.is_number())
    {
        const double number = value.get<double>();
        if (std::isfinite(number) && std::floor(number) == number &&
            number >= static_cast<double>(std::numeric_limits<int64_t>::min()) &&
            number <= static_cast<double>(std::numeric_limits<int64_t>::max()))
            return static_cast<int64_t>(number);
    }
    if (!value.is_object() || value.value("type", "") != "number")
        return std::nullopt;
    const std::string text = value.value("value", "");
    try
    {
        size_t consumed = 0;
        const long long result = std::stoll(text, &consumed, 10);
        if (consumed == text.size())
            return static_cast<int64_t>(result);
    }
    catch (...)
    {
    }
    return std::nullopt;
}

std::optional<int64_t> primitiveIntegerValue(const json& value)
{
    if (value.is_number_integer())
        return value.get<int64_t>();
    if (value.is_number_unsigned())
    {
        const uint64_t number = value.get<uint64_t>();
        if (number <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
            return static_cast<int64_t>(number);
        return std::nullopt;
    }
    if (!value.is_object() || value.value("type", "") != "number")
        return std::nullopt;
    try
    {
        const std::string text = value.value("value", "");
        size_t consumed = 0;
        const long long result = std::stoll(text, &consumed, 10);
        if (consumed == text.size())
            return static_cast<int64_t>(result);
    }
    catch (...)
    {
    }
    return std::nullopt;
}

uint64_t positiveUnsignedField(const json& object, std::string_view key)
{
    if (!object.is_object() || !object.contains(std::string(key)))
        return 0;
    const json& value = object[std::string(key)];
    if (value.is_number_unsigned())
        return value.get<uint64_t>();
    if (value.is_number_integer())
    {
        const int64_t number = value.get<int64_t>();
        if (number > 0)
            return static_cast<uint64_t>(number);
    }
    return 0;
}

const json& directSequenceTerminal(const json& operation)
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

struct Block
{
    std::string id;
    size_t start = 0;
    size_t end = 0;
    std::string terminator;
    std::vector<size_t> successors;
};

struct PrototypeCfg
{
    uint64_t id = 0;
    size_t entry = 1;
    std::vector<Block> blocks;
};

struct ArgumentBinding
{
    size_t argument = 0;
    int64_t destination = -1;
};

struct LoadArgumentsShape
{
    size_t arity = 0;
    std::vector<ArgumentBinding> bindings;
};

struct RegisterClearRangeShape
{
    int64_t first_register = 0;
    int64_t last_register = 0;
};

class Emitter
{
public:
    Emitter(const json& reachableIr, const json& cfg)
        : reachableIr(reachableIr)
    {
        initialize("CFG parsing", [&] { parseCfg(cfg); });
        initialize("call-edge parsing", [&] { parseCallEdges(); });
        initialize("transition parsing", [&] { parseTransitionSequences(); });
        initialize("runtime-lane parsing", [&] { parseLaneReplaySequences(); });
        initialize("instruction parsing", [&] { parseInstructions(); });
        initialize("root-argument parsing", [&] { parseRootArguments(); });
        initialize("capture-provenance parsing", [&] { parseCaptureProvenance(); });
    }

    SemanticCandidate emit()
    {
        append("-- Internal trace-specialized semantic candidate for Luraph v14.7.\n");
        append("-- This is executable reconstruction scaffolding, not a claim of original source.\n");
        append("local environment = (getfenv and getfenv(0)) or _ENV\n");
        append("local unpack_values = unpack or table.unpack\n");
        append("local select_value = select\n");
        append("local function unresolved_helper(...) return nil end\n");
        append("local function unsupported_semantic_operation(prototype, pc, kind, reason)\n");
        append("  error(\"unsupported recovered semantic operation at prototype \" .. tostring(prototype) .. \" pc \" .. tostring(pc) .. \" (\" .. tostring(kind) .. \"): \" .. tostring(reason), 0)\n");
        append("end\n");
        append("local function resolve_named_function(name)\n");
        append("  return environment[name]\n");
        append("    or (environment.string and environment.string[name])\n");
        append("    or (environment.table and environment.table[name])\n");
        append("    or (environment.coroutine and environment.coroutine[name])\n");
        append("    or (environment.task and environment.task[name])\n");
        append("    or (environment.debug and environment.debug[name])\n");
        append("    or unresolved_helper\n");
        append("end\n");
        append("local helper_values = setmetatable({}, { __index = function() return unresolved_helper end })\n");
        append("helper_values[23] = function(first, values, last) return unpack_values(values, first, last) end\n");
        append("helper_values[34] = function(fn, env) return setfenv and setfenv(fn, env) or fn end\n");
        append("helper_values[36] = table.move or unresolved_helper\n");
        append("helper_values[39] = bit32 and bit32.bxor or unresolved_helper\n");
        append("helper_values[41] = table.create or function() return {} end\n");
        append("helper_values[53] = function(...) return select_value(\"#\", ...), {...} end\n");
        append("local opcode_values = {}\n");
        append("local operand_values = {}\n");
        append("local function capture_register_cell(open_cells, registers, slot)\n");
        append("  local cell = open_cells[slot]\n");
        append("  if not cell then cell = { [2] = slot, [3] = registers }; open_cells[slot] = cell end\n");
        append("  return cell\n");
        append("end\n");
        append("local function close_captured_values(open_cells, registers, from_slot)\n");
        append("  for slot, cell in open_cells do\n");
        append("    if slot >= from_slot and cell[3] == registers then\n");
        append("      cell[3] = { [slot] = registers[slot] }; open_cells[slot] = nil\n");
        append("    end\n");
        append("  end\n");
        append("end\n");
        append("local function unresolved_capture_cell(prototype, pc, encoded_key)\n");
        append("  local message = \"unresolved capture key at prototype \" .. tostring(prototype) .. \" pc \" .. tostring(pc) .. \" (encoded key \" .. tostring(encoded_key) .. \")\"\n");
        append("  local storage = setmetatable({}, { __index = function() error(message, 0) end, __newindex = function() error(message, 0) end })\n");
        append("  return { [2] = encoded_key, [3] = storage }\n");
        append("end\n");
        append("local function call_recovered(value, fallback, fallback_captures, ...)\n");
        append("  if type(value) == \"function\" then return value(...) end\n");
        append("  return fallback(fallback_captures, ...)\n");
        append("end\n");
        append("local legacy_transition_positions = {}\n");
        append("local transition_activation_positions = {}\n");
        append("local lane_activation_positions = {}\n");
        append("local semantic_recent_sites = {}\n");
        append("local function semantic_trace_tail() return table.concat(semantic_recent_sites, \" -> \") end\n");
        append("local function expand_replay_runs(runs)\n");
        append("  local sequences = {}\n");
        append("  for _, run in ipairs(runs) do\n");
        append("    for _ = 1, run[1] do sequences[#sequences + 1] = run[2] end\n");
        append("  end\n");
        append("  return sequences\n");
        append("end\n");
        append("local function replay_legacy_transition(prototype, pc, sequence)\n");
        append("  local key = tostring(prototype) .. \":\" .. tostring(pc)\n");
        append("  local position = (legacy_transition_positions[key] or 0) + 1\n");
        append("  legacy_transition_positions[key] = position\n");
        append("  if position > #sequence then\n");
        append("    local count = #sequence\n");
        append("    for period = 1, math.min(16, math.floor(count / 3)) do\n");
        append("      local start = count - period * 3 + 1\n");
        append("      local repeats = true\n");
        append("      for index = start, count - period do\n");
        append("        if sequence[index] ~= sequence[index + period] then repeats = false; break end\n");
        append("      end\n");
        append("      if repeats then return sequence[start + ((position - start) % period)] end\n");
        append("    end\n");
        append("    error(\"observed transition sequence exhausted at prototype \" .. tostring(prototype) .. \" pc \" .. tostring(pc) .. \" after \" .. tostring(#sequence) .. \" visits; recent path: \" .. semantic_trace_tail(), 0)\n");
        append("  end\n");
        append("  return sequence[position]\n");
        append("end\n");
        append("local function replay_runtime_lanes(local_positions, prototype, pc, sequences, repeat_from)\n");
        append("  local key = \"lane:\" .. tostring(prototype) .. \":\" .. tostring(pc)\n");
        append("  local position = (local_positions[key] or 0) + 1\n");
        append("  local_positions[key] = position\n");
        append("  local activation_key = key .. \":activation\"\n");
        append("  local activation_position = local_positions[activation_key]\n");
        append("  if activation_position == nil then\n");
        append("    activation_position = (lane_activation_positions[key] or 0) + 1\n");
        append("    lane_activation_positions[key] = activation_position\n");
        append("    local_positions[activation_key] = activation_position\n");
        append("  end\n");
        append("  if activation_position > #sequences then\n");
        append("    if repeat_from > 0 and repeat_from <= #sequences then activation_position = #sequences else\n");
        append("      error(\"observed runtime-lane activation sequence exhausted at prototype \" .. tostring(prototype) .. \" pc \" .. tostring(pc) .. \" after \" .. tostring(#sequences) .. \" activations; recent path: \" .. semantic_trace_tail(), 0)\n");
        append("    end\n");
        append("  end\n");
        append("  local sequence = sequences[activation_position]\n");
        append("  if position > #sequence then\n");
        append("    error(\"observed runtime-lane sequence exhausted at prototype \" .. tostring(prototype) .. \" pc \" .. tostring(pc) .. \" after \" .. tostring(#sequence) .. \" visits; recent path: \" .. semantic_trace_tail(), 0)\n");
        append("  end\n");
        append("  return sequence[position]\n");
        append("end\n");
        append("local function replay_activation_transition(local_positions, prototype, pc, sequences, repeat_from)\n");
        append("  local key = tostring(prototype) .. \":\" .. tostring(pc)\n");
        append("  local position = (local_positions[key] or 0) + 1\n");
        append("  local_positions[key] = position\n");
        append("  local activation_key = key .. \":activation\"\n");
        append("  local activation_position = local_positions[activation_key]\n");
        append("  if activation_position == nil then\n");
        append("    activation_position = (transition_activation_positions[key] or 0) + 1\n");
        append("    transition_activation_positions[key] = activation_position\n");
        append("    local_positions[activation_key] = activation_position\n");
        append("  end\n");
        append("  if activation_position > #sequences then\n");
        append("    if repeat_from > 0 and repeat_from <= #sequences then activation_position = #sequences else\n");
        append("      error(\"observed activation sequence exhausted at prototype \" .. tostring(prototype) .. \" pc \" .. tostring(pc) .. \" after \" .. tostring(#sequences) .. \" activations; recent path: \" .. semantic_trace_tail(), 0)\n");
        append("    end\n");
        append("  end\n");
        append("  local sequence = sequences[activation_position]\n");
        append("  if position > #sequence then\n");
        append("    error(\"observed per-activation transition sequence exhausted at prototype \" .. tostring(prototype) .. \" pc \" .. tostring(pc) .. \" after \" .. tostring(#sequence) .. \" visits; recent path: \" .. semantic_trace_tail(), 0)\n");
        append("  end\n");
        append("  return sequence[position]\n");
        append("end\n");
        append("local semantic_step_count = 0\n");
        append("local semantic_site_counts = {}\n");
        append("local function semantic_step(prototype, pc)\n");
        append("  semantic_step_count += 1\n");
        append("  local key = tostring(prototype) .. \":\" .. tostring(pc)\n");
        append("  semantic_site_counts[key] = (semantic_site_counts[key] or 0) + 1\n");
        append("  semantic_recent_sites[#semantic_recent_sites + 1] = key\n");
        append("  if #semantic_recent_sites > 96 then table.remove(semantic_recent_sites, 1) end\n");
        append("  if semantic_step_count > 1000000 then\n");
        append("    local hottest_key, hottest_count = key, 0\n");
        append("    for site, count in semantic_site_counts do\n");
        append("      if count > hottest_count then hottest_key, hottest_count = site, count end\n");
        append("    end\n");
        append("    error(\"semantic step budget exhausted at \" .. key .. \"; hottest site \" .. hottest_key .. \" (\" .. tostring(hottest_count) .. \" visits); recent path: \" .. semantic_trace_tail(), 0)\n");
        append("  end\n");
        append("end\n");
        append("local function prepare_generic_iterator(registers, state, base_register)\n");
        append("  local iterator = registers[base_register]\n");
        append("  local invariant = registers[base_register + 1]\n");
        append("  local control = registers[base_register + 2]\n");
        append("  local runner = coroutine.wrap(function()\n");
        append("    coroutine.yield()\n");
        append("    for key, value in iterator, invariant, control do\n");
        append("      coroutine.yield(true, key, value)\n");
        append("    end\n");
        append("  end)\n");
        append("  runner()\n");
        append("  state[\"f\"] = runner\n");
        append("end\n");
        append("local function build_root_arguments()\n");
        append("  -- Trace-backed bootstrap slots recovered from the payload's first activation.\n");
        if (rootArgumentExpressions.empty())
        {
            append("  return { [1] = rawset, [2] = environment, [12] = environment.coroutine, [52] = environment.debug }\n");
            result.inferred_root_slots = 4;
        }
        else
        {
            append("  return {\n");
            for (const auto& [key, value] : rootArgumentExpressions)
                append("    [" + std::to_string(key) + "] = " + value + ",\n");
            append("  }\n");
            result.inferred_root_slots = rootArgumentExpressions.size();
        }
        append("end\n");
        append("local function build_root_captures()\n");
        append("  local root_registers, inherited_registers, captures = {}, {}, {}\n");
        const json payloadRoot = reachableIr.value("payload_root", json(nullptr));
        const json rootDescriptor = payloadRoot.is_object()
            ? payloadRoot.value("closure_descriptor", json(nullptr)) : json(nullptr);
        if (rootDescriptor.is_object() && rootDescriptor.contains("captures") && rootDescriptor["captures"].is_array())
        {
            for (const json& capture : rootDescriptor["captures"])
            {
                const int64_t captureIndex = capture.value("capture_index", int64_t(-1));
                const int64_t kind = capture.value("capture_kind", int64_t(-1));
                const int64_t slot = capture.value("slot", int64_t(-1));
                if (captureIndex < 0 || slot < 0)
                {
                    ++result.unresolved_closure_descriptors;
                    continue;
                }
                if (kind == 0 || kind > 1)
                {
                    const std::string storage = kind == 0 ? "root_registers" : "inherited_registers";
                    append("  " + storage + "[" + std::to_string(slot) + "] = unresolved_helper\n");
                    append("  captures[" + std::to_string(captureIndex) + "] = { [2] = " +
                        std::to_string(slot) + ", [3] = " + storage + " }\n");
                }
                else
                    append("  captures[" + std::to_string(captureIndex) + "] = unresolved_helper\n");
            }
        }
        else
            ++result.unresolved_closure_descriptors;
        append("  return captures\n");
        append("end\n");

        const std::vector<uint64_t> prototypeIds = orderedPrototypeIds();
        append("local ");
        for (size_t index = 0; index < prototypeIds.size(); ++index)
        {
            if (index > 0)
                append(", ");
            append(prototypeName(prototypeIds[index]));
        }
        append("\n\n");

        for (uint64_t prototypeId : prototypeIds)
            emitPrototype(prototypeId);

        const uint64_t root = payloadRoot.is_object()
            ? payloadRoot.value("payload_prototype", uint64_t(0)) : uint64_t(0);
        if (root == 0 || !instructions.contains(root))
        {
            ++result.unsupported_operations;
            append("return nil\n");
        }
        else
            append("return " + prototypeName(root) + "(build_root_captures(), build_root_arguments())\n");
        result.source = output.str();
        result.prototypes = prototypeIds.size();
        return result;
    }

private:
    template<typename Callback>
    static void initialize(std::string_view stage, Callback&& callback)
    {
        try
        {
            callback();
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string(stage) + " failed: " + error.what());
        }
    }

    struct Context
    {
        uint64_t prototype = 0;
        size_t pc = 0;
        std::optional<uint64_t> callee;
        bool callee_consumed = false;
        const json* instruction = nullptr;
        std::string runtime_lanes_variable;
        std::set<std::string> runtime_lane_names;
        std::map<std::string, std::string> stable_lane_literals;
        bool path_specific = false;
    };

    struct CaptureDomain
    {
        bool seen = false;
        bool complete = true;
        std::set<int64_t> indices;
    };

    struct ObservedValueIdentity
    {
        std::string key;
        json value = json::object();
        bool callable = false;
    };

    struct RegisterCaptureSlice
    {
        int64_t encoded_key = -1;
        std::set<size_t> producer_pcs;
    };

    struct RegisterIdentitySlice
    {
        ObservedValueIdentity identity;
        size_t observations = 0;
        std::set<size_t> producer_pcs;
    };

    struct RegisterWriteInfo
    {
        json value = nullptr;
        json runtime_resolution = nullptr;
    };

    struct ObservedArgumentIdentityEvidence
    {
        ObservedValueIdentity identity;
        size_t observations = 0;
    };

    struct ObservedCallFrameEvidence
    {
        bool argument_count_complete = false;
        std::optional<size_t> argument_count;
        int64_t caller_opcode = -1;
        std::map<size_t, ObservedArgumentIdentityEvidence> argument_identities;
        json caller_handler = nullptr;
    };

    struct HandlerCallFrame
    {
        std::string base_lane;
        int64_t function_offset = 0;
        std::vector<int64_t> argument_offsets;
    };

    struct ResolvedCallFrame
    {
        std::optional<int64_t> function_register;
        std::vector<int64_t> argument_registers;
        std::string source;
        std::string base_lane;
        std::optional<int64_t> base_register;
        int64_t caller_opcode = -1;
    };

    struct TransitionModel
    {
        std::vector<size_t> legacy_sequence;
        std::vector<std::vector<size_t>> activation_sequences;
        size_t stable_suffix_start = 0;
    };

    struct LaneReplayModel
    {
        std::set<std::string> replay_lanes;
        std::map<std::string, std::string> stable_lane_literals;
        std::vector<std::vector<json>> activation_sequences;
        size_t stable_suffix_start = 0;
    };

    const json& reachableIr;
    std::map<uint64_t, PrototypeCfg> cfgs;
    std::map<uint64_t, std::map<size_t, std::vector<json>>> instructions;
    std::map<std::pair<uint64_t, size_t>, uint64_t> callEdges;
    std::map<std::pair<uint64_t, size_t>, std::map<uint64_t, size_t>> observedCallEdges;
    std::map<std::tuple<uint64_t, size_t, uint64_t>, ObservedCallFrameEvidence> observedCallFrames;
    std::map<std::pair<uint64_t, size_t>, TransitionModel> transitionModels;
    std::map<std::pair<uint64_t, size_t>, LaneReplayModel> laneReplayModels;
    std::map<uint64_t, CaptureDomain> captureDomains;
    std::map<uint64_t, std::map<int64_t, std::set<int64_t>>> captureKeyEvidence;
    std::map<uint64_t, std::map<int64_t, std::map<std::string, json>>> captureValueIdentities;
    std::set<std::tuple<uint64_t, uint64_t, int64_t, int64_t>> inheritedCaptureCells;
    std::map<std::tuple<uint64_t, int64_t, int64_t>, json> callArgumentIdentityEvidence;
    std::map<uint64_t, std::map<int64_t, std::set<uint64_t>>> closureRegisterTargets;
    std::map<uint64_t, std::map<int64_t, std::set<uint64_t>>> captureClosureTargets;
    uint64_t rootPrototype = 0;
    std::map<int64_t, std::string> rootArgumentExpressions;
    std::set<uint64_t> rootArgumentPrototypes;
    bool rootArgumentTableComplete = false;
    bool rootCallFrameSpecialized = false;
    std::set<std::tuple<uint64_t, size_t, int64_t>> remappedCaptureSites;
    std::set<std::tuple<uint64_t, size_t, int64_t>> unresolvedCaptureSites;
    std::ostringstream output;
    SemanticCandidate result;
    size_t line = 1;

    void append(std::string_view text)
    {
        output << text;
        line += static_cast<size_t>(std::count(text.begin(), text.end(), '\n'));
    }

    static std::string indentation(size_t depth)
    {
        return std::string(depth * 2, ' ');
    }

    static std::string prototypeName(uint64_t id)
    {
        return "recovered_routine_" + std::to_string(id);
    }

    void parseCfg(const json& cfg)
    {
        if (!cfg.contains("prototypes") || !cfg["prototypes"].is_array())
            return;
        for (const json& row : cfg["prototypes"])
        {
            PrototypeCfg prototype;
            prototype.id = row.value("runtime_id", uint64_t(0));
            prototype.entry = row.value("entry_pc", size_t(1));
            std::map<std::string, size_t> starts;
            if (row.contains("blocks") && row["blocks"].is_array())
                for (const json& block : row["blocks"])
                    starts[block.value("id", "")] = block.value("start_pc", size_t(0));
            if (row.contains("blocks") && row["blocks"].is_array())
            {
                for (const json& blockRow : row["blocks"])
                {
                    if (!blockRow.value("reachable", false))
                        continue;
                    Block block;
                    block.id = blockRow.value("id", "");
                    block.start = blockRow.value("start_pc", size_t(0));
                    block.end = blockRow.value("end_pc", size_t(0));
                    block.terminator = blockRow.value("terminator", "fallthrough");
                    for (const json& successor : blockRow.value("successors", json::array()))
                        if (successor.is_string() && starts.contains(successor.get<std::string>()))
                            block.successors.push_back(starts[successor.get<std::string>()]);
                    prototype.blocks.push_back(std::move(block));
                }
            }
            if (prototype.id != 0)
                cfgs[prototype.id] = std::move(prototype);
        }
    }

    void parseCallEdges()
    {
        if (!reachableIr.contains("prototype_call_edges") || !reachableIr["prototype_call_edges"].is_array())
            return;
        for (const json& edge : reachableIr["prototype_call_edges"])
        {
            const uint64_t prototype = edge.value("caller_prototype", uint64_t(0));
            const size_t pc = edge.value("caller_pc", size_t(0));
            const uint64_t callee = edge.value("callee_prototype", uint64_t(0));
            if (prototype != 0 && pc != 0 && callee != 0)
            {
                callEdges[{prototype, pc}] = callee;
                const uint64_t observations = positiveUnsignedField(edge, "observed_activations");
                if (observations > 0 && observations <= std::numeric_limits<size_t>::max())
                {
                    size_t& total = observedCallEdges[{prototype, pc}][callee];
                    const size_t count = static_cast<size_t>(observations);
                    total = count <= std::numeric_limits<size_t>::max() - total ? total + count : 0;

                    ObservedCallFrameEvidence frame;
                    frame.caller_opcode = edge.contains("caller_opcode") && edge["caller_opcode"].is_number_integer()
                        ? edge["caller_opcode"].get<int64_t>() : int64_t(-1);
                    frame.argument_count_complete = edge.value("observed_argument_count_complete", false);
                    if (frame.argument_count_complete && edge.contains("observed_argument_count"))
                    {
                        const json& argumentCount = edge["observed_argument_count"];
                        if (argumentCount.is_number_unsigned() &&
                            argumentCount.get<uint64_t>() <= std::numeric_limits<size_t>::max())
                            frame.argument_count = static_cast<size_t>(argumentCount.get<uint64_t>());
                        else if (argumentCount.is_number_integer())
                        {
                            const int64_t value = argumentCount.get<int64_t>();
                            if (value >= 0 && static_cast<uint64_t>(value) <= std::numeric_limits<size_t>::max())
                                frame.argument_count = static_cast<size_t>(value);
                        }
                    }
                    frame.argument_count_complete = frame.argument_count_complete && frame.argument_count.has_value();
                    if (edge.contains("observed_caller_handler") && edge["observed_caller_handler"].is_object())
                        frame.caller_handler = edge["observed_caller_handler"];

                    std::set<size_t> ambiguousArguments;
                    if (frame.argument_count_complete && edge.contains("observed_argument_identities") &&
                        edge["observed_argument_identities"].is_array())
                        for (const json& row : edge["observed_argument_identities"])
                        {
                            const size_t argumentIndex = row.value("argument_index", size_t(0));
                            const uint64_t identityObservations = positiveUnsignedField(row, "observed_activations");
                            if (argumentIndex == 0 || argumentIndex > *frame.argument_count ||
                                identityObservations != observations || !row.contains("identity"))
                                continue;
                            const std::optional<ObservedValueIdentity> identity = observedValueIdentity(row["identity"]);
                            if (!identity || !identity->callable || ambiguousArguments.contains(argumentIndex))
                                continue;
                            const auto existing = frame.argument_identities.find(argumentIndex);
                            if (existing != frame.argument_identities.end() &&
                                existing->second.identity.key != identity->key)
                            {
                                frame.argument_identities.erase(existing);
                                ambiguousArguments.insert(argumentIndex);
                                continue;
                            }
                            frame.argument_identities[argumentIndex] = {
                                *identity,
                                static_cast<size_t>(identityObservations),
                            };
                        }

                    const auto frameKey = std::make_tuple(prototype, pc, callee);
                    if (!observedCallFrames.emplace(frameKey, std::move(frame)).second)
                    {
                        ObservedCallFrameEvidence& duplicate = observedCallFrames[frameKey];
                        duplicate.argument_count_complete = false;
                        duplicate.argument_count.reset();
                        duplicate.argument_identities.clear();
                        duplicate.caller_handler = nullptr;
                    }
                }
            }
        }
    }

    static bool writesRegister(const json& value, int64_t target)
    {
        if (value.is_array())
        {
            for (const json& child : value)
                if (writesRegister(child, target))
                    return true;
            return false;
        }
        if (!value.is_object())
            return false;
        if (value.value("kind", "") == "register_write")
            if (const std::optional<int64_t> destination = integerValue(value.value("register", json::object()));
                destination && *destination == target)
                return true;
        for (const auto& [name, child] : value.items())
        {
            (void)name;
            if (writesRegister(child, target))
                return true;
        }
        return false;
    }

    static bool rootArgumentTableEscapes(const json& value, std::string_view parentKind = {},
        std::string_view childName = {})
    {
        if (value.is_array())
        {
            for (const json& child : value)
                if (rootArgumentTableEscapes(child, parentKind, childName))
                    return true;
            return false;
        }
        if (!value.is_object())
            return false;
        const std::string kind = value.value("kind", "");
        if (kind == "register_read")
            if (const std::optional<int64_t> index = integerValue(value.value("index", json::object()));
                index && *index == 1)
                return parentKind != "index_read" || childName != "table";
        for (const auto& [name, child] : value.items())
            if (rootArgumentTableEscapes(child, kind, name))
                return true;
        return false;
    }

    void parseRootArguments()
    {
        const json payloadRoot = reachableIr.value("payload_root", json::object());
        rootPrototype = positiveUnsignedField(payloadRoot, "payload_prototype");
        if (rootPrototype > 0)
            rootArgumentPrototypes.insert(rootPrototype);
        if (reachableIr.contains("root_argument_table_prototypes") &&
            reachableIr["root_argument_table_prototypes"].is_array())
            for (const json& prototype : reachableIr["root_argument_table_prototypes"])
            {
                const std::optional<uint64_t> prototypeId = nonnegativeInteger(prototype);
                if (prototypeId && *prototypeId > 0)
                    rootArgumentPrototypes.insert(*prototypeId);
            }
        result.root_argument_shared_prototypes = rootArgumentPrototypes.size();
        const json payloadArguments = reachableIr.value("payload_activation_arguments", json(nullptr));
        if (rootPrototype == 0 || !payloadArguments.is_object() ||
            !payloadArguments.contains("argument_table_entries") ||
            !payloadArguments["argument_table_entries"].is_array())
            return;
        const size_t argumentCount = payloadArguments.value("argument_count", size_t(0));
        rootCallFrameSpecialized = argumentCount == 1 &&
            std::none_of(callEdges.begin(), callEdges.end(), [&](const auto& edge) {
                return edge.second == rootPrototype;
            });
        if (!payloadArguments.value("argument_table_conflict", false) &&
            payloadArguments.contains("argument_table_domains") &&
            payloadArguments["argument_table_domains"].is_array())
            for (const json& domain : payloadArguments["argument_table_domains"])
                if (domain.is_object() && domain.value("argument_index", size_t(0)) == 1 &&
                    domain.value("complete", false))
                {
                    const size_t observedEntries = domain.value("observed_entries", size_t(0));
                    const size_t recoveredEntries = static_cast<size_t>(std::count_if(
                        payloadArguments["argument_table_entries"].begin(),
                        payloadArguments["argument_table_entries"].end(), [](const json& entry) {
                            return entry.is_object() && entry.value("argument_index", size_t(0)) == 1;
                        }));
                    rootArgumentTableComplete = observedEntries == recoveredEntries;
                    break;
                }
        for (const json& entry : payloadArguments["argument_table_entries"])
        {
            if (!entry.is_object() || entry.value("argument_index", size_t(0)) != 1 ||
                !entry.contains("key") || !entry.contains("value"))
                continue;
            const std::optional<int64_t> key = primitiveIntegerValue(entry["key"]);
            const std::optional<std::string> value = observedBootstrapExpression(entry["value"]);
            if (key && *key >= 0 && value)
                rootArgumentExpressions[*key] = *value;
        }
        const auto prototype = instructions.find(rootPrototype);
        if (prototype == instructions.end())
        {
            rootArgumentExpressions.clear();
            return;
        }
        for (const auto& [pc, rows] : prototype->second)
        {
            (void)pc;
            for (const json& instruction : rows)
                if (const json* semantic = semanticOperationForInstruction(instruction);
                    semantic && (writesRegister(*semantic, 1) || rootArgumentTableEscapes(*semantic)))
                {
                    rootArgumentExpressions.clear();
                    rootArgumentTableComplete = false;
                    return;
                }
        }
        result.root_argument_table_complete = rootArgumentTableComplete;
        result.root_call_frame_specialized = rootCallFrameSpecialized;
    }

    void parseTransitionSequences()
    {
        if (!reachableIr.contains("observed_transition_sequences") ||
            !reachableIr["observed_transition_sequences"].is_array())
            return;
        for (const json& row : reachableIr["observed_transition_sequences"])
        {
            const uint64_t prototype = row.value("prototype", uint64_t(0));
            const size_t pc = row.value("pc", size_t(0));
            if (prototype == 0 || pc == 0)
                continue;
            TransitionModel& model = transitionModels[{prototype, pc}];
            const auto appendSequence = [](const json& values, std::vector<size_t>& sequence) {
                if (!values.is_array())
                    return;
                for (const json& next : values)
                    if (next.is_number_unsigned() || next.is_number_integer())
                    {
                        const int64_t value = next.get<int64_t>();
                        if (value > 0)
                            sequence.push_back(static_cast<size_t>(value));
                    }
            };
            if (row.contains("next_pcs"))
                appendSequence(row["next_pcs"], model.legacy_sequence);
            if (row.contains("activation_sequences") && row["activation_sequences"].is_array())
            {
                for (const json& activation : row["activation_sequences"])
                {
                    std::vector<size_t> sequence;
                    if (activation.is_object() && activation.contains("next_pcs"))
                        appendSequence(activation["next_pcs"], sequence);
                    if (!sequence.empty())
                        model.activation_sequences.push_back(std::move(sequence));
                }
                if (!model.activation_sequences.empty())
                {
                    ++result.activation_scoped_transition_sites;
                    const size_t repeatFrom = row.value("repeat_from_sequence", size_t(0));
                    if (repeatFrom > 0 && repeatFrom <= model.activation_sequences.size())
                    {
                        model.stable_suffix_start = repeatFrom;
                        ++result.stable_mutation_epoch_sites;
                    }
                }
            }
            const std::vector<size_t>& sequence = model.legacy_sequence;
            if (sequence.size() >= 4 && sequence.back() == sequence[sequence.size() - 2] &&
                sequence.back() == sequence[sequence.size() - 3])
                ++result.steady_state_transition_sites;
            else
            {
                const size_t maximumPeriod = std::min<size_t>(16, sequence.size() / 3);
                for (size_t period = 2; period <= maximumPeriod; ++period)
                {
                    const size_t start = sequence.size() - period * 3;
                    bool repeats = true;
                    for (size_t index = start; index + period < sequence.size(); ++index)
                        if (sequence[index] != sequence[index + period])
                        {
                            repeats = false;
                            break;
                        }
                    if (repeats)
                    {
                        ++result.periodic_transition_sites;
                        break;
                    }
                }
            }
        }
    }

    void parseLaneReplaySequences()
    {
        if (!reachableIr.contains("observed_lane_sequences") ||
            !reachableIr["observed_lane_sequences"].is_array())
            return;
        for (const json& row : reachableIr["observed_lane_sequences"])
        {
            const uint64_t prototype = row.value("prototype", uint64_t(0));
            const size_t pc = row.value("pc", size_t(0));
            if (prototype == 0 || pc == 0 || !row.contains("lanes") || !row["lanes"].is_array() ||
                !row.contains("activation_sequences") || !row["activation_sequences"].is_array())
                continue;
            LaneReplayModel model;
            std::set<std::string> observedLanes;
            for (const json& lane : row["lanes"])
                if (lane.is_string())
                    observedLanes.insert(lane.get<std::string>());
            for (const json& activation : row["activation_sequences"])
            {
                if (!activation.is_object() || !activation.contains("frames") || !activation["frames"].is_array())
                    continue;
                std::vector<json> frames;
                for (const json& frame : activation["frames"])
                    if (frame.is_object())
                        frames.push_back(frame);
                if (!frames.empty())
                    model.activation_sequences.push_back(std::move(frames));
            }
            size_t observedFrameCount = 0;
            for (const std::vector<json>& frames : model.activation_sequences)
                observedFrameCount += frames.size();
            for (const std::string& lane : observedLanes)
            {
                std::optional<std::string> stableLiteral;
                bool stable = observedFrameCount > 0;
                for (const std::vector<json>& frames : model.activation_sequences)
                    for (const json& frame : frames)
                    {
                        if (!frame.contains(lane))
                        {
                            stable = false;
                            continue;
                        }
                        const std::optional<std::string> literal = specializationPrimitiveLiteral(frame[lane]);
                        if (!literal || (stableLiteral && *stableLiteral != *literal))
                            stable = false;
                        else if (!stableLiteral)
                            stableLiteral = literal;
                    }
                if (stable && stableLiteral)
                {
                    model.stable_lane_literals[lane] = *stableLiteral;
                    ++result.specialized_stable_lanes;
                    result.specialized_stable_lane_values += observedFrameCount;
                }
                else
                    model.replay_lanes.insert(lane);
            }
            const size_t repeatFrom = row.value("repeat_from_sequence", size_t(0));
            if (repeatFrom > 0 && repeatFrom <= model.activation_sequences.size())
                model.stable_suffix_start = repeatFrom;
            if ((!model.replay_lanes.empty() || !model.stable_lane_literals.empty()) &&
                !model.activation_sequences.empty())
            {
                if (!model.replay_lanes.empty())
                {
                    ++result.dynamic_lane_replay_sites;
                    result.replayed_dynamic_lane_values += observedFrameCount * model.replay_lanes.size();
                }
                laneReplayModels[{prototype, pc}] = std::move(model);
            }
        }
    }

    void parseInstructions()
    {
        if (!reachableIr.contains("prototypes") || !reachableIr["prototypes"].is_array())
            return;
        for (const json& prototype : reachableIr["prototypes"])
        {
            const uint64_t id = prototype.value("runtime_id", uint64_t(0));
            if (id == 0 || !prototype.contains("instructions") || !prototype["instructions"].is_array())
                continue;
            for (const json& instruction : prototype["instructions"])
            {
                const size_t pc = instruction.value("pc", size_t(0));
                if (pc != 0)
                    instructions[id][pc].push_back(instruction);
                if (!instruction.contains("observed_returns") || !instruction["observed_returns"].is_array() ||
                    instruction["observed_returns"].empty())
                    continue;
                result.observed_return_events += instruction["observed_returns"].size();
                const json* semantic = semanticOperationForInstruction(instruction);
                if (!semantic || semantic->value("kind", "") != "return")
                {
                    ++result.return_arity_mismatches;
                    continue;
                }
                const json values = semantic->value("values", json::array());
                if (isPathSpecificOperation(*semantic) && values.is_array() && values.empty())
                {
                    const json& first = instruction["observed_returns"].front();
                    const bool stable = first.is_object() && first.value("complete", false) &&
                        first.contains("values") && first["values"].is_array() &&
                        std::all_of(instruction["observed_returns"].begin(),
                            instruction["observed_returns"].end(), [&](const json& returned) {
                                return returned.is_object() && returned.value("complete", false) &&
                                    returned.value("arity", std::numeric_limits<size_t>::max()) ==
                                        first["values"].size() &&
                                    returned.value("values", json(nullptr)) == first["values"];
                            }) &&
                        std::all_of(first["values"].begin(), first["values"].end(), [](const json& returned) {
                            return specializationPrimitiveLiteral(returned).has_value();
                        });
                    if (stable)
                        ++result.verified_return_sites;
                    else
                        ++result.return_arity_mismatches;
                    continue;
                }
                bool explicitArity = values.is_array();
                if (explicitArity && !values.empty() && values.back().is_object())
                {
                    const std::string lastKind = values.back().value("kind", "");
                    explicitArity = lastKind != "call" && lastKind != "register_range" && lastKind != "varargs";
                }
                if (!explicitArity)
                    continue;
                const bool matches = std::all_of(instruction["observed_returns"].begin(),
                    instruction["observed_returns"].end(), [&](const json& returned) {
                        return returned.value("complete", false) &&
                            returned.value("arity", std::numeric_limits<size_t>::max()) == values.size();
                    });
                if (matches)
                    ++result.verified_return_sites;
                else
                    ++result.return_arity_mismatches;
            }
        }
    }

    static void collectUpvalueIndexLanes(const json& value, std::set<std::string>& lanes)
    {
        if (value.is_array())
        {
            for (const json& item : value)
                collectUpvalueIndexLanes(item, lanes);
            return;
        }
        if (!value.is_object())
            return;
        if (value.value("kind", "") == "index_read")
        {
            const json& table = value.contains("table") ? value["table"] : json::object();
            const json& index = value.contains("index") ? value["index"] : json::object();
            if (table.is_object() && table.value("kind", "") == "upvalue_file" &&
                index.is_object() && index.value("kind", "") == "immediate")
            {
                const std::string lane = index.value("lane", "");
                if (!lane.empty())
                    lanes.insert(lane);
            }
        }
        for (const auto& [key, child] : value.items())
        {
            (void)key;
            collectUpvalueIndexLanes(child, lanes);
        }
    }

    static bool plainIdentifier(std::string_view value)
    {
        if (value.empty() || (!std::isalpha(static_cast<unsigned char>(value.front())) && value.front() != '_'))
            return false;
        return std::all_of(value.begin() + 1, value.end(), [](unsigned char ch) {
            return std::isalnum(ch) || ch == '_';
        });
    }

    static std::optional<std::string> topLevelGlobalFunctionName(std::string_view path)
    {
        if (path.starts_with("_G."))
            path.remove_prefix(3);
        if (!plainIdentifier(path))
            return std::nullopt;
        return std::string(path);
    }

    static std::optional<ObservedValueIdentity> observedValueIdentity(const json& value)
    {
        if (!value.is_object())
            return std::nullopt;
        const std::string type = value.value("type", "");
        if (type == "function")
        {
            const bool callable = !value.contains("callable") ||
                (value["callable"].is_boolean() && value["callable"].get<bool>());
            const std::string name = value.contains("name") && value["name"].is_string()
                ? value["name"].get<std::string>() : std::string();
            if (!callable || !plainIdentifier(name))
                return ObservedValueIdentity{
                    "unidentified_function:" + (name.empty() ? std::string("<anonymous>") : name),
                    {{"type", "function"}, {"name", name.empty() ? json(nullptr) : json(name)}},
                    false,
                };
            return ObservedValueIdentity{
                "function:" + name,
                {{"type", "function"}, {"name", name}},
                true,
            };
        }
        if (type == "global_reference")
        {
            const std::string path = value.contains("path") && value["path"].is_string()
                ? value["path"].get<std::string>() : std::string();
            if (path.empty())
                return std::nullopt;
            if (const std::optional<std::string> name = topLevelGlobalFunctionName(path))
                return ObservedValueIdentity{
                    "function:" + *name,
                    {{"type", "global_reference"}, {"path", path}},
                    true,
                };
            return ObservedValueIdentity{
                "global_reference:" + path,
                {{"type", "global_reference"}, {"path", path}},
                false,
            };
        }
        if (type == "nil" || type == "boolean" || type == "number" || type == "string")
        {
            if (!value.contains("value"))
                return std::nullopt;
            const json normalized = {{"type", type}, {"value", value["value"]}};
            return ObservedValueIdentity{"primitive:" + normalized.dump(), normalized, false};
        }
        if (type.empty() || type == "invalid")
            return std::nullopt;
        return ObservedValueIdentity{"non_callable_type:" + type, {{"type", type}}, false};
    }

    void recordObservedCaptureValues(uint64_t prototype, const json& domain)
    {
        if (prototype == 0 || !domain.contains("indices") || !domain["indices"].is_array() ||
            !domain.contains("values"))
            return;
        std::set<int64_t> declaredIndices;
        for (const json& index : domain["indices"])
            if (index.is_number_integer() && index.get<int64_t>() >= 0)
                declaredIndices.insert(index.get<int64_t>());

        const auto record = [&](const json& observed) {
            if (!observed.is_object() || !observed.contains("capture_index") ||
                !observed["capture_index"].is_number_integer() || !observed.contains("resolved_value"))
                return;
            const int64_t captureIndex = observed["capture_index"].get<int64_t>();
            if (!declaredIndices.contains(captureIndex))
                return;
            const std::optional<ObservedValueIdentity> identity =
                observedValueIdentity(observed["resolved_value"]);
            if (identity)
                captureValueIdentities[prototype][captureIndex][identity->key] = identity->value;
        };

        if (domain["values"].is_object())
            for (auto value = domain["values"].begin(); value != domain["values"].end(); ++value)
                record(value.value());
        else if (domain["values"].is_array())
            for (const json& value : domain["values"])
                record(value);
    }

    void recordInheritedCaptureCells(uint64_t parentPrototype, const json& descriptor)
    {
        const uint64_t childPrototype = positiveUnsignedField(descriptor, "target_prototype");
        if (parentPrototype == 0 || childPrototype == 0 || !descriptor.value("complete", false) ||
            !descriptor.contains("captures") || !descriptor["captures"].is_array())
            return;
        for (const json& capture : descriptor["captures"])
        {
            const int64_t captureIndex = capture.value("capture_index", int64_t(-1));
            const int64_t captureKind = capture.value("capture_kind", int64_t(-1));
            const int64_t parentKey = capture.value("slot", int64_t(-1));
            if (captureKind == 2 && captureIndex >= 0 && parentKey >= 0)
                inheritedCaptureCells.insert({parentPrototype, childPrototype, captureIndex, parentKey});
        }
    }

    void mergeCaptureDomain(uint64_t prototype, std::set<int64_t> indices, bool complete)
    {
        if (prototype == 0)
            return;
        CaptureDomain& domain = captureDomains[prototype];
        if (!domain.seen)
        {
            domain.seen = true;
            domain.complete = complete;
            domain.indices = std::move(indices);
            return;
        }
        if (!complete || domain.indices != indices)
            domain.complete = false;
    }

    void addCaptureDomain(uint64_t prototype, const json& descriptor)
    {
        std::set<int64_t> indices;
        bool complete = descriptor.value("complete", false) && descriptor.contains("captures") &&
            descriptor["captures"].is_array();
        if (complete)
        {
            for (const json& capture : descriptor["captures"])
            {
                const int64_t index = capture.value("capture_index", int64_t(-1));
                if (index < 0 || !indices.insert(index).second)
                {
                    complete = false;
                    break;
                }
            }
        }
        mergeCaptureDomain(prototype, std::move(indices), complete);
    }

    void parseObservedCaptureDomains()
    {
        if (!reachableIr.contains("observed_capture_domains") ||
            !reachableIr["observed_capture_domains"].is_array())
            return;
        for (const json& row : reachableIr["observed_capture_domains"])
        {
            const uint64_t prototype = row.value("prototype", uint64_t(0));
            std::set<int64_t> indices;
            bool complete = prototype > 0 && row.value("complete", false) &&
                row.contains("indices") && row["indices"].is_array();
            if (complete)
            {
                for (const json& value : row["indices"])
                {
                    if (!value.is_number_integer())
                    {
                        complete = false;
                        break;
                    }
                    const int64_t index = value.get<int64_t>();
                    if (index < 0 || !indices.insert(index).second)
                    {
                        complete = false;
                        break;
                    }
                }
            }
            recordObservedCaptureValues(prototype, row);
            mergeCaptureDomain(prototype, std::move(indices), complete);
        }
    }

    static std::optional<RegisterWriteInfo> lastRegisterWrite(
        const json& operation, int64_t targetRegister)
    {
        if (!operation.is_object())
            return std::nullopt;
        const std::string kind = operation.value("kind", "");
        if (kind == "operation_sequence" || kind == "protector_internal_sequence" || kind == "block")
        {
            std::optional<RegisterWriteInfo> result;
            for (const json& child : operation.value("operations", json::array()))
                if (std::optional<RegisterWriteInfo> value = lastRegisterWrite(child, targetRegister))
                    result = std::move(value);
            return result;
        }
        if (kind != "register_write")
            return std::nullopt;
        const std::optional<int64_t> destination = integerValue(operation.value("register", json::object()));
        if (!destination || *destination != targetRegister)
            return std::nullopt;
        return RegisterWriteInfo{
            operation.value("value", json(nullptr)),
            operation.value("runtime_resolution", json(nullptr)),
        };
    }

    static std::optional<json> registerWriteValue(const json& operation, int64_t targetRegister)
    {
        const std::optional<RegisterWriteInfo> write = lastRegisterWrite(operation, targetRegister);
        return write ? std::optional<json>(write->value) : std::nullopt;
    }

    static void collectRegisterWriteDestinations(const json& operation, std::set<int64_t>& registers)
    {
        if (operation.is_array())
        {
            for (const json& child : operation)
                collectRegisterWriteDestinations(child, registers);
            return;
        }
        if (!operation.is_object())
            return;
        if (operation.value("kind", "") == "register_write")
            if (const std::optional<int64_t> destination = integerValue(
                    operation.value("register", json::object())); destination && *destination >= 0)
                registers.insert(*destination);
        for (const auto& [name, child] : operation.items())
        {
            (void)name;
            collectRegisterWriteDestinations(child, registers);
        }
    }

    static void collectCaptureKeys(const json& value, std::set<int64_t>& keys)
    {
        if (value.is_array())
        {
            for (const json& item : value)
                collectCaptureKeys(item, keys);
            return;
        }
        if (!value.is_object())
            return;
        if (value.value("kind", "") == "index_read")
        {
            const json table = value.value("table", json::object());
            if (table.value("kind", "") == "upvalue_file")
                if (const std::optional<int64_t> key = integerValue(value.value("index", json::object())); key && *key >= 0)
                    keys.insert(*key);
        }
        for (const auto& [name, child] : value.items())
        {
            (void)name;
            collectCaptureKeys(child, keys);
        }
    }

    static std::optional<int64_t> directCaptureKey(const json& value)
    {
        if (!value.is_object() || value.value("kind", "") != "index_read")
            return std::nullopt;
        const json table = value.value("table", json::object());
        if (!table.is_object() || table.value("kind", "") != "upvalue_file")
            return std::nullopt;
        const std::optional<int64_t> key = integerValue(value.value("index", json::object()));
        return key && *key >= 0 ? key : std::nullopt;
    }

    static std::optional<int64_t> captureCellValueKey(const json& value)
    {
        if (const std::optional<int64_t> direct = directCaptureKey(value))
            return direct;
        if (!value.is_object() || value.value("kind", "") != "index_read")
            return std::nullopt;
        const json storageRead = value.value("table", json::object());
        const json slotRead = value.value("index", json::object());
        if (!storageRead.is_object() || storageRead.value("kind", "") != "index_read" ||
            !slotRead.is_object() || slotRead.value("kind", "") != "index_read")
            return std::nullopt;
        const std::optional<int64_t> storageField = integerValue(storageRead.value("index", json::object()));
        const std::optional<int64_t> slotField = integerValue(slotRead.value("index", json::object()));
        if (!storageField || *storageField != 3 || !slotField || *slotField != 2)
            return std::nullopt;
        const std::optional<int64_t> storageKey = directCaptureKey(storageRead.value("table", json::object()));
        const std::optional<int64_t> slotKey = directCaptureKey(slotRead.value("table", json::object()));
        if (!storageKey || !slotKey || *storageKey != *slotKey)
            return std::nullopt;
        return storageKey;
    }

    static void collectCallFunctionRegisters(const json& value, std::set<int64_t>& registers)
    {
        if (value.is_array())
        {
            for (const json& item : value)
                collectCallFunctionRegisters(item, registers);
            return;
        }
        if (!value.is_object())
            return;
        if (value.value("kind", "") == "call")
        {
            const json function = value.value("function", json::object());
            if (function.value("kind", "") == "register_read")
                if (const std::optional<int64_t> index = integerValue(function.value("index", json::object())); index && *index >= 0)
                    registers.insert(*index);
        }
        for (const auto& [name, child] : value.items())
        {
            (void)name;
            collectCallFunctionRegisters(child, registers);
        }
    }

    static void collectCallExpressions(const json& value, std::vector<const json*>& calls)
    {
        if (value.is_array())
        {
            for (const json& item : value)
                collectCallExpressions(item, calls);
            return;
        }
        if (!value.is_object())
            return;
        if (value.value("kind", "") == "call")
            calls.push_back(&value);
        for (const auto& [name, child] : value.items())
        {
            (void)name;
            collectCallExpressions(child, calls);
        }
    }

    static std::optional<std::pair<std::string, int64_t>> affineLaneOffset(
        const json& value, size_t depth = 0)
    {
        if (depth > 8 || !value.is_object())
            return std::nullopt;
        const std::string kind = value.value("kind", "");
        if (kind == "operand" || kind == "immediate")
        {
            const std::string lane = value.value("lane", "");
            return lane.empty() ? std::nullopt :
                std::optional<std::pair<std::string, int64_t>>({lane, 0});
        }
        if (kind != "binary")
            return std::nullopt;
        const std::string operation = value.value("operator", "");
        if (operation != "+" && operation != "-")
            return std::nullopt;
        const json left = value.value("left", json::object());
        const json right = value.value("right", json::object());
        const std::optional<std::pair<std::string, int64_t>> leftLane = affineLaneOffset(left, depth + 1);
        const std::optional<std::pair<std::string, int64_t>> rightLane = affineLaneOffset(right, depth + 1);
        const std::optional<int64_t> leftConstant = integerValue(left);
        const std::optional<int64_t> rightConstant = integerValue(right);
        const auto shifted = [](const std::pair<std::string, int64_t>& lane, int64_t amount,
                                 bool subtract) -> std::optional<std::pair<std::string, int64_t>> {
            if ((!subtract && amount > 0 && lane.second > std::numeric_limits<int64_t>::max() - amount) ||
                (!subtract && amount < 0 && lane.second < std::numeric_limits<int64_t>::min() - amount) ||
                (subtract && amount > 0 && lane.second < std::numeric_limits<int64_t>::min() + amount) ||
                (subtract && amount < 0 && lane.second > std::numeric_limits<int64_t>::max() + amount))
                return std::nullopt;
            return std::pair<std::string, int64_t>{
                lane.first,
                subtract ? lane.second - amount : lane.second + amount,
            };
        };
        if (leftLane && rightConstant)
            return shifted(*leftLane, *rightConstant, operation == "-");
        if (operation == "+" && leftConstant && rightLane)
            return shifted(*rightLane, *leftConstant, false);
        return std::nullopt;
    }

    static std::optional<HandlerCallFrame> handlerCallFrame(const json& handler, int64_t expectedOpcode)
    {
        if (!handler.is_object() || handler.value("opcode", int64_t(-1)) != expectedOpcode ||
            !handler.value("normalization_complete", false) || !handler.value("vm_state_independent", false) ||
            !handler.contains("effects") || !handler["effects"].is_object() ||
            !handler.contains("semantic_operation") || !handler["semantic_operation"].is_object())
            return std::nullopt;
        const json& effects = handler["effects"];
        const json candidates = effects.value("operation_candidates", json::array());
        if (effects.value("calls", size_t(0)) != 1 || effects.value("register_calls", size_t(0)) != 1 ||
            !candidates.is_array() || candidates.size() != 1 || candidates[0] != "call")
            return std::nullopt;
        std::vector<const json*> calls;
        collectCallExpressions(handler["semantic_operation"], calls);
        if (calls.size() != 1 || calls.front()->value("method", false) ||
            !calls.front()->contains("function") || !(*calls.front())["function"].is_object() ||
            (*calls.front())["function"].value("kind", "") != "register_read" ||
            !calls.front()->contains("arguments") || !(*calls.front())["arguments"].is_array())
            return std::nullopt;
        const std::optional<std::pair<std::string, int64_t>> function =
            affineLaneOffset((*calls.front())["function"].value("index", json::object()));
        if (!function)
            return std::nullopt;
        HandlerCallFrame frame;
        frame.base_lane = function->first;
        frame.function_offset = function->second;
        for (const json& argument : (*calls.front())["arguments"])
        {
            if (!argument.is_object() || argument.value("kind", "") != "register_read")
                return std::nullopt;
            const std::optional<std::pair<std::string, int64_t>> index =
                affineLaneOffset(argument.value("index", json::object()));
            if (!index || index->first != frame.base_lane)
                return std::nullopt;
            frame.argument_offsets.push_back(index->second);
        }
        return frame;
    }

    std::optional<int64_t> instructionLaneValue(
        const json& instruction, uint64_t prototype, size_t pc, const std::string& lane) const
    {
        if (lane.empty())
            return std::nullopt;
        if (const auto replay = laneReplayModels.find({prototype, pc}); replay != laneReplayModels.end() &&
            (replay->second.replay_lanes.contains(lane) || replay->second.stable_lane_literals.contains(lane)))
            return std::nullopt;
        const json staticLanes = instruction.value("static_lanes", json::object());
        const json lanes = instruction.value("lanes", json::object());
        if (!staticLanes.is_object() || !lanes.is_object() ||
            !staticLanes.contains(lane) || !lanes.contains(lane))
            return std::nullopt;
        const std::optional<int64_t> staticValue = primitiveIntegerValue(staticLanes[lane]);
        const std::optional<int64_t> effectiveValue = primitiveIntegerValue(lanes[lane]);
        if (!staticValue || !effectiveValue || *staticValue < 0 || *staticValue != *effectiveValue)
            return std::nullopt;
        const json overrides = instruction.value("runtime_lane_overrides", json::object());
        if (overrides.is_object() && overrides.contains(lane))
        {
            const std::optional<int64_t> overrideValue = primitiveIntegerValue(overrides[lane]);
            if (!overrideValue || *overrideValue != *effectiveValue)
                return std::nullopt;
        }
        return effectiveValue;
    }

    static std::optional<int64_t> shiftedRegister(int64_t base, int64_t offset)
    {
        if ((offset > 0 && base > std::numeric_limits<int64_t>::max() - offset) ||
            (offset < 0 && base < std::numeric_limits<int64_t>::min() - offset))
            return std::nullopt;
        const int64_t result = base + offset;
        return result >= 0 ? std::optional<int64_t>(result) : std::nullopt;
    }

    std::optional<int64_t> instructionRegisterIndex(const json& index, const json& instruction,
        uint64_t prototype, size_t pc) const
    {
        if (const std::optional<int64_t> concrete = integerValue(index); concrete && *concrete >= 0)
            return concrete;
        const std::optional<std::pair<std::string, int64_t>> affine = affineLaneOffset(index);
        if (!affine)
            return std::nullopt;
        const std::optional<int64_t> base = instructionLaneValue(instruction, prototype, pc, affine->first);
        return base ? shiftedRegister(*base, affine->second) : std::nullopt;
    }

    std::optional<ResolvedCallFrame> resolveObservedCallFrame(uint64_t prototype, size_t pc,
        const json& instruction, const ObservedCallFrameEvidence& evidence) const
    {
        if (!evidence.argument_count_complete || !evidence.argument_count)
            return std::nullopt;
        std::vector<const json*> calls;
        if (const json* semantic = semanticOperationForInstruction(instruction))
            collectCallExpressions(*semantic, calls);
        if (calls.size() == 1)
        {
            const json& call = *calls.front();
            if (call.value("method", false) || !call.contains("function") || !call["function"].is_object() ||
                call["function"].value("kind", "") != "register_read" ||
                !call.contains("arguments") || !call["arguments"].is_array() ||
                call["arguments"].size() != *evidence.argument_count)
                return std::nullopt;
            ResolvedCallFrame frame;
            frame.source = "semantic_operation";
            frame.caller_opcode = evidence.caller_opcode;
            frame.function_register = instructionRegisterIndex(
                call["function"].value("index", json::object()), instruction, prototype, pc);
            if (!frame.function_register)
                return std::nullopt;
            for (const json& argument : call["arguments"])
            {
                if (!argument.is_object() || argument.value("kind", "") != "register_read")
                    return std::nullopt;
                const std::optional<int64_t> argumentRegister = instructionRegisterIndex(
                    argument.value("index", json::object()), instruction, prototype, pc);
                if (!argumentRegister)
                    return std::nullopt;
                frame.argument_registers.push_back(*argumentRegister);
            }
            return frame;
        }
        if (!calls.empty())
            return std::nullopt;

        const std::optional<HandlerCallFrame> handler =
            handlerCallFrame(evidence.caller_handler, evidence.caller_opcode);
        if (!handler || handler->argument_offsets.size() != *evidence.argument_count)
            return std::nullopt;
        const std::optional<int64_t> base =
            instructionLaneValue(instruction, prototype, pc, handler->base_lane);
        if (!base)
            return std::nullopt;
        ResolvedCallFrame frame;
        frame.source = "observed_caller_handler";
        frame.base_lane = handler->base_lane;
        frame.base_register = base;
        frame.caller_opcode = evidence.caller_opcode;
        frame.function_register = shiftedRegister(*base, handler->function_offset);
        if (!frame.function_register)
            return std::nullopt;
        for (int64_t offset : handler->argument_offsets)
        {
            const std::optional<int64_t> argumentRegister = shiftedRegister(*base, offset);
            if (!argumentRegister)
                return std::nullopt;
            frame.argument_registers.push_back(*argumentRegister);
        }
        return frame;
    }

    static bool containsOperationKind(const json& value, std::string_view expectedKind)
    {
        if (value.is_array())
        {
            for (const json& item : value)
                if (containsOperationKind(item, expectedKind))
                    return true;
            return false;
        }
        if (!value.is_object())
            return false;
        if (value.value("kind", "") == expectedKind)
            return true;
        for (const auto& [name, child] : value.items())
        {
            (void)name;
            if (containsOperationKind(child, expectedKind))
                return true;
        }
        return false;
    }

    static bool isPathSpecificOperation(const json& value)
    {
        return value.is_object() && value.value("path_specific", false) &&
            !value.value("static_semantic", true) && !value.value("proof", "").empty();
    }

    static const json* semanticOperationForInstruction(const json& instruction)
    {
        if (instruction.contains("semantic_operation") && instruction["semantic_operation"].is_object())
            return &instruction["semantic_operation"];
        if (instruction.contains("observational_semantic_operation") &&
            isPathSpecificOperation(instruction["observational_semantic_operation"]))
            return &instruction["observational_semantic_operation"];
        return nullptr;
    }

    static std::string provenanceCommentLabel(const json& value)
    {
        std::string label = value.value("proof", "unspecified");
        if (label.size() > 96)
            label.resize(96);
        for (char& ch : label)
            if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_' && ch != '-' && ch != '.')
                ch = '_';
        return label.empty() ? "unspecified" : label;
    }

    void recordPathSpecificOperation(const json& value, const Context& context)
    {
        ++result.path_specific_operations;
        if (containsOperationKind(value, "register_write"))
            ++result.path_specific_register_writes;
        if (containsOperationKind(value, "table_write"))
            ++result.path_specific_table_writes;
        if (containsOperationKind(value, "jump") || containsOperationKind(value, "branch"))
            ++result.path_specific_control_flow;
        if (containsOperationKind(value, "call"))
            ++result.path_specific_calls;
        if (containsOperationKind(value, "return"))
            ++result.path_specific_returns;
        if (containsOperationKind(value, "closure"))
            ++result.path_specific_closures;
        if (containsOperationKind(value, "load_arguments") || containsOperationKind(value, "capture_varargs"))
            ++result.path_specific_argument_loads;

        result.path_specific_operation_provenance.push_back({
            {"prototype", context.prototype},
            {"pc", context.pc},
            {"kind", value.value("kind", "unknown")},
            {"semantic_family", value.value("semantic_family", value.value("kind", "unknown"))},
            {"proof", value.value("proof", "")},
            {"observation_count", value.value("observation_count", size_t(0))},
            {"source_claim", false},
            {"operation", value},
        });
    }

    void recordUnknownOperation(const json& value, std::string_view reason, const Context& context)
    {
        result.unknown_operations.push_back({
            {"prototype", context.prototype},
            {"pc", context.pc},
            {"kind", value.value("kind", "unknown")},
            {"path_specific", context.path_specific},
            {"proof", value.value("proof", "")},
            {"reason", reason},
            {"source_claim", false},
            {"operation", value},
        });
    }

    void emitPathSpecificProvenanceComment(const json& value, size_t depth)
    {
        const std::string kind = identifier(value.value("kind", "unknown"));
        append(indentation(depth) + "-- Path-specific " + kind + "; provenance: " +
            provenanceCommentLabel(value) + "; not original source.\n");
    }

    static bool hasCallableRuntimeResolution(const json& value)
    {
        if (value.is_array())
        {
            for (const json& item : value)
                if (hasCallableRuntimeResolution(item))
                    return true;
            return false;
        }
        if (!value.is_object())
            return false;
        if (value.contains("runtime_resolution") && value["runtime_resolution"].is_object())
        {
            const json& resolution = value["runtime_resolution"];
            const json resolved = resolution.value("value", json::object());
            if (resolution.value("non_speculative", false) && resolved.is_object() &&
                resolved.value("type", "") == "function" && resolved.value("callable", false))
                return true;
        }
        for (const auto& [name, child] : value.items())
        {
            (void)name;
            if (hasCallableRuntimeResolution(child))
                return true;
        }
        return false;
    }

    const Block* blockContaining(uint64_t prototype, size_t pc) const
    {
        const auto cfg = cfgs.find(prototype);
        if (cfg == cfgs.end())
            return nullptr;
        for (const Block& block : cfg->second.blocks)
            if (pc >= block.start && pc <= block.end)
                return &block;
        return nullptr;
    }

    std::vector<const Block*> predecessorBlocks(uint64_t prototype, size_t blockStart) const
    {
        std::vector<const Block*> predecessors;
        const auto cfg = cfgs.find(prototype);
        if (cfg == cfgs.end())
            return predecessors;
        for (const Block& block : cfg->second.blocks)
            if (std::find(block.successors.begin(), block.successors.end(), blockStart) != block.successors.end())
                predecessors.push_back(&block);
        return predecessors;
    }

    std::optional<RegisterCaptureSlice> resolveRegisterCaptureKey(uint64_t prototype, const Block& block, size_t beforePc,
        int64_t registerIndex, std::set<std::tuple<uint64_t, size_t, size_t, int64_t>>& visited,
        bool directCaptureReadOnly = false, size_t depth = 0) const
    {
        if (depth > 128 || !visited.insert({prototype, block.start, beforePc, registerIndex}).second)
            return std::nullopt;
        const auto prototypeRows = instructions.find(prototype);
        if (prototypeRows == instructions.end())
            return std::nullopt;

        auto row = prototypeRows->second.lower_bound(beforePc);
        while (row != prototypeRows->second.begin())
        {
            --row;
            if (row->first < block.start)
                break;
            if (row->first > block.end)
                continue;
            for (auto instruction = row->second.rbegin(); instruction != row->second.rend(); ++instruction)
            {
                if (instruction->contains("closure_descriptor") && (*instruction)["closure_descriptor"].is_object() &&
                    (*instruction)["closure_descriptor"].value("destination_register", int64_t(-1)) == registerIndex)
                    return std::nullopt;
                const json* semantic = semanticOperationForInstruction(*instruction);
                if (!semantic)
                    continue;
                const std::optional<json> written = registerWriteValue(*semantic, registerIndex);
                if (!written)
                    continue;

                if (written->is_object() && written->value("kind", "") == "register_read")
                {
                    const std::optional<int64_t> source = integerValue(written->value("index", json::object()));
                    if (!source || *source < 0)
                        return std::nullopt;
                    return resolveRegisterCaptureKey(
                        prototype, block, row->first, *source, visited, directCaptureReadOnly, depth + 1);
                }
                if (directCaptureReadOnly)
                {
                    const std::optional<int64_t> captureKey = captureCellValueKey(*written);
                    return captureKey
                        ? std::optional<RegisterCaptureSlice>(RegisterCaptureSlice{*captureKey, {row->first}})
                        : std::nullopt;
                }
                std::set<int64_t> captureKeys;
                collectCaptureKeys(*written, captureKeys);
                if (captureKeys.size() == 1)
                    return RegisterCaptureSlice{*captureKeys.begin(), {row->first}};
                return std::nullopt;
            }
        }

        const std::vector<const Block*> predecessors = predecessorBlocks(prototype, block.start);
        if (predecessors.empty())
            return std::nullopt;
        std::optional<RegisterCaptureSlice> resolved;
        for (const Block* predecessor : predecessors)
        {
            auto branchVisited = visited;
            const std::optional<RegisterCaptureSlice> candidate = resolveRegisterCaptureKey(
                prototype, *predecessor, predecessor->end + 1, registerIndex, branchVisited,
                directCaptureReadOnly, depth + 1);
            if (!candidate || (resolved && resolved->encoded_key != candidate->encoded_key))
                return std::nullopt;
            if (!resolved)
                resolved = candidate;
            else
                resolved->producer_pcs.insert(candidate->producer_pcs.begin(), candidate->producer_pcs.end());
        }
        return resolved;
    }

    static std::optional<RegisterIdentitySlice> observedRegisterIdentity(
        const RegisterWriteInfo& write, size_t pc)
    {
        const json& resolution = write.runtime_resolution;
        if (!resolution.is_object() || !resolution.value("non_speculative", false) ||
            resolution.value("scope", "") != "executed-payload-site" ||
            !resolution.contains("observation_count") ||
            (!resolution["observation_count"].is_number_integer() &&
                !resolution["observation_count"].is_number_unsigned()) ||
            !resolution.contains("value"))
            return std::nullopt;
        const int64_t signedObservations = resolution["observation_count"].is_number_unsigned()
            ? (resolution["observation_count"].get<uint64_t>() <=
                    static_cast<uint64_t>(std::numeric_limits<int64_t>::max())
                    ? static_cast<int64_t>(resolution["observation_count"].get<uint64_t>())
                    : int64_t(-1))
            : resolution["observation_count"].get<int64_t>();
        const std::optional<ObservedValueIdentity> identity = observedValueIdentity(resolution["value"]);
        if (signedObservations <= 0 || !identity || !identity->callable)
            return std::nullopt;
        return RegisterIdentitySlice{
            *identity,
            static_cast<size_t>(signedObservations),
            {pc},
        };
    }

    std::optional<RegisterIdentitySlice> resolveRegisterIdentity(uint64_t prototype, const Block& block,
        size_t beforePc, int64_t registerIndex,
        std::set<std::tuple<uint64_t, size_t, size_t, int64_t>>& visited, size_t depth = 0) const
    {
        if (depth > 128 || !visited.insert({prototype, block.start, beforePc, registerIndex}).second)
            return std::nullopt;
        const auto prototypeRows = instructions.find(prototype);
        if (prototypeRows == instructions.end())
            return std::nullopt;

        auto row = prototypeRows->second.lower_bound(beforePc);
        while (row != prototypeRows->second.begin())
        {
            --row;
            if (row->first < block.start)
                break;
            if (row->first > block.end)
                continue;
            for (auto instruction = row->second.rbegin(); instruction != row->second.rend(); ++instruction)
            {
                if (instruction->contains("closure_descriptor") && (*instruction)["closure_descriptor"].is_object() &&
                    (*instruction)["closure_descriptor"].value("destination_register", int64_t(-1)) == registerIndex)
                    return std::nullopt;
                const json* semantic = semanticOperationForInstruction(*instruction);
                if (!semantic)
                    continue;
                const std::optional<RegisterWriteInfo> write =
                    lastRegisterWrite(*semantic, registerIndex);
                if (!write)
                    continue;
                if (const std::optional<RegisterIdentitySlice> identity = observedRegisterIdentity(*write, row->first))
                    return identity;
                if (!write->runtime_resolution.is_null())
                    return std::nullopt;
                if (!write->value.is_object() || write->value.value("kind", "") != "register_read")
                    return std::nullopt;
                const std::optional<int64_t> source = integerValue(write->value.value("index", json::object()));
                if (!source || *source < 0)
                    return std::nullopt;
                return resolveRegisterIdentity(prototype, block, row->first, *source, visited, depth + 1);
            }
        }

        const std::vector<const Block*> predecessors = predecessorBlocks(prototype, block.start);
        if (predecessors.empty())
            return std::nullopt;
        std::optional<RegisterIdentitySlice> resolved;
        for (const Block* predecessor : predecessors)
        {
            auto branchVisited = visited;
            const std::optional<RegisterIdentitySlice> candidate = resolveRegisterIdentity(
                prototype, *predecessor, predecessor->end + 1, registerIndex, branchVisited, depth + 1);
            if (!candidate || (resolved && resolved->identity.key != candidate->identity.key))
                return std::nullopt;
            if (!resolved)
                resolved = candidate;
            else
            {
                if (candidate->observations > std::numeric_limits<size_t>::max() - resolved->observations)
                    return std::nullopt;
                resolved->observations += candidate->observations;
                resolved->producer_pcs.insert(candidate->producer_pcs.begin(), candidate->producer_pcs.end());
            }
        }
        return resolved;
    }

    bool completeCaptureIdentityDomain(uint64_t prototype) const
    {
        const auto domain = captureDomains.find(prototype);
        const auto values = captureValueIdentities.find(prototype);
        if (domain == captureDomains.end() || !domain->second.seen || !domain->second.complete ||
            values == captureValueIdentities.end())
            return false;
        for (int64_t captureIndex : domain->second.indices)
        {
            const auto identity = values->second.find(captureIndex);
            if (identity == values->second.end() || identity->second.size() != 1)
                return false;
        }
        return true;
    }

    std::optional<int64_t> provenCaptureIndex(uint64_t prototype, int64_t encodedKey) const
    {
        if (validCaptureKey(prototype, encodedKey))
            return encodedKey;
        const auto prototypeEvidence = captureKeyEvidence.find(prototype);
        if (prototypeEvidence == captureKeyEvidence.end())
            return std::nullopt;
        const auto evidence = prototypeEvidence->second.find(encodedKey);
        if (evidence == prototypeEvidence->second.end() || evidence->second.size() != 1 ||
            !validCaptureKey(prototype, *evidence->second.begin()))
            return std::nullopt;
        return *evidence->second.begin();
    }

    bool propagateInheritedCaptureValues()
    {
        bool changed = true;
        bool anyChanged = false;
        size_t rounds = 0;
        while (changed && rounds++ <= inheritedCaptureCells.size())
        {
            changed = false;
            for (const auto& [parent, child, childIndex, parentKey] : inheritedCaptureCells)
            {
                if (!validCaptureKey(child, childIndex))
                    continue;
                const std::optional<int64_t> parentIndex = provenCaptureIndex(parent, parentKey);
                if (!parentIndex)
                    continue;
                const auto parentValues = captureValueIdentities.find(parent);
                if (parentValues == captureValueIdentities.end())
                    continue;
                const auto source = parentValues->second.find(*parentIndex);
                if (source == parentValues->second.end() || source->second.size() != 1)
                    continue;
                auto& destination = captureValueIdentities[child][childIndex];
                const auto& [identity, value] = *source->second.begin();
                if (!destination.contains(identity))
                {
                    destination[identity] = value;
                    changed = true;
                    anyChanged = true;
                }
            }
        }
        return anyChanged;
    }

    bool addCallArgumentIdentityEvidence()
    {
        bool changed = false;
        for (const auto& [site, targets] : observedCallEdges)
        {
            if (targets.size() != 1)
                continue;
            const auto& [callee, observedCalls] = *targets.begin();
            const std::optional<json> instruction = instructionAt(site.first, site.second);
            const Block* block = blockContaining(site.first, site.second);
            if (!instruction || !block || !semanticOperationForInstruction(*instruction) ||
                !completeCaptureIdentityDomain(site.first))
                continue;
            const auto frameEvidence = observedCallFrames.find({site.first, site.second, callee});
            if (frameEvidence == observedCallFrames.end())
                continue;
            const std::optional<ResolvedCallFrame> callFrame = resolveObservedCallFrame(
                site.first, site.second, *instruction, frameEvidence->second);
            if (!callFrame || callFrame->argument_registers.size() != *frameEvidence->second.argument_count)
                continue;

            for (size_t argumentIndex = 0; argumentIndex < callFrame->argument_registers.size(); ++argumentIndex)
            {
                const int64_t argumentRegister = callFrame->argument_registers[argumentIndex];

                std::set<std::tuple<uint64_t, size_t, size_t, int64_t>> captureVisited;
                const std::optional<RegisterCaptureSlice> capture = resolveRegisterCaptureKey(
                    site.first, *block, site.second, argumentRegister, captureVisited, true);
                if (!capture)
                    continue;

                std::optional<ObservedValueIdentity> argumentIdentity;
                size_t identityObservations = 0;
                std::set<size_t> identityProducerPcs;
                const auto observedIdentity = frameEvidence->second.argument_identities.find(argumentIndex + 1);
                if (observedIdentity != frameEvidence->second.argument_identities.end())
                {
                    argumentIdentity = observedIdentity->second.identity;
                    identityObservations = observedIdentity->second.observations;
                }
                else
                {
                    std::set<std::tuple<uint64_t, size_t, size_t, int64_t>> identityVisited;
                    const std::optional<RegisterIdentitySlice> identity = resolveRegisterIdentity(
                        site.first, *block, site.second, argumentRegister, identityVisited);
                    if (identity)
                    {
                        argumentIdentity = identity->identity;
                        identityObservations = identity->observations;
                        identityProducerPcs = identity->producer_pcs;
                    }
                }
                if (!argumentIdentity || !argumentIdentity->callable || identityObservations != observedCalls)
                    continue;

                std::set<int64_t> matchingCaptures;
                const CaptureDomain& domain = captureDomains.at(site.first);
                for (int64_t captureIndex : domain.indices)
                {
                    const auto& identities = captureValueIdentities.at(site.first).at(captureIndex);
                    if (identities.size() == 1 && identities.contains(argumentIdentity->key))
                        matchingCaptures.insert(captureIndex);
                }
                if (matchingCaptures.size() != 1)
                    continue;
                const int64_t resolvedCapture = *matchingCaptures.begin();
                changed = captureKeyEvidence[site.first][capture->encoded_key].insert(resolvedCapture).second || changed;

                json captureProducerPcs = json::array();
                for (size_t pc : capture->producer_pcs)
                    captureProducerPcs.push_back(pc);
                json identityProducerPcRows = json::array();
                for (size_t pc : identityProducerPcs)
                    identityProducerPcRows.push_back(pc);
                json detail = {
                    {"caller_prototype", site.first},
                    {"caller_pc", site.second},
                    {"callee_prototype", callee},
                    {"argument_index", argumentIndex + 1},
                    {"argument_register", argumentRegister},
                    {"encoded_key", capture->encoded_key},
                    {"capture_index", resolvedCapture},
                    {"observed_calls", observedCalls},
                    {"observed_argument_count", *frameEvidence->second.argument_count},
                    {"identity_observations", identityObservations},
                    {"identity", argumentIdentity->value},
                    {"call_frame_source", callFrame->source},
                    {"caller_opcode", callFrame->caller_opcode},
                    {"function_register", callFrame->function_register ?
                        json(*callFrame->function_register) : json(nullptr)},
                    {"base_lane", callFrame->base_lane.empty() ? json(nullptr) : json(callFrame->base_lane)},
                    {"base_register", callFrame->base_register ? json(*callFrame->base_register) : json(nullptr)},
                    {"capture_producer_pcs", std::move(captureProducerPcs)},
                    {"identity_producer_pcs", std::move(identityProducerPcRows)},
                    {"capture_domain_complete", true},
                };
                json& evidence = callArgumentIdentityEvidence[
                    {site.first, capture->encoded_key, resolvedCapture}];
                if (!evidence.is_array())
                    evidence = json::array();
                if (std::find(evidence.begin(), evidence.end(), detail) == evidence.end())
                {
                    evidence.push_back(std::move(detail));
                    changed = true;
                }
            }
        }
        return changed;
    }

    void addCallDerivedCaptureEvidence()
    {
        for (const auto& [site, callee] : callEdges)
        {
            const auto instruction = instructionAt(site.first, site.second);
            const Block* block = blockContaining(site.first, site.second);
            const json* semantic = instruction ? semanticOperationForInstruction(*instruction) : nullptr;
            if (!instruction || !block || !semantic)
                continue;
            std::set<int64_t> functionRegisters;
            collectCallFunctionRegisters(*semantic, functionRegisters);
            if (functionRegisters.size() != 1)
                continue;
            std::set<std::tuple<uint64_t, size_t, size_t, int64_t>> visited;
            const std::optional<RegisterCaptureSlice> encodedKey = resolveRegisterCaptureKey(
                site.first, *block, site.second, *functionRegisters.begin(), visited);
            if (!encodedKey)
                continue;

            std::set<int64_t> matchingCaptures;
            const auto captureTargets = captureClosureTargets.find(site.first);
            if (captureTargets == captureClosureTargets.end())
                continue;
            for (const auto& [captureIndex, targets] : captureTargets->second)
                if (targets.size() == 1 && targets.contains(callee))
                    matchingCaptures.insert(captureIndex);
            if (matchingCaptures.size() == 1)
                captureKeyEvidence[site.first][encodedKey->encoded_key].insert(*matchingCaptures.begin());
        }
    }

    void addUniqueCallableCaptureEvidence()
    {
        std::map<uint64_t, std::set<int64_t>> callableCaptureKeys;
        for (const auto& [prototype, rows] : instructions)
            for (const auto& [pc, instructionRows] : rows)
            {
                (void)pc;
                for (const json& instruction : instructionRows)
                {
                    const json* semantic = semanticOperationForInstruction(instruction);
                    if (!semantic || !hasCallableRuntimeResolution(*semantic))
                        continue;
                    collectCaptureKeys(*semantic, callableCaptureKeys[prototype]);
                }
            }

        for (const auto& [prototype, encodedKeys] : callableCaptureKeys)
        {
            if (encodedKeys.size() != 1)
                continue;
            std::set<uint64_t> reachableCallTargets;
            for (const auto& [site, callee] : callEdges)
            {
                if (site.first != prototype)
                    continue;
                const std::optional<json> instruction = instructionAt(site.first, site.second);
                const json* semantic = instruction ? semanticOperationForInstruction(*instruction) : nullptr;
                if (semantic && containsOperationKind(*semantic, "call"))
                    reachableCallTargets.insert(callee);
            }
            if (reachableCallTargets.size() != 1)
                continue;

            const auto captureTargets = captureClosureTargets.find(prototype);
            if (captureTargets == captureClosureTargets.end())
                continue;
            std::set<int64_t> matchingCaptures;
            for (const auto& [captureIndex, targets] : captureTargets->second)
                if (targets.size() == 1 && targets.contains(*reachableCallTargets.begin()))
                    matchingCaptures.insert(captureIndex);
            if (matchingCaptures.size() == 1)
                captureKeyEvidence[prototype][*encodedKeys.begin()].insert(*matchingCaptures.begin());
        }
    }

    void parseCaptureProvenance()
    {
        parseObservedCaptureDomains();
        for (const json& descriptor : reachableIr.value("closure_descriptors", json::array()))
            if (descriptor.is_object())
            {
                addCaptureDomain(positiveUnsignedField(descriptor, "target_prototype"), descriptor);
                recordInheritedCaptureCells(positiveUnsignedField(descriptor, "prototype"), descriptor);
            }
        const json payloadRoot = reachableIr.value("payload_root", json::object());
        if (payloadRoot.contains("closure_descriptor") && payloadRoot["closure_descriptor"].is_object())
        {
            addCaptureDomain(positiveUnsignedField(payloadRoot, "payload_prototype"), payloadRoot["closure_descriptor"]);
            recordInheritedCaptureCells(
                positiveUnsignedField(payloadRoot, "bootstrap_prototype"), payloadRoot["closure_descriptor"]);
        }

        for (const auto& [prototype, rows] : instructions)
        {
            for (const auto& [pc, instructionRows] : rows)
            {
                (void)pc;
                for (const json& instruction : instructionRows)
                {
                    if (instruction.contains("closure_descriptor") && instruction["closure_descriptor"].is_object())
                    {
                        const json& descriptor = instruction["closure_descriptor"];
                        const uint64_t target = positiveUnsignedField(descriptor, "target_prototype");
                        addCaptureDomain(target, descriptor);
                        recordInheritedCaptureCells(prototype, descriptor);
                        const int64_t destination = descriptor.value("destination_register", int64_t(-1));
                        if (target != 0 && destination >= 0)
                            closureRegisterTargets[prototype][destination].insert(target);
                        if (const json* semantic = semanticOperationForInstruction(instruction); target != 0 && semantic)
                        {
                            std::set<int64_t> semanticDestinations;
                            collectRegisterWriteDestinations(*semantic, semanticDestinations);
                            if (semanticDestinations.size() == 1)
                                closureRegisterTargets[prototype][*semanticDestinations.begin()].insert(target);
                        }
                    }

                }
            }
        }

        for (const auto& [prototype, rows] : instructions)
        {
            for (const auto& [pc, instructionRows] : rows)
            {
                (void)pc;
                for (const json& instruction : instructionRows)
                {
                    if (!instruction.contains("closure_descriptor") || !instruction["closure_descriptor"].is_object())
                        continue;
                    const json& descriptor = instruction["closure_descriptor"];
                    const uint64_t target = positiveUnsignedField(descriptor, "target_prototype");
                    if (target == 0 || !descriptor.value("complete", false) ||
                        !descriptor.contains("captures") || !descriptor["captures"].is_array())
                        continue;
                    for (const json& capture : descriptor["captures"])
                    {
                        const int64_t captureIndex = capture.value("capture_index", int64_t(-1));
                        const int64_t kind = capture.value("capture_kind", int64_t(-1));
                        const int64_t slot = capture.value("slot", int64_t(-1));
                        if (captureIndex < 0 || slot < 0 || (kind != 0 && kind != 1))
                            continue;
                        const auto producer = closureRegisterTargets[prototype].find(slot);
                        if (producer != closureRegisterTargets[prototype].end() && producer->second.size() == 1)
                            captureClosureTargets[target][captureIndex].insert(*producer->second.begin());
                    }
                }
            }
        }

        for (const auto& [prototype, rows] : instructions)
        {
            for (const auto& [pc, instructionRows] : rows)
            {
                (void)pc;
                for (const json& instruction : instructionRows)
                {

                    const json* semantic = semanticOperationForInstruction(instruction);
                    if (!semantic)
                        continue;
                    std::set<std::string> lanes;
                    collectUpvalueIndexLanes(*semantic, lanes);
                    const json runtimeOverrides = instruction.value("runtime_lane_overrides", json::object());
                    const json staticLanes = instruction.value("static_lanes", json::object());
                    const json currentLanes = instruction.value("lanes", json::object());
                    for (const std::string& lane : lanes)
                    {
                        if (!runtimeOverrides.contains(lane))
                            continue;
                        const json& encodedValue = staticLanes.contains(lane) ? staticLanes[lane] :
                            currentLanes.contains(lane) ? currentLanes[lane] : json(nullptr);
                        const std::optional<int64_t> encoded = primitiveIntegerValue(encodedValue);
                        const std::optional<int64_t> resolved = primitiveIntegerValue(runtimeOverrides[lane]);
                        if (encoded && resolved && *encoded >= 0 && *resolved >= 0)
                            captureKeyEvidence[prototype][*encoded].insert(*resolved);
                    }
                }
            }
        }
        addCallDerivedCaptureEvidence();
        addUniqueCallableCaptureEvidence();
        const size_t maximumRounds = observedCallEdges.size() + inheritedCaptureCells.size() + 2;
        for (size_t round = 0; round < maximumRounds; ++round)
        {
            bool changed = propagateInheritedCaptureValues();
            changed = addCallArgumentIdentityEvidence() || changed;
            if (!changed)
                break;
        }
    }

    bool validCaptureKey(uint64_t prototype, int64_t key) const
    {
        const auto found = captureDomains.find(prototype);
        return found != captureDomains.end() && found->second.seen && found->second.complete &&
            found->second.indices.contains(key);
    }

    std::optional<int64_t> remapCaptureKey(uint64_t prototype, size_t pc, int64_t encodedKey,
        std::optional<int64_t> runtimeKey = std::nullopt)
    {
        const auto domain = captureDomains.find(prototype);
        if (domain == captureDomains.end() || !domain->second.seen || !domain->second.complete)
        {
            if (unresolvedCaptureSites.insert({prototype, pc, encodedKey}).second)
                ++result.unresolved_capture_keys;
            return std::nullopt;
        }

        std::optional<int64_t> resolved = runtimeKey;
        if (!resolved)
        {
            const auto prototypeEvidence = captureKeyEvidence.find(prototype);
            if (prototypeEvidence != captureKeyEvidence.end())
            {
                const auto evidence = prototypeEvidence->second.find(encodedKey);
                if (evidence != prototypeEvidence->second.end() && evidence->second.size() == 1)
                    resolved = *evidence->second.begin();
            }
        }
        if (!resolved && validCaptureKey(prototype, encodedKey))
            resolved = encodedKey;
        if (!resolved && domain->second.indices.size() == 1)
            resolved = *domain->second.indices.begin();

        if (!resolved || !validCaptureKey(prototype, *resolved))
        {
            if (unresolvedCaptureSites.insert({prototype, pc, encodedKey}).second)
                ++result.unresolved_capture_keys;
            return std::nullopt;
        }
        if (*resolved != encodedKey && remappedCaptureSites.insert({prototype, pc, encodedKey}).second)
        {
            ++result.capture_key_remaps;
            json resolution = {
                {"prototype", prototype},
                {"pc", pc},
                {"encoded", encodedKey},
                {"resolved", *resolved},
                {"complete", true},
                {"evidence", runtimeKey ? "runtime_override" : "capture_provenance"},
            };
            if (!runtimeKey)
            {
                const auto callEvidence = callArgumentIdentityEvidence.find({prototype, encodedKey, *resolved});
                if (callEvidence != callArgumentIdentityEvidence.end() && callEvidence->second.is_array() &&
                    !callEvidence->second.empty())
                {
                    resolution["evidence"] = "call_argument_identity";
                    resolution["evidence_details"] = {
                        {"kind", "call_argument_identity"},
                        {"observations", callEvidence->second},
                    };
                }
            }
            result.capture_key_resolutions.push_back(std::move(resolution));
        }
        return resolved;
    }

    std::string captureCellForKey(int64_t encodedKey, Context& context,
        std::optional<int64_t> runtimeKey = std::nullopt)
    {
        const std::optional<int64_t> resolved = remapCaptureKey(context.prototype, context.pc, encodedKey, runtimeKey);
        if (resolved)
            return "captured_values[" + std::to_string(*resolved) + "]";
        return "unresolved_capture_cell(" + std::to_string(context.prototype) + ", " +
            std::to_string(context.pc) + ", " + std::to_string(encodedKey) + ")";
    }

    std::string captureCellExpression(const json& index, Context& context, size_t depth)
    {
        const std::optional<int64_t> currentKey = integerValue(index);
        if (!currentKey)
        {
            if (unresolvedCaptureSites.insert({context.prototype, context.pc, int64_t(-1)}).second)
                ++result.unresolved_capture_keys;
            return "unresolved_capture_cell(" + std::to_string(context.prototype) + ", " +
                std::to_string(context.pc) + ", " + expression(index, context, depth + 1) + ")";
        }

        int64_t encodedKey = *currentKey;
        std::optional<int64_t> runtimeKey;
        const std::string lane = index.value("lane", "");
        if (const auto stable = context.stable_lane_literals.find(lane);
            !lane.empty() && stable != context.stable_lane_literals.end())
            return "captured_values[" + stable->second + "]";
        if (!lane.empty() && !context.runtime_lanes_variable.empty() &&
            context.runtime_lane_names.contains(lane))
            return "captured_values[" + context.runtime_lanes_variable + "[" + quoteLuau(lane) + "]]";
        if (context.instruction && !lane.empty())
        {
            const json staticLanes = context.instruction->value("static_lanes", json::object());
            if (staticLanes.contains(lane))
                if (const std::optional<int64_t> value = primitiveIntegerValue(staticLanes[lane]); value && *value >= 0)
                    encodedKey = *value;
            const json runtimeOverrides = context.instruction->value("runtime_lane_overrides", json::object());
            if (runtimeOverrides.contains(lane))
                if (const std::optional<int64_t> value = primitiveIntegerValue(runtimeOverrides[lane]); value && *value >= 0)
                    runtimeKey = *value;
        }
        return captureCellForKey(encodedKey, context, runtimeKey);
    }

    std::vector<uint64_t> orderedPrototypeIds() const
    {
        std::vector<uint64_t> ids;
        ids.reserve(instructions.size());
        for (const auto& [id, rows] : instructions)
            ids.push_back(id);
        return ids;
    }

    bool hasCallArgumentIdentityResolution(uint64_t prototype, const json& value) const
    {
        std::set<int64_t> encodedKeys;
        collectCaptureKeys(value, encodedKeys);
        if (encodedKeys.size() != 1)
            return false;
        const auto prototypeEvidence = captureKeyEvidence.find(prototype);
        if (prototypeEvidence == captureKeyEvidence.end())
            return false;
        const auto evidence = prototypeEvidence->second.find(*encodedKeys.begin());
        if (evidence == prototypeEvidence->second.end() || evidence->second.size() != 1)
            return false;
        return callArgumentIdentityEvidence.contains(
            {prototype, *encodedKeys.begin(), *evidence->second.begin()});
    }

    std::optional<std::string> observedLiteral(const json& operation)
    {
        if (!operation.contains("runtime_resolution") || !operation["runtime_resolution"].is_object())
            return std::nullopt;
        const json& resolution = operation["runtime_resolution"];
        if (!resolution.value("non_speculative", false) || !resolution.contains("value") || !resolution["value"].is_object())
            return std::nullopt;
        const json& value = resolution["value"];
        const std::string type = jsonStringOr(value, "type");
        if (type == "function")
        {
            const std::string name = jsonStringOr(value, "name");
            if (name.empty())
                return std::nullopt;
            ++result.runtime_specializations;
            return "resolve_named_function(" + quoteLuau(name) + ")";
        }
        if (type == "string" || type == "number" || type == "boolean" || type == "nil")
        {
            ++result.runtime_specializations;
            return primitiveLiteral(value);
        }
        return std::nullopt;
    }

    std::string unsupportedExpression(const Context& context, std::string_view kind, std::string_view reason)
    {
        ++result.unsupported_expressions;
        return "unsupported_semantic_operation(" + std::to_string(context.prototype) + ", " +
            std::to_string(context.pc) + ", " + quoteLuau(kind) + ", " + quoteLuau(reason) + ")";
    }

    std::string expression(const json& value, Context& context, size_t depth = 0)
    {
        if (depth > 64 || !value.is_object())
            return unsupportedExpression(context, "expression", depth > 64
                ? "expression nesting limit exceeded" : "expression object is missing");
        const std::string kind = jsonStringOr(value, "kind");
        if (kind == "immediate")
        {
            const std::string lane = jsonStringOr(value, "lane");
            if (const auto stable = context.stable_lane_literals.find(lane);
                !lane.empty() && stable != context.stable_lane_literals.end())
                return stable->second;
            if (!lane.empty() && !context.runtime_lanes_variable.empty() &&
                context.runtime_lane_names.contains(lane))
                return context.runtime_lanes_variable + "[" + quoteLuau(lane) + "]";
            const json primitive = value.value("value", json(nullptr));
            return supportedPrimitive(primitive) ? primitiveLiteral(primitive) :
                unsupportedExpression(context, "immediate", "immediate value is not a supported primitive");
        }
        if (kind == "operand")
        {
            const std::string lane = jsonStringOr(value, "lane");
            std::string source;
            if (const auto stable = context.stable_lane_literals.find(lane);
                !lane.empty() && stable != context.stable_lane_literals.end())
                source = stable->second;
            else if (!lane.empty() && !context.runtime_lanes_variable.empty() &&
                context.runtime_lane_names.contains(lane))
                source = context.runtime_lanes_variable + "[" + quoteLuau(lane) + "]";
            else if (context.instruction && context.instruction->contains("lanes") &&
                (*context.instruction)["lanes"].is_object() && (*context.instruction)["lanes"].contains(lane))
                source = primitiveLiteral((*context.instruction)["lanes"][lane]);
            if (source.empty())
            {
                return unsupportedExpression(context, "operand", "missing runtime lane " +
                    identifier(lane.empty() ? "unknown" : lane));
            }
            const int64_t adjustment = value.value("adjustment", int64_t(0));
            if (adjustment != 0)
                source = "(" + source + " + (" + std::to_string(adjustment) + "))";
            return source;
        }
        if (kind == "constant")
        {
            const json primitive = value.value("value", json(nullptr));
            return supportedPrimitive(primitive) ? primitiveLiteral(primitive) :
                unsupportedExpression(context, "constant", "constant value is not a supported primitive");
        }
        if (kind == "global")
        {
            if (value.contains("key") && value["key"].is_object())
                return "environment[" + expression(value["key"], context, depth + 1) + "]";
            return "environment[" + quoteLuau(jsonStringOr(value, "name")) + "]";
        }
        if (kind == "global_read")
            return "environment[" + expression(value.value("key", json::object()), context, depth + 1) + "]";
        if (kind == "environment")
            return "environment";
        if (kind == "current_pc")
            return "pc";
        if (kind == "observed_register_value")
        {
            if (value.contains("value") && value["value"].is_object() && jsonStringOr(value["value"], "type") == "function")
            {
                const std::string name = jsonStringOr(value["value"], "name");
                if (!name.empty())
                    return "resolve_named_function(" + quoteLuau(name) + ")";
            }
            const json primitive = value.value("value", json(nullptr));
            return supportedPrimitive(primitive) ? primitiveLiteral(primitive) :
                unsupportedExpression(context, kind, "observed register value is not a stable primitive");
        }
        if (kind == "register_read")
            return "registers[" + expression(value.value("index", json::object()), context, depth + 1) + "]";
        if (kind == "register_file")
            return "registers";
        if (kind == "upvalue_file")
            return "captured_values";
        if (kind == "top_register")
            return "top";
        if (kind == "varargs")
            return "...";
        if (kind == "semantic_local")
            return identifier(jsonStringOr(value, "name", "local_value"));
        if (kind == "vm_state")
            return "state[" + quoteLuau(jsonStringOr(value, "name", "?")) + "]";
        if (kind == "helper_table")
            return "helper_values";
        if (kind == "opcode_table")
            return "opcode_values";
        if (kind == "opcode_read")
            return "opcode_values[" + expression(value.value("index", json::object()), context, depth + 1) + "]";
        if (kind == "operand_table")
            return "operand_values";
        if (kind == "index_read")
        {
            const json table = value.value("table", json::object());
            const json index = value.value("index", json::object());
            if (table.is_object() && table.value("kind", "") == "upvalue_file")
                return captureCellExpression(index, context, depth + 1);
            if (rootArgumentPrototypes.contains(context.prototype) && table.is_object() &&
                table.value("kind", "") == "register_read")
            {
                const std::optional<int64_t> tableRegister = integerValue(table.value("index", json::object()));
                const std::optional<int64_t> key = integerValue(index);
                if (tableRegister && *tableRegister == 1 && key)
                {
                    if (const auto found = rootArgumentExpressions.find(*key); found != rootArgumentExpressions.end())
                    {
                        ++result.root_argument_references_specialized;
                        return found->second;
                    }
                    else if (rootArgumentTableComplete)
                    {
                        ++result.root_argument_references_specialized;
                        ++result.absent_root_argument_references_specialized;
                        return "nil";
                    }
                }
            }
            return "(" + expression(table, context, depth + 1) + ")[" +
                expression(index, context, depth + 1) + "]";
        }
        if (kind == "binary")
            return "(" + expression(value.value("left", json::object()), context, depth + 1) + " " +
                jsonStringOr(value, "operator", "+") + " " + expression(value.value("right", json::object()), context, depth + 1) + ")";
        if (kind == "unary")
            return "(" + jsonStringOr(value, "operator", "not") + " " +
                expression(value.value("value", json::object()), context, depth + 1) + ")";
        if (kind == "if_expression")
            return "(if " + expression(value.value("condition", json::object()), context, depth + 1) +
                " then " + expression(value.value("then", json::object()), context, depth + 1) +
                " else " + expression(value.value("else", json::object()), context, depth + 1) + ")";
        if (kind == "table")
        {
            std::string source = "{";
            bool first = true;
            for (const json& entry : value.value("entries", json::array()))
            {
                if (!first)
                    source += ", ";
                first = false;
                if (entry.value("entry_kind", "list") != "list")
                    source += "[" + expression(entry.value("key", json::object()), context, depth + 1) + "] = ";
                source += expression(entry.value("value", json::object()), context, depth + 1);
            }
            return source + "}";
        }
        if (kind == "register_range")
            return "unpack_values(registers, " + expression(value.value("from", json::object()), context, depth + 1) + ", " +
                expression(value.value("to", json::object()), context, depth + 1) + ")";
        if (kind == "call")
        {
            std::vector<std::string> arguments;
            for (const json& argument : value.value("arguments", json::array()))
                arguments.push_back(expression(argument, context, depth + 1));
            std::string joined;
            for (size_t index = 0; index < arguments.size(); ++index)
            {
                if (index > 0)
                    joined += ", ";
                joined += arguments[index];
            }
            const json function = value.value("function", json::object());
            if (value.value("method", false))
            {
                if (!function.is_object() || function.value("kind", "") != "index_read" ||
                    !function.contains("table") || !function["table"].is_object() ||
                    !function.contains("index") || !function["index"].is_object())
                {
                    return unsupportedExpression(context, "method_call", "receiver expression is incomplete");
                }
                const std::string receiver = expression(function["table"], context, depth + 1);
                const json& methodIndex = function["index"];
                const std::string receiverName = "recovered_receiver_" + std::to_string(context.prototype) + "_" +
                    std::to_string(context.pc);
                if (!context.callee && methodIndex.value("kind", "") == "constant" &&
                    methodIndex.contains("value") && methodIndex["value"].is_string() &&
                    plainIdentifier(methodIndex["value"].get<std::string>()))
                    return "(" + receiver + "):" + methodIndex["value"].get<std::string>() + "(" + joined + ")";

                const std::string callableName = receiverName + "_method";
                const std::string method = expression(methodIndex, context, depth + 1);
                std::string invocation;
                if (context.callee && !context.callee_consumed)
                {
                    context.callee_consumed = true;
                    ++result.direct_prototype_calls;
                    invocation = "call_recovered(" + callableName + ", " + prototypeName(*context.callee) +
                        ", captured_values, " + receiverName + (joined.empty() ? "" : ", " + joined) + ")";
                }
                else
                    invocation = callableName + "(" + receiverName + (joined.empty() ? "" : ", " + joined) + ")";
                return "(function() local " + receiverName + " = " + receiver + "; local " + callableName +
                    " = " + receiverName + "[" + method + "]; return " + invocation + " end)()";
            }
            if (context.callee && !context.callee_consumed)
            {
                context.callee_consumed = true;
                ++result.direct_prototype_calls;
                const std::string callable = expression(function, context, depth + 1);
                return "call_recovered(" + callable + ", " + prototypeName(*context.callee) + ", captured_values" +
                    (joined.empty() ? "" : ", " + joined) + ")";
            }
            return "(" + expression(function, context, depth + 1) + ")(" + joined + ")";
        }
        return unsupportedExpression(context, "expression",
            kind.empty() ? "unknown expression kind" : "unsupported expression kind: " + kind);
    }

    std::string target(const json& value, Context& context)
    {
        const std::string kind = value.value("kind", "");
        if (kind == "register")
            return "registers[" + expression(value.value("index", json::object()), context) + "]";
        if (kind == "index")
            return "(" + expression(value.value("table", json::object()), context) + ")[" +
                expression(value.value("index", json::object()), context) + "]";
        if (kind == "top_register")
            return "top";
        if (kind == "program_counter")
            return "pc";
        if (kind == "semantic_local")
            return identifier(value.value("name", "local_value"));
        if (kind == "vm_state")
            return "state[" + quoteLuau(value.value("name", "?")) + "]";
        if (kind == "opcode_slot")
            return "opcode_values[" + expression(value.value("index", json::object()), context) + "]";
        ++result.unsupported_operations;
        return "state[\"unsupported_target\"]";
    }

    void unsupportedOperation(std::string_view kind, std::string_view reason, size_t depth, const Context& context)
    {
        ++result.unsupported_operations;
        if (context.path_specific)
            ++result.unsupported_path_specific_operations;
        const std::string prefix = indentation(depth);
        append(prefix + "-- Unsupported recovered operation; execution stops instead of guessing.\n");
        append(prefix + "unsupported_semantic_operation(" + std::to_string(context.prototype) + ", " +
            std::to_string(context.pc) + ", " + quoteLuau(kind) + ", " + quoteLuau(reason) + ")\n");
    }

    std::optional<std::vector<std::string>> observedReturnLiterals(
        const json& operation, const Context& context) const
    {
        const json* observations = nullptr;
        if (operation.contains("observed_returns") && operation["observed_returns"].is_array())
            observations = &operation["observed_returns"];
        else if (context.instruction && context.instruction->contains("observed_returns") &&
            (*context.instruction)["observed_returns"].is_array())
            observations = &(*context.instruction)["observed_returns"];
        if (!observations || observations->empty())
            return std::nullopt;

        const json* referenceValues = nullptr;
        size_t referenceArity = std::numeric_limits<size_t>::max();
        for (const json& observation : *observations)
        {
            if (!observation.is_object() || !observation.value("complete", false) ||
                !observation.contains("arity") ||
                !observation.contains("values") || !observation["values"].is_array())
                return std::nullopt;
            const json& arityValue = observation["arity"];
            size_t arity = 0;
            if (arityValue.is_number_unsigned())
                arity = arityValue.get<size_t>();
            else if (arityValue.is_number_integer() && arityValue.get<int64_t>() >= 0)
                arity = static_cast<size_t>(arityValue.get<int64_t>());
            else
                return std::nullopt;
            if (observation["values"].size() != arity)
                return std::nullopt;
            if (!referenceValues)
            {
                referenceValues = &observation["values"];
                referenceArity = arity;
            }
            else if (referenceArity != arity || *referenceValues != observation["values"])
                return std::nullopt;
        }

        std::vector<std::string> literals;
        literals.reserve(referenceArity);
        for (const json& value : *referenceValues)
        {
            const std::optional<std::string> literal = specializationPrimitiveLiteral(value);
            if (!literal)
                return std::nullopt;
            literals.push_back(*literal);
        }
        return literals;
    }

    std::optional<std::string> jumpDestination(const json& operation, Context& context)
    {
        if (!operation.contains("target") || !operation["target"].is_object())
            return std::nullopt;
        json target = operation["target"];
        std::optional<int64_t> adjustment;
        if (target.contains("adjustment") && target["adjustment"].is_number_integer())
        {
            adjustment = target["adjustment"].get<int64_t>();
            target.erase("adjustment");
        }
        if (!adjustment && operation.contains("runtime_validation") &&
            operation["runtime_validation"].is_object() &&
            operation["runtime_validation"].contains("target_adjustment") &&
            operation["runtime_validation"]["target_adjustment"].is_number_integer())
            adjustment = operation["runtime_validation"]["target_adjustment"].get<int64_t>();
        if (!adjustment && !context.path_specific)
            adjustment = 1;
        if (!adjustment)
            return std::nullopt;
        const std::string base = expression(target, context);
        return *adjustment == 0 ? base : "(" + base + " + (" + std::to_string(*adjustment) + "))";
    }

    static std::optional<std::string> constantString(const json& value)
    {
        if (!value.is_object() || value.value("kind", "") != "constant" || !value.contains("value"))
            return std::nullopt;
        const json& primitive = value["value"];
        if (primitive.is_string())
            return primitive.get<std::string>();
        if (!primitive.is_object() || primitive.value("type", "") != "string")
            return std::nullopt;
        if (primitive.contains("value") && primitive["value"].is_string())
            return primitive["value"].get<std::string>();
        if (primitive.contains("bytes_hex") && primitive["bytes_hex"].is_string())
            return decodeHexBytes(primitive["bytes_hex"].get<std::string>());
        return std::nullopt;
    }

    static std::string recoveredOperationName(
        std::string_view role, const Context& context, size_t operationId)
    {
        return "recovered_" + std::string(role) + "_p" + std::to_string(context.prototype) +
            "_pc" + std::to_string(context.pc) + "_op" + std::to_string(operationId);
    }

    static std::optional<uint64_t> nonnegativeInteger(const json& value)
    {
        if (value.is_number_unsigned())
            return value.get<uint64_t>();
        if (value.is_number_integer())
        {
            const int64_t number = value.get<int64_t>();
            if (number >= 0)
                return static_cast<uint64_t>(number);
        }
        return std::nullopt;
    }

    static std::optional<uint64_t> bindingInteger(
        const json& binding, std::initializer_list<std::string_view> names)
    {
        if (!binding.is_object())
            return std::nullopt;
        for (std::string_view name : names)
        {
            const auto value = binding.find(std::string(name));
            if (value != binding.end())
                return nonnegativeInteger(*value);
        }
        return std::nullopt;
    }

    static std::optional<int64_t> destinationFromKey(const std::string& value)
    {
        try
        {
            size_t consumed = 0;
            const long long destination = std::stoll(value, &consumed, 10);
            if (consumed == value.size() && destination >= 0)
                return static_cast<int64_t>(destination);
        }
        catch (...)
        {
        }
        return std::nullopt;
    }

    static bool appendArgumentBinding(LoadArgumentsShape& shape, uint64_t argument,
        uint64_t destination, std::set<int64_t>& destinations, std::string& reason)
    {
        if (argument == 0 || argument > shape.arity)
        {
            reason = "argument binding is outside the fixed arity";
            return false;
        }
        if (destination > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
        {
            reason = "argument register destination is out of range";
            return false;
        }
        const int64_t registerIndex = static_cast<int64_t>(destination);
        if (!destinations.insert(registerIndex).second)
        {
            reason = "argument register destinations are not unique";
            return false;
        }
        shape.bindings.push_back({static_cast<size_t>(argument), registerIndex});
        return true;
    }

    static std::optional<LoadArgumentsShape> loadArgumentsShape(
        const json& value, std::string& reason)
    {
        if (!value.contains("observed_argument_arities") ||
            !value["observed_argument_arities"].is_array() ||
            value["observed_argument_arities"].size() != 1)
        {
            reason = "load_arguments requires exactly one observed fixed arity";
            return std::nullopt;
        }
        const std::optional<uint64_t> arity = nonnegativeInteger(
            value["observed_argument_arities"].front());
        if (!arity || *arity > std::numeric_limits<size_t>::max())
        {
            reason = "observed fixed argument arity is invalid";
            return std::nullopt;
        }

        LoadArgumentsShape shape;
        shape.arity = static_cast<size_t>(*arity);
        std::set<int64_t> destinations;
        const json* bindings = nullptr;
        for (std::string_view name : {"argument_bindings", "argument_writes", "register_writes"})
        {
            const auto candidate = value.find(std::string(name));
            if (candidate != value.end())
            {
                if (!candidate->is_array())
                {
                    reason = std::string(name) + " must be an array";
                    return std::nullopt;
                }
                bindings = &*candidate;
                break;
            }
        }

        if (bindings)
        {
            for (const json& binding : *bindings)
            {
                const std::optional<uint64_t> argument = bindingInteger(
                    binding, {"argument_index", "argument", "source_argument"});
                const std::optional<uint64_t> destination = bindingInteger(
                    binding, {"destination_register", "register"});
                if (!argument || !destination)
                {
                    reason = "argument binding lacks an explicit source argument or register destination";
                    return std::nullopt;
                }
                if (!appendArgumentBinding(shape, *argument, *destination, destinations, reason))
                    return std::nullopt;
            }
        }
        else
        {
            const json* orderedDestinations = nullptr;
            for (std::string_view name : {"argument_registers", "destination_registers"})
            {
                const auto candidate = value.find(std::string(name));
                if (candidate != value.end())
                {
                    if (!candidate->is_array())
                    {
                        reason = std::string(name) + " must be an array";
                        return std::nullopt;
                    }
                    orderedDestinations = &*candidate;
                    break;
                }
            }
            if (orderedDestinations)
            {
                for (size_t index = 0; index < orderedDestinations->size(); ++index)
                {
                    const std::optional<uint64_t> destination = nonnegativeInteger((*orderedDestinations)[index]);
                    if (!destination)
                    {
                        reason = "ordered argument register destination is invalid";
                        return std::nullopt;
                    }
                    if (!appendArgumentBinding(shape, index + 1, *destination, destinations, reason))
                        return std::nullopt;
                }
            }
            else if (value.contains("write_origins"))
            {
                const json& origins = value["write_origins"];
                if (!origins.is_object())
                {
                    reason = "write_origins must be an object";
                    return std::nullopt;
                }
                for (auto origin = origins.begin(); origin != origins.end(); ++origin)
                {
                    const std::optional<int64_t> destination = destinationFromKey(origin.key());
                    if (!destination || !origin.value().is_array() || origin.value().size() != 1 ||
                        !origin.value().front().is_object() ||
                        origin.value().front().value("kind", "") != "argument")
                    {
                        reason = "write origin does not prove one argument and register destination";
                        return std::nullopt;
                    }
                    const std::optional<uint64_t> argument = bindingInteger(
                        origin.value().front(), {"index", "argument_index", "argument"});
                    if (!argument || !appendArgumentBinding(shape, *argument,
                            static_cast<uint64_t>(*destination), destinations, reason))
                    {
                        if (reason.empty())
                            reason = "write origin lacks an explicit source argument";
                        return std::nullopt;
                    }
                }
            }
        }

        if (shape.bindings.empty())
        {
            reason = "load_arguments has no proven argument-to-register bindings";
            return std::nullopt;
        }
        if (value.contains("write_count"))
        {
            const std::optional<uint64_t> writeCount = nonnegativeInteger(value["write_count"]);
            const uint64_t observations = positiveUnsignedField(value, "observation_count");
            if (!writeCount || observations == 0 ||
                shape.bindings.size() > std::numeric_limits<uint64_t>::max() / observations ||
                *writeCount != observations * shape.bindings.size())
            {
                reason = "write_count is inconsistent with the proven argument bindings";
                return std::nullopt;
            }
        }
        return shape;
    }

    static std::optional<int64_t> provenRegisterIndex(
        const json& value, std::string_view field)
    {
        const auto found = value.find(std::string(field));
        if (found == value.end())
            return std::nullopt;
        if (const std::optional<int64_t> direct = primitiveIntegerValue(*found))
            return direct;
        return integerValue(*found);
    }

    static std::optional<RegisterClearRangeShape> registerClearRangeShape(
        const json& value, std::string& reason)
    {
        const std::optional<int64_t> first = provenRegisterIndex(value, "first_register");
        const std::optional<int64_t> last = provenRegisterIndex(value, "last_register");
        if (!first || !last || *first < 0 || *last < 0)
        {
            reason = "register_clear_range bounds are not proven nonnegative integral register indices";
            return std::nullopt;
        }

        const auto stepValue = value.find("step");
        const std::optional<int64_t> step = stepValue == value.end()
            ? std::nullopt
            : (primitiveIntegerValue(*stepValue).has_value()
                    ? primitiveIntegerValue(*stepValue)
                    : integerValue(*stepValue));
        if (!step || *step != 1)
        {
            reason = "register_clear_range requires a proven unit positive step";
            return std::nullopt;
        }
        if (!value.contains("inclusive_last_register") ||
            !value["inclusive_last_register"].is_boolean() ||
            !value["inclusive_last_register"].get<bool>())
        {
            reason = "register_clear_range requires a proven inclusive upper bound";
            return std::nullopt;
        }
        if (!value.contains("writes_nil") || !value["writes_nil"].is_boolean() ||
            !value["writes_nil"].get<bool>())
        {
            reason = "register_clear_range requires a proven nil write";
            return std::nullopt;
        }
        if (!value.contains("empty") || !value["empty"].is_boolean() ||
            value["empty"].get<bool>() != (*first > *last))
        {
            reason = "register_clear_range empty-range evidence contradicts its bounds";
            return std::nullopt;
        }
        if (value.value("assignment_count_overflow", false))
        {
            reason = "register_clear_range assignment count overflowed";
            return std::nullopt;
        }

        const uint64_t expectedAssignments = *first > *last
            ? 0
            : static_cast<uint64_t>(*last) - static_cast<uint64_t>(*first) + 1;
        if (value.contains("assignment_count") && !value["assignment_count"].is_null())
        {
            const std::optional<uint64_t> assignments = nonnegativeInteger(value["assignment_count"]);
            if (!assignments || *assignments != expectedAssignments)
            {
                reason = "register_clear_range assignment count contradicts its inclusive bounds";
                return std::nullopt;
            }
        }

        return RegisterClearRangeShape{*first, *last};
    }

    void operation(const json& value, size_t depth, Context& context, bool controlHandled = false)
    {
        ++result.operations;
        const size_t operationId = result.operations;
        const std::string prefix = indentation(depth);
        const std::string kind = value.value("kind", "");
        if (controlHandled && kind == "jump")
            return;
        if (kind == "operation_sequence" || kind == "protector_internal_sequence" || kind == "block")
        {
            for (const json& child : value.value("operations", json::array()))
                operation(child, depth, context, controlHandled);
            return;
        }
        if (kind == "register_write")
        {
            if (!value.contains("register") || !value["register"].is_object() ||
                !value.contains("value") || !value["value"].is_object())
            {
                unsupportedOperation(kind, "register destination or value is incomplete", depth, context);
                return;
            }
            const std::string registerIndex = expression(value.value("register", json::object()), context);
            const bool structuralCapture = hasCallArgumentIdentityResolution(
                context.prototype, value.value("value", json::object()));
            const std::optional<std::string> observed = structuralCapture
                ? std::nullopt : observedLiteral(value);
            const std::string source = observed ? *observed : expression(value.value("value", json::object()), context);
            if (!context.path_specific)
                append(prefix + "registers[" + registerIndex + "] = " + source + ";\n");
            else
            {
                const std::optional<int64_t> staticRegister = integerValue(value["register"]);
                const std::string role = staticRegister
                    ? "register_" + std::to_string(*staticRegister) : "register_value";
                const std::string recoveredValue = recoveredOperationName(role, context, operationId);
                append(prefix + "do\n");
                append(prefix + "  local " + recoveredValue + " = " + source + "\n");
                append(prefix + "  registers[" + registerIndex + "] = " + recoveredValue + "\n");
                append(prefix + "end\n");
            }
            return;
        }
        if (kind == "table_write")
        {
            if (!value.contains("table") || !value["table"].is_object() ||
                !value.contains("index") || !value["index"].is_object() ||
                !value.contains("value") || !value["value"].is_object())
            {
                unsupportedOperation(kind, "table, index, or value evidence is incomplete", depth, context);
                return;
            }
            const std::string table = expression(value.value("table", json::object()), context);
            const std::string index = expression(value.value("index", json::object()), context);
            const std::string source = expression(value.value("value", json::object()), context);
            if (!context.path_specific)
                append(prefix + "(" + table + ")[" + index + "] = " + source + ";\n");
            else
            {
                const std::string recoveredTable = recoveredOperationName("table", context, operationId);
                const std::string recoveredValue = recoveredOperationName("table_value", context, operationId);
                append(prefix + "do\n");
                append(prefix + "  local " + recoveredTable + " = " + table + "\n");
                const std::optional<std::string> field = constantString(value["index"]);
                if (field && plainIdentifier(*field) && identifier(*field) == *field)
                {
                    append(prefix + "  local " + recoveredValue + " = " + source + "\n");
                    append(prefix + "  " + recoveredTable + "." + *field + " = " + recoveredValue + "\n");
                }
                else
                {
                    const std::string recoveredKey = recoveredOperationName("table_key", context, operationId);
                    append(prefix + "  local " + recoveredKey + " = " + index + "\n");
                    append(prefix + "  local " + recoveredValue + " = " + source + "\n");
                    append(prefix + "  " + recoveredTable + "[" + recoveredKey + "] = " + recoveredValue + "\n");
                }
                append(prefix + "end\n");
            }
            return;
        }
        if (kind == "call")
        {
            if (!value.contains("function") || !value["function"].is_object() ||
                !value.contains("arguments") || !value["arguments"].is_array())
            {
                unsupportedOperation(kind, "call target or argument expressions were not recovered", depth, context);
                return;
            }
            append(prefix + expression(value, context) + ";\n");
            return;
        }
        if (kind == "expression")
        {
            append(prefix + "do local _ = " + expression(value.value("value", json::object()), context) + " end\n");
            return;
        }
        if (kind == "set_top")
        {
            append(prefix + "top = " + expression(value.value("value", json::object()), context) + ";\n");
            return;
        }
        if (kind == "adjust_top")
        {
            std::string op = value.value("operator", "+");
            if (!op.ends_with('='))
                op += '=';
            append(prefix + "top " + op + " " + expression(value.value("value", json::object()), context) + ";\n");
            return;
        }
        if (kind == "assign")
        {
            std::vector<std::string> targets;
            std::vector<std::string> values;
            for (const json& item : value.value("targets", json::array()))
                targets.push_back(target(item, context));
            for (const json& item : value.value("values", json::array()))
                values.push_back(expression(item, context));
            append(prefix);
            for (size_t index = 0; index < targets.size(); ++index)
            {
                if (index > 0)
                    append(", ");
                append(targets[index]);
            }
            append(" = ");
            if (values.empty())
                append("nil");
            for (size_t index = 0; index < values.size(); ++index)
            {
                if (index > 0)
                    append(", ");
                append(values[index]);
            }
            append(";\n");
            return;
        }
        if (kind == "compound_write")
        {
            std::string op = value.value("operator", "+");
            if (!op.ends_with('='))
                op += '=';
            append(prefix + target(value.value("target", json::object()), context) + " " + op + " " +
                expression(value.value("value", json::object()), context) + ";\n");
            return;
        }
        if (kind == "prepare_vm_state")
        {
            for (const json& binding : value.value("bindings", json::array()))
                append(prefix + "state[" + quoteLuau(binding.value("slot", "?")) + "] = " +
                    expression(binding.value("value", json::object()), context) + ";\n");
            return;
        }
        if (kind == "prepare_register_clear")
        {
            append(prefix + "state[" + quoteLuau(value.value("state", "register_clear")) + "] = { from = " +
                expression(value.value("from", json::object()), context) + ", to = " +
                expression(value.value("to", json::object()), context) + " };\n");
            return;
        }
        if (kind == "clear_prepared_register_range")
        {
            const std::string stateName = quoteLuau(value.value("state", "register_clear"));
            append(prefix + "do\n");
            append(prefix + "  local clear_range = state[" + stateName + "]\n");
            append(prefix + "  if clear_range then\n");
            append(prefix + "    for register_index = clear_range.from, clear_range.to do registers[register_index] = nil end\n");
            append(prefix + "  end\n");
            append(prefix + "end\n");
            return;
        }
        if (kind == "register_clear_range")
        {
            std::string reason;
            const std::optional<RegisterClearRangeShape> shape = registerClearRangeShape(value, reason);
            if (!shape)
            {
                unsupportedOperation(kind, reason, depth, context);
                return;
            }
            append(prefix + "for register_index = " + std::to_string(shape->first_register) + ", " +
                std::to_string(shape->last_register) + ", 1 do\n");
            append(prefix + "  registers[register_index] = nil\n");
            append(prefix + "end\n");
            return;
        }
        if (kind == "load_arguments")
        {
            std::string reason;
            const std::optional<LoadArgumentsShape> shape = loadArgumentsShape(value, reason);
            if (!shape)
            {
                unsupportedOperation(kind, reason, depth, context);
                return;
            }
            append(prefix + "if argument_count ~= " + std::to_string(shape->arity) + " then\n");
            append(prefix + "  unsupported_semantic_operation(" + std::to_string(context.prototype) + ", " +
                std::to_string(context.pc) + ", \"load_arguments\", \"fixed argument arity mismatch: expected " +
                std::to_string(shape->arity) + ", got \" .. tostring(argument_count))\n");
            append(prefix + "end\n");
            for (const ArgumentBinding& binding : shape->bindings)
                append(prefix + "registers[" + std::to_string(binding.destination) + "] = select_value(" +
                    std::to_string(binding.argument) + ", ...);\n");
            ++result.fixed_argument_loads;
            return;
        }
        if (kind == "capture_varargs")
        {
            const std::string valuesSlot = jsonStringOr(value, "values_slot");
            const std::string countSlot = jsonStringOr(value, "count_slot");
            if (valuesSlot.empty() || countSlot.empty() || valuesSlot == countSlot)
            {
                unsupportedOperation(kind,
                    "variadic capture state destinations are incomplete or conflicting", depth, context);
                return;
            }
            if (context.path_specific && value.contains("observed_argument_arities") &&
                (!value["observed_argument_arities"].is_array() ||
                    value["observed_argument_arities"].size() < 2))
            {
                unsupportedOperation(kind,
                    "variadic capture does not contain varying argument arity evidence", depth, context);
                return;
            }
            append(prefix + "state[" + quoteLuau(valuesSlot) + "] = {...};\n");
            append(prefix + "state[" + quoteLuau(countSlot) + "] = select_value(\"#\", ...);\n");
            ++result.variadic_argument_captures;
            return;
        }
        if (kind == "close_upvalues")
        {
            append(prefix + "close_captured_values(open_cells, registers, " +
                expression(value.value("from", json::object()), context) + ");\n");
            return;
        }
        if (kind == "generic_for_prepare")
        {
            append(prefix + "prepare_generic_iterator(registers, state, " +
                expression(value.value("base_register", json::object()), context) + ");\n");
            return;
        }
        if (kind == "numeric_for")
        {
            const std::string loopName = identifier(value.value("index", "loop_index"));
            append(prefix + "for " + loopName + " = " + expression(value.value("from", json::object()), context) + ", " +
                expression(value.value("to", json::object()), context) + ", " +
                expression(value.value("step", json{{"kind", "constant"}, {"value", 1}}), context) + " do\n");
            for (const json& child : value.value("body", json::array()))
                operation(child, depth + 1, context, controlHandled);
            append(prefix + "end\n");
            return;
        }
        if (kind == "return")
        {
            const json values = value.value("values", json::array());
            if (!values.is_array())
            {
                unsupportedOperation(kind, "return value list is incomplete", depth, context);
                return;
            }
            std::vector<std::string> renderedValues;
            for (const json& item : values)
                renderedValues.push_back(expression(item, context));
            if (context.path_specific && renderedValues.empty())
            {
                const std::optional<std::vector<std::string>> observed = observedReturnLiterals(value, context);
                if (!observed)
                {
                    unsupportedOperation(kind, "observed return arity or values are incomplete or inconsistent", depth, context);
                    return;
                }
                renderedValues = *observed;
            }
            append(prefix + "return");
            for (size_t index = 0; index < renderedValues.size(); ++index)
                append((index == 0 ? " " : ", ") + renderedValues[index]);
            append("\n");
            return;
        }
        if (kind == "branch")
        {
            if (!value.contains("condition") || !value["condition"].is_object())
            {
                if (!controlHandled)
                    unsupportedOperation(kind, "branch condition was not recovered", depth, context);
                return;
            }
            append(prefix + "if " + expression(value.value("condition", json::object()), context) + " then\n");
            for (const json& child : value.value("then", json::array()))
                operation(child, depth + 1, context, controlHandled);
            if (!value.value("else", json::array()).empty())
            {
                append(prefix + "else\n");
                for (const json& child : value.value("else", json::array()))
                    operation(child, depth + 1, context, controlHandled);
            }
            append(prefix + "end\n");
            return;
        }
        if (kind == "jump")
        {
            const std::optional<std::string> destination = jumpDestination(value, context);
            if (!destination)
            {
                unsupportedOperation(kind, "jump adjustment is not proven", depth, context);
                return;
            }
            append(prefix + "pc = " + *destination + ";\n");
            return;
        }
        constexpr std::string_view reason = "operation kind is not implemented by the semantic emitter";
        recordUnknownOperation(value, reason, context);
        unsupportedOperation(kind.empty() ? std::string_view("unknown") : std::string_view(kind),
            reason, depth, context);
    }

    std::optional<json> instructionAt(uint64_t prototype, size_t pc) const
    {
        auto prototypeIt = instructions.find(prototype);
        if (prototypeIt == instructions.end())
            return std::nullopt;
        auto row = prototypeIt->second.find(pc);
        if (row == prototypeIt->second.end() || row->second.empty())
            return std::nullopt;
        return row->second.front();
    }

    bool closureConstruction(const json& instruction, const json& semanticOperation,
        size_t depth, Context& context)
    {
        const bool semanticClosure = semanticOperation.value("kind", "") == "closure";
        const json* descriptorValue = nullptr;
        if (instruction.contains("closure_descriptor") && instruction["closure_descriptor"].is_object())
            descriptorValue = &instruction["closure_descriptor"];
        else if (semanticClosure && semanticOperation.contains("descriptor") &&
            semanticOperation["descriptor"].is_object())
            descriptorValue = &semanticOperation["descriptor"];
        if (!descriptorValue && !semanticClosure && instruction.value("opcode", int64_t(-1)) != 22 &&
            instruction.value("opcode", int64_t(-1)) != 112)
            return false;
        if (!descriptorValue)
        {
            ++result.unresolved_closure_descriptors;
            unsupportedOperation("closure", "closure descriptor is unavailable", depth, context);
            return true;
        }
        const json& descriptor = *descriptorValue;
        const uint64_t targetPrototype = descriptor.contains("target_prototype") &&
                descriptor["target_prototype"].is_number_unsigned()
            ? descriptor["target_prototype"].get<uint64_t>()
            : descriptor.contains("target_prototype") && descriptor["target_prototype"].is_number_integer() &&
                    descriptor["target_prototype"].get<int64_t>() > 0
                ? static_cast<uint64_t>(descriptor["target_prototype"].get<int64_t>())
                : uint64_t(0);
        const int64_t destination = descriptor.value("destination_register", int64_t(-1));
        if (!descriptor.value("complete", false) || targetPrototype == 0 || destination < 0 ||
            !instructions.contains(targetPrototype) || !descriptor.contains("captures") || !descriptor["captures"].is_array())
        {
            ++result.unresolved_closure_descriptors;
            unsupportedOperation("closure", "closure descriptor is incomplete or targets an unknown prototype", depth, context);
            return true;
        }
        const std::string prefix = indentation(depth);
        std::set<int64_t> captureIndices;
        for (const json& capture : descriptor["captures"])
        {
            const int64_t captureIndex = capture.value("capture_index", int64_t(-1));
            const int64_t kind = capture.value("capture_kind", int64_t(-1));
            const int64_t slot = capture.value("slot", int64_t(-1));
            if (captureIndex < 0 || !captureIndices.insert(captureIndex).second ||
                kind < 0 || kind > 2 || slot < 0)
            {
                ++result.unresolved_closure_descriptors;
                unsupportedOperation("closure", kind == 3
                    ? "capture kind 3 remains distinct and is not semantically proven"
                    : "capture metadata is invalid or duplicated", depth, context);
                return true;
            }
        }

        append(prefix + "do\n");
        append(prefix + "  local callback_captures = {\n");
        for (const json& capture : descriptor["captures"])
        {
            const int64_t captureIndex = capture.value("capture_index", int64_t(-1));
            const int64_t kind = capture.value("capture_kind", int64_t(-1));
            const int64_t slot = capture.value("slot", int64_t(-1));
            std::string source;
            if (kind == 0)
                source = "capture_register_cell(open_cells, registers, " + std::to_string(slot) + ")";
            else if (kind == 1)
                source = "registers[" + std::to_string(slot) + "]";
            else
                source = captureCellForKey(slot, context);
            append(prefix + "    [" + std::to_string(captureIndex) + "] = " + source + ",\n");
        }
        append(prefix + "  }\n");
        const std::string callbackName = "recovered_callback_" + std::to_string(context.prototype) + "_" +
            std::to_string(context.pc);
        append(prefix + "  local " + callbackName + " = function(...)\n");
        append(prefix + "    return " + prototypeName(targetPrototype) + "(callback_captures, ...)\n");
        append(prefix + "  end\n");
        append(prefix + "  registers[" + std::to_string(destination) + "] = " + callbackName + "\n");
        append(prefix + "end\n");
        ++result.closure_constructors;
        return true;
    }

    static bool branchSideJumps(const json& branch, std::string_view side)
    {
        const json operations = branch.value(std::string(side), json::array());
        return operations.is_array() && std::any_of(operations.begin(), operations.end(), [](const json& operation) {
            return operation.value("kind", "") == "jump";
        });
    }

    static std::optional<size_t> branchStaticTarget(const json& branch)
    {
        for (std::string_view side : {"then", "else"})
        {
            const json operations = branch.value(std::string(side), json::array());
            for (const json& operation : operations)
            {
                if (operation.value("kind", "") != "jump")
                    continue;
                if (std::optional<int64_t> target = integerValue(operation.value("target", json::object())); target && *target >= 0)
                    return static_cast<size_t>(*target + 1);
            }
        }
        return std::nullopt;
    }

    std::pair<std::optional<size_t>, std::optional<size_t>> branchTargets(const Block& block, const json& branch)
    {
        const size_t fallthrough = block.end + 1;
        const bool thenJumps = branchSideJumps(branch, "then");
        const bool elseJumps = branchSideJumps(branch, "else");
        const std::optional<size_t> staticTarget = branchStaticTarget(branch);
        std::optional<size_t> explicitTarget;
        if (block.successors.size() >= 2)
        {
            auto nonFallthrough = std::find_if(block.successors.begin(), block.successors.end(),
                [&](size_t successor) { return successor != fallthrough; });
            if (nonFallthrough != block.successors.end())
                explicitTarget = *nonFallthrough;
        }
        else if (block.successors.size() == 1)
        {
            ++result.unobserved_branch_arms;
            if (block.successors.front() != fallthrough)
                explicitTarget = block.successors.front();
            else
                explicitTarget = staticTarget;
        }
        if (!explicitTarget)
            explicitTarget = staticTarget;

        std::optional<size_t> trueTarget;
        std::optional<size_t> falseTarget;
        if (thenJumps)
        {
            trueTarget = explicitTarget;
            falseTarget = fallthrough;
        }
        else if (elseJumps)
        {
            trueTarget = fallthrough;
            falseTarget = explicitTarget;
        }
        else if (block.successors.size() >= 2)
        {
            trueTarget = block.successors[0];
            falseTarget = block.successors[1];
            ++result.symbolic_transitions;
        }
        else if (block.successors.size() == 1)
        {
            trueTarget = block.successors.front();
            falseTarget = block.successors.front();
            ++result.symbolic_transitions;
        }
        else
            ++result.symbolic_transitions;
        return {trueTarget, falseTarget};
    }

    void transition(const Block& block, const std::optional<json>& lastInstruction, size_t depth, Context& context)
    {
        const std::string prefix = indentation(depth);
        const json* selectedOperation = lastInstruction
            ? semanticOperationForInstruction(*lastInstruction) : nullptr;
        const json& terminalOperation = selectedOperation
            ? directSequenceTerminal(*selectedOperation) : json(nullptr);
        const std::string kind = terminalOperation.is_object() ? terminalOperation.value("kind", "") : "";
        if (kind == "return")
            return;
        if (kind == "branch" && terminalOperation.contains("condition") &&
            terminalOperation["condition"].is_object())
        {
            const auto [whenTrue, whenFalse] = branchTargets(block, terminalOperation);
            append(prefix + "if " + expression(terminalOperation.value("condition", json::object()), context) + " then\n");
            append(prefix + "  pc = " + (whenTrue ? std::to_string(*whenTrue) : "nil") + "\n");
            append(prefix + "else\n");
            append(prefix + "  pc = " + (whenFalse ? std::to_string(*whenFalse) : "nil") + "\n");
            append(prefix + "end\n");
            return;
        }
        if (kind == "branch" && context.path_specific && block.successors.size() == 1)
            ++result.unobserved_branch_arms;
        if (kind == "generic_for_prepare")
        {
            append(prefix + "pc = (" + expression(terminalOperation.value("loop_target", json::object()), context) + ") + 1\n");
            return;
        }
        if (block.successors.size() == 1)
            append(prefix + "pc = " + std::to_string(block.successors.front()) + "\n");
        else if (block.successors.size() > 1)
        {
            ++result.dynamic_edge_sites;
            auto model = transitionModels.find({context.prototype, block.end});
            if (model != transitionModels.end() && !model->second.activation_sequences.empty())
            {
                append(prefix + "pc = replay_activation_transition(replay_positions, " +
                    std::to_string(context.prototype) + ", " + std::to_string(block.end) + ", {");
                for (size_t activationIndex = 0;
                    activationIndex < model->second.activation_sequences.size(); ++activationIndex)
                {
                    if (activationIndex > 0)
                        append(", ");
                    append("{");
                    const std::vector<size_t>& sequence = model->second.activation_sequences[activationIndex];
                    for (size_t index = 0; index < sequence.size(); ++index)
                    {
                        if (index > 0)
                            append(", ");
                        append(std::to_string(sequence[index]));
                    }
                    append("}");
                }
                append("}, " + std::to_string(model->second.stable_suffix_start) + ")\n");
                ++result.replayed_dynamic_edge_sites;
            }
            else if (model != transitionModels.end() && !model->second.legacy_sequence.empty())
            {
                append(prefix + "pc = replay_legacy_transition(" + std::to_string(context.prototype) + ", " +
                    std::to_string(block.end) + ", {");
                for (size_t index = 0; index < model->second.legacy_sequence.size(); ++index)
                {
                    if (index > 0)
                        append(", ");
                    append(std::to_string(model->second.legacy_sequence[index]));
                }
                append("})\n");
                ++result.replayed_dynamic_edge_sites;
            }
            else
            {
                ++result.symbolic_transitions;
                ++result.unsupported_operations;
                if (context.path_specific)
                    ++result.unsupported_path_specific_operations;
                append(prefix + "-- Multiple destinations were observed here without an ordered trace.\n");
                append(prefix + "unsupported_semantic_operation(" + std::to_string(context.prototype) + ", " +
                    std::to_string(block.end) + ", \"dynamic_transition\", \"ordered branch evidence is unavailable\")\n");
            }
        }
        else if (kind == "jump")
        {
            const std::optional<std::string> destination = jumpDestination(terminalOperation, context);
            if (destination)
                append(prefix + "pc = " + *destination + "\n");
            else
                unsupportedOperation("jump", "jump adjustment is not proven by runtime evidence or CFG", depth, context);
        }
        else
            append(prefix + "pc = nil\n");
    }

    void emitLaneReplay(const LaneReplayModel& model, uint64_t prototype, size_t pc,
        size_t depth, Context& context)
    {
        context.stable_lane_literals = model.stable_lane_literals;
        context.runtime_lane_names = model.replay_lanes;
        if (model.replay_lanes.empty())
            return;
        context.runtime_lanes_variable = "runtime_lanes_" + std::to_string(pc);
        append(indentation(depth) + "local " + context.runtime_lanes_variable +
            " = replay_runtime_lanes(replay_positions, " + std::to_string(prototype) + ", " +
            std::to_string(pc) + ", {");
        for (size_t activationIndex = 0; activationIndex < model.activation_sequences.size(); ++activationIndex)
        {
            if (activationIndex > 0)
                append(", ");
            append("{");
            const std::vector<json>& frames = model.activation_sequences[activationIndex];
            for (size_t frameIndex = 0; frameIndex < frames.size(); ++frameIndex)
            {
                if (frameIndex > 0)
                    append(", ");
                append("{");
                bool firstLane = true;
                for (const std::string& lane : model.replay_lanes)
                {
                    if (!firstLane)
                        append(", ");
                    firstLane = false;
                    append("[" + quoteLuau(lane) + "] = " + primitiveLiteral(frames[frameIndex][lane]));
                }
                append("}");
            }
            append("}");
        }
        append("}, " + std::to_string(model.stable_suffix_start) + ")\n");
    }

    void emitPrototype(uint64_t id)
    {
        auto cfg = cfgs.find(id);
        auto rows = instructions.find(id);
        if (cfg == cfgs.end() || rows == instructions.end())
            return;
        const bool specializedRootCall = id == rootPrototype && rootCallFrameSpecialized;
        append(prototypeName(id) + " = function(captured_values, ...)\n");
        append("  captured_values = captured_values or {}\n");
        append("  local registers = {}\n");
        append("  local open_cells = {}\n");
        append("  local replay_positions = {}\n");
        append("  local state = { Q = environment }\n");
        if (specializedRootCall)
        {
            append("  local root_arguments = select_value(1, ...)\n");
            append("  local argument_count = 1\n");
            append("  registers[1] = root_arguments\n");
            append("  local top = 1\n");
        }
        else
        {
            append("  local argument_count = select_value(\"#\", ...)\n");
            append("  for argument_index = 1, argument_count do registers[argument_index] = select_value(argument_index, ...) end\n");
            append("  local top = argument_count\n");
        }
        append("  local pc = " + std::to_string(cfg->second.entry) + "\n");
        append("  while pc ~= nil do\n");
        append("    semantic_step(" + std::to_string(id) + ", pc)\n");
        constexpr size_t kDispatchBucketWidth = 64;
        if (cfg->second.blocks.empty())
        {
            append("    return nil\n");
            append("  end\n");
            append("  return nil\n");
            append("end\n\n");
            return;
        }
        append("    local dispatch_bucket = math.floor((pc - 1) / " +
            std::to_string(kDispatchBucketWidth) + ")\n");
        bool firstBucket = true;
        bool firstBlock = true;
        size_t currentBucket = std::numeric_limits<size_t>::max();
        for (const Block& block : cfg->second.blocks)
        {
            const size_t bucket = block.start == 0 ? 0 : (block.start - 1) / kDispatchBucketWidth;
            if (bucket != currentBucket)
            {
                if (currentBucket != std::numeric_limits<size_t>::max())
                    append("      else\n        return nil\n      end\n");
                append(std::string(firstBucket ? "    if dispatch_bucket == " : "    elseif dispatch_bucket == ") +
                    std::to_string(bucket) + " then\n");
                firstBucket = false;
                firstBlock = true;
                currentBucket = bucket;
            }
            const size_t firstLine = line;
            const size_t firstProvenanceRecord = result.path_specific_operation_provenance.size();
            const size_t firstUnknownOperation = result.unknown_operations.size();
            std::set<size_t> pathSpecificPcs;
            append(std::string(firstBlock ? "      if pc == " : "      elseif pc == ") +
                std::to_string(block.start) + " then\n");
            firstBlock = false;
            Context context;
            context.prototype = id;
            std::optional<json> lastInstruction;
            for (const auto& [pc, instructionRows] : rows->second)
            {
                if (pc < block.start || pc > block.end)
                    continue;
                context.runtime_lanes_variable.clear();
                context.runtime_lane_names.clear();
                context.stable_lane_literals.clear();
                if (const auto laneModel = laneReplayModels.find({id, pc}); laneModel != laneReplayModels.end())
                    emitLaneReplay(laneModel->second, id, pc, 4, context);
                for (const json& instruction : instructionRows)
                {
                    lastInstruction = instruction;
                    context.pc = pc;
                    context.instruction = &instruction;
                    auto callee = callEdges.find({id, pc});
                    context.callee = callee == callEdges.end() ? std::nullopt : std::optional<uint64_t>(callee->second);
                    context.callee_consumed = false;
                    context.path_specific = false;
                    if (const json* semantic = semanticOperationForInstruction(instruction))
                    {
                        context.path_specific = isPathSpecificOperation(*semantic);
                        if (context.path_specific)
                        {
                            pathSpecificPcs.insert(pc);
                            recordPathSpecificOperation(*semantic, context);
                            emitPathSpecificProvenanceComment(*semantic, 4);
                        }
                        const bool controlHandled = pc == block.end;
                        if (!closureConstruction(instruction, *semantic, 4, context))
                            operation(*semantic, 4, context, controlHandled);
                    }
                    else if (instruction.contains("observational_semantic_operation") &&
                        instruction["observational_semantic_operation"].is_object())
                    {
                        context.path_specific = true;
                        pathSpecificPcs.insert(pc);
                        constexpr std::string_view reason = "path-specific proof metadata is incomplete";
                        recordUnknownOperation(instruction["observational_semantic_operation"], reason, context);
                        unsupportedOperation("observational_semantic_operation",
                            reason, 4, context);
                    }
                }
            }
            transition(block, lastInstruction, 4, context);
            json blockOperationProvenance = json::array();
            for (size_t index = firstProvenanceRecord;
                 index < result.path_specific_operation_provenance.size(); ++index)
                blockOperationProvenance.push_back(result.path_specific_operation_provenance[index]);
            json blockUnknownOperations = json::array();
            for (size_t index = firstUnknownOperation; index < result.unknown_operations.size(); ++index)
                blockUnknownOperations.push_back(result.unknown_operations[index]);
            result.mapping.push_back({
                {"prototype", id},
                {"block", block.id},
                {"pc_start", block.start},
                {"pc_end", block.end},
                {"terminator", block.terminator},
                {"successors", block.successors},
                {"path_specific", !pathSpecificPcs.empty()},
                {"path_specific_pcs", pathSpecificPcs},
                {"path_specific_operation_provenance", std::move(blockOperationProvenance)},
                {"unknown_operations", std::move(blockUnknownOperations)},
                {"source_claim", false},
                {"line_start", firstLine},
                {"line_end", line > 0 ? line - 1 : 0},
            });
            ++result.blocks;
        }
        append("      else\n        return nil\n      end\n");
        append("    else\n      return nil\n    end\n");
        append("  end\n");
        append("  return nil\n");
        append("end\n\n");
    }
};

} // namespace

SemanticCandidate emitSemanticCandidate(const json& reachableIr, const json& cfg)
{
    return Emitter(reachableIr, cfg).emit();
}

} // namespace alex::deobfuscator::luraph
