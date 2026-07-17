#include "passes/names.hpp"

#include "Luau/Allocator.h"
#include "Luau/Ast.h"
#include "Luau/Lexer.h"
#include "Luau/Parser.h"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <exception>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace alex::deobfuscator
{
namespace
{

enum class CandidateFamily
{
    Generated,
    Temporary,
};

enum class BindingRole
{
    Registers,
    MutableCell,
    Callback,
    SemanticValue,
    VmValue,
    VmTemporary,
};

struct Candidate
{
    Luau::AstLocal* local = nullptr;
    CandidateFamily family = CandidateFamily::Generated;
    std::string original_name;
    std::string replacement;
    BindingRole role = BindingRole::VmValue;
    std::vector<Luau::Location> occurrences;

    std::set<std::string> static_indices;
    bool saw_index = false;
    bool all_indices_are_one = true;
    bool multi_index = false;
    bool callback = false;
    bool callback_role_conflict = false;
    bool saw_table_assignment = false;
    bool table_shape_compatible = true;
    bool cell_shape_compatible = true;
    std::set<std::string> value_roles;
    std::set<std::string> usage_roles;
    std::map<std::string, double> name_scores;
    std::string semantic_base;
    double semantic_confidence = 0.0;
    size_t unknown_value_assignments = 0;
    bool generated_parameter = false;
    bool rename_eligible = true;
    std::vector<Luau::AstExprFunction*> function_values;
};

struct LocalDeclaration
{
    Luau::AstStatLocal* statement = nullptr;
    Luau::AstLocal* local = nullptr;
};

struct ParseContext
{
    Luau::Allocator allocator;
    Luau::AstNameTable names{allocator};
    Luau::ParseResult result;
};

std::unique_ptr<ParseContext> parse(std::string_view source)
{
    auto context = std::make_unique<ParseContext>();
    context->result = Luau::Parser::parse(source.data(), source.size(), context->names, context->allocator);
    return context;
}

bool hasDecimalSuffix(std::string_view name, std::string_view prefix)
{
    if (!name.starts_with(prefix) || name.size() == prefix.size())
        return false;

    return std::all_of(name.begin() + static_cast<std::ptrdiff_t>(prefix.size()), name.end(), [](char ch) {
        return ch >= '0' && ch <= '9';
    });
}

std::optional<CandidateFamily> candidateFamily(std::string_view name)
{
    if (name == "temporary")
        return CandidateFamily::Temporary;
    if (hasDecimalSuffix(name, "local_") || hasDecimalSuffix(name, "function_"))
        return CandidateFamily::Generated;
    return std::nullopt;
}

std::optional<CandidateFamily> residualCandidateFamily(std::string_view name)
{
    if (hasDecimalSuffix(name, "vm_value_"))
        return CandidateFamily::Generated;
    if (hasDecimalSuffix(name, "vm_temporary_"))
        return CandidateFamily::Temporary;
    return std::nullopt;
}

bool aliasCandidateName(std::string_view name)
{
    return candidateFamily(name).has_value() || hasDecimalSuffix(name, "vm_value_") ||
        hasDecimalSuffix(name, "vm_temporary_");
}

class BindingCollector final : public Luau::AstVisitor
{
public:
    explicit BindingCollector(
        bool include_residual = false,
        bool include_callbacks = false,
        bool include_parameters = false)
        : include_residual(include_residual)
        , include_callbacks(include_callbacks)
        , include_parameters(include_parameters)
    {
    }

    std::vector<Candidate> candidates;
    std::vector<LocalDeclaration> local_declarations;
    std::vector<Luau::AstStatLocal*> local_statements;

    bool visit(Luau::AstStatLocal* node) override
    {
        local_statements.push_back(node);
        if (node->vars.size == 1)
            local_declarations.push_back({node, node->vars.data[0]});
        for (Luau::AstLocal* local : node->vars)
            add(local);
        return true;
    }

    bool visit(Luau::AstStatFor* node) override
    {
        add(node->var);
        return true;
    }

    bool visit(Luau::AstStatForIn* node) override
    {
        for (Luau::AstLocal* local : node->vars)
            add(local);
        return true;
    }

    bool visit(Luau::AstStatLocalFunction* node) override
    {
        add(node->name);
        return true;
    }

    bool visit(Luau::AstExprFunction* node) override
    {
        add(node->self);
        for (Luau::AstLocal* local : node->args)
            add(local);
        return true;
    }

    bool visit(Luau::AstStatClass* node) override
    {
        add(node->name);
        return true;
    }

    bool visit(Luau::AstType*) override
    {
        return true;
    }

private:
    bool include_residual = false;
    bool include_callbacks = false;
    bool include_parameters = false;
    std::unordered_set<Luau::AstLocal*> seen;

    void add(Luau::AstLocal* local)
    {
        if (!local || !seen.insert(local).second || !local->name.value)
            return;

        const std::string_view name(local->name.value);
        std::optional<CandidateFamily> family = candidateFamily(name);
        if (!family && include_residual)
            family = residualCandidateFamily(name);
        if (!family && include_callbacks && hasDecimalSuffix(name, "callback_"))
            family = CandidateFamily::Generated;
        const bool generated_parameter = !family && include_parameters && hasDecimalSuffix(name, "argument_");
        if (generated_parameter)
            family = CandidateFamily::Generated;
        if (!family)
            return;

        Candidate candidate;
        candidate.local = local;
        candidate.family = *family;
        candidate.original_name = std::string(name);
        candidate.generated_parameter = generated_parameter;
        candidate.occurrences.push_back(local->location);
        candidates.push_back(std::move(candidate));
    }
};

Luau::AstExpr* unwrapTransparent(Luau::AstExpr* expression)
{
    while (expression)
    {
        if (auto group = expression->as<Luau::AstExprGroup>())
            expression = group->expr;
        else if (auto assertion = expression->as<Luau::AstExprTypeAssertion>())
            expression = assertion->expr;
        else if (auto instantiate = expression->as<Luau::AstExprInstantiate>())
            expression = instantiate->expr;
        else
            break;
    }
    return expression;
}

Luau::AstExprLocal* directLocal(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    return expression ? expression->as<Luau::AstExprLocal>() : nullptr;
}

std::string snakeCase(std::string_view value);

std::string withoutNumericSuffix(std::string_view name)
{
    const size_t separator = name.rfind('_');
    if (separator == std::string_view::npos || separator + 1 == name.size() ||
        !std::all_of(name.begin() + static_cast<std::ptrdiff_t>(separator + 1), name.end(), [](char ch) {
            return std::isdigit(static_cast<unsigned char>(ch));
        }))
        return std::string(name);
    return std::string(name.substr(0, separator));
}

std::optional<std::string> callbackPurposeFromSignal(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    if (!expression)
        return std::nullopt;
    if (auto property = expression->as<Luau::AstExprIndexName>(); property && property->index.value)
        return "on_" + snakeCase(property->index.value);
    std::string role;
    if (auto local = expression->as<Luau::AstExprLocal>(); local && local->local && local->local->name.value)
        role = withoutNumericSuffix(local->local->name.value);
    else if (auto global = expression->as<Luau::AstExprGlobal>(); global && global->name.value)
        role = withoutNumericSuffix(global->name.value);
    if (!role.empty())
    {
        constexpr std::string_view suffix = "_signal";
        if (role.ends_with(suffix))
            role.erase(role.size() - suffix.size());
        if (!role.empty() && role != "signal")
            return "on_" + role;
    }
    return std::nullopt;
}

std::optional<std::string> signalIdentifier(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    if (!expression)
        return std::nullopt;
    if (auto property = expression->as<Luau::AstExprIndexName>(); property && property->index.value)
        return std::string(property->index.value);
    if (auto local = expression->as<Luau::AstExprLocal>(); local && local->local && local->local->name.value)
    {
        std::string name = withoutNumericSuffix(local->local->name.value);
        constexpr std::string_view suffix = "_signal";
        if (name.ends_with(suffix))
            name.erase(name.size() - suffix.size());
        return name;
    }
    return std::nullopt;
}

std::vector<std::string> callbackParameterRoles(std::string_view signal)
{
    static const std::map<std::string_view, std::vector<std::string>> Roles{
        {"activated", {"input"}},
        {"animation_played", {"animation_track"}},
        {"changed", {"changed_value"}},
        {"character_added", {"character"}},
        {"character_removing", {"character"}},
        {"child_added", {"child"}},
        {"child_removed", {"child"}},
        {"descendant_added", {"descendant"}},
        {"descendant_removing", {"descendant"}},
        {"heartbeat", {"delta_time"}},
        {"input_began", {"input", "game_processed"}},
        {"input_changed", {"input", "game_processed"}},
        {"input_ended", {"input", "game_processed"}},
        {"player_added", {"player"}},
        {"player_removing", {"player"}},
        {"post_simulation", {"delta_time"}},
        {"pre_animation", {"delta_time"}},
        {"pre_render", {"delta_time"}},
        {"pre_simulation", {"delta_time"}},
        {"render_stepped", {"delta_time"}},
        {"stepped", {"time", "delta_time"}},
        {"touch_ended", {"hit"}},
        {"touched", {"hit"}},
    };
    const std::string normalized = snakeCase(signal);
    if (auto found = Roles.find(normalized); found != Roles.end())
        return found->second;
    return {};
}

bool isFunctionValue(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    return expression && expression->is<Luau::AstExprFunction>();
}

std::string snakeCase(std::string_view value)
{
    std::string result;
    for (size_t index = 0; index < value.size(); ++index)
    {
        const unsigned char ch = static_cast<unsigned char>(value[index]);
        if (std::isupper(ch))
        {
            const bool previous_lower = index > 0 && (std::islower(static_cast<unsigned char>(value[index - 1])) ||
                std::isdigit(static_cast<unsigned char>(value[index - 1])));
            const bool acronym_boundary = index > 0 && std::isupper(static_cast<unsigned char>(value[index - 1])) &&
                index + 1 < value.size() && std::islower(static_cast<unsigned char>(value[index + 1]));
            if (!result.empty() && result.back() != '_' && (previous_lower || acronym_boundary))
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

std::string constantString(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    if (auto value = expression ? expression->as<Luau::AstExprConstantString>() : nullptr)
        return std::string(value->value.data, value->value.size);
    return {};
}

std::optional<std::string> propertyRole(std::string_view property)
{
    static const std::map<std::string_view, std::string_view> Roles{
        {"Activated", "activated_signal"},
        {"Animation", "animation"},
        {"AnimationId", "animation_id"},
        {"AnimationPlayed", "animation_played_signal"},
        {"CanCollide", "can_collide"},
        {"CFrame", "cframe"},
        {"Changed", "changed_signal"},
        {"Character", "character"},
        {"CharacterAdded", "character_added_signal"},
        {"ChildAdded", "child_added_signal"},
        {"ChildRemoved", "child_removed_signal"},
        {"CurrentCamera", "current_camera"},
        {"Enabled", "enabled"},
        {"Heartbeat", "heartbeat_signal"},
        {"Health", "health"},
        {"KeyCode", "key_code"},
        {"LocalPlayer", "local_player"},
        {"Magnitude", "magnitude"},
        {"Name", "name"},
        {"Parent", "parent"},
        {"Position", "position"},
        {"RenderStepped", "render_stepped_signal"},
        {"Size", "size"},
        {"Touched", "touched_signal"},
        {"Transparency", "transparency"},
        {"UserId", "user_id"},
        {"UserInputType", "user_input_type"},
        {"Value", "value"},
        {"X", "x"},
        {"Y", "y"},
        {"Z", "z"},
    };
    if (auto found = Roles.find(property); found != Roles.end())
        return std::string(found->second);
    return std::nullopt;
}

std::optional<std::string> callRole(Luau::AstExprCall* call)
{
    if (!call)
        return std::nullopt;
    Luau::AstExpr* callee = unwrapTransparent(call->func);
    if (auto global = callee->as<Luau::AstExprGlobal>(); global && global->name.value)
    {
        const std::string_view name(global->name.value);
        if (name == "pcall" || name == "xpcall")
            return "success";
    }

    auto method = callee->as<Luau::AstExprIndexName>();
    if (!method || !method->index.value)
        return std::nullopt;
    const std::string_view name(method->index.value);
    if ((name == "FindFirstChild" || name == "FindFirstChildOfClass" || name == "FindFirstChildWhichIsA" ||
            name == "WaitForChild" || name == "GetService") && call->args.size > 0)
    {
        const std::string literal = constantString(call->args.data[0]);
        if (!literal.empty())
            return snakeCase(literal);
    }
    if (auto receiver = unwrapTransparent(method->expr)->as<Luau::AstExprGlobal>();
        receiver && receiver->name.value)
    {
        const std::string_view owner(receiver->name.value);
        if (owner == "Instance" && name == "new" && call->args.size > 0)
        {
            const std::string class_name = constantString(call->args.data[0]);
            if (!class_name.empty())
                return snakeCase(class_name);
        }
        static const std::map<std::string_view, std::string_view> Constructors{
            {"BrickColor", "brick_color"},
            {"CFrame", "cframe"},
            {"Color3", "color"},
            {"DateTime", "date_time"},
            {"Ray", "ray"},
            {"Rect", "rect"},
            {"TweenInfo", "tween_info"},
            {"UDim", "udim"},
            {"UDim2", "udim2"},
            {"Vector2", "vector2"},
            {"Vector3", "vector3"},
        };
        if ((name == "new" || name == "fromRGB" || name == "fromHSV") && Constructors.contains(owner))
            return std::string(Constructors.at(owner));
    }
    static const std::map<std::string_view, std::string_view> Roles{
        {"Clone", "clone"},
        {"Connect", "connection"},
        {"Create", "tween"},
        {"GetAttribute", "attribute_value"},
        {"GetAttributes", "attributes"},
        {"GetChildren", "children"},
        {"GetDescendants", "descendants"},
        {"GetMouse", "mouse"},
        {"GetPlayerFromCharacter", "player"},
        {"GetPlayers", "players"},
        {"GetPlayingAnimationTracks", "animation_tracks"},
        {"IsA", "condition"},
        {"IsAncestorOf", "condition"},
        {"IsDescendantOf", "condition"},
        {"JSONDecode", "decoded_value"},
        {"JSONEncode", "json"},
        {"LoadAnimation", "animation_track"},
        {"Once", "connection"},
        {"Raycast", "raycast_result"},
    };
    if (auto found = Roles.find(name); found != Roles.end())
        return std::string(found->second);
    return std::nullopt;
}

std::optional<std::string> assignedValueRole(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    if (!expression)
        return std::nullopt;
    if (expression->is<Luau::AstExprFunction>())
        return "callback";
    if (expression->is<Luau::AstExprTable>())
        return "values";
    if (expression->is<Luau::AstExprConstantBool>())
        return "condition";
    if (expression->is<Luau::AstExprConstantString>() || expression->is<Luau::AstExprInterpString>())
        return "text";
    if (expression->is<Luau::AstExprConstantNumber>() || expression->is<Luau::AstExprConstantInteger>())
        return "number";
    if (auto unary = expression->as<Luau::AstExprUnary>())
    {
        if (unary->op == Luau::AstExprUnary::Op::Not)
            return "condition";
        if (unary->op == Luau::AstExprUnary::Op::Minus || unary->op == Luau::AstExprUnary::Op::Len)
            return "number";
    }
    if (auto binary = expression->as<Luau::AstExprBinary>())
    {
        switch (binary->op)
        {
        case Luau::AstExprBinary::CompareNe:
        case Luau::AstExprBinary::CompareEq:
        case Luau::AstExprBinary::CompareLt:
        case Luau::AstExprBinary::CompareLe:
        case Luau::AstExprBinary::CompareGt:
        case Luau::AstExprBinary::CompareGe: return "condition";
        case Luau::AstExprBinary::Concat: return "text";
        case Luau::AstExprBinary::Add:
        case Luau::AstExprBinary::Sub:
        case Luau::AstExprBinary::Mul:
        case Luau::AstExprBinary::Div:
        case Luau::AstExprBinary::FloorDiv:
        case Luau::AstExprBinary::Mod:
        case Luau::AstExprBinary::Pow: return "number";
        default: break;
        }
    }
    if (auto property = expression->as<Luau::AstExprIndexName>())
    {
        if (property->index.value)
        {
            if (std::optional<std::string> role = propertyRole(property->index.value))
                return role;
            else
                return snakeCase(property->index.value);
        }
    }
    if (expression->is<Luau::AstExprIndexExpr>())
        return "indexed_value";
    if (auto call = expression->as<Luau::AstExprCall>())
        return callRole(call);
    if (auto global = expression->as<Luau::AstExprGlobal>(); global && global->name.value)
        return snakeCase(global->name.value);
    if (auto local = expression->as<Luau::AstExprLocal>(); local && local->local && local->local->name.value)
    {
        std::string base(local->local->name.value);
        const size_t suffix = base.rfind('_');
        if (suffix != std::string::npos && suffix + 1 < base.size() &&
            std::all_of(base.begin() + static_cast<std::ptrdiff_t>(suffix + 1), base.end(), [](char ch) {
                return std::isdigit(static_cast<unsigned char>(ch));
            }))
            base.erase(suffix);
        static const std::set<std::string> ProvenRoles{
            "activated_signal", "animation", "animation_id", "animation_played_signal", "animation_track",
            "animation_tracks", "animator", "attribute_value", "attributes", "callback", "cframe", "changed_signal",
            "character", "character_added_signal", "child", "child_added_signal", "child_removed_signal", "children",
            "color", "condition", "connection", "current_camera", "decoded_value", "delta_time", "descendant",
            "descendants", "enabled", "frame", "game_processed", "health", "heartbeat_signal", "hit", "humanoid",
            "humanoid_root_part", "input", "json", "key_code",
            "local_player", "magnitude", "mouse", "name", "number", "parent", "part", "player", "players",
            "position", "raycast_result", "remote_event", "render_stepped_signal", "screen_gui", "signal", "size",
            "task", "text", "text_label", "time", "transparency", "tween", "udim", "udim2", "user_id",
            "user_input_type", "values", "vector2", "vector3", "workspace", "x", "y", "z",
        };
        if (ProvenRoles.contains(base))
            return base;
        return "forwarded_value";
    }
    return std::nullopt;
}

std::optional<std::pair<std::string, bool>> staticIndex(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    if (!expression)
        return std::nullopt;

    if (auto integer = expression->as<Luau::AstExprConstantInteger>())
    {
        const double value = static_cast<double>(integer->value);
        return std::pair{"number:" + std::to_string(std::bit_cast<uint64_t>(value)), integer->value == 1};
    }

    if (auto number = expression->as<Luau::AstExprConstantNumber>())
    {
        const uint64_t bits = std::bit_cast<uint64_t>(number->value);
        return std::pair{"number:" + std::to_string(bits), number->value == 1.0};
    }

    if (auto string = expression->as<Luau::AstExprConstantString>())
        return std::pair{"string:" + std::string(string->value.data, string->value.size), false};

    if (auto boolean = expression->as<Luau::AstExprConstantBool>())
        return std::pair{boolean->value ? "boolean:true" : "boolean:false", false};

    if (expression->is<Luau::AstExprConstantNil>())
        return std::pair{"nil", false};

    return std::nullopt;
}

void noteStaticIndex(Candidate& candidate, std::string key, bool is_one)
{
    candidate.saw_index = true;
    candidate.all_indices_are_one = candidate.all_indices_are_one && is_one;
    candidate.static_indices.insert(std::move(key));
    candidate.multi_index = candidate.multi_index || candidate.static_indices.size() > 1;
}

void addNameEvidence(Candidate& candidate, std::string role, double weight)
{
    if (!role.empty() && role != "value")
        candidate.name_scores[std::move(role)] += weight;
}

void noteIndex(Candidate& candidate, Luau::AstExpr* index, bool dynamic_is_multi_index)
{
    if (std::optional<std::pair<std::string, bool>> value = staticIndex(index))
        noteStaticIndex(candidate, std::move(value->first), value->second);
    else
    {
        candidate.saw_index = true;
        candidate.all_indices_are_one = false;
        candidate.multi_index = candidate.multi_index || dynamic_is_multi_index;
    }
}

void noteAssignedValue(Candidate& candidate, Luau::AstExpr* value)
{
    if (isFunctionValue(value))
    {
        candidate.callback = true;
        if (auto function = unwrapTransparent(value)->as<Luau::AstExprFunction>();
            function && std::find(candidate.function_values.begin(), candidate.function_values.end(), function) ==
                candidate.function_values.end())
            candidate.function_values.push_back(function);
    }
    else
    {
        Luau::AstExpr* assigned = unwrapTransparent(value);
        if (!assigned || !assigned->is<Luau::AstExprConstantNil>())
            candidate.callback_role_conflict = true;
    }

    value = unwrapTransparent(value);
    if (std::optional<std::string> role = assignedValueRole(value); role && *role != "value")
    {
        candidate.value_roles.insert(*role);
        addNameEvidence(candidate, std::move(*role), 5.0);
    }
    else if (value && !value->is<Luau::AstExprConstantNil>())
        ++candidate.unknown_value_assignments;
    if (auto table = value ? value->as<Luau::AstExprTable>() : nullptr)
    {
        candidate.saw_table_assignment = true;
        const bool empty = table->items.size == 0;
        const bool nil_slot = table->items.size == 1 &&
            table->items.data[0].kind == Luau::AstExprTable::Item::Kind::List &&
            unwrapTransparent(table->items.data[0].value)->is<Luau::AstExprConstantNil>();
        candidate.cell_shape_compatible = candidate.cell_shape_compatible && (empty || nil_slot);
    }
    else if (value && !value->is<Luau::AstExprConstantNil>())
    {
        candidate.table_shape_compatible = false;
        candidate.cell_shape_compatible = false;
    }
}

class DirectReturnCollector final : public Luau::AstVisitor
{
public:
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

std::string functionNameForReturnRole(std::string_view role)
{
    if (role == "condition")
        return "check_condition";
    if (role == "number")
        return "calculate_number";
    if (role == "text")
        return "build_text";
    if (role == "values" || role == "children" || role == "descendants" || role == "players" ||
        role == "attributes")
        return "build_" + std::string(role);
    if (role == "callback")
        return {};
    return "get_" + std::string(role);
}

class UsageCollector final : public Luau::AstVisitor
{
public:
    UsageCollector(std::vector<Candidate>& candidates, const std::unordered_set<Luau::AstStatLocal*>& removed_declarations)
        : candidates(candidates)
        , removed_declarations(removed_declarations)
    {
        for (size_t index = 0; index < candidates.size(); ++index)
            by_local.emplace(candidates[index].local, index);
    }

    void finish()
    {
        for (Candidate& candidate : candidates)
            noteFunctionReturnBehavior(candidate);

        for (const CallbackUse& use : callback_uses)
        {
            Luau::AstExprFunction* function = use.function;
            if (!function && use.callback_local)
            {
                Candidate* callback = find(use.callback_local);
                if (!callback || callback->function_values.size() != 1)
                    continue;
                function = callback->function_values.front();
            }
            noteCallbackParameters(function, use.signal);
        }
    }

    bool visit(Luau::AstExprLocal* node) override
    {
        if (Candidate* candidate = find(node->local))
            candidate->occurrences.push_back(node->location);
        return true;
    }

    bool visit(Luau::AstExprUnary* node) override
    {
        if (node->op == Luau::AstExprUnary::Op::Not)
            noteCondition(node->expr);
        return true;
    }

    bool visit(Luau::AstExprIfElse* node) override
    {
        noteCondition(node->condition);
        return true;
    }

    bool visit(Luau::AstStatIf* node) override
    {
        noteCondition(node->condition);
        return true;
    }

    bool visit(Luau::AstStatWhile* node) override
    {
        noteCondition(node->condition);
        return true;
    }

    bool visit(Luau::AstStatRepeat* node) override
    {
        noteCondition(node->condition);
        return true;
    }

    bool visit(Luau::AstExprIndexExpr* node) override
    {
        if (Luau::AstExprLocal* base = directLocal(node->expr))
            if (Candidate* candidate = find(base->local))
            {
                noteIndex(*candidate, node->index, true);
                candidate->usage_roles.insert("values");
                addNameEvidence(*candidate, "values", 3.0);
            }
        return true;
    }

    bool visit(Luau::AstExprCall* node) override
    {
        if (Luau::AstExprLocal* callee = directLocal(node->func))
            if (Candidate* candidate = find(callee->local))
            {
                candidate->callback = true;
                candidate->usage_roles.insert("callback");
                addNameEvidence(*candidate, "callback", 6.0);
            }
        auto noteArgument = [&](size_t index, std::string role, double weight) {
            if (index >= node->args.size)
                return;
            if (Luau::AstExprLocal* argument = directLocal(node->args.data[index]))
                if (Candidate* candidate = find(argument->local))
                {
                    candidate->usage_roles.insert(role);
                    addNameEvidence(*candidate, std::move(role), weight);
                }
        };
        if (auto global = unwrapTransparent(node->func)->as<Luau::AstExprGlobal>(); global && global->name.value)
        {
            const std::string_view name(global->name.value);
            if (name == "pcall" || name == "xpcall")
                noteArgument(0, "protected_action", 10.0);
            else if (name == "ipairs" || name == "pairs" || name == "next")
                noteArgument(0, "values", 4.0);
        }
        if (auto method = unwrapTransparent(node->func)->as<Luau::AstExprIndexName>(); method && method->index.value)
        {
            const std::string_view method_name(method->index.value);
            if (method_name == "Connect" || method_name == "Once")
            {
                if (std::optional<std::string> purpose = callbackPurposeFromSignal(method->expr))
                    noteArgument(0, *purpose, 12.0);
                else
                    noteArgument(0, "event_handler", 8.0);

                if (node->args.size > 0)
                    if (std::optional<std::string> signal = signalIdentifier(method->expr))
                    {
                        Luau::AstExpr* callback = unwrapTransparent(node->args.data[0]);
                        if (auto local = callback ? callback->as<Luau::AstExprLocal>() : nullptr)
                            callback_uses.push_back({local->local, nullptr, *signal});
                        else if (auto function = callback ? callback->as<Luau::AstExprFunction>() : nullptr)
                            callback_uses.push_back({nullptr, function, *signal});
                    }
            }
            if (auto receiver = unwrapTransparent(method->expr)->as<Luau::AstExprGlobal>();
                receiver && receiver->name.value)
            {
                const std::string_view receiver_name(receiver->name.value);
                if (receiver_name == "task" &&
                    (method_name == "spawn" || method_name == "defer" || method_name == "delay"))
                    noteArgument(method_name == "delay" ? 1 : 0,
                        method_name == "spawn" ? "background_task" :
                        method_name == "defer" ? "deferred_task" : "delayed_task", 10.0);
                else if (receiver_name == "table" &&
                    (method_name == "insert" || method_name == "remove" || method_name == "sort" ||
                        method_name == "clear"))
                    noteArgument(0, "values", 4.0);
            }
            if (Luau::AstExprLocal* receiver = directLocal(method->expr))
                if (Candidate* candidate = find(receiver->local))
                {
                    const std::string_view name(method_name);
                    if (name == "Disconnect")
                    {
                        candidate->usage_roles.insert("connection");
                        addNameEvidence(*candidate, "connection", 5.0);
                    }
                    else if (name == "FireServer" || name == "FireClient" || name == "FireAllClients")
                    {
                        candidate->usage_roles.insert("remote_event");
                        addNameEvidence(*candidate, "remote_event", 6.0);
                    }
                    else if (name == "Connect" || name == "Once" || name == "Wait")
                    {
                        candidate->usage_roles.insert("signal");
                        addNameEvidence(*candidate, "signal", 5.0);
                    }
                    else if (name == "AdjustSpeed" || name == "Play" || name == "Stop")
                    {
                        candidate->usage_roles.insert("animation_track");
                        addNameEvidence(*candidate, "animation_track", 5.0);
                    }
                    else
                    {
                        candidate->usage_roles.insert("object");
                        addNameEvidence(*candidate, "object", 2.0);
                    }
                }
        }
        return true;
    }

    bool visit(Luau::AstExprBinary* node) override
    {
        std::optional<std::pair<std::string, double>> evidence;
        switch (node->op)
        {
        case Luau::AstExprBinary::Concat: evidence = std::pair{"text", 4.0}; break;
        case Luau::AstExprBinary::Add:
        case Luau::AstExprBinary::Sub:
        case Luau::AstExprBinary::Mul:
        case Luau::AstExprBinary::Div:
        case Luau::AstExprBinary::FloorDiv:
        case Luau::AstExprBinary::Mod:
        case Luau::AstExprBinary::Pow: evidence = std::pair{"number", 3.0}; break;
        default: break;
        }
        if (evidence)
            for (Luau::AstExpr* operand : {node->left, node->right})
                if (Luau::AstExprLocal* local = directLocal(operand))
                    if (Candidate* candidate = find(local->local))
                    {
                        candidate->usage_roles.insert(evidence->first);
                        addNameEvidence(*candidate, evidence->first, evidence->second);
                    }
        return true;
    }

    bool visit(Luau::AstExprIndexName* node) override
    {
        if (node->index.value)
            if (Luau::AstExprLocal* receiver = directLocal(node->expr))
                if (Candidate* candidate = find(receiver->local))
                {
                    const std::string_view property(node->index.value);
                    if (property == "Character" || property == "CharacterAdded" || property == "CharacterRemoving" || property == "UserId")
                    {
                        candidate->usage_roles.insert("player");
                        addNameEvidence(*candidate, "player", 4.0);
                    }
                    else if (property == "Health" || property == "WalkSpeed")
                    {
                        candidate->usage_roles.insert("humanoid");
                        addNameEvidence(*candidate, "humanoid", 5.0);
                    }
                    else if (property == "CanCollide" || property == "CanQuery" || property == "CanTouch" ||
                        property == "CustomPhysicalProperties")
                    {
                        candidate->usage_roles.insert("part");
                        addNameEvidence(*candidate, "part", 4.0);
                    }
                    else if (property == "MouseButton1Click" || property == "Activated")
                    {
                        candidate->usage_roles.insert("text_button");
                        addNameEvidence(*candidate, "text_button", 5.0);
                    }
                    else if (property == "Text" || property == "TextColor3" || property == "TextSize" ||
                        property == "TextTransparency")
                    {
                        candidate->usage_roles.insert("text_label");
                        addNameEvidence(*candidate, "text_label", 3.0);
                    }
                    else if (property == "Anchored" || property == "AssemblyLinearVelocity" ||
                        property == "AssemblyAngularVelocity")
                    {
                        candidate->usage_roles.insert("part");
                        addNameEvidence(*candidate, "part", 4.0);
                    }
                    else
                    {
                        candidate->usage_roles.insert("object");
                        addNameEvidence(*candidate, "object", 2.0);
                    }
                }
        return true;
    }

    bool visit(Luau::AstStatLocal* node) override
    {
        if (removed_declarations.contains(node))
            return false;

        const size_t count = std::min(node->vars.size, node->values.size);
        for (size_t index = 0; index < count; ++index)
            if (Candidate* candidate = find(node->vars.data[index]))
                noteAssignedValue(*candidate, node->values.data[index]);
        return true;
    }

    bool visit(Luau::AstStatAssign* node) override
    {
        const size_t count = std::min(node->vars.size, node->values.size);
        for (size_t index = 0; index < count; ++index)
        {
            if (Luau::AstExprLocal* target = directLocal(node->vars.data[index]))
                if (Candidate* candidate = find(target->local))
                    noteAssignedValue(*candidate, node->values.data[index]);
            if (Luau::AstExprLocal* value = directLocal(node->values.data[index]))
                if (Candidate* candidate = find(value->local))
                    if (auto property = unwrapTransparent(node->vars.data[index])->as<Luau::AstExprIndexName>();
                        property && property->index.value)
                    {
                        const std::string role = snakeCase(property->index.value) + "_hook";
                        candidate->usage_roles.insert(role);
                        addNameEvidence(*candidate, role, 12.0);
                    }
        }
        return true;
    }

    bool visit(Luau::AstStatFunction* node) override
    {
        if (Luau::AstExprLocal* target = directLocal(node->name))
            if (Candidate* candidate = find(target->local))
            {
                candidate->callback = true;
                noteFunctionValue(*candidate, node->func);
            }
        return true;
    }

    bool visit(Luau::AstStatLocalFunction* node) override
    {
        if (Candidate* candidate = find(node->name))
        {
            candidate->callback = true;
            noteFunctionValue(*candidate, node->func);
        }
        return true;
    }

    bool visit(Luau::AstType*) override
    {
        return true;
    }

private:
    struct CallbackUse
    {
        Luau::AstLocal* callback_local = nullptr;
        Luau::AstExprFunction* function = nullptr;
        std::string signal;
    };

    std::vector<Candidate>& candidates;
    const std::unordered_set<Luau::AstStatLocal*>& removed_declarations;
    std::unordered_map<Luau::AstLocal*, size_t> by_local;
    std::vector<CallbackUse> callback_uses;

    Candidate* find(Luau::AstLocal* local)
    {
        const auto found = by_local.find(local);
        return found == by_local.end() ? nullptr : &candidates[found->second];
    }

    static void noteFunctionValue(Candidate& candidate, Luau::AstExprFunction* function)
    {
        if (function && std::find(candidate.function_values.begin(), candidate.function_values.end(), function) ==
                candidate.function_values.end())
            candidate.function_values.push_back(function);
    }

    std::optional<std::string> provenCandidateRole(Candidate& candidate)
    {
        std::set<std::string> roles;
        for (const std::string& role : candidate.value_roles)
            if (role != "callback" && role != "forwarded_value" && role != "object")
                roles.insert(role);
        for (const std::string& role : candidate.usage_roles)
            if (role != "callback" && role != "forwarded_value" && role != "object")
                roles.insert(role);
        if (roles.size() == 1)
            return *roles.begin();

        std::vector<std::pair<std::string, double>> ranked;
        for (const auto& [role, score] : candidate.name_scores)
            if (role != "callback" && role != "forwarded_value" && role != "object")
                ranked.emplace_back(role, score);
        std::sort(ranked.begin(), ranked.end(), [](const auto& left, const auto& right) {
            return left.second != right.second ? left.second > right.second : left.first < right.first;
        });
        if (!ranked.empty() && ranked[0].second >= 7.0 &&
            (ranked.size() == 1 || ranked[0].second - ranked[1].second >= 3.0))
            return ranked[0].first;
        return std::nullopt;
    }

    std::optional<std::string> provenExpressionRole(Luau::AstExpr* expression)
    {
        if (std::optional<std::string> role = assignedValueRole(expression);
            role && *role != "forwarded_value" && *role != "callback" && *role != "object")
            return role;
        if (Luau::AstExprLocal* local = directLocal(expression))
            if (Candidate* candidate = find(local->local))
                return provenCandidateRole(*candidate);
        return std::nullopt;
    }

    void noteFunctionReturnBehavior(Candidate& candidate)
    {
        if (!hasDecimalSuffix(candidate.original_name, "function_") || candidate.function_values.size() != 1)
            return;

        DirectReturnCollector returns;
        candidate.function_values.front()->body->visit(&returns);
        std::set<std::string> roles;
        bool saw_value_return = false;
        bool unresolved = false;
        for (Luau::AstStatReturn* statement : returns.returns)
        {
            if (statement->list.size == 0)
                continue;
            saw_value_return = true;
            std::optional<std::string> role = provenExpressionRole(statement->list.data[0]);
            if (!role)
                unresolved = true;
            else
                roles.insert(*role);
        }
        if (!saw_value_return || unresolved || roles.size() != 1)
            return;

        const std::string function_name = functionNameForReturnRole(*roles.begin());
        if (!function_name.empty())
            addNameEvidence(candidate, function_name, 10.0);
    }

    void noteCallbackParameters(Luau::AstExprFunction* function, std::string_view signal)
    {
        if (!function)
            return;
        const std::vector<std::string> roles = callbackParameterRoles(signal);
        const size_t count = std::min(function->args.size, roles.size());
        for (size_t index = 0; index < count; ++index)
            if (Candidate* candidate = find(function->args.data[index]))
            {
                candidate->usage_roles.insert(roles[index]);
                addNameEvidence(*candidate, roles[index], 14.0);
            }
    }

    void noteCondition(Luau::AstExpr* expression)
    {
        if (Luau::AstExprLocal* local = directLocal(expression))
            if (Candidate* candidate = find(local->local))
            {
                candidate->usage_roles.insert("condition");
                addNameEvidence(*candidate, "condition", 5.0);
            }
    }

};

class LocalReferenceCounter final : public Luau::AstVisitor
{
public:
    std::unordered_map<Luau::AstLocal*, size_t> counts;

    bool visit(Luau::AstExprLocal* node) override
    {
        ++counts[node->local];
        return true;
    }

    bool visit(Luau::AstType*) override
    {
        return true;
    }
};

bool safeUnusedInitializer(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    if (!expression)
        return false;

    if (expression->is<Luau::AstExprLocal>() || expression->is<Luau::AstExprConstantNil>() ||
        expression->is<Luau::AstExprConstantBool>() || expression->is<Luau::AstExprConstantNumber>() ||
        expression->is<Luau::AstExprConstantInteger>() || expression->is<Luau::AstExprConstantString>())
        return true;

    if (auto interpolated = expression->as<Luau::AstExprInterpString>())
        return interpolated->expressions.size == 0;

    if (auto unary = expression->as<Luau::AstExprUnary>())
    {
        Luau::AstExpr* operand = unwrapTransparent(unary->expr);
        return unary->op == Luau::AstExprUnary::Op::Minus && operand &&
            (operand->is<Luau::AstExprConstantNumber>() || operand->is<Luau::AstExprConstantInteger>());
    }
    return false;
}

struct CleanupPlan
{
    std::vector<Luau::AstStatLocal*> statements;
    std::unordered_set<Luau::AstStatLocal*> statement_set;
};

struct DeclaratorCleanup
{
    Luau::AstStatLocal* statement = nullptr;
    std::vector<Luau::AstLocal*> removed;
};

std::vector<DeclaratorCleanup> planUnusedUninitializedDeclarators(
    Luau::AstStatBlock* root,
    const BindingCollector& bindings,
    const CleanupPlan& statement_cleanup)
{
    LocalReferenceCounter references;
    root->visit(&references);

    std::vector<DeclaratorCleanup> result;
    for (Luau::AstStatLocal* statement : bindings.local_statements)
    {
        if (!statement || statement_cleanup.statement_set.contains(statement) || statement->values.size != 0 ||
            statement->isConst || statement->isExported)
            continue;

        DeclaratorCleanup cleanup;
        cleanup.statement = statement;
        bool simple = true;
        for (Luau::AstLocal* local : statement->vars)
        {
            if (!local || local->annotation || local->isConst || local->isExported || !local->name.value)
            {
                simple = false;
                break;
            }
            if ((candidateFamily(local->name.value) || residualCandidateFamily(local->name.value)) &&
                references.counts[local] == 0)
                cleanup.removed.push_back(local);
        }
        if (simple && !cleanup.removed.empty())
            result.push_back(std::move(cleanup));
    }
    return result;
}

CleanupPlan planUnusedDeclarationCleanup(Luau::AstStatBlock* root, const BindingCollector& bindings)
{
    LocalReferenceCounter all_references;
    root->visit(&all_references);

    struct Eligible
    {
        LocalDeclaration declaration;
        std::unordered_map<Luau::AstLocal*, size_t> contained_references;
        bool remove = false;
    };

    std::vector<Eligible> eligible;
    std::unordered_map<Luau::AstLocal*, size_t> by_local;
    for (const LocalDeclaration& declaration : bindings.local_declarations)
    {
        Luau::AstStatLocal* statement = declaration.statement;
        if (!statement || statement->vars.size != 1 || statement->values.size != 1 || statement->isExported ||
            declaration.local->isExported || !safeUnusedInitializer(statement->values.data[0]))
            continue;

        LocalReferenceCounter contained;
        statement->visit(&contained);
        by_local.emplace(declaration.local, eligible.size());
        eligible.push_back({declaration, std::move(contained.counts), false});
    }

    std::vector<size_t> queue;
    for (size_t index = 0; index < eligible.size(); ++index)
        if (!all_references.counts.contains(eligible[index].declaration.local) ||
            all_references.counts[eligible[index].declaration.local] == 0)
            queue.push_back(index);

    for (size_t next = 0; next < queue.size(); ++next)
    {
        Eligible& declaration = eligible[queue[next]];
        if (declaration.remove || all_references.counts[declaration.declaration.local] != 0)
            continue;
        declaration.remove = true;

        for (const auto& [referenced, count] : declaration.contained_references)
        {
            size_t& remaining = all_references.counts[referenced];
            remaining = count > remaining ? 0 : remaining - count;
            if (remaining == 0)
                if (auto found = by_local.find(referenced); found != by_local.end())
                    queue.push_back(found->second);
        }
    }

    CleanupPlan plan;
    for (const Eligible& declaration : eligible)
        if (declaration.remove)
        {
            plan.statements.push_back(declaration.declaration.statement);
            plan.statement_set.insert(declaration.declaration.statement);
        }
    return plan;
}

bool locationEncloses(const Luau::Location& outer, const Luau::Location& inner)
{
    return outer.begin <= inner.begin && inner.end <= outer.end;
}

bool insideRemovedDeclaration(const Luau::Location& location, const CleanupPlan& cleanup)
{
    return std::any_of(cleanup.statements.begin(), cleanup.statements.end(), [&](Luau::AstStatLocal* statement) {
        return locationEncloses(statement->location, location);
    });
}

BindingRole inferRole(Candidate& candidate)
{
    if (candidate.multi_index && candidate.saw_table_assignment && candidate.table_shape_compatible)
        return BindingRole::Registers;
    if (candidate.saw_index && candidate.all_indices_are_one && candidate.saw_table_assignment &&
        candidate.cell_shape_compatible)
        return BindingRole::MutableCell;
    if (candidate.callback && !candidate.callback_role_conflict && candidate.unknown_value_assignments == 0 &&
        (candidate.value_roles.empty() ||
            (candidate.value_roles.size() == 1 && candidate.value_roles.contains("callback"))))
    {
        std::pair<std::string, double> purpose;
        for (const auto& [role, score] : candidate.name_scores)
            if (role != "callback" && score > purpose.second)
                purpose = {role, score};
        if (!purpose.first.empty() && purpose.second >= 8.0)
        {
            candidate.semantic_base = purpose.first;
            candidate.semantic_confidence = 1.0;
            return BindingRole::SemanticValue;
        }
        return BindingRole::Callback;
    }
    if (candidate.value_roles.size() == 1 && candidate.unknown_value_assignments == 0)
    {
        if (candidate.value_roles.contains("callback") && !candidate.callback &&
            !candidate.usage_roles.contains("callback"))
            return candidate.family == CandidateFamily::Temporary ? BindingRole::VmTemporary : BindingRole::VmValue;
        candidate.semantic_base = *candidate.value_roles.begin();
        return BindingRole::SemanticValue;
    }
    if (candidate.value_roles.empty() && candidate.usage_roles.size() == 1)
    {
        candidate.semantic_base = *candidate.usage_roles.begin();
        candidate.semantic_confidence = 1.0;
        return BindingRole::SemanticValue;
    }
    if (!candidate.name_scores.empty())
    {
        std::vector<std::pair<std::string, double>> ranked(candidate.name_scores.begin(), candidate.name_scores.end());
        std::sort(ranked.begin(), ranked.end(), [](const auto& left, const auto& right) {
            return left.second != right.second ? left.second > right.second : left.first < right.first;
        });
        const double second = ranked.size() > 1 ? ranked[1].second : 0.0;
        const bool corroborated = candidate.value_roles.contains(ranked[0].first) &&
            candidate.usage_roles.contains(ranked[0].first);
        const bool unsafe_callback_guess = ranked[0].first == "callback" &&
            (!candidate.usage_roles.contains("callback") || candidate.callback_role_conflict);
        const bool mixed_roles = candidate.value_roles.size() > 1;
        const double required_score = mixed_roles ? 8.0 : 7.0;
        const double required_margin = 3.0;
        if (ranked[0].second >= required_score && ranked[0].second - second >= required_margin &&
            !unsafe_callback_guess && (candidate.unknown_value_assignments <= 1 || corroborated) &&
            (!mixed_roles || corroborated))
        {
            candidate.semantic_base = ranked[0].first;
            candidate.semantic_confidence = ranked[0].second / (ranked[0].second + second + 1.0);
            return BindingRole::SemanticValue;
        }
    }
    return candidate.family == CandidateFamily::Temporary ? BindingRole::VmTemporary : BindingRole::VmValue;
}

std::string_view roleBase(BindingRole role)
{
    switch (role)
    {
    case BindingRole::Registers: return "registers";
    case BindingRole::MutableCell: return "state_cell";
    case BindingRole::Callback: return "callback";
    case BindingRole::SemanticValue: return "value";
    case BindingRole::VmValue: return "vm_value";
    case BindingRole::VmTemporary: return "vm_temporary";
    }
    return "vm_value";
}

std::set<std::string> collectOccupiedNames(std::string_view source)
{
    Luau::Allocator allocator;
    Luau::AstNameTable names(allocator);
    Luau::Lexer lexer(source.data(), source.size(), names);
    lexer.setSkipComments(true);

    std::set<std::string> occupied;
    for (;;)
    {
        const Luau::Lexeme& token = lexer.next();
        if (token.type == Luau::Lexeme::Eof)
            break;
        if (token.type == Luau::Lexeme::Name && token.name)
            occupied.emplace(token.name);
    }
    return occupied;
}

class FreshNameAllocator
{
public:
    explicit FreshNameAllocator(std::set<std::string> occupied)
        : occupied(std::move(occupied))
    {
    }

    std::string allocate(const Candidate& candidate)
    {
        const std::string base = candidate.role == BindingRole::SemanticValue
            ? candidate.semantic_base
            : std::string(roleBase(candidate.role));
        size_t& ordinal = ordinals[base];
        for (;;)
        {
            ++ordinal;
            const std::string name = candidate.role == BindingRole::SemanticValue && ordinal == 1
                ? base
                : base + "_" + std::to_string(ordinal);
            if (!Luau::Lexer::isReserved(name) && occupied.insert(name).second)
                return name;
        }
    }

private:
    std::set<std::string> occupied;
    std::map<std::string, size_t> ordinals;
};

class SourceOffsets
{
public:
    explicit SourceOffsets(std::string_view source)
        : source(source)
    {
        line_starts.push_back(0);
        for (size_t index = 0; index < source.size(); ++index)
            if (source[index] == '\n')
                line_starts.push_back(index + 1);
    }

    std::optional<size_t> offset(const Luau::Position& position) const
    {
        if (!position.hasValue() || position.line >= line_starts.size())
            return std::nullopt;

        const size_t line_start = line_starts[position.line];
        const size_t line_end = position.line + 1 < line_starts.size() ? line_starts[position.line + 1] - 1 : source.size();
        if (position.column > line_end - line_start)
            return std::nullopt;
        return line_start + position.column;
    }

private:
    std::string_view source;
    std::vector<size_t> line_starts;
};

struct Edit
{
    size_t begin = 0;
    size_t end = 0;
    std::string replacement;
    Luau::Location location;
};

class LexicalAliasFacts final : public Luau::AstVisitor
{
public:
    std::vector<Luau::AstStatBlock*> blocks;
    std::vector<Luau::AstExprFunction*> functions;
    std::vector<Luau::Location> loops;
    std::vector<Luau::AstLocal*> locals;
    std::unordered_map<Luau::AstLocal*, std::vector<Luau::AstExprLocal*>> occurrences;
    std::unordered_map<Luau::AstLocal*, std::vector<Luau::AstExprLocal*>> reads;
    std::unordered_map<Luau::AstLocal*, std::vector<Luau::Location>> writes;

    bool visit(Luau::AstStatBlock* node) override
    {
        blocks.push_back(node);
        return true;
    }

    bool visit(Luau::AstExprFunction* node) override
    {
        functions.push_back(node);
        addLocal(node->self);
        for (Luau::AstLocal* local : node->args)
            addLocal(local);
        return true;
    }

    bool visit(Luau::AstStatLocal* node) override
    {
        for (Luau::AstLocal* local : node->vars)
            addLocal(local);
        return true;
    }

    bool visit(Luau::AstStatLocalFunction* node) override
    {
        addLocal(node->name);
        return true;
    }

    bool visit(Luau::AstStatFor* node) override
    {
        loops.push_back(node->location);
        addLocal(node->var);
        return true;
    }

    bool visit(Luau::AstStatForIn* node) override
    {
        loops.push_back(node->location);
        for (Luau::AstLocal* local : node->vars)
            addLocal(local);
        return true;
    }

    bool visit(Luau::AstStatWhile* node) override
    {
        loops.push_back(node->location);
        return true;
    }

    bool visit(Luau::AstStatRepeat* node) override
    {
        loops.push_back(node->location);
        return true;
    }

    bool visit(Luau::AstStatAssign* node) override
    {
        for (Luau::AstExpr* variable : node->vars)
            if (Luau::AstExprLocal* local = directLocal(variable))
            {
                writes[local->local].push_back(local->location);
                assignment_targets.insert(local);
            }
        return true;
    }

    bool visit(Luau::AstStatCompoundAssign* node) override
    {
        if (Luau::AstExprLocal* local = directLocal(node->var))
            writes[local->local].push_back(local->location);
        return true;
    }

    bool visit(Luau::AstExprLocal* node) override
    {
        occurrences[node->local].push_back(node);
        if (!assignment_targets.contains(node))
            reads[node->local].push_back(node);
        return true;
    }

    bool captured(Luau::AstLocal* local) const
    {
        auto found = reads.find(local);
        if (found == reads.end())
            return false;
        for (Luau::AstExprLocal* read : found->second)
            for (Luau::AstExprFunction* function : functions)
                if (function->functionDepth > local->functionDepth &&
                    locationEncloses(function->location, read->location))
                    return true;
        return false;
    }

    bool capturedWrite(Luau::AstLocal* local) const
    {
        auto found = writes.find(local);
        if (found == writes.end())
            return false;
        for (const Luau::Location& write : found->second)
            for (Luau::AstExprFunction* function : functions)
                if (function->functionDepth > local->functionDepth &&
                    locationEncloses(function->location, write))
                    return true;
        return false;
    }

    bool writesInside(Luau::AstStat* statement, Luau::AstLocal* local) const
    {
        auto found = writes.find(local);
        if (found == writes.end())
            return false;
        return std::any_of(found->second.begin(), found->second.end(), [&](const Luau::Location& write) {
            return locationEncloses(statement->location, write);
        });
    }

    std::vector<Luau::AstExprLocal*> readsInside(Luau::AstStat* statement, Luau::AstLocal* local) const
    {
        std::vector<Luau::AstExprLocal*> result;
        auto found = reads.find(local);
        if (found == reads.end())
            return result;
        for (Luau::AstExprLocal* read : found->second)
            if (locationEncloses(statement->location, read->location))
                result.push_back(read);
        return result;
    }

    bool insideLoop(const Luau::Location& location) const
    {
        return std::any_of(loops.begin(), loops.end(), [&](const Luau::Location& loop) {
            return locationEncloses(loop, location);
        });
    }

private:
    std::unordered_set<Luau::AstExprLocal*> assignment_targets;
    std::unordered_set<Luau::AstLocal*> seen_locals;

    void addLocal(Luau::AstLocal* local)
    {
        if (local && seen_locals.insert(local).second)
            locals.push_back(local);
    }
};

struct LexicalAliasDefinition
{
    Luau::AstLocal* target = nullptr;
    Luau::AstLocal* source = nullptr;
    bool local_declaration = false;
};

std::optional<LexicalAliasDefinition> lexicalAliasDefinition(Luau::AstStat* statement)
{
    if (auto assignment = statement->as<Luau::AstStatAssign>())
    {
        if (assignment->vars.size != 1 || assignment->values.size != 1)
            return std::nullopt;
        Luau::AstExprLocal* target = directLocal(assignment->vars.data[0]);
        Luau::AstExprLocal* source = directLocal(assignment->values.data[0]);
        if (!target || !source || target->local == source->local)
            return std::nullopt;
        return LexicalAliasDefinition{target->local, source->local, false};
    }
    if (auto declaration = statement->as<Luau::AstStatLocal>())
    {
        if (declaration->vars.size != 1 || declaration->values.size != 1 || declaration->isConst ||
            declaration->isExported || declaration->vars.data[0]->annotation)
            return std::nullopt;
        Luau::AstExprLocal* source = directLocal(declaration->values.data[0]);
        if (!source || declaration->vars.data[0] == source->local)
            return std::nullopt;
        return LexicalAliasDefinition{declaration->vars.data[0], source->local, true};
    }
    return std::nullopt;
}

bool unconditionalOverwriteWithoutRead(
    Luau::AstStat* statement,
    Luau::AstLocal* target,
    const LexicalAliasFacts& facts)
{
    auto assignment = statement->as<Luau::AstStatAssign>();
    if (!assignment || assignment->vars.size != 1 || assignment->values.size != 1)
        return false;
    Luau::AstExprLocal* written = directLocal(assignment->vars.data[0]);
    return written && written->local == target && facts.readsInside(statement, target).empty();
}

bool straightLineBlockOverwriteWithoutRead(
    Luau::AstStat* statement,
    Luau::AstLocal* target,
    const LexicalAliasFacts& facts)
{
    auto block = statement->as<Luau::AstStatBlock>();
    if (!block)
        return false;

    for (Luau::AstStat* child : block->body)
    {
        if (!facts.readsInside(child, target).empty())
            return false;
        if (facts.writesInside(child, target))
            return unconditionalOverwriteWithoutRead(child, target, facts);
    }
    return false;
}

Luau::AstStat* innermostStatementContaining(
    const LexicalAliasFacts& facts,
    const Luau::Location& location)
{
    Luau::AstStat* result = nullptr;
    for (Luau::AstStatBlock* block : facts.blocks)
        for (Luau::AstStat* statement : block->body)
            if (locationEncloses(statement->location, location) &&
                (!result || locationEncloses(result->location, statement->location)))
                result = statement;
    return result;
}

bool readFeedsSimpleOverwrite(
    const LexicalAliasFacts& facts,
    Luau::AstLocal* source,
    const Luau::Location& write,
    const Luau::Location& read)
{
    Luau::AstStat* statement = innermostStatementContaining(facts, write);
    auto assignment = statement ? statement->as<Luau::AstStatAssign>() : nullptr;
    if (!assignment || assignment->vars.size != 1 || assignment->values.size != 1)
        return false;
    Luau::AstExprLocal* target = directLocal(assignment->vars.data[0]);
    return target && target->local == source &&
        locationEncloses(assignment->values.data[0]->location, read);
}

std::optional<std::string> coalesceOneProducerAliasVersion(std::string_view source)
{
    std::unique_ptr<ParseContext> parsed = parse(source);
    if (!parsed->result.root || !parsed->result.errors.empty())
        return std::nullopt;

    LexicalAliasFacts facts;
    parsed->result.root->visit(&facts);
    const SourceOffsets offsets(source);

    for (Luau::AstStatBlock* block : facts.blocks)
        for (size_t index = 0; index + 1 < block->body.size; ++index)
        {
            Luau::AstStat* producer_statement = block->body.data[index];
            auto producer = producer_statement->as<Luau::AstStatAssign>();
            if (!producer || producer->vars.size != 1 || producer->values.size != 1 ||
                !unwrapTransparent(producer->values.data[0])->is<Luau::AstExprFunction>())
                continue;
            Luau::AstExprLocal* source_lhs = directLocal(producer->vars.data[0]);
            if (!source_lhs || !source_lhs->local->name.value ||
                !aliasCandidateName(source_lhs->local->name.value))
                continue;
            if (!facts.readsInside(producer_statement, source_lhs->local).empty())
                continue;

            Luau::AstStat* alias_statement = block->body.data[index + 1];
            const std::optional<LexicalAliasDefinition> alias = lexicalAliasDefinition(alias_statement);
            if (!alias || alias->source != source_lhs->local || alias->target == alias->source ||
                !alias->target->name.value || aliasCandidateName(alias->target->name.value) ||
                alias->target->functionDepth != alias->source->functionDepth ||
                alias->target->loopDepth != 0 || alias->source->loopDepth != 0)
                continue;

            bool captured_outside_producer = false;
            if (auto reads = facts.reads.find(alias->source); reads != facts.reads.end())
                for (Luau::AstExprLocal* read : reads->second)
                    if (!locationEncloses(producer->values.data[0]->location, read->location))
                        for (Luau::AstExprFunction* function : facts.functions)
                            if (function->functionDepth > alias->source->functionDepth &&
                                locationEncloses(function->location, read->location))
                                captured_outside_producer = true;
            if (captured_outside_producer)
                continue;

            bool source_version_dead = true;
            for (size_t next = index + 2; next < block->body.size; ++next)
            {
                Luau::AstStat* following = block->body.data[next];
                if (!facts.readsInside(following, alias->source).empty())
                {
                    source_version_dead = false;
                    break;
                }
                if (facts.writesInside(following, alias->source))
                {
                    if (unconditionalOverwriteWithoutRead(following, alias->source, facts))
                        break;
                }
            }
            if (!source_version_dead)
                continue;

            const std::string source_name(alias->source->name.value);
            const std::string target_name(alias->target->name.value);
            const std::optional<size_t> lhs_begin = offsets.offset(source_lhs->location.begin);
            const std::optional<size_t> lhs_end = offsets.offset(source_lhs->location.end);
            const std::optional<size_t> alias_begin = offsets.offset(alias_statement->location.begin);
            const std::optional<size_t> alias_end = offsets.offset(alias_statement->location.end);
            if (!lhs_begin || !lhs_end || !alias_begin || !alias_end || *lhs_end < *lhs_begin ||
                *alias_end <= *alias_begin || *lhs_end - *lhs_begin != source_name.size() ||
                source.substr(*lhs_begin, *lhs_end - *lhs_begin) != source_name)
                continue;

            std::vector<Edit> edits;
            edits.push_back({*lhs_begin, *lhs_end,
                alias->local_declaration ? "local " + target_name : target_name, source_lhs->location});
            edits.push_back({*alias_begin, *alias_end, "", alias_statement->location});
            std::sort(edits.begin(), edits.end(), [](const Edit& left, const Edit& right) {
                return left.begin != right.begin ? left.begin < right.begin : left.end < right.end;
            });
            bool overlaps = false;
            for (size_t edit = 1; edit < edits.size(); ++edit)
                overlaps = overlaps || edits[edit].begin < edits[edit - 1].end;
            if (overlaps)
                continue;

            std::string rewritten(source);
            for (auto edit = edits.rbegin(); edit != edits.rend(); ++edit)
                rewritten.replace(edit->begin, edit->end - edit->begin, edit->replacement);
            std::unique_ptr<ParseContext> reparsed = parse(rewritten);
            if (reparsed->result.root && reparsed->result.errors.empty())
                return rewritten;
        }
    return std::nullopt;
}

bool deferredFunctionDefinition(Luau::AstStat* statement)
{
    if (statement->is<Luau::AstStatLocalFunction>())
        return true;
    if (auto assignment = statement->as<Luau::AstStatAssign>())
        return assignment->vars.size == 1 && assignment->values.size == 1 &&
            unwrapTransparent(assignment->values.data[0])->is<Luau::AstExprFunction>();
    if (auto declaration = statement->as<Luau::AstStatLocal>())
        return declaration->vars.size == 1 && declaration->values.size == 1 &&
            unwrapTransparent(declaration->values.data[0])->is<Luau::AstExprFunction>();
    return false;
}

std::optional<std::string> coalesceOneDeferredValueTransport(std::string_view source)
{
    std::unique_ptr<ParseContext> parsed = parse(source);
    if (!parsed->result.root || !parsed->result.errors.empty())
        return std::nullopt;

    LexicalAliasFacts facts;
    parsed->result.root->visit(&facts);
    const SourceOffsets offsets(source);

    for (Luau::AstStatBlock* block : facts.blocks)
        for (size_t producer_index = 0; producer_index + 2 < block->body.size; ++producer_index)
        {
            Luau::AstStat* producer_statement = block->body.data[producer_index];
            auto producer = producer_statement->as<Luau::AstStatAssign>();
            if (!producer || producer->vars.size != 1 || producer->values.size != 1)
                continue;
            Luau::AstExprLocal* source_lhs = directLocal(producer->vars.data[0]);
            if (!source_lhs || !source_lhs->local->name.value ||
                !aliasCandidateName(source_lhs->local->name.value) ||
                !facts.readsInside(producer_statement, source_lhs->local).empty() ||
                facts.captured(source_lhs->local))
                continue;

            for (size_t alias_index = producer_index + 2;
                 alias_index < block->body.size && alias_index <= producer_index + 4;
                 ++alias_index)
            {
                bool deferred_bridge = true;
                for (size_t bridge = producer_index + 1; bridge < alias_index; ++bridge)
                    deferred_bridge = deferred_bridge && deferredFunctionDefinition(block->body.data[bridge]) &&
                        facts.readsInside(block->body.data[bridge], source_lhs->local).empty();
                if (!deferred_bridge)
                    break;

                Luau::AstStat* alias_statement = block->body.data[alias_index];
                const std::optional<LexicalAliasDefinition> alias = lexicalAliasDefinition(alias_statement);
                if (!alias || alias->local_declaration || alias->source != source_lhs->local ||
                    alias->target == alias->source || !alias->target->name.value ||
                    aliasCandidateName(alias->target->name.value) ||
                    alias->target->functionDepth != alias->source->functionDepth ||
                    alias->target->loopDepth != 0 || alias->source->loopDepth != 0)
                    continue;

                bool source_version_dead = true;
                for (size_t next = alias_index + 1; next < block->body.size; ++next)
                {
                    Luau::AstStat* following = block->body.data[next];
                    if (!facts.readsInside(following, alias->source).empty())
                    {
                        source_version_dead = false;
                        break;
                    }
                    if (facts.writesInside(following, alias->source))
                    {
                        if (unconditionalOverwriteWithoutRead(following, alias->source, facts))
                            break;
                    }
                }
                if (!source_version_dead)
                    continue;

                const std::string source_name(alias->source->name.value);
                const std::string target_name(alias->target->name.value);
                const std::optional<size_t> lhs_begin = offsets.offset(source_lhs->location.begin);
                const std::optional<size_t> lhs_end = offsets.offset(source_lhs->location.end);
                const std::optional<size_t> alias_begin = offsets.offset(alias_statement->location.begin);
                const std::optional<size_t> alias_end = offsets.offset(alias_statement->location.end);
                if (!lhs_begin || !lhs_end || !alias_begin || !alias_end || *lhs_end < *lhs_begin ||
                    *alias_end <= *alias_begin || *lhs_end - *lhs_begin != source_name.size() ||
                    source.substr(*lhs_begin, *lhs_end - *lhs_begin) != source_name)
                    continue;

                std::string rewritten(source);
                rewritten.replace(*alias_begin, *alias_end - *alias_begin, "");
                rewritten.replace(*lhs_begin, *lhs_end - *lhs_begin, target_name);
                std::unique_ptr<ParseContext> reparsed = parse(rewritten);
                if (reparsed->result.root && reparsed->result.errors.empty())
                    return rewritten;
            }
        }
    return std::nullopt;
}

std::optional<std::string> eliminateOneProvenLexicalAlias(std::string_view source)
{
    std::unique_ptr<ParseContext> parsed = parse(source);
    if (!parsed->result.root || !parsed->result.errors.empty())
        return std::nullopt;

    LexicalAliasFacts facts;
    parsed->result.root->visit(&facts);

    std::unordered_map<Luau::AstLocal*, Luau::AstStatBlock*> declaration_blocks;
    for (Luau::AstStatBlock* block : facts.blocks)
        for (Luau::AstStat* statement : block->body)
            if (auto declaration = statement->as<Luau::AstStatLocal>())
                for (Luau::AstLocal* local : declaration->vars)
                    declaration_blocks.emplace(local, block);
            else if (auto function = statement->as<Luau::AstStatLocalFunction>())
                declaration_blocks.emplace(function->name, block);

    const SourceOffsets offsets(source);
    for (Luau::AstStatBlock* block : facts.blocks)
        for (size_t statement_index = 0; statement_index < block->body.size; ++statement_index)
        {
            Luau::AstStat* statement = block->body.data[statement_index];
            const std::optional<LexicalAliasDefinition> alias = lexicalAliasDefinition(statement);
            if (!alias || !alias->target->name.value || !alias->source->name.value ||
                !aliasCandidateName(alias->target->name.value) || alias->target->functionDepth != alias->source->functionDepth ||
                alias->target->loopDepth != 0 || alias->source->loopDepth != 0 ||
                facts.capturedWrite(alias->target) || facts.capturedWrite(alias->source))
                continue;
            const bool target_captured = facts.captured(alias->target);
            const auto target_declaration = declaration_blocks.find(alias->target);
            const bool target_declared_in_block = alias->local_declaration ||
                (target_declaration != declaration_blocks.end() && target_declaration->second == block);

            std::vector<Luau::AstExprLocal*> replace_reads;
            bool safe = true;
            bool later_overwrite = false;
            for (size_t next = statement_index + 1; next < block->body.size; ++next)
            {
                Luau::AstStat* following = block->body.data[next];
                if (facts.writesInside(following, alias->source))
                {
                    safe = false;
                    break;
                }
                if (facts.writesInside(following, alias->target))
                {
                    later_overwrite = unconditionalOverwriteWithoutRead(following, alias->target, facts);
                    safe = later_overwrite;
                    break;
                }
                std::vector<Luau::AstExprLocal*> reads = facts.readsInside(following, alias->target);
                replace_reads.insert(replace_reads.end(), reads.begin(), reads.end());
            }
            if (!safe || (target_captured && later_overwrite) || (!target_declared_in_block && !later_overwrite))
                continue;

            const std::optional<size_t> statement_begin = offsets.offset(statement->location.begin);
            const std::optional<size_t> statement_end = offsets.offset(statement->location.end);
            if (!statement_begin || !statement_end || *statement_end <= *statement_begin)
                continue;
            if (source.substr(*statement_begin, *statement_end - *statement_begin).find(';') != std::string_view::npos)
                continue;
            size_t next_token = *statement_end;
            while (next_token < source.size() &&
                std::isspace(static_cast<unsigned char>(source[next_token])))
                ++next_token;
            if (next_token < source.size() && source[next_token] == ';')
                continue;

            std::vector<Edit> edits;
            const std::string target_name(alias->target->name.value);
            const std::string source_name(alias->source->name.value);
            edits.push_back({*statement_begin, *statement_end,
                alias->local_declaration && later_overwrite ? "local " + target_name : "", statement->location});
            bool locations_match = true;
            for (Luau::AstExprLocal* read : replace_reads)
            {
                const std::optional<size_t> begin = offsets.offset(read->location.begin);
                const std::optional<size_t> end = offsets.offset(read->location.end);
                if (!begin || !end || *end < *begin || *end - *begin != target_name.size() ||
                    source.substr(*begin, *end - *begin) != target_name)
                {
                    locations_match = false;
                    break;
                }
                edits.push_back({*begin, *end, source_name, read->location});
            }
            if (!locations_match)
                continue;

            std::sort(edits.begin(), edits.end(), [](const Edit& left, const Edit& right) {
                return left.begin != right.begin ? left.begin < right.begin : left.end < right.end;
            });
            bool overlaps = false;
            for (size_t index = 1; index < edits.size(); ++index)
                overlaps = overlaps || edits[index].begin < edits[index - 1].end;
            if (overlaps)
                continue;

            std::string rewritten(source);
            for (auto edit = edits.rbegin(); edit != edits.rend(); ++edit)
                rewritten.replace(edit->begin, edit->end - edit->begin, edit->replacement);
            std::unique_ptr<ParseContext> reparsed = parse(rewritten);
            if (reparsed->result.root && reparsed->result.errors.empty())
                return rewritten;
        }
    return std::nullopt;
}

std::optional<std::string> promoteOneProvenAliasName(std::string_view source)
{
    std::unique_ptr<ParseContext> parsed = parse(source);
    if (!parsed->result.root || !parsed->result.errors.empty())
        return std::nullopt;

    LexicalAliasFacts facts;
    parsed->result.root->visit(&facts);
    const SourceOffsets offsets(source);

    for (Luau::AstStatBlock* block : facts.blocks)
        for (Luau::AstStat* statement : block->body)
        {
            auto declaration = statement->as<Luau::AstStatLocal>();
            const std::optional<LexicalAliasDefinition> alias = lexicalAliasDefinition(statement);
            if (!declaration || !alias || !alias->local_declaration || !alias->target->name.value ||
                !alias->source->name.value || !aliasCandidateName(alias->source->name.value) ||
                aliasCandidateName(alias->target->name.value) || alias->target->functionDepth != alias->source->functionDepth ||
                alias->target->loopDepth != 0 || alias->source->loopDepth != 0 ||
                facts.writes.contains(alias->target) || facts.capturedWrite(alias->source) ||
                facts.insideLoop(statement->location) || !facts.reads.contains(alias->target) ||
                facts.reads.at(alias->target).empty())
                continue;

            const std::string source_name(alias->source->name.value);
            const std::string target_name(alias->target->name.value);
            const bool collides = std::any_of(facts.locals.begin(), facts.locals.end(), [&](Luau::AstLocal* local) {
                return local != alias->target && local != alias->source && local->name.value &&
                    std::string_view(local->name.value) == target_name;
            });
            if (collides)
                continue;

            bool source_rebound_after = false;
            bool source_rebound_after_final_use = true;
            const bool target_captured = facts.captured(alias->target);
            if (auto writes = facts.writes.find(alias->source); writes != facts.writes.end())
                for (const Luau::Location& write : writes->second)
                    if (statement->location.end <= write.begin)
                    {
                        source_rebound_after = true;
                        if (target_captured || facts.insideLoop(write))
                            source_rebound_after_final_use = false;
                        if (auto reads = facts.reads.find(alias->target); reads != facts.reads.end())
                            for (Luau::AstExprLocal* read : reads->second)
                                if (facts.insideLoop(read->location) ||
                                    (!(read->location.end <= write.begin) &&
                                        !readFeedsSimpleOverwrite(
                                            facts, alias->source, write, read->location)))
                                    source_rebound_after_final_use = false;
                    }
            if (source_rebound_after && !source_rebound_after_final_use)
                continue;

            const std::optional<size_t> statement_begin = offsets.offset(statement->location.begin);
            const std::optional<size_t> statement_end = offsets.offset(statement->location.end);
            const std::optional<size_t> declaration_begin = offsets.offset(alias->source->location.begin);
            const std::optional<size_t> declaration_end = offsets.offset(alias->source->location.end);
            if (!statement_begin || !statement_end || !declaration_begin || !declaration_end ||
                *statement_end <= *statement_begin || *declaration_end < *declaration_begin ||
                *declaration_end - *declaration_begin != source_name.size() ||
                source.substr(*declaration_begin, *declaration_end - *declaration_begin) != source_name)
                continue;

            std::vector<Edit> edits;
            edits.push_back({*statement_begin, *statement_end, "", statement->location});
            edits.push_back({*declaration_begin, *declaration_end, target_name, alias->source->location});
            bool locations_match = true;
            if (auto occurrences = facts.occurrences.find(alias->source); occurrences != facts.occurrences.end())
                for (Luau::AstExprLocal* occurrence : occurrences->second)
                {
                    if (locationEncloses(statement->location, occurrence->location))
                        continue;
                    const std::optional<size_t> begin = offsets.offset(occurrence->location.begin);
                    const std::optional<size_t> end = offsets.offset(occurrence->location.end);
                    if (!begin || !end || *end < *begin || *end - *begin != source_name.size() ||
                        source.substr(*begin, *end - *begin) != source_name)
                    {
                        locations_match = false;
                        break;
                    }
                    edits.push_back({*begin, *end, target_name, occurrence->location});
                }
            if (!locations_match)
                continue;

            std::sort(edits.begin(), edits.end(), [](const Edit& left, const Edit& right) {
                return left.begin != right.begin ? left.begin < right.begin : left.end < right.end;
            });
            bool overlaps = false;
            for (size_t index = 1; index < edits.size(); ++index)
                overlaps = overlaps || edits[index].begin < edits[index - 1].end;
            if (overlaps)
                continue;

            std::string rewritten(source);
            for (auto edit = edits.rbegin(); edit != edits.rend(); ++edit)
                rewritten.replace(edit->begin, edit->end - edit->begin, edit->replacement);
            std::unique_ptr<ParseContext> reparsed = parse(rewritten);
            if (reparsed->result.root && reparsed->result.errors.empty())
                return rewritten;
        }
    return std::nullopt;
}

size_t diagnosticCoordinate(unsigned int coordinate)
{
    return coordinate == UINT32_MAX ? 0 : static_cast<size_t>(coordinate) + 1;
}

void addDiagnostic(
    ResidualBindingRenameResult& result,
    std::string code,
    std::string message,
    const Luau::Location& location = {})
{
    result.diagnostics.push_back({
        std::move(code),
        std::move(message),
        diagnosticCoordinate(location.begin.line),
        diagnosticCoordinate(location.begin.column),
    });
}

void addParseDiagnostics(
    ResidualBindingRenameResult& result,
    const Luau::ParseResult& parsed,
    std::string_view code,
    std::string_view prefix)
{
    for (const Luau::ParseError& error : parsed.errors)
        addDiagnostic(result, std::string(code), std::string(prefix) + error.getMessage(), error.getLocation());
}

void countCommittedCandidate(ResidualBindingRenameResult& result, const Candidate& candidate)
{
    ++result.renamed;
    if (candidate.family == CandidateFamily::Temporary)
        ++result.temporary_bindings_renamed;
    else
        ++result.generated_bindings_renamed;

    switch (candidate.role)
    {
    case BindingRole::Registers:
        ++result.role_counts.registers;
        ++result.semantic_role_names;
        break;
    case BindingRole::MutableCell:
        ++result.role_counts.mutable_cells;
        ++result.semantic_role_names;
        break;
    case BindingRole::Callback:
        ++result.role_counts.callbacks;
        ++result.semantic_role_names;
        break;
    case BindingRole::SemanticValue:
        ++result.role_counts.semantic_values;
        ++result.semantic_role_names;
        break;
    case BindingRole::VmValue:
        ++result.role_counts.vm_values;
        ++result.generic_fallback_names;
        break;
    case BindingRole::VmTemporary:
        ++result.role_counts.vm_temporaries;
        ++result.generic_fallback_names;
        break;
    }
}

ResidualBindingRenameResult renameImpl(std::string_view source)
{
    ResidualBindingRenameResult result;
    std::string working_source(source);
    for (size_t iteration = 0; iteration < 128; ++iteration)
    {
        std::optional<std::string> rewritten = coalesceOneProducerAliasVersion(working_source);
        if (!rewritten)
            rewritten = coalesceOneDeferredValueTransport(working_source);
        if (!rewritten)
            rewritten = eliminateOneProvenLexicalAlias(working_source);
        if (!rewritten)
            rewritten = promoteOneProvenAliasName(working_source);
        if (!rewritten || *rewritten == working_source)
            break;
        working_source = std::move(*rewritten);
        ++result.lexical_alias_versions_eliminated;
    }
    source = working_source;
    result.source = working_source;

    std::unique_ptr<ParseContext> parsed = parse(source);
    if (!parsed->result.root || !parsed->result.errors.empty())
    {
        if (parsed->result.errors.empty())
            addDiagnostic(result, "input_parse_error", "Luau parser returned no syntax tree");
        else
            addParseDiagnostics(result, parsed->result, "input_parse_error", "input did not parse: ");
        return result;
    }

    BindingCollector bindings(false, false, true);
    parsed->result.root->visit(&bindings);
    const CleanupPlan cleanup = planUnusedDeclarationCleanup(parsed->result.root, bindings);
    const std::vector<DeclaratorCleanup> declarator_cleanup =
        planUnusedUninitializedDeclarators(parsed->result.root, bindings, cleanup);

    std::unordered_set<Luau::AstLocal*> removed_declarators;
    std::unordered_set<Luau::AstLocal*> rewritten_declarators;
    size_t removed_declarator_count = 0;
    for (const DeclaratorCleanup& declaration : declarator_cleanup)
    {
        for (Luau::AstLocal* local : declaration.statement->vars)
            rewritten_declarators.insert(local);
        for (Luau::AstLocal* local : declaration.removed)
        {
            removed_declarators.insert(local);
            ++removed_declarator_count;
        }
    }

    bindings.candidates.erase(
        std::remove_if(bindings.candidates.begin(), bindings.candidates.end(), [&](const Candidate& candidate) {
            return insideRemovedDeclaration(candidate.local->location, cleanup) ||
                removed_declarators.contains(candidate.local);
        }),
        bindings.candidates.end());

    if (bindings.candidates.empty() && cleanup.statements.empty() && declarator_cleanup.empty())
    {
        result.changed = result.lexical_alias_versions_eliminated != 0;
        result.committed = true;
        return result;
    }

    std::sort(bindings.candidates.begin(), bindings.candidates.end(), [](const Candidate& left, const Candidate& right) {
        if (left.local->location.begin.line != right.local->location.begin.line)
            return left.local->location.begin.line < right.local->location.begin.line;
        return left.local->location.begin.column < right.local->location.begin.column;
    });

    UsageCollector usages(bindings.candidates, cleanup.statement_set);
    parsed->result.root->visit(&usages);
    usages.finish();
    LexicalAliasFacts lexical_facts;
    parsed->result.root->visit(&lexical_facts);

    FreshNameAllocator names(collectOccupiedNames(source));
    for (Candidate& candidate : bindings.candidates)
    {
        const size_t writes = lexical_facts.writes.contains(candidate.local)
            ? lexical_facts.writes.at(candidate.local).size()
            : 0;
        candidate.role = lexical_facts.captured(candidate.local) && writes > 1
            ? (candidate.family == CandidateFamily::Temporary ? BindingRole::VmTemporary : BindingRole::VmValue)
            : inferRole(candidate);
        if (candidate.generated_parameter &&
            (candidate.role == BindingRole::VmValue || candidate.role == BindingRole::VmTemporary))
        {
            candidate.rename_eligible = false;
            continue;
        }
        candidate.replacement = names.allocate(candidate);
    }
    bindings.candidates.erase(
        std::remove_if(bindings.candidates.begin(), bindings.candidates.end(), [](const Candidate& candidate) {
            return !candidate.rename_eligible;
        }),
        bindings.candidates.end());

    if (bindings.candidates.empty() && cleanup.statements.empty() && declarator_cleanup.empty())
    {
        result.changed = result.lexical_alias_versions_eliminated != 0;
        result.committed = true;
        return result;
    }

    const SourceOffsets offsets(source);
    std::vector<Edit> edits;
    std::unordered_map<Luau::AstLocal*, const Candidate*> candidate_by_local;
    for (const Candidate& candidate : bindings.candidates)
        candidate_by_local.emplace(candidate.local, &candidate);

    for (const DeclaratorCleanup& cleanup_entry : declarator_cleanup)
    {
        Luau::AstStatLocal* statement = cleanup_entry.statement;
        const std::optional<size_t> begin = offsets.offset(statement->location.begin);
        const std::optional<size_t> end = offsets.offset(statement->location.end);
        if (!begin || !end || *end <= *begin)
        {
            addDiagnostic(
                result,
                "declaration_location_mismatch",
                "AST location did not match uninitialized local declaration",
                statement->location);
            return result;
        }

        std::string replacement;
        for (Luau::AstLocal* local : statement->vars)
        {
            if (removed_declarators.contains(local))
                continue;
            if (replacement.empty())
                replacement = "local ";
            else
                replacement += ", ";
            if (auto candidate = candidate_by_local.find(local); candidate != candidate_by_local.end())
                replacement += candidate->second->replacement;
            else
                replacement += local->name.value;
        }
        edits.push_back({*begin, *end, std::move(replacement), statement->location});
    }

    for (Luau::AstStatLocal* statement : cleanup.statements)
    {
        const std::optional<size_t> begin = offsets.offset(statement->location.begin);
        const std::optional<size_t> end = offsets.offset(statement->location.end);
        Luau::AstLocal* local = statement->vars.data[0];
        const std::optional<size_t> name_begin = offsets.offset(local->location.begin);
        const std::optional<size_t> name_end = offsets.offset(local->location.end);
        const std::string_view name(local->name.value ? local->name.value : "");
        if (!begin || !end || !name_begin || !name_end || *end <= *begin || *name_end < *name_begin ||
            *name_begin < *begin || *name_end > *end || *name_end - *name_begin != name.size() ||
            source.substr(*name_begin, *name_end - *name_begin) != name)
        {
            addDiagnostic(
                result,
                "declaration_location_mismatch",
                "AST location did not match removable local declaration",
                statement->location);
            return result;
        }
        edits.push_back({*begin, *end, "", statement->location});
    }

    for (const Candidate& candidate : bindings.candidates)
        for (const Luau::Location& occurrence : candidate.occurrences)
        {
            if (rewritten_declarators.contains(candidate.local) && occurrence == candidate.local->location)
                continue;
            const std::optional<size_t> begin = offsets.offset(occurrence.begin);
            const std::optional<size_t> end = offsets.offset(occurrence.end);
            if (!begin || !end || *end < *begin || *end - *begin != candidate.original_name.size() ||
                source.substr(*begin, *end - *begin) != candidate.original_name)
            {
                addDiagnostic(
                    result,
                    "source_token_mismatch",
                    "AST location did not match local token '" + candidate.original_name + "'",
                    occurrence);
                return result;
            }
            edits.push_back({*begin, *end, candidate.replacement, occurrence});
        }

    std::sort(edits.begin(), edits.end(), [](const Edit& left, const Edit& right) {
        if (left.begin != right.begin)
            return left.begin < right.begin;
        return left.end < right.end;
    });
    for (size_t index = 1; index < edits.size(); ++index)
        if (edits[index].begin < edits[index - 1].end)
        {
            addDiagnostic(result, "overlapping_ast_locations", "AST local token locations overlap", edits[index].location);
            return result;
        }

    std::string rewritten(source);
    for (auto edit = edits.rbegin(); edit != edits.rend(); ++edit)
        rewritten.replace(edit->begin, edit->end - edit->begin, edit->replacement);

    for (size_t iteration = 0; iteration < 128; ++iteration)
    {
        std::optional<std::string> refined = coalesceOneProducerAliasVersion(rewritten);
        if (!refined)
            refined = coalesceOneDeferredValueTransport(rewritten);
        if (!refined)
            refined = eliminateOneProvenLexicalAlias(rewritten);
        if (!refined)
            refined = promoteOneProvenAliasName(rewritten);
        if (!refined || *refined == rewritten)
            break;
        rewritten = std::move(*refined);
        ++result.lexical_alias_versions_eliminated;
    }

    std::unique_ptr<ParseContext> reparsed = parse(rewritten);
    if (!reparsed->result.root || !reparsed->result.errors.empty())
    {
        if (reparsed->result.errors.empty())
            addDiagnostic(result, "output_parse_error", "rewritten Luau returned no syntax tree");
        else
            addParseDiagnostics(result, reparsed->result, "output_parse_error", "rewritten Luau did not parse: ");
        return result;
    }

    BindingCollector residual;
    reparsed->result.root->visit(&residual);
    const CleanupPlan residual_cleanup = planUnusedDeclarationCleanup(reparsed->result.root, residual);
    if (!residual.candidates.empty() || !residual_cleanup.statements.empty())
    {
        addDiagnostic(
            result,
            "idempotence_failure",
            "rewritten Luau still contains an eligible local binding or removable declaration",
            !residual.candidates.empty() ? residual.candidates.front().local->location
                                         : residual_cleanup.statements.front()->location);
        return result;
    }

    result.source = std::move(rewritten);
    result.changed = true;
    result.committed = true;
    result.unused_declarations_removed = cleanup.statements.size() + removed_declarator_count;
    for (const Candidate& candidate : bindings.candidates)
        countCommittedCandidate(result, candidate);
    return result;
}

ResidualBindingRenameResult refineResidualImpl(std::string_view source, bool stabilize_ambiguous = false)
{
    ResidualBindingRenameResult result;
    result.source.assign(source);

    std::unique_ptr<ParseContext> parsed = parse(source);
    if (!parsed->result.root || !parsed->result.errors.empty())
    {
        if (parsed->result.errors.empty())
            addDiagnostic(result, "input_parse_error", "Luau parser returned no syntax tree");
        else
            addParseDiagnostics(result, parsed->result, "input_parse_error", "input did not parse: ");
        return result;
    }

    BindingCollector bindings(true);
    parsed->result.root->visit(&bindings);
    const CleanupPlan no_statement_cleanup;
    const std::vector<DeclaratorCleanup> declarator_cleanup =
        planUnusedUninitializedDeclarators(parsed->result.root, bindings, no_statement_cleanup);

    std::unordered_set<Luau::AstLocal*> removed_declarators;
    std::unordered_set<Luau::AstLocal*> rewritten_declarators;
    for (const DeclaratorCleanup& declaration : declarator_cleanup)
    {
        for (Luau::AstLocal* local : declaration.statement->vars)
            rewritten_declarators.insert(local);
        removed_declarators.insert(declaration.removed.begin(), declaration.removed.end());
    }
    bindings.candidates.erase(
        std::remove_if(bindings.candidates.begin(), bindings.candidates.end(), [&](const Candidate& candidate) {
            return removed_declarators.contains(candidate.local);
        }),
        bindings.candidates.end());

    if (bindings.candidates.empty() && declarator_cleanup.empty())
    {
        result.committed = true;
        return result;
    }

    const std::unordered_set<Luau::AstStatLocal*> removed_declarations;
    UsageCollector usages(bindings.candidates, removed_declarations);
    parsed->result.root->visit(&usages);
    usages.finish();
    LexicalAliasFacts lexical_facts;
    parsed->result.root->visit(&lexical_facts);

    FreshNameAllocator names(collectOccupiedNames(source));
    std::vector<Candidate*> refinements;
    for (Candidate& candidate : bindings.candidates)
    {
        if (!residualCandidateFamily(candidate.original_name))
            continue;
        const size_t writes = lexical_facts.writes.contains(candidate.local)
            ? lexical_facts.writes.at(candidate.local).size()
            : 0;
        candidate.role = !stabilize_ambiguous && lexical_facts.captured(candidate.local) && writes > 1
            ? (candidate.family == CandidateFamily::Temporary ? BindingRole::VmTemporary : BindingRole::VmValue)
            : inferRole(candidate);
        if (candidate.role == BindingRole::VmValue || candidate.role == BindingRole::VmTemporary)
        {
            if (!stabilize_ambiguous)
                continue;

            std::string dominant_role;
            double dominant_score = 0.0;
            for (const auto& [role, score] : candidate.name_scores)
                if (score > dominant_score || (score == dominant_score && role < dominant_role))
                {
                    dominant_role = role;
                    dominant_score = score;
                }

            const bool merged = candidate.value_roles.size() > 1 || candidate.unknown_value_assignments > 0;
            if (!dominant_role.empty() && dominant_role != "value" && dominant_role != "forwarded_value" &&
                dominant_score >= 3.0)
                candidate.semantic_base = std::string(merged ? "merged_" : "working_") + dominant_role;
            else if (candidate.callback || candidate.usage_roles.contains("callback"))
                candidate.semantic_base = merged ? "merged_callback" : "working_callback";
            else if (candidate.saw_index)
                candidate.semantic_base = merged ? "merged_collection" : "working_collection";
            else
                candidate.semantic_base = merged ? "merged_value" : "working_value";
            candidate.semantic_confidence = 0.0;
            candidate.role = BindingRole::SemanticValue;
            ++result.generated_merge_names;
        }
        candidate.replacement = names.allocate(candidate);
        refinements.push_back(&candidate);
    }
    if (refinements.empty() && declarator_cleanup.empty())
    {
        result.committed = true;
        return result;
    }

    const SourceOffsets offsets(source);
    std::vector<Edit> edits;
    std::unordered_map<Luau::AstLocal*, const Candidate*> refinement_by_local;
    for (const Candidate* candidate : refinements)
        refinement_by_local.emplace(candidate->local, candidate);

    for (const DeclaratorCleanup& cleanup : declarator_cleanup)
    {
        const std::optional<size_t> begin = offsets.offset(cleanup.statement->location.begin);
        const std::optional<size_t> end = offsets.offset(cleanup.statement->location.end);
        if (!begin || !end || *end <= *begin)
        {
            addDiagnostic(
                result,
                "declaration_location_mismatch",
                "AST location did not match residual local declaration",
                cleanup.statement->location);
            return result;
        }

        std::string replacement;
        for (Luau::AstLocal* local : cleanup.statement->vars)
        {
            if (removed_declarators.contains(local))
                continue;
            if (replacement.empty())
                replacement = "local ";
            else
                replacement += ", ";
            if (auto refined = refinement_by_local.find(local); refined != refinement_by_local.end())
                replacement += refined->second->replacement;
            else
                replacement += local->name.value;
        }
        edits.push_back({*begin, *end, std::move(replacement), cleanup.statement->location});
    }

    for (const Candidate* candidate : refinements)
        for (const Luau::Location& occurrence : candidate->occurrences)
        {
            if (rewritten_declarators.contains(candidate->local) && occurrence == candidate->local->location)
                continue;
            const std::optional<size_t> begin = offsets.offset(occurrence.begin);
            const std::optional<size_t> end = offsets.offset(occurrence.end);
            if (!begin || !end || *end < *begin || *end - *begin != candidate->original_name.size() ||
                source.substr(*begin, *end - *begin) != candidate->original_name)
            {
                addDiagnostic(
                    result,
                    "source_token_mismatch",
                    "AST location did not match residual local token '" + candidate->original_name + "'",
                    occurrence);
                return result;
            }
            edits.push_back({*begin, *end, candidate->replacement, occurrence});
        }

    std::sort(edits.begin(), edits.end(), [](const Edit& left, const Edit& right) {
        if (left.begin != right.begin)
            return left.begin < right.begin;
        return left.end < right.end;
    });
    for (size_t index = 1; index < edits.size(); ++index)
        if (edits[index].begin < edits[index - 1].end)
        {
            addDiagnostic(result, "overlapping_ast_locations", "AST residual local token locations overlap", edits[index].location);
            return result;
        }

    std::string rewritten(source);
    for (auto edit = edits.rbegin(); edit != edits.rend(); ++edit)
        rewritten.replace(edit->begin, edit->end - edit->begin, edit->replacement);

    std::unique_ptr<ParseContext> reparsed = parse(rewritten);
    if (!reparsed->result.root || !reparsed->result.errors.empty())
    {
        if (reparsed->result.errors.empty())
            addDiagnostic(result, "output_parse_error", "refined Luau returned no syntax tree");
        else
            addParseDiagnostics(result, reparsed->result, "output_parse_error", "refined Luau did not parse: ");
        return result;
    }

    result.source = std::move(rewritten);
    result.changed = true;
    result.committed = true;
    result.unused_declarations_removed = removed_declarators.size();
    for (const Candidate* candidate : refinements)
        countCommittedCandidate(result, *candidate);
    return result;
}

ResidualBindingRenameResult splitOneStraightLineResidualRole(std::string_view source)
{
    ResidualBindingRenameResult result;
    result.source.assign(source);

    std::unique_ptr<ParseContext> parsed = parse(source);
    if (!parsed->result.root || !parsed->result.errors.empty())
        return result;

    LexicalAliasFacts facts;
    parsed->result.root->visit(&facts);

    struct Proposal
    {
        Luau::AstStatBlock* block = nullptr;
        Luau::AstStatAssign* assignment = nullptr;
        Luau::AstExprLocal* target = nullptr;
        bool separate_declaration = false;
        Candidate candidate;
        std::vector<Luau::AstExprLocal*> reads;
    };
    std::optional<Proposal> best;

    auto activeLocals = [&](Luau::AstStatBlock* block) {
        size_t count = 0;
        for (Luau::AstStat* statement : block->body)
        {
            if (auto declaration = statement->as<Luau::AstStatLocal>())
                count += declaration->vars.size;
            else if (statement->is<Luau::AstStatLocalFunction>())
                ++count;
            else if (auto numeric = statement->as<Luau::AstStatFor>())
            {
                (void)numeric;
                ++count;
            }
            else if (auto generic = statement->as<Luau::AstStatForIn>())
                count += generic->vars.size;
        }
        Luau::AstExprFunction* owner = nullptr;
        for (Luau::AstExprFunction* function : facts.functions)
            if (locationEncloses(function->body->location, block->location) &&
                (!owner || locationEncloses(owner->body->location, function->body->location)))
                owner = function;
        if (owner)
            count += owner->args.size + (owner->self ? 1 : 0);
        return count;
    };

    for (Luau::AstStatBlock* block : facts.blocks)
    {
        if (activeLocals(block) >= 1000)
            continue;
        for (size_t index = 0; index < block->body.size; ++index)
        {
            auto assignment = block->body.data[index]->as<Luau::AstStatAssign>();
            if (!assignment || assignment->vars.size == 0 || assignment->values.size == 0)
                continue;
            for (size_t variable_index = 0; variable_index < assignment->vars.size; ++variable_index)
            {
            Luau::AstExprLocal* target = directLocal(assignment->vars.data[variable_index]);
            if (!target || !target->local || !target->local->name.value ||
                !residualCandidateFamily(target->local->name.value) || target->local->loopDepth != 0 ||
                !facts.readsInside(block->body.data[index], target->local).empty() || facts.captured(target->local))
                continue;

            bool assignment_in_nested_function = false;
            for (Luau::AstExprFunction* function : facts.functions)
                if (function->functionDepth > target->local->functionDepth &&
                    locationEncloses(function->location, assignment->location))
                    assignment_in_nested_function = true;
            if (assignment_in_nested_function)
                continue;

            Candidate candidate;
            candidate.local = target->local;
            candidate.family = *residualCandidateFamily(target->local->name.value);
            candidate.original_name = target->local->name.value;
            if (assignment->vars.size == assignment->values.size)
                noteAssignedValue(candidate, assignment->values.data[variable_index]);
            else if (assignment->vars.size == 1)
                noteAssignedValue(candidate, assignment->values.data[0]);
            else
                ++candidate.unknown_value_assignments;

            std::vector<Luau::AstExprLocal*> reads;
            std::vector<Luau::AstStat*> usage_statements;
            bool safe = true;
            for (size_t next = index + 1; next < block->body.size; ++next)
            {
                Luau::AstStat* following = block->body.data[next];
                if (facts.writesInside(following, target->local))
                {
                    auto boundary = following->as<Luau::AstStatAssign>();
                    bool direct_boundary = false;
                    if (boundary)
                        for (Luau::AstExpr* variable : boundary->vars)
                            if (Luau::AstExprLocal* written = directLocal(variable);
                                written && written->local == target->local)
                                direct_boundary = true;
                    const bool block_boundary = !direct_boundary &&
                        straightLineBlockOverwriteWithoutRead(following, target->local, facts);
                    if (!direct_boundary && !block_boundary)
                        safe = false;
                    else if (direct_boundary)
                    {
                        std::vector<Luau::AstExprLocal*> boundary_reads =
                            facts.readsInside(following, target->local);
                        reads.insert(reads.end(), boundary_reads.begin(), boundary_reads.end());
                    }
                    break;
                }
                usage_statements.push_back(following);
                std::vector<Luau::AstExprLocal*> statement_reads = facts.readsInside(following, target->local);
                reads.insert(reads.end(), statement_reads.begin(), statement_reads.end());
            }
            if (!safe || reads.empty())
                continue;

            for (Luau::AstExprLocal* read : reads)
                for (Luau::AstExprFunction* function : facts.functions)
                    if (function->functionDepth > target->local->functionDepth &&
                        locationEncloses(function->location, read->location))
                        safe = false;
            if (!safe)
                continue;

            std::vector<Candidate> version_candidates;
            version_candidates.push_back(std::move(candidate));
            const std::unordered_set<Luau::AstStatLocal*> no_removed_declarations;
            UsageCollector version_usages(version_candidates, no_removed_declarations);
            for (Luau::AstStat* statement : usage_statements)
                statement->visit(&version_usages);
            candidate = std::move(version_candidates.front());
            candidate.role = inferRole(candidate);
            if (candidate.role != BindingRole::SemanticValue && candidate.role != BindingRole::Callback)
                continue;

            Proposal proposal{block, assignment, target, assignment->vars.size != 1, std::move(candidate), std::move(reads)};
            if (!best || proposal.reads.size() > best->reads.size() ||
                (proposal.reads.size() == best->reads.size() &&
                    proposal.assignment->location.begin < best->assignment->location.begin))
                best = std::move(proposal);
            }
        }
    }

    if (!best)
    {
        result.committed = true;
        return result;
    }

    FreshNameAllocator names(collectOccupiedNames(source));
    best->candidate.replacement = names.allocate(best->candidate);
    const SourceOffsets offsets(source);
    std::vector<Edit> edits;
    const std::optional<size_t> target_begin = offsets.offset(best->target->location.begin);
    const std::optional<size_t> target_end = offsets.offset(best->target->location.end);
    if (!target_begin || !target_end || *target_end < *target_begin ||
        source.substr(*target_begin, *target_end - *target_begin) != best->candidate.original_name)
        return result;
    if (best->separate_declaration)
    {
        const std::optional<size_t> assignment_begin = offsets.offset(best->assignment->location.begin);
        if (!assignment_begin)
            return result;
        size_t line_begin = *assignment_begin;
        while (line_begin > 0 && source[line_begin - 1] != '\n')
            --line_begin;
        const std::string indentation(source.substr(line_begin, *assignment_begin - line_begin));
        edits.push_back({*assignment_begin, *assignment_begin,
            "local " + best->candidate.replacement + "\n" + indentation, best->assignment->location});
        edits.push_back({*target_begin, *target_end, best->candidate.replacement, best->target->location});
    }
    else
        edits.push_back({*target_begin, *target_end, "local " + best->candidate.replacement, best->target->location});
    for (Luau::AstExprLocal* read : best->reads)
    {
        const std::optional<size_t> begin = offsets.offset(read->location.begin);
        const std::optional<size_t> end = offsets.offset(read->location.end);
        if (!begin || !end || *end < *begin ||
            source.substr(*begin, *end - *begin) != best->candidate.original_name)
            return result;
        edits.push_back({*begin, *end, best->candidate.replacement, read->location});
    }
    std::sort(edits.begin(), edits.end(), [](const Edit& left, const Edit& right) {
        return left.begin != right.begin ? left.begin < right.begin : left.end < right.end;
    });
    for (size_t index = 1; index < edits.size(); ++index)
        if (edits[index].begin < edits[index - 1].end)
            return result;

    std::string rewritten(source);
    for (auto edit = edits.rbegin(); edit != edits.rend(); ++edit)
        rewritten.replace(edit->begin, edit->end - edit->begin, edit->replacement);
    std::unique_ptr<ParseContext> reparsed = parse(rewritten);
    if (!reparsed->result.root || !reparsed->result.errors.empty())
        return result;

    result.source = std::move(rewritten);
    result.changed = true;
    result.committed = true;
    countCommittedCandidate(result, best->candidate);
    return result;
}

ResidualBindingRenameResult splitStraightLineResidualImpl(std::string_view source)
{
    ResidualBindingRenameResult result;
    result.source.assign(source);
    constexpr size_t MaximumSafeSplits = 512;
    for (size_t iteration = 0; iteration < MaximumSafeSplits; ++iteration)
    {
        ResidualBindingRenameResult split = splitOneStraightLineResidualRole(result.source);
        if (!split.committed || !split.changed || split.source == result.source)
            break;
        result.source = std::move(split.source);
        result.renamed += split.renamed;
        result.generated_bindings_renamed += split.generated_bindings_renamed;
        result.temporary_bindings_renamed += split.temporary_bindings_renamed;
        result.semantic_role_names += split.semantic_role_names;
        result.role_counts.callbacks += split.role_counts.callbacks;
        result.role_counts.semantic_values += split.role_counts.semantic_values;
        result.changed = true;
    }
    result.committed = true;
    return result;
}

ResidualBindingRenameResult renameGeneratedCallbackPurposesImpl(std::string_view source)
{
    ResidualBindingRenameResult result;
    result.source.assign(source);
    std::unique_ptr<ParseContext> parsed = parse(source);
    if (!parsed->result.root || !parsed->result.errors.empty())
        return result;

    BindingCollector bindings(false, true);
    parsed->result.root->visit(&bindings);
    if (bindings.candidates.empty())
    {
        result.committed = true;
        return result;
    }

    const std::unordered_set<Luau::AstStatLocal*> no_removed_declarations;
    UsageCollector usages(bindings.candidates, no_removed_declarations);
    parsed->result.root->visit(&usages);
    usages.finish();
    FreshNameAllocator names(collectOccupiedNames(source));
    std::vector<Candidate*> proven;
    for (Candidate& candidate : bindings.candidates)
    {
        candidate.role = inferRole(candidate);
        if (candidate.role != BindingRole::SemanticValue || candidate.semantic_base.empty() ||
            candidate.semantic_base == "callback")
            continue;
        candidate.replacement = names.allocate(candidate);
        proven.push_back(&candidate);
    }
    if (proven.empty())
    {
        result.committed = true;
        return result;
    }

    const SourceOffsets offsets(source);
    std::vector<Edit> edits;
    for (const Candidate* candidate : proven)
        for (const Luau::Location& occurrence : candidate->occurrences)
        {
            const std::optional<size_t> begin = offsets.offset(occurrence.begin);
            const std::optional<size_t> end = offsets.offset(occurrence.end);
            if (!begin || !end || *end < *begin || *end - *begin != candidate->original_name.size() ||
                source.substr(*begin, *end - *begin) != candidate->original_name)
                return result;
            edits.push_back({*begin, *end, candidate->replacement, occurrence});
        }
    std::sort(edits.begin(), edits.end(), [](const Edit& left, const Edit& right) {
        return left.begin != right.begin ? left.begin < right.begin : left.end < right.end;
    });
    for (size_t index = 1; index < edits.size(); ++index)
        if (edits[index].begin < edits[index - 1].end)
            return result;

    std::string rewritten(source);
    for (auto edit = edits.rbegin(); edit != edits.rend(); ++edit)
        rewritten.replace(edit->begin, edit->end - edit->begin, edit->replacement);
    std::unique_ptr<ParseContext> reparsed = parse(rewritten);
    if (!reparsed->result.root || !reparsed->result.errors.empty())
        return result;

    result.source = std::move(rewritten);
    result.changed = true;
    result.committed = true;
    for (const Candidate* candidate : proven)
        countCommittedCandidate(result, *candidate);
    return result;
}

} // namespace

ResidualBindingRenameResult renameResidualBindings(std::string_view final_source)
{
    try
    {
        return renameImpl(final_source);
    }
    catch (const std::exception& error)
    {
        ResidualBindingRenameResult result;
        result.source.assign(final_source);
        addDiagnostic(result, "internal_error", std::string("residual binding rename failed: ") + error.what());
        return result;
    }
    catch (...)
    {
        ResidualBindingRenameResult result;
        result.source.assign(final_source);
        addDiagnostic(result, "internal_error", "residual binding rename failed with an unknown error");
        return result;
    }
}

ResidualBindingRenameResult refineResidualBindingNames(std::string_view final_source)
{
    try
    {
        return refineResidualImpl(final_source, false);
    }
    catch (const std::exception& error)
    {
        ResidualBindingRenameResult result;
        result.source.assign(final_source);
        addDiagnostic(result, "internal_error", std::string("residual binding refinement failed: ") + error.what());
        return result;
    }
    catch (...)
    {
        ResidualBindingRenameResult result;
        result.source.assign(final_source);
        addDiagnostic(result, "internal_error", "residual binding refinement failed with an unknown error");
        return result;
    }
}

ResidualBindingRenameResult stabilizeResidualBindingNames(std::string_view final_source)
{
    try
    {
        return refineResidualImpl(final_source, true);
    }
    catch (const std::exception& error)
    {
        ResidualBindingRenameResult result;
        result.source.assign(final_source);
        addDiagnostic(result, "internal_error", std::string("residual binding stabilization failed: ") + error.what());
        return result;
    }
    catch (...)
    {
        ResidualBindingRenameResult result;
        result.source.assign(final_source);
        addDiagnostic(result, "internal_error", "residual binding stabilization failed with an unknown error");
        return result;
    }
}

ResidualBindingRenameResult splitStraightLineResidualRoles(std::string_view final_source)
{
    try
    {
        return splitStraightLineResidualImpl(final_source);
    }
    catch (const std::exception& error)
    {
        ResidualBindingRenameResult result;
        result.source.assign(final_source);
        addDiagnostic(result, "internal_error", std::string("straight-line residual splitting failed: ") + error.what());
        return result;
    }
    catch (...)
    {
        ResidualBindingRenameResult result;
        result.source.assign(final_source);
        addDiagnostic(result, "internal_error", "straight-line residual splitting failed with an unknown error");
        return result;
    }
}

ResidualBindingRenameResult renameGeneratedCallbackPurposes(std::string_view final_source)
{
    try
    {
        return renameGeneratedCallbackPurposesImpl(final_source);
    }
    catch (const std::exception& error)
    {
        ResidualBindingRenameResult result;
        result.source.assign(final_source);
        addDiagnostic(result, "internal_error", std::string("callback purpose rename failed: ") + error.what());
        return result;
    }
    catch (...)
    {
        ResidualBindingRenameResult result;
        result.source.assign(final_source);
        addDiagnostic(result, "internal_error", "callback purpose rename failed with an unknown error");
        return result;
    }
}

} // namespace alex::deobfuscator
