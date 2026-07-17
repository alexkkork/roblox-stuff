#include "passes/fields.hpp"

#include "Luau/Allocator.h"
#include "Luau/Ast.h"
#include "Luau/Compiler.h"
#include "Luau/Parser.h"

#include <algorithm>
#include <cctype>
#include <exception>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace alex::deobfuscator::state_fields
{
namespace
{

struct ParseContext
{
    Luau::Allocator allocator;
    Luau::AstNameTable names{allocator};
    Luau::ParseResult result;
};

struct Edit
{
    size_t begin = 0;
    size_t end = 0;
    std::string replacement;
};

struct FieldKey
{
    Luau::AstLocal* table = nullptr;
    std::string name;
};

struct FieldKeyLess
{
    bool operator()(const FieldKey& left, const FieldKey& right) const
    {
        if (left.table != right.table)
            return std::less<Luau::AstLocal*>{}(left.table, right.table);
        return left.name < right.name;
    }
};

struct FieldFacts
{
    FieldKey key;
    std::vector<Luau::Location> occurrences;
    std::set<std::string> destination_roles;
    size_t function_writes = 0;
    size_t other_writes = 0;
    size_t first_offset = 0;
};

struct TableFacts
{
    size_t references = 0;
    size_t static_field_bases = 0;
    std::set<std::string> occupied_fields;
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

        const size_t begin = line_starts[position.line];
        const size_t end = position.line + 1 < line_starts.size() ? line_starts[position.line + 1] - 1 : source.size();
        if (position.column > end - begin)
            return std::nullopt;
        return begin + position.column;
    }

    std::optional<std::pair<size_t, size_t>> range(const Luau::Location& location) const
    {
        const std::optional<size_t> begin = offset(location.begin);
        const std::optional<size_t> end = offset(location.end);
        if (!begin || !end || *end < *begin)
            return std::nullopt;
        return std::pair{*begin, *end};
    }

private:
    std::string_view source;
    std::vector<size_t> line_starts;
};

std::unique_ptr<ParseContext> parse(std::string_view source)
{
    auto context = std::make_unique<ParseContext>();
    context->result = Luau::Parser::parse(source.data(), source.size(), context->names, context->allocator);
    return context;
}

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

bool hasDecimalSuffix(std::string_view name, std::string_view prefix)
{
    if (!name.starts_with(prefix) || name.size() == prefix.size())
        return false;
    return std::all_of(name.begin() + static_cast<std::ptrdiff_t>(prefix.size()), name.end(), [](char ch) {
        return std::isdigit(static_cast<unsigned char>(ch));
    });
}

bool generatedStateName(std::string_view name)
{
    return name == "script_state" || hasDecimalSuffix(name, "script_state_");
}

bool generatedCallbackName(std::string_view name)
{
    auto hasOrdinalSegments = [](std::string_view candidate, std::string_view prefix) {
        if (!candidate.starts_with(prefix) || candidate.size() == prefix.size())
            return false;
        bool previous_separator = true;
        for (char ch : candidate.substr(prefix.size()))
        {
            if (ch == '_')
            {
                if (previous_separator)
                    return false;
                previous_separator = true;
            }
            else if (std::isdigit(static_cast<unsigned char>(ch)))
                previous_separator = false;
            else
                return false;
        }
        return !previous_separator;
    };
    return hasOrdinalSegments(name, "callback_") || hasOrdinalSegments(name, "event_handler_");
}

bool isFunctionValue(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    return expression && expression->is<Luau::AstExprFunction>();
}

std::string constantString(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    if (auto value = expression ? expression->as<Luau::AstExprConstantString>() : nullptr)
        return std::string(value->value.data, value->value.size);
    return {};
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
    return result.empty() ? "callback" : result;
}

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
    if (role.empty())
        return std::nullopt;

    constexpr std::string_view suffix = "_signal";
    if (role.ends_with(suffix))
        role.erase(role.size() - suffix.size());
    if (role.empty() || role == "signal")
        return std::nullopt;
    return "on_" + snakeCase(role);
}

std::optional<std::string> propertyName(Luau::AstExpr* expression)
{
    expression = unwrapTransparent(expression);
    if (!expression)
        return std::nullopt;
    if (auto property = expression->as<Luau::AstExprIndexName>(); property && property->index.value)
        return std::string(property->index.value);
    if (auto property = expression->as<Luau::AstExprIndexExpr>())
    {
        std::string name = constantString(property->index);
        if (!name.empty())
            return name;
    }
    return std::nullopt;
}

class StateTableCollector final : public Luau::AstVisitor
{
public:
    std::unordered_set<Luau::AstLocal*> tables;

    bool visit(Luau::AstStatLocal* node) override
    {
        const size_t count = std::min(node->vars.size, node->values.size);
        for (size_t index = 0; index < count; ++index)
        {
            Luau::AstLocal* local = node->vars.data[index];
            if (!local || !local->name.value || !generatedStateName(local->name.value))
                continue;
            Luau::AstExpr* value = unwrapTransparent(node->values.data[index]);
            if (auto table = value ? value->as<Luau::AstExprTable>() : nullptr; table && table->items.size == 0)
                tables.insert(local);
        }
        return true;
    }

    bool visit(Luau::AstType*) override
    {
        return false;
    }
};

class FactCollector final : public Luau::AstVisitor
{
public:
    explicit FactCollector(const std::unordered_set<Luau::AstLocal*>& state_tables)
        : state_tables(state_tables)
    {
        for (Luau::AstLocal* table : state_tables)
            tables.emplace(table, TableFacts{});
    }

    std::map<FieldKey, FieldFacts, FieldKeyLess> fields;
    std::unordered_map<Luau::AstLocal*, TableFacts> tables;

    bool visit(Luau::AstExprLocal* node) override
    {
        if (auto found = tables.find(node->local); found != tables.end())
            ++found->second.references;
        return true;
    }

    bool visit(Luau::AstExprIndexName* node) override
    {
        Luau::AstExprLocal* base = directLocal(node->expr);
        if (!base || !node->index.value)
            return true;
        auto table = tables.find(base->local);
        if (table == tables.end())
            return true;

        ++table->second.static_field_bases;
        table->second.occupied_fields.insert(node->index.value);
        if (generatedCallbackName(node->index.value))
        {
            FieldFacts& facts = field(base->local, node->index.value);
            facts.occurrences.push_back(node->indexLocation);
        }
        return true;
    }

    bool visit(Luau::AstStatAssign* node) override
    {
        const bool exact_assignment = node->vars.size == node->values.size;
        for (size_t index = 0; index < node->vars.size; ++index)
        {
            if (FieldFacts* target = callbackField(node->vars.data[index]))
            {
                if (exact_assignment && isFunctionValue(node->values.data[index]))
                    ++target->function_writes;
                else
                    ++target->other_writes;
            }

            if (!exact_assignment)
                continue;
            FieldFacts* value = callbackField(node->values.data[index]);
            if (!value || callbackField(node->vars.data[index]))
                continue;
            if (std::optional<std::string> property = propertyName(node->vars.data[index]); property &&
                !property->empty() && std::isupper(static_cast<unsigned char>(property->front())))
                value->destination_roles.insert(snakeCase(*property) + "_hook");
        }
        return true;
    }

    bool visit(Luau::AstStatCompoundAssign* node) override
    {
        if (FieldFacts* target = callbackField(node->var))
            ++target->other_writes;
        return true;
    }

    bool visit(Luau::AstStatFunction* node) override
    {
        if (FieldFacts* target = callbackField(node->name))
            ++target->function_writes;
        return true;
    }

    bool visit(Luau::AstExprCall* node) override
    {
        Luau::AstExpr* callee = unwrapTransparent(node->func);
        if (auto global = callee ? callee->as<Luau::AstExprGlobal>() : nullptr; global && global->name.value)
        {
            const std::string_view name(global->name.value);
            if (name == "pcall")
                noteArgument(node, 0, "protected_action");
            else if (name == "xpcall")
            {
                noteArgument(node, 0, "protected_action");
                noteArgument(node, 1, "error_handler");
            }
            else if (name == "hookfunction" && node->args.size >= 2)
            {
                if (std::optional<std::string> property = propertyName(node->args.data[0]))
                    noteArgument(node, 1, snakeCase(*property) + "_hook");
            }
            else if (name == "hookmetamethod" && node->args.size >= 3)
            {
                const std::string method = constantString(node->args.data[1]);
                if (!method.empty())
                    noteArgument(node, 2, snakeCase(method) + "_hook");
            }
        }

        auto method = callee ? callee->as<Luau::AstExprIndexName>() : nullptr;
        if (!method || !method->index.value)
            return true;
        const std::string_view method_name(method->index.value);
        if (method_name == "Connect" || method_name == "Once")
        {
            const std::string role = callbackPurposeFromSignal(method->expr).value_or("event_handler");
            noteArgument(node, 0, role);
        }
        if (auto receiver = unwrapTransparent(method->expr)->as<Luau::AstExprGlobal>();
            receiver && receiver->name.value && std::string_view(receiver->name.value) == "task")
        {
            if (method_name == "spawn")
                noteArgument(node, 0, "background_task");
            else if (method_name == "defer")
                noteArgument(node, 0, "deferred_task");
            else if (method_name == "delay")
                noteArgument(node, 1, "delayed_task");
        }
        return true;
    }

    bool visit(Luau::AstType*) override
    {
        return false;
    }

private:
    const std::unordered_set<Luau::AstLocal*>& state_tables;

    FieldFacts& field(Luau::AstLocal* table, std::string_view name)
    {
        FieldKey key{table, std::string(name)};
        auto [iterator, inserted] = fields.try_emplace(key);
        if (inserted)
            iterator->second.key = std::move(key);
        return iterator->second;
    }

    FieldFacts* callbackField(Luau::AstExpr* expression)
    {
        expression = unwrapTransparent(expression);
        auto property = expression ? expression->as<Luau::AstExprIndexName>() : nullptr;
        if (!property || !property->index.value || !generatedCallbackName(property->index.value))
            return nullptr;
        Luau::AstExprLocal* base = directLocal(property->expr);
        if (!base || !state_tables.contains(base->local))
            return nullptr;
        return &field(base->local, property->index.value);
    }

    void noteArgument(Luau::AstExprCall* call, size_t index, std::string role)
    {
        if (index >= call->args.size)
            return;
        if (FieldFacts* facts = callbackField(call->args.data[index]))
            facts->destination_roles.insert(std::move(role));
    }
};

void applyEdits(std::string& source, std::vector<Edit>& edits)
{
    std::sort(edits.begin(), edits.end(), [](const Edit& left, const Edit& right) {
        if (left.begin != right.begin)
            return left.begin > right.begin;
        return left.end > right.end;
    });
    for (const Edit& edit : edits)
        source.replace(edit.begin, edit.end - edit.begin, edit.replacement);
}

bool compiles(std::string_view source, std::string& diagnostic)
{
    try
    {
        const std::string bytecode = Luau::compile(std::string(source));
        if (!bytecode.empty() && bytecode[0] != 0)
            return true;
        if (bytecode.size() > 1)
            diagnostic.assign(bytecode.data() + 1, bytecode.size() - 1);
        else
            diagnostic = "compiler returned no bytecode";
    }
    catch (const std::exception& error)
    {
        diagnostic = error.what();
    }
    catch (...)
    {
        diagnostic = "compiler raised an unknown exception";
    }
    return false;
}

} // namespace

RefinementResult refineGeneratedCallbackFields(std::string_view source)
{
    RefinementResult result;
    result.source.assign(source);

    std::unique_ptr<ParseContext> parsed = parse(source);
    if (!parsed->result.root || !parsed->result.errors.empty())
    {
        result.diagnostics.push_back("source could not be parsed for state field refinement");
        return result;
    }
    result.parse_succeeded = true;

    StateTableCollector state_tables;
    parsed->result.root->visit(&state_tables);
    if (state_tables.tables.empty())
        return result;

    FactCollector collector(state_tables.tables);
    parsed->result.root->visit(&collector);
    result.generated_callback_fields_found = collector.fields.size();

    std::unordered_set<Luau::AstLocal*> unsafe_tables;
    for (const auto& [table, facts] : collector.tables)
        if (facts.references != facts.static_field_bases)
            unsafe_tables.insert(table);
    result.unsafe_state_tables = unsafe_tables.size();

    const SourceOffsets offsets(source);
    std::vector<FieldFacts*> candidates;
    for (auto& [key, facts] : collector.fields)
    {
        if (unsafe_tables.contains(key.table))
        {
            ++result.unsafe_fields;
            continue;
        }
        if (facts.function_writes != 1 || facts.other_writes != 0 || facts.destination_roles.empty())
        {
            ++result.unproven_fields;
            continue;
        }
        if (facts.destination_roles.size() != 1)
        {
            ++result.ambiguous_fields;
            continue;
        }
        if (facts.occurrences.empty())
        {
            ++result.unproven_fields;
            continue;
        }
        const std::optional<size_t> first = offsets.offset(facts.occurrences.front().begin);
        if (!first)
        {
            ++result.unproven_fields;
            continue;
        }
        facts.first_offset = *first;
        candidates.push_back(&facts);
    }

    std::sort(candidates.begin(), candidates.end(), [](const FieldFacts* left, const FieldFacts* right) {
        return left->first_offset < right->first_offset;
    });

    std::vector<Edit> edits;
    for (FieldFacts* facts : candidates)
    {
        std::set<std::string>& occupied = collector.tables.at(facts->key.table).occupied_fields;
        const std::string& base = *facts->destination_roles.begin();
        std::string replacement = base;
        size_t suffix = 1;
        while (occupied.contains(replacement))
            replacement = base + "_" + std::to_string(++suffix);
        if (replacement != base)
            ++result.name_collisions_detected;

        std::vector<Edit> field_edits;
        bool valid = true;
        for (const Luau::Location& occurrence : facts->occurrences)
        {
            const std::optional<std::pair<size_t, size_t>> range = offsets.range(occurrence);
            if (!range || source.substr(range->first, range->second - range->first) != facts->key.name)
            {
                valid = false;
                break;
            }
            field_edits.push_back({range->first, range->second, replacement});
        }
        if (!valid)
        {
            ++result.unproven_fields;
            result.diagnostics.push_back("a generated callback field had an invalid source range");
            continue;
        }

        occupied.insert(replacement);
        ++result.fields_proposed;
        result.references_proposed += field_edits.size();
        edits.insert(edits.end(), std::make_move_iterator(field_edits.begin()), std::make_move_iterator(field_edits.end()));
    }

    if (edits.empty())
        return result;

    std::string candidate(source);
    applyEdits(candidate, edits);
    result.compile_attempted = true;
    std::string diagnostic;
    result.candidate_compiled = compiles(candidate, diagnostic);
    if (!result.candidate_compiled)
    {
        result.diagnostics.push_back("refined state fields were withheld because the candidate did not compile: " + diagnostic);
        return result;
    }

    result.source = std::move(candidate);
    result.committed = true;
    result.fields_renamed = result.fields_proposed;
    result.references_renamed = result.references_proposed;
    result.name_collisions_avoided = result.name_collisions_detected;
    return result;
}

} // namespace alex::deobfuscator::state_fields
