#include "register_overflow.hpp"

#include "Luau/Ast.h"
#include "Luau/Parser.h"

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace rbx::runtime
{
namespace
{

class SourceOffsets
{
public:
    explicit SourceOffsets(std::string_view source)
        : source(source)
    {
        lineStarts.push_back(0);
        for (size_t index = 0; index < source.size(); ++index)
            if (source[index] == '\n')
                lineStarts.push_back(index + 1);
    }

    std::optional<size_t> offset(const Luau::Position& position) const
    {
        if (!position.hasValue() || position.line >= lineStarts.size())
            return std::nullopt;

        const size_t begin = lineStarts[position.line];
        const size_t end = position.line + 1 < lineStarts.size() ? lineStarts[position.line + 1] - 1 : source.size();
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
    std::vector<size_t> lineStarts;
};

struct Edit
{
    size_t begin = 0;
    size_t end = 0;
    std::string replacement;
};

struct Candidate
{
    Luau::AstStat* statement = nullptr;
    std::vector<Luau::AstLocal*> bindings;
    bool supported = true;
};

struct FunctionRegion
{
    Luau::AstExprFunction* function = nullptr;
    size_t begin = 0;
    size_t end = 0;
    size_t insertion = 0;
    size_t functionDepth = 0;
    std::string spillName;
    std::vector<Luau::AstLocal*> locals;
    std::vector<Candidate*> candidates;
};

class Collector final : public Luau::AstVisitor
{
public:
    std::vector<Luau::AstExprFunction*> functions;
    std::vector<Luau::AstExprLocal*> references;
    std::vector<Candidate> candidates;
    std::vector<Luau::AstLocal*> locals;
    std::set<std::string> occupiedNames;

    bool visit(Luau::AstExprFunction* node) override
    {
        functions.push_back(node);
        add(node->self);
        for (Luau::AstLocal* argument : node->args)
            add(argument);
        return true;
    }

    bool visit(Luau::AstExprLocal* node) override
    {
        references.push_back(node);
        return true;
    }

    bool visit(Luau::AstStatLocal* node) override
    {
        Candidate candidate;
        candidate.statement = node;
        for (Luau::AstLocal* local : node->vars)
        {
            add(local);
            candidate.bindings.push_back(local);
            if (local->annotation)
                candidate.supported = false;
        }
        candidates.push_back(std::move(candidate));
        return true;
    }

    bool visit(Luau::AstStatLocalFunction* node) override
    {
        add(node->name);
        Candidate candidate;
        candidate.statement = node;
        candidate.bindings.push_back(node->name);
        candidate.supported = node->name->annotation == nullptr;
        candidates.push_back(std::move(candidate));
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

private:
    void add(Luau::AstLocal* local)
    {
        if (!local)
            return;
        locals.push_back(local);
        if (local->name.value)
            occupiedNames.insert(local->name.value);
    }
};

class BlockCollector final : public Luau::AstVisitor
{
public:
    std::vector<Luau::AstStatBlock*> blocks;

    bool visit(Luau::AstStatBlock* node) override
    {
        blocks.push_back(node);
        return true;
    }
};

class ReferenceCollector final : public Luau::AstVisitor
{
public:
    std::vector<Luau::AstLocal*> references;

    bool visit(Luau::AstExprLocal* node) override
    {
        references.push_back(node->local);
        return true;
    }
};

struct FunctionSpan
{
    size_t begin = 0;
    size_t end = 0;
    size_t id = 0;
};

class FunctionLayout
{
public:
    FunctionLayout(const Collector& collector, const SourceOffsets& offsets)
    {
        for (Luau::AstExprFunction* function : collector.functions)
        {
            if (const auto range = offsets.range(function->location))
                spans.push_back({range->first, range->second, 0});
        }

        std::sort(spans.begin(), spans.end(), [](const FunctionSpan& left, const FunctionSpan& right) {
            if (left.begin != right.begin)
                return left.begin < right.begin;
            return left.end > right.end;
        });
        for (size_t index = 0; index < spans.size(); ++index)
            spans[index].id = index + 1;
    }

    size_t owner(size_t begin, size_t end) const
    {
        size_t result = 0;
        size_t width = size_t(-1);
        for (const FunctionSpan& span : spans)
        {
            if (span.begin <= begin && end <= span.end && span.end - span.begin < width)
            {
                result = span.id;
                width = span.end - span.begin;
            }
        }
        return result;
    }

private:
    std::vector<FunctionSpan> spans;
};

std::unordered_map<size_t, size_t> localPressureByFunction(
    const Collector& collector,
    const SourceOffsets& offsets,
    const FunctionLayout& layout
)
{
    std::unordered_map<size_t, size_t> pressure;
    for (Luau::AstLocal* local : collector.locals)
    {
        if (const auto range = offsets.range(local->location))
            ++pressure[layout.owner(range->first, range->second)];
    }
    return pressure;
}

std::string indentationAt(std::string_view source, size_t offset)
{
    if (offset > source.size())
        return {};

    const size_t lineStart = offset == 0 ? 0 : source.rfind('\n', offset - 1) + 1;
    const std::string_view prefix = source.substr(lineStart, offset - lineStart);
    if (prefix.find_first_not_of(" \t") != std::string_view::npos)
        return {};
    return std::string(prefix);
}

std::vector<Luau::AstLocal*> directBindings(Luau::AstStat* statement)
{
    std::vector<Luau::AstLocal*> result;
    if (auto local = statement->as<Luau::AstStatLocal>())
    {
        for (Luau::AstLocal* binding : local->vars)
            result.push_back(binding);
    }
    else if (auto function = statement->as<Luau::AstStatLocalFunction>())
        result.push_back(function->name);
    return result;
}

std::string bindingMetricName(Luau::AstLocal* binding)
{
    return binding->name.value ? std::string(binding->name.value) : std::string{};
}

bool hasScopeSensitiveDeclaration(Luau::AstStat* statement)
{
    return statement->is<Luau::AstStatTypeAlias>() || statement->is<Luau::AstStatTypeFunction>() ||
           statement->is<Luau::AstStatDeclareGlobal>() || statement->is<Luau::AstStatDeclareFunction>() ||
           statement->is<Luau::AstStatClass>() || statement->is<Luau::AstStatDeclareExternType>();
}

bool parsesCleanly(std::string_view source)
{
    Luau::Allocator allocator;
    Luau::AstNameTable names(allocator);
    const Luau::ParseResult parsed = Luau::Parser::parse(source.data(), source.size(), names, allocator);
    return parsed.root && parsed.errors.empty();
}

struct SinkInsertion
{
    size_t origin = 0;
    std::string declaration;
};

bool encloses(const FunctionRegion& region, size_t begin, size_t end)
{
    return region.begin <= begin && end <= region.end;
}

FunctionRegion* ownerFor(std::vector<FunctionRegion>& regions, size_t begin, size_t end, size_t functionDepth)
{
    FunctionRegion* owner = &regions.front();
    size_t ownerWidth = owner->end - owner->begin;
    for (FunctionRegion& region : regions)
    {
        if (region.functionDepth != functionDepth || !encloses(region, begin, end))
            continue;
        const size_t width = region.end - region.begin;
        if (width <= ownerWidth)
        {
            owner = &region;
            ownerWidth = width;
        }
    }
    return owner;
}

std::string uniqueSpillName(const std::set<std::string>& occupied, size_t ordinal)
{
    for (;; ++ordinal)
    {
        std::string candidate = ordinal == 1 ? "script_state" : "script_state_" + std::to_string(ordinal);
        if (!occupied.count(candidate))
            return candidate;
    }
}

std::string uniqueFieldName(std::string_view preferred, std::set<std::string>& occupied, size_t fallbackOrdinal)
{
    std::string base = preferred.empty() ? "value_" + std::to_string(fallbackOrdinal) : std::string(preferred);
    std::string candidate = base;
    size_t suffix = 1;
    while (!occupied.insert(candidate).second)
        candidate = base + "_" + std::to_string(++suffix);
    return candidate;
}

void applyEdits(std::string& source, std::vector<Edit>& edits)
{
    std::sort(edits.begin(), edits.end(), [](const Edit& left, const Edit& right) {
        if (left.begin != right.begin)
            return left.begin > right.begin;
        return left.end > right.end;
    });

    size_t previousBegin = source.size() + 1;
    for (const Edit& edit : edits)
    {
        if (edit.begin > edit.end || edit.end > source.size() || edit.end > previousBegin)
            continue;
        source.replace(edit.begin, edit.end - edit.begin, edit.replacement);
        previousBegin = edit.begin;
    }
}

} // namespace

RegisterOverflowRewrite narrowRegisterOverflowScopes(std::string_view source, size_t retainedLocalTarget)
{
    RegisterOverflowRewrite result;
    result.source.assign(source);
    std::unordered_set<size_t> rewrittenFunctions;
    std::map<std::pair<size_t, std::string>, size_t> sunkBindingCounts;

    // First split side-effect-free declarations by the direct statement that
    // first references each AST binding. References outside the block's direct
    // statements (notably a repeat-until condition) keep the binding in place.
    {
        Luau::Allocator allocator;
        Luau::AstNameTable names(allocator);
        Luau::ParseResult parsed = Luau::Parser::parse(source.data(), source.size(), names, allocator);
        if (!parsed.root || !parsed.errors.empty())
        {
            result.diagnostics.push_back("source could not be parsed for register lifetime narrowing");
            return result;
        }

        const SourceOffsets offsets(source);
        Collector collector;
        parsed.root->visit(&collector);
        const FunctionLayout layout(collector, offsets);
        const std::unordered_map<size_t, size_t> pressure = localPressureByFunction(collector, offsets, layout);

        std::unordered_map<Luau::AstLocal*, size_t> totalReferences;
        for (Luau::AstExprLocal* reference : collector.references)
            ++totalReferences[reference->local];

        BlockCollector blocks;
        parsed.root->visit(&blocks);
        std::vector<Edit> edits;
        std::map<size_t, std::vector<SinkInsertion>> insertions;
        std::unordered_set<size_t> phaseFunctions;
        std::map<std::pair<size_t, std::string>, size_t> phaseBindingCounts;
        size_t declarationsSunk = 0;
        size_t bindingsNarrowed = 0;

        for (Luau::AstStatBlock* block : blocks.blocks)
        {
            const size_t statementCount = block->body.size;
            if (statementCount == 0)
                continue;

            std::vector<std::vector<Luau::AstLocal*>> references(statementCount);
            std::unordered_map<Luau::AstLocal*, size_t> observedReferences;
            for (size_t index = 0; index < statementCount; ++index)
            {
                ReferenceCollector statementReferences;
                block->body.data[index]->visit(&statementReferences);
                references[index] = std::move(statementReferences.references);
                for (Luau::AstLocal* local : references[index])
                    ++observedReferences[local];
            }

            for (size_t index = 0; index < statementCount; ++index)
            {
                auto declaration = block->body.data[index]->as<Luau::AstStatLocal>();
                if (!declaration || declaration->values.size != 0 || declaration->isConst || declaration->isExported)
                    continue;

                bool supported = declaration->vars.size != 0;
                for (Luau::AstLocal* binding : declaration->vars)
                    supported = supported && binding->annotation == nullptr;
                if (!supported)
                    continue;

                const auto statementRange = offsets.range(declaration->location);
                const auto firstBindingRange = offsets.range(declaration->vars.data[0]->location);
                if (!statementRange || !firstBindingRange)
                    continue;

                const size_t owner = layout.owner(firstBindingRange->first, firstBindingRange->second);
                const auto ownerPressure = pressure.find(owner);
                if (ownerPressure == pressure.end() || ownerPressure->second <= retainedLocalTarget)
                    continue;

                std::unordered_map<Luau::AstLocal*, std::string> bindingSource;
                for (Luau::AstLocal* binding : declaration->vars)
                {
                    const auto bindingRange = offsets.range(binding->location);
                    if (!bindingRange)
                    {
                        supported = false;
                        break;
                    }
                    bindingSource[binding] = std::string(source.substr(bindingRange->first, bindingRange->second - bindingRange->first));
                }
                if (!supported)
                    continue;

                std::vector<Luau::AstLocal*> retained;
                std::map<size_t, std::vector<Luau::AstLocal*>> moved;
                std::vector<Luau::AstLocal*> changed;
                size_t changedBindings = 0;
                for (Luau::AstLocal* binding : declaration->vars)
                {
                    std::optional<size_t> firstUse;
                    for (size_t useIndex = index + 1; useIndex < statementCount && !firstUse; ++useIndex)
                    {
                        if (std::find(references[useIndex].begin(), references[useIndex].end(), binding) != references[useIndex].end())
                            firstUse = useIndex;
                    }

                    const bool hasOutsideReference = observedReferences[binding] < totalReferences[binding];
                    if (firstUse && *firstUse > index + 1)
                    {
                        moved[*firstUse].push_back(binding);
                        changed.push_back(binding);
                        ++changedBindings;
                    }
                    else if (firstUse || hasOutsideReference)
                        retained.push_back(binding);
                    else
                    {
                        changed.push_back(binding);
                        ++changedBindings;
                    }
                }

                if (changedBindings == 0)
                    continue;

                std::map<size_t, size_t> targetOffsets;
                for (const auto& [targetIndex, bindings] : moved)
                {
                    (void)bindings;
                    const auto targetRange = offsets.range(block->body.data[targetIndex]->location);
                    if (!targetRange)
                    {
                        supported = false;
                        break;
                    }
                    targetOffsets[targetIndex] = targetRange->first;
                }
                if (!supported)
                    continue;

                auto makeDeclaration = [&](const std::vector<Luau::AstLocal*>& bindings) {
                    std::string text = "local ";
                    for (size_t bindingIndex = 0; bindingIndex < bindings.size(); ++bindingIndex)
                    {
                        if (bindingIndex != 0)
                            text += ", ";
                        text += bindingSource.at(bindings[bindingIndex]);
                    }
                    return text;
                };

                edits.push_back({statementRange->first, statementRange->second, retained.empty() ? std::string{} : makeDeclaration(retained)});
                for (const auto& [targetIndex, bindings] : moved)
                    insertions[targetOffsets.at(targetIndex)].push_back({statementRange->first, makeDeclaration(bindings)});

                ++declarationsSunk;
                bindingsNarrowed += changedBindings;
                for (Luau::AstLocal* binding : changed)
                    ++phaseBindingCounts[{owner, bindingMetricName(binding)}];
                phaseFunctions.insert(owner);
            }
        }

        for (auto& [offset, pending] : insertions)
        {
            std::sort(pending.begin(), pending.end(), [](const SinkInsertion& left, const SinkInsertion& right) {
                return left.origin < right.origin;
            });
            const std::string indentation = indentationAt(source, offset);
            std::string replacement;
            for (const SinkInsertion& insertion : pending)
                replacement += insertion.declaration + "\n" + indentation;
            edits.push_back({offset, offset, std::move(replacement)});
        }

        if (!edits.empty())
        {
            std::string narrowed = result.source;
            applyEdits(narrowed, edits);
            if (parsesCleanly(narrowed))
            {
                result.source = std::move(narrowed);
                result.declarationsSunk += declarationsSunk;
                result.bindingsNarrowed += bindingsNarrowed;
                for (const auto& [binding, count] : phaseBindingCounts)
                    sunkBindingCounts[binding] += count;
                rewrittenFunctions.insert(phaseFunctions.begin(), phaseFunctions.end());
            }
            else
                result.diagnostics.push_back("sunk register declarations did not reparse; declaration sinking was skipped");
        }
    }

    // Reparse after sinking, then place ordinary scopes around declaration
    // intervals that close before a later direct declaration. Bindings that
    // began outside an interval remain in the surrounding lexical scope.
    {
        Luau::Allocator allocator;
        Luau::AstNameTable names(allocator);
        Luau::ParseResult parsed = Luau::Parser::parse(result.source.data(), result.source.size(), names, allocator);
        if (!parsed.root || !parsed.errors.empty())
        {
            result.diagnostics.push_back("source could not be reparsed for register scope narrowing");
            result.functionsRewritten = rewrittenFunctions.size();
            result.applied = result.source != source;
            return result;
        }

        const SourceOffsets offsets(result.source);
        Collector collector;
        parsed.root->visit(&collector);
        const FunctionLayout layout(collector, offsets);
        const std::unordered_map<size_t, size_t> pressure = localPressureByFunction(collector, offsets, layout);

        std::unordered_map<Luau::AstLocal*, size_t> totalReferences;
        for (Luau::AstExprLocal* reference : collector.references)
            ++totalReferences[reference->local];

        BlockCollector blocks;
        parsed.root->visit(&blocks);
        std::vector<Edit> edits;
        std::unordered_set<size_t> phaseFunctions;
        std::map<std::pair<size_t, std::string>, size_t> phaseBindingCounts;
        size_t scopesNarrowed = 0;

        for (Luau::AstStatBlock* block : blocks.blocks)
        {
            const size_t statementCount = block->body.size;
            if (statementCount < 2)
                continue;

            std::vector<std::vector<Luau::AstLocal*>> references(statementCount);
            std::vector<std::vector<Luau::AstLocal*>> declarations(statementCount);
            std::unordered_map<Luau::AstLocal*, size_t> observedReferences;
            for (size_t index = 0; index < statementCount; ++index)
            {
                ReferenceCollector statementReferences;
                block->body.data[index]->visit(&statementReferences);
                references[index] = std::move(statementReferences.references);
                declarations[index] = directBindings(block->body.data[index]);
                for (Luau::AstLocal* local : references[index])
                    ++observedReferences[local];
            }

            std::unordered_map<Luau::AstLocal*, size_t> lastUse;
            for (size_t declarationIndex = 0; declarationIndex < statementCount; ++declarationIndex)
            {
                for (Luau::AstLocal* binding : declarations[declarationIndex])
                {
                    size_t end = declarationIndex;
                    for (size_t useIndex = declarationIndex; useIndex < statementCount; ++useIndex)
                    {
                        if (std::find(references[useIndex].begin(), references[useIndex].end(), binding) != references[useIndex].end())
                            end = useIndex;
                    }
                    if (observedReferences[binding] < totalReferences[binding])
                        end = statementCount;
                    lastUse[binding] = end;
                }
            }

            size_t cursor = 0;
            while (cursor < statementCount)
            {
                size_t start = cursor;
                while (start < statementCount && declarations[start].empty())
                    ++start;
                if (start == statementCount)
                    break;

                const auto firstBindingRange = offsets.range(declarations[start].front()->location);
                if (!firstBindingRange)
                {
                    cursor = start + 1;
                    continue;
                }
                const size_t owner = layout.owner(firstBindingRange->first, firstBindingRange->second);
                const auto ownerPressure = pressure.find(owner);
                if (ownerPressure == pressure.end() || ownerPressure->second <= retainedLocalTarget)
                {
                    cursor = start + 1;
                    continue;
                }

                size_t end = start;
                size_t scan = start;
                while (scan < statementCount && scan <= end)
                {
                    for (Luau::AstLocal* binding : declarations[scan])
                        end = std::max(end, lastUse.at(binding));
                    ++scan;
                }
                if (end >= statementCount)
                {
                    cursor = start + 1;
                    continue;
                }

                bool hasLaterDeclaration = false;
                for (size_t index = end + 1; index < statementCount; ++index)
                    hasLaterDeclaration = hasLaterDeclaration || !declarations[index].empty();
                if (!hasLaterDeclaration)
                {
                    cursor = start + 1;
                    continue;
                }

                bool scopeSensitive = false;
                for (size_t index = start; index <= end; ++index)
                    scopeSensitive = scopeSensitive || hasScopeSensitiveDeclaration(block->body.data[index]);
                if (scopeSensitive)
                {
                    cursor = start + 1;
                    continue;
                }

                const auto startRange = offsets.range(block->body.data[start]->location);
                const auto endRange = offsets.range(block->body.data[end]->location);
                if (!startRange || !endRange)
                {
                    cursor = start + 1;
                    continue;
                }

                const std::string indentation = indentationAt(result.source, startRange->first);
                edits.push_back({startRange->first, startRange->first, "do\n" + indentation});
                edits.push_back({endRange->second, endRange->second, "\n" + indentation + "end"});
                ++scopesNarrowed;
                for (size_t index = start; index <= end; ++index)
                    for (Luau::AstLocal* binding : declarations[index])
                        ++phaseBindingCounts[{owner, bindingMetricName(binding)}];
                phaseFunctions.insert(owner);
                cursor = end + 1;
            }
        }

        if (!edits.empty())
        {
            std::string narrowed = result.source;
            applyEdits(narrowed, edits);
            if (parsesCleanly(narrowed))
            {
                result.source = std::move(narrowed);
                result.scopesNarrowed += scopesNarrowed;
                for (const auto& [binding, count] : phaseBindingCounts)
                {
                    const auto sunk = sunkBindingCounts.find(binding);
                    const size_t alreadyCounted = sunk == sunkBindingCounts.end() ? 0 : sunk->second;
                    if (count > alreadyCounted)
                        result.bindingsNarrowed += count - alreadyCounted;
                }
                rewrittenFunctions.insert(phaseFunctions.begin(), phaseFunctions.end());
            }
            else
                result.diagnostics.push_back("narrowed register scopes did not reparse; scope narrowing was skipped");
        }
    }

    result.functionsRewritten = rewrittenFunctions.size();
    result.applied = result.source != source;
    return result;
}

RegisterOverflowRewrite spillRegisterOverflow(std::string_view source, size_t retainedLocalTarget)
{
    RegisterOverflowRewrite result;
    result.source.assign(source);

    Luau::Allocator allocator;
    Luau::AstNameTable names(allocator);
    Luau::ParseResult parsed = Luau::Parser::parse(source.data(), source.size(), names, allocator);
    if (!parsed.root || !parsed.errors.empty())
    {
        result.diagnostics.push_back("source could not be parsed for register spilling");
        return result;
    }

    const SourceOffsets offsets(source);
    Collector collector;
    parsed.root->visit(&collector);

    std::vector<FunctionRegion> regions;
    regions.push_back({nullptr, 0, source.size(), 0, 0});
    for (Luau::AstExprFunction* function : collector.functions)
    {
        const auto functionRange = offsets.range(function->location);
        const auto bodyRange = function->body ? offsets.range(function->body->location) : std::nullopt;
        if (!functionRange || !bodyRange)
            continue;
        regions.push_back({function, functionRange->first, functionRange->second, bodyRange->first, function->functionDepth});
    }

    std::unordered_map<Luau::AstLocal*, FunctionRegion*> localOwners;
    for (Luau::AstLocal* local : collector.locals)
    {
        const auto range = offsets.range(local->location);
        if (range)
        {
            FunctionRegion* owner = ownerFor(regions, range->first, range->second, local->functionDepth);
            owner->locals.push_back(local);
            localOwners[local] = owner;
        }
    }
    for (Candidate& candidate : collector.candidates)
    {
        if (!candidate.bindings.empty())
            if (auto owner = localOwners.find(candidate.bindings.front()); owner != localOwners.end())
                owner->second->candidates.push_back(&candidate);
    }

    std::unordered_map<Luau::AstLocal*, std::string> replacements;
    std::unordered_map<Luau::AstStat*, FunctionRegion*> selectedStatements;
    size_t spillOrdinal = 1;

    for (FunctionRegion& region : regions)
    {
        if (region.locals.size() <= retainedLocalTarget)
            continue;

        region.spillName = uniqueSpillName(collector.occupiedNames, spillOrdinal++);
        size_t remaining = region.locals.size();
        size_t slot = 1;
        std::set<std::string> occupiedFields;

        for (auto iterator = region.candidates.rbegin();
             iterator != region.candidates.rend() && remaining > retainedLocalTarget;
             ++iterator)
        {
            Candidate* candidate = *iterator;
            if (!candidate->supported)
                continue;
            selectedStatements[candidate->statement] = &region;
            for (Luau::AstLocal* binding : candidate->bindings)
            {
                const std::string_view preferred = binding->name.value ? std::string_view(binding->name.value) : std::string_view{};
                replacements[binding] = region.spillName + "." + uniqueFieldName(preferred, occupiedFields, slot++);
                --remaining;
            }
        }

        if (remaining > retainedLocalTarget)
        {
            result.diagnostics.push_back(
                "function at line " + std::to_string(region.function ? region.function->location.begin.line + 1 : 1) +
                " contains unspillable parameters, loop bindings, or typed declarations");
        }
        if (slot > 1)
        {
            result.functionsRewritten++;
            result.bindingsSpilled += slot - 1;
        }
    }

    if (replacements.empty())
        return result;

    std::vector<Edit> edits;
    for (FunctionRegion& region : regions)
        if (!region.spillName.empty())
            edits.push_back({region.insertion, region.insertion, "local " + region.spillName + " = {}\n"});

    for (const auto& [statement, region] : selectedStatements)
    {
        const auto statementRange = offsets.range(statement->location);
        if (!statementRange)
            continue;

        if (auto local = statement->as<Luau::AstStatLocal>())
        {
            if (local->values.size == 0)
            {
                edits.push_back({statementRange->first, statementRange->second, ""});
                continue;
            }

            const auto firstVariable = offsets.range(local->vars.data[0]->location);
            if (!firstVariable)
                continue;
            edits.push_back({statementRange->first, firstVariable->first, ""});
            for (Luau::AstLocal* binding : local->vars)
            {
                const auto bindingRange = offsets.range(binding->location);
                if (bindingRange)
                    edits.push_back({bindingRange->first, bindingRange->second, replacements.at(binding)});
            }
        }
        else if (auto function = statement->as<Luau::AstStatLocalFunction>())
        {
            const auto nameRange = offsets.range(function->name->location);
            if (nameRange)
                edits.push_back({statementRange->first, nameRange->second, replacements.at(function->name) + " = function"});
        }
    }

    for (Luau::AstExprLocal* reference : collector.references)
    {
        const auto replacement = replacements.find(reference->local);
        if (replacement == replacements.end())
            continue;
        const auto range = offsets.range(reference->location);
        if (range)
            edits.push_back({range->first, range->second, replacement->second});
    }

    applyEdits(result.source, edits);
    result.applied = true;
    return result;
}

} // namespace rbx::runtime
