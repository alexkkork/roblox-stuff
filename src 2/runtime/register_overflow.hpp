#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace rbx::runtime
{

struct RegisterOverflowRewrite
{
    std::string source;
    bool applied = false;
    size_t functionsRewritten = 0;
    size_t bindingsSpilled = 0;
    size_t declarationsSunk = 0;
    size_t bindingsNarrowed = 0;
    size_t scopesNarrowed = 0;
    std::vector<std::string> diagnostics;
};

// Reduces simultaneous lexical lifetimes without changing bindings into table
// fields. Declarations are moved to their first containing statement and
// disconnected lifetime intervals receive ordinary Luau `do` scopes.
RegisterOverflowRewrite narrowRegisterOverflowScopes(std::string_view source, size_t retainedLocalTarget = 140);

// Rewrites excess lexical bindings into private per-function tables. This does
// not raise Luau's bytecode limits; it reduces register and upvalue pressure
// while preserving binding identity through the parsed AST.
RegisterOverflowRewrite spillRegisterOverflow(std::string_view source, size_t retainedLocalTarget = 140);

} // namespace rbx::runtime
