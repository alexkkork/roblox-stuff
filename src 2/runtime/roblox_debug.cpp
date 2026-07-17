#include "roblox_debug.hpp"

#include "runtime_context.hpp"

#include "lua.h"
#include "lualib.h"

#include <string>

namespace rbx::runtime
{
namespace
{

ThreadContext& currentThread(lua_State* L)
{
    ThreadContext* thread = RuntimeContext::threadFrom(L);
    if (!thread)
        luaL_error(L, "debug library is not attached to a runtime thread");
    return *thread;
}

std::string automaticMemoryCategory(const ThreadContext& thread)
{
    return thread.script.debugName.empty() ? "RuntimeScript" : thread.script.debugName;
}

int debugDumpCodeSize(lua_State* L)
{
    luaL_error(L, "dumpcodesize can only be called from CommandBar");
    return 0;
}

int debugLoadModule(lua_State* L)
{
    luaL_error(L, "debug.loadmodule is not enabled.");
    return 0;
}

int debugDumpHeap(lua_State* L)
{
    luaL_error(L, "debug.dumpheap is not enabled.");
    return 0;
}

int debugDumpRefs(lua_State* L)
{
    luaL_error(L, "debug.dumprefs is not enabled.");
    return 0;
}

int debugTraceRefs(lua_State* L)
{
    luaL_error(L, "debug.tracerefs is not enabled.");
    return 0;
}

int debugGetMemoryCategory(lua_State* L)
{
    ThreadContext& thread = currentThread(L);
    if (thread.memoryCategory.empty())
    {
        const std::string category = automaticMemoryCategory(thread);
        lua_pushlstring(L, category.data(), category.size());
    }
    else
        lua_pushlstring(L, thread.memoryCategory.data(), thread.memoryCategory.size());
    return 1;
}

int debugSetMemoryCategory(lua_State* L)
{
    size_t length = 0;
    const char* category = luaL_checklstring(L, 1, &length);
    if (length == 0 || length > 255)
        luaL_error(L, "invalid memory category");
    currentThread(L).memoryCategory.assign(category, length);
    return 0;
}

int debugResetMemoryCategory(lua_State* L)
{
    currentThread(L).memoryCategory.clear();
    return 0;
}

int debugProfileBegin(lua_State* L)
{
    size_t length = 0;
    const char* label = luaL_checklstring(L, 1, &length);
    if (length == 0 || length > 1024)
        luaL_error(L, "invalid profile label");
    ThreadContext& thread = currentThread(L);
    if (thread.profileLabels.size() >= 1024)
        luaL_error(L, "debug.profilebegin nesting limit exceeded");
    thread.profileLabels.emplace_back(label, length);
    return 0;
}

int debugProfileEnd(lua_State* L)
{
    ThreadContext& thread = currentThread(L);
    // Roblox logs an unmatched profileend diagnostic but does not make the
    // script fail. A headless runner has no MicroProfiler output sink.
    if (!thread.profileLabels.empty())
        thread.profileLabels.pop_back();
    return 0;
}

} // namespace

void installRobloxDebug(lua_State* L)
{
    lua_getglobal(L, "debug");
    if (!lua_istable(L, -1))
        luaL_error(L, "debug library is unavailable");
    // Registration order is script-visible through next().  This sequence
    // reproduces Studio 0.729.0.7290838's native debug table layout.
    lua_pushcfunction(L, debugDumpHeap, "dumpheap");
    lua_setfield(L, -2, "dumpheap");
    lua_pushcfunction(L, debugSetMemoryCategory, "setmemorycategory");
    lua_setfield(L, -2, "setmemorycategory");
    lua_pushcfunction(L, debugDumpCodeSize, "dumpcodesize");
    lua_setfield(L, -2, "dumpcodesize");
    lua_pushcfunction(L, debugProfileBegin, "profilebegin");
    lua_setfield(L, -2, "profilebegin");
    lua_pushcfunction(L, debugProfileEnd, "profileend");
    lua_setfield(L, -2, "profileend");
    lua_pushcfunction(L, debugLoadModule, "loadmodule");
    lua_setfield(L, -2, "loadmodule");
    lua_pushcfunction(L, debugDumpRefs, "dumprefs");
    lua_setfield(L, -2, "dumprefs");
    lua_pushcfunction(L, debugGetMemoryCategory, "getmemorycategory");
    lua_setfield(L, -2, "getmemorycategory");
    lua_pushcfunction(L, debugResetMemoryCategory, "resetmemorycategory");
    lua_setfield(L, -2, "resetmemorycategory");
    lua_pushcfunction(L, debugTraceRefs, "tracerefs");
    lua_setfield(L, -2, "tracerefs");
    lua_pop(L, 1);
}

} // namespace rbx::runtime
