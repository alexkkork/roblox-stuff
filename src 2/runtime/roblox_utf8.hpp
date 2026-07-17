#pragma once

struct lua_State;

namespace rbx::runtime
{

// Adds the Roblox release-729 extensions to Luau's stock utf8 library.
// Call after luaL_openlibs and before luaL_sandbox.
void installRobloxUtf8(lua_State* L);

} // namespace rbx::runtime
