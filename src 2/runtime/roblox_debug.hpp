#pragma once

struct lua_State;

namespace rbx::runtime
{

// Adds Roblox's release-729 extensions to Luau's stock debug library.
// Call after luaL_openlibs and before luaL_sandbox.
void installRobloxDebug(lua_State* L);

} // namespace rbx::runtime
