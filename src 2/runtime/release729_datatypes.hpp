#pragma once

#include "lua.h"

#include <span>
#include <string_view>

namespace rbx::runtime
{

// Script-visible datatype catalog pinned to the release-729 environment.  The
// full API dump describes where datatypes are used, but not which constructor
// globals exist or whether values are mutable; this catalog is the host-side
// complement used by conformance tests and environment assembly.
enum class DatatypeAvailability
{
    ExistingNative,
    ExistingShim,
    Release729Pack,
    EngineProduced,
    Inaccessible,
    Unsupported,
};

struct DatatypeCatalogEntry
{
    std::string_view name;
    DatatypeAvailability availability;
    bool hasGlobal;
    bool constructible;
    bool mutableValue;
};

std::span<const DatatypeCatalogEntry> release729DatatypeCatalog();
std::string_view toString(DatatypeAvailability availability);

// Installs the release-729 datatype values that are independent of Instance
// reflection and the scheduler.  Existing globals are preserved unless this
// pack intentionally replaces a table-backed compatibility value with locked
// userdata.  Call after Enum and the core math datatypes are installed.
void installRelease729Datatypes(lua_State* state);

} // namespace rbx::runtime
