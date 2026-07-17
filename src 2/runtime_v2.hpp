#pragma once

#include "runtime/release_manifest.hpp"

#include "lua.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rbx::v2
{

constexpr int kInstanceTag = 20;
constexpr int kRuntimeVersion = ::rbx::runtime::kReportSchemaVersion;
constexpr std::string_view kEngineRelease = ::rbx::runtime::kEngineRelease;

struct EngineOptions
{
    bool strictUnsupported = false;
    bool executorExtensions = false;
};

struct DataModelChildSnapshot
{
    uint64_t instanceId = 0;
    uint64_t parentId = 0;
    std::string className;
    std::string name;
    bool serviceClass = false;
    bool destroyed = false;
    bool registryObjectValid = false;
};

struct DataModelSnapshot
{
    bool engineInitialized = false;
    bool engineSealed = false;
    std::string engineRelease;
    std::string apiHash;
    std::string reflectionVersion;

    bool gameGlobalPresent = false;
    bool gameIsNativeInstance = false;
    bool gameRegistryIdentityValid = false;
    uint64_t gameInstanceId = 0;
    uint64_t gameParentId = 0;
    std::string gameClassName;
    std::string gameName;
    bool gameDestroyed = false;

    std::optional<int64_t> placeId;
    std::optional<int64_t> gameId;
    std::optional<int64_t> placeVersion;
    std::optional<std::string> jobId;

    bool workspaceGlobalPresent = false;
    bool workspaceIsNativeInstance = false;
    bool workspaceRegistryIdentityValid = false;
    bool workspaceAliasIdentityValid = false;
    uint64_t workspaceInstanceId = 0;
    uint64_t workspaceParentId = 0;
    std::string workspaceClassName;
    bool workspaceDestroyed = false;

    std::vector<DataModelChildSnapshot> directChildren;
    std::vector<std::string> inspectionErrors;
};

void initialize(lua_State* L, std::string_view apiDumpJson, const EngineOptions& options);
void seal(lua_State* L);
void shutdown(lua_State* L);
bool pushExecute(lua_State* L);
bool pushSchedulerReport(lua_State* L);
std::string engineStatsJson(lua_State* L);
DataModelSnapshot inspectDataModel(lua_State* L);

bool isInstance(lua_State* L, int index);
std::string instanceClassName(lua_State* L, int index);
bool enumItemName(lua_State* L, int index, std::string_view expectedType, std::string& itemName);

const char* shimSource();

} // namespace rbx::v2
