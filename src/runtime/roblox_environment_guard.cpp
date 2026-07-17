#include "roblox_environment_guard.hpp"

#include "release_manifest.hpp"

#include <algorithm>
#include <sstream>

namespace rbx::runtime
{
namespace
{

std::string boolText(bool value)
{
    return value ? "true" : "false";
}

template<typename T>
std::string valueText(const std::optional<T>& value)
{
    if (!value)
        return "missing";
    std::ostringstream stream;
    stream << *value;
    return stream.str();
}

template<>
std::string valueText(const std::optional<std::string>& value)
{
    return value ? *value : "missing";
}

class Evaluation
{
public:
    void require(bool condition, std::string code, std::string subject, std::string expected, std::string observed)
    {
        ++result.checksPerformed;
        if (!condition)
            result.findings.push_back({std::move(code), std::move(subject), std::move(expected), std::move(observed)});
    }

    RobloxEnvironmentResult finish()
    {
        result.passed = result.findings.empty();
        return std::move(result);
    }

private:
    RobloxEnvironmentResult result;
};

} // namespace

RobloxEnvironmentPolicy defaultRobloxEnvironmentPolicy()
{
    RobloxEnvironmentPolicy policy;
    policy.expectedEngineRelease = std::string(kEngineRelease);
    policy.expectedApiHash = std::string(kFullApiSha256);
    policy.expectedReflectionVersion = std::string(kReflectionDescriptorVersion);
    policy.requiredServices = {
        "Workspace",
        "RunService",
        "Players",
        "HttpService",
        "CollectionService",
        "TweenService",
        "Debris",
        "UserInputService",
        "ContextActionService",
    };
    return policy;
}

RobloxEnvironmentResult evaluateRobloxEnvironment(
    const v2::DataModelSnapshot& snapshot, const RobloxEnvironmentPolicy& policy)
{
    Evaluation evaluation;
    evaluation.require(snapshot.engineInitialized, "engine_uninitialized", "runtime engine", "initialized",
        snapshot.engineInitialized ? "initialized" : "missing");
    if (policy.requireSealedEngine)
        evaluation.require(snapshot.engineSealed, "engine_unsealed", "runtime engine", "sealed", snapshot.engineSealed ? "sealed" : "bootstrapping");
    if (!policy.expectedEngineRelease.empty())
        evaluation.require(snapshot.engineRelease == policy.expectedEngineRelease, "engine_release_mismatch", "engine release",
            policy.expectedEngineRelease, snapshot.engineRelease);
    if (!policy.expectedApiHash.empty())
        evaluation.require(snapshot.apiHash == policy.expectedApiHash, "api_hash_mismatch", "API descriptor",
            policy.expectedApiHash, snapshot.apiHash);
    if (!policy.expectedReflectionVersion.empty())
        evaluation.require(snapshot.reflectionVersion == policy.expectedReflectionVersion, "reflection_version_mismatch", "reflection metadata",
            policy.expectedReflectionVersion, snapshot.reflectionVersion);

    evaluation.require(snapshot.inspectionErrors.empty(), "inspection_failed", "native registry inspection", "no errors",
        snapshot.inspectionErrors.empty() ? "no errors" : snapshot.inspectionErrors.front());
    evaluation.require(snapshot.gameGlobalPresent, "game_missing", "game", "native DataModel", "missing");
    evaluation.require(snapshot.gameIsNativeInstance, "game_not_native", "game", "native Instance userdata",
        snapshot.gameIsNativeInstance ? "native userdata" : "non-native value");
    evaluation.require(snapshot.gameRegistryIdentityValid, "game_identity_mismatch", "game", "engine registry identity",
        boolText(snapshot.gameRegistryIdentityValid));
    evaluation.require(snapshot.gameClassName == "DataModel", "game_class_mismatch", "game.ClassName", "DataModel", snapshot.gameClassName);
    evaluation.require(!snapshot.gameDestroyed, "game_destroyed", "game", "live", snapshot.gameDestroyed ? "destroyed" : "live");
    evaluation.require(snapshot.gameInstanceId != 0, "game_id_invalid", "game registry id", "non-zero", std::to_string(snapshot.gameInstanceId));
    evaluation.require(snapshot.gameParentId == 0, "game_parent_mismatch", "game.Parent", "nil", std::to_string(snapshot.gameParentId));
    evaluation.require(snapshot.placeVersion && *snapshot.placeVersion >= 1, "place_version_invalid", "game.PlaceVersion", ">= 1",
        valueText(snapshot.placeVersion));

    if (policy.expectedPlaceId)
        evaluation.require(snapshot.placeId == policy.expectedPlaceId, "place_id_mismatch", "game.PlaceId",
            valueText(policy.expectedPlaceId), valueText(snapshot.placeId));
    if (policy.expectedGameId)
        evaluation.require(snapshot.gameId == policy.expectedGameId, "game_id_mismatch", "game.GameId",
            valueText(policy.expectedGameId), valueText(snapshot.gameId));
    if (policy.expectedJobId)
        evaluation.require(snapshot.jobId == policy.expectedJobId, "job_id_mismatch", "game.JobId",
            valueText(policy.expectedJobId), valueText(snapshot.jobId));

    evaluation.require(snapshot.workspaceGlobalPresent, "workspace_missing", "workspace", "native Workspace", "missing");
    evaluation.require(snapshot.workspaceIsNativeInstance, "workspace_not_native", "workspace", "native Instance userdata",
        snapshot.workspaceIsNativeInstance ? "native userdata" : "non-native value");
    evaluation.require(snapshot.workspaceRegistryIdentityValid, "workspace_identity_mismatch", "workspace", "engine registry identity",
        boolText(snapshot.workspaceRegistryIdentityValid));
    if (policy.requireWorkspaceAlias)
        evaluation.require(snapshot.workspaceAliasIdentityValid, "workspace_alias_mismatch", "Workspace", "same object as workspace",
            boolText(snapshot.workspaceAliasIdentityValid));
    evaluation.require(snapshot.workspaceClassName == "Workspace", "workspace_class_mismatch", "workspace.ClassName", "Workspace",
        snapshot.workspaceClassName);
    evaluation.require(!snapshot.workspaceDestroyed, "workspace_destroyed", "workspace", "live",
        snapshot.workspaceDestroyed ? "destroyed" : "live");
    evaluation.require(snapshot.workspaceParentId == snapshot.gameInstanceId && snapshot.gameInstanceId != 0,
        "workspace_parent_mismatch", "workspace.Parent", "game", std::to_string(snapshot.workspaceParentId));

    for (const std::string& requiredClass : policy.requiredServices)
    {
        std::vector<const v2::DataModelChildSnapshot*> matches;
        for (const v2::DataModelChildSnapshot& child : snapshot.directChildren)
            if (child.className == requiredClass)
                matches.push_back(&child);

        evaluation.require(matches.size() == 1, "service_singleton_mismatch", requiredClass, "exactly one DataModel child",
            std::to_string(matches.size()));
        if (matches.size() != 1)
            continue;

        const v2::DataModelChildSnapshot& service = *matches.front();
        evaluation.require(service.parentId == snapshot.gameInstanceId, "service_parent_mismatch", requiredClass + ".Parent", "game",
            std::to_string(service.parentId));
        evaluation.require(service.serviceClass, "service_tag_missing", requiredClass, "reflection Service tag", "not tagged Service");
        evaluation.require(!service.destroyed, "service_destroyed", requiredClass, "live", service.destroyed ? "destroyed" : "live");
        if (policy.requireNativeServiceObjects)
            evaluation.require(service.registryObjectValid, "service_identity_mismatch", requiredClass, "native registry object", "invalid object");
    }

    return evaluation.finish();
}

std::string_view robloxEnvironmentStatus(const RobloxEnvironmentResult& result)
{
    return result.passed ? "passed" : "failed";
}

} // namespace rbx::runtime
