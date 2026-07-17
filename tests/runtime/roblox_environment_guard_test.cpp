#include "runtime/release_manifest.hpp"
#include "runtime/roblox_environment_guard.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

namespace
{

rbx::v2::DataModelSnapshot validSnapshot()
{
    rbx::v2::DataModelSnapshot snapshot;
    snapshot.engineInitialized = true;
    snapshot.engineSealed = true;
    snapshot.engineRelease = std::string(rbx::runtime::kEngineRelease);
    snapshot.apiHash = std::string(rbx::runtime::kFullApiSha256);
    snapshot.reflectionVersion = std::string(rbx::runtime::kReflectionDescriptorVersion);
    snapshot.gameGlobalPresent = true;
    snapshot.gameIsNativeInstance = true;
    snapshot.gameRegistryIdentityValid = true;
    snapshot.gameInstanceId = 1;
    snapshot.gameClassName = "DataModel";
    snapshot.gameName = "game";
    snapshot.placeId = 123;
    snapshot.gameId = 456;
    snapshot.placeVersion = 1;
    snapshot.jobId = "job-789";
    snapshot.workspaceGlobalPresent = true;
    snapshot.workspaceIsNativeInstance = true;
    snapshot.workspaceRegistryIdentityValid = true;
    snapshot.workspaceAliasIdentityValid = true;
    snapshot.workspaceInstanceId = 2;
    snapshot.workspaceParentId = 1;
    snapshot.workspaceClassName = "Workspace";

    uint64_t id = 2;
    for (const std::string& name : rbx::runtime::defaultRobloxEnvironmentPolicy().requiredServices)
        snapshot.directChildren.push_back({id++, 1, name, name, true, false, true});
    return snapshot;
}

bool hasFinding(const rbx::runtime::RobloxEnvironmentResult& result, const std::string& code)
{
    return std::any_of(result.findings.begin(), result.findings.end(), [&](const auto& finding) { return finding.code == code; });
}

} // namespace

int main()
{
    try
    {
        rbx::runtime::RobloxEnvironmentPolicy policy = rbx::runtime::defaultRobloxEnvironmentPolicy();
        policy.expectedPlaceId = 123;
        policy.expectedGameId = 456;
        policy.expectedJobId = "job-789";

        const rbx::runtime::RobloxEnvironmentResult valid =
            rbx::runtime::evaluateRobloxEnvironment(validSnapshot(), policy);
        if (!valid.passed || valid.checksPerformed < 50 || !valid.findings.empty())
            throw std::runtime_error("valid native DataModel snapshot was rejected");

        rbx::v2::DataModelSnapshot replacedGame = validSnapshot();
        replacedGame.gameRegistryIdentityValid = false;
        const auto replacedResult = rbx::runtime::evaluateRobloxEnvironment(replacedGame, policy);
        if (replacedResult.passed || !hasFinding(replacedResult, "game_identity_mismatch"))
            throw std::runtime_error("replaced game userdata was not detected");

        rbx::v2::DataModelSnapshot duplicateService = validSnapshot();
        duplicateService.directChildren.push_back({999, 1, "Players", "Players", true, false, true});
        const auto duplicateResult = rbx::runtime::evaluateRobloxEnvironment(duplicateService, policy);
        if (duplicateResult.passed || !hasFinding(duplicateResult, "service_singleton_mismatch"))
            throw std::runtime_error("duplicate service singleton was not detected");

        rbx::v2::DataModelSnapshot wrongIdentity = validSnapshot();
        wrongIdentity.placeId = 124;
        wrongIdentity.jobId = "forged-job";
        const auto identityResult = rbx::runtime::evaluateRobloxEnvironment(wrongIdentity, policy);
        if (identityResult.passed || !hasFinding(identityResult, "place_id_mismatch") || !hasFinding(identityResult, "job_id_mismatch"))
            throw std::runtime_error("DataModel identity mismatch was not detected");

        rbx::v2::DataModelSnapshot detachedWorkspace = validSnapshot();
        detachedWorkspace.workspaceParentId = 0;
        const auto workspaceResult = rbx::runtime::evaluateRobloxEnvironment(detachedWorkspace, policy);
        if (workspaceResult.passed || !hasFinding(workspaceResult, "workspace_parent_mismatch"))
            throw std::runtime_error("detached Workspace was not detected");

        std::cout << "roblox-environment-guard-ok\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "Roblox environment guard failure: " << error.what() << '\n';
        return 1;
    }
}
