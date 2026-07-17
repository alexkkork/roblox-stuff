#pragma once

#include "../runtime_v2.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rbx::runtime
{

struct RobloxEnvironmentPolicy
{
    std::string expectedEngineRelease;
    std::string expectedApiHash;
    std::string expectedReflectionVersion;
    std::optional<int64_t> expectedPlaceId;
    std::optional<int64_t> expectedGameId;
    std::optional<std::string> expectedJobId;
    std::vector<std::string> requiredServices;
    bool requireSealedEngine = true;
    bool requireWorkspaceAlias = true;
    bool requireNativeServiceObjects = true;
};

struct RobloxEnvironmentFinding
{
    std::string code;
    std::string subject;
    std::string expected;
    std::string observed;
};

struct RobloxEnvironmentResult
{
    bool passed = false;
    std::size_t checksPerformed = 0;
    std::vector<RobloxEnvironmentFinding> findings;
};

RobloxEnvironmentPolicy defaultRobloxEnvironmentPolicy();
RobloxEnvironmentResult evaluateRobloxEnvironment(
    const v2::DataModelSnapshot& snapshot, const RobloxEnvironmentPolicy& policy);
std::string_view robloxEnvironmentStatus(const RobloxEnvironmentResult& result);

} // namespace rbx::runtime
