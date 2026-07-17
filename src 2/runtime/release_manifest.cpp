#include "release_manifest.hpp"

#include <nlohmann/json.hpp>

namespace rbx::runtime
{

#if defined(__GNUC__)
__attribute__((used))
#endif
static const char kReleaseContractMarkers[] =
    "0.729.0.7290838\0"
    "6e9b580e2e24643214caf0f4bbbb3db911ca30f3\0";

std::string_view name(ExecutionMode mode)
{
    return mode == ExecutionMode::Diagnostic ? "diagnostic" : "faithful";
}

std::string_view name(ExecutorPreset preset)
{
    return preset == ExecutorPreset::Opiumware ? "opiumware" : "generic";
}

std::string_view name(FilesystemPolicy policy)
{
    switch (policy)
    {
    case FilesystemPolicy::Disabled:
        return "disabled";
    case FilesystemPolicy::Memory:
        return "memory";
    case FilesystemPolicy::ProfileDefault:
    default:
        return "profile-default";
    }
}

std::string releaseManifestJson()
{
    return nlohmann::json{
        {"schema", "rbx-luau-runtime.release.v1"},
        {"engine_release", kEngineRelease},
        {"studio_version", kStudioVersion},
        {"luau", {{"tag", kLuauTag}, {"commit", kLuauCommit}}},
        {"api", {{"kind", "Full-API-Dump"}, {"sha256", kFullApiSha256}}},
        {"oracle", {
            {"context", "studio-edit"},
            {"probe_sha256", kCoreOracleProbeSha256},
            {"core_sha256", kCoreOracleSha256},
            {"required_identical_captures", 2},
        }},
        {"subject", {{"sha256", kSubjectSha256}, {"bytes", kSubjectBytes}}},
        {"report_schema", kReportSchemaVersion},
        {"scenario_schema", kScenarioSchemaVersion},
    }.dump();
}

} // namespace rbx::runtime
