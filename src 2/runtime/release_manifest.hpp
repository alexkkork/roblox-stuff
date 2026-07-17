#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace rbx::runtime
{

inline constexpr int kReportSchemaVersion = 3;
inline constexpr int kScenarioSchemaVersion = 2;
inline constexpr std::string_view kEngineRelease = "729";
inline constexpr std::string_view kStudioVersion = "0.729.0.7290838";
inline constexpr std::string_view kLuauTag = "0.729";
inline constexpr std::string_view kLuauCommit = "6e9b580e2e24643214caf0f4bbbb3db911ca30f3";
inline constexpr std::string_view kFullApiSha256 = "88de6ce88153b2c7d226d7c2d22752e6e04d266c28b36809d9d61bf8256cf6bd";
inline constexpr std::string_view kReflectionDescriptorVersion = "1";
inline constexpr std::string_view kCoreOracleProbeSha256 = "dbd2d32751a3666858edff70b6831e6a939aac1121dc645740a933c56a0c6aa6";
inline constexpr std::string_view kCoreOracleSha256 = "aeaba8290d1963f8dc746d7df725149dd66aa2a717f7956d967352c02dfd9047";
inline constexpr std::string_view kSubjectSha256 = "ea93959c47e6ada393fdf3d5ad884b6fd713aa5d76ac7259e84bd18464153e15";
inline constexpr uint64_t kSubjectBytes = 368779;

enum class ExecutionMode
{
    Faithful,
    Diagnostic,
};

enum class ExecutorPreset
{
    Generic,
    Opiumware,
};

enum class FilesystemPolicy
{
    ProfileDefault,
    Disabled,
    Memory,
};

std::string_view name(ExecutionMode mode);
std::string_view name(ExecutorPreset preset);
std::string_view name(FilesystemPolicy policy);
std::string releaseManifestJson();

} // namespace rbx::runtime
