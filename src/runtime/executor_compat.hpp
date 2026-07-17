#pragma once

#include "memory_filesystem.hpp"
#include "release_manifest.hpp"
#include "security.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace rbx::runtime
{

enum class RuntimeProfile
{
    RobloxClient,
    ExecutorClient,
};

enum class ClosureKind
{
    Luau,
    NativeC,
    Unknown,
};

struct ClosureMetadata
{
    bool isFunction = false;
    bool isNativeC = false;
    bool isLuauBytecode = false;
};

struct ExecutorCompatibilityOptions
{
    RuntimeProfile profile = RuntimeProfile::RobloxClient;
    ExecutionMode executionMode = ExecutionMode::Faithful;
    ExecutorPreset preset = ExecutorPreset::Generic;
    FilesystemPolicy filesystem = FilesystemPolicy::ProfileDefault;
    MemoryFilesystemLimits filesystemLimits;
    uint64_t deterministicSeed = 0;
};

struct ExecutorIdentity
{
    std::string name;
    std::string version;
};

struct ExecutorSurface
{
    ExecutorIdentity identity;
    std::set<std::string, std::less<>> supportedGlobals;
    std::set<std::string, std::less<>> unsupportedGlobals;
    std::map<std::string, std::string, std::less<>> requestHeaders;
    std::shared_ptr<MemoryFilesystem> filesystem;
};

class ExecutorCompatibility
{
public:
    explicit ExecutorCompatibility(ExecutorCompatibilityOptions options);

    const ExecutorCompatibilityOptions& options() const;
    const ExecutorSurface& surface() const;
    const SecurityDescriptor& security() const;

    bool enabled() const;
    bool supports(std::string_view global) const;
    bool explicitlyUnsupported(std::string_view global) const;
    ClosureKind classifyClosure(const ClosureMetadata& metadata) const;

    std::map<std::string, std::string, std::less<>> applyRequestPersona(
        const std::map<std::string, std::string, std::less<>>& input) const;

private:
    ExecutorCompatibilityOptions options_;
    ExecutorSurface surface_;
    SecurityDescriptor security_;
};

std::string_view toString(RuntimeProfile profile);
std::string_view toString(ClosureKind kind);

std::optional<RuntimeProfile> parseRuntimeProfile(std::string_view text);
std::optional<ExecutionMode> parseExecutionMode(std::string_view text);
std::optional<ExecutorPreset> parseExecutorPreset(std::string_view text);
std::optional<FilesystemPolicy> parseFilesystemPolicy(std::string_view text);

} // namespace rbx::runtime
