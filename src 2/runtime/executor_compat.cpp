#include "executor_compat.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace rbx::runtime
{
namespace
{

template<typename Enum, std::size_t Size>
std::optional<Enum> parseEnum(std::string_view text, const std::array<Enum, Size>& values, std::string_view (*stringify)(Enum))
{
    auto found = std::find_if(values.begin(), values.end(), [text, stringify](Enum value) {
        return stringify(value) == text;
    });
    return found == values.end() ? std::nullopt : std::optional(*found);
}

bool containsHeader(const std::map<std::string, std::string, std::less<>>& headers, std::string_view requested)
{
    return std::any_of(headers.begin(), headers.end(), [requested](const auto& header) {
        return header.first.size() == requested.size() &&
            std::equal(header.first.begin(), header.first.end(), requested.begin(), [](unsigned char left, unsigned char right) {
                return std::tolower(left) == std::tolower(right);
            });
    });
}

uint64_t splitMix64(uint64_t& state)
{
    uint64_t value = (state += UINT64_C(0x9e3779b97f4a7c15));
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

std::string syntheticFingerprint(uint64_t seed)
{
    // This is deliberately synthetic and derived only from the run seed. It
    // never fingerprints the host, Roblox installation, or signed-in user.
    uint64_t state = seed ^ UINT64_C(0x4f7069756d776172);
    std::ostringstream output;
    output << std::hex << std::nouppercase << std::setfill('0');
    for (int index = 0; index < 6; ++index)
        output << std::setw(16) << splitMix64(state);
    return output.str();
}

} // namespace

ExecutorCompatibility::ExecutorCompatibility(ExecutorCompatibilityOptions options)
    : options_(options)
{
    if (options_.filesystem == FilesystemPolicy::ProfileDefault)
        options_.filesystem = options_.profile == RuntimeProfile::ExecutorClient ? FilesystemPolicy::Memory : FilesystemPolicy::Disabled;
    SecurityPolicy policy;
    if (options_.profile == RuntimeProfile::ExecutorClient)
        security_ = policy.descriptor(SecurityIdentity::ExecutorSandbox);
    else
        security_ = policy.descriptor(SecurityIdentity::LocalScript);

    if (options_.profile == RuntimeProfile::RobloxClient)
    {
        surface_.identity = {"Roblox", "release-729"};
        if (options_.filesystem == FilesystemPolicy::Memory)
            throw std::invalid_argument("roblox-client cannot expose executor filesystem APIs");
        return;
    }

    surface_.identity = options_.preset == ExecutorPreset::Opiumware ? ExecutorIdentity{"Opiumware", "compat-release-729"}
                                                                    : ExecutorIdentity{"RobloxLuauRuntime", "3.0"};
    surface_.supportedGlobals = {
        "checkcaller",
        "cloneref",
        "compareinstances",
        "getexecutorname",
        "getgenv",
        "gethui",
        "getrenv",
        "getsenv",
        "http_request",
        "identifyexecutor",
        "iscclosure",
        "islclosure",
        "request",
    };
    surface_.unsupportedGlobals = {
        "debug.getproto",
        "debug.getprotos",
        "debug.setconstant",
        "getgc",
        "getconnections",
        "getloadedmodules",
        "hookfunction",
        "hookmetamethod",
        "newcclosure",
        "sethiddenproperty",
        "setidentity",
    };

    if (options_.filesystem == FilesystemPolicy::Memory)
    {
        surface_.filesystem = std::make_shared<MemoryFilesystem>(options_.filesystemLimits);
        surface_.supportedGlobals.insert({
            "appendfile",
            "delfile",
            "delfolder",
            "isfile",
            "isfolder",
            "listfiles",
            "loadfile",
            "makefolder",
            "readfile",
            "writefile",
        });
    }

    // A generic executor must not impersonate a named product. Persona headers
    // are only introduced by the explicit named preset.
    if (options_.preset == ExecutorPreset::Opiumware)
    {
        const std::string fingerprint = syntheticFingerprint(options_.deterministicSeed);
        surface_.requestHeaders.emplace("Opiumware-Fingerprint", fingerprint);
        surface_.requestHeaders.emplace("Opiumware-User-Identifier", fingerprint);
        surface_.requestHeaders.emplace("X-Executor", "Opiumware");
    }
}

const ExecutorCompatibilityOptions& ExecutorCompatibility::options() const
{
    return options_;
}

const ExecutorSurface& ExecutorCompatibility::surface() const
{
    return surface_;
}

const SecurityDescriptor& ExecutorCompatibility::security() const
{
    return security_;
}

bool ExecutorCompatibility::enabled() const
{
    return options_.profile == RuntimeProfile::ExecutorClient;
}

bool ExecutorCompatibility::supports(std::string_view global) const
{
    return surface_.supportedGlobals.contains(global);
}

bool ExecutorCompatibility::explicitlyUnsupported(std::string_view global) const
{
    return surface_.unsupportedGlobals.contains(global);
}

ClosureKind ExecutorCompatibility::classifyClosure(const ClosureMetadata& metadata) const
{
    if (!metadata.isFunction)
        return ClosureKind::Unknown;
    if (metadata.isNativeC && !metadata.isLuauBytecode)
        return ClosureKind::NativeC;
    if (metadata.isLuauBytecode && !metadata.isNativeC)
        return ClosureKind::Luau;
    return ClosureKind::Unknown;
}

std::map<std::string, std::string, std::less<>> ExecutorCompatibility::applyRequestPersona(
    const std::map<std::string, std::string, std::less<>>& input) const
{
    auto result = input;
    for (const auto& [name, value] : surface_.requestHeaders)
    {
        if (!containsHeader(result, name))
            result.emplace(name, value);
    }
    return result;
}

std::string_view toString(RuntimeProfile profile)
{
    return profile == RuntimeProfile::RobloxClient ? "roblox-client" : "executor-client";
}

std::string_view toString(ClosureKind kind)
{
    switch (kind)
    {
    case ClosureKind::Luau:
        return "luau";
    case ClosureKind::NativeC:
        return "c";
    case ClosureKind::Unknown:
        return "unknown";
    }
    return "unknown";
}

std::optional<RuntimeProfile> parseRuntimeProfile(std::string_view text)
{
    static constexpr std::array values{RuntimeProfile::RobloxClient, RuntimeProfile::ExecutorClient};
    return parseEnum(text, values, toString);
}

std::optional<ExecutionMode> parseExecutionMode(std::string_view text)
{
    static constexpr std::array values{ExecutionMode::Faithful, ExecutionMode::Diagnostic};
    return parseEnum(text, values, name);
}

std::optional<ExecutorPreset> parseExecutorPreset(std::string_view text)
{
    static constexpr std::array values{ExecutorPreset::Generic, ExecutorPreset::Opiumware};
    return parseEnum(text, values, name);
}

std::optional<FilesystemPolicy> parseFilesystemPolicy(std::string_view text)
{
    static constexpr std::array values{FilesystemPolicy::ProfileDefault, FilesystemPolicy::Disabled, FilesystemPolicy::Memory};
    return parseEnum(text, values, name);
}

} // namespace rbx::runtime
