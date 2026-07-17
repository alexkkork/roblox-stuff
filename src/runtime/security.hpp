#pragma once

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rbx::runtime
{

enum class SecurityIdentity : uint8_t
{
    Anonymous,
    LocalScript,
    ModuleScript,
    Plugin,
    RobloxScript,
    CommandLine,
    ExecutorSandbox,
};

enum class Capability : uint8_t
{
    CreateInstances,
    ReadDataModel,
    WriteDataModel,
    LocalUser,
    HttpPublic,
    HttpPrivate,
    DataStore,
    Messaging,
    Plugin,
    RobloxScript,
    LoadString,
    DebugIntrospection,
    MemoryFilesystem,
    ExecutorCompatibility,
    HostModuleSource,
    UnsafeNative,
    Count,
};

class CapabilitySet
{
public:
    CapabilitySet() = default;
    CapabilitySet(std::initializer_list<Capability> capabilities);

    bool contains(Capability capability) const;
    bool containsAll(const CapabilitySet& required) const;
    bool empty() const;
    std::size_t size() const;

    CapabilitySet& add(Capability capability);
    CapabilitySet& remove(Capability capability);
    CapabilitySet intersect(const CapabilitySet& other) const;
    CapabilitySet unite(const CapabilitySet& other) const;
    std::vector<Capability> values() const;

    friend bool operator==(const CapabilitySet&, const CapabilitySet&) = default;

private:
    static constexpr std::size_t kCount = static_cast<std::size_t>(Capability::Count);
    std::bitset<kCount> bits_;
};

struct SecurityDescriptor
{
    SecurityIdentity identity = SecurityIdentity::Anonymous;
    CapabilitySet capabilities;
};

class SecurityPolicy
{
public:
    SecurityPolicy();

    const CapabilitySet& defaults(SecurityIdentity identity) const;
    SecurityDescriptor descriptor(SecurityIdentity identity) const;

    // Child execution may be made less privileged, but never gains capabilities
    // merely because a caller requested a stronger identity.
    SecurityDescriptor inherit(const SecurityDescriptor& parent, SecurityIdentity requestedIdentity) const;

    bool allows(const SecurityDescriptor& descriptor, Capability capability) const;
    bool allows(const SecurityDescriptor& descriptor, const CapabilitySet& required) const;
    std::optional<std::string> denialReason(const SecurityDescriptor& descriptor, const CapabilitySet& required) const;

private:
    static constexpr std::size_t kIdentityCount = static_cast<std::size_t>(SecurityIdentity::ExecutorSandbox) + 1;
    std::array<CapabilitySet, kIdentityCount> defaults_;
};

std::string_view toString(SecurityIdentity identity);
std::string_view toString(Capability capability);
std::optional<SecurityIdentity> parseSecurityIdentity(std::string_view text);

} // namespace rbx::runtime
