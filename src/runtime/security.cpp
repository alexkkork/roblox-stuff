#include "security.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace rbx::runtime
{
namespace
{

constexpr std::size_t indexOf(SecurityIdentity identity)
{
    return static_cast<std::size_t>(identity);
}

constexpr std::size_t indexOf(Capability capability)
{
    return static_cast<std::size_t>(capability);
}

} // namespace

CapabilitySet::CapabilitySet(std::initializer_list<Capability> capabilities)
{
    for (Capability capability : capabilities)
        add(capability);
}

bool CapabilitySet::contains(Capability capability) const
{
    return bits_.test(indexOf(capability));
}

bool CapabilitySet::containsAll(const CapabilitySet& required) const
{
    return (bits_ & required.bits_) == required.bits_;
}

bool CapabilitySet::empty() const
{
    return bits_.none();
}

std::size_t CapabilitySet::size() const
{
    return bits_.count();
}

CapabilitySet& CapabilitySet::add(Capability capability)
{
    if (capability == Capability::Count)
        throw std::invalid_argument("Count is not a capability");
    bits_.set(indexOf(capability));
    return *this;
}

CapabilitySet& CapabilitySet::remove(Capability capability)
{
    if (capability != Capability::Count)
        bits_.reset(indexOf(capability));
    return *this;
}

CapabilitySet CapabilitySet::intersect(const CapabilitySet& other) const
{
    CapabilitySet result;
    result.bits_ = bits_ & other.bits_;
    return result;
}

CapabilitySet CapabilitySet::unite(const CapabilitySet& other) const
{
    CapabilitySet result;
    result.bits_ = bits_ | other.bits_;
    return result;
}

std::vector<Capability> CapabilitySet::values() const
{
    std::vector<Capability> result;
    for (std::size_t index = 0; index < kCount; ++index)
    {
        if (bits_.test(index))
            result.push_back(static_cast<Capability>(index));
    }
    return result;
}

SecurityPolicy::SecurityPolicy()
{
    const CapabilitySet common{
        Capability::CreateInstances,
        Capability::ReadDataModel,
        Capability::WriteDataModel,
    };

    defaults_[indexOf(SecurityIdentity::Anonymous)] = {};
    defaults_[indexOf(SecurityIdentity::LocalScript)] = common.unite({Capability::LocalUser, Capability::HttpPublic});
    defaults_[indexOf(SecurityIdentity::ModuleScript)] = common.unite({Capability::LocalUser, Capability::HttpPublic});
    defaults_[indexOf(SecurityIdentity::Plugin)] = common.unite({
        Capability::LocalUser,
        Capability::HttpPublic,
        Capability::Plugin,
        Capability::LoadString,
    });
    defaults_[indexOf(SecurityIdentity::RobloxScript)] = common.unite({
        Capability::LocalUser,
        Capability::HttpPublic,
        Capability::RobloxScript,
    });
    defaults_[indexOf(SecurityIdentity::CommandLine)] = common.unite({
        Capability::HttpPublic,
        Capability::LoadString,
        Capability::DebugIntrospection,
        Capability::HostModuleSource,
    });
    defaults_[indexOf(SecurityIdentity::ExecutorSandbox)] = common.unite({
        Capability::LocalUser,
        Capability::HttpPublic,
        Capability::LoadString,
        Capability::MemoryFilesystem,
        Capability::ExecutorCompatibility,
    });
}

const CapabilitySet& SecurityPolicy::defaults(SecurityIdentity identity) const
{
    return defaults_.at(indexOf(identity));
}

SecurityDescriptor SecurityPolicy::descriptor(SecurityIdentity identity) const
{
    return SecurityDescriptor{identity, defaults(identity)};
}

SecurityDescriptor SecurityPolicy::inherit(const SecurityDescriptor& parent, SecurityIdentity requestedIdentity) const
{
    const CapabilitySet& requested = defaults(requestedIdentity);
    if (!parent.capabilities.containsAll(requested))
        return parent;
    return SecurityDescriptor{requestedIdentity, requested};
}

bool SecurityPolicy::allows(const SecurityDescriptor& descriptor, Capability capability) const
{
    return descriptor.capabilities.contains(capability);
}

bool SecurityPolicy::allows(const SecurityDescriptor& descriptor, const CapabilitySet& required) const
{
    return descriptor.capabilities.containsAll(required);
}

std::optional<std::string> SecurityPolicy::denialReason(const SecurityDescriptor& descriptor, const CapabilitySet& required) const
{
    if (allows(descriptor, required))
        return std::nullopt;

    std::ostringstream message;
    message << "identity " << toString(descriptor.identity) << " lacks ";
    bool first = true;
    for (Capability capability : required.values())
    {
        if (descriptor.capabilities.contains(capability))
            continue;
        if (!first)
            message << ", ";
        message << toString(capability);
        first = false;
    }
    return message.str();
}

std::string_view toString(SecurityIdentity identity)
{
    switch (identity)
    {
    case SecurityIdentity::Anonymous:
        return "anonymous";
    case SecurityIdentity::LocalScript:
        return "local-script";
    case SecurityIdentity::ModuleScript:
        return "module-script";
    case SecurityIdentity::Plugin:
        return "plugin";
    case SecurityIdentity::RobloxScript:
        return "roblox-script";
    case SecurityIdentity::CommandLine:
        return "command-line";
    case SecurityIdentity::ExecutorSandbox:
        return "executor-sandbox";
    }
    return "unknown";
}

std::string_view toString(Capability capability)
{
    switch (capability)
    {
    case Capability::CreateInstances:
        return "create-instances";
    case Capability::ReadDataModel:
        return "read-data-model";
    case Capability::WriteDataModel:
        return "write-data-model";
    case Capability::LocalUser:
        return "local-user";
    case Capability::HttpPublic:
        return "http-public";
    case Capability::HttpPrivate:
        return "http-private";
    case Capability::DataStore:
        return "data-store";
    case Capability::Messaging:
        return "messaging";
    case Capability::Plugin:
        return "plugin";
    case Capability::RobloxScript:
        return "roblox-script";
    case Capability::LoadString:
        return "load-string";
    case Capability::DebugIntrospection:
        return "debug-introspection";
    case Capability::MemoryFilesystem:
        return "memory-filesystem";
    case Capability::ExecutorCompatibility:
        return "executor-compatibility";
    case Capability::HostModuleSource:
        return "host-module-source";
    case Capability::UnsafeNative:
        return "unsafe-native";
    case Capability::Count:
        break;
    }
    return "unknown";
}

std::optional<SecurityIdentity> parseSecurityIdentity(std::string_view text)
{
    static constexpr std::array identities{
        SecurityIdentity::Anonymous,
        SecurityIdentity::LocalScript,
        SecurityIdentity::ModuleScript,
        SecurityIdentity::Plugin,
        SecurityIdentity::RobloxScript,
        SecurityIdentity::CommandLine,
        SecurityIdentity::ExecutorSandbox,
    };
    auto found = std::find_if(identities.begin(), identities.end(), [text](SecurityIdentity identity) {
        return toString(identity) == text;
    });
    return found == identities.end() ? std::nullopt : std::optional(*found);
}

} // namespace rbx::runtime
