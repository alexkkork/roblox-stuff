#pragma once

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rbx::v2::reflection
{

using json = nlohmann::json;

enum class Support
{
    Implemented,
    FixtureBacked,
    Unsupported,
    Inaccessible,
};

inline std::string_view supportName(Support value)
{
    switch (value)
    {
    case Support::Implemented:
        return "implemented";
    case Support::FixtureBacked:
        return "fixture-backed";
    case Support::Inaccessible:
        return "inaccessible";
    case Support::Unsupported:
    default:
        return "unsupported";
    }
}

struct TypeDescriptor
{
    std::string category;
    std::string name;
};

struct ParameterDescriptor
{
    std::string name;
    TypeDescriptor type;
    bool hasDefault = false;
    std::string defaultValue;
};

struct SecurityDescriptor
{
    std::string read = "None";
    std::string write = "None";
};

struct CapabilityDescriptor
{
    std::vector<std::string> read;
    std::vector<std::string> write;
};

struct SerializationDescriptor
{
    bool present = false;
    bool canLoad = false;
    bool canSave = false;
};

struct MemberDescriptor
{
    std::string name;
    std::string declaringClass;
    std::string memberType;
    std::string category;
    std::string threadSafety;
    TypeDescriptor valueType;
    TypeDescriptor returnType;
    SecurityDescriptor security;
    CapabilityDescriptor capabilities;
    SerializationDescriptor serialization;
    std::vector<ParameterDescriptor> parameters;
    std::set<std::string> tags;
    bool hasSimulationAccess = false;
    bool simulationAccess = false;
    Support support = Support::Unsupported;

    bool hasTag(std::string_view tag) const
    {
        return tags.find(std::string(tag)) != tags.end();
    }

    bool isCallable() const
    {
        return memberType == "Function" || memberType == "YieldFunction";
    }

    bool isValueSlot() const
    {
        return memberType == "Property" || memberType == "Callback";
    }
};

struct ClassDescriptor
{
    std::string name;
    std::string superclass;
    std::string memoryCategory;
    std::set<std::string> tags;
    std::unordered_map<std::string, MemberDescriptor> members;
};

struct ResolvedMember
{
    const MemberDescriptor* descriptor = nullptr;
    std::string requestedName;
    std::string canonicalName;

    explicit operator bool() const
    {
        return descriptor != nullptr;
    }
};

class Database
{
public:
    void load(std::string_view source)
    {
        classes_.clear();
        aliases_.clear();
        memberCount_ = 0;
        enumCount_ = 0;
        enumItemCount_ = 0;

        json root;
        try
        {
            root = json::parse(source);
        }
        catch (const std::exception& error)
        {
            throw std::runtime_error(std::string("invalid Roblox API dump: ") + error.what());
        }

        version_.clear();
        if (root.contains("Version") && root["Version"].is_string())
            version_ = root["Version"].get<std::string>();
        else if (root.contains("Version") && root["Version"].is_number_integer())
            version_ = std::to_string(root["Version"].get<long long>());

        const json& classes = root.contains("Classes") ? root["Classes"] : json::array();
        if (!classes.is_array())
            throw std::runtime_error("Roblox API dump Classes must be an array");

        for (const json& sourceClass : classes)
        {
            if (!sourceClass.is_object())
                continue;
            ClassDescriptor descriptor;
            descriptor.name = sourceClass.value("Name", "");
            descriptor.superclass = sourceClass.value("Superclass", "");
            descriptor.memoryCategory = sourceClass.value("MemoryCategory", "");
            parseStringSet(sourceClass.value("Tags", json::array()), descriptor.tags);
            if (descriptor.name.empty())
                continue;

            for (const json& sourceMember : sourceClass.value("Members", json::array()))
            {
                if (!sourceMember.is_object())
                    continue;
                MemberDescriptor member = parseMember(sourceMember, descriptor.name);
                if (member.name.empty() || member.memberType.empty())
                    continue;
                descriptor.members[member.name] = std::move(member);
                ++memberCount_;
            }
            classes_[descriptor.name] = std::move(descriptor);
        }

        const json& enums = root.contains("Enums") ? root["Enums"] : json::array();
        if (enums.is_array())
        {
            enumCount_ = enums.size();
            for (const json& sourceEnum : enums)
                if (sourceEnum.is_object() && sourceEnum.value("Items", json::array()).is_array())
                    enumItemCount_ += sourceEnum.value("Items", json::array()).size();
        }

        buildAliases();
    }

    const ClassDescriptor* findClass(std::string_view name) const
    {
        auto found = classes_.find(std::string(name));
        return found == classes_.end() ? nullptr : &found->second;
    }

    ResolvedMember resolve(std::string_view className, std::string_view requestedName) const
    {
        ResolvedMember result;
        result.requestedName = std::string(requestedName);
        result.canonicalName = result.requestedName;

        std::set<std::string> visited;
        std::string cursor(className);
        while (!cursor.empty() && cursor != "<<<ROOT>>>" && visited.insert(cursor).second)
        {
            auto alias = aliases_.find(aliasKey(cursor, requestedName));
            if (alias != aliases_.end())
            {
                result.canonicalName = alias->second;
                result.descriptor = findMemberFrom(cursor, result.canonicalName);
                if (result.descriptor)
                    return result;
            }

            const ClassDescriptor* descriptor = findClass(cursor);
            if (!descriptor)
                break;
            auto member = descriptor->members.find(std::string(requestedName));
            if (member != descriptor->members.end())
            {
                result.descriptor = &member->second;
                return result;
            }
            cursor = descriptor->superclass;
        }
        return result;
    }

    bool isA(std::string_view className, std::string_view target) const
    {
        std::set<std::string> visited;
        std::string cursor(className);
        while (!cursor.empty() && cursor != "<<<ROOT>>>" && visited.insert(cursor).second)
        {
            if (cursor == target)
                return true;
            const ClassDescriptor* descriptor = findClass(cursor);
            if (!descriptor)
                return false;
            cursor = descriptor->superclass;
        }
        return false;
    }

    size_t classCount() const
    {
        return classes_.size();
    }

    size_t memberCount() const
    {
        return memberCount_;
    }

    bool markSupport(std::string_view declaringClass, std::string_view memberName, Support support)
    {
        auto foundClass = classes_.find(std::string(declaringClass));
        if (foundClass == classes_.end())
            return false;
        auto foundMember = foundClass->second.members.find(std::string(memberName));
        if (foundMember == foundClass->second.members.end() || foundMember->second.support == Support::Inaccessible)
            return false;
        foundMember->second.support = support;
        return true;
    }

    json stats() const
    {
        std::unordered_map<std::string, size_t> supportCounts;
        size_t properties = 0;
        size_t functions = 0;
        size_t events = 0;
        size_t callbacks = 0;
        for (const auto& [_, descriptor] : classes_)
        {
            for (const auto& [__, member] : descriptor.members)
            {
                ++supportCounts[std::string(supportName(member.support))];
                if (member.memberType == "Property")
                    ++properties;
                else if (member.memberType == "Event")
                    ++events;
                else if (member.memberType == "Callback")
                    ++callbacks;
                else
                    ++functions;
            }
        }
        return json{
            {"version", version_},
            {"classes", classes_.size()},
            {"members", memberCount_},
            {"enums", enumCount_},
            {"enum_items", enumItemCount_},
            {"properties", properties},
            {"functions", functions},
            {"events", events},
            {"callbacks", callbacks},
            {"aliases", aliases_.size()},
            {"support", supportCounts},
        };
    }

private:
    static std::string aliasKey(std::string_view className, std::string_view memberName)
    {
        std::string result;
        result.reserve(className.size() + memberName.size() + 1);
        result.append(className);
        result.push_back('\0');
        result.append(memberName);
        return result;
    }

    static std::string lower(std::string_view input)
    {
        std::string result(input);
        std::transform(result.begin(), result.end(), result.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        return result;
    }

    static void parseStringSet(const json& value, std::set<std::string>& output)
    {
        if (!value.is_array())
            return;
        for (const json& entry : value)
            if (entry.is_string())
                output.insert(entry.get<std::string>());
    }

    static void parseStringVector(const json& value, std::vector<std::string>& output)
    {
        if (value.is_string())
            output.push_back(value.get<std::string>());
        else if (value.is_array())
            for (const json& entry : value)
                if (entry.is_string())
                    output.push_back(entry.get<std::string>());
    }

    static TypeDescriptor parseType(const json& value)
    {
        TypeDescriptor output;
        if (value.is_string())
            output.name = value.get<std::string>();
        else if (value.is_object())
        {
            output.category = value.value("Category", "");
            output.name = value.value("Name", "");
        }
        return output;
    }

    static std::string stringifyDefault(const json& value)
    {
        if (value.is_string())
            return value.get<std::string>();
        return value.dump();
    }

    static bool privileged(std::string_view security)
    {
        return !security.empty() && security != "None";
    }

    static bool privilegedCapabilities(const std::vector<std::string>& capabilities)
    {
        static const std::set<std::string> privilegedNames = {
            "CapabilityControl", "InternalTest", "PluginOrOpenCloud", "RemoteCommand", "ScriptGlobals",
        };
        return std::any_of(capabilities.begin(), capabilities.end(), [&](const std::string& capability) {
            return privilegedNames.count(capability) != 0;
        });
    }

    static MemberDescriptor parseMember(const json& value, const std::string& declaringClass)
    {
        MemberDescriptor output;
        output.name = value.value("Name", "");
        output.declaringClass = declaringClass;
        output.memberType = value.value("MemberType", "");
        output.category = value.value("Category", "");
        output.threadSafety = value.value("ThreadSafety", "");
        output.valueType = parseType(value.value("ValueType", json::object()));
        output.returnType = parseType(value.value("ReturnType", json::object()));
        parseStringSet(value.value("Tags", json::array()), output.tags);

        const json& security = value.contains("Security") ? value["Security"] : json();
        if (security.is_string())
            output.security.read = output.security.write = security.get<std::string>();
        else if (security.is_object())
        {
            output.security.read = security.value("Read", "None");
            output.security.write = security.value("Write", output.security.read);
        }

        const json& capabilities = value.contains("Capabilities") ? value["Capabilities"] : json();
        if (capabilities.is_array() || capabilities.is_string())
        {
            parseStringVector(capabilities, output.capabilities.read);
            output.capabilities.write = output.capabilities.read;
        }
        else if (capabilities.is_object())
        {
            parseStringVector(capabilities.value("Read", json::array()), output.capabilities.read);
            parseStringVector(capabilities.value("Write", json::array()), output.capabilities.write);
        }

        const json& serialization = value.contains("Serialization") ? value["Serialization"] : json();
        if (serialization.is_object())
        {
            output.serialization.present = true;
            output.serialization.canLoad = serialization.value("CanLoad", false);
            output.serialization.canSave = serialization.value("CanSave", false);
        }

        const json& parameters = value.contains("Parameters") ? value["Parameters"] : json::array();
        if (parameters.is_array())
        {
            for (const json& parameter : parameters)
            {
                if (!parameter.is_object())
                    continue;
                ParameterDescriptor parsed;
                parsed.name = parameter.value("Name", "");
                parsed.type = parseType(parameter.value("Type", json::object()));
                parsed.hasDefault = parameter.contains("Default");
                if (parsed.hasDefault)
                    parsed.defaultValue = stringifyDefault(parameter["Default"]);
                output.parameters.push_back(std::move(parsed));
            }
        }

        if (value.contains("SimulationAccess") && value["SimulationAccess"].is_boolean())
        {
            output.hasSimulationAccess = true;
            output.simulationAccess = value["SimulationAccess"].get<bool>();
        }

        if (output.hasTag("NotScriptable") || privileged(output.security.read) || privilegedCapabilities(output.capabilities.read))
            output.support = Support::Inaccessible;
        else if (output.memberType == "Event")
            output.support = Support::Implemented;
        else if (output.memberType == "Property" || output.memberType == "Callback")
            output.support = Support::FixtureBacked;
        else
            output.support = Support::Unsupported;
        return output;
    }

    const MemberDescriptor* findMemberFrom(std::string className, std::string_view memberName) const
    {
        std::set<std::string> visited;
        while (!className.empty() && className != "<<<ROOT>>>" && visited.insert(className).second)
        {
            const ClassDescriptor* descriptor = findClass(className);
            if (!descriptor)
                return nullptr;
            auto member = descriptor->members.find(std::string(memberName));
            if (member != descriptor->members.end())
                return &member->second;
            className = descriptor->superclass;
        }
        return nullptr;
    }

    void addAlias(std::string_view className, std::string_view legacyName, std::string_view canonicalName)
    {
        if (findMemberFrom(std::string(className), canonicalName))
            aliases_[aliasKey(className, legacyName)] = std::string(canonicalName);
    }

    void buildAliases()
    {
        // The API dump marks legacy descriptors as Deprecated, but does not carry
        // their preferred descriptor.  Case-only aliases can be derived without
        // guessing; the remaining long-standing Instance aliases are explicit.
        for (const auto& [className, descriptor] : classes_)
        {
            for (const auto& [name, member] : descriptor.members)
            {
                if (!member.hasTag("Deprecated"))
                    continue;
                const std::string folded = lower(name);
                const MemberDescriptor* candidate = nullptr;
                for (const auto& [candidateName, candidateMember] : descriptor.members)
                {
                    if (candidateName != name && lower(candidateName) == folded && !candidateMember.hasTag("Deprecated") &&
                        candidateMember.memberType == member.memberType)
                    {
                        if (candidate)
                        {
                            candidate = nullptr;
                            break;
                        }
                        candidate = &candidateMember;
                    }
                }
                if (candidate)
                    aliases_[aliasKey(className, name)] = candidate->name;
            }
        }

        addAlias("Instance", "children", "GetChildren");
        addAlias("Instance", "getChildren", "GetChildren");
        addAlias("Instance", "findFirstChild", "FindFirstChild");
        addAlias("Instance", "isDescendantOf", "IsDescendantOf");
        addAlias("Instance", "clone", "Clone");
        addAlias("Instance", "destroy", "Destroy");
        addAlias("Instance", "Remove", "Destroy");
        addAlias("Instance", "remove", "Destroy");
    }

    std::string version_;
    std::unordered_map<std::string, ClassDescriptor> classes_;
    std::unordered_map<std::string, std::string> aliases_;
    size_t memberCount_ = 0;
    size_t enumCount_ = 0;
    size_t enumItemCount_ = 0;
};

} // namespace rbx::v2::reflection
