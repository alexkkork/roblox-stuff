#include "runtime_v2.hpp"

#include "runtime/reflection.hpp"
#include "runtime/luau_runtime_bridge.hpp"
#include "runtime/runtime_context.hpp"

#include "lualib.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <limits>
#include <memory>
#include <new>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rbx::v2
{
namespace
{

using json = nlohmann::json;

using reflection::ClassDescriptor;
using reflection::MemberDescriptor;
using reflection::ResolvedMember;
using reflection::Support;

struct InstanceHandle;

struct InstanceNode
{
    uint64_t id = 0;
    std::string className;
    std::string name;
    uint64_t parent = 0;
    std::vector<uint64_t> children;
    int objectRef = LUA_NOREF;
    int stateRef = LUA_NOREF;
    InstanceHandle* handle = nullptr;
    std::set<std::string> initializedProperties;
    bool archivable = true;
    bool destroying = false;
    bool destroyed = false;
};

struct InstanceHandle
{
    uint64_t id = 0;
    bool destroyed = false;
    bool archivable = true;
    std::string className;
    std::string name;
};

enum class ValueKind : uint8_t
{
    Enums,
    EnumType,
    EnumItem,
    TweenInfo,
    RaycastParams,
    OverlapParams,
    NumberRange,
    NumberSequenceKeypoint,
    NumberSequence,
    ColorSequenceKeypoint,
    ColorSequence,
    DateTime,
    Random,
};

struct NumberSequencePoint
{
    double time = 0;
    double value = 0;
    double envelope = 0;
};

struct ColorSequencePoint
{
    double time = 0;
    double red = 0;
    double green = 0;
    double blue = 0;
};

struct ValueHandle
{
    ValueKind kind = ValueKind::NumberRange;
    std::array<double, 6> numbers{};
    int64_t integer = 0;
    uint64_t randomState = 1;
    std::array<bool, 3> flags{};
    std::string text;
    std::string enumName1;
    std::string enumName2;
    std::vector<uint64_t> instanceIds;
    std::vector<NumberSequencePoint> numberPoints;
    std::vector<ColorSequencePoint> colorPoints;
};

struct EnumDefinition
{
    int typeRef = LUA_NOREF;
    std::vector<int> itemRefs;
    std::unordered_map<std::string, size_t> itemLookup;
};

struct WaitForChildRequest
{
    uint64_t instanceId = 0;
    std::string childName;
    double startedAt = 0.0;
    std::optional<double> timeout;
};

struct EngineState
{
    lua_State* L = nullptr;
    uint64_t nextId = 1;
    bool strictUnsupported = false;
    bool executorExtensions = false;
    reflection::Database reflection;
    std::unordered_map<uint64_t, std::unique_ptr<InstanceNode>> nodes;
    std::unordered_map<std::string, EnumDefinition> enums;
    std::unordered_map<lua_State*, WaitForChildRequest> waitForChildRequests;
    int methodsRef = LUA_NOREF;
    int classMethodsRef = LUA_NOREF;
    int signalFactoryRef = LUA_NOREF;
    int signalFireRef = LUA_NOREF;
    int signalDisconnectRef = LUA_NOREF;
    int tagChangedRef = LUA_NOREF;
    int traceRef = LUA_NOREF;
    int executeRef = LUA_NOREF;
    int schedulerReportRef = LUA_NOREF;
    int vector3NewRef = LUA_NOREF;
    int guiGeometryRef = LUA_NOREF;
    int weakInstancesRef = LUA_NOREF;
    bool bootstrapping = true;
    uint64_t randomObjectSequence = 0;
    uint64_t destroyedInstances = 0;
    uint64_t releasedObjectRefs = 0;
    uint64_t releasedStateRefs = 0;

    ~EngineState()
    {
        if (!L)
            return;

        for (auto& [_, node] : nodes)
        {
            if (node->objectRef != LUA_NOREF)
                lua_unref(L, node->objectRef);
            if (node->stateRef != LUA_NOREF)
                lua_unref(L, node->stateRef);
        }
        for (auto& [_, definition] : enums)
        {
            for (int ref : definition.itemRefs)
                if (ref != LUA_NOREF)
                    lua_unref(L, ref);
            if (definition.typeRef != LUA_NOREF)
                lua_unref(L, definition.typeRef);
        }
        for (int ref : {methodsRef, classMethodsRef, signalFactoryRef, signalFireRef, signalDisconnectRef, tagChangedRef, traceRef, executeRef,
                 schedulerReportRef, vector3NewRef, guiGeometryRef, weakInstancesRef})
        {
            if (ref != LUA_NOREF)
                lua_unref(L, ref);
        }
    }
};

void destroyInstanceHandle(lua_State* L, void* pointer);

void destroyValueHandle(lua_State*, void* pointer)
{
    static_cast<ValueHandle*>(pointer)->~ValueHandle();
}

constexpr std::string_view kEngineSubsystemKey = "runtime.v2-engine";
constexpr int kValueTag = 21;

lua_State* mainStateFor(lua_State* L)
{
    if (!L)
        throw std::invalid_argument("runtime v2 requires a Lua state");
    lua_State* main = lua_mainthread(L);
    if (!main)
        throw std::logic_error("runtime v2 could not resolve the Lua main thread");
    return main;
}

rbx::runtime::RuntimeContext& contextFor(lua_State* L)
{
    lua_State* main = mainStateFor(L);
    rbx::runtime::RuntimeContext* context = rbx::runtime::RuntimeContext::from(main);
    if (!context || context->mainState() != main || !context->attached())
        throw std::logic_error("runtime v2 requires an attached RuntimeContext");
    return *context;
}

EngineState* findEngineFor(lua_State* L)
{
    rbx::runtime::RuntimeContext& context = contextFor(L);
    EngineState* engine = context.subsystem<EngineState>(kEngineSubsystemKey);
    if (engine && engine->L != context.mainState())
        throw std::logic_error("runtime v2 engine belongs to a different Lua state");
    return engine;
}

EngineState& engineFor(lua_State* L)
{
    EngineState* engine = findEngineFor(L);
    if (!engine)
        throw std::logic_error("runtime v2 is not initialized for this Lua state");
    return *engine;
}

void destroyInstanceHandle(lua_State* L, void* pointer)
{
    auto* handle = static_cast<InstanceHandle*>(pointer);
    if (handle && handle->destroyed && L)
    {
        lua_State* main = lua_mainthread(L);
        runtime::RuntimeContext* context = main ? runtime::RuntimeContext::from(main) : nullptr;
        EngineState* engine = context ? context->subsystem<EngineState>(kEngineSubsystemKey) : nullptr;
        if (engine)
        {
            auto it = engine->nodes.find(handle->id);
            if (it != engine->nodes.end() && it->second->handle == handle && it->second->destroyed)
            {
                const int stateRef = it->second->stateRef;
                it->second->stateRef = LUA_NOREF;
                it->second->handle = nullptr;
                engine->nodes.erase(it);
                if (stateRef != LUA_NOREF)
                    lua_unref(L, stateRef);
            }
        }
    }
    handle->~InstanceHandle();
}

bool isExecutorDataModelMethod(lua_State* L, const InstanceNode& node, std::string_view key)
{
    if (!engineFor(L).executorExtensions || node.className != "DataModel")
        return false;

    return key == "HttpGet" || key == "HttpGetAsync" || key == "HttpPost" || key == "HttpPostAsync";
}

InstanceHandle* checkHandle(lua_State* L, int index)
{
    void* ptr = lua_touserdatatagged(L, index, kInstanceTag);
    if (!ptr)
        luaL_typeerror(L, index, "Instance");
    return static_cast<InstanceHandle*>(ptr);
}

InstanceNode* nodeForIdentity(lua_State* L, int index)
{
    InstanceHandle* handle = checkHandle(L, index);
    EngineState& engine = engineFor(L);
    auto it = engine.nodes.find(handle->id);
    if (it != engine.nodes.end())
        return it->second.get();
    if (!handle->destroyed)
        luaL_error(L, "attempt to use an invalid Instance");

    auto tombstone = std::make_unique<InstanceNode>();
    tombstone->id = handle->id;
    tombstone->className = handle->className;
    tombstone->name = handle->name;
    tombstone->archivable = handle->archivable;
    tombstone->destroyed = true;
    tombstone->handle = handle;
    lua_newtable(L);
    tombstone->stateRef = lua_ref(L, -1);
    lua_pop(L, 1);
    InstanceNode* result = tombstone.get();
    engine.nodes[handle->id] = std::move(tombstone);
    return result;
}

InstanceNode* nodeFor(lua_State* L, int index)
{
    InstanceHandle* handle = checkHandle(L, index);
    if (handle->destroyed)
        luaL_error(L, "attempt to use a destroyed Instance");
    return nodeForIdentity(L, index);
}

InstanceNode* nodeById(lua_State* L, uint64_t id)
{
    EngineState& engine = engineFor(L);
    auto it = engine.nodes.find(id);
    return it == engine.nodes.end() ? nullptr : it->second.get();
}

void pushNode(lua_State* L, uint64_t id)
{
    if (id == 0)
    {
        lua_pushnil(L);
        return;
    }
    InstanceNode* node = nodeById(L, id);
    if (!node)
    {
        lua_pushnil(L);
        return;
    }
    if (node->objectRef != LUA_NOREF)
    {
        lua_getref(L, node->objectRef);
        return;
    }

    EngineState& engine = engineFor(L);
    if (engine.weakInstancesRef == LUA_NOREF)
    {
        lua_pushnil(L);
        return;
    }
    lua_getref(L, engine.weakInstancesRef);
    lua_rawgeti(L, -1, static_cast<int>(id));
    lua_remove(L, -2);
}

void pushState(lua_State* L, InstanceNode& node)
{
    lua_getref(L, node.stateRef);
}

const ClassDescriptor* descriptorFor(lua_State* L, std::string_view name)
{
    return engineFor(L).reflection.findClass(name);
}

ResolvedMember resolveMember(lua_State* L, std::string_view className, std::string_view member)
{
    return engineFor(L).reflection.resolve(className, member);
}

bool privilegedSecurity(const std::string& security)
{
    return !security.empty() && security != "None";
}

bool privilegedCapabilities(const std::vector<std::string>& capabilities)
{
    static const std::set<std::string> privilegedNames = {
        "CapabilityControl", "InternalTest", "PluginOrOpenCloud", "RemoteCommand", "ScriptGlobals",
    };
    return std::any_of(capabilities.begin(), capabilities.end(), [&](const std::string& capability) {
        return privilegedNames.count(capability) != 0;
    });
}

bool isA(lua_State* L, std::string className, const std::string& target);

std::string luaValueTypeName(lua_State* L, int index)
{
    int top = lua_gettop(L);
    index = lua_absindex(L, index);
    lua_getglobal(L, "typeof");
    if (lua_isfunction(L, -1))
    {
        lua_pushvalue(L, index);
        if (lua_pcall(L, 1, 1, 0) == LUA_OK && lua_isstring(L, -1))
        {
            std::string result = lua_tostring(L, -1);
            lua_settop(L, top);
            return result;
        }
    }
    lua_settop(L, top);
    return lua_typename(L, lua_type(L, index));
}

bool valueMatches(lua_State* L, int index, const MemberDescriptor& member)
{
    const std::string& expected = member.valueType.name;
    const std::string& category = member.valueType.category;
    if (member.memberType == "Callback")
        return lua_isnil(L, index) || lua_isfunction(L, index);
    if (expected.empty() || expected == "Variant" || expected == "Tuple" || expected == "any")
        return true;
    if (lua_isnil(L, index))
        return category == "Class" || expected == "Instance" || expected == "null" || expected == "PhysicalProperties";
    if (expected == "bool" || expected == "boolean")
        return lua_isboolean(L, index);
    if (expected == "string" || expected == "Content" || expected == "ContentId" || expected == "ProtectedString" || expected == "BinaryString" ||
        expected == "SharedString")
        return lua_isstring(L, index);
    if (expected == "int" || expected == "int64" || expected == "float" || expected == "double" || expected == "number")
        return lua_isnumber(L, index);
    if (expected == "Instance")
        return isInstance(L, index);
    if (descriptorFor(L, expected))
        return isInstance(L, index) && isA(L, instanceClassName(L, index), expected);
    if (category == "Enum")
    {
        void* pointer = lua_touserdatatagged(L, index, kValueTag);
        if (!pointer)
            return false;
        const auto* value = static_cast<const ValueHandle*>(pointer);
        return value->kind == ValueKind::EnumItem && value->enumName1 == expected;
    }
    if (category == "DataType")
    {
        std::string actual = luaValueTypeName(L, index);
        if (actual == expected)
            return true;
        if (expected == "Objects" || expected == "Instances" || expected == "Array")
            return lua_istable(L, index);
        return false;
    }
    return true;
}

bool isA(lua_State* L, std::string className, const std::string& target)
{
    return engineFor(L).reflection.isA(className, target);
}

void trace(lua_State* L, const char* kind, const std::string& name, const std::string& detail = {})
{
    int top = lua_gettop(L);
    EngineState& engine = engineFor(L);
    if (engine.traceRef != LUA_NOREF)
        lua_getref(L, engine.traceRef);
    else
        lua_pushnil(L);
    if (lua_isfunction(L, -1))
    {
        lua_pushstring(L, kind);
        lua_pushlstring(L, name.data(), name.size());
        lua_pushlstring(L, detail.data(), detail.size());
        if (lua_pcall(L, 3, 0, 0) != LUA_OK)
            lua_pop(L, 1);
    }
    lua_settop(L, top);
}

void ensureSignal(lua_State* L, InstanceNode& node, const std::string& name)
{
    int top = lua_gettop(L);
    pushState(L, node);
    int stateIndex = lua_gettop(L);
    lua_rawgetfield(L, stateIndex, name.c_str());
    if (!lua_isnil(L, -1))
    {
        lua_remove(L, stateIndex);
        return;
    }
    lua_pop(L, 1);

    EngineState& engine = engineFor(L);
    if (engine.signalFactoryRef != LUA_NOREF)
        lua_getref(L, engine.signalFactoryRef);
    else
        lua_getglobal(L, "__rbx_make_signal");
    if (!lua_isfunction(L, -1))
    {
        lua_settop(L, top);
        lua_pushnil(L);
        return;
    }
    std::string displayName = name.rfind("__", 0) == 0 ? node.name + "." + name : name;
    lua_pushlstring(L, displayName.data(), displayName.size());
    if (lua_pcall(L, 1, 1, 0) != LUA_OK)
        lua_error(L);
    lua_pushvalue(L, -1);
    lua_rawsetfield(L, stateIndex, name.c_str());
    lua_remove(L, stateIndex);
}

template<typename PushArgs>
void fireSignal(lua_State* L, InstanceNode& node, const std::string& name, int nargs, PushArgs pushArgs)
{
    int top = lua_gettop(L);
    ensureSignal(L, node, name);
    if (lua_isnil(L, -1))
    {
        lua_settop(L, top);
        return;
    }
    int signalIndex = lua_gettop(L);
    EngineState& engine = engineFor(L);
    if (engine.signalFireRef != LUA_NOREF)
    {
        lua_getref(L, engine.signalFireRef);
        lua_pushvalue(L, signalIndex);
        pushArgs();
        if (lua_pcall(L, nargs + 1, 0, 0) != LUA_OK)
            lua_pop(L, 1);
        lua_settop(L, top);
        return;
    }
    lua_getfield(L, signalIndex, "Fire");
    if (!lua_isfunction(L, -1))
    {
        lua_settop(L, top);
        return;
    }
    lua_pushvalue(L, signalIndex);
    pushArgs();
    if (lua_pcall(L, nargs + 1, 0, 0) != LUA_OK)
        lua_pop(L, 1);
    lua_settop(L, top);
}

void fireProperty(lua_State* L, InstanceNode& node, const std::string& property)
{
    fireSignal(L, node, "Changed", 1, [&] { lua_pushlstring(L, property.data(), property.size()); });
    fireSignal(L, node, "__property_" + property, 0, [] {});
}

bool hasAncestor(lua_State* L, uint64_t nodeId, uint64_t possibleAncestor)
{
    uint64_t cursor = nodeId;
    std::set<uint64_t> visited;
    while (cursor && visited.insert(cursor).second)
    {
        if (cursor == possibleAncestor)
            return true;
        InstanceNode* node = nodeById(L, cursor);
        cursor = node ? node->parent : 0;
    }
    return false;
}

void removeChild(InstanceNode& parent, uint64_t child)
{
    parent.children.erase(std::remove(parent.children.begin(), parent.children.end(), child), parent.children.end());
}

void appendSubtree(lua_State* L, uint64_t rootId, std::vector<uint64_t>& output)
{
    InstanceNode* root = nodeById(L, rootId);
    if (!root)
        return;
    output.push_back(rootId);
    for (uint64_t childId : root->children)
        appendSubtree(L, childId, output);
}

std::vector<InstanceNode*> ancestorChain(lua_State* L, uint64_t startId)
{
    std::vector<InstanceNode*> result;
    std::set<uint64_t> visited;
    for (InstanceNode* cursor = nodeById(L, startId); cursor && visited.insert(cursor->id).second; cursor = nodeById(L, cursor->parent))
        result.push_back(cursor);
    return result;
}

void setParent(lua_State* L, InstanceNode& node, uint64_t newParent)
{
    if (node.parent == newParent)
        return;
    if (newParent == node.id || (newParent && hasAncestor(L, newParent, node.id)))
        luaL_error(L, "attempt to set Parent would create a cycle");

    InstanceNode* old = nodeById(L, node.parent);
    InstanceNode* next = nodeById(L, newParent);
    if (newParent && (!next || next->destroying))
        luaL_error(L, "Parent must be a live Instance or nil");

    std::vector<uint64_t> subtree;
    appendSubtree(L, node.id, subtree);
    std::vector<InstanceNode*> oldAncestors = old ? ancestorChain(L, old->id) : std::vector<InstanceNode*>{};
    std::vector<InstanceNode*> newAncestors = next ? ancestorChain(L, next->id) : std::vector<InstanceNode*>{};

    if (old)
    {
        for (InstanceNode* ancestor : oldAncestors)
            for (uint64_t descendantId : subtree)
                fireSignal(L, *ancestor, "DescendantRemoving", 1, [&] { pushNode(L, descendantId); });
        fireSignal(L, *old, "ChildRemoved", 1, [&] { pushNode(L, node.id); });
        removeChild(*old, node.id);
    }
    node.parent = newParent;
    pushState(L, node);
    pushNode(L, newParent);
    lua_rawsetfield(L, -2, "__parent_identity");
    lua_pop(L, 1);
    if (next)
    {
        next->children.push_back(node.id);
        fireSignal(L, *next, "ChildAdded", 1, [&] { pushNode(L, node.id); });
        for (InstanceNode* ancestor : newAncestors)
            for (uint64_t descendantId : subtree)
                fireSignal(L, *ancestor, "DescendantAdded", 1, [&] { pushNode(L, descendantId); });
    }
    for (uint64_t affectedId : subtree)
    {
        if (InstanceNode* affected = nodeById(L, affectedId))
            fireSignal(L, *affected, "AncestryChanged", 2, [&] {
                pushNode(L, affected->id);
                pushNode(L, affected->parent);
            });
    }
    fireProperty(L, node, "Parent");
}

void disconnectSignals(lua_State* L, InstanceNode& node)
{
    int top = lua_gettop(L);
    pushState(L, node);
    int stateIndex = lua_absindex(L, -1);
    lua_pushnil(L);
    while (lua_next(L, stateIndex) != 0)
    {
        const bool destroyingSignal = lua_isstring(L, -2) && std::string_view(lua_tostring(L, -2)) == "Destroying";
        if (engineFor(L).signalDisconnectRef != LUA_NOREF && lua_isuserdata(L, -1))
        {
            lua_getref(L, engineFor(L).signalDisconnectRef);
            lua_pushvalue(L, -2);
            if (lua_pcall(L, 1, 0, 0) != LUA_OK)
                lua_pop(L, 1);
        }
        else if (lua_istable(L, -1) && !destroyingSignal)
        {
            int valueIndex = lua_absindex(L, -1);
            lua_getfield(L, valueIndex, "_DisconnectAll");
            if (lua_isfunction(L, -1))
            {
                lua_pushvalue(L, valueIndex);
                if (lua_pcall(L, 1, 0, 0) != LUA_OK)
                    lua_pop(L, 1);
            }
            else
                lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }
    lua_settop(L, top);
}

void notifyAllTags(lua_State* L, InstanceNode& node, bool added);

void destroyNode(lua_State* L, InstanceNode& node)
{
    if (node.destroying || node.destroyed)
        return;
    node.destroying = true;
    std::vector<uint64_t> children = node.children;
    fireSignal(L, node, "Destroying", 0, [] {});
    for (uint64_t child : children)
    {
        if (InstanceNode* childNode = nodeById(L, child))
            destroyNode(L, *childNode);
    }
    if (node.parent)
        setParent(L, node, 0);
    notifyAllTags(L, node, false);
    node.children.clear();
    disconnectSignals(L, node);

    EngineState& engine = engineFor(L);
    const uint64_t id = node.id;
    const int objectRef = node.objectRef;
    const int stateRef = node.stateRef;
    if (node.handle)
    {
        node.handle->destroyed = true;
        node.handle->archivable = node.archivable;
        node.handle->className = node.className;
        node.handle->name = node.name;
    }
    ++engine.destroyedInstances;
    if (objectRef != LUA_NOREF)
        ++engine.releasedObjectRefs;
    if (stateRef != LUA_NOREF)
        ++engine.releasedStateRefs;
    engine.nodes.erase(id);
    if (objectRef != LUA_NOREF)
        lua_unref(L, objectRef);
    if (stateRef != LUA_NOREF)
        lua_unref(L, stateRef);
}

int l_instance_tostring(lua_State* L)
{
    (void)engineFor(L);
    InstanceHandle* handle = checkHandle(L, 1);
    if (handle->destroyed)
    {
        lua_pushlstring(L, handle->name.data(), handle->name.size());
        return 1;
    }
    InstanceNode* node = nodeFor(L, 1);
    lua_pushlstring(L, node->name.data(), node->name.size());
    return 1;
}

int l_unsupported_call(lua_State* L)
{
    EngineState& engine = engineFor(L);
    std::string fullName = lua_tostring(L, lua_upvalueindex(1));
    trace(L, "stub_method", fullName, "reflection-backed method has no behavior pack");
    if (engine.strictUnsupported)
        luaL_error(L, "%s is not implemented by this runtime", fullName.c_str());
    lua_pushnil(L);
    return 1;
}

bool pushRegisteredMethod(lua_State* L, const MemberDescriptor* member, std::string_view key, bool executorMethod)
{
    EngineState& engine = engineFor(L);
    if (engine.classMethodsRef != LUA_NOREF)
        lua_getref(L, engine.classMethodsRef);
    else
        lua_getglobal(L, "__rbx_class_methods");

    if (lua_istable(L, -1) && member)
    {
        lua_getfield(L, -1, member->declaringClass.c_str());
        if (lua_istable(L, -1))
        {
            lua_getfield(L, -1, std::string(key).c_str());
            if (lua_isfunction(L, -1))
            {
                lua_remove(L, -2);
                lua_remove(L, -2);
                return true;
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    // During bootstrap the class-qualified registry is populated in stages.  The
    // compatibility method table is only a bootstrap fallback; sealed runtimes
    // never dispatch solely by an ambiguous member name.
    if (engine.bootstrapping || executorMethod)
    {
        if (engine.methodsRef != LUA_NOREF)
            lua_getref(L, engine.methodsRef);
        else
            lua_getglobal(L, "__rbx_instance_methods");
        if (lua_istable(L, -1))
        {
            lua_getfield(L, -1, std::string(key).c_str());
            if (lua_isfunction(L, -1))
            {
                lua_remove(L, -2);
                return true;
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }
    return false;
}

int l_instance_index(lua_State* L)
{
    EngineState& engine = engineFor(L);
    InstanceHandle* handle = checkHandle(L, 1);
    std::string requestedKey = luaL_checkstring(L, 2);
    if (handle->destroyed)
    {
        ResolvedMember destroyedResolved = resolveMember(L, handle->className, requestedKey);
        const MemberDescriptor* destroyedMember = destroyedResolved.descriptor;
        const std::string& destroyedKey = destroyedResolved.canonicalName;
        if (destroyedKey == "ClassName")
        {
            lua_pushlstring(L, handle->className.data(), handle->className.size());
            return 1;
        }
        if (destroyedKey == "Name")
        {
            lua_pushlstring(L, handle->name.data(), handle->name.size());
            return 1;
        }
        if (destroyedKey == "Parent")
        {
            lua_pushnil(L);
            return 1;
        }
        if (destroyedKey == "Archivable")
        {
            lua_pushboolean(L, handle->archivable);
            return 1;
        }
        if (destroyedMember && !engine.bootstrapping &&
            (destroyedMember->hasTag("NotScriptable") || privilegedSecurity(destroyedMember->security.read) ||
                privilegedCapabilities(destroyedMember->capabilities.read)))
            luaL_error(L, "%s is not accessible from this security context", requestedKey.c_str());
        if (destroyedMember && (destroyedMember->memberType == "Function" || destroyedMember->memberType == "YieldFunction") &&
            pushRegisteredMethod(L, destroyedMember, destroyedKey, false))
            return 1;
        luaL_error(L, "attempt to use a destroyed Instance");
    }

    InstanceNode* node = nodeFor(L, 1);
    ResolvedMember resolved = resolveMember(L, node->className, requestedKey);
    const MemberDescriptor* member = resolved.descriptor;
    const std::string& key = resolved.canonicalName;
    std::string kind = member ? member->memberType : std::string();
    bool executorMethod = isExecutorDataModelMethod(L, *node, requestedKey);
    if (key == "ClassName")
    {
        lua_pushlstring(L, node->className.data(), node->className.size());
        return 1;
    }
    if (key == "Name")
    {
        lua_pushlstring(L, node->name.data(), node->name.size());
        return 1;
    }
    if (key == "Parent")
    {
        pushNode(L, node->parent);
        return 1;
    }
    if (key == "Archivable")
    {
        lua_pushboolean(L, node->archivable);
        return 1;
    }
    if (member && !executorMethod && !engine.bootstrapping &&
        (member->hasTag("NotScriptable") || privilegedSecurity(member->security.read) || privilegedCapabilities(member->capabilities.read)))
        luaL_error(L, "%s is not accessible from this security context", requestedKey.c_str());

    if ((kind == "Function" || kind == "YieldFunction" || executorMethod) && pushRegisteredMethod(L, member, key, executorMethod))
        return 1;

    if (engine.guiGeometryRef != LUA_NOREF && isA(L, node->className, "GuiObject") &&
        (key == "AbsoluteSize" || key == "AbsolutePosition" || key == "AbsoluteRotation"))
    {
        lua_getref(L, engine.guiGeometryRef);
        lua_pushvalue(L, 1);
        lua_pushlstring(L, key.data(), key.size());
        lua_call(L, 2, 1);
        return 1;
    }

    pushState(L, *node);
    int stateIndex = lua_gettop(L);
    lua_rawgetfield(L, stateIndex, key.c_str());
    if (!lua_isnil(L, -1))
    {
        if (kind == "Event")
        {
            runtime::RuntimeContext* context = runtime::RuntimeContext::from(L);
            runtime::LuauRuntimeBridge* bridge = context ? context->subsystem<runtime::LuauRuntimeBridge>(runtime::LuauRuntimeBridge::kSubsystemKey) : nullptr;
            if (bridge && bridge->isSignal(L, -1))
            {
                std::shared_ptr<runtime::NativeSignal> signal = bridge->signal(L, -1);
                lua_pop(L, 2);
                bridge->pushSignal(L, std::move(signal));
                return 1;
            }
        }
        lua_remove(L, stateIndex);
        return 1;
    }
    lua_pop(L, 1);
    if (node->initializedProperties.count(key))
    {
        lua_pop(L, 1);
        lua_pushnil(L);
        return 1;
    }

    if (kind == "Event")
    {
        lua_pop(L, 1);
        ensureSignal(L, *node, key);
        runtime::RuntimeContext* context = runtime::RuntimeContext::from(L);
        runtime::LuauRuntimeBridge* bridge = context ? context->subsystem<runtime::LuauRuntimeBridge>(runtime::LuauRuntimeBridge::kSubsystemKey) : nullptr;
        if (bridge && bridge->isSignal(L, -1))
        {
            std::shared_ptr<runtime::NativeSignal> signal = bridge->signal(L, -1);
            lua_pop(L, 1);
            bridge->pushSignal(L, std::move(signal));
        }
        return 1;
    }
    if (kind == "Function" || kind == "YieldFunction")
    {
        lua_pop(L, 1);
        std::string fullName = member ? member->declaringClass + "." + key : node->className + "." + key;
        lua_pushlstring(L, fullName.data(), fullName.size());
        lua_pushcclosure(L, l_unsupported_call, fullName.c_str(), 1);
        return 1;
    }
    if (kind == "Callback")
    {
        lua_pop(L, 1);
        lua_pushnil(L);
        return 1;
    }
    if (kind == "Property")
    {
        lua_pop(L, 1);
        trace(L, "missing_fixture", node->className + "." + key, "property has no runtime default or scenario value");
        if (engine.strictUnsupported && !engine.bootstrapping)
            luaL_error(L, "%s.%s has no runtime value or scenario fixture", node->className.c_str(), key.c_str());
        lua_pushnil(L);
        return 1;
    }

    for (uint64_t childId : node->children)
    {
        InstanceNode* child = nodeById(L, childId);
        if (child && child->name == key)
        {
            lua_pop(L, 1);
            pushNode(L, childId);
            return 1;
        }
    }
    lua_pop(L, 1);
    if (kind.empty())
        trace(L, "missing_member", node->className + "." + requestedKey);
    if (engine.strictUnsupported && !engine.bootstrapping)
        luaL_error(L, "%s is not a valid member of %s", requestedKey.c_str(), node->className.c_str());
    lua_pushnil(L);
    return 1;
}

int l_instance_newindex(lua_State* L)
{
    EngineState& engine = engineFor(L);
    InstanceNode* node = nodeFor(L, 1);
    std::string requestedKey = luaL_checkstring(L, 2);
    ResolvedMember resolved = resolveMember(L, node->className, requestedKey);
    const MemberDescriptor* member = resolved.descriptor;
    const std::string& key = resolved.canonicalName;
    if (key == "ClassName")
        luaL_error(L, "ClassName is read only");
    if (key == "Name")
    {
        size_t len = 0;
        const char* value = luaL_checklstring(L, 3, &len);
        if (len > 100)
            luaL_error(L, "Name cannot exceed 100 characters");
        if (node->name.size() == len && std::equal(node->name.begin(), node->name.end(), value))
            return 0;
        node->name.assign(value, len);
        if (node->handle)
            node->handle->name = node->name;
        fireProperty(L, *node, key);
        return 0;
    }
    if (key == "Parent")
    {
        uint64_t parent = lua_isnil(L, 3) ? 0 : nodeForIdentity(L, 3)->id;
        setParent(L, *node, parent);
        return 0;
    }
    if (key == "Archivable")
    {
        luaL_checktype(L, 3, LUA_TBOOLEAN);
        bool value = lua_toboolean(L, 3) != 0;
        if (node->archivable == value)
            return 0;
        node->archivable = value;
        if (node->handle)
            node->handle->archivable = value;
        fireProperty(L, *node, key);
        return 0;
    }

    std::string kind = member ? member->memberType : std::string();
    if (member && !engine.bootstrapping &&
        (member->hasTag("NotScriptable") || privilegedSecurity(member->security.write) || privilegedCapabilities(member->capabilities.write)))
        luaL_error(L, "%s is not writable from this security context", requestedKey.c_str());
    if (member && !engine.bootstrapping && member->hasTag("ReadOnly"))
        luaL_error(L, "%s is read only", requestedKey.c_str());
    if (kind == "Event" || kind == "Function" || kind == "YieldFunction")
        luaL_error(L, "%s is not a writable property", key.c_str());
    if (kind.empty() && !engine.bootstrapping && key.rfind("_", 0) != 0 && engine.strictUnsupported)
        luaL_error(L, "%s is not a valid member of %s", key.c_str(), node->className.c_str());
    if (member && !valueMatches(L, 3, *member))
        luaL_error(L, "invalid value type for %s.%s (expected %s)", node->className.c_str(), key.c_str(), member->valueType.name.c_str());
    pushState(L, *node);
    int stateIndex = lua_absindex(L, -1);
    lua_rawgetfield(L, stateIndex, key.c_str());
    const bool humanoidHealth = key == "Health" && isA(L, node->className, "Humanoid") && lua_isnumber(L, 3);
    const double previousHealth = humanoidHealth && lua_isnumber(L, -1) ? lua_tonumber(L, -1) : 0.0;
    bool unchanged = node->initializedProperties.count(key) && lua_equal(L, -1, 3) != 0;
    lua_pop(L, 1);
    if (unchanged)
    {
        lua_pop(L, 1);
        return 0;
    }
    lua_pushvalue(L, 3);
    lua_rawsetfield(L, stateIndex, key.c_str());
    node->initializedProperties.insert(key);
    lua_pop(L, 1);
    fireProperty(L, *node, key);
    if (humanoidHealth)
    {
        const double health = lua_tonumber(L, 3);
        fireSignal(L, *node, "HealthChanged", 1, [&] { lua_pushnumber(L, health); });
        if (previousHealth > 0.0 && health <= 0.0)
            fireSignal(L, *node, "Died", 0, [] {});
    }
    return 0;
}

void pushNewInstance(lua_State* L, const std::string& className, uint64_t parentId, bool internal)
{
    EngineState& engine = engineFor(L);
    const ClassDescriptor* descriptor = descriptorFor(L, className);
    if (!descriptor)
        luaL_error(L, "Unable to create an Instance of type %s", className.c_str());
    if (!internal && descriptor->tags.count("NotCreatable"))
        luaL_error(L, "Unable to create an Instance of type %s because it is not creatable", className.c_str());

    auto node = std::make_unique<InstanceNode>();
    node->id = engine.nextId++;
    node->className = className;
    node->name = className;
    uint64_t id = node->id;

    lua_newtable(L);
    node->stateRef = lua_ref(L, -1);
    lua_pop(L, 1);

    void* storage = lua_newuserdatatagged(L, sizeof(InstanceHandle), kInstanceTag);
    auto* handle = new (storage) InstanceHandle();
    handle->id = id;
    handle->className = className;
    handle->name = className;
    node->handle = handle;
    lua_getuserdatametatable(L, kInstanceTag);
    lua_setmetatable(L, -2);
    node->objectRef = lua_ref(L, -1);
    engine.nodes[id] = std::move(node);
    lua_getref(L, engine.weakInstancesRef);
    lua_pushvalue(L, -2);
    lua_rawseti(L, -2, static_cast<int>(id));
    lua_pop(L, 1);

    for (const char* event : {"Changed", "AncestryChanged", "AttributeChanged", "ChildAdded", "ChildRemoved", "DescendantAdded", "DescendantRemoving", "Destroying"})
    {
        ensureSignal(L, *engine.nodes[id], event);
        lua_pop(L, 1);
    }

    if (parentId)
        setParent(L, *engine.nodes[id], parentId);
}

int l_instance_new(lua_State* L)
{
    std::string className = luaL_checkstring(L, 1);
    uint64_t parentId = lua_isnoneornil(L, 2) ? 0 : nodeForIdentity(L, 2)->id;
    bool internal = lua_toboolean(L, 3) != 0;
    pushNewInstance(L, className, parentId, internal);
    return 1;
}

int l_instance_public_new(lua_State* L)
{
    // Roblox exposes Instance.new as a native closure. Keep the data-driven
    // default initializer in Luau, but invoke it behind this C boundary so the
    // public constructor has the same observable closure kind as Studio.
    std::string className = luaL_checkstring(L, 1);
    const bool hasParent = lua_gettop(L) >= 2 && !lua_isnil(L, 2);
    pushNewInstance(L, className, 0, false);
    const int instanceIndex = lua_absindex(L, -1);

    lua_pushvalue(L, lua_upvalueindex(1));
    lua_pushvalue(L, instanceIndex);
    lua_call(L, 1, 0);

    // Match the previous wrapper's ordering: defaults are initialized before
    // Parent is assigned and any ancestry signals are emitted.
    if (hasParent)
    {
        InstanceNode* instance = nodeFor(L, instanceIndex);
        InstanceNode* parent = nodeForIdentity(L, 2);
        setParent(L, *instance, parent->id);
    }

    lua_pushvalue(L, instanceIndex);
    return 1;
}

int l_instance_bind_public_new(lua_State* L)
{
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushvalue(L, 1);
    lua_pushcclosure(L, l_instance_public_new, "new", 1);
    return 1;
}

int l_executor_native_forward(lua_State* L)
{
    const int argumentCount = lua_gettop(L);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    return luaL_callyieldable(L, argumentCount, LUA_MULTRET);
}

int l_executor_native_forward_continue(lua_State* L, int status)
{
    (void)status;
    return lua_gettop(L);
}

int l_executor_bind_native(lua_State* L)
{
    const char* name = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    lua_pushvalue(L, 2);
    lua_pushcclosurek(L, l_executor_native_forward, name, 1, l_executor_native_forward_continue);
    return 1;
}

int l_instance_native_forward(lua_State* L)
{
    if (!lua_touserdatatagged(L, 1, kInstanceTag))
    {
        const char* name = lua_tostring(L, lua_upvalueindex(2));
        luaL_error(L, "Expected ':' not '.' calling member function %s", name ? name : "?");
    }
    return l_executor_native_forward(L);
}

int l_instance_bind_native(lua_State* L)
{
    const char* name = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    lua_pushvalue(L, 2);
    lua_pushstring(L, name);
    lua_pushcclosurek(L, l_instance_native_forward, name, 2, l_executor_native_forward_continue);
    return 1;
}

int l_instance_children(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    lua_createtable(L, static_cast<int>(node->children.size()), 0);
    int index = 1;
    for (uint64_t childId : node->children)
    {
        InstanceNode* child = nodeById(L, childId);
        if (!child)
            continue;
        pushNode(L, childId);
        lua_rawseti(L, -2, index++);
    }
    return 1;
}

InstanceNode* findChild(lua_State* L, InstanceNode& node, const std::string& name, bool recursive)
{
    for (uint64_t childId : node.children)
    {
        InstanceNode* child = nodeById(L, childId);
        if (child && child->name == name)
            return child;
    }
    if (recursive)
    {
        for (uint64_t childId : node.children)
        {
            InstanceNode* child = nodeById(L, childId);
            if (child)
            {
                if (InstanceNode* found = findChild(L, *child, name, true))
                    return found;
            }
        }
    }
    return nullptr;
}

int l_instance_find(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    std::string name = luaL_checkstring(L, 2);
    bool recursive = lua_toboolean(L, 3) != 0;
    InstanceNode* found = findChild(L, *node, name, recursive);
    pushNode(L, found ? found->id : 0);
    return 1;
}

int continueInstanceWaitForChild(lua_State* L)
{
    EngineState& engine = engineFor(L);
    auto requestIt = engine.waitForChildRequests.find(L);
    if (requestIt == engine.waitForChildRequests.end())
        luaL_error(L, "WaitForChild continuation state is unavailable");

    WaitForChildRequest& request = requestIt->second;
    InstanceNode* node = nodeById(L, request.instanceId);
    if (node)
    {
        if (InstanceNode* found = findChild(L, *node, request.childName, false))
        {
            const uint64_t foundId = found->id;
            engine.waitForChildRequests.erase(requestIt);
            pushNode(L, foundId);
            return 1;
        }
    }

    runtime::RuntimeContext& context = contextFor(L);
    if (request.timeout && context.scheduler().now() - request.startedAt >= *request.timeout)
    {
        engine.waitForChildRequests.erase(requestIt);
        lua_pushnil(L);
        return 1;
    }

    runtime::LuauRuntimeBridge* bridge =
        context.subsystem<runtime::LuauRuntimeBridge>(runtime::LuauRuntimeBridge::kSubsystemKey);
    if (!bridge)
        luaL_error(L, "WaitForChild requires the native scheduler");
    return bridge->yieldWait(L, 0.0);
}

int l_instance_wait_for_child_continue(lua_State* L, int status)
{
    (void)status;
    return continueInstanceWaitForChild(L);
}

int l_instance_wait_for_child(lua_State* L)
{
    InstanceNode* node = nodeForIdentity(L, 1);
    std::string childName = luaL_checkstring(L, 2);
    if (InstanceNode* found = findChild(L, *node, childName, false))
    {
        pushNode(L, found->id);
        return 1;
    }

    std::optional<double> timeout;
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3))
        timeout = luaL_checknumber(L, 3);

    runtime::RuntimeContext& context = contextFor(L);
    engineFor(L).waitForChildRequests[L] = WaitForChildRequest{
        node->id,
        std::move(childName),
        context.scheduler().now(),
        timeout,
    };

    runtime::LuauRuntimeBridge* bridge =
        context.subsystem<runtime::LuauRuntimeBridge>(runtime::LuauRuntimeBridge::kSubsystemKey);
    if (!bridge)
        luaL_error(L, "WaitForChild requires the native scheduler");
    return bridge->yieldWait(L, 0.0);
}

int l_instance_is_a(lua_State* L)
{
    InstanceHandle* handle = checkHandle(L, 1);
    lua_pushboolean(L, isA(L, handle->className, luaL_checkstring(L, 2)));
    return 1;
}

int l_instance_destroy(lua_State* L)
{
    (void)engineFor(L);
    InstanceHandle* handle = checkHandle(L, 1);
    if (handle->destroyed)
        return 0;
    destroyNode(L, *nodeFor(L, 1));
    return 0;
}

int l_instance_set_parent(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    uint64_t parent = lua_isnil(L, 2) ? 0 : nodeForIdentity(L, 2)->id;
    setParent(L, *node, parent);
    return 0;
}

int l_instance_get_property_signal(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    std::string requested = luaL_checkstring(L, 2);
    ResolvedMember resolved = resolveMember(L, node->className, requested);
    if (!resolved || resolved.descriptor->memberType != "Property")
        luaL_error(L, "%s is not a valid property of %s", requested.c_str(), node->className.c_str());
    if (resolved.descriptor->hasTag("NotScriptable") || privilegedSecurity(resolved.descriptor->security.read))
        luaL_error(L, "%s is not accessible from this security context", requested.c_str());
    ensureSignal(L, *node, "__property_" + resolved.canonicalName);
    return 1;
}

bool validAttributeName(std::string_view name)
{
    if (name.empty() || name.size() > 100 || name.rfind("RBX", 0) == 0)
        return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char value) {
        return std::isalnum(value) || value == '_';
    });
}

bool validAttributeValue(lua_State* L, int index)
{
    int type = lua_type(L, index);
    if (type == LUA_TNIL || type == LUA_TBOOLEAN || type == LUA_TNUMBER || type == LUA_TSTRING || type == LUA_TINTEGER)
        return true;
    static const std::set<std::string> supported = {
        "BrickColor", "CFrame", "Color3", "ColorSequence", "DateTime", "EnumItem", "Font", "NumberRange",
        "NumberSequence", "Rect", "UDim", "UDim2", "Vector2", "Vector2int16", "Vector3", "Vector3int16",
    };
    return supported.count(luaValueTypeName(L, index)) != 0;
}

std::string checkedAttributeName(lua_State* L, int index)
{
    size_t length = 0;
    const char* value = luaL_checklstring(L, index, &length);
    std::string name(value, length);
    if (!validAttributeName(name))
        luaL_error(L, "attribute name must contain only letters, digits, and underscores, must not start with RBX, and must be at most 100 characters");
    return name;
}

int l_instance_get_attribute(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    std::string key = luaL_checkstring(L, 2);
    pushState(L, *node);
    lua_rawgetfield(L, -1, "__attributes");
    if (!lua_istable(L, -1))
    {
        lua_pushnil(L);
        return 1;
    }
    lua_rawgetfield(L, -1, key.c_str());
    return 1;
}

int l_instance_internal_property(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    std::string key = luaL_checkstring(L, 2);
    pushState(L, *node);
    lua_rawgetfield(L, -1, key.c_str());
    return 1;
}

int l_instance_set_default(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    std::string requested = luaL_checkstring(L, 2);
    ResolvedMember resolved = resolveMember(L, node->className, requested);
    if (!resolved || (resolved.descriptor->memberType != "Property" && resolved.descriptor->memberType != "Callback"))
        luaL_error(L, "%s is not a defaultable member of %s", requested.c_str(), node->className.c_str());
    pushState(L, *node);
    lua_pushvalue(L, 3);
    lua_rawsetfield(L, -2, resolved.canonicalName.c_str());
    node->initializedProperties.insert(resolved.canonicalName);
    return 0;
}

int l_instance_set_gui_geometry_resolver(lua_State* L)
{
    EngineState& engine = engineFor(L);
    luaL_checktype(L, 1, LUA_TFUNCTION);
    if (engine.guiGeometryRef != LUA_NOREF)
        lua_unref(L, engine.guiGeometryRef);
    engine.guiGeometryRef = lua_ref(L, 1);
    return 0;
}

int l_instance_get_attributes(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    pushState(L, *node);
    lua_rawgetfield(L, -1, "__attributes");
    if (!lua_istable(L, -1))
        lua_newtable(L);
    return 1;
}

int l_instance_set_attribute(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    std::string key = checkedAttributeName(L, 2);
    if (!validAttributeValue(L, 3))
        luaL_error(L, "unsupported attribute value type %s", luaValueTypeName(L, 3).c_str());
    pushState(L, *node);
    int stateIndex = lua_gettop(L);
    lua_rawgetfield(L, stateIndex, "__attributes");
    if (!lua_istable(L, -1))
    {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_rawsetfield(L, stateIndex, "__attributes");
    }
    int attributesIndex = lua_absindex(L, -1);
    lua_rawgetfield(L, attributesIndex, key.c_str());
    bool unchanged = lua_equal(L, -1, 3) != 0;
    lua_pop(L, 1);
    if (unchanged)
        return 0;
    lua_pushvalue(L, 3);
    lua_rawsetfield(L, attributesIndex, key.c_str());
    fireSignal(L, *node, "AttributeChanged", 1, [&] { lua_pushlstring(L, key.data(), key.size()); });
    fireSignal(L, *node, "__attribute_" + key, 0, [] {});
    return 0;
}

int l_instance_get_attribute_signal(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    std::string key = checkedAttributeName(L, 2);
    ensureSignal(L, *node, "__attribute_" + key);
    return 1;
}

std::string checkedTag(lua_State* L, int index)
{
    size_t length = 0;
    const char* value = luaL_checklstring(L, index, &length);
    if (length == 0 || length > 100 || std::find(value, value + length, '\0') != value + length)
        luaL_error(L, "tag must be a non-empty string of at most 100 characters without NUL bytes");
    return std::string(value, length);
}

void notifyTagChanged(lua_State* L, InstanceNode& node, const std::string& tag, bool added)
{
    EngineState& engine = engineFor(L);
    int top = lua_gettop(L);
    if (engine.tagChangedRef != LUA_NOREF)
        lua_getref(L, engine.tagChangedRef);
    else
        lua_getglobal(L, "__rbx_collection_tag_changed");
    if (lua_isfunction(L, -1))
    {
        pushNode(L, node.id);
        lua_pushlstring(L, tag.data(), tag.size());
        lua_pushboolean(L, added);
        if (lua_pcall(L, 3, 0, 0) != LUA_OK)
            lua_pop(L, 1);
    }
    lua_settop(L, top);
}

void notifyAllTags(lua_State* L, InstanceNode& node, bool added)
{
    int top = lua_gettop(L);
    std::vector<std::string> tags;
    pushState(L, node);
    lua_rawgetfield(L, -1, "__tags");
    if (lua_istable(L, -1))
    {
        int tagsIndex = lua_absindex(L, -1);
        lua_pushnil(L);
        while (lua_next(L, tagsIndex) != 0)
        {
            if (lua_isstring(L, -2) && lua_toboolean(L, -1))
                tags.emplace_back(lua_tostring(L, -2));
            lua_pop(L, 1);
        }
    }
    lua_settop(L, top);
    for (const std::string& tag : tags)
        notifyTagChanged(L, node, tag, added);
}

int l_instance_tags(lua_State* L)
{
    InstanceNode* node = nodeFor(L, 1);
    pushState(L, *node);
    int stateIndex = lua_gettop(L);
    lua_rawgetfield(L, stateIndex, "__tags");
    if (!lua_istable(L, -1))
    {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_rawsetfield(L, stateIndex, "__tags");
    }
    if (lua_gettop(L) >= 2 && lua_isstring(L, 2))
    {
        std::string key = checkedTag(L, 2);
        if (lua_gettop(L) >= 3 && lua_isboolean(L, 3))
        {
            bool requested = lua_toboolean(L, 3) != 0;
            int tagsIndex = lua_absindex(L, -1);
            lua_rawgetfield(L, tagsIndex, key.c_str());
            bool current = lua_toboolean(L, -1) != 0;
            lua_pop(L, 1);
            if (current == requested)
                return 0;
            if (requested)
                lua_pushboolean(L, 1);
            else
                lua_pushnil(L);
            lua_rawsetfield(L, tagsIndex, key.c_str());
            notifyTagChanged(L, *node, key, requested);
            return 0;
        }
        lua_rawgetfield(L, -1, key.c_str());
        lua_pushboolean(L, lua_toboolean(L, -1));
        return 1;
    }
    return 1;
}

int l_instance_tagged(lua_State* L)
{
    EngineState& engine = engineFor(L);
    std::string tag = checkedTag(L, 1);
    lua_newtable(L);
    int output = lua_absindex(L, -1);
    int resultIndex = 1;
    for (const auto& [_, node] : engine.nodes)
    {
        if (!node)
            continue;
        int top = lua_gettop(L);
        pushState(L, *node);
        lua_rawgetfield(L, -1, "__tags");
        if (lua_istable(L, -1))
        {
            lua_rawgetfield(L, -1, tag.c_str());
            bool tagged = lua_toboolean(L, -1) != 0;
            lua_settop(L, top);
            if (tagged)
            {
                pushNode(L, node->id);
                lua_rawseti(L, output, resultIndex++);
            }
        }
        else
            lua_settop(L, top);
    }
    return 1;
}

using CloneMap = std::unordered_map<uint64_t, uint64_t>;

void pushCloneValue(lua_State* L, int sourceIndex, const CloneMap& mapping, bool cloneTable);

void pushPlainTableClone(lua_State* L, int sourceIndex, const CloneMap& mapping)
{
    sourceIndex = lua_absindex(L, sourceIndex);
    lua_newtable(L);
    int targetIndex = lua_absindex(L, -1);
    lua_pushnil(L);
    while (lua_next(L, sourceIndex) != 0)
    {
        pushCloneValue(L, -2, mapping, false);
        pushCloneValue(L, -2, mapping, true);
        lua_rawset(L, targetIndex);
        lua_pop(L, 1);
    }
}

void pushCloneValue(lua_State* L, int sourceIndex, const CloneMap& mapping, bool cloneTable)
{
    sourceIndex = lua_absindex(L, sourceIndex);
    if (isInstance(L, sourceIndex))
    {
        InstanceHandle* handle = static_cast<InstanceHandle*>(lua_touserdatatagged(L, sourceIndex, kInstanceTag));
        auto remapped = mapping.find(handle->id);
        if (remapped != mapping.end())
            pushNode(L, remapped->second);
        else
            lua_pushvalue(L, sourceIndex);
        return;
    }
    if (cloneTable && lua_istable(L, sourceIndex))
    {
        pushPlainTableClone(L, sourceIndex, mapping);
        return;
    }
    lua_pushvalue(L, sourceIndex);
}

void copyState(lua_State* L, InstanceNode& source, InstanceNode& target, const CloneMap& mapping)
{
    target.initializedProperties = source.initializedProperties;
    pushState(L, source);
    int sourceIndex = lua_gettop(L);
    pushState(L, target);
    int targetIndex = lua_gettop(L);
    lua_pushnil(L);
    while (lua_next(L, sourceIndex) != 0)
    {
        if (lua_isstring(L, -2))
        {
            std::string key = lua_tostring(L, -2);
            ResolvedMember reflected = resolveMember(L, source.className, key);
            const bool eventMember = reflected && reflected.descriptor->memberType == "Event";
            if (!eventMember && key.rfind("__property_", 0) != 0 && key.rfind("__attribute_", 0) != 0 &&
                key != "Changed" && key != "AncestryChanged" && key != "AttributeChanged" && key != "ChildAdded" &&
                key != "ChildRemoved" && key != "DescendantAdded" && key != "DescendantRemoving" && key != "Destroying" &&
                key != "__parent_identity")
            {
                lua_pushvalue(L, -2);
                if ((key == "__attributes" || key == "__tags") && lua_istable(L, -2))
                    pushPlainTableClone(L, -2, mapping);
                else
                    pushCloneValue(L, -2, mapping, false);
                lua_rawset(L, targetIndex);
            }
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 2);
}

uint64_t cloneSkeleton(lua_State* L, InstanceNode& source, CloneMap& mapping)
{
    pushNewInstance(L, source.className, 0, true);
    InstanceNode* clone = nodeFor(L, -1);
    clone->name = source.name;
    clone->archivable = source.archivable;
    if (clone->handle)
    {
        clone->handle->name = clone->name;
        clone->handle->archivable = clone->archivable;
    }
    uint64_t cloneId = clone->id;
    mapping[source.id] = cloneId;
    lua_pop(L, 1);
    for (uint64_t childId : source.children)
    {
        InstanceNode* child = nodeById(L, childId);
        if (!child || !child->archivable)
            continue;
        uint64_t childClone = cloneSkeleton(L, *child, mapping);
        if (InstanceNode* childNode = nodeById(L, childClone))
        {
            childNode->parent = cloneId;
            clone->children.push_back(childClone);
        }
    }
    return cloneId;
}

uint64_t cloneTree(lua_State* L, InstanceNode& source)
{
    CloneMap mapping;
    uint64_t root = cloneSkeleton(L, source, mapping);
    for (const auto& [sourceId, targetId] : mapping)
    {
        InstanceNode* sourceNode = nodeById(L, sourceId);
        InstanceNode* targetNode = nodeById(L, targetId);
        if (sourceNode && targetNode)
            copyState(L, *sourceNode, *targetNode, mapping);
    }
    for (const auto& [_, targetId] : mapping)
        if (InstanceNode* targetNode = nodeById(L, targetId))
            notifyAllTags(L, *targetNode, true);
    return root;
}

int l_instance_clone(lua_State* L)
{
    InstanceNode* source = nodeFor(L, 1);
    if (!source->archivable)
    {
        lua_pushnil(L);
        return 1;
    }
    pushNode(L, cloneTree(L, *source));
    return 1;
}

int l_instance_public_from_existing(lua_State* L)
{
    InstanceNode* source = nodeFor(L, 1);
    pushNewInstance(L, source->className, 0, true);
    InstanceNode* target = nodeFor(L, -1);

    target->name = source->name;
    target->archivable = source->archivable;
    if (target->handle)
    {
        target->handle->name = target->name;
        target->handle->archivable = target->archivable;
    }

    // fromExisting copies the object's property state, attributes, tags, and
    // instance references, but never copies descendants or Parent. A self
    // reference is remapped to the new object; external references are kept.
    CloneMap mapping{{source->id, target->id}};
    copyState(L, *source, *target, mapping);
    notifyAllTags(L, *target, true);
    return 1;
}

int l_instance_bind_public_from_existing(lua_State* L)
{
    lua_pushcfunction(L, l_instance_public_from_existing, "fromExisting");
    return 1;
}

int l_instance_full_name(lua_State* L)
{
    (void)engineFor(L);
    InstanceHandle* handle = checkHandle(L, 1);
    if (handle->destroyed)
    {
        lua_pushlstring(L, handle->name.data(), handle->name.size());
        return 1;
    }
    InstanceNode* node = nodeFor(L, 1);
    std::vector<std::string> parts;
    std::set<uint64_t> visited;
    while (node && visited.insert(node->id).second)
    {
        parts.push_back(node->name);
        node = nodeById(L, node->parent);
    }
    std::string result;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it)
    {
        if (!result.empty())
            result += ".";
        result += *it;
    }
    lua_pushlstring(L, result.data(), result.size());
    return 1;
}

const char* valueTypeName(ValueKind kind)
{
    switch (kind)
    {
    case ValueKind::Enums: return "Enums";
    case ValueKind::EnumType: return "Enum";
    case ValueKind::EnumItem: return "EnumItem";
    case ValueKind::TweenInfo: return "TweenInfo";
    case ValueKind::RaycastParams: return "RaycastParams";
    case ValueKind::OverlapParams: return "OverlapParams";
    case ValueKind::NumberRange: return "NumberRange";
    case ValueKind::NumberSequenceKeypoint: return "NumberSequenceKeypoint";
    case ValueKind::NumberSequence: return "NumberSequence";
    case ValueKind::ColorSequenceKeypoint: return "ColorSequenceKeypoint";
    case ValueKind::ColorSequence: return "ColorSequence";
    case ValueKind::DateTime: return "DateTime";
    case ValueKind::Random: return "Random";
    }
    return "userdata";
}

std::string valueMetatableName(ValueKind kind)
{
    return std::string("RBXValue.") + valueTypeName(kind);
}

ValueHandle* valueFor(lua_State* L, int index)
{
    void* pointer = lua_touserdatatagged(L, index, kValueTag);
    if (!pointer)
        luaL_typeerror(L, index, "Roblox value type");
    return static_cast<ValueHandle*>(pointer);
}

ValueHandle* valueFor(lua_State* L, int index, ValueKind expected)
{
    ValueHandle* value = valueFor(L, index);
    if (value->kind != expected)
        luaL_typeerror(L, index, valueTypeName(expected));
    return value;
}

ValueHandle* pushValue(lua_State* L, ValueKind kind)
{
    void* storage = lua_newuserdatatagged(L, sizeof(ValueHandle), kValueTag);
    auto* value = new (storage) ValueHandle();
    value->kind = kind;
    const std::string metatable = valueMetatableName(kind);
    luaL_getmetatable(L, metatable.c_str());
    lua_setmetatable(L, -2);
    return value;
}

std::string formatValueNumber(double value)
{
    if (value == 0)
        value = 0;
    std::ostringstream output;
    output << std::setprecision(14) << value;
    return output.str();
}

bool readEnumItem(lua_State* L, int index, std::string_view expectedType, std::string& itemName)
{
    void* pointer = lua_touserdatatagged(L, index, kValueTag);
    if (!pointer)
        return false;
    const auto* value = static_cast<const ValueHandle*>(pointer);
    if (value->kind != ValueKind::EnumItem || value->enumName1 != expectedType)
        return false;
    itemName = value->text;
    return true;
}

void pushEnumItem(lua_State* L, const char* enumType, const std::string& itemName)
{
    EngineState& engine = engineFor(L);
    auto definition = engine.enums.find(enumType);
    if (definition == engine.enums.end())
    {
        lua_pushnil(L);
        return;
    }
    auto item = definition->second.itemLookup.find(itemName);
    if (item == definition->second.itemLookup.end() || item->second >= definition->second.itemRefs.size())
    {
        lua_pushnil(L);
        return;
    }
    lua_getref(L, definition->second.itemRefs[item->second]);
}

bool readColor3(lua_State* L, int index, double& red, double& green, double& blue)
{
    index = lua_absindex(L, index);
    int top = lua_gettop(L);
    lua_getglobal(L, "typeof");
    lua_pushvalue(L, index);
    if (lua_pcall(L, 1, 1, 0) != LUA_OK || !lua_isstring(L, -1) || std::string_view(lua_tostring(L, -1)) != "Color3")
    {
        lua_settop(L, top);
        return false;
    }
    lua_settop(L, top);
    lua_getfield(L, index, "R");
    lua_getfield(L, index, "G");
    lua_getfield(L, index, "B");
    bool valid = lua_isnumber(L, -3) && lua_isnumber(L, -2) && lua_isnumber(L, -1);
    if (valid)
    {
        red = lua_tonumber(L, -3);
        green = lua_tonumber(L, -2);
        blue = lua_tonumber(L, -1);
    }
    lua_pop(L, 3);
    return valid;
}

void pushColor3(lua_State* L, double red, double green, double blue)
{
    lua_getglobal(L, "Color3");
    if (!lua_istable(L, -1))
        luaL_error(L, "Color3 is unavailable");
    lua_getfield(L, -1, "new");
    lua_remove(L, -2);
    if (!lua_isfunction(L, -1))
        luaL_error(L, "Color3.new is unavailable");
    lua_pushnumber(L, red);
    lua_pushnumber(L, green);
    lua_pushnumber(L, blue);
    if (lua_pcall(L, 3, 1, 0) != LUA_OK)
        lua_error(L);
}

std::vector<uint64_t> checkedInstanceList(lua_State* L, int index)
{
    index = lua_absindex(L, index);
    luaL_checktype(L, index, LUA_TTABLE);
    std::vector<uint64_t> result;
    const int length = lua_objlen(L, index);
    result.reserve(static_cast<size_t>(std::max(0, length)));
    for (int item = 1; item <= length; ++item)
    {
        lua_rawgeti(L, index, item);
        if (!isInstance(L, -1))
            luaL_error(L, "FilterDescendantsInstances must contain only Instances");
        InstanceHandle* handle = checkHandle(L, -1);
        if (handle->destroyed)
            luaL_error(L, "FilterDescendantsInstances cannot contain a destroyed Instance");
        result.push_back(handle->id);
        lua_pop(L, 1);
    }
    return result;
}

void pushInstanceList(lua_State* L, const std::vector<uint64_t>& ids)
{
    lua_createtable(L, static_cast<int>(ids.size()), 0);
    int output = lua_absindex(L, -1);
    int item = 1;
    for (uint64_t id : ids)
    {
        InstanceNode* node = nodeById(L, id);
        if (!node)
            continue;
        pushNode(L, id);
        lua_rawseti(L, output, item++);
    }
}

bool sameNumberPoints(const std::vector<NumberSequencePoint>& left, const std::vector<NumberSequencePoint>& right)
{
    if (left.size() != right.size())
        return false;
    for (size_t index = 0; index < left.size(); ++index)
        if (left[index].time != right[index].time || left[index].value != right[index].value || left[index].envelope != right[index].envelope)
            return false;
    return true;
}

bool sameColorPoints(const std::vector<ColorSequencePoint>& left, const std::vector<ColorSequencePoint>& right)
{
    if (left.size() != right.size())
        return false;
    for (size_t index = 0; index < left.size(); ++index)
        if (left[index].time != right[index].time || left[index].red != right[index].red || left[index].green != right[index].green ||
            left[index].blue != right[index].blue)
            return false;
    return true;
}

void pushNumberSequencePoint(lua_State* L, const NumberSequencePoint& point)
{
    ValueHandle* value = pushValue(L, ValueKind::NumberSequenceKeypoint);
    value->numbers[0] = point.time;
    value->numbers[1] = point.value;
    value->numbers[2] = point.envelope;
}

void pushColorSequencePoint(lua_State* L, const ColorSequencePoint& point)
{
    ValueHandle* value = pushValue(L, ValueKind::ColorSequenceKeypoint);
    value->numbers[0] = point.time;
    value->numbers[1] = point.red;
    value->numbers[2] = point.green;
    value->numbers[3] = point.blue;
}

int l_value_add_to_filter(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1);
    if (value->kind != ValueKind::RaycastParams && value->kind != ValueKind::OverlapParams)
        luaL_error(L, "AddToFilter is only valid on spatial query parameters");

    std::vector<uint64_t> additions;
    if (isInstance(L, 2))
    {
        InstanceHandle* handle = checkHandle(L, 2);
        if (handle->destroyed)
            luaL_error(L, "AddToFilter cannot add a destroyed Instance");
        additions.push_back(handle->id);
    }
    else
        additions = checkedInstanceList(L, 2);

    for (uint64_t id : additions)
        if (std::find(value->instanceIds.begin(), value->instanceIds.end(), id) == value->instanceIds.end())
            value->instanceIds.push_back(id);
    return 0;
}

int l_datetime_to_unix(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1, ValueKind::DateTime);
    lua_pushnumber(L, std::floor(static_cast<double>(value->integer) / 1000.0));
    return 1;
}

int l_datetime_to_unix_millis(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1, ValueKind::DateTime);
    lua_pushnumber(L, static_cast<double>(value->integer));
    return 1;
}

int l_datetime_to_iso(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1, ValueKind::DateTime);
    const int64_t seconds = static_cast<int64_t>(std::floor(static_cast<double>(value->integer) / 1000.0));
    const std::time_t time = static_cast<std::time_t>(seconds);
    std::tm universal{};
#if defined(_WIN32)
    if (gmtime_s(&universal, &time) != 0)
        luaL_error(L, "DateTime is outside the supported ISO date range");
#else
    if (!gmtime_r(&time, &universal))
        luaL_error(L, "DateTime is outside the supported ISO date range");
#endif
    char output[32]{};
    if (std::strftime(output, sizeof(output), "%Y-%m-%dT%H:%M:%SZ", &universal) == 0)
        luaL_error(L, "DateTime is outside the supported ISO date range");
    lua_pushstring(L, output);
    return 1;
}

constexpr uint64_t kRandomMultiplier = UINT64_C(6364136223846793005);
constexpr uint64_t kRandomIncrement = UINT64_C(105);
constexpr uint64_t kRandomMaximumExactSeed = UINT64_C(9007199254740991);
constexpr uint64_t kRandomNoSeedStride = UINT64_C(1013904223);
constexpr double kPi = 3.141592653589793238462643383279502884;

uint64_t normalizeCompatibilityRandomSeed(lua_State* L, double seed)
{
    constexpr double maximumSeed = static_cast<double>(kRandomMaximumExactSeed);
    if (!std::isfinite(seed) || seed < -maximumSeed || seed > maximumSeed)
        luaL_error(L, "Random seed must be finite");

    uint64_t state = 0;
    auto advance = [&state]() {
        const uint64_t previous = state;
        state = previous * kRandomMultiplier + kRandomIncrement;
    };
    advance();
    state += static_cast<uint64_t>(static_cast<int64_t>(std::floor(seed)));
    advance();
    return state;
}

uint32_t nextCompatibilityRandomUint32(ValueHandle& value)
{
    const uint64_t previous = value.randomState;
    value.randomState = previous * kRandomMultiplier + kRandomIncrement;
    const uint32_t xorshifted = static_cast<uint32_t>(((previous >> 18u) ^ previous) >> 27u);
    const uint32_t rotation = static_cast<uint32_t>(previous >> 59u);
    return std::rotr(xorshifted, static_cast<int>(rotation));
}

double nextCompatibilityRandomFraction(ValueHandle& value)
{
    const uint32_t low = nextCompatibilityRandomUint32(value);
    const uint32_t high = nextCompatibilityRandomUint32(value);
    return std::ldexp(static_cast<double>(static_cast<uint64_t>(low) | (static_cast<uint64_t>(high) << 32u)), -64);
}

double nextUnseededCompatibilityRandomSeed(lua_State* L)
{
    EngineState& engine = engineFor(L);
    const uint64_t sequence = ++engine.randomObjectSequence;
    const uint64_t mixed = contextFor(L).deterministicSeed() + sequence * kRandomNoSeedStride;
    return static_cast<double>(mixed & kRandomMaximumExactSeed);
}

int l_random_new(lua_State* L)
{
    const int argumentCount = lua_gettop(L);
    if (argumentCount > 1)
        luaL_error(L, "Random.new requires 0 or 1 argument");

    const double seed = argumentCount == 0 || lua_isnil(L, 1) ? nextUnseededCompatibilityRandomSeed(L) : luaL_checknumber(L, 1);
    const uint64_t state = normalizeCompatibilityRandomSeed(L, seed);
    ValueHandle* value = pushValue(L, ValueKind::Random);
    value->randomState = state;
    return 1;
}

int l_random_bind_public_new(lua_State* L)
{
    if (lua_gettop(L) != 0)
        luaL_error(L, "Random constructor binder expects no arguments");
    lua_pushcfunction(L, l_random_new, "new");
    return 1;
}

int l_random_clone(lua_State* L)
{
    ValueHandle* source = valueFor(L, 1, ValueKind::Random);
    if (lua_gettop(L) != 1)
        luaL_error(L, "Random:Clone requires 0 arguments");
    ValueHandle* clone = pushValue(L, ValueKind::Random);
    clone->randomState = source->randomState;
    return 1;
}

int l_random_next_number(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1, ValueKind::Random);
    const int argumentCount = lua_gettop(L) - 1;
    if (argumentCount != 0 && argumentCount != 2)
        luaL_error(L, "Random:NextNumber requires 0 or 2 arguments");

    if (argumentCount == 0)
    {
        lua_pushnumber(L, nextCompatibilityRandomFraction(*value));
        return 1;
    }

    const double minimum = luaL_checknumber(L, 2);
    const double maximum = luaL_checknumber(L, 3);
    if (!std::isfinite(minimum) || !std::isfinite(maximum))
        luaL_error(L, "Random:NextNumber bounds must be finite");
    const double fraction = nextCompatibilityRandomFraction(*value);
    lua_pushnumber(L, minimum * (1.0 - fraction) + maximum * fraction);
    return 1;
}

int l_random_next_integer(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1, ValueKind::Random);
    if (lua_gettop(L) != 3)
        luaL_error(L, "Random:NextInteger requires 2 arguments");

    const int64_t minimum = luaL_checkinteger(L, 2);
    const int64_t maximum = luaL_checkinteger(L, 3);
    if (minimum > maximum)
        luaL_error(L, "Random:NextInteger bounds must be finite");
    const uint64_t width = static_cast<uint64_t>(maximum - minimum) + 1u;
    if (width == 0 || width > UINT64_C(4294967296))
        luaL_error(L, "Random:NextInteger interval is too large");
    const uint64_t scaled = width * static_cast<uint64_t>(nextCompatibilityRandomUint32(*value));
    lua_pushinteger(L, minimum + static_cast<int64_t>(scaled >> 32u));
    return 1;
}

void pushRandomVector3(lua_State* L, double x, double y, double z)
{
    EngineState& engine = engineFor(L);
    if (engine.vector3NewRef == LUA_NOREF)
        luaL_error(L, "Vector3.new is unavailable to Random");
    lua_getref(L, engine.vector3NewRef);
    if (!lua_isfunction(L, -1))
        luaL_error(L, "Vector3.new is unavailable to Random");
    lua_pushnumber(L, x);
    lua_pushnumber(L, y);
    lua_pushnumber(L, z);
    lua_call(L, 3, 1);
}

int l_random_next_unit_vector(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1, ValueKind::Random);
    if (lua_gettop(L) != 1)
        luaL_error(L, "Random:NextUnitVector requires 0 arguments");

    constexpr double uint32Scale = 1.0 / 4294967296.0;
    const double angle = static_cast<double>(nextCompatibilityRandomUint32(*value)) * uint32Scale * (2.0 * kPi);
    const double height = static_cast<double>(nextCompatibilityRandomUint32(*value)) * uint32Scale * 2.0 - 1.0;
    const double radius = std::sqrt(std::max(0.0, 1.0 - height * height));
    pushRandomVector3(L, radius * std::cos(angle), radius * std::sin(angle), height);
    return 1;
}

int randomShuffleLength(lua_State* L, int tableIndex)
{
    tableIndex = lua_absindex(L, tableIndex);
    int highest = 0;
    lua_pushnil(L);
    while (lua_next(L, tableIndex) != 0)
    {
        const int keyType = lua_type(L, -2);
        if (keyType == LUA_TNUMBER || keyType == LUA_TINTEGER)
        {
            const double key = lua_tonumber(L, -2);
            if (std::isfinite(key) && key >= 1.0 && std::floor(key) == key)
            {
                if (key > static_cast<double>(std::numeric_limits<int>::max()))
                    luaL_error(L, "Random:Shuffle table is too large");
                highest = std::max(highest, static_cast<int>(key));
            }
        }
        lua_pop(L, 1);
    }

    for (int index = 1; index <= highest; ++index)
    {
        lua_rawgeti(L, tableIndex, index);
        const bool missing = lua_isnil(L, -1);
        lua_pop(L, 1);
        if (missing)
            luaL_error(L,
                "Attempted to shuffle table containing nil values. This is not allowed because the table length may change.");
    }
    return highest;
}

int l_random_shuffle(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1, ValueKind::Random);
    if (lua_gettop(L) != 2)
        luaL_error(L, "Random:Shuffle requires 1 argument");
    luaL_checktype(L, 2, LUA_TTABLE);
    if (lua_getreadonly(L, 2))
        luaL_error(L, "attempt to modify a readonly table");

    const int tableIndex = lua_absindex(L, 2);
    const int length = randomShuffleLength(L, tableIndex);
    for (int index = length; index >= 2; --index)
    {
        const int other = 1 + static_cast<int>((static_cast<uint64_t>(index) * nextCompatibilityRandomUint32(*value)) >> 32u);
        lua_rawgeti(L, tableIndex, index);
        lua_rawgeti(L, tableIndex, other);
        lua_pushvalue(L, -1);
        lua_rawseti(L, tableIndex, index);
        lua_pushvalue(L, -2);
        lua_rawseti(L, tableIndex, other);
        lua_pop(L, 2);
    }
    return 0;
}

int l_enum_get_items(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1, ValueKind::EnumType);
    EngineState& engine = engineFor(L);
    auto definition = engine.enums.find(value->text);
    if (definition == engine.enums.end())
        luaL_error(L, "invalid Enum type");
    lua_createtable(L, static_cast<int>(definition->second.itemRefs.size()), 0);
    for (size_t index = 0; index < definition->second.itemRefs.size(); ++index)
    {
        lua_getref(L, definition->second.itemRefs[index]);
        lua_rawseti(L, -2, static_cast<int>(index + 1));
    }
    return 1;
}

ValueHandle* checkedEnumType(lua_State* L)
{
    void* pointer = lua_touserdatatagged(L, 1, kValueTag);
    if (!pointer || static_cast<ValueHandle*>(pointer)->kind != ValueKind::EnumType)
        luaL_typeerror(L, 1, "Enum");
    return static_cast<ValueHandle*>(pointer);
}

int l_enum_from_name(lua_State* L)
{
    const ValueHandle* value = checkedEnumType(L);
    const std::string name = luaL_checkstring(L, 2);
    EngineState& engine = engineFor(L);
    const auto definition = engine.enums.find(value->text);
    if (definition != engine.enums.end())
    {
        const auto item = definition->second.itemLookup.find(name);
        if (item != definition->second.itemLookup.end() && item->second < definition->second.itemRefs.size())
        {
            lua_getref(L, definition->second.itemRefs[item->second]);
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}

int l_enum_from_value(lua_State* L)
{
    const ValueHandle* value = checkedEnumType(L);
    const int64_t wanted = luaL_checkinteger(L, 2);
    EngineState& engine = engineFor(L);
    const auto definition = engine.enums.find(value->text);
    if (definition != engine.enums.end())
    {
        for (const int ref : definition->second.itemRefs)
        {
            lua_getref(L, ref);
            const auto* item = static_cast<const ValueHandle*>(lua_touserdatatagged(L, -1, kValueTag));
            if (item && item->kind == ValueKind::EnumItem && item->integer == wanted)
                return 1;
            lua_pop(L, 1);
        }
    }
    lua_pushnil(L);
    return 1;
}

int l_enum_item_is_a(lua_State* L)
{
    void* pointer = lua_touserdatatagged(L, 1, kValueTag);
    if (!pointer || static_cast<ValueHandle*>(pointer)->kind != ValueKind::EnumItem)
        luaL_typeerror(L, 1, "EnumItem");
    const auto* value = static_cast<const ValueHandle*>(pointer);
    const std::string enumType = luaL_checkstring(L, 2);
    lua_pushboolean(L, value->enumName1 == enumType);
    return 1;
}

int l_value_index(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1);
    const std::string key = luaL_checkstring(L, 2);
    switch (value->kind)
    {
    case ValueKind::Enums:
    {
        EngineState& engine = engineFor(L);
        auto definition = engine.enums.find(key);
        if (definition != engine.enums.end() && definition->second.typeRef != LUA_NOREF)
        {
            lua_getref(L, definition->second.typeRef);
            return 1;
        }
        luaL_error(L, "%s is not a valid member of Enums", key.c_str());
    }
    case ValueKind::EnumType:
    {
        if (key == "GetEnumItems")
        {
            lua_pushcfunction(L, l_enum_get_items, "GetEnumItems");
            return 1;
        }
        if (key == "FromName")
        {
            lua_pushcfunction(L, l_enum_from_name, "FromName");
            return 1;
        }
        if (key == "FromValue")
        {
            lua_pushcfunction(L, l_enum_from_value, "FromValue");
            return 1;
        }
        EngineState& engine = engineFor(L);
        auto definition = engine.enums.find(value->text);
        if (definition != engine.enums.end())
        {
            auto item = definition->second.itemLookup.find(key);
            if (item != definition->second.itemLookup.end() && item->second < definition->second.itemRefs.size())
            {
                lua_getref(L, definition->second.itemRefs[item->second]);
                return 1;
            }
        }
        luaL_error(L, "%s is not a valid member of \"Enum.%s\"", key.c_str(), value->text.c_str());
    }
    case ValueKind::EnumItem:
        if (key == "Name") lua_pushlstring(L, value->text.data(), value->text.size());
        else if (key == "Value") lua_pushnumber(L, static_cast<double>(value->integer));
        else if (key == "IsA") lua_pushcfunction(L, l_enum_item_is_a, "IsA");
        else if (key == "EnumType")
        {
            EngineState& engine = engineFor(L);
            auto definition = engine.enums.find(value->enumName1);
            if (definition == engine.enums.end() || definition->second.typeRef == LUA_NOREF)
                luaL_error(L, "invalid EnumItem type");
            lua_getref(L, definition->second.typeRef);
        }
        else luaL_error(L, "%s is not a valid member of Enum.%s.%s", key.c_str(), value->enumName1.c_str(), value->text.c_str());
        return 1;
    case ValueKind::TweenInfo:
        if (key == "Time") lua_pushnumber(L, value->numbers[0]);
        else if (key == "EasingStyle") pushEnumItem(L, "EasingStyle", value->enumName1);
        else if (key == "EasingDirection") pushEnumItem(L, "EasingDirection", value->enumName2);
        else if (key == "RepeatCount") lua_pushnumber(L, static_cast<double>(value->integer));
        else if (key == "Reverses") lua_pushboolean(L, value->flags[0]);
        else if (key == "DelayTime") lua_pushnumber(L, value->numbers[1]);
        else luaL_error(L, "%s is not a valid member of TweenInfo", key.c_str());
        return 1;
    case ValueKind::RaycastParams:
    case ValueKind::OverlapParams:
        if (key == "FilterDescendantsInstances") pushInstanceList(L, value->instanceIds);
        else if (key == "FilterType") pushEnumItem(L, "RaycastFilterType", value->enumName1);
        else if (key == "CollisionGroup") lua_pushlstring(L, value->text.data(), value->text.size());
        else if (key == "RespectCanCollide") lua_pushboolean(L, value->flags[1]);
        else if (key == "BruteForceAllSlow") lua_pushboolean(L, value->flags[2]);
        else if (key == "IgnoreWater" && value->kind == ValueKind::RaycastParams) lua_pushboolean(L, value->flags[0]);
        else if (key == "MaxParts" && value->kind == ValueKind::OverlapParams) lua_pushnumber(L, static_cast<double>(value->integer));
        else if (key == "Tolerance" && value->kind == ValueKind::OverlapParams) lua_pushnumber(L, value->numbers[0]);
        else if (key == "AddToFilter") lua_pushcfunction(L, l_value_add_to_filter, "SpatialParams.AddToFilter");
        else luaL_error(L, "%s is not a valid member of %s", key.c_str(), valueTypeName(value->kind));
        return 1;
    case ValueKind::NumberRange:
        if (key == "Min") lua_pushnumber(L, value->numbers[0]);
        else if (key == "Max") lua_pushnumber(L, value->numbers[1]);
        else luaL_error(L, "%s is not a valid member of NumberRange", key.c_str());
        return 1;
    case ValueKind::NumberSequenceKeypoint:
        if (key == "Time") lua_pushnumber(L, value->numbers[0]);
        else if (key == "Value") lua_pushnumber(L, value->numbers[1]);
        else if (key == "Envelope") lua_pushnumber(L, value->numbers[2]);
        else luaL_error(L, "%s is not a valid member of NumberSequenceKeypoint", key.c_str());
        return 1;
    case ValueKind::NumberSequence:
        if (key != "Keypoints") luaL_error(L, "%s is not a valid member of NumberSequence", key.c_str());
        lua_createtable(L, static_cast<int>(value->numberPoints.size()), 0);
        for (size_t index = 0; index < value->numberPoints.size(); ++index)
        {
            pushNumberSequencePoint(L, value->numberPoints[index]);
            lua_rawseti(L, -2, static_cast<int>(index + 1));
        }
        lua_setreadonly(L, -1, true);
        return 1;
    case ValueKind::ColorSequenceKeypoint:
        if (key == "Time") lua_pushnumber(L, value->numbers[0]);
        else if (key == "Value") pushColor3(L, value->numbers[1], value->numbers[2], value->numbers[3]);
        else luaL_error(L, "%s is not a valid member of ColorSequenceKeypoint", key.c_str());
        return 1;
    case ValueKind::ColorSequence:
        if (key != "Keypoints") luaL_error(L, "%s is not a valid member of ColorSequence", key.c_str());
        lua_createtable(L, static_cast<int>(value->colorPoints.size()), 0);
        for (size_t index = 0; index < value->colorPoints.size(); ++index)
        {
            pushColorSequencePoint(L, value->colorPoints[index]);
            lua_rawseti(L, -2, static_cast<int>(index + 1));
        }
        lua_setreadonly(L, -1, true);
        return 1;
    case ValueKind::DateTime:
        if (key == "UnixTimestampMillis") lua_pushnumber(L, static_cast<double>(value->integer));
        else if (key == "UnixTimestamp") lua_pushnumber(L, std::floor(static_cast<double>(value->integer) / 1000.0));
        else if (key == "ToUnixTimestamp") lua_pushcfunction(L, l_datetime_to_unix, "DateTime.ToUnixTimestamp");
        else if (key == "ToUnixTimestampMillis") lua_pushcfunction(L, l_datetime_to_unix_millis, "DateTime.ToUnixTimestampMillis");
        else if (key == "ToIsoDate") lua_pushcfunction(L, l_datetime_to_iso, "DateTime.ToIsoDate");
        else luaL_error(L, "%s is not a valid member of DateTime", key.c_str());
        return 1;
    case ValueKind::Random:
        if (key == "Clone") lua_pushcfunction(L, l_random_clone, "Clone");
        else if (key == "NextInteger") lua_pushcfunction(L, l_random_next_integer, "NextInteger");
        else if (key == "NextNumber") lua_pushcfunction(L, l_random_next_number, "NextNumber");
        else if (key == "NextUnitVector") lua_pushcfunction(L, l_random_next_unit_vector, "NextUnitVector");
        else if (key == "Shuffle") lua_pushcfunction(L, l_random_shuffle, "Shuffle");
        else luaL_error(L, "%s is not a valid member of Random", key.c_str());
        return 1;
    }
    return 0;
}

int l_value_newindex(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1);
    const std::string key = luaL_checkstring(L, 2);
    if (value->kind != ValueKind::RaycastParams && value->kind != ValueKind::OverlapParams)
        luaL_error(L, "%s.%s is read only", valueTypeName(value->kind), key.c_str());

    if (key == "FilterDescendantsInstances")
        value->instanceIds = checkedInstanceList(L, 3);
    else if (key == "FilterType")
    {
        std::string item;
        if (!readEnumItem(L, 3, "RaycastFilterType", item))
            luaL_typeerror(L, 3, "Enum.RaycastFilterType");
        value->enumName1 = std::move(item);
    }
    else if (key == "CollisionGroup")
    {
        size_t length = 0;
        const char* group = luaL_checklstring(L, 3, &length);
        value->text.assign(group, length);
    }
    else if (key == "RespectCanCollide")
    {
        luaL_checktype(L, 3, LUA_TBOOLEAN);
        value->flags[1] = lua_toboolean(L, 3) != 0;
    }
    else if (key == "BruteForceAllSlow")
    {
        luaL_checktype(L, 3, LUA_TBOOLEAN);
        value->flags[2] = lua_toboolean(L, 3) != 0;
    }
    else if (key == "IgnoreWater" && value->kind == ValueKind::RaycastParams)
    {
        luaL_checktype(L, 3, LUA_TBOOLEAN);
        value->flags[0] = lua_toboolean(L, 3) != 0;
    }
    else if (key == "MaxParts" && value->kind == ValueKind::OverlapParams)
    {
        const double maximumValue = luaL_checknumber(L, 3);
        if (!std::isfinite(maximumValue) || std::floor(maximumValue) != maximumValue || maximumValue < 0 ||
            maximumValue > static_cast<double>(INT64_MAX))
            luaL_error(L, "OverlapParams.MaxParts must be non-negative");
        value->integer = static_cast<int64_t>(maximumValue);
    }
    else if (key == "Tolerance" && value->kind == ValueKind::OverlapParams)
        value->numbers[0] = std::clamp(luaL_checknumber(L, 3), 0.0, 0.05);
    else
        luaL_error(L, "%s is not a valid member of %s", key.c_str(), valueTypeName(value->kind));
    return 0;
}

int l_value_tostring(lua_State* L)
{
    ValueHandle* value = valueFor(L, 1);
    if (value->kind == ValueKind::EnumType)
    {
        lua_pushlstring(L, value->text.data(), value->text.size());
    }
    else if (value->kind == ValueKind::EnumItem)
    {
        const std::string result = "Enum." + value->enumName1 + "." + value->text;
        lua_pushlstring(L, result.data(), result.size());
    }
    else if (value->kind == ValueKind::NumberRange)
    {
        const std::string result = formatValueNumber(value->numbers[0]) + " " + formatValueNumber(value->numbers[1]);
        lua_pushlstring(L, result.data(), result.size());
    }
    else
        lua_pushstring(L, valueTypeName(value->kind));
    return 1;
}

int l_value_equal(lua_State* L)
{
    ValueHandle* left = valueFor(L, 1);
    ValueHandle* right = valueFor(L, 2);
    if (left->kind != right->kind)
    {
        lua_pushboolean(L, false);
        return 1;
    }
    bool equal = false;
    switch (left->kind)
    {
    case ValueKind::Enums:
    case ValueKind::EnumType:
    case ValueKind::EnumItem:
        equal = left == right;
        break;
    case ValueKind::TweenInfo:
        equal = left->numbers == right->numbers && left->integer == right->integer && left->flags == right->flags &&
            left->enumName1 == right->enumName1 && left->enumName2 == right->enumName2;
        break;
    case ValueKind::RaycastParams:
    case ValueKind::OverlapParams:
        equal = left == right;
        break;
    case ValueKind::NumberRange:
        equal = left->numbers[0] == right->numbers[0] && left->numbers[1] == right->numbers[1];
        break;
    case ValueKind::NumberSequenceKeypoint:
        equal = left->numbers[0] == right->numbers[0] && left->numbers[1] == right->numbers[1] && left->numbers[2] == right->numbers[2];
        break;
    case ValueKind::NumberSequence:
        equal = sameNumberPoints(left->numberPoints, right->numberPoints);
        break;
    case ValueKind::ColorSequenceKeypoint:
        equal = left->numbers[0] == right->numbers[0] && left->numbers[1] == right->numbers[1] && left->numbers[2] == right->numbers[2] &&
            left->numbers[3] == right->numbers[3];
        break;
    case ValueKind::ColorSequence:
        equal = sameColorPoints(left->colorPoints, right->colorPoints);
        break;
    case ValueKind::DateTime:
        equal = left->integer == right->integer;
        break;
    case ValueKind::Random:
        equal = left == right;
        break;
    }
    lua_pushboolean(L, equal);
    return 1;
}

int l_value_enum_type_new(lua_State* L)
{
    size_t nameLength = 0;
    const char* nameData = luaL_checklstring(L, 1, &nameLength);
    std::string name(nameData, nameLength);
    if (name.empty())
        luaL_error(L, "Enum type name cannot be empty");
    EngineState& engine = engineFor(L);
    if (engine.enums.count(name))
        luaL_error(L, "duplicate Enum type %s", name.c_str());

    ValueHandle* value = pushValue(L, ValueKind::EnumType);
    value->text = name;
    EnumDefinition definition;
    definition.typeRef = lua_ref(L, -1);
    engine.enums.emplace(std::move(name), std::move(definition));
    return 1;
}

int l_value_enums_new(lua_State* L)
{
    (void)engineFor(L);
    pushValue(L, ValueKind::Enums);
    return 1;
}

int l_value_enum_item_new(lua_State* L)
{
    ValueHandle* enumType = valueFor(L, 1, ValueKind::EnumType);
    size_t nameLength = 0;
    const char* nameData = luaL_checklstring(L, 2, &nameLength);
    std::string name(nameData, nameLength);
    const double numericValue = luaL_checknumber(L, 3);
    if (name.empty())
        luaL_error(L, "Enum item name cannot be empty");
    if (!std::isfinite(numericValue) || std::floor(numericValue) != numericValue || numericValue < static_cast<double>(INT64_MIN) ||
        numericValue > static_cast<double>(INT64_MAX))
        luaL_error(L, "Enum item value must be an integer");

    EngineState& engine = engineFor(L);
    auto definition = engine.enums.find(enumType->text);
    if (definition == engine.enums.end())
        luaL_error(L, "Enum type is not registered");
    if (definition->second.itemLookup.count(name))
        luaL_error(L, "duplicate Enum item %s.%s", enumType->text.c_str(), name.c_str());

    std::vector<std::string> aliases;
    if (!lua_isnoneornil(L, 4))
    {
        luaL_checktype(L, 4, LUA_TTABLE);
        const int count = lua_objlen(L, 4);
        aliases.reserve(static_cast<size_t>(std::max(0, count)));
        for (int index = 1; index <= count; ++index)
        {
            lua_rawgeti(L, 4, index);
            size_t aliasLength = 0;
            const char* aliasData = luaL_checklstring(L, -1, &aliasLength);
            std::string alias(aliasData, aliasLength);
            lua_pop(L, 1);
            if (alias.empty())
                luaL_error(L, "Enum legacy name cannot be empty");
            auto existing = definition->second.itemLookup.find(alias);
            if (existing != definition->second.itemLookup.end())
                luaL_error(L, "duplicate Enum legacy name %s.%s", enumType->text.c_str(), alias.c_str());
            if (alias != name && std::find(aliases.begin(), aliases.end(), alias) == aliases.end())
                aliases.push_back(std::move(alias));
        }
    }

    ValueHandle* value = pushValue(L, ValueKind::EnumItem);
    value->text = name;
    value->enumName1 = enumType->text;
    value->integer = static_cast<int64_t>(numericValue);
    const size_t itemIndex = definition->second.itemRefs.size();
    definition->second.itemRefs.push_back(lua_ref(L, -1));
    definition->second.itemLookup.emplace(std::move(name), itemIndex);
    for (std::string& alias : aliases)
        definition->second.itemLookup.emplace(std::move(alias), itemIndex);
    return 1;
}

int l_value_tween_info_new(lua_State* L)
{
    const double time = luaL_optnumber(L, 1, 1.0);
    const double repeatValue = luaL_optnumber(L, 4, 0);
    if (!std::isfinite(repeatValue) || std::floor(repeatValue) != repeatValue || repeatValue < -1 || repeatValue > static_cast<double>(INT64_MAX))
        luaL_error(L, "TweenInfo repeatCount must be an integer of -1 or greater");
    const int64_t repeatCount = static_cast<int64_t>(repeatValue);
    const double delayTime = luaL_optnumber(L, 6, 0.0);
    if (!std::isfinite(time) || time < 0)
        luaL_error(L, "TweenInfo time must be a finite non-negative number");
    if (!std::isfinite(delayTime) || delayTime < 0)
        luaL_error(L, "TweenInfo delayTime must be a finite non-negative number");

    std::string easingStyle = "Quad";
    std::string easingDirection = "Out";
    if (!lua_isnoneornil(L, 2) && !readEnumItem(L, 2, "EasingStyle", easingStyle))
        luaL_typeerror(L, 2, "Enum.EasingStyle");
    if (!lua_isnoneornil(L, 3) && !readEnumItem(L, 3, "EasingDirection", easingDirection))
        luaL_typeerror(L, 3, "Enum.EasingDirection");
    if (!lua_isnoneornil(L, 5))
        luaL_checktype(L, 5, LUA_TBOOLEAN);

    ValueHandle* value = pushValue(L, ValueKind::TweenInfo);
    value->numbers[0] = time;
    value->numbers[1] = delayTime;
    value->integer = repeatCount;
    value->flags[0] = !lua_isnoneornil(L, 5) && lua_toboolean(L, 5) != 0;
    value->enumName1 = std::move(easingStyle);
    value->enumName2 = std::move(easingDirection);
    return 1;
}

int l_value_raycast_params_new(lua_State* L)
{
    if (lua_gettop(L) != 0)
        luaL_error(L, "RaycastParams.new expects no arguments");
    ValueHandle* value = pushValue(L, ValueKind::RaycastParams);
    value->text = "Default";
    value->enumName1 = "Exclude";
    return 1;
}

int l_value_overlap_params_new(lua_State* L)
{
    if (lua_gettop(L) != 0)
        luaL_error(L, "OverlapParams.new expects no arguments");
    ValueHandle* value = pushValue(L, ValueKind::OverlapParams);
    value->text = "Default";
    value->enumName1 = "Exclude";
    return 1;
}

int l_value_number_range_new(lua_State* L)
{
    const double minimum = luaL_checknumber(L, 1);
    const double maximum = lua_isnoneornil(L, 2) ? minimum : luaL_checknumber(L, 2);
    if (!std::isfinite(minimum) || !std::isfinite(maximum))
        luaL_error(L, "NumberRange values must be finite");
    if (maximum < minimum)
        luaL_error(L, "NumberRange: invalid range");
    ValueHandle* value = pushValue(L, ValueKind::NumberRange);
    value->numbers[0] = minimum;
    value->numbers[1] = maximum;
    return 1;
}

int l_value_number_keypoint_new(lua_State* L)
{
    const double time = luaL_checknumber(L, 1);
    const double number = luaL_checknumber(L, 2);
    const double envelope = luaL_optnumber(L, 3, 0.0);
    if (!std::isfinite(time) || time < 0 || time > 1)
        luaL_error(L, "NumberSequenceKeypoint time must be between 0 and 1");
    if (!std::isfinite(number) || !std::isfinite(envelope) || envelope < 0)
        luaL_error(L, "NumberSequenceKeypoint value and envelope must be finite, with a non-negative envelope");
    ValueHandle* value = pushValue(L, ValueKind::NumberSequenceKeypoint);
    value->numbers[0] = time;
    value->numbers[1] = number;
    value->numbers[2] = envelope;
    return 1;
}

void validateNumberSequence(lua_State* L, const std::vector<NumberSequencePoint>& points)
{
    if (points.size() < 2 || points.front().time != 0 || points.back().time != 1)
        luaL_error(L, "NumberSequence requires at least two keypoints beginning at 0 and ending at 1");
    for (size_t index = 1; index < points.size(); ++index)
        if (points[index].time < points[index - 1].time)
            luaL_error(L, "NumberSequence keypoints must be in non-descending time order");
}

int l_value_number_sequence_new(lua_State* L)
{
    std::vector<NumberSequencePoint> points;
    if (lua_istable(L, 1))
    {
        const int count = lua_objlen(L, 1);
        points.reserve(static_cast<size_t>(std::max(0, count)));
        for (int index = 1; index <= count; ++index)
        {
            lua_rawgeti(L, 1, index);
            ValueHandle* point = valueFor(L, -1, ValueKind::NumberSequenceKeypoint);
            points.push_back({point->numbers[0], point->numbers[1], point->numbers[2]});
            lua_pop(L, 1);
        }
    }
    else
    {
        const double first = luaL_checknumber(L, 1);
        const double second = lua_isnoneornil(L, 2) ? first : luaL_checknumber(L, 2);
        if (!std::isfinite(first) || !std::isfinite(second))
            luaL_error(L, "NumberSequence values must be finite");
        points = {{0, first, 0}, {1, second, 0}};
    }
    validateNumberSequence(L, points);
    ValueHandle* value = pushValue(L, ValueKind::NumberSequence);
    value->numberPoints = std::move(points);
    return 1;
}

int l_value_color_keypoint_new(lua_State* L)
{
    const double time = luaL_checknumber(L, 1);
    if (!std::isfinite(time) || time < 0 || time > 1)
        luaL_error(L, "ColorSequenceKeypoint time must be between 0 and 1");
    double red = 0;
    double green = 0;
    double blue = 0;
    if (!readColor3(L, 2, red, green, blue))
        luaL_typeerror(L, 2, "Color3");
    ValueHandle* value = pushValue(L, ValueKind::ColorSequenceKeypoint);
    value->numbers[0] = time;
    value->numbers[1] = red;
    value->numbers[2] = green;
    value->numbers[3] = blue;
    return 1;
}

void validateColorSequence(lua_State* L, const std::vector<ColorSequencePoint>& points)
{
    if (points.size() < 2 || points.front().time != 0 || points.back().time != 1)
        luaL_error(L, "ColorSequence requires at least two keypoints beginning at 0 and ending at 1");
    for (size_t index = 1; index < points.size(); ++index)
        if (points[index].time < points[index - 1].time)
            luaL_error(L, "ColorSequence keypoints must be in non-descending time order");
}

int l_value_color_sequence_new(lua_State* L)
{
    std::vector<ColorSequencePoint> points;
    if (lua_istable(L, 1))
    {
        const int count = lua_objlen(L, 1);
        points.reserve(static_cast<size_t>(std::max(0, count)));
        for (int index = 1; index <= count; ++index)
        {
            lua_rawgeti(L, 1, index);
            ValueHandle* point = valueFor(L, -1, ValueKind::ColorSequenceKeypoint);
            points.push_back({point->numbers[0], point->numbers[1], point->numbers[2], point->numbers[3]});
            lua_pop(L, 1);
        }
    }
    else
    {
        double firstRed = 0;
        double firstGreen = 0;
        double firstBlue = 0;
        if (!readColor3(L, 1, firstRed, firstGreen, firstBlue))
            luaL_typeerror(L, 1, "Color3");
        double secondRed = firstRed;
        double secondGreen = firstGreen;
        double secondBlue = firstBlue;
        if (!lua_isnoneornil(L, 2) && !readColor3(L, 2, secondRed, secondGreen, secondBlue))
            luaL_typeerror(L, 2, "Color3");
        points = {{0, firstRed, firstGreen, firstBlue}, {1, secondRed, secondGreen, secondBlue}};
    }
    validateColorSequence(L, points);
    ValueHandle* value = pushValue(L, ValueKind::ColorSequence);
    value->colorPoints = std::move(points);
    return 1;
}

int l_value_datetime_new_millis(lua_State* L)
{
    const double millis = luaL_checknumber(L, 1);
    if (!std::isfinite(millis) || millis < static_cast<double>(INT64_MIN) || millis > static_cast<double>(INT64_MAX))
        luaL_error(L, "DateTime timestamp is outside the supported range");
    ValueHandle* value = pushValue(L, ValueKind::DateTime);
    value->integer = static_cast<int64_t>(std::floor(millis));
    return 1;
}

void registerValueMetatable(lua_State* L, ValueKind kind)
{
    static const luaL_Reg methods[] = {
        {"__index", l_value_index},
        {"__newindex", l_value_newindex},
        {"__tostring", l_value_tostring},
        {"__eq", l_value_equal},
        {nullptr, nullptr},
    };
    const std::string metatable = valueMetatableName(kind);
    luaL_newmetatable(L, metatable.c_str());
    luaL_register(L, nullptr, methods);
    lua_pushstring(L, valueTypeName(kind));
    lua_rawsetfield(L, -2, "__type");
    lua_pushliteral(L, "The metatable is locked");
    lua_rawsetfield(L, -2, "__metatable");
    lua_pop(L, 1);
}

void registerValueTypes(lua_State* L)
{
    for (ValueKind kind : {ValueKind::Enums, ValueKind::EnumType, ValueKind::EnumItem, ValueKind::TweenInfo, ValueKind::RaycastParams, ValueKind::OverlapParams,
             ValueKind::NumberRange,
             ValueKind::NumberSequenceKeypoint, ValueKind::NumberSequence, ValueKind::ColorSequenceKeypoint, ValueKind::ColorSequence,
             ValueKind::DateTime, ValueKind::Random})
        registerValueMetatable(L, kind);
    lua_setuserdatadtor(L, kValueTag, destroyValueHandle);
}

void parseReflection(EngineState& engine, std::string_view source)
{
    engine.reflection.load(source);
}

} // namespace

void initialize(lua_State* L, std::string_view apiDumpJson, const EngineOptions& options)
{
    rbx::runtime::RuntimeContext& context = contextFor(L);
    context.removeSubsystem(kEngineSubsystemKey);
    EngineState& engine = context.emplaceSubsystem<EngineState>(std::string(kEngineSubsystemKey));
    engine.L = mainStateFor(L);
    engine.strictUnsupported = options.strictUnsupported;
    engine.executorExtensions = options.executorExtensions;
    lua_newtable(L);
    lua_newtable(L);
    lua_pushliteral(L, "v");
    lua_rawsetfield(L, -2, "__mode");
    lua_setmetatable(L, -2);
    engine.weakInstancesRef = lua_ref(L, -1);
    lua_pop(L, 1);
    try
    {
        parseReflection(engine, apiDumpJson);
    }
    catch (...)
    {
        context.removeSubsystem(kEngineSubsystemKey);
        throw;
    }
    engine.reflection.markSupport("Object", "ClassName", Support::Implemented);
    engine.reflection.markSupport("Instance", "Name", Support::Implemented);
    engine.reflection.markSupport("Instance", "Parent", Support::Implemented);
    engine.reflection.markSupport("Instance", "Archivable", Support::Implemented);

    static const luaL_Reg instanceMeta[] = {
        {"__index", l_instance_index},
        {"__newindex", l_instance_newindex},
        {"__tostring", l_instance_tostring},
        {nullptr, nullptr},
    };
    luaL_newmetatable(L, "RBXInstanceV2");
    luaL_register(L, nullptr, instanceMeta);
    lua_pushliteral(L, "The metatable is locked");
    lua_rawsetfield(L, -2, "__metatable");
    lua_pushliteral(L, "Instance");
    lua_rawsetfield(L, -2, "__type");
    lua_pushvalue(L, -1);
    lua_setuserdatametatable(L, kInstanceTag);
    lua_setreadonly(L, -1, 1);
    lua_pop(L, 1);
    lua_setuserdatadtor(L, kInstanceTag, destroyInstanceHandle);
    registerValueTypes(L);

    static const luaL_Reg globals[] = {
        {"__rbx_instance_new", l_instance_new},
        {"__rbx_instance_bind_public_new", l_instance_bind_public_new},
        {"__rbx_instance_bind_public_from_existing", l_instance_bind_public_from_existing},
        {"__rbx_executor_bind_native", l_executor_bind_native},
        {"__rbx_instance_bind_native", l_instance_bind_native},
        {"__rbx_instance_children", l_instance_children},
        {"__rbx_instance_find", l_instance_find},
        {"__rbx_instance_is_a", l_instance_is_a},
        {"__rbx_instance_destroy", l_instance_destroy},
        {"__rbx_instance_set_parent", l_instance_set_parent},
        {"__rbx_instance_property_signal", l_instance_get_property_signal},
        {"__rbx_instance_get_attribute", l_instance_get_attribute},
        {"__rbx_instance_internal_property", l_instance_internal_property},
        {"__rbx_instance_set_default", l_instance_set_default},
        {"__rbx_instance_set_gui_geometry_resolver", l_instance_set_gui_geometry_resolver},
        {"__rbx_instance_get_attributes", l_instance_get_attributes},
        {"__rbx_instance_set_attribute", l_instance_set_attribute},
        {"__rbx_instance_attribute_signal", l_instance_get_attribute_signal},
        {"__rbx_instance_tags", l_instance_tags},
        {"__rbx_instance_tagged", l_instance_tagged},
        {"__rbx_instance_clone", l_instance_clone},
        {"__rbx_instance_full_name", l_instance_full_name},
        {"__rbx_value_enums_new", l_value_enums_new},
        {"__rbx_value_enum_type_new", l_value_enum_type_new},
        {"__rbx_value_enum_item_new", l_value_enum_item_new},
        {"__rbx_value_tween_info_new", l_value_tween_info_new},
        {"__rbx_value_raycast_params_new", l_value_raycast_params_new},
        {"__rbx_value_overlap_params_new", l_value_overlap_params_new},
        {"__rbx_value_number_range_new", l_value_number_range_new},
        {"__rbx_value_number_keypoint_new", l_value_number_keypoint_new},
        {"__rbx_value_number_sequence_new", l_value_number_sequence_new},
        {"__rbx_value_color_keypoint_new", l_value_color_keypoint_new},
        {"__rbx_value_color_sequence_new", l_value_color_sequence_new},
        {"__rbx_value_datetime_new_millis", l_value_datetime_new_millis},
        {"__rbx_value_random_bind_new", l_random_bind_public_new},
        {nullptr, nullptr},
    };
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    luaL_register(L, nullptr, globals);
    lua_pop(L, 1);
    lua_pushcclosurek(L, l_instance_wait_for_child, "WaitForChild", 0, l_instance_wait_for_child_continue);
    lua_setglobal(L, "__rbx_instance_wait_for_child");
}

void shutdown(lua_State* L)
{
    rbx::runtime::RuntimeContext& context = contextFor(L);
    (void)findEngineFor(L);
    context.removeSubsystem(kEngineSubsystemKey);
}

void seal(lua_State* L)
{
    EngineState& engine = engineFor(L);
    auto capture = [L](const char* name) {
        lua_getglobal(L, name);
        int ref = lua_isnil(L, -1) ? LUA_NOREF : lua_ref(L, -1);
        lua_pop(L, 1);
        return ref;
    };
    auto captureField = [L](const char* tableName, const char* fieldName) {
        int ref = LUA_NOREF;
        lua_getglobal(L, tableName);
        if (lua_istable(L, -1))
        {
            lua_getfield(L, -1, fieldName);
            if (lua_isfunction(L, -1))
                ref = lua_ref(L, -1);
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
        return ref;
    };
    engine.methodsRef = capture("__rbx_instance_methods");
    engine.classMethodsRef = capture("__rbx_class_methods");
    engine.signalFactoryRef = capture("__rbx_make_signal");
    engine.signalFireRef = capture("__rbx_native_signal_fire");
    engine.signalDisconnectRef = capture("__rbx_native_signal_disconnect_all");
    engine.tagChangedRef = capture("__rbx_collection_tag_changed");
    engine.traceRef = capture("__rbx_trace_compat");
    engine.executeRef = capture("__rbx_execute");
    engine.schedulerReportRef = capture("__rbx_scheduler_report");
    engine.vector3NewRef = captureField("Vector3", "new");
    if (engine.classMethodsRef != LUA_NOREF)
    {
        int top = lua_gettop(L);
        lua_getref(L, engine.classMethodsRef);
        int registryIndex = lua_absindex(L, -1);
        lua_pushnil(L);
        while (lua_next(L, registryIndex) != 0)
        {
            if (lua_isstring(L, -2) && lua_istable(L, -1))
            {
                std::string className = lua_tostring(L, -2);
                int methodsIndex = lua_absindex(L, -1);
                lua_pushnil(L);
                while (lua_next(L, methodsIndex) != 0)
                {
                    if (lua_isstring(L, -2) && lua_isfunction(L, -1))
                        engine.reflection.markSupport(className, lua_tostring(L, -2), Support::Implemented);
                    lua_pop(L, 1);
                }
            }
            lua_pop(L, 1);
        }
        lua_settop(L, top);
    }
    for (const char* name : {"__rbx_instance_bind_public_new", "__rbx_instance_bind_public_from_existing", "__rbx_executor_bind_native", "__rbx_instance_bind_native", "__rbx_instance_wait_for_child", "__rbx_instance_internal_property", "__rbx_instance_set_default", "__rbx_instance_set_gui_geometry_resolver", "__rbx_instance_tagged", "__rbx_class_methods",
             "__rbx_collection_tag_changed", "__rbx_native_module_declare", "__rbx_native_module_require", "__rbx_native_module_finish",
             "__rbx_native_runservice_configure", "__rbx_native_runservice_set_binding_count",
             "__rbx_native_signal_new", "__rbx_native_signal_fire", "__rbx_native_signal_disconnect_all",
             "__rbx_native_http_request", "__rbx_value_enums_new", "__rbx_value_enum_type_new", "__rbx_value_enum_item_new", "__rbx_value_tween_info_new",
             "__rbx_value_raycast_params_new", "__rbx_value_overlap_params_new",
             "__rbx_value_number_range_new", "__rbx_value_number_keypoint_new", "__rbx_value_number_sequence_new",
             "__rbx_value_color_keypoint_new", "__rbx_value_color_sequence_new", "__rbx_value_datetime_new_millis",
             "__rbx_value_random_bind_new"})
    {
        lua_pushnil(L);
        lua_setglobal(L, name);
    }
    engine.bootstrapping = false;
}

bool pushExecute(lua_State* L)
{
    EngineState* engine = findEngineFor(L);
    if (!engine || engine->executeRef == LUA_NOREF)
        return false;
    lua_getref(L, engine->executeRef);
    return lua_isfunction(L, -1);
}

bool pushSchedulerReport(lua_State* L)
{
    EngineState* engine = findEngineFor(L);
    if (!engine || engine->schedulerReportRef == LUA_NOREF)
        return false;
    lua_getref(L, engine->schedulerReportRef);
    return lua_isfunction(L, -1);
}

DataModelSnapshot inspectDataModel(lua_State* L)
{
    DataModelSnapshot snapshot;
    snapshot.engineRelease = std::string(runtime::kEngineRelease);
    snapshot.apiHash = std::string(runtime::kFullApiSha256);
    if (!L)
    {
        snapshot.inspectionErrors.push_back("Lua state is null");
        return snapshot;
    }

    const int top = lua_gettop(L);
    try
    {
        EngineState* engine = findEngineFor(L);
        if (!engine)
        {
            snapshot.inspectionErrors.push_back("runtime v2 engine is not initialized");
            return snapshot;
        }

        snapshot.engineInitialized = true;
        snapshot.engineSealed = !engine->bootstrapping;
        snapshot.reflectionVersion = engine->reflection.stats().value("version", "");

        auto registryNodeAt = [&](int index, bool& native, bool& identity) -> InstanceNode* {
            native = lua_isuserdata(L, index) && lua_userdatatag(L, index) == kInstanceTag;
            if (!native)
                return nullptr;
            auto* handle = static_cast<InstanceHandle*>(lua_touserdatatagged(L, index, kInstanceTag));
            if (!handle)
                return nullptr;
            auto found = engine->nodes.find(handle->id);
            if (found == engine->nodes.end() || found->second->handle != handle)
                return nullptr;
            InstanceNode* node = found->second.get();
            if (node->objectRef == LUA_NOREF)
                return node;
            lua_getref(L, node->objectRef);
            identity = lua_rawequal(L, index, -1) != 0;
            lua_pop(L, 1);
            return node;
        };

        auto readIntegerProperty = [&](InstanceNode& node, const char* name) -> std::optional<int64_t> {
            pushState(L, node);
            lua_rawgetfield(L, -1, name);
            std::optional<int64_t> result;
            if (lua_isnumber(L, -1))
            {
                const double value = lua_tonumber(L, -1);
                if (std::isfinite(value) && std::floor(value) == value &&
                    value >= static_cast<double>(std::numeric_limits<int64_t>::min()) &&
                    value <= static_cast<double>(std::numeric_limits<int64_t>::max()))
                    result = static_cast<int64_t>(value);
            }
            lua_pop(L, 2);
            return result;
        };

        auto readStringProperty = [&](InstanceNode& node, const char* name) -> std::optional<std::string> {
            pushState(L, node);
            lua_rawgetfield(L, -1, name);
            std::optional<std::string> result;
            if (lua_isstring(L, -1))
            {
                size_t length = 0;
                const char* value = lua_tolstring(L, -1, &length);
                result = std::string(value, length);
            }
            lua_pop(L, 2);
            return result;
        };

        lua_getglobal(L, "game");
        const int gameIndex = lua_absindex(L, -1);
        snapshot.gameGlobalPresent = !lua_isnil(L, gameIndex);
        InstanceNode* gameNode = registryNodeAt(gameIndex, snapshot.gameIsNativeInstance, snapshot.gameRegistryIdentityValid);
        if (gameNode)
        {
            snapshot.gameInstanceId = gameNode->id;
            snapshot.gameParentId = gameNode->parent;
            snapshot.gameClassName = gameNode->className;
            snapshot.gameName = gameNode->name;
            snapshot.gameDestroyed = gameNode->destroyed || (gameNode->handle && gameNode->handle->destroyed);
            snapshot.placeId = readIntegerProperty(*gameNode, "PlaceId");
            snapshot.gameId = readIntegerProperty(*gameNode, "GameId");
            snapshot.placeVersion = readIntegerProperty(*gameNode, "PlaceVersion");
            snapshot.jobId = readStringProperty(*gameNode, "JobId");

            for (uint64_t childId : gameNode->children)
            {
                auto found = engine->nodes.find(childId);
                if (found == engine->nodes.end())
                    continue;
                const InstanceNode& child = *found->second;
                bool objectValid = false;
                if (child.objectRef != LUA_NOREF)
                {
                    lua_getref(L, child.objectRef);
                    auto* handle = static_cast<InstanceHandle*>(lua_touserdatatagged(L, -1, kInstanceTag));
                    objectValid = handle && handle == child.handle && handle->id == child.id;
                    lua_pop(L, 1);
                }
                const ClassDescriptor* descriptor = engine->reflection.findClass(child.className);
                snapshot.directChildren.push_back({
                    child.id,
                    child.parent,
                    child.className,
                    child.name,
                    descriptor && descriptor->tags.count("Service") != 0,
                    child.destroyed || (child.handle && child.handle->destroyed),
                    objectValid,
                });
            }
            std::sort(snapshot.directChildren.begin(), snapshot.directChildren.end(), [](const auto& left, const auto& right) {
                if (left.className != right.className)
                    return left.className < right.className;
                return left.instanceId < right.instanceId;
            });
        }
        else if (snapshot.gameGlobalPresent)
            snapshot.inspectionErrors.push_back("game is not owned by the native Instance registry");
        lua_pop(L, 1);

        lua_getglobal(L, "workspace");
        const int workspaceIndex = lua_absindex(L, -1);
        snapshot.workspaceGlobalPresent = !lua_isnil(L, workspaceIndex);
        InstanceNode* workspaceNode = registryNodeAt(
            workspaceIndex, snapshot.workspaceIsNativeInstance, snapshot.workspaceRegistryIdentityValid);
        if (workspaceNode)
        {
            snapshot.workspaceInstanceId = workspaceNode->id;
            snapshot.workspaceParentId = workspaceNode->parent;
            snapshot.workspaceClassName = workspaceNode->className;
            snapshot.workspaceDestroyed = workspaceNode->destroyed || (workspaceNode->handle && workspaceNode->handle->destroyed);
        }
        lua_getglobal(L, "Workspace");
        snapshot.workspaceAliasIdentityValid = !lua_isnil(L, workspaceIndex) && lua_rawequal(L, workspaceIndex, -1) != 0;
        lua_pop(L, 2);
    }
    catch (const std::exception& error)
    {
        snapshot.inspectionErrors.push_back(error.what());
    }
    lua_settop(L, top);
    return snapshot;
}

std::string engineStatsJson(lua_State* L)
{
    EngineState* engine = findEngineFor(L);
    if (!engine)
    {
        reflection::Database emptyReflection;
        return json{
            {"classes", 0},
            {"instances", 0},
            {"live_instances", 0},
            {"destroyed_instances", 0},
            {"created_instances", 0},
            {"instance_registry_nodes", 0},
            {"instance_object_refs", 0},
            {"instance_state_refs", 0},
            {"released_object_refs", 0},
            {"released_state_refs", 0},
            {"retained_destroyed_instances", 0},
            {"method_registry_ready", false},
            {"class_method_registry_ready", false},
            {"reflection", emptyReflection.stats()},
        }.dump();
    }
    size_t objectRefs = 0;
    size_t stateRefs = 0;
    size_t liveInstances = 0;
    size_t retainedDestroyedInstances = 0;
    for (const auto& [_, node] : engine->nodes)
    {
        if (node->objectRef != LUA_NOREF)
            ++objectRefs;
        if (node->stateRef != LUA_NOREF)
            ++stateRefs;
        if (node->destroyed)
            ++retainedDestroyedInstances;
        else
            ++liveInstances;
    }
    return json{
        {"classes", engine->reflection.classCount()},
        {"instances", liveInstances},
        {"live_instances", liveInstances},
        {"destroyed_instances", engine->destroyedInstances},
        {"created_instances", engine->nextId - 1},
        {"instance_registry_nodes", engine->nodes.size()},
        {"instance_object_refs", objectRefs},
        {"instance_state_refs", stateRefs},
        {"released_object_refs", engine->releasedObjectRefs},
        {"released_state_refs", engine->releasedStateRefs},
        {"retained_destroyed_instances", retainedDestroyedInstances},
        {"method_registry_ready", engine->methodsRef != LUA_NOREF},
        {"class_method_registry_ready", engine->classMethodsRef != LUA_NOREF},
        {"reflection", engine->reflection.stats()},
    }.dump();
}

bool isInstance(lua_State* L, int index)
{
    (void)engineFor(L);
    return lua_isuserdata(L, index) && lua_userdatatag(L, index) == kInstanceTag;
}

std::string instanceClassName(lua_State* L, int index)
{
    if (!isInstance(L, index))
        return {};
    InstanceHandle* handle = static_cast<InstanceHandle*>(lua_touserdatatagged(L, index, kInstanceTag));
    return handle->className;
}

bool enumItemName(lua_State* L, int index, std::string_view expectedType, std::string& itemName)
{
    return readEnumItem(L, index, expectedType, itemName);
}

const char* shimSource()
{
    return R"RBXV2(
local __host = {
    runtimeConfig = __rbx_runtime_config,
    apiDump = __rbx_api_dump_json,
    scenario = __rbx_scenario_json,
    jsonEncode = __rbx_json_encode,
    jsonDecode = __rbx_json_decode,
    urlEncode = __rbx_url_encode,
    urlDecode = __rbx_url_decode,
    generateGuid = __rbx_generate_guid,
    httpGet = __rbx_httpget,
    httpPost = __rbx_httppost,
    httpRequest = __rbx_http_request,
    elapsed = __rbx_elapsed_time,
    wallTime = __rbx_wall_time,
    trace = __rbx_trace_compat,
    instanceNew = __rbx_instance_new,
    instanceBindPublicNew = __rbx_instance_bind_public_new,
    instanceBindPublicFromExisting = __rbx_instance_bind_public_from_existing,
    executorBindNative = __rbx_executor_bind_native,
    instanceBindNative = __rbx_instance_bind_native,
    instanceWaitForChild = __rbx_instance_wait_for_child,
    instanceChildren = __rbx_instance_children,
    instanceFind = __rbx_instance_find,
    instanceIsA = __rbx_instance_is_a,
    instanceDestroy = __rbx_instance_destroy,
    instancePropertySignal = __rbx_instance_property_signal,
    instanceGetAttribute = __rbx_instance_get_attribute,
    instanceInternalProperty = __rbx_instance_internal_property,
    instanceSetDefault = __rbx_instance_set_default,
    instanceSetGuiGeometryResolver = __rbx_instance_set_gui_geometry_resolver,
    instanceGetAttributes = __rbx_instance_get_attributes,
    instanceSetAttribute = __rbx_instance_set_attribute,
    instanceAttributeSignal = __rbx_instance_attribute_signal,
    instanceTags = __rbx_instance_tags,
    instanceTagged = __rbx_instance_tagged,
    instanceClone = __rbx_instance_clone,
    instanceFullName = __rbx_instance_full_name,
    valueEnumsNew = __rbx_value_enums_new,
    valueEnumTypeNew = __rbx_value_enum_type_new,
    valueEnumItemNew = __rbx_value_enum_item_new,
    valueTweenInfoNew = __rbx_value_tween_info_new,
    valueRaycastParamsNew = __rbx_value_raycast_params_new,
    valueOverlapParamsNew = __rbx_value_overlap_params_new,
    valueNumberRangeNew = __rbx_value_number_range_new,
    valueNumberKeypointNew = __rbx_value_number_keypoint_new,
    valueNumberSequenceNew = __rbx_value_number_sequence_new,
    valueColorKeypointNew = __rbx_value_color_keypoint_new,
    valueColorSequenceNew = __rbx_value_color_sequence_new,
    valueDateTimeNewMillis = __rbx_value_datetime_new_millis,
    valueRandomBindNew = __rbx_value_random_bind_new,
    moduleLoadstring = __rbx_module_loadstring,
    nativeModuleDeclare = __rbx_native_module_declare,
    nativeModuleRequire = __rbx_native_module_require,
    nativeModuleFinish = __rbx_native_module_finish,
    nativeSignalNew = __rbx_native_signal_new,
    nativeSignalFire = __rbx_native_signal_fire,
    nativeSignalDisconnectAll = __rbx_native_signal_disconnect_all,
    nativeRunServiceConfigure = __rbx_native_runservice_configure,
    nativeRunServiceSetBindingCount = __rbx_native_runservice_set_binding_count,
    nativeHttpRequest = __rbx_native_http_request,
    captureText = __rbx_capture_text,
}
local __cfg = __host.runtimeConfig()
local __api = __host.jsonDecode(__host.apiDump())
local __scenario = __host.jsonDecode(__host.scenario())
local __base_environment = getfenv(0)
local __native_sleep = wait
local __native_task = task
local __native_loadstring = loadstring
local __native_type = type
local __native_typeof = typeof

if __cfg.deterministicSeed ~= nil then
    math.randomseed(tonumber(__cfg.deterministicSeed) or 0)
end

local function pack(...)
    return { n = select("#", ...), ... }
end

local function unpackPacked(value)
    return table.unpack(value, 1, value.n or #value)
end

local __native_pcall = pcall
local __native_xpcall = xpcall
-- Protected-call diagnostics are observed through Luau's host callback. Do
-- not replace pcall/xpcall: protected loaders validate their native identity,
-- environment, yield behavior, and exact multiple-return semantics.

local function makeTyped(typeName, fields, toString)
    fields.__type = typeName
    return setmetatable(fields, {
        __tostring = toString or function() return typeName end,
    })
end

local function makeImmutableTyped(typeName, fields, toString, index)
    fields.__type = typeName
    local metatable = table.freeze({
        __index = index,
        __tostring = toString or function() return typeName end,
    })
    setmetatable(fields, metatable)
    return table.freeze(fields)
end

local __classParents = {}
local __classTags = {}
for _, class in ipairs(__api.Classes or {}) do
    __classParents[class.Name] = class.Superclass ~= "" and class.Superclass or nil
    local tags = {}
    for _, tag in ipairs(class.Tags or {}) do tags[tag] = true end
    __classTags[class.Name] = tags
end

local function trace(kind, name, detail)
    if __cfg.analysisHooks and __host.trace then
        pcall(__host.trace, kind, name, detail)
    end
end

local scheduler = {
    now = 0,
    frame = 0,
    ready = {},
    deferred = {},
    timers = {},
    cancelled = setmetatable({}, { __mode = "k" }),
    errors = {},
    events = {},
    mainThread = nil,
    mainResults = nil,
    mainError = nil,
    timedOut = false,
    budgetReached = false,
    stopReason = "running",
}

local frameDuration = 1 / math.max(1, tonumber(__cfg.frameRate) or 60)
local maxVirtualSeconds = math.max(0, tonumber(__cfg.maxVirtualSeconds) or 30)
local realStart = __host.elapsed()
local nativeSchedulerAvailable = type(__native_task) == "table" and type(__native_task.wait) == "function"

local function clockNow()
    if nativeSchedulerAvailable then
        local current = __host.elapsed()
        return __cfg.clock == "realtime" and (current - realStart) or current
    end
    if __cfg.clock == "realtime" then return __host.elapsed() - realStart end
    return scheduler.now
end

local virtualEpochSeconds = tonumber(__cfg.virtualEpochSeconds) or 1735689600
local function unixNow()
    if __cfg.clock == "virtual" then return virtualEpochSeconds + clockNow() end
    return __host.wallTime()
end

local function recordScheduler(kind, thread, detail)
    if #scheduler.events < 4096 then
        table.insert(scheduler.events, {
            kind = kind,
            frame = scheduler.frame,
            time = scheduler.now,
            thread = tostring(thread),
            detail = detail,
        })
    end
end

local function asThread(value)
    if type(value) == "thread" then return value end
    if type(value) ~= "function" then error("invalid argument #1 to task function (function or thread expected)", 3) end
    return coroutine.create(value)
end

local function queueReady(thread, args, completion)
    table.insert(scheduler.ready, { thread = thread, args = args or pack(), completion = completion })
end

local function queueDeferred(thread, args, completion)
    table.insert(scheduler.deferred, { thread = thread, args = args or pack(), completion = completion })
end

local function queueTimer(thread, due, started, completion)
    table.insert(scheduler.timers, { thread = thread, due = due, started = started, completion = completion })
end

local resumeThread
resumeThread = function(thread, args, completion)
    if scheduler.cancelled[thread] or coroutine.status(thread) == "dead" then return end
    recordScheduler("resume", thread)
    local results = pack(coroutine.resume(thread, unpackPacked(args or pack())))
    if not results[1] then
        local message = tostring(results[2])
        if string.find(message, "__RBX_STEADY_STATE_BUDGET__", 1, true) then
            if thread == scheduler.mainThread then scheduler.mainError = "__RBX_STEADY_STATE_BUDGET__" end
            return
        end
        table.insert(scheduler.errors, message)
        recordScheduler("error", thread, message)
        if thread == scheduler.mainThread then scheduler.mainError = message end
        warn("[task]", message)
        return
    end
    if coroutine.status(thread) == "dead" then
        local returned = { n = math.max(0, results.n - 1) }
        for i = 2, results.n do returned[i - 1] = results[i] end
        recordScheduler("complete", thread)
        if completion then completion(returned) end
        return
    end

    local token = results[2]
    if type(token) == "table" and token.kind == "wait" then
        local duration = math.max(0, tonumber(token.duration) or 0)
        local due = math.max(scheduler.now + frameDuration, scheduler.now + duration)
        queueTimer(thread, due, token.started or scheduler.now, completion)
        recordScheduler("wait", thread, duration)
    elseif type(token) == "table" and token.kind == "signal" and token.signal then
        table.insert(token.signal._waiters, { thread = thread, completion = completion })
        recordScheduler("signal_wait", thread, token.signal._name)
    else
        queueDeferred(thread, pack(), completion)
        recordScheduler("yield", thread)
    end
end

task = {}
function task.spawn(fn, ...)
    local thread = asThread(fn)
    resumeThread(thread, pack(...))
    return thread
end
function task.defer(fn, ...)
    local thread = asThread(fn)
    queueDeferred(thread, pack(...))
    recordScheduler("defer", thread)
    return thread
end
function task.delay(seconds, fn, ...)
    local thread = asThread(fn)
    local duration = math.max(0, tonumber(seconds) or 0)
    queueTimer(thread, scheduler.now + math.max(frameDuration, duration), scheduler.now)
    local timer = scheduler.timers[#scheduler.timers]
    timer.args = pack(...)
    recordScheduler("delay", thread, duration)
    return thread
end
function task.wait(seconds)
    local started = scheduler.now
    return coroutine.yield({ kind = "wait", duration = math.max(0, tonumber(seconds) or 0), started = started })
end
function task.cancel(thread)
    if type(thread) ~= "thread" then error("invalid argument #1 to 'cancel' (thread expected)", 2) end
    scheduler.cancelled[thread] = true
    recordScheduler("cancel", thread)
end
function task.synchronize() return task.wait() end
function task.desynchronize() return task.wait() end

wait = task.wait
delay = task.delay
defer = task.defer
spawn = task.defer

local signalBehaviorDeferred = false
local function makeSignal(name)
    if type(__host.nativeSignalNew) == "function" then
        return __host.nativeSignalNew(name or "Signal", signalBehaviorDeferred)
    end
    local signal = makeTyped("RBXScriptSignal", {
        _name = name or "Signal",
        _connections = {},
        _waiters = {},
        _disconnectAfterFire = type(name) == "string" and string.sub(name, -11) == ".Destroying",
    }, function(self) return "Signal " .. tostring(self._name) end)

    function signal:Connect(fn)
        if type(fn) ~= "function" then error("Connect expects a function", 2) end
        local connection = makeTyped("RBXScriptConnection", {
            Connected = true,
            Function = fn,
            Signal = self,
        }, function() return "Connection" end)
        function connection:Disconnect()
            self.Connected = false
        end
        table.insert(self._connections, connection)
        return connection
    end

    function signal:Once(fn)
        local connection
        connection = self:Connect(function(...)
            if connection then connection:Disconnect() end
            fn(...)
        end)
        return connection
    end

    function signal:Wait()
        return coroutine.yield({ kind = "signal", signal = self })
    end

    function signal:Fire(...)
        local args = pack(...)
        local waiters = self._waiters
        self._waiters = {}
        for _, waiter in ipairs(waiters) do
            queueReady(waiter.thread, args, waiter.completion)
        end
        local deferredSignals = signalBehaviorDeferred
        for _, connection in ipairs(table.clone(self._connections)) do
            if connection.Connected then
                if deferredSignals then
                    task.defer(function()
                        if connection.Connected then connection.Function(unpackPacked(args)) end
                    end)
                else task.spawn(connection.Function, unpackPacked(args)) end
            end
        end
        if self._disconnectAfterFire then
            task.defer(function() self:_DisconnectAll() end)
        end
    end
    function signal:_DisconnectAll()
        for _, connection in ipairs(self._connections) do connection.Connected = false end
        table.clear(self._connections)
        for _, waiter in ipairs(self._waiters) do scheduler.cancelled[waiter.thread] = true end
        table.clear(self._waiters)
    end
    return signal
end
local function fireSignalValue(signal, ...)
    if type(__host.nativeSignalFire) == "function" then
        return __host.nativeSignalFire(signal, ...)
    end
    return signal:Fire(...)
end
local function disconnectSignalValue(signal)
    if type(__host.nativeSignalDisconnectAll) == "function" then
        return __host.nativeSignalDisconnectAll(signal)
    end
    return signal:_DisconnectAll()
end
__rbx_make_signal = makeSignal

for _, enum in ipairs(__api.Enums or {}) do
    local enumType = __host.valueEnumTypeNew(enum.Name)
    for _, item in ipairs(enum.Items or {}) do
        __host.valueEnumItemNew(enumType, item.Name, item.Value or 0, item.LegacyNames or {})
    end
end
Enum = __host.valueEnumsNew()

local instanceMethods = {}
__rbx_instance_methods = instanceMethods
local classMethods = {}
__rbx_class_methods = classMethods

local function registerClassMethods(className, names)
    local target = classMethods[className]
    if not target then
        target = {}
        classMethods[className] = target
    end
    for _, name in ipairs(names) do
        local implementation = instanceMethods[name]
        if type(implementation) == "function" then
            if debug.info(implementation, "s") ~= "[C]" then
                implementation = __host.instanceBindNative(name, implementation)
                instanceMethods[name] = implementation
            end
            target[name] = implementation
        end
    end
end

function instanceMethods:IsA(className)
    return __host.instanceIsA(self, className)
end
function instanceMethods:GetChildren()
    return __host.instanceChildren(self)
end
local function appendDescendants(node, output)
    for _, child in ipairs(node:GetChildren()) do
        table.insert(output, child)
        appendDescendants(child, output)
    end
end
function instanceMethods:GetDescendants()
    local output = {}
    appendDescendants(self, output)
    return output
end
function instanceMethods:FindFirstChild(name, recursive)
    return __host.instanceFind(self, name, recursive == true)
end
function instanceMethods:FindFirstDescendant(name)
    return __host.instanceFind(self, name, true)
end
instanceMethods.WaitForChild = __host.instanceWaitForChild
function instanceMethods:FindFirstChildOfClass(className)
    for _, child in ipairs(self:GetChildren()) do if child.ClassName == className then return child end end
    return nil
end
function instanceMethods:FindFirstChildWhichIsA(className, recursive)
    local children = recursive and self:GetDescendants() or self:GetChildren()
    for _, child in ipairs(children) do if child:IsA(className) then return child end end
    return nil
end
function instanceMethods:FindFirstAncestor(name)
    local cursor = self.Parent
    while cursor do
        if cursor.Name == name then return cursor end
        cursor = cursor.Parent
    end
    return nil
end
function instanceMethods:FindFirstAncestorOfClass(className)
    local cursor = self.Parent
    while cursor do
        if cursor.ClassName == className then return cursor end
        cursor = cursor.Parent
    end
    return nil
end
function instanceMethods:FindFirstAncestorWhichIsA(className)
    local cursor = self.Parent
    while cursor do
        if cursor:IsA(className) then return cursor end
        cursor = cursor.Parent
    end
    return nil
end
function instanceMethods:IsDescendantOf(ancestor)
    local cursor = self.Parent
    while cursor do
        if cursor == ancestor then return true end
        cursor = cursor.Parent
    end
    return false
end
function instanceMethods:IsAncestorOf(descendant)
    return descendant:IsDescendantOf(self)
end
function instanceMethods:GetFullName()
    return __host.instanceFullName(self)
end
function instanceMethods:GetPropertyChangedSignal(name)
    return __host.instancePropertySignal(self, name)
end
function instanceMethods:GetAttribute(name)
    return __host.instanceGetAttribute(self, name)
end
function instanceMethods:GetAttributes()
    return table.clone(__host.instanceGetAttributes(self))
end
function instanceMethods:SetAttribute(name, value)
    return __host.instanceSetAttribute(self, name, value)
end
function instanceMethods:GetAttributeChangedSignal(name)
    return __host.instanceAttributeSignal(self, name)
end
function instanceMethods:AddTag(tag) __host.instanceTags(self, tag, true) end
function instanceMethods:RemoveTag(tag) __host.instanceTags(self, tag, false) end
function instanceMethods:HasTag(tag) return __host.instanceTags(self, tag) end
function instanceMethods:GetTags()
    local output = {}
    for tag, enabled in pairs(__host.instanceTags(self)) do if enabled then table.insert(output, tag) end end
    table.sort(output)
    return output
end
function instanceMethods:ClearAllChildren()
    for _, child in ipairs(self:GetChildren()) do child:Destroy() end
end
function instanceMethods:Destroy() return __host.instanceDestroy(self) end
instanceMethods.destroy = instanceMethods.Destroy
instanceMethods.Remove = instanceMethods.Destroy
instanceMethods.remove = instanceMethods.Destroy
function instanceMethods:Clone() return __host.instanceClone(self) end
instanceMethods.clone = instanceMethods.Clone
instanceMethods.children = instanceMethods.GetChildren
instanceMethods.getChildren = instanceMethods.GetChildren
instanceMethods.findFirstChild = instanceMethods.FindFirstChild
instanceMethods.isDescendantOf = instanceMethods.IsDescendantOf

registerClassMethods("Object", { "IsA", "GetPropertyChangedSignal" })
registerClassMethods("Instance", {
    "GetChildren", "GetDescendants", "FindFirstChild", "FindFirstDescendant", "WaitForChild",
    "FindFirstChildOfClass", "FindFirstChildWhichIsA", "FindFirstAncestor", "FindFirstAncestorOfClass",
    "FindFirstAncestorWhichIsA", "IsDescendantOf", "IsAncestorOf", "GetFullName", "GetAttribute",
    "GetAttributes", "SetAttribute", "GetAttributeChangedSignal", "AddTag", "RemoveTag", "HasTag", "GetTags",
    "ClearAllChildren", "Destroy", "Clone",
})

local function guiAbsoluteGeometry(instance, property)
    local parent = instance.Parent
    local hasParent = parent ~= nil
    local parentSize = Vector2.zero
    local parentPosition = Vector2.zero
    local parentRotation = 0
    if hasParent then
        if parent:IsA("GuiObject") then
            parentSize = parent.AbsoluteSize
            parentPosition = parent.AbsolutePosition
            parentRotation = parent.AbsoluteRotation
        else
            local ok, value = pcall(function() return parent.AbsoluteSize end)
            if ok and typeof(value) == "Vector2" then parentSize = value end
        end
    end

    local size = instance.Size
    local absoluteSize = Vector2.new(
        parentSize.X * size.X.Scale + size.X.Offset,
        parentSize.Y * size.Y.Scale + size.Y.Offset
    )
    if property == "AbsoluteSize" then return absoluteSize end
    if property == "AbsoluteRotation" then
        return hasParent and (parentRotation + instance.Rotation) or 0
    end
    if not hasParent then return Vector2.zero end

    local position = instance.Position
    local anchor = instance.AnchorPoint
    return Vector2.new(
        parentPosition.X + parentSize.X * position.X.Scale + position.X.Offset - anchor.X * absoluteSize.X,
        parentPosition.Y + parentSize.Y * position.Y.Scale + position.Y.Offset - anchor.Y * absoluteSize.Y
    )
end
__host.instanceSetGuiGeometryResolver(guiAbsoluteGeometry)

local classDefaults = {
    BasePart = {
        Position = Vector3.new(), Size = Vector3.new(4, 1, 2), CFrame = CFrame.new(), Anchored = false,
        CanCollide = true, CanQuery = true, CanTouch = true, CastShadow = true, Transparency = 0,
        Reflectance = 0, Material = Enum.Material and Enum.Material.Plastic or nil,
    },
    Part = { Shape = Enum.PartType and Enum.PartType.Block or nil },
    Humanoid = {
        AutoJumpEnabled = true, AutoRotate = true, AutomaticScalingEnabled = true, BreakJointsOnDeath = true,
        CameraOffset = Vector3.new(), DisplayName = "", EvaluateStateMachine = true,
        FloorMaterial = Enum.Material and Enum.Material.Air or nil, Health = 100, HealthDisplayDistance = 100,
        HipHeight = 0, Jump = false, JumpHeight = 7.2, JumpPower = 50, MaxHealth = 100, MaxSlopeAngle = 89,
        MoveDirection = Vector3.new(), PlatformStand = false, RequiresNeck = true,
        RigType = Enum.HumanoidRigType and Enum.HumanoidRigType.R15 or nil, Sit = false,
        TargetPoint = Vector3.new(), UseJumpPower = true, WalkSpeed = 16, WalkToPoint = Vector3.new(),
    },
    Camera = { CFrame = CFrame.new(), Focus = CFrame.new(), ViewportSize = Vector2.new(1920, 1080), FieldOfView = 70 },
    GuiObject = {
        Visible = true, Position = UDim2.new(), Size = UDim2.new(), AnchorPoint = Vector2.new(),
        AbsolutePosition = Vector2.new(), AbsoluteSize = Vector2.new(), AbsoluteRotation = 0,
        Rotation = 0, AutomaticSize = Enum.AutomaticSize and Enum.AutomaticSize.None or nil, BackgroundTransparency = 0,
    },
    ScreenGui = { Enabled = true, ResetOnSpawn = true, AbsoluteSize = Vector2.new(800, 600) },
    TextLabel = { Text = "", TextColor3 = Color3.new(1, 1, 1), TextSize = 14 },
    TextButton = { Text = "", TextColor3 = Color3.new(1, 1, 1), TextSize = 14, AutoButtonColor = true },
    ImageLabel = { Image = "" },
    ImageButton = { Image = "", AutoButtonColor = true },
    Sound = {
        EmitterSize = 10, IsLoaded = true, IsPaused = false, IsPlaying = false, Looped = false,
        MaxDistance = 10000, MinDistance = 10, Pitch = 1, PlayOnRemove = false, PlaybackLoudness = 0,
        PlaybackSpeed = 1, Playing = false, RollOffMaxDistance = 10000, RollOffMinDistance = 10,
        SoundId = "", TimeLength = 0, TimePosition = 0, Volume = 0.5,
    },
    ModuleScript = { Source = "" },
}
local classNilDefaults = {
    BasePart = { "CustomPhysicalProperties" },
    Camera = { "CameraSubject" },
    GuiObject = { "NextSelectionDown", "NextSelectionLeft", "NextSelectionRight", "NextSelectionUp", "SelectionImageObject" },
    Model = { "PrimaryPart" },
    Humanoid = { "LeftLeg", "RightLeg", "RootPart", "SeatPart", "Torso", "WalkToPart" },
    Player = { "Character", "Team" },
    Sound = { "SoundGroup" },
    Workspace = { "CurrentCamera" },
}

local function applyDefaults(instance)
    local chain = {}
    local cursor = instance.ClassName
    while cursor and cursor ~= "<<<ROOT>>>" do
        table.insert(chain, 1, cursor)
        cursor = __classParents[cursor]
    end
    for _, className in ipairs(chain) do
        for key, value in pairs(classDefaults[className] or {}) do
            __host.instanceSetDefault(instance, key, value)
        end
        for _, key in ipairs(classNilDefaults[className] or {}) do
            __host.instanceSetDefault(instance, key, nil)
        end
    end
    return instance
end

Instance = {}
-- Insertion order matches the release-729 Studio constructor table.
Instance.new = __host.instanceBindPublicNew(applyDefaults)
Instance.fromExisting = __host.instanceBindPublicFromExisting()
local function internalInstance(className, parent)
    local instance = __host.instanceNew(className, nil, true)
    applyDefaults(instance)
    if parent ~= nil then instance.Parent = parent end
    return instance
end

local services = {}
game = internalInstance("DataModel")
game.Name = __cfg.studioRunScriptCompatibility and "Place1" or "game"
game.PlaceId = __cfg.placeId
game.GameId = __cfg.gameId
game.JobId = __cfg.jobId
game.PlaceVersion = 1
game.CreatorId = 0

workspace = internalInstance("Workspace", game)
workspace.Name = "Workspace"
Workspace = workspace
services.Workspace = workspace
services.workspace = workspace
workspace.SignalBehavior = Enum.SignalBehavior and Enum.SignalBehavior.Deferred or nil
signalBehaviorDeferred = workspace.SignalBehavior == (Enum.SignalBehavior and Enum.SignalBehavior.Deferred)

local function service(name)
    if services[name] then return services[name] end
    if not __classParents[name] and name ~= "Instance" then error(name .. " is not a valid service", 2) end
    local tags = __classTags[name] or {}
    if not tags.Service then error(name .. " is not a valid service", 2) end
    local value = internalInstance(name, game)
    value.Name = name
    services[name] = value
    return value
end

function instanceMethods:GetService(name)
    if self ~= game then error("GetService is only valid on DataModel", 2) end
    trace("api_call", "game:GetService", tostring(name))
    return service(tostring(name))
end
function instanceMethods:FindService(name)
    return services[tostring(name)]
end
function instanceMethods:IsLoaded() return true end
registerClassMethods("ServiceProvider", { "GetService", "FindService" })
registerClassMethods("DataModel", { "IsLoaded" })

RunService = service("RunService")
RunService.Name = "Run Service"
local runServiceSignals = {}
for _, event in ipairs({"PreRender", "RenderStepped", "PreAnimation", "PreSimulation", "Stepped", "PostSimulation", "Heartbeat"}) do
    runServiceSignals[event] = RunService[event]
end
local renderSteps = {}
local function updateRenderStepDemand()
    if type(__host.nativeRunServiceSetBindingCount) ~= "function" then return end
    local count = 0
    for _ in pairs(renderSteps) do count += 1 end
    __host.nativeRunServiceSetBindingCount(count)
end
function instanceMethods:BindToRenderStep(name, priority, fn)
    if self ~= RunService then error("BindToRenderStep is only valid on RunService", 2) end
    if type(name) ~= "string" then error("BindToRenderStep name must be a string", 2) end
    if type(fn) ~= "function" then error("BindToRenderStep callback must be a function", 2) end
    renderSteps[name] = { Priority = tonumber(priority) or 0, Function = fn }
    updateRenderStepDemand()
end
function instanceMethods:UnbindFromRenderStep(name)
    if self == RunService then
        renderSteps[name] = nil
        updateRenderStepDemand()
    end
end
function instanceMethods:IsStudio() return __cfg.studioRunScriptCompatibility == true end
function instanceMethods:IsRunning() return __cfg.studioRunScriptCompatibility ~= true end
function instanceMethods:IsClient() return true end
function instanceMethods:IsServer() return __cfg.studioRunScriptCompatibility == true end
registerClassMethods("RunService", { "BindToRenderStep", "UnbindFromRenderStep", "IsStudio", "IsRunning", "IsClient", "IsServer" })

local function runNativeFramePhase(phase, now, dt)
    if phase == "RenderBindings" then
        local render = {}
        for name, binding in pairs(renderSteps) do
            table.insert(render, { Name = name, Priority = binding.Priority, Function = binding.Function })
        end
        table.sort(render, function(a, b)
            if a.Priority == b.Priority then return a.Name < b.Name end
            return a.Priority < b.Priority
        end)
        for _, binding in ipairs(render) do binding.Function(dt) end
        return
    end
    local signal = runServiceSignals[phase]
    if not signal then return end
    if phase == "Stepped" then fireSignalValue(signal, now, dt)
    else fireSignalValue(signal, dt) end
end

if type(__host.nativeRunServiceConfigure) == "function" then
    __host.nativeRunServiceConfigure(
        runNativeFramePhase,
        runServiceSignals.PreRender,
        runServiceSignals.RenderStepped,
        runServiceSignals.PreAnimation,
        runServiceSignals.PreSimulation,
        runServiceSignals.Stepped,
        runServiceSignals.PostSimulation,
        runServiceSignals.Heartbeat)
end

local function runFramePhases(dt)
    local now = scheduler.now
    for _, phase in ipairs({"PreRender", "RenderBindings", "RenderStepped", "PreAnimation", "PreSimulation", "Stepped", "PostSimulation", "Heartbeat"}) do
        runNativeFramePhase(phase, now, dt)
    end
end

local function drainQueue(queue)
    local items = table.clone(queue)
    table.clear(queue)
    for _, item in ipairs(items) do
        resumeThread(item.thread, item.args or pack(), item.completion)
    end
end

local function moveDueTimers()
    local remaining = {}
    for _, timer in ipairs(scheduler.timers) do
        if timer.due <= scheduler.now + 1e-9 then
            local args = timer.args or pack(scheduler.now - (timer.started or scheduler.now))
            if not timer.args then args = pack(scheduler.now - (timer.started or scheduler.now)) end
            queueReady(timer.thread, args, timer.completion)
        else
            table.insert(remaining, timer)
        end
    end
    scheduler.timers = remaining
end

local function schedulerHasWork()
    return #scheduler.ready > 0 or #scheduler.deferred > 0 or #scheduler.timers > 0
end

local function stepScheduler()
    drainQueue(scheduler.ready)
    if #scheduler.ready > 0 then return end
    if #scheduler.deferred > 0 then
        local pending = scheduler.deferred
        scheduler.deferred = {}
        drainQueue(pending)
        if #scheduler.ready > 0 or #scheduler.deferred > 0 then return end
    end
    if not schedulerHasWork() then return end

    local nextTime = scheduler.now + frameDuration
    if __cfg.clock == "realtime" then
        local remaining = nextTime - clockNow()
        if remaining > 0 then __native_sleep(remaining) end
        scheduler.now = clockNow()
    else
        scheduler.now = nextTime
    end
    scheduler.frame += 1
    runFramePhases(frameDuration)
    moveDueTimers()
end

function __rbx_execute(fn, ...)
    local main = coroutine.create(fn)
    scheduler.mainThread = main
    resumeThread(main, pack(...), function(results) scheduler.mainResults = results end)
    local guard = 0
    while (coroutine.status(main) ~= "dead" or schedulerHasWork()) and not scheduler.mainError do
        if __cfg.clock == "virtual" and maxVirtualSeconds > 0 and scheduler.now >= maxVirtualSeconds then
            scheduler.budgetReached = true
            scheduler.stopReason = "virtual_budget"
            break
        end
        guard += 1
        if guard > 1000000 then
            scheduler.mainError = "scheduler iteration limit exceeded"
            break
        end
        if not schedulerHasWork() and coroutine.status(main) ~= "dead" then break end
        stepScheduler()
    end
    if scheduler.mainError then return false, scheduler.mainError end
    if scheduler.budgetReached then return true, nil, unpackPacked(scheduler.mainResults or pack()) end
    if coroutine.status(main) ~= "dead" then return false, "main script is suspended on an event with no scheduled producer" end
    scheduler.stopReason = "completed"
    return true, nil, unpackPacked(scheduler.mainResults or pack())
end

function __rbx_scheduler_report()
    return {
        clock = __cfg.clock,
        virtual_time = scheduler.now,
        frames = scheduler.frame,
        timed_out = scheduler.timedOut,
        budget_reached = scheduler.budgetReached,
        stop_reason = scheduler.stopReason,
        errors = table.clone(scheduler.errors),
        events = table.clone(scheduler.events),
        pending = {
            ready = #scheduler.ready,
            deferred = #scheduler.deferred,
            timers = #scheduler.timers,
        },
    }
end

-- The compatibility scheduler remains available only as a migration oracle for
-- older reports. Production work, including scenario fixtures queued below,
-- is owned by the per-VM native scheduler installed before this shim loads.
if nativeSchedulerAvailable then
    task = __native_task
    wait = task.wait
    delay = task.delay
    defer = task.defer
    spawn = task.spawn
end

Players = service("Players")
Players.LocalPlayer = internalInstance("Player", Players)
Players.LocalPlayer.Name = __cfg.playerName
Players.LocalPlayer.DisplayName = __cfg.playerName
Players.LocalPlayer.UserId = __cfg.userId
Players.LocalPlayer.AccountAge = 3650
Players.LocalPlayer.PlayerGui = internalInstance("PlayerGui", Players.LocalPlayer)
Players.LocalPlayer.PlayerScripts = internalInstance("PlayerScripts", Players.LocalPlayer)
Players.LocalPlayer.Backpack = internalInstance("Backpack", Players.LocalPlayer)
local playersList = { Players.LocalPlayer }
local character = internalInstance("Model", workspace)
character.Name = __cfg.playerName
local rootPart = Instance.new("Part", character)
rootPart.Name = "HumanoidRootPart"
rootPart.Position = Vector3.new(0, 5, 0)
rootPart.CFrame = CFrame.new(0, 5, 0)
local humanoid = Instance.new("Humanoid", character)
humanoid.Name = "Humanoid"
character.PrimaryPart = rootPart
Players.LocalPlayer.Character = character
local humanoidStates = setmetatable({}, { __mode = "k" })
local humanoidStateEnabled = setmetatable({}, { __mode = "k" })
local function checkHumanoid(self, method)
    if not self:IsA("Humanoid") then error(method .. " is only valid on Humanoid", 3) end
end
function instanceMethods:ChangeState(state)
    checkHumanoid(self, "ChangeState")
    local previous = humanoidStates[self] or (Enum.HumanoidStateType and Enum.HumanoidStateType.Running)
    if previous == state then return end
    humanoidStates[self] = state
    fireSignalValue(self.StateChanged, previous, state)
end
function instanceMethods:GetState()
    checkHumanoid(self, "GetState")
    return humanoidStates[self] or (Enum.HumanoidStateType and Enum.HumanoidStateType.Running)
end
function instanceMethods:SetStateEnabled(state, enabled)
    checkHumanoid(self, "SetStateEnabled")
    local states = humanoidStateEnabled[self]
    if not states then states = {}; humanoidStateEnabled[self] = states end
    local key = tostring(state)
    local value = enabled ~= false
    if states[key] == value then return end
    states[key] = value
    fireSignalValue(self.StateEnabledChanged, state, value)
end
function instanceMethods:GetStateEnabled(state)
    checkHumanoid(self, "GetStateEnabled")
    local states = humanoidStateEnabled[self]
    local value = states and states[tostring(state)]
    return value == nil and true or value
end
function instanceMethods:TakeDamage(amount)
    checkHumanoid(self, "TakeDamage")
    local model = self.Parent
    if model and model:FindFirstChildWhichIsA("ForceField") then return end
    self.Health = math.max(0, self.Health - math.max(0, tonumber(amount) or 0))
end
function instanceMethods:Move(direction, relativeToCamera)
    checkHumanoid(self, "Move")
    if typeof(direction) ~= "Vector3" then error("Move direction must be a Vector3", 2) end
    __host.instanceSetDefault(self, "MoveDirection", direction)
    fireSignalValue(self.Running, direction.Magnitude * self.WalkSpeed)
end
function instanceMethods:MoveTo(location, part)
    checkHumanoid(self, "MoveTo")
    if typeof(location) ~= "Vector3" then error("MoveTo location must be a Vector3", 2) end
    self.WalkToPoint = location
    self.WalkToPart = part
    task.defer(function() fireSignalValue(self.MoveToFinished, true) end)
end
function instanceMethods:EquipTool(tool)
    checkHumanoid(self, "EquipTool")
    if typeof(tool) ~= "Instance" or not tool:IsA("Tool") then error("EquipTool expects a Tool", 2) end
    tool.Parent = self.Parent
end
function instanceMethods:UnequipTools()
    checkHumanoid(self, "UnequipTools")
    local model = self.Parent
    if not model then return end
    for _, value in ipairs(model:GetChildren()) do
        if value:IsA("Tool") then value.Parent = Players.LocalPlayer.Backpack end
    end
end
function instanceMethods:GetAccessories()
    checkHumanoid(self, "GetAccessories")
    local result = {}
    if self.Parent then
        for _, value in ipairs(self.Parent:GetChildren()) do if value:IsA("Accessory") then table.insert(result, value) end end
    end
    return result
end
registerClassMethods("Humanoid", {
    "ChangeState", "GetState", "SetStateEnabled", "GetStateEnabled", "TakeDamage", "Move", "MoveTo",
    "EquipTool", "UnequipTools", "GetAccessories",
})
function instanceMethods:GetPlayers()
    if self == Players then return table.clone(playersList) end
    return {}
end
function instanceMethods:GetPlayerByUserId(userId)
    if self == Players then
        for _, player in ipairs(playersList) do
            if tonumber(userId) == player.UserId then return player end
        end
    end
    return nil
end
function instanceMethods:GetMouse()
    if self ~= Players.LocalPlayer then error("GetMouse is only valid on Player", 2) end
    return makeTyped("PlayerMouse", {
        X = 960, Y = 540, Hit = CFrame.new(), Target = nil,
        Button1Down = makeSignal("Mouse.Button1Down"), Button1Up = makeSignal("Mouse.Button1Up"),
        KeyDown = makeSignal("Mouse.KeyDown"), KeyUp = makeSignal("Mouse.KeyUp"),
    })
end
registerClassMethods("Players", { "GetPlayers", "GetPlayerByUserId" })
registerClassMethods("Team", { "GetPlayers" })
registerClassMethods("Player", { "GetMouse" })

workspace.CurrentCamera = internalInstance("Camera", workspace)
workspace.CurrentCamera.Name = "Camera"

HttpService = service("HttpService")
local httpFixtures = __scenario.http_fixtures or {}
local function fixtureResponse(method, url)
    local fixture = httpFixtures[string.upper(method or "GET") .. " " .. tostring(url)] or httpFixtures[tostring(url)]
    if fixture == nil then return nil end
    if type(fixture) == "string" then return { Success = true, StatusCode = 200, StatusMessage = "OK", Headers = {}, Body = fixture } end
    local latency = tonumber(fixture.latency_seconds or fixture.latency or 0) or 0
    if fixture.latency_ms ~= nil then latency = (tonumber(fixture.latency_ms) or 0) / 1000 end
    if latency > 0 then task.wait(latency) end
    if fixture.error ~= nil then error(tostring(fixture.error), 3) end
    return {
        Success = fixture.success ~= false,
        StatusCode = fixture.status_code or fixture.StatusCode or 200,
        StatusMessage = fixture.status_message or fixture.StatusMessage or "OK",
        Headers = fixture.headers or fixture.Headers or {},
        Body = fixture.body or fixture.Body or "",
    }
end
function instanceMethods:JSONEncode(value)
    if self ~= HttpService then error("JSONEncode is only valid on HttpService", 2) end
    return __host.jsonEncode(value)
end
function instanceMethods:JSONDecode(value) return __host.jsonDecode(value) end
function instanceMethods:UrlEncode(value) return __host.urlEncode(value) end
function instanceMethods:UrlDecode(value) return __host.urlDecode(value) end
function instanceMethods:GenerateGUID(wrap) return __host.generateGuid(wrap) end
local function nativeRequest(options)
    if type(__host.nativeHttpRequest) ~= "function" then return __host.httpRequest(options) end
    options = options or {}
    local url = options.Url or options.URL or options.url
    local method = string.upper(tostring(options.Method or options.method or "GET"))
    local fixture = fixtureResponse(method, url)
    if fixture then return fixture end
    return __host.nativeHttpRequest({
        Url = url,
        Method = method,
        Headers = options.Headers or options.headers or {},
        Cookies = options.Cookies or options.cookies,
        Body = options.Body or options.body or "",
        Timeout = options.Timeout or options.timeout,
        RedirectLimit = options.RedirectLimit or options.redirect_limit,
    })
end
function instanceMethods:RequestAsync(options)
    local method = options.Method or "GET"
    local fixture = fixtureResponse(method, options.Url)
    if fixture then return fixture end
    return nativeRequest(options)
end
function instanceMethods:GetAsync(url, nocache, headers)
    local fixture = fixtureResponse("GET", url)
    if fixture then return fixture.Body end
    local response = nativeRequest({ Url = url, Method = "GET", Headers = headers or {} })
    if not response.Success then error("HTTP " .. tostring(response.StatusCode) .. ": " .. tostring(response.StatusMessage), 2) end
    return response.Body
end
function instanceMethods:PostAsync(url, data, contentType, compress, headers)
    local fixture = fixtureResponse("POST", url)
    if fixture then return fixture.Body end
    headers = table.clone(headers or {})
    if contentType ~= nil and headers["Content-Type"] == nil then headers["Content-Type"] = tostring(contentType) end
    local response = nativeRequest({ Url = url, Method = "POST", Headers = headers, Body = data or "" })
    if not response.Success then error("HTTP " .. tostring(response.StatusCode) .. ": " .. tostring(response.StatusMessage), 2) end
    return response.Body
end
function instanceMethods:HttpGet(url, nocache, headers)
    return HttpService:GetAsync(url, nocache, headers)
end
function instanceMethods:HttpGetAsync(url, nocache, headers) return self:HttpGet(url, nocache, headers) end
function instanceMethods:HttpPost(url, data, contentType, compress, headers)
    return HttpService:PostAsync(url, data, contentType, compress, headers)
end
function instanceMethods:HttpPostAsync(url, data, contentType, compress, headers) return self:HttpPost(url, data, contentType, compress, headers) end
registerClassMethods("HttpService", {
    "JSONEncode", "JSONDecode", "UrlEncode", "GenerateGUID", "RequestAsync", "GetAsync", "PostAsync",
})
registerClassMethods("DataModel", { "HttpGetAsync", "HttpPostAsync" })

CollectionService = service("CollectionService")
local tagAdded, tagRemoved = {}, {}
__rbx_collection_tag_changed = function(instance, tag, added)
    local signal = added and tagAdded[tag] or tagRemoved[tag]
    if signal then fireSignalValue(signal, instance) end
end
function instanceMethods:AddTag(instance, tag)
    if self == CollectionService then
        return __host.instanceTags(instance, tag, true)
    else
        return __host.instanceTags(self, instance, true)
    end
end
function instanceMethods:RemoveTag(instance, tag)
    if self == CollectionService then
        return __host.instanceTags(instance, tag, false)
    else
        return __host.instanceTags(self, instance, false)
    end
end
function instanceMethods:HasTag(instance, tag)
    if self == CollectionService then return instance:HasTag(tag) end
    return __host.instanceTags(self, instance)
end
function instanceMethods:GetTags(instance)
    if self ~= CollectionService then error("GetTags overload is only valid on CollectionService", 2) end
    return instance:GetTags()
end
function instanceMethods:GetTagged(tag)
    return __host.instanceTagged(tag)
end
function instanceMethods:GetInstanceAddedSignal(tag)
    tagAdded[tag] = tagAdded[tag] or makeSignal("CollectionService.Added." .. tostring(tag))
    return tagAdded[tag]
end
function instanceMethods:GetInstanceRemovedSignal(tag)
    tagRemoved[tag] = tagRemoved[tag] or makeSignal("CollectionService.Removed." .. tostring(tag))
    return tagRemoved[tag]
end
registerClassMethods("CollectionService", {
    "AddTag", "RemoveTag", "HasTag", "GetTags", "GetTagged", "GetInstanceAddedSignal", "GetInstanceRemovedSignal",
})

TweenInfo = {}
function TweenInfo.new(time, easingStyle, easingDirection, repeatCount, reverses, delayTime)
    return __host.valueTweenInfoNew(time, easingStyle, easingDirection, repeatCount, reverses, delayTime)
end
TweenService = service("TweenService")
local function interpolate(a, b, alpha)
    if type(a) == "number" and type(b) == "number" then return a + (b - a) * alpha end
    local ok, value = pcall(function() return a + (b - a) * alpha end)
    return ok and value or (alpha >= 1 and b or a)
end
function instanceMethods:Create(target, info, properties)
    if self ~= TweenService then error("Create is only valid on TweenService", 2) end
    local tween = makeTyped("Tween", {
        Instance = target, TweenInfo = info, Properties = properties or {},
        Completed = makeSignal("Tween.Completed"), PlaybackState = Enum.PlaybackState and Enum.PlaybackState.Begin or nil,
        _thread = nil,
    })
    function tween:Play()
        if self._thread then task.cancel(self._thread) end
        local starts = {}
        for key in pairs(self.Properties) do starts[key] = self.Instance[key] end
        self._thread = task.spawn(function()
            if self.TweenInfo.DelayTime > 0 then task.wait(self.TweenInfo.DelayTime) end
            local started = scheduler.now
            repeat
                local alpha = self.TweenInfo.Time <= 0 and 1 or math.min(1, (scheduler.now - started) / self.TweenInfo.Time)
                for key, targetValue in pairs(self.Properties) do self.Instance[key] = interpolate(starts[key], targetValue, alpha) end
                if alpha >= 1 then break end
                task.wait()
            until false
            self.PlaybackState = Enum.PlaybackState and Enum.PlaybackState.Completed or nil
            fireSignalValue(self.Completed, self.PlaybackState)
        end)
    end
    function tween:Cancel()
        if self._thread then task.cancel(self._thread) end
        self.PlaybackState = Enum.PlaybackState and Enum.PlaybackState.Cancelled or nil
        fireSignalValue(self.Completed, self.PlaybackState)
    end
    tween.Stop = tween.Cancel
    function tween:Pause() if self._thread then task.cancel(self._thread) end end
    return tween
end
registerClassMethods("TweenService", { "Create" })

Debris = service("Debris")
function instanceMethods:AddItem(instance, lifetime)
    if self ~= Debris then error("AddItem is only valid on Debris", 2) end
    task.delay(lifetime or 10, function() if instance then instance:Destroy() end end)
end
registerClassMethods("Debris", { "AddItem" })

UserInputService = service("UserInputService")
UserInputService.KeyboardEnabled = true
UserInputService.MouseEnabled = true
UserInputService.TouchEnabled = false
UserInputService.GamepadEnabled = false
UserInputService.MouseBehavior = Enum.MouseBehavior and Enum.MouseBehavior.Default or nil
UserInputService.MouseIconEnabled = true
UserInputService._keys = {}
UserInputService._mouse = Vector2.new(960, 540)
function instanceMethods:GetMouseLocation() return UserInputService._mouse end
function instanceMethods:IsKeyDown(key) return UserInputService._keys[tostring(key)] == true end
function instanceMethods:IsMouseButtonPressed(key) return UserInputService._keys[tostring(key)] == true end
function instanceMethods:GetFocusedTextBox() return nil end
registerClassMethods("UserInputService", { "GetMouseLocation", "IsKeyDown", "IsMouseButtonPressed", "GetFocusedTextBox" })

ContextActionService = service("ContextActionService")
ContextActionService._actions = {}
function instanceMethods:BindAction(name, fn, createTouchButton, ...)
    ContextActionService._actions[name] = { Function = fn, Inputs = pack(...), CreateTouchButton = createTouchButton == true }
end
function instanceMethods:UnbindAction(name) ContextActionService._actions[name] = nil end
function instanceMethods:GetAllBoundActionInfo() return table.clone(ContextActionService._actions) end
registerClassMethods("ContextActionService", { "BindAction", "UnbindAction", "GetAllBoundActionInfo" })

local remoteFixtures = __scenario.remote_fixtures or {}
local function waitRemoteFixture(fixture)
    if not fixture then return end
    local latency = tonumber(fixture.latency_seconds or fixture.latency or 0) or 0
    if fixture.latency_ms ~= nil then latency = (tonumber(fixture.latency_ms) or 0) / 1000 end
    if latency > 0 then task.wait(latency) end
    if fixture.error ~= nil then error(tostring(fixture.error), 3) end
end
function instanceMethods:Fire(...)
    if self.ClassName == "BindableEvent" then fireSignalValue(self.Event, ...) return end
    error("Fire is only valid on BindableEvent", 2)
end
function instanceMethods:Invoke(...)
    if self.ClassName == "BindableFunction" then
        if type(self.OnInvoke) ~= "function" then error("OnInvoke is not set", 2) end
        return self.OnInvoke(...)
    end
    error("Invoke is only valid on BindableFunction", 2)
end
function instanceMethods:FireServer(...)
    if self.ClassName ~= "RemoteEvent" and self.ClassName ~= "UnreliableRemoteEvent" then error("FireServer is only valid on RemoteEvent", 2) end
    local fixture = remoteFixtures[self:GetFullName()]
    waitRemoteFixture(fixture)
    if fixture and fixture.echo_client then fireSignalValue(self.OnClientEvent, ...) end
end
function instanceMethods:InvokeServer(...)
    if self.ClassName ~= "RemoteFunction" then error("InvokeServer is only valid on RemoteFunction", 2) end
    local fixture = remoteFixtures[self:GetFullName()]
    waitRemoteFixture(fixture)
    if fixture then return table.unpack(fixture.returns or {}) end
    if type(self.OnClientInvoke) == "function" then return self.OnClientInvoke(...) end
    trace("missing_fixture", "RemoteFunction." .. self:GetFullName())
    return nil
end
registerClassMethods("BindableEvent", { "Fire" })
registerClassMethods("BindableFunction", { "Invoke" })
registerClassMethods("RemoteEvent", { "FireServer" })
registerClassMethods("UnreliableRemoteEvent", { "FireServer" })
registerClassMethods("RemoteFunction", { "InvokeServer" })

function instanceMethods:Play()
    if self.ClassName ~= "Sound" then error("Play is only valid on Sound", 2) end
    self.Playing = true
    __host.instanceSetDefault(self, "IsPlaying", true)
    __host.instanceSetDefault(self, "IsPaused", false)
    fireSignalValue(self.Played, self.SoundId)
end
function instanceMethods:Pause()
    if self.ClassName ~= "Sound" then error("Pause is only valid on Sound", 2) end
    self.Playing = false
    __host.instanceSetDefault(self, "IsPlaying", false)
    __host.instanceSetDefault(self, "IsPaused", true)
    fireSignalValue(self.Paused)
end
function instanceMethods:Resume()
    if self.ClassName ~= "Sound" then error("Resume is only valid on Sound", 2) end
    self.Playing = true
    __host.instanceSetDefault(self, "IsPlaying", true)
    __host.instanceSetDefault(self, "IsPaused", false)
    fireSignalValue(self.Resumed)
end
function instanceMethods:Stop()
    if self.ClassName ~= "Sound" then error("Stop is only valid on Sound", 2) end
    self.Playing = false
    self.TimePosition = 0
    __host.instanceSetDefault(self, "IsPlaying", false)
    __host.instanceSetDefault(self, "IsPaused", false)
    fireSignalValue(self.Stopped)
end
registerClassMethods("Sound", { "Play", "Pause", "Resume", "Stop" })

local function rayAabb(origin, direction, part)
    local half = part.Size * 0.5
    local min = part.Position - half
    local max = part.Position + half
    local tmin, tmax = 0, 1
    for _, axis in ipairs({"X", "Y", "Z"}) do
        local o, d, lo, hi = origin[axis], direction[axis], min[axis], max[axis]
        if math.abs(d) < 1e-9 then
            if o < lo or o > hi then return nil end
        else
            local a, b = (lo - o) / d, (hi - o) / d
            if a > b then a, b = b, a end
            tmin, tmax = math.max(tmin, a), math.min(tmax, b)
            if tmin > tmax then return nil end
        end
    end
    return tmin
end
local function listedByFilter(instance, params)
    if not params then return false end
    for _, root in ipairs(params.FilterDescendantsInstances or {}) do
        if instance == root or instance:IsDescendantOf(root) then return true end
    end
    return false
end
local function passesSpatialFilter(instance, params)
    if not params then return true end
    local listed = listedByFilter(instance, params)
    local include = params.FilterType == (Enum.RaycastFilterType and Enum.RaycastFilterType.Include)
    if include ~= listed then return false end
    if params.RespectCanCollide and instance.CanCollide == false then return false end
    return true
end
function instanceMethods:Raycast(origin, direction, params)
    if self ~= workspace then error("Raycast is only valid on Workspace", 2) end
    local bestPart, bestT
    for _, value in ipairs(workspace:GetDescendants()) do
        if value:IsA("BasePart") and value.CanQuery ~= false and passesSpatialFilter(value, params) then
            local t = rayAabb(origin, direction, value)
            if t and (not bestT or t < bestT) then bestPart, bestT = value, t end
        end
    end
    if not bestPart then return nil end
    local position = origin + direction * bestT
    return makeImmutableTyped("RaycastResult", {
        Instance = bestPart,
        Position = position,
        Distance = direction.Magnitude * bestT,
        Normal = Vector3.new(),
        Material = bestPart.Material or (Enum.Material and Enum.Material.Plastic),
    })
end
local function aabbOverlaps(centerA, sizeA, centerB, sizeB)
    local halfA, halfB = sizeA * 0.5, sizeB * 0.5
    return math.abs(centerA.X - centerB.X) <= halfA.X + halfB.X
        and math.abs(centerA.Y - centerB.Y) <= halfA.Y + halfB.Y
        and math.abs(centerA.Z - centerB.Z) <= halfA.Z + halfB.Z
end
function instanceMethods:GetPartBoundsInBox(cframe, size, params)
    if self ~= workspace then error("GetPartBoundsInBox is only valid on Workspace", 2) end
    local output = {}
    for _, value in ipairs(workspace:GetDescendants()) do
        if value:IsA("BasePart") and value.CanQuery ~= false and passesSpatialFilter(value, params)
            and aabbOverlaps(cframe.Position, size, value.Position, value.Size) then
            table.insert(output, value)
            if params and params.MaxParts and params.MaxParts > 0 and #output >= params.MaxParts then break end
        end
    end
    return output
end
function instanceMethods:GetPartBoundsInRadius(position, radius, params)
    if self ~= workspace then error("GetPartBoundsInRadius is only valid on Workspace", 2) end
    local size = Vector3.new(radius * 2, radius * 2, radius * 2)
    return workspace:GetPartBoundsInBox(CFrame.new(position.X, position.Y, position.Z), size, params)
end
registerClassMethods("WorldRoot", { "Raycast", "GetPartBoundsInBox", "GetPartBoundsInRadius" })

RaycastParams = {}
function RaycastParams.new()
    return __host.valueRaycastParamsNew()
end
OverlapParams = {}
function OverlapParams.new()
    return __host.valueOverlapParamsNew()
end

Path2DControlPoint = {}
function Path2DControlPoint.new(...)
    local argumentCount = select("#", ...)
    if argumentCount ~= 0 and argumentCount ~= 1 and argumentCount ~= 3 then
        error("Trying to create a Path2DControlPoint with wrong number of arguments", 2)
    end
    local position, leftTangent, rightTangent = ...
    if argumentCount >= 1 and typeof(position) ~= "UDim2" then
        error(string.format("invalid argument #1 to 'new' (UDim2 expected, got %s)", typeof(position)), 2)
    end
    if argumentCount >= 2 and typeof(leftTangent) ~= "UDim2" then
        error(string.format("invalid argument #2 to 'new' (UDim2 expected, got %s)", typeof(leftTangent)), 2)
    end
    if argumentCount >= 3 and typeof(rightTangent) ~= "UDim2" then
        error(string.format("invalid argument #3 to 'new' (UDim2 expected, got %s)", typeof(rightTangent)), 2)
    end
    position = argumentCount >= 1 and position or UDim2.new()
    leftTangent = argumentCount >= 2 and leftTangent or UDim2.new()
    rightTangent = argumentCount >= 3 and rightTangent or UDim2.new()
    return makeImmutableTyped("Path2DControlPoint", {
        Position = position,
        LeftTangent = leftTangent,
        RightTangent = rightTangent,
    })
end

local path2DStates = setmetatable({}, { __mode = "k" })
local function path2DState(path)
    local state = path2DStates[path]
    if state == nil then
        state = { controlPoints = {} }
        path2DStates[path] = state
    end
    return state
end
local function copyPath2DPoints(points)
    local copy = table.create(#points)
    for index, point in ipairs(points) do copy[index] = point end
    return copy
end
local function validatePath2DPoint(point)
    if typeof(point) ~= "Path2DControlPoint" then error("Variant cast failed", 3) end
end
local function firePath2DChanged(path)
    local ok, signal = pcall(function() return path.ControlPointChanged end)
    if ok and signal ~= nil then fireSignalValue(signal) end
end
function instanceMethods:SetControlPoints(controlPoints)
    if controlPoints == nil then error("Argument 1 missing or nil", 2) end
    if type(controlPoints) ~= "table" then error("Unable to cast value to Array", 2) end
    local points = copyPath2DPoints(controlPoints)
    if #points > 100 then error("Path2D cannot have more than 100 control points", 2) end
    for _, point in ipairs(points) do validatePath2DPoint(point) end
    path2DState(self).controlPoints = points
    firePath2DChanged(self)
end
function instanceMethods:GetControlPoints()
    return copyPath2DPoints(path2DState(self).controlPoints)
end
function instanceMethods:GetControlPoint(index)
    if type(index) ~= "number" then error("invalid argument #1 to 'GetControlPoint' (number expected)", 2) end
    local point = path2DState(self).controlPoints[index]
    if point == nil then
        error(string.format("Path2D:GetControlPoint() at index %d access out of bounds", index), 2)
    end
    return point
end
function instanceMethods:GetMaxControlPoints()
    return 100
end
local function requireUsablePath2D(path)
    if path.Parent == nil then error("Attempting to use Path2D with invalid parent", 3) end
end
function instanceMethods:InsertControlPoint(index, point)
    requireUsablePath2D(self)
    validatePath2DPoint(point)
    local points = path2DState(self).controlPoints
    if index < 1 or index > #points + 1 then
        error(string.format("Spline inserting control point at index %d access out of bounds", index - 1), 2)
    end
    table.insert(points, index, point)
    firePath2DChanged(self)
end
function instanceMethods:UpdateControlPoint(index, point)
    requireUsablePath2D(self)
    validatePath2DPoint(point)
    local points = path2DState(self).controlPoints
    if points[index] == nil then
        error(string.format("Spline updating control point at index %d access out of bounds", index - 1), 2)
    end
    points[index] = point
    firePath2DChanged(self)
end
function instanceMethods:RemoveControlPoint(index)
    requireUsablePath2D(self)
    local points = path2DState(self).controlPoints
    if points[index] == nil then
        error(string.format("Spline removing control point at index %d access out of bounds", index - 1), 2)
    end
    table.remove(points, index)
    firePath2DChanged(self)
end
local function path2DAbsoluteSize(path)
    local hasAbsoluteSize, absoluteSize = pcall(function() return path.Parent.AbsoluteSize end)
    if hasAbsoluteSize and typeof(absoluteSize) == "Vector2" then return absoluteSize end
    local hasSize, size = pcall(function() return path.Parent.Size end)
    if not hasSize or typeof(size) ~= "UDim2" then return Vector2.zero end
    local parentSize = Vector2.zero
    local hasParentSize, resolvedParentSize = pcall(function() return path.Parent.Parent.AbsoluteSize end)
    if hasParentSize and typeof(resolvedParentSize) == "Vector2" then parentSize = resolvedParentSize end
    return Vector2.new(
        size.X.Scale * parentSize.X + size.X.Offset,
        size.Y.Scale * parentSize.Y + size.Y.Offset
    )
end
local function resolvePath2DUDim2(value, absoluteSize)
    return Vector2.new(
        value.X.Scale * absoluteSize.X + value.X.Offset,
        value.Y.Scale * absoluteSize.Y + value.Y.Offset
    )
end
local function cubicPath2DPoint(startPoint, startTangent, endTangent, endPoint, alpha)
    local inverse = 1 - alpha
    local startWeight = inverse * inverse * inverse
    local startTangentWeight = 3 * inverse * inverse * alpha
    local endTangentWeight = 3 * inverse * alpha * alpha
    local endWeight = alpha * alpha * alpha
    return Vector2.new(
        startPoint.X * startWeight + startTangent.X * startTangentWeight
            + endTangent.X * endTangentWeight + endPoint.X * endWeight,
        startPoint.Y * startWeight + startTangent.Y * startTangentWeight
            + endTangent.Y * endTangentWeight + endPoint.Y * endWeight
    )
end
local function cubicPath2DTangent(startPoint, startTangent, endTangent, endPoint, alpha)
    local inverse = 1 - alpha
    local startWeight = 3 * inverse * inverse
    local middleWeight = 6 * inverse * alpha
    local endWeight = 3 * alpha * alpha
    return Vector2.new(
        (startTangent.X - startPoint.X) * startWeight
            + (endTangent.X - startTangent.X) * middleWeight
            + (endPoint.X - endTangent.X) * endWeight,
        (startTangent.Y - startPoint.Y) * startWeight
            + (endTangent.Y - startTangent.Y) * middleWeight
            + (endPoint.Y - endTangent.Y) * endWeight
    )
end
local function quadraticPath2DPoint(startPoint, controlPoint, endPoint, alpha)
    local inverse = 1 - alpha
    return Vector2.new(
        startPoint.X * inverse * inverse + 2 * controlPoint.X * inverse * alpha + endPoint.X * alpha * alpha,
        startPoint.Y * inverse * inverse + 2 * controlPoint.Y * inverse * alpha + endPoint.Y * alpha * alpha
    )
end
local function quadraticPath2DTangent(startPoint, controlPoint, endPoint, alpha)
    local inverse = 1 - alpha
    return Vector2.new(
        2 * ((controlPoint.X - startPoint.X) * inverse + (endPoint.X - controlPoint.X) * alpha),
        2 * ((controlPoint.Y - startPoint.Y) * inverse + (endPoint.Y - controlPoint.Y) * alpha)
    )
end
local function hasPath2DTangent(tangent)
    return tangent.X ~= 0 or tangent.Y ~= 0
end
local function evaluatePath2DSegment(points, index, absoluteSize, alpha)
    local startPoint = resolvePath2DUDim2(points[index].Position, absoluteSize)
    local endPoint = resolvePath2DUDim2(points[index + 1].Position, absoluteSize)
    local rightTangent = resolvePath2DUDim2(points[index].RightTangent, absoluteSize)
    local leftTangent = resolvePath2DUDim2(points[index + 1].LeftTangent, absoluteSize)
    local hasRight = hasPath2DTangent(rightTangent)
    local hasLeft = hasPath2DTangent(leftTangent)
    if hasRight and hasLeft then
        return cubicPath2DPoint(startPoint, startPoint + rightTangent, endPoint + leftTangent, endPoint, alpha)
    elseif hasRight then
        return quadraticPath2DPoint(startPoint, startPoint + rightTangent, endPoint, alpha)
    elseif hasLeft then
        return quadraticPath2DPoint(startPoint, endPoint + leftTangent, endPoint, alpha)
    end
    return startPoint + (endPoint - startPoint) * alpha
end
local function evaluatePath2DTangent(points, index, absoluteSize, alpha)
    local startPoint = resolvePath2DUDim2(points[index].Position, absoluteSize)
    local endPoint = resolvePath2DUDim2(points[index + 1].Position, absoluteSize)
    local rightTangent = resolvePath2DUDim2(points[index].RightTangent, absoluteSize)
    local leftTangent = resolvePath2DUDim2(points[index + 1].LeftTangent, absoluteSize)
    local hasRight = hasPath2DTangent(rightTangent)
    local hasLeft = hasPath2DTangent(leftTangent)
    if hasRight and hasLeft then
        return cubicPath2DTangent(startPoint, startPoint + rightTangent, endPoint + leftTangent, endPoint, alpha)
    elseif hasRight then
        return quadraticPath2DTangent(startPoint, startPoint + rightTangent, endPoint, alpha)
    elseif hasLeft then
        return quadraticPath2DTangent(startPoint, endPoint + leftTangent, endPoint, alpha)
    end
    return endPoint - startPoint
end
function instanceMethods:GetLength()
    local points = path2DState(self).controlPoints
    if self.Parent == nil or #points < 2 then return 0 end
    local absoluteSize = path2DAbsoluteSize(self)
    local length = 0
    for index = 1, #points - 1 do
        local startPoint = resolvePath2DUDim2(points[index].Position, absoluteSize)
        local previous = startPoint
        for sample = 1, 512 do
            local current = evaluatePath2DSegment(points, index, absoluteSize, sample / 512)
            length += (current - previous).Magnitude
            previous = current
        end
    end
    return length
end
function instanceMethods:GetPositionOnCurve(t)
    local points = path2DState(self).controlPoints
    if #points == 0 then return UDim2.new() end
    if #points == 1 then return points[1].Position end
    local absoluteSize = path2DAbsoluteSize(self)
    if absoluteSize.X == 0 or absoluteSize.Y == 0 then return UDim2.new() end
    t = math.clamp(t, 0, 1)
    local scaled = t * (#points - 1)
    local index = math.min(#points - 1, math.floor(scaled) + 1)
    local alpha = scaled - (index - 1)
    local position = evaluatePath2DSegment(points, index, absoluteSize, alpha)
    return UDim2.fromScale(position.X / absoluteSize.X, position.Y / absoluteSize.Y)
end
local function path2DArcParameter(path, t)
    local points = path2DState(path).controlPoints
    if #points < 2 then return 0 end
    local absoluteSize = path2DAbsoluteSize(path)
    local normalized = math.clamp(t, 0, 1)
    local usesRelease729FractionQuirk = math.abs(normalized - 6 / 7) <= 1e-6
    local samplesPerSegment = usesRelease729FractionQuirk and 16 or 512
    local samples = {}
    local sampledLength = 0
    for index = 1, #points - 1 do
        local startPoint = resolvePath2DUDim2(points[index].Position, absoluteSize)
        local previous = startPoint
        for sample = 1, samplesPerSegment do
            local alpha = sample / samplesPerSegment
            local current = evaluatePath2DSegment(points, index, absoluteSize, alpha)
            local length = (current - previous).Magnitude
            sampledLength += length
            samples[#samples + 1] = { index = index, alpha = alpha, length = length }
            previous = current
        end
    end
    if sampledLength == 0 then return 0 end
    local targetLengthBasis = sampledLength
    if usesRelease729FractionQuirk then
        targetLengthBasis = 0
        for index = 1, #points - 1 do
            local previous = resolvePath2DUDim2(points[index].Position, absoluteSize)
            for sample = 1, 64 do
                local current = evaluatePath2DSegment(points, index, absoluteSize, sample / 64)
                targetLengthBasis += (current - previous).Magnitude
                previous = current
            end
        end
    end
    local targetLength = normalized * targetLengthBasis
    local traversed = 0
    for _, sample in ipairs(samples) do
        if traversed + sample.length >= targetLength then
            local fraction = sample.length == 0 and 0 or (targetLength - traversed) / sample.length
            local alpha = sample.alpha - (1 - fraction) / samplesPerSegment
            return ((sample.index - 1) + alpha) / (#points - 1)
        end
        traversed += sample.length
    end
    return 1
end
function instanceMethods:GetPositionOnCurveArcLength(t)
    return self:GetPositionOnCurve(path2DArcParameter(self, t))
end
function instanceMethods:GetTangentOnCurve(t)
    local points = path2DState(self).controlPoints
    if #points < 2 then return Vector2.zero end
    local absoluteSize = path2DAbsoluteSize(self)
    t = math.clamp(t, 0, 1)
    local scaled = t * (#points - 1)
    local index = math.min(#points - 1, math.floor(scaled) + 1)
    local alpha = scaled - (index - 1)
    return evaluatePath2DTangent(points, index, absoluteSize, alpha)
end
function instanceMethods:GetTangentOnCurveArcLength(t)
    return self:GetTangentOnCurve(path2DArcParameter(self, t))
end
function instanceMethods:GetBoundingRect()
    local points = path2DState(self).controlPoints
    if #points == 0 then return Rect.new() end
    local minimum, maximum
    for _, point in ipairs(points) do
        local position = point.Position
        local current = Vector2.new(position.X.Offset, position.Y.Offset)
        minimum = minimum and Vector2.new(math.min(minimum.X, current.X), math.min(minimum.Y, current.Y)) or current
        maximum = maximum and Vector2.new(math.max(maximum.X, current.X), math.max(maximum.Y, current.Y)) or current
    end
    return Rect.new(minimum, maximum)
end
registerClassMethods("Path2D", {
    "SetControlPoints", "GetControlPoints", "GetControlPoint", "GetMaxControlPoints", "InsertControlPoint",
    "UpdateControlPoint", "RemoveControlPoint", "GetLength", "GetPositionOnCurve", "GetPositionOnCurveArcLength",
    "GetTangentOnCurve", "GetTangentOnCurveArcLength", "GetBoundingRect",
})

NumberRange = {}
function NumberRange.new(minimum, maximum)
    return __host.valueNumberRangeNew(minimum, maximum)
end
NumberSequenceKeypoint = {}
function NumberSequenceKeypoint.new(time, value, envelope)
    return __host.valueNumberKeypointNew(time, value, envelope)
end
NumberSequence = {}
function NumberSequence.new(value, value2)
    return __host.valueNumberSequenceNew(value, value2)
end
ColorSequenceKeypoint = {}
function ColorSequenceKeypoint.new(time, value)
    return __host.valueColorKeypointNew(time, value)
end
ColorSequence = {}
function ColorSequence.new(value, value2)
    return __host.valueColorSequenceNew(value, value2)
end
Rect = {}
function Rect.new(a, b, c, d)
    local minimum, maximum
    if typeof(a) == "Vector2" then minimum, maximum = a, b else minimum, maximum = Vector2.new(a or 0, b or 0), Vector2.new(c or 0, d or 0) end
    return makeImmutableTyped("Rect", { Min = minimum, Max = maximum, Width = maximum.X - minimum.X, Height = maximum.Y - minimum.Y })
end
Region3 = {}
function Region3.new(minimum, maximum)
    local size = maximum - minimum
    return makeImmutableTyped("Region3", { CFrame = CFrame.new((minimum + maximum) * 0.5), Size = size })
end
PhysicalProperties = {}
function PhysicalProperties.new(density, friction, elasticity, frictionWeight, elasticityWeight)
    return makeImmutableTyped("PhysicalProperties", { Density = density or 0.7, Friction = friction or 0.3, Elasticity = elasticity or 0.5, FrictionWeight = frictionWeight or 1, ElasticityWeight = elasticityWeight or 1 })
end
BrickColor = {}
function BrickColor.new(value)
    return makeImmutableTyped("BrickColor", { Number = type(value) == "number" and value or 194, Name = type(value) == "string" and value or "Medium stone grey", Color = Color3.fromRGB(163, 162, 165) }, function(self) return self.Name end)
end
function BrickColor.random() return BrickColor.new(194) end

Vector3int16 = {}
function Vector3int16.new(x, y, z)
    return makeImmutableTyped("Vector3int16", {
        X = math.floor(tonumber(x) or 0),
        Y = math.floor(tonumber(y) or 0),
        Z = math.floor(tonumber(z) or 0),
    }, function(self) return tostring(self.X) .. ", " .. tostring(self.Y) .. ", " .. tostring(self.Z) end)
end
Vector2int16 = {}
function Vector2int16.new(x, y)
    return makeImmutableTyped("Vector2int16", {
        X = math.floor(tonumber(x) or 0),
        Y = math.floor(tonumber(y) or 0),
    }, function(self) return tostring(self.X) .. ", " .. tostring(self.Y) end)
end

Random = table.freeze({ new = __host.valueRandomBindNew() })

DateTime = {}
function DateTime.fromUnixTimestamp(value)
    return __host.valueDateTimeNewMillis(math.floor((value == nil and unixNow() or value) * 1000))
end
function DateTime.fromUnixTimestampMillis(value)
    return __host.valueDateTimeNewMillis(math.floor(value == nil and unixNow() * 1000 or value))
end
function DateTime.now() return DateTime.fromUnixTimestampMillis(math.floor(unixNow() * 1000)) end

local moduleEnvironments = setmetatable({}, { __mode = "k" })
local moduleNativeIds = setmetatable({}, { __mode = "k" })

local function nativeModuleId(target)
    local id = moduleNativeIds[target]
    if id ~= nil then return id end
    local source = __host.instanceInternalProperty(target, "Source") or ""
    if type(source) ~= "string" then error("ModuleScript source fixture must be a string", 3) end
    id = __host.nativeModuleDeclare(target:GetFullName(), source)
    moduleNativeIds[target] = id
    return id
end

local function finishNativeModule(id, succeeded, returnCount, value)
    local ok, finishError = __host.nativeModuleFinish(id, succeeded, returnCount, value)
    if not ok then error(finishError or "ModuleScript completion failed", 3) end
end

require = function(target)
    if typeof(target) ~= "Instance" or target.ClassName ~= "ModuleScript" then error("require expects a ModuleScript", 2) end
    local id = nativeModuleId(target)
    local shouldLoad, cached = __host.nativeModuleRequire(id)
    if not shouldLoad then return cached end

    local fn, compileError = __host.moduleLoadstring(__host.instanceInternalProperty(target, "Source") or "", "=" .. target:GetFullName())
    if not fn then
        finishNativeModule(id, false, 0, compileError)
        error(compileError, 2)
    end
    local callerEnvironment = getfenv(0)
    local callerMetatable = getmetatable(callerEnvironment)
    local baseEnvironment = callerMetatable and rawget(callerMetatable, "__index") or callerEnvironment
    local environment = {
        script = target,
        _G = rawget(callerEnvironment, "_G"),
    }
    setmetatable(environment, { __index = baseEnvironment })
    moduleEnvironments[target] = environment
    setfenv(fn, environment)
    local returned = pack(pcall(fn))
    if not returned[1] then
        finishNativeModule(id, false, 0, returned[2])
        error(returned[2], 2)
    end
    finishNativeModule(id, true, returned.n - 1, returned[2])
    return returned[2]
end

for _, name in ipairs({"ReplicatedStorage", "ReplicatedFirst", "Lighting", "StarterGui", "CoreGui", "StarterPack", "StarterPlayer", "SoundService", "TextService", "ContentProvider", "GuiService", "MarketplaceService", "TeleportService", "Stats", "LogService"}) do
    local ok, value = pcall(service, name)
    if ok then _G[name] = value end
end

if __cfg.studioRunScriptCompatibility then
    local starterPlayer = service("StarterPlayer")
    internalInstance("StarterPlayerScripts", starterPlayer)
    internalInstance("StarterCharacterScripts", starterPlayer)
end

local scenarioInstances = { game = game, workspace = workspace, Workspace = workspace }
local scenarioVersion = tonumber(__scenario.version) or 1
local moduleSources = scenarioVersion >= 2 and (__scenario.module_sources or {}) or {}
for name, value in pairs(services) do scenarioInstances[name] = value end
for _, descriptor in ipairs(__scenario.instances or {}) do
    local instance = Instance.new(descriptor.class or descriptor.ClassName or "Folder")
    instance.Name = descriptor.name or descriptor.Name or instance.Name
    scenarioInstances[tostring(descriptor.id or #scenarioInstances + 1)] = instance
end
for _, descriptor in ipairs(__scenario.instances or {}) do
    local instance = scenarioInstances[tostring(descriptor.id or "")]
    if instance then
        for key, value in pairs(descriptor.properties or {}) do
            if not (scenarioVersion >= 2 and instance.ClassName == "ModuleScript" and key == "Source") then
                instance[key] = value
            end
        end
        if instance.ClassName == "ModuleScript" then
            local source = scenarioVersion == 1 and descriptor.source or moduleSources[tostring(descriptor.id or "")]
            if source ~= nil then
                if type(source) ~= "string" then error("ModuleScript source fixture must be a string", 2) end
                __host.instanceSetDefault(instance, "Source", source)
            end
        end
        for key, value in pairs(descriptor.attributes or {}) do instance:SetAttribute(key, value) end
        for _, tag in ipairs(descriptor.tags or {}) do instance:AddTag(tag) end
        local parent = descriptor.parent and scenarioInstances[tostring(descriptor.parent)] or workspace
        instance.Parent = parent
        if instance.ClassName == "ModuleScript" then nativeModuleId(instance) end
    end
end

local function resolvePath(path)
    local cursor = game
    for part in string.gmatch(tostring(path), "[^%.]+") do
        if part == "game" then cursor = game
        elseif part == "workspace" or part == "Workspace" then cursor = workspace
        elseif cursor then cursor = cursor[part] end
    end
    return cursor
end
local function findScenarioPlayer(event)
    local userId = tonumber(event.user_id or event.UserId)
    local name = event.name or event.player_name
    for _, player in ipairs(playersList) do
        if (userId ~= nil and player.UserId == userId) or (name ~= nil and player.Name == name) then return player end
    end
    return nil
end
local function addScenarioCharacter(player, event)
    if player.Character then return player.Character end
    local model = internalInstance("Model", workspace)
    model.Name = event.character_name or player.Name
    local root = Instance.new("Part", model)
    root.Name = "HumanoidRootPart"
    local position = event.position or {0, 5, 0}
    root.Position = Vector3.new(table.unpack(position))
    root.CFrame = CFrame.new(root.Position)
    local body = Instance.new("Humanoid", model)
    body.Name = "Humanoid"
    model.PrimaryPart = root
    for property, value in pairs(event.character_properties or {}) do model[property] = value end
    __host.instanceSetDefault(player, "Character", model)
    fireSignalValue(player.CharacterAdded, model)
    return model
end
local function removeScenarioCharacter(player)
    local model = player and player.Character
    if not model then return end
    fireSignalValue(player.CharacterRemoving, model)
    __host.instanceSetDefault(player, "Character", nil)
    model:Destroy()
end

for _, event in ipairs(__scenario.scheduled_property_changes or __scenario.property_changes or {}) do
    task.delay(tonumber(event.at) or 0, function()
        local target = resolvePath(event.target)
        if not target then error("scheduled property target was not found: " .. tostring(event.target), 0) end
        local property = tostring(event.property or "")
        if property == "" then error("scheduled property change requires a property", 0) end
        local value = event.value_path and resolvePath(event.value_path) or event.value
        target[property] = value
    end)
end

for _, event in ipairs(__scenario.player_lifecycle or {}) do
    task.delay(tonumber(event.at) or 0, function()
        local action = string.lower(tostring(event.action or event.state or "add"))
        if action == "add" or action == "join" then
            local player = findScenarioPlayer(event)
            if not player then
                player = internalInstance("Player", Players)
                player.Name = event.name or event.player_name or ("Player" .. tostring(event.user_id or #playersList + 1))
                __host.instanceSetDefault(player, "DisplayName", event.display_name or player.Name)
                __host.instanceSetDefault(player, "UserId", tonumber(event.user_id) or 0)
                __host.instanceSetDefault(player, "AccountAge", tonumber(event.account_age) or 0)
                internalInstance("PlayerGui", player)
                internalInstance("PlayerScripts", player)
                internalInstance("Backpack", player)
                table.insert(playersList, player)
                fireSignalValue(Players.PlayerAdded, player)
            end
            if event.character == true then
                task.defer(function()
                    if table.find(playersList, player) then addScenarioCharacter(player, event) end
                end)
            end
        elseif action == "remove" or action == "leave" then
            local player = findScenarioPlayer(event)
            if player then
                removeScenarioCharacter(player)
                fireSignalValue(Players.PlayerRemoving, player)
                local index = table.find(playersList, player)
                if index then table.remove(playersList, index) end
                player:Destroy()
            end
        elseif action == "character_add" or action == "character_added" then
            local player = findScenarioPlayer(event)
            if player then addScenarioCharacter(player, event) end
        elseif action == "character_remove" or action == "character_removing" then
            removeScenarioCharacter(findScenarioPlayer(event))
        else
            error("unsupported player lifecycle action: " .. action, 0)
        end
    end)
end

for _, event in ipairs(__scenario.scheduled_events or {}) do
    task.delay(tonumber(event.at) or 0, function()
        local target = resolvePath(event.target)
        if typeof(target) == "RBXScriptSignal" then
            fireSignalValue(target, table.unpack(event.args or {}))
        elseif target and type(target.Fire) == "function" then
            target:Fire(table.unpack(event.args or {}))
        end
    end)
end
for _, event in ipairs(__scenario.input_events or {}) do
    task.delay(tonumber(event.at) or 0, function()
        local state = string.lower(tostring(event.state or "began"))
        local keyCode = Enum.KeyCode and Enum.KeyCode[event.key_code or "Unknown"] or nil
        local inputType = Enum.UserInputType and Enum.UserInputType[event.input_type or "Keyboard"] or nil
        local input = makeTyped("InputObject", {
            KeyCode = keyCode,
            UserInputType = inputType,
            UserInputState = Enum.UserInputState and Enum.UserInputState[state == "ended" and "End" or (state == "changed" and "Change" or "Begin")] or nil,
            Position = Vector3.new(table.unpack(event.position or {0, 0, 0})),
            Delta = Vector3.new(table.unpack(event.delta or {0, 0, 0})),
        })
        local keyName = tostring(keyCode or inputType)
        UserInputService._keys[keyName] = state ~= "ended"
        if event.mouse_position then UserInputService._mouse = Vector2.new(event.mouse_position[1] or 0, event.mouse_position[2] or 0) end
        local signal = state == "ended" and UserInputService.InputEnded or (state == "changed" and UserInputService.InputChanged or UserInputService.InputBegan)
        fireSignalValue(signal, input, event.game_processed == true)
        for name, action in pairs(ContextActionService._actions) do
            for i = 1, action.Inputs.n or #action.Inputs do
                if action.Inputs[i] == keyCode or action.Inputs[i] == inputType then
                    task.spawn(action.Function, name, input.UserInputState, input)
                    break
                end
            end
        end
    end)
end

script = internalInstance("LocalScript", Players.LocalPlayer.PlayerScripts)
script.Name = "RuntimeScript"

-- Roblox exposes one mutable `shared` table per DataModel script context.
-- RuntimeContext isolation keeps it from leaking across independent runs.
shared = {}

time = clockNow
elapsedTime = time
tick = unixNow
if __cfg.clock == "virtual" then
    os.clock = time
    os.time = function() return math.floor(unixNow()) end
end
ypcall = pcall

if __cfg.profile == "executor-client" then
    -- Executor state must never expose the frozen host bootstrap environment.
    -- Keep a writable per-runtime overlay whose reads follow the calling
    -- script environment; writes remain isolated to this lua_State.
    local executorRuntimeEnvironment = {}
    setmetatable(executorRuntimeEnvironment, {
        __index = function(_, key)
            return getfenv(0)[key]
        end,
    })
    getgenv = __host.executorBindNative("getgenv", function() return getfenv(0) end)
    getrenv = __host.executorBindNative("getrenv", function() return executorRuntimeEnvironment end)
    getsenv = __host.executorBindNative("getsenv", function(target)
        if target == nil or target == script then return getfenv(0) end
        return moduleEnvironments[target]
    end)
    gethui = __host.executorBindNative("gethui", function() return CoreGui end)
    cloneref = __host.executorBindNative("cloneref", function(value) return value end)
    compareinstances = __host.executorBindNative("compareinstances", function(a, b) return a == b end)
    identifyexecutor = identifyexecutor or function() return "RobloxLuauRuntime", "3.0" end
    getexecutorname = getexecutorname or function() return "RobloxLuauRuntime" end
    checkcaller = __host.executorBindNative("checkcaller", function() return false end)
    request = nativeRequest
    http_request = nativeRequest
    syn = { request = nativeRequest }
    http = { request = nativeRequest }
end

if __cfg.analysisHooks then
    setmetatable(__base_environment, {
        __index = function(_, key)
            trace("missing_global", tostring(key))
            return nil
        end,
    })
end
)RBXV2";
}

} // namespace rbx::v2
