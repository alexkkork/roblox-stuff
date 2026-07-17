#include "runtime/runtime_context.hpp"
#include "runtime_v2.hpp"

#include "lualib.h"

#include <nlohmann/json.hpp>

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace
{

constexpr const char* kMinimalApiDump = R"JSON({
  "Version": "729",
  "Classes": [
    {
      "Name": "Object",
      "Superclass": "<<<ROOT>>>",
      "Members": [
        {
          "MemberType": "Property",
          "Name": "ClassName",
          "ValueType": {"Category": "Primitive", "Name": "string"},
          "Security": {"Read": "None", "Write": "None"},
          "Tags": ["ReadOnly"]
        }
      ]
    },
    {
      "Name": "Instance",
      "Superclass": "Object",
      "Members": [
        {
          "MemberType": "Property",
          "Name": "Name",
          "ValueType": {"Category": "Primitive", "Name": "string"},
          "Security": {"Read": "None", "Write": "None"}
        },
        {
          "MemberType": "Property",
          "Name": "Parent",
          "ValueType": {"Category": "Class", "Name": "Instance"},
          "Security": {"Read": "None", "Write": "None"}
        },
        {
          "MemberType": "Property",
          "Name": "Archivable",
          "ValueType": {"Category": "Primitive", "Name": "bool"},
          "Security": {"Read": "None", "Write": "None"}
        }
      ]
    },
    {"Name": "Folder", "Superclass": "Instance", "Members": []},
    {"Name": "DataModel", "Superclass": "Instance", "Members": []}
  ],
  "Enums": []
})JSON";

struct Vm
{
    lua_State* state = nullptr;
    std::unique_ptr<rbx::runtime::RuntimeContext> context;
    bool engineInitialized = false;

    Vm()
    {
        state = luaL_newstate();
        if (!state)
            throw std::runtime_error("failed to create Luau VM");
        context = std::make_unique<rbx::runtime::RuntimeContext>(state);
        context->attach();
        luaL_openlibs(state);
        rbx::v2::initialize(state, kMinimalApiDump, {});
        engineInitialized = true;
    }

    ~Vm()
    {
        if (!state)
            return;
        if (engineInitialized)
            rbx::v2::shutdown(state);
        if (context)
            context->detach();
        context.reset();
        lua_close(state);
    }
};

void createInstance(Vm& vm, const char* className, lua_State* executionState = nullptr)
{
    lua_State* state = executionState ? executionState : vm.state;
    lua_getglobal(state, "__rbx_instance_new");
    if (!lua_isfunction(state, -1))
        throw std::runtime_error("runtime v2 constructor was not installed");
    lua_pushstring(state, className);
    if (lua_pcall(state, 1, 1, 0) != LUA_OK)
    {
        std::string message = lua_isstring(state, -1) ? lua_tostring(state, -1) : "unknown Instance creation error";
        lua_pop(state, 1);
        throw std::runtime_error(message);
    }
    if (!rbx::v2::isInstance(state, -1) || rbx::v2::instanceClassName(state, -1) != className)
        throw std::runtime_error("created value did not resolve through this VM's Instance registry");
    lua_pop(state, 1);
}

std::size_t instanceCount(Vm& vm)
{
    return nlohmann::json::parse(rbx::v2::engineStatsJson(vm.state)).at("instances").get<std::size_t>();
}

double createUnseededRandomAndDraw(Vm& vm)
{
    lua_State* state = vm.state;
    lua_getglobal(state, "__rbx_value_random_bind_new");
    if (!lua_isfunction(state, -1) || lua_pcall(state, 0, 1, 0) != LUA_OK || !lua_isfunction(state, -1))
        throw std::runtime_error("runtime v2 Random constructor binder was not installed");
    if (lua_pcall(state, 0, 1, 0) != LUA_OK || !lua_isuserdata(state, -1))
        throw std::runtime_error("runtime v2 Random constructor did not return userdata");

    lua_getfield(state, -1, "NextNumber");
    if (!lua_isfunction(state, -1))
        throw std::runtime_error("native Random did not expose NextNumber");
    lua_pushvalue(state, -2);
    if (lua_pcall(state, 1, 1, 0) != LUA_OK || !lua_isnumber(state, -1))
        throw std::runtime_error("native Random NextNumber failed");
    const double result = lua_tonumber(state, -1);
    lua_pop(state, 2);
    return result;
}

} // namespace

int main()
{
    try
    {
        Vm first;
        Vm second;

        const double firstRandom = createUnseededRandomAndDraw(first);
        const double secondRandom = createUnseededRandomAndDraw(first);
        const double isolatedRandom = createUnseededRandomAndDraw(second);
        if (firstRandom != isolatedRandom || firstRandom == secondRandom)
            throw std::runtime_error("Random no-seed streams leaked between simultaneous Luau VMs");

        createInstance(first, "DataModel");
        createInstance(first, "Folder");
        createInstance(second, "DataModel");
        lua_State* secondCoroutine = lua_newthread(second.state);
        createInstance(second, "Folder", secondCoroutine);
        if (instanceCount(first) != 2 || instanceCount(second) != 2)
            throw std::runtime_error("Instance registries leaked between simultaneous Luau VMs");

        rbx::v2::shutdown(first.state);
        first.engineInitialized = false;

        createInstance(second, "Folder");
        if (instanceCount(second) != 3)
            throw std::runtime_error("shutting down one VM mutated the other VM's engine");
        lua_pop(second.state, 1);

        std::cout << "runtime-v2-isolation-ok\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "runtime v2 isolation failure: " << error.what() << '\n';
        return 1;
    }
}
