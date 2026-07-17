#pragma once

#include "executor_compat.hpp"
#include "module_registry.hpp"
#include "network_broker.hpp"
#include "scheduler.hpp"
#include "security.hpp"
#include "signal.hpp"

#include "lua.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <typeindex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rbx::runtime
{

enum class ActorLane : uint8_t
{
    Synchronized,
    Desynchronized,
};

struct ScriptEnvironment
{
    uint64_t scriptInstanceId = 0;
    std::string debugName;
    std::string className = "LocalScript";
    std::optional<ModuleId> evaluatingModule;
};

class CancellationToken
{
public:
    bool cancelled() const;
    std::string reason() const;

private:
    struct State;
    explicit CancellationToken(std::shared_ptr<State> state);
    std::shared_ptr<State> state_;
    friend class CancellationSource;
};

class CancellationSource
{
public:
    CancellationSource();

    CancellationToken token() const;
    bool cancel(std::string reason = "cancelled");
    bool cancelled() const;

private:
    std::shared_ptr<CancellationToken::State> state_;
};

struct ThreadContext
{
    uint64_t id = 0;
    lua_State* thread = nullptr;
    ScriptEnvironment script;
    SecurityDescriptor security;
    CancellationSource cancellation;
    TaskId schedulerTask = 0;
    ActorLane actorLane = ActorLane::Synchronized;
    bool callerControlledYield = false;
    // An empty value means the script's automatic category. Roblox scopes the
    // override and profiler annotations to the current coroutine.
    std::string memoryCategory;
    std::vector<std::string> profileLabels;
};

struct RuntimeContextOptions
{
    RuntimeProfile profile = RuntimeProfile::RobloxClient;
    ExecutionMode executionMode = ExecutionMode::Faithful;
    ExecutorPreset executorPreset = ExecutorPreset::Generic;
    FilesystemPolicy filesystem = FilesystemPolicy::ProfileDefault;
    ClockMode clockMode = ClockMode::Virtual;
    int64_t virtualEpochMillis = 0;
    uint64_t deterministicSeed = 0;
    std::size_t memoryLimitBytes = 512 * 1024 * 1024;
    SchedulerOptions scheduler;
    MemoryFilesystemLimits filesystemLimits;
};

class RuntimeContext
{
public:
    RuntimeContext(lua_State* mainState, RuntimeContextOptions options = {});
    ~RuntimeContext();

    RuntimeContext(const RuntimeContext&) = delete;
    RuntimeContext& operator=(const RuntimeContext&) = delete;

    // Installs an exclusive per-VM anchor in lua_Callbacks::userdata and a
    // coroutine lifecycle hook. Existing interrupt/panic hooks are untouched.
    // Attachment fails closed if another owner already uses callback userdata,
    // userthread, or the main thread-data slot.
    void attach();
    void detach();
    bool attached() const;

    static RuntimeContext* from(lua_State* state);
    static const RuntimeContext* from(const lua_State* state);
    static ThreadContext* threadFrom(lua_State* thread);

    ThreadContext& mainThread();
    ThreadContext& thread(lua_State* state);
    const ThreadContext& thread(lua_State* state) const;
    ThreadContext& attachCoroutine(lua_State* state, lua_State* parent = nullptr);
    bool detachCoroutine(lua_State* state);
    std::size_t threadCount() const;
    TaskExecutionMetadata taskMetadata(lua_State* state) const;
    bool bindTask(TaskId task, lua_State* state);
    SecurityDescriptor restrictIdentity(lua_State* state, SecurityIdentity requestedIdentity);

    lua_State* mainState() const;
    const RuntimeContextOptions& options() const;
    uint64_t deterministicSeed() const;
    std::size_t memoryLimitBytes() const;

    Scheduler& scheduler();
    const Scheduler& scheduler() const;
    ModuleRegistry& modules();
    const ModuleRegistry& modules() const;
    SecurityPolicy& securityPolicy();
    const SecurityPolicy& securityPolicy() const;
    ExecutorCompatibility& executor();
    const ExecutorCompatibility& executor() const;

    std::shared_ptr<NativeSignal> createSignal(std::string name, SignalBehavior behavior = SignalBehavior::Immediate);

    NetworkBroker& installNetwork(NetworkPolicyConfig policy, std::shared_ptr<IHttpTransport> transport);
    NetworkBroker* network();
    const NetworkBroker* network() const;

    // Migration hook for legacy subsystems such as runtime_v2's EngineState.
    // The object is owned by this VM and cannot be observed by another state.
    template<typename T>
    void setSubsystem(std::string key, std::shared_ptr<T> value)
    {
        assertOwnerThread();
        if (!value)
            throw std::invalid_argument("subsystem value cannot be null");
        subsystemSlots_[std::move(key)] = SubsystemSlot{std::move(value), std::type_index(typeid(T))};
    }

    template<typename T, typename... Args>
    T& emplaceSubsystem(std::string key, Args&&... args)
    {
        auto value = std::make_shared<T>(std::forward<Args>(args)...);
        T& reference = *value;
        setSubsystem<T>(std::move(key), std::move(value));
        return reference;
    }

    template<typename T>
    T* subsystem(std::string_view key)
    {
        assertOwnerThread();
        auto found = subsystemSlots_.find(std::string(key));
        if (found == subsystemSlots_.end())
            return nullptr;
        if (found->second.type != std::type_index(typeid(T)))
            throw std::logic_error("runtime subsystem type mismatch");
        return static_cast<T*>(found->second.value.get());
    }

    bool removeSubsystem(std::string_view key);
    void clearSubsystems();

private:
    struct Anchor
    {
        uint64_t magic = 0;
        RuntimeContext* context = nullptr;
    };

    struct SubsystemSlot
    {
        std::shared_ptr<void> value;
        std::type_index type{typeid(void)};
    };

    static void userthreadHook(lua_State* parent, lua_State* thread);
    ThreadContext& createThreadContext(lua_State* state, const ThreadContext* parent);
    bool ownsCurrentThread() const;
    void assertOwnerThread() const;

    static constexpr uint64_t kAnchorMagic = UINT64_C(0x5242584354583732); // RBXCTX72

    lua_State* mainState_ = nullptr;
    RuntimeContextOptions options_;
    std::thread::id ownerThread_;
    Anchor anchor_;
    bool attached_ = false;
    uint64_t nextThreadId_ = 1;

    SecurityPolicy securityPolicy_;
    std::shared_ptr<RuntimeClock> clock_;
    Scheduler scheduler_;
    ModuleRegistry modules_;
    ExecutorCompatibility executor_;
    std::unique_ptr<NetworkBroker> network_;
    std::vector<std::shared_ptr<NativeSignal>> ownedSignals_;

    std::unordered_map<lua_State*, std::unique_ptr<ThreadContext>> threads_;
    std::unordered_map<std::string, SubsystemSlot> subsystemSlots_;
};

std::string_view toString(ActorLane lane);

} // namespace rbx::runtime
