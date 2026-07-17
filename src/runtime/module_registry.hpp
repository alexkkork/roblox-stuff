#pragma once

#include "runtime_value.hpp"
#include "scheduler.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace rbx::runtime
{

using ModuleId = uint64_t;

enum class ModuleState : uint8_t
{
    Unloaded,
    Loading,
    Loaded,
    Failed,
};

enum class RequireAction : uint8_t
{
    StartLoading,
    ReturnCached,
    Wait,
    RaiseCachedError,
    CycleError,
    UnknownModule,
};

struct RequireDecision
{
    RequireAction action = RequireAction::UnknownModule;
    ModuleId module = 0;
    std::shared_ptr<const RuntimeValue> cachedValue;
    std::string error;
};

struct ModuleSnapshot
{
    ModuleId id = 0;
    std::string debugName;
    ModuleState state = ModuleState::Unloaded;
    TaskId loaderTask = 0;
    std::size_t waiterCount = 0;
    bool hasSource = false;
    bool hasValue = false;
    std::string error;
};

class ModuleRegistry
{
public:
    class HostSourceAccess
    {
    private:
        HostSourceAccess() = default;
        friend class ModuleRegistry;
    };

    explicit ModuleRegistry(Scheduler& scheduler);
    ~ModuleRegistry();

    ModuleRegistry(const ModuleRegistry&) = delete;
    ModuleRegistry& operator=(const ModuleRegistry&) = delete;

    bool declare(ModuleId id, std::string debugName);
    bool erase(ModuleId id);
    bool contains(ModuleId id) const;

    HostSourceAccess hostSourceAccess() const;
    void setSource(HostSourceAccess, ModuleId id, std::string source);
    std::optional<std::string_view> source(HostSourceAccess, ModuleId id) const;

    // requesterModule is the currently evaluating ModuleScript, when any.
    // requesterTask is suspended for concurrent loads and resumed via the
    // scheduler's Module queue when the load reaches a terminal state.
    RequireDecision require(ModuleId id, std::optional<ModuleId> requesterModule, TaskId requesterTask);

    bool finishSuccess(ModuleId id, TaskId loaderTask, RuntimeValue value, std::size_t returnCount = 1);
    bool finishFailure(ModuleId id, TaskId loaderTask, std::string error);
    bool reset(ModuleId id);

    ModuleState state(ModuleId id) const;
    std::shared_ptr<const RuntimeValue> cachedValue(ModuleId id) const;
    std::optional<std::string> cachedError(ModuleId id) const;
    std::optional<ModuleSnapshot> snapshot(ModuleId id) const;
    std::vector<ModuleSnapshot> snapshots() const;

private:
    struct Waiter
    {
        TaskId task = 0;
        CancellationObserverId cancellationObserver = 0;
    };

    struct Record
    {
        ModuleId id = 0;
        std::string debugName;
        std::string source;
        bool sourcePresent = false;
        ModuleState state = ModuleState::Unloaded;
        TaskId loaderTask = 0;
        CancellationObserverId loaderCancellationObserver = 0;
        std::shared_ptr<const RuntimeValue> value;
        std::string error;
        std::vector<Waiter> waiters;
    };

    bool introducesCycle(ModuleId from, ModuleId to) const;
    bool hasPath(ModuleId from, ModuleId target, std::unordered_set<ModuleId>& visited) const;
    void addDependency(ModuleId from, ModuleId to);
    void removeDependencies(ModuleId id);
    void wakeWaiters(Record& record, bool success);
    void removeWaiter(ModuleId id, TaskId task);
    void assertOwnerThread() const;

    Scheduler& scheduler_;
    std::unordered_map<ModuleId, Record> records_;
    std::unordered_map<ModuleId, std::unordered_set<ModuleId>> dependencies_;
};

std::string_view toString(ModuleState state);
std::string_view toString(RequireAction action);

} // namespace rbx::runtime
