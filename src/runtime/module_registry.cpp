#include "module_registry.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace rbx::runtime
{

ModuleRegistry::ModuleRegistry(Scheduler& scheduler)
    : scheduler_(scheduler)
{
}

ModuleRegistry::~ModuleRegistry()
{
    // Scheduler outlives the registry in RuntimeContext. Remove every callback
    // that captured this before releasing records, including active loaders.
    if (!scheduler_.ownsCurrentThread())
        std::terminate();
    for (auto& [_, record] : records_)
    {
        if (record.loaderCancellationObserver != 0 && record.loaderTask != 0)
            scheduler_.removeCancellationObserver(record.loaderTask, record.loaderCancellationObserver);
        for (const Waiter& waiter : record.waiters)
            scheduler_.removeCancellationObserver(waiter.task, waiter.cancellationObserver);
        record.waiters.clear();
    }
}

bool ModuleRegistry::declare(ModuleId id, std::string debugName)
{
    assertOwnerThread();
    if (id == 0)
        throw std::invalid_argument("module id zero is reserved");
    Record record;
    record.id = id;
    record.debugName = debugName.empty() ? "ModuleScript" : std::move(debugName);
    return records_.emplace(id, std::move(record)).second;
}

bool ModuleRegistry::erase(ModuleId id)
{
    assertOwnerThread();
    auto found = records_.find(id);
    if (found == records_.end() || found->second.state == ModuleState::Loading || !found->second.waiters.empty())
        return false;
    removeDependencies(id);
    records_.erase(found);
    return true;
}

bool ModuleRegistry::contains(ModuleId id) const
{
    assertOwnerThread();
    return records_.contains(id);
}

ModuleRegistry::HostSourceAccess ModuleRegistry::hostSourceAccess() const
{
    assertOwnerThread();
    return HostSourceAccess{};
}

void ModuleRegistry::setSource(HostSourceAccess, ModuleId id, std::string sourceValue)
{
    assertOwnerThread();
    auto found = records_.find(id);
    if (found == records_.end())
        throw std::out_of_range("unknown module id");
    if (found->second.state == ModuleState::Loading)
        throw std::logic_error("cannot replace ModuleScript source while it is loading");
    found->second.source = std::move(sourceValue);
    found->second.sourcePresent = true;
    reset(id);
}

std::optional<std::string_view> ModuleRegistry::source(HostSourceAccess, ModuleId id) const
{
    assertOwnerThread();
    auto found = records_.find(id);
    if (found == records_.end() || !found->second.sourcePresent)
        return std::nullopt;
    return found->second.source;
}

RequireDecision ModuleRegistry::require(ModuleId id, std::optional<ModuleId> requesterModule, TaskId requesterTask)
{
    assertOwnerThread();
    auto found = records_.find(id);
    if (found == records_.end())
        return RequireDecision{RequireAction::UnknownModule, id, {}, "attempt to require an unknown ModuleScript"};

    Record& record = found->second;
    if (record.state == ModuleState::Loaded)
        return RequireDecision{RequireAction::ReturnCached, id, record.value, {}};
    if (record.state == ModuleState::Failed)
        return RequireDecision{RequireAction::RaiseCachedError, id, {}, record.error};

    if (requesterModule)
    {
        if (*requesterModule == id || introducesCycle(*requesterModule, id))
            return RequireDecision{RequireAction::CycleError, id, {}, "Requested module was required recursively"};
        addDependency(*requesterModule, id);
    }

    if (record.state == ModuleState::Unloaded)
    {
        if (requesterTask == 0)
            return RequireDecision{RequireAction::UnknownModule, id, {}, "module load requires a scheduler task"};
        record.state = ModuleState::Loading;
        record.loaderTask = requesterTask;
        record.loaderCancellationObserver = scheduler_.addCancellationObserver(requesterTask, [this, id, requesterTask] {
            finishFailure(id, requesterTask, "ModuleScript loader was cancelled");
        });
        if (record.loaderCancellationObserver == 0)
        {
            record.state = ModuleState::Unloaded;
            record.loaderTask = 0;
            return RequireDecision{RequireAction::UnknownModule, id, {}, "module loader task is no longer active"};
        }
        record.error.clear();
        record.value.reset();
        return RequireDecision{RequireAction::StartLoading, id, {}, {}};
    }

    if (record.loaderTask == requesterTask && requesterTask != 0)
        return RequireDecision{RequireAction::CycleError, id, {}, "Requested module was required recursively"};
    if (requesterTask == 0)
        return RequireDecision{RequireAction::UnknownModule, id, {}, "concurrent require needs a scheduler task"};
    if (std::any_of(record.waiters.begin(), record.waiters.end(), [requesterTask](const Waiter& waiter) {
            return waiter.task == requesterTask;
        }))
        return RequireDecision{RequireAction::Wait, id, {}, {}};

    const CancellationObserverId observer = scheduler_.addCancellationObserver(requesterTask, [this, id, requesterTask] {
        removeWaiter(id, requesterTask);
    });
    if (observer == 0)
        return RequireDecision{RequireAction::UnknownModule, id, {}, "requiring task is no longer active"};
    record.waiters.push_back(Waiter{requesterTask, observer});
    return RequireDecision{RequireAction::Wait, id, {}, {}};
}

bool ModuleRegistry::finishSuccess(ModuleId id, TaskId loaderTask, RuntimeValue value, std::size_t returnCount)
{
    assertOwnerThread();
    auto found = records_.find(id);
    if (found == records_.end() || found->second.state != ModuleState::Loading || found->second.loaderTask != loaderTask)
        return false;
    if (returnCount != 1)
    {
        return finishFailure(id, loaderTask, "Module code did not return exactly one value");
    }

    Record& record = found->second;
    scheduler_.removeCancellationObserver(loaderTask, record.loaderCancellationObserver);
    record.loaderCancellationObserver = 0;
    record.state = ModuleState::Loaded;
    record.loaderTask = 0;
    record.value = std::make_shared<const RuntimeValue>(std::move(value));
    record.error.clear();
    removeDependencies(id);
    wakeWaiters(record, true);
    return true;
}

bool ModuleRegistry::finishFailure(ModuleId id, TaskId loaderTask, std::string error)
{
    assertOwnerThread();
    auto found = records_.find(id);
    if (found == records_.end() || found->second.state != ModuleState::Loading || found->second.loaderTask != loaderTask)
        return false;
    Record& record = found->second;
    scheduler_.removeCancellationObserver(loaderTask, record.loaderCancellationObserver);
    record.loaderCancellationObserver = 0;
    record.state = ModuleState::Failed;
    record.loaderTask = 0;
    record.value.reset();
    record.error = error.empty() ? "ModuleScript failed" : std::move(error);
    removeDependencies(id);
    wakeWaiters(record, false);
    return true;
}

bool ModuleRegistry::reset(ModuleId id)
{
    assertOwnerThread();
    auto found = records_.find(id);
    if (found == records_.end() || found->second.state == ModuleState::Loading || !found->second.waiters.empty())
        return false;
    found->second.state = ModuleState::Unloaded;
    found->second.loaderTask = 0;
    found->second.value.reset();
    found->second.error.clear();
    removeDependencies(id);
    return true;
}

ModuleState ModuleRegistry::state(ModuleId id) const
{
    assertOwnerThread();
    auto found = records_.find(id);
    return found == records_.end() ? ModuleState::Unloaded : found->second.state;
}

std::shared_ptr<const RuntimeValue> ModuleRegistry::cachedValue(ModuleId id) const
{
    assertOwnerThread();
    auto found = records_.find(id);
    return found == records_.end() ? nullptr : found->second.value;
}

std::optional<std::string> ModuleRegistry::cachedError(ModuleId id) const
{
    assertOwnerThread();
    auto found = records_.find(id);
    if (found == records_.end() || found->second.state != ModuleState::Failed)
        return std::nullopt;
    return found->second.error;
}

std::optional<ModuleSnapshot> ModuleRegistry::snapshot(ModuleId id) const
{
    assertOwnerThread();
    auto found = records_.find(id);
    if (found == records_.end())
        return std::nullopt;
    const Record& record = found->second;
    return ModuleSnapshot{
        record.id,
        record.debugName,
        record.state,
        record.loaderTask,
        record.waiters.size(),
        record.sourcePresent,
        record.value != nullptr,
        record.error,
    };
}

std::vector<ModuleSnapshot> ModuleRegistry::snapshots() const
{
    assertOwnerThread();
    std::vector<ModuleSnapshot> result;
    result.reserve(records_.size());
    for (const auto& [id, _] : records_)
        result.push_back(*snapshot(id));
    std::sort(result.begin(), result.end(), [](const ModuleSnapshot& lhs, const ModuleSnapshot& rhs) {
        return lhs.id < rhs.id;
    });
    return result;
}

bool ModuleRegistry::introducesCycle(ModuleId from, ModuleId to) const
{
    std::unordered_set<ModuleId> visited;
    return hasPath(to, from, visited);
}

bool ModuleRegistry::hasPath(ModuleId from, ModuleId target, std::unordered_set<ModuleId>& visited) const
{
    if (from == target)
        return true;
    if (!visited.insert(from).second)
        return false;
    auto found = dependencies_.find(from);
    if (found == dependencies_.end())
        return false;
    return std::any_of(found->second.begin(), found->second.end(), [&](ModuleId next) {
        return hasPath(next, target, visited);
    });
}

void ModuleRegistry::addDependency(ModuleId from, ModuleId to)
{
    dependencies_[from].insert(to);
}

void ModuleRegistry::removeDependencies(ModuleId id)
{
    dependencies_.erase(id);
    for (auto& [_, edges] : dependencies_)
        edges.erase(id);
}

void ModuleRegistry::wakeWaiters(Record& record, bool success)
{
    std::vector<Waiter> waiters = std::move(record.waiters);
    record.waiters.clear();
    for (const Waiter& waiter : waiters)
    {
        scheduler_.removeCancellationObserver(waiter.task, waiter.cancellationObserver);
        ResumeData data;
        data.arguments.emplace_back(success);
        data.arguments.emplace_back(static_cast<int64_t>(record.id));
        if (!success)
            data.arguments.emplace_back(record.error);
        data.sourceName = record.debugName;
        scheduler_.resume(waiter.task, std::move(data), QueueKind::Module);
    }
}

void ModuleRegistry::removeWaiter(ModuleId id, TaskId task)
{
    auto found = records_.find(id);
    if (found == records_.end())
        return;
    auto waiter = std::find_if(found->second.waiters.begin(), found->second.waiters.end(), [task](const Waiter& value) {
        return value.task == task;
    });
    if (waiter != found->second.waiters.end())
    {
        scheduler_.removeCancellationObserver(waiter->task, waiter->cancellationObserver);
        found->second.waiters.erase(waiter);
    }
}

void ModuleRegistry::assertOwnerThread() const
{
    if (!scheduler_.ownsCurrentThread())
        throw std::logic_error("module registry may only be accessed by the scheduler owner thread");
}

std::string_view toString(ModuleState state)
{
    switch (state)
    {
    case ModuleState::Unloaded:
        return "unloaded";
    case ModuleState::Loading:
        return "loading";
    case ModuleState::Loaded:
        return "loaded";
    case ModuleState::Failed:
        return "failed";
    }
    return "unknown";
}

std::string_view toString(RequireAction action)
{
    switch (action)
    {
    case RequireAction::StartLoading:
        return "start-loading";
    case RequireAction::ReturnCached:
        return "return-cached";
    case RequireAction::Wait:
        return "wait";
    case RequireAction::RaiseCachedError:
        return "raise-cached-error";
    case RequireAction::CycleError:
        return "cycle-error";
    case RequireAction::UnknownModule:
        return "unknown-module";
    }
    return "unknown";
}

} // namespace rbx::runtime
