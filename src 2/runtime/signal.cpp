#include "signal.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace rbx::runtime
{

struct SignalConnection::State
{
    std::atomic<bool> connected{true};
    uint64_t id = 0;
    std::function<void(uint64_t)> disconnect;
    std::function<void()> cleanup;
    std::atomic<bool> cleaned{false};

    void runCleanup()
    {
        if (!cleaned.exchange(true, std::memory_order_acq_rel) && cleanup)
            cleanup();
    }
};

struct NativeSignal::Slot
{
    uint64_t id = 0;
    std::shared_ptr<SignalConnection::State> state;
    SignalTaskFactory factory;
    std::string callbackName;
    bool once = false;
    std::optional<TaskExecutionMetadata> execution;
};

struct NativeSignal::Waiter
{
    TaskId task = 0;
    CancellationObserverId cancellationObserver = 0;
};

SignalConnection::SignalConnection(std::shared_ptr<State> state)
    : state_(std::move(state))
{
}

bool SignalConnection::connected() const
{
    return state_ && state_->connected.load(std::memory_order_acquire);
}

void SignalConnection::disconnect()
{
    if (!state_ || !state_->connected.exchange(false, std::memory_order_acq_rel))
        return;
    if (state_->disconnect)
        state_->disconnect(state_->id);
    state_->runCleanup();
}

uint64_t SignalConnection::id() const
{
    return state_ ? state_->id : 0;
}

void SignalConnection::setDisconnectCallback(std::function<void()> callback)
{
    if (!state_)
        return;
    state_->cleanup = std::move(callback);
    if (!state_->connected.load(std::memory_order_acquire))
        state_->runCleanup();
}

SignalConnection::operator bool() const
{
    return state_ != nullptr;
}

NativeSignal::NativeSignal(Scheduler& scheduler, std::string name, SignalBehavior behavior)
    : scheduler_(scheduler)
    , name_(std::move(name))
    , behavior_(behavior)
{
}

NativeSignal::~NativeSignal()
{
    // RuntimeContext::detach disconnects every owned signal before destroying
    // its Scheduler, but Lua userdata may retain the now-empty signal until a
    // later lua_close. Do not touch the non-owning scheduler reference once no
    // scheduler-side cleanup remains.
    if (!slots_.empty() || !waiters_.empty())
        disconnectAll(true);
}

SignalConnection NativeSignal::connect(SignalTaskFactory factory, std::string callbackName)
{
    if (!scheduler_.ownsCurrentThread())
        throw std::logic_error("signals may only be connected on the scheduler owner thread");
    if (!factory)
        throw std::invalid_argument("signal callback factory cannot be empty");

    auto state = std::make_shared<SignalConnection::State>();
    state->id = nextConnectionId_++;
    std::weak_ptr<NativeSignal> weakSelf = weak_from_this();
    if (weakSelf.expired())
        throw std::logic_error("NativeSignal must be owned by std::shared_ptr before Connect");
    state->disconnect = [weakSelf](uint64_t id) {
        if (std::shared_ptr<NativeSignal> self = weakSelf.lock())
            self->disconnect(id);
    };
    slots_.push_back(Slot{state->id, state, std::move(factory), std::move(callbackName), false, scheduler_.currentTaskMetadata()});
    return SignalConnection(std::move(state));
}

SignalConnection NativeSignal::once(SignalTaskFactory factory, std::string callbackName)
{
    SignalConnection result = connect(std::move(factory), std::move(callbackName));
    auto found = std::find_if(slots_.begin(), slots_.end(), [&result](const Slot& slot) {
        return slot.id == result.id();
    });
    if (found != slots_.end())
        found->once = true;
    return result;
}

bool NativeSignal::wait(TaskId task)
{
    if (!scheduler_.ownsCurrentThread())
        throw std::logic_error("signal wait may only be registered on the scheduler owner thread");
    const std::optional<TaskSnapshot> snapshot = scheduler_.task(task);
    if (!snapshot || snapshot->status == TaskStatus::Completed || snapshot->status == TaskStatus::Cancelled || snapshot->status == TaskStatus::Failed)
        return false;
    if (std::any_of(waiters_.begin(), waiters_.end(), [task](const Waiter& waiter) {
            return waiter.task == task;
        }))
        return false;

    std::weak_ptr<NativeSignal> weakSelf = weak_from_this();
    if (weakSelf.expired())
        throw std::logic_error("NativeSignal must be owned by std::shared_ptr before Wait");
    const CancellationObserverId observer = scheduler_.addCancellationObserver(task, [weakSelf, task] {
        if (std::shared_ptr<NativeSignal> self = weakSelf.lock())
            self->removeWaiter(task);
    });
    if (observer == 0)
        return false;
    waiters_.push_back(Waiter{task, observer});
    return true;
}

bool NativeSignal::removeWaiter(TaskId task)
{
    if (!scheduler_.ownsCurrentThread())
        throw std::logic_error("signal waiters may only be modified on the scheduler owner thread");
    auto found = std::find_if(waiters_.begin(), waiters_.end(), [task](const Waiter& waiter) {
        return waiter.task == task;
    });
    if (found == waiters_.end())
        return false;
    scheduler_.removeCancellationObserver(found->task, found->cancellationObserver);
    waiters_.erase(found);
    return true;
}

std::size_t NativeSignal::fire(SignalArguments arguments)
{
    if (!scheduler_.ownsCurrentThread())
        throw std::logic_error("signals may only be fired on the scheduler owner thread");
    ++fireCount_;
    std::size_t scheduled = 0;

    std::vector<Waiter> waiters = std::move(waiters_);
    waiters_.clear();
    for (const Waiter& waiter : waiters)
    {
        scheduler_.removeCancellationObserver(waiter.task, waiter.cancellationObserver);
        ResumeData data;
        data.arguments = arguments;
        data.sourceName = name_;
        if (scheduler_.resume(waiter.task, std::move(data), QueueKind::Signal))
            ++scheduled;
    }

    // Copy slots because callback factories are allowed to connect/disconnect.
    std::vector<Slot> current = slots_;
    for (Slot& slot : current)
    {
        if (!slot.state->connected.load(std::memory_order_acquire))
            continue;
        TaskCallback callback;
        try
        {
            callback = slot.factory(arguments);
        }
        catch (...)
        {
            callback = [](const ResumeData&) {
                return TaskStep::fail("signal callback factory threw an exception");
            };
        }
        if (slot.once)
        {
            slot.state->connected.store(false, std::memory_order_release);
            disconnect(slot.id);
        }
        if (!callback)
            continue;

        ResumeData initial;
        initial.arguments = arguments;
        initial.source = QueueKind::Signal;
        initial.sourceName = name_;
        const std::string taskName = slot.callbackName.empty() ? name_ + " connection" : slot.callbackName;
        if (behavior_ == SignalBehavior::Deferred)
            scheduler_.defer(std::move(callback), taskName, std::move(initial), slot.execution);
        else
            scheduler_.spawnImmediate(std::move(callback), taskName, std::move(initial), slot.execution);
        ++scheduled;
    }
    pruneDisconnected();
    return scheduled;
}

void NativeSignal::disconnectAll(bool cancelWaiters)
{
    // This check must precede the scheduler access. An empty signal can legally
    // outlive a detached RuntimeContext through Lua userdata ownership.
    if (slots_.empty() && waiters_.empty())
        return;
    if (!scheduler_.ownsCurrentThread())
        return;
    for (Slot& slot : slots_)
    {
        slot.state->connected.store(false, std::memory_order_release);
        slot.state->disconnect = {};
        slot.state->runCleanup();
    }
    slots_.clear();

    std::vector<Waiter> waiters = std::move(waiters_);
    waiters_.clear();
    for (const Waiter& waiter : waiters)
    {
        scheduler_.removeCancellationObserver(waiter.task, waiter.cancellationObserver);
        if (cancelWaiters)
            scheduler_.cancel(waiter.task, "signal destroyed");
    }
}

void NativeSignal::setBehavior(SignalBehavior behavior)
{
    if (!scheduler_.ownsCurrentThread())
        throw std::logic_error("signal behavior may only be changed on the scheduler owner thread");
    behavior_ = behavior;
}

SignalBehavior NativeSignal::behavior() const
{
    return behavior_;
}

const std::string& NativeSignal::name() const
{
    return name_;
}

SignalSnapshot NativeSignal::snapshot() const
{
    SignalSnapshot result;
    result.name = name_;
    result.behavior = behavior_;
    result.waiterCount = waiters_.size();
    result.fireCount = fireCount_;
    result.connectionCount = std::count_if(slots_.begin(), slots_.end(), [](const Slot& slot) {
        return slot.state->connected.load(std::memory_order_acquire);
    });
    return result;
}

void NativeSignal::disconnect(uint64_t id)
{
    if (!scheduler_.ownsCurrentThread())
        return;
    auto found = std::find_if(slots_.begin(), slots_.end(), [id](const Slot& slot) {
        return slot.id == id;
    });
    if (found != slots_.end())
    {
        found->state->connected.store(false, std::memory_order_release);
        found->state->disconnect = {};
        found->state->runCleanup();
    }
    pruneDisconnected();
}

void NativeSignal::pruneDisconnected()
{
    slots_.erase(std::remove_if(slots_.begin(), slots_.end(), [](const Slot& slot) {
                     return !slot.state->connected.load(std::memory_order_acquire);
                 }),
        slots_.end());
}

} // namespace rbx::runtime
