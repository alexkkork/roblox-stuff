#include "runtime_context.hpp"

#include <utility>

namespace rbx::runtime
{

struct CancellationToken::State
{
    std::atomic<bool> cancelled{false};
    mutable std::mutex mutex;
    std::string reason;
};

CancellationToken::CancellationToken(std::shared_ptr<State> state)
    : state_(std::move(state))
{
}

bool CancellationToken::cancelled() const
{
    return state_ && state_->cancelled.load(std::memory_order_acquire);
}

std::string CancellationToken::reason() const
{
    if (!state_)
        return {};
    std::lock_guard lock(state_->mutex);
    return state_->reason;
}

CancellationSource::CancellationSource()
    : state_(std::make_shared<CancellationToken::State>())
{
}

CancellationToken CancellationSource::token() const
{
    return CancellationToken(state_);
}

bool CancellationSource::cancel(std::string reason)
{
    bool expected = false;
    if (!state_->cancelled.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return false;
    std::lock_guard lock(state_->mutex);
    state_->reason = reason.empty() ? "cancelled" : std::move(reason);
    return true;
}

bool CancellationSource::cancelled() const
{
    return state_->cancelled.load(std::memory_order_acquire);
}

RuntimeContext::RuntimeContext(lua_State* mainState, RuntimeContextOptions options)
    : mainState_(mainState ? lua_mainthread(mainState) : nullptr)
    , options_(options)
    , ownerThread_(std::this_thread::get_id())
    , anchor_{kAnchorMagic, this}
    , clock_(makeClock(options.clockMode, options.virtualEpochMillis))
    , scheduler_(clock_, options.scheduler)
    , modules_(scheduler_)
    , executor_(ExecutorCompatibilityOptions{
          options.profile,
          options.executionMode,
          options.executorPreset,
          options.filesystem,
          options.filesystemLimits,
          options.deterministicSeed,
      })
{
    if (!mainState_)
        throw std::invalid_argument("runtime context requires a Lua state");
    if (options_.memoryLimitBytes == 0)
        throw std::invalid_argument("runtime memory limit must be non-zero");
}

RuntimeContext::~RuntimeContext()
{
    if (attached_)
    {
        if (!ownsCurrentThread())
            std::terminate();
        detach();
    }
}

void RuntimeContext::attach()
{
    assertOwnerThread();
    if (attached_)
        return;
    lua_Callbacks* callbacks = lua_callbacks(mainState_);
    if (callbacks->userdata != nullptr)
        throw std::logic_error("lua_Callbacks userdata is already owned");
    if (callbacks->userthread != nullptr)
        throw std::logic_error("lua userthread callback is already owned");
    if (lua_getthreaddata(mainState_) != nullptr)
        throw std::logic_error("main Lua thread-data is already owned");

    callbacks->userdata = &anchor_;
    callbacks->userthread = &RuntimeContext::userthreadHook;
    attached_ = true;
    try
    {
        createThreadContext(mainState_, nullptr);
    }
    catch (...)
    {
        callbacks->userthread = nullptr;
        callbacks->userdata = nullptr;
        attached_ = false;
        throw;
    }
}

void RuntimeContext::detach()
{
    assertOwnerThread();
    if (!attached_)
        return;

    network_.reset();
    for (const std::shared_ptr<NativeSignal>& signal : ownedSignals_)
        signal->disconnectAll(true);
    ownedSignals_.clear();
    clearSubsystems();
    for (auto& [state, context] : threads_)
    {
        context->cancellation.cancel("runtime context detached");
        if (context->schedulerTask != 0)
            scheduler_.cancel(context->schedulerTask, "runtime context detached");
        if (lua_getthreaddata(state) == context.get())
            lua_setthreaddata(state, nullptr);
    }
    threads_.clear();

    lua_Callbacks* callbacks = lua_callbacks(mainState_);
    if (callbacks->userdata == &anchor_)
        callbacks->userdata = nullptr;
    if (callbacks->userthread == &RuntimeContext::userthreadHook)
        callbacks->userthread = nullptr;
    attached_ = false;
}

bool RuntimeContext::attached() const
{
    return attached_;
}

RuntimeContext* RuntimeContext::from(lua_State* state)
{
    if (!state)
        return nullptr;
    lua_Callbacks* callbacks = lua_callbacks(state);
    if (callbacks->userthread != &RuntimeContext::userthreadHook)
        return nullptr;
    void* userdata = callbacks->userdata;
    if (!userdata)
        return nullptr;
    auto* anchor = static_cast<Anchor*>(userdata);
    return anchor->magic == kAnchorMagic ? anchor->context : nullptr;
}

const RuntimeContext* RuntimeContext::from(const lua_State* state)
{
    return from(const_cast<lua_State*>(state));
}

ThreadContext* RuntimeContext::threadFrom(lua_State* state)
{
    RuntimeContext* context = from(state);
    if (!context)
        return nullptr;
    void* data = lua_getthreaddata(state);
    auto* threadContext = static_cast<ThreadContext*>(data);
    return threadContext && threadContext->thread == state ? threadContext : nullptr;
}

ThreadContext& RuntimeContext::mainThread()
{
    return thread(mainState_);
}

ThreadContext& RuntimeContext::thread(lua_State* state)
{
    assertOwnerThread();
    auto found = threads_.find(state);
    if (found == threads_.end())
        throw std::out_of_range("Lua coroutine is not attached to this runtime");
    return *found->second;
}

const ThreadContext& RuntimeContext::thread(lua_State* state) const
{
    assertOwnerThread();
    auto found = threads_.find(state);
    if (found == threads_.end())
        throw std::out_of_range("Lua coroutine is not attached to this runtime");
    return *found->second;
}

ThreadContext& RuntimeContext::attachCoroutine(lua_State* state, lua_State* parent)
{
    assertOwnerThread();
    if (!attached_ || from(state) != this)
        throw std::logic_error("coroutine does not belong to the attached runtime");
    auto found = threads_.find(state);
    if (found != threads_.end())
        return *found->second;
    const ThreadContext* parentContext = nullptr;
    if (parent)
    {
        auto parentFound = threads_.find(parent);
        if (parentFound != threads_.end())
            parentContext = parentFound->second.get();
    }
    return createThreadContext(state, parentContext);
}

bool RuntimeContext::detachCoroutine(lua_State* state)
{
    assertOwnerThread();
    if (state == mainState_)
        return false;
    auto found = threads_.find(state);
    if (found == threads_.end())
        return false;
    found->second->cancellation.cancel("coroutine destroyed");
    if (found->second->schedulerTask != 0)
        scheduler_.cancel(found->second->schedulerTask, "coroutine destroyed");
    if (lua_getthreaddata(state) == found->second.get())
        lua_setthreaddata(state, nullptr);
    threads_.erase(found);
    return true;
}

std::size_t RuntimeContext::threadCount() const
{
    assertOwnerThread();
    return threads_.size();
}

TaskExecutionMetadata RuntimeContext::taskMetadata(lua_State* state) const
{
    const ThreadContext& context = thread(state);
    TaskExecutionMetadata result;
    result.threadContextId = context.id;
    result.scriptInstanceId = context.script.scriptInstanceId;
    result.security = context.security;
    result.actorLane = static_cast<uint8_t>(context.actorLane);
    return result;
}

bool RuntimeContext::bindTask(TaskId taskId, lua_State* state)
{
    assertOwnerThread();
    ThreadContext& context = thread(state);
    if (!scheduler_.setTaskMetadata(taskId, taskMetadata(state)))
        return false;
    context.schedulerTask = taskId;
    return true;
}

SecurityDescriptor RuntimeContext::restrictIdentity(lua_State* state, SecurityIdentity requestedIdentity)
{
    assertOwnerThread();
    ThreadContext& context = thread(state);
    context.security = securityPolicy_.inherit(context.security, requestedIdentity);
    if (context.schedulerTask != 0)
        scheduler_.setTaskMetadata(context.schedulerTask, taskMetadata(state));
    return context.security;
}

lua_State* RuntimeContext::mainState() const
{
    return mainState_;
}

const RuntimeContextOptions& RuntimeContext::options() const
{
    return options_;
}

uint64_t RuntimeContext::deterministicSeed() const
{
    return options_.deterministicSeed;
}

std::size_t RuntimeContext::memoryLimitBytes() const
{
    return options_.memoryLimitBytes;
}

Scheduler& RuntimeContext::scheduler()
{
    return scheduler_;
}

const Scheduler& RuntimeContext::scheduler() const
{
    return scheduler_;
}

ModuleRegistry& RuntimeContext::modules()
{
    return modules_;
}

const ModuleRegistry& RuntimeContext::modules() const
{
    return modules_;
}

SecurityPolicy& RuntimeContext::securityPolicy()
{
    return securityPolicy_;
}

const SecurityPolicy& RuntimeContext::securityPolicy() const
{
    return securityPolicy_;
}

ExecutorCompatibility& RuntimeContext::executor()
{
    return executor_;
}

const ExecutorCompatibility& RuntimeContext::executor() const
{
    return executor_;
}

std::shared_ptr<NativeSignal> RuntimeContext::createSignal(std::string name, SignalBehavior behavior)
{
    assertOwnerThread();
    auto signal = std::make_shared<NativeSignal>(scheduler_, std::move(name), behavior);
    ownedSignals_.push_back(signal);
    return signal;
}

NetworkBroker& RuntimeContext::installNetwork(NetworkPolicyConfig policy, std::shared_ptr<IHttpTransport> transport)
{
    assertOwnerThread();
    network_ = std::make_unique<NetworkBroker>(scheduler_, std::move(policy), std::move(transport));
    return *network_;
}

NetworkBroker* RuntimeContext::network()
{
    return network_.get();
}

const NetworkBroker* RuntimeContext::network() const
{
    return network_.get();
}

bool RuntimeContext::removeSubsystem(std::string_view key)
{
    assertOwnerThread();
    return subsystemSlots_.erase(std::string(key)) != 0;
}

void RuntimeContext::clearSubsystems()
{
    assertOwnerThread();
    subsystemSlots_.clear();
}

void RuntimeContext::userthreadHook(lua_State* parent, lua_State* state)
{
    lua_State* callbackState = state ? state : parent;
    if (!callbackState)
        return;
    RuntimeContext* context = from(callbackState);
    if (!context || !context->ownsCurrentThread())
        return;
    if (parent)
        context->attachCoroutine(state, parent);
    else
        context->detachCoroutine(state);
}

ThreadContext& RuntimeContext::createThreadContext(lua_State* state, const ThreadContext* parent)
{
    if (lua_getthreaddata(state) != nullptr)
        throw std::logic_error("Lua thread-data is already owned");

    auto result = std::make_unique<ThreadContext>();
    result->id = nextThreadId_++;
    result->thread = state;
    if (parent)
    {
        result->script = parent->script;
        result->security = parent->security;
        result->actorLane = parent->actorLane;
        result->memoryCategory = parent->memoryCategory;
    }
    else
    {
        result->script.debugName = "RuntimeScript";
        result->security = executor_.security();
    }
    ThreadContext* pointer = result.get();
    threads_.emplace(state, std::move(result));
    lua_setthreaddata(state, pointer);
    return *pointer;
}

void RuntimeContext::assertOwnerThread() const
{
    if (!ownsCurrentThread())
        throw std::logic_error("runtime context may only be accessed by its owner thread");
}

bool RuntimeContext::ownsCurrentThread() const
{
    return ownerThread_ == std::this_thread::get_id();
}

std::string_view toString(ActorLane lane)
{
    return lane == ActorLane::Synchronized ? "synchronized" : "desynchronized";
}

} // namespace rbx::runtime
