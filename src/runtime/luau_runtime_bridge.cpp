#include "luau_runtime_bridge.hpp"

#include "lualib.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <limits>
#include <new>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace rbx::runtime
{
namespace
{

enum class LuaYieldKind
{
    Wait,
    Signal,
    Module,
    External,
};

struct LuaYieldRequest
{
    LuaYieldKind kind = LuaYieldKind::Wait;
    double seconds = 0.0;
    std::string key;
};

auto findHeader(std::map<std::string, std::string, std::less<>>& headers, std::string_view requested)
{
    return std::find_if(headers.begin(), headers.end(), [requested](const auto& header) {
        return header.first.size() == requested.size() &&
            std::equal(header.first.begin(), header.first.end(), requested.begin(), [](unsigned char left, unsigned char right) {
                return std::tolower(left) == std::tolower(right);
            });
    });
}

ModuleId checkModuleId(lua_State* state, int index)
{
    if (lua_isinteger64(state, index))
    {
        int exact = 0;
        const int64_t value = lua_tointeger64(state, index, &exact);
        if (!exact || value <= 0)
        {
            luaL_error(state, "native ModuleScript id must be a positive exact integer");
            return 0;
        }
        return static_cast<ModuleId>(value);
    }
    const double value = luaL_checknumber(state, index);
    constexpr double kLargestExactInteger = 9007199254740991.0;
    if (!std::isfinite(value) || value <= 0.0 || value > kLargestExactInteger || std::floor(value) != value)
    {
        luaL_error(state, "native ModuleScript id must be a positive exact integer");
        return 0;
    }
    return static_cast<ModuleId>(value);
}

} // namespace

struct LuauRuntimeBridge::SignalUserdata
{
    std::shared_ptr<NativeSignal> value;
};

struct LuauRuntimeBridge::ConnectionUserdata
{
    SignalConnection value;
};

struct LuauRuntimeBridge::Impl
{
    struct MainCapture
    {
        std::vector<int> results;
        std::string error;
    };

    struct ScheduledTask
    {
        TaskId task = 0;
        int returnedThreadReference = LUA_NOREF;
    };

    struct HttpPending
    {
        TaskId task = 0;
        NetworkRequestId request = 0;
        CancellationObserverId cancellationObserver = 0;
    };

    struct LuaArgumentPack
    {
        std::weak_ptr<LuauRuntimeBridge> bridge;
        std::vector<int> references;

        ~LuaArgumentPack()
        {
            if (std::shared_ptr<LuauRuntimeBridge> owner = bridge.lock())
            {
                for (int reference : references)
                    owner->impl_->release(reference);
            }
        }
    };

    struct LuaCall : std::enable_shared_from_this<LuaCall>
    {
        std::weak_ptr<LuauRuntimeBridge> bridge;
        lua_State* coroutine = nullptr;
        int threadReference = LUA_NOREF;
        int functionReference = LUA_NOREF;
        RuntimeValues initialArguments;
        bool started = false;
        bool finished = false;
        bool cancellationObserverInstalled = false;
        TaskId task = 0;
        CancellationObserverId cancellationObserver = 0;
        std::shared_ptr<MainCapture> mainCapture;

        void bindTask(const std::shared_ptr<LuauRuntimeBridge>& owner, TaskId taskValue)
        {
            if (task != 0 || taskValue == 0)
                return;
            task = taskValue;
            Scheduler& scheduler = owner->context().scheduler();
            owner->impl_->threadTasks[coroutine] = task;
            owner->context().thread(coroutine).schedulerTask = task;
            std::weak_ptr<LuaCall> weakSelf = weak_from_this();
            cancellationObserver = scheduler.addCancellationObserver(task, [weakSelf] {
                std::shared_ptr<LuaCall> self = weakSelf.lock();
                if (!self)
                    return;
                if (std::shared_ptr<LuauRuntimeBridge> bridgeOwner = self->bridge.lock())
                {
                    if (bridgeOwner->context().scheduler().currentTask() == self->task)
                        return;
                }
                self->finish(true);
            });
            cancellationObserverInstalled = cancellationObserver != 0;
        }

        void finish(bool resetThread)
        {
            if (finished)
                return;
            finished = true;
            if (std::shared_ptr<LuauRuntimeBridge> owner = bridge.lock())
            {
                if (cancellationObserverInstalled)
                    owner->context().scheduler().removeCancellationObserver(task, cancellationObserver);
                if (resetThread && coroutine)
                    lua_resetthread(coroutine);
                else if (coroutine)
                    lua_settop(coroutine, 0);
                owner->impl_->release(threadReference);
                owner->impl_->release(functionReference);
                owner->impl_->threadTasks.erase(coroutine);
                auto moduleStack = owner->impl_->moduleEvaluationStacks.find(coroutine);
                if (moduleStack != owner->impl_->moduleEvaluationStacks.end())
                {
                    for (auto module = moduleStack->second.rbegin(); module != moduleStack->second.rend(); ++module)
                        owner->context().modules().finishFailure(*module, task, "ModuleScript loader task ended before completion");
                    owner->impl_->moduleEvaluationStacks.erase(moduleStack);
                }
                if (ThreadContext* thread = RuntimeContext::threadFrom(coroutine))
                    thread->script.evaluatingModule.reset();
            }
            threadReference = LUA_NOREF;
            functionReference = LUA_NOREF;
            coroutine = nullptr;
        }

        TaskStep resume(const ResumeData& data)
        {
            std::shared_ptr<LuauRuntimeBridge> owner = bridge.lock();
            if (!owner || finished || !coroutine)
                return TaskStep::fail("Luau task bridge is no longer available");
            Scheduler& scheduler = owner->context().scheduler();
            if (!task)
                bindTask(owner, scheduler.currentTask().value_or(0));
            if (!task)
                return TaskStep::fail("Luau task resumed outside native scheduler");
            // The scheduled callback executes in this bridge-created coroutine,
            // not in the source thread that requested it. Update the running
            // record before Lua code can spawn descendants or call task.wait.
            scheduler.setTaskMetadata(task, owner->context().taskMetadata(coroutine));

            int argumentCount = 0;
            if (!started)
            {
                started = true;
                // makeCall installs the callable when it creates the thread,
                // matching coroutine.create. Besides avoiding a second stack
                // mutation here, this keeps an unstarted task.defer/delay
                // observably suspended instead of looking like a dead thread.
                argumentCount = owner->impl_->pushValues(coroutine, initialArguments);
                initialArguments.clear();
            }
            else if (data.source == QueueKind::Timer && data.returnWaitedSeconds)
            {
                lua_pushnumber(coroutine, data.waitedSeconds);
                argumentCount = 1;
            }
            else
                argumentCount = owner->impl_->pushValues(coroutine, data.arguments);

            const int status = lua_resume(coroutine, owner->context().mainState(), argumentCount);
            if (status == LUA_OK)
            {
                if (mainCapture)
                {
                    const int resultCount = lua_gettop(coroutine);
                    mainCapture->results.reserve(static_cast<std::size_t>(resultCount));
                    for (int index = 1; index <= resultCount; ++index)
                        mainCapture->results.push_back(owner->impl_->retain(coroutine, index));
                }
                finish(false);
                return TaskStep::complete();
            }
            if (status != LUA_YIELD)
            {
                const char* message = lua_tostring(coroutine, -1);
                std::string error = message ? message : "Luau coroutine failed";
                if (const char* trace = lua_debugtrace(coroutine); trace && *trace)
                {
                    if (error.find(trace) == std::string::npos)
                        error += "\n" + std::string(trace);
                }
                if (mainCapture)
                    mainCapture->error = error;
                finish(true);
                return TaskStep::fail(std::move(error));
            }

            lua_settop(coroutine, 0);
            auto yielded = owner->impl_->yieldRequests.find(coroutine);
            if (yielded == owner->impl_->yieldRequests.end())
                return TaskStep::arbitraryYield();
            LuaYieldRequest request = std::move(yielded->second);
            owner->impl_->yieldRequests.erase(yielded);
            if (request.kind == LuaYieldKind::Signal)
                return TaskStep::waitSignal(std::move(request.key));
            if (request.kind == LuaYieldKind::Module)
                return TaskStep::waitModule(std::move(request.key));
            if (request.kind == LuaYieldKind::External)
                return TaskStep::waitExternal(std::move(request.key));
            return TaskStep::wait(request.seconds);
        }
    };

    RuntimeContext& context;
    LuauRuntimeBridgeOptions options;
    bool installed = false;
    bool active = true;
    int traceReference = LUA_NOREF;
    lua_CFunction coroutineCloseFunction = nullptr;
    std::unordered_set<int> references;
    std::unordered_map<lua_State*, LuaYieldRequest> yieldRequests;
    std::unordered_map<lua_State*, TaskId> threadTasks;
    std::unordered_map<lua_State*, std::vector<ModuleId>> moduleEvaluationStacks;
    ModuleId nextModuleId = 1;
    int runServiceCallbackReference = LUA_NOREF;
    std::vector<std::shared_ptr<NativeSignal>> runServiceSignals;
    std::size_t runServiceBindingCount = 0;
    bool runServiceFrameArmed = false;
    double nextRunServiceFrameDue = 0.0;
    ScriptEnvironment runServiceScript;
    SecurityDescriptor runServiceSecurity;
    ActorLane runServiceActorLane = ActorLane::Synchronized;

    Impl(RuntimeContext& contextValue, LuauRuntimeBridgeOptions optionsValue)
        : context(contextValue)
        , options(optionsValue)
    {
    }

    int retain(lua_State* state, int index)
    {
        if (!active)
            return LUA_NOREF;
        const int reference = lua_ref(state, index);
        if (reference > LUA_REFNIL)
            references.insert(reference);
        return reference;
    }

    int cloneReference(int reference)
    {
        if (reference <= LUA_REFNIL || !active)
            return LUA_NOREF;
        lua_getref(context.mainState(), reference);
        const int clone = retain(context.mainState(), -1);
        lua_pop(context.mainState(), 1);
        return clone;
    }

    void release(int reference)
    {
        if (reference <= LUA_REFNIL || !active || !references.erase(reference))
            return;
        lua_unref(context.mainState(), reference);
    }

    std::shared_ptr<LuaArgumentPack> capture(lua_State* state, int first, int count, const std::shared_ptr<LuauRuntimeBridge>& owner)
    {
        auto pack = std::make_shared<LuaArgumentPack>();
        pack->bridge = owner;
        pack->references.reserve(static_cast<std::size_t>(std::max(0, count)));
        for (int offset = 0; offset < count; ++offset)
            pack->references.push_back(retain(state, first + offset));
        return pack;
    }

    int pushValues(lua_State* destination, const RuntimeValues& values)
    {
        int count = 0;
        for (const RuntimeValue& value : values)
        {
            const RuntimeValue::Storage& storage = value.storage();
            if (std::holds_alternative<NilValue>(storage))
                lua_pushnil(destination);
            else if (const bool* boolean = std::get_if<bool>(&storage))
                lua_pushboolean(destination, *boolean);
            else if (const int64_t* integer = std::get_if<int64_t>(&storage))
                lua_pushinteger64(destination, *integer);
            else if (const double* number = std::get_if<double>(&storage))
                lua_pushnumber(destination, *number);
            else if (const std::string* string = std::get_if<std::string>(&storage))
                lua_pushlstring(destination, string->data(), string->size());
            else
            {
                const OpaqueValue& opaque = std::get<OpaqueValue>(storage);
                if (opaque.typeName != "LuaSignalArguments")
                {
                    lua_pushnil(destination);
                }
                else
                {
                    auto pack = std::static_pointer_cast<const LuaArgumentPack>(opaque.storage);
                    for (int reference : pack->references)
                    {
                        lua_getref(context.mainState(), reference);
                        lua_xmove(context.mainState(), destination, 1);
                        ++count;
                    }
                    continue;
                }
            }
            ++count;
        }
        return count;
    }

    int pushCachedModule(lua_State* destination, ModuleId module)
    {
        const std::shared_ptr<const RuntimeValue> cached = context.modules().cachedValue(module);
        if (!cached)
        {
            luaL_error(destination, "native ModuleScript cache is empty");
            return 0;
        }
        lua_pushboolean(destination, false);
        RuntimeValues values{*cached};
        if (pushValues(destination, values) != 1)
        {
            luaL_error(destination, "native ModuleScript cache contained an invalid value pack");
            return 0;
        }
        return 2;
    }

    void restoreEvaluatingModule(lua_State* state, ModuleId expected)
    {
        auto found = moduleEvaluationStacks.find(state);
        if (found == moduleEvaluationStacks.end() || found->second.empty() || found->second.back() != expected)
            throw std::logic_error("native ModuleScript evaluation stack is inconsistent");
        found->second.pop_back();
        ThreadContext& thread = context.thread(state);
        thread.script.evaluatingModule = found->second.empty() ? std::nullopt : std::optional(found->second.back());
        if (found->second.empty())
            moduleEvaluationStacks.erase(found);
    }

    std::shared_ptr<LuaCall> makeCall(int functionReference, RuntimeValues arguments, const std::shared_ptr<LuauRuntimeBridge>& owner)
    {
        auto call = std::make_shared<LuaCall>();
        call->bridge = owner;
        call->functionReference = functionReference;
        call->initialArguments = std::move(arguments);
        call->coroutine = lua_newthread(context.mainState());
        call->threadReference = retain(context.mainState(), -1);
        lua_pop(context.mainState(), 1);
        lua_getref(context.mainState(), functionReference);
        lua_xmove(context.mainState(), call->coroutine, 1);
        return call;
    }

    std::shared_ptr<LuaCall> adoptCall(lua_State* coroutine, const std::shared_ptr<LuauRuntimeBridge>& owner)
    {
        auto call = std::make_shared<LuaCall>();
        call->bridge = owner;
        call->coroutine = coroutine;
        call->started = true;
        lua_pushthread(coroutine);
        call->threadReference = retain(coroutine, -1);
        lua_pop(coroutine, 1);
        return call;
    }

    TaskCallback callbackFor(int functionReference, RuntimeValues arguments, const std::shared_ptr<LuauRuntimeBridge>& owner)
    {
        std::shared_ptr<LuaCall> call = makeCall(functionReference, std::move(arguments), owner);
        return [call](const ResumeData& data) {
            return call->resume(data);
        };
    }

    ScheduledTask schedule(lua_State* source, int callableIndex, int firstArgument, int argumentCount, QueueKind queue, double delaySeconds)
    {
        std::shared_ptr<LuauRuntimeBridge> owner = source ? LuauRuntimeBridge::from(source)->shared_from_this() : nullptr;
        if (!owner)
            throw std::logic_error("Luau runtime bridge is unavailable");

        lua_State* suppliedThread = lua_tothread(source, callableIndex);
        if (suppliedThread)
        {
            const int coroutineStatus = lua_costatus(source, suppliedThread);
            if (coroutineStatus != LUA_COSUS)
            {
                const char* statusName = coroutineStatus == LUA_CORUN ? "running" : coroutineStatus == LUA_CONOR ? "normal" : "dead";
                luaL_error(source, "cannot schedule %s coroutine", statusName);
                return {};
            }
        }

        auto pack = capture(source, firstArgument, argumentCount, owner);
        RuntimeValues arguments{RuntimeValue::opaque<const LuaArgumentPack>(pack, "LuaSignalArguments")};

        if (suppliedThread)
        {
            const int returnedThreadReference = retain(source, callableIndex);
            ResumeData initial;
            initial.arguments = std::move(arguments);

            auto existing = threadTasks.find(suppliedThread);
            if (existing != threadTasks.end())
            {
                const TaskId existingTask = existing->second;
                bool resumed = false;
                if (queue == QueueKind::Deferred)
                    resumed = context.scheduler().resume(existingTask, std::move(initial), QueueKind::Deferred);
                else if (queue == QueueKind::Timer)
                    resumed = context.scheduler().resumeAfter(existingTask, delaySeconds, std::move(initial));
                else
                    resumed = context.scheduler().resumeImmediate(existingTask, std::move(initial));
                if (!resumed)
                {
                    release(returnedThreadReference);
                    luaL_error(source, "cannot schedule coroutine in its current task state");
                    return {};
                }
                return ScheduledTask{existingTask, returnedThreadReference};
            }

            std::shared_ptr<LuaCall> call = adoptCall(suppliedThread, owner);
            const TaskExecutionMetadata metadata = context.taskMetadata(suppliedThread);
            const int stableThreadReference = cloneReference(call->threadReference);
            TaskCallback callback = [call](const ResumeData& data) {
                return call->resume(data);
            };
            TaskId task = 0;
            if (queue == QueueKind::Deferred)
                task = context.scheduler().defer(std::move(callback), "task.defer", std::move(initial), metadata);
            else if (queue == QueueKind::Timer)
                task = context.scheduler().delay(delaySeconds, std::move(callback), "task.delay", std::move(initial), metadata);
            else
                task = context.scheduler().spawnImmediate(std::move(callback), "task.spawn", std::move(initial), metadata);
            call->bindTask(owner, task);
            release(returnedThreadReference);
            return ScheduledTask{task, stableThreadReference};
        }

        const int functionReference = retain(source, callableIndex);
        std::shared_ptr<LuaCall> call = makeCall(functionReference, std::move(arguments), owner);
        ThreadContext& childContext = context.thread(call->coroutine);
        const ThreadContext& sourceContext = context.thread(source);
        childContext.script = sourceContext.script;
        childContext.security = sourceContext.security;
        childContext.actorLane = sourceContext.actorLane;
        const int returnedThreadReference = cloneReference(call->threadReference);
        TaskCallback callback = [call](const ResumeData& data) {
            return call->resume(data);
        };
        const TaskExecutionMetadata metadata = context.taskMetadata(call->coroutine);
        TaskId task = 0;
        if (queue == QueueKind::Deferred)
            task = context.scheduler().defer(std::move(callback), "task.defer", {}, metadata);
        else if (queue == QueueKind::Timer)
            task = context.scheduler().delay(delaySeconds, std::move(callback), "task.delay", {}, metadata);
        else
            task = context.scheduler().spawnImmediate(std::move(callback), "task.spawn", {}, metadata);
        call->bindTask(owner, task);
        return ScheduledTask{task, returnedThreadReference};
    }

    bool armRunServiceFrame(bool hasActiveExecution)
    {
        bool hasDemand = runServiceBindingCount != 0;
        for (const std::shared_ptr<NativeSignal>& signal : runServiceSignals)
        {
            const SignalSnapshot snapshot = signal->snapshot();
            hasDemand = hasDemand || snapshot.connectionCount != 0 || snapshot.waiterCount != 0;
        }
        if (!hasActiveExecution || runServiceCallbackReference == LUA_NOREF || !hasDemand)
        {
            runServiceFrameArmed = false;
            return false;
        }
        const double frameDuration = context.scheduler().options().frameDurationSeconds;
        if (!runServiceFrameArmed)
        {
            nextRunServiceFrameDue = context.scheduler().now() + frameDuration;
            runServiceFrameArmed = true;
        }
        else if (nextRunServiceFrameDue < context.scheduler().now() - frameDuration)
            nextRunServiceFrameDue = context.scheduler().now() + frameDuration;
        return true;
    }

    void scheduleRunServiceFrame(const std::shared_ptr<LuauRuntimeBridge>& owner)
    {
        if (runServiceCallbackReference == LUA_NOREF)
            return;
        struct Phase
        {
            RunPhase phase;
            const char* callbackName;
        };
        // RenderBindings deliberately shares the PreRender phase key and is
        // inserted second, placing priority-sorted bindings after PreRender
        // and before RenderStepped without inventing an engine phase.
        static constexpr Phase phases[] = {
            {RunPhase::PreRender, "PreRender"},
            {RunPhase::PreRender, "RenderBindings"},
            {RunPhase::RenderStepped, "RenderStepped"},
            {RunPhase::PreAnimation, "PreAnimation"},
            {RunPhase::PreSimulation, "PreSimulation"},
            {RunPhase::Stepped, "Stepped"},
            {RunPhase::PostSimulation, "PostSimulation"},
            {RunPhase::Heartbeat, "Heartbeat"},
        };
        Scheduler& scheduler = context.scheduler();
        const double frameTime = scheduler.now();
        const double frameDuration = scheduler.options().frameDurationSeconds;
        for (const Phase& phase : phases)
        {
            const int callbackReference = cloneReference(runServiceCallbackReference);
            RuntimeValues arguments{RuntimeValue(phase.callbackName), RuntimeValue(frameTime), RuntimeValue(frameDuration)};
            std::shared_ptr<LuaCall> call = makeCall(callbackReference, std::move(arguments), owner);
            ThreadContext& child = context.thread(call->coroutine);
            child.script = runServiceScript;
            child.security = runServiceSecurity;
            child.actorLane = runServiceActorLane;
            TaskCallback callback = [call](const ResumeData& data) {
                return call->resume(data);
            };
            const TaskId task = scheduler.schedulePhase(
                phase.phase, std::move(callback), std::string("RunService.") + phase.callbackName, {}, context.taskMetadata(call->coroutine));
            call->bindTask(owner, task);
        }
        nextRunServiceFrameDue += frameDuration;
        if (nextRunServiceFrameDue <= frameTime + 1e-12)
            nextRunServiceFrameDue = frameTime + frameDuration;
    }

    RuntimeValues networkResultValues(NetworkResult result, const std::shared_ptr<LuauRuntimeBridge>& owner, std::string_view requestUrl)
    {
        RuntimeValues values;
        if (!result)
        {
            std::string message = "HTTP request failed (" + std::string(toString(result.error)) + "): " + result.message;
            if (!result.requiredHost.empty())
                message += " [required-host=" + result.requiredHost + "]";
            if (!requestUrl.empty())
                message += " [url=" + std::string(requestUrl) + "]";
            values.emplace_back(false);
            values.emplace_back(std::move(message));
            return values;
        }

        lua_State* main = context.mainState();
        lua_newtable(main);
        const int response = lua_absindex(main, -1);
        lua_pushboolean(main, result.response.statusCode >= 200 && result.response.statusCode < 300);
        lua_setfield(main, response, "Success");
        lua_pushinteger(main, result.response.statusCode);
        lua_setfield(main, response, "StatusCode");
        lua_pushlstring(main, result.response.statusMessage.data(), result.response.statusMessage.size());
        lua_setfield(main, response, "StatusMessage");
        lua_pushlstring(main, result.response.body.data(), result.response.body.size());
        lua_setfield(main, response, "Body");
        lua_newtable(main);
        const int headers = lua_absindex(main, -1);
        for (const auto& [name, value] : result.response.headers)
        {
            lua_pushlstring(main, value.data(), value.size());
            lua_setfield(main, headers, name.c_str());
        }
        lua_setfield(main, response, "Headers");
        // Executor request APIs expose a Cookies table even when the transport
        // does not maintain a persistent cookie jar.
        lua_newtable(main);
        lua_setfield(main, response, "Cookies");
        auto pack = capture(main, response, 1, owner);
        lua_pop(main, 1);
        values.emplace_back(true);
        values.emplace_back(RuntimeValue::opaque<const LuaArgumentPack>(pack, "LuaSignalArguments"));
        return values;
    }

    void traceNetwork(const NetworkResult& result, std::string_view requestUrl)
    {
        if (traceReference == LUA_NOREF)
            return;
        auto emit = [&](const char* kind, const std::string& name, const std::string& detail) {
            const int top = lua_gettop(context.mainState());
            lua_getref(context.mainState(), traceReference);
            if (!lua_isfunction(context.mainState(), -1))
            {
                lua_settop(context.mainState(), top);
                return;
            }
            lua_pushstring(context.mainState(), kind);
            lua_pushlstring(context.mainState(), name.data(), name.size());
            lua_pushlstring(context.mainState(), detail.data(), detail.size());
            if (lua_pcall(context.mainState(), 3, 0, 0) != LUA_OK)
                lua_pop(context.mainState(), 1);
            lua_settop(context.mainState(), top);
        };
        if (!result)
        {
            if (!result.requiredHost.empty())
                emit("network_blocked", std::string(requestUrl), result.requiredHost);
            return;
        }
        for (std::size_t index = 1; index < result.response.hops.size(); ++index)
            emit("network_redirect", result.response.hops[index - 1].url, result.response.hops[index].url);
        if (result.response.statusCode >= 400)
        {
            const std::string finalUrl = result.response.hops.empty() ? std::string(requestUrl) : result.response.hops.back().url;
            emit("network_response", finalUrl, std::to_string(result.response.statusCode));
        }
    }
};

LuauRuntimeBridge::LuauRuntimeBridge(RuntimeContext& context, LuauRuntimeBridgeOptions options)
    : impl_(std::make_unique<Impl>(context, options))
{
    if (!context.attached())
        throw std::logic_error("RuntimeContext must be attached before creating its Luau bridge");
    if (options.signalUserdataTag == options.connectionUserdataTag || options.signalUserdataTag < 0 || options.connectionUserdataTag < 0)
        throw std::invalid_argument("Luau signal userdata tags must be distinct and non-negative");
}

std::shared_ptr<LuauRuntimeBridge> LuauRuntimeBridge::create(RuntimeContext& context, LuauRuntimeBridgeOptions options)
{
    auto bridge = std::shared_ptr<LuauRuntimeBridge>(new LuauRuntimeBridge(context, options));
    context.setSubsystem<LuauRuntimeBridge>(std::string(kSubsystemKey), bridge);
    bridge->install();
    return bridge;
}

LuauRuntimeBridge::~LuauRuntimeBridge()
{
    shutdown();
}

void LuauRuntimeBridge::install()
{
    if (impl_->installed)
        return;
    lua_State* state = impl_->context.mainState();
    lua_getglobal(state, "__rbx_trace_compat");
    if (lua_isfunction(state, -1))
        impl_->traceReference = impl_->retain(state, -1);
    lua_pop(state, 1);

    // Keep Luau's coroutine.close behavior byte-for-byte observable while
    // teaching the native scheduler that a script closed one of its threads.
    // The public replacement is deliberately a zero-upvalue C closure: debug
    // and executor compatibility APIs must not reveal a host bookkeeping
    // closure or a captured copy of the original function.
    lua_getglobal(state, "coroutine");
    if (lua_istable(state, -1))
    {
        lua_getfield(state, -1, "close");
        if (lua_iscfunction(state, -1))
        {
            impl_->coroutineCloseFunction = lua_tocfunction(state, -1);
            lua_pop(state, 1);
            lua_pushcfunction(state, coroutineClose, "close");
            lua_setfield(state, -2, "close");
        }
        else
            lua_pop(state, 1);
    }
    lua_pop(state, 1);

    static const luaL_Reg signalMeta[] = {
        {"__index", signalIndex},
        {"__newindex", signalNewIndex},
        {"__tostring", signalToString},
        {"__eq", signalEqual},
        {nullptr, nullptr},
    };
    luaL_newmetatable(state, "RBXScriptSignal.Native");
    luaL_register(state, nullptr, signalMeta);
    lua_pushliteral(state, "The metatable is locked");
    lua_setfield(state, -2, "__metatable");
    lua_pushliteral(state, "RBXScriptSignal");
    lua_setfield(state, -2, "__type");
    lua_pushvalue(state, -1);
    lua_setuserdatametatable(state, impl_->options.signalUserdataTag);
    lua_setreadonly(state, -1, 1);
    lua_pop(state, 1);
    lua_setuserdatadtor(state, impl_->options.signalUserdataTag, [](lua_State* L, void* pointer) {
        (void)L;
        static_cast<SignalUserdata*>(pointer)->~SignalUserdata();
    });

    static const luaL_Reg connectionMeta[] = {
        {"__index", connectionIndex},
        {"__newindex", connectionNewIndex},
        {"__tostring", connectionToString},
        {nullptr, nullptr},
    };
    luaL_newmetatable(state, "RBXScriptConnection.Native");
    luaL_register(state, nullptr, connectionMeta);
    lua_pushliteral(state, "The metatable is locked");
    lua_setfield(state, -2, "__metatable");
    lua_pushliteral(state, "RBXScriptConnection");
    lua_setfield(state, -2, "__type");
    lua_pushvalue(state, -1);
    lua_setuserdatametatable(state, impl_->options.connectionUserdataTag);
    lua_setreadonly(state, -1, 1);
    lua_pop(state, 1);
    lua_setuserdatadtor(state, impl_->options.connectionUserdataTag, [](lua_State* L, void* pointer) {
        (void)L;
        static_cast<ConnectionUserdata*>(pointer)->~ConnectionUserdata();
    });

    // These are integration-only entrypoints. The Roblox shim captures them as
    // locals and the host scrub removes the globals before user code executes.
    // Native signal userdata itself deliberately has no Fire member.
    lua_pushcfunction(state, nativeSignalNew, "__rbx_native_signal_new");
    lua_setglobal(state, "__rbx_native_signal_new");
    lua_pushcfunction(state, nativeSignalFire, "__rbx_native_signal_fire");
    lua_setglobal(state, "__rbx_native_signal_fire");
    lua_pushcfunction(state, nativeSignalDisconnectAll, "__rbx_native_signal_disconnect_all");
    lua_setglobal(state, "__rbx_native_signal_disconnect_all");
    lua_pushcfunction(state, nativeRunServiceConfigure, "__rbx_native_runservice_configure");
    lua_setglobal(state, "__rbx_native_runservice_configure");
    lua_pushcfunction(state, nativeRunServiceSetBindingCount, "__rbx_native_runservice_set_binding_count");
    lua_setglobal(state, "__rbx_native_runservice_set_binding_count");
    lua_pushcfunction(state, nativeModuleDeclare, "__rbx_native_module_declare");
    lua_setglobal(state, "__rbx_native_module_declare");
    lua_pushcclosurek(state, nativeModuleRequire, "__rbx_native_module_require", 0, nativeModuleContinue);
    lua_setglobal(state, "__rbx_native_module_require");
    lua_pushcfunction(state, nativeModuleFinish, "__rbx_native_module_finish");
    lua_setglobal(state, "__rbx_native_module_finish");
    lua_pushcclosurek(state, nativeHttpRequest, "__rbx_native_http_request", 0, nativeHttpContinue);
    lua_setglobal(state, "__rbx_native_http_request");

    if (impl_->options.installTaskLibrary)
    {
        static const luaL_Reg taskFunctions[] = {
            // Studio 0.729.0.7290838 next() layout is observable and differs
            // from declaration order; preserve the oracle-derived sequence.
            {"synchronize", taskSynchronize},
            {"delay", taskDelay},
            {"defer", taskDefer},
            {"spawn", taskSpawn},
            {"desynchronize", taskDesynchronize},
            {"cancel", taskCancel},
            {"wait", taskWait},
            {nullptr, nullptr},
        };
        lua_newtable(state);
        luaL_register(state, nullptr, taskFunctions);
        lua_setreadonly(state, -1, 1);
        lua_setglobal(state, "task");
    }
    impl_->installed = true;
}

void LuauRuntimeBridge::shutdown()
{
    if (!impl_ || !impl_->active)
        return;
    impl_->yieldRequests.clear();
    impl_->threadTasks.clear();
    impl_->moduleEvaluationStacks.clear();
    impl_->runServiceSignals.clear();
    impl_->runServiceBindingCount = 0;
    impl_->runServiceFrameArmed = false;
    impl_->release(impl_->runServiceCallbackReference);
    impl_->runServiceCallbackReference = LUA_NOREF;
    std::vector<int> references(impl_->references.begin(), impl_->references.end());
    for (int reference : references)
        impl_->release(reference);
    impl_->active = false;
    impl_->installed = false;
}

bool LuauRuntimeBridge::installed() const
{
    return impl_->installed;
}

void LuauRuntimeBridge::pushSignal(lua_State* state, std::shared_ptr<NativeSignal> signalValue)
{
    if (!signalValue)
        luaL_error(state, "cannot push a null RBXScriptSignal");
    void* storage = lua_newuserdatatagged(state, sizeof(SignalUserdata), impl_->options.signalUserdataTag);
    new (storage) SignalUserdata{std::move(signalValue)};
    lua_getuserdatametatable(state, impl_->options.signalUserdataTag);
    lua_setmetatable(state, -2);
}

bool LuauRuntimeBridge::isSignal(lua_State* state, int index) const
{
    return lua_isuserdata(state, index) && lua_userdatatag(state, index) == impl_->options.signalUserdataTag;
}

std::shared_ptr<NativeSignal> LuauRuntimeBridge::signal(lua_State* state, int index) const
{
    return checkSignal(state, index)->value;
}

std::size_t LuauRuntimeBridge::fire(lua_State* state, const std::shared_ptr<NativeSignal>& signalValue, int firstArgument, int argumentCount)
{
    auto pack = impl_->capture(state, firstArgument, argumentCount, shared_from_this());
    RuntimeValues arguments{RuntimeValue::opaque<const Impl::LuaArgumentPack>(pack, "LuaSignalArguments")};
    return signalValue->fire(std::move(arguments));
}

std::size_t LuauRuntimeBridge::fire(const std::shared_ptr<NativeSignal>& signalValue, RuntimeValues arguments)
{
    return signalValue->fire(std::move(arguments));
}

bool LuauRuntimeBridge::resumeCallerControlled(TaskId task, RuntimeValues arguments)
{
    ResumeData data;
    data.arguments = std::move(arguments);
    return impl_->context.scheduler().resumeManual(task, std::move(data));
}

LuauMainResult LuauRuntimeBridge::runMain(
    lua_State* state, int closureIndex, int firstArgument, int argumentCount, LuauMainRunOptions runOptions)
{
    if (!lua_isfunction(state, closureIndex))
        throw std::invalid_argument("runMain closureIndex must reference a function");
    if (argumentCount < 0 || (argumentCount > 0 && firstArgument == 0))
        throw std::invalid_argument("runMain argument range is invalid");
    if (runOptions.maxResumes == 0 || !std::isfinite(runOptions.maxVirtualSeconds) || runOptions.maxVirtualSeconds < 0.0 ||
        !std::isfinite(runOptions.maxWallSeconds) || runOptions.maxWallSeconds < 0.0)
        throw std::invalid_argument("runMain limits are invalid");

    const int functionReference = impl_->retain(state, closureIndex);
    auto pack = impl_->capture(state, firstArgument, argumentCount, shared_from_this());
    RuntimeValues arguments{RuntimeValue::opaque<const Impl::LuaArgumentPack>(pack, "LuaSignalArguments")};
    std::shared_ptr<Impl::LuaCall> call = impl_->makeCall(functionReference, std::move(arguments), shared_from_this());
    ThreadContext& mainCallContext = impl_->context.thread(call->coroutine);
    const ThreadContext& sourceContext = impl_->context.thread(state);
    mainCallContext.script = sourceContext.script;
    mainCallContext.security = sourceContext.security;
    mainCallContext.actorLane = sourceContext.actorLane;
    auto capture = std::make_shared<Impl::MainCapture>();
    call->mainCapture = capture;
    TaskCallback callback = [call](const ResumeData& data) {
        return call->resume(data);
    };

    Scheduler& scheduler = impl_->context.scheduler();
    // A RuntimeContext can host more than one top-level run (tests, local
    // tools, and scenario jobs do this deliberately). Terminal tasks remain
    // in the scheduler report, so do not misattribute an older failure to the
    // new main task.
    std::unordered_set<TaskId> preexistingTerminalTasks;
    for (const TaskSnapshot& taskSnapshot : scheduler.tasks())
    {
        if (taskSnapshot.status == TaskStatus::Completed || taskSnapshot.status == TaskStatus::Cancelled ||
            taskSnapshot.status == TaskStatus::Failed)
            preexistingTerminalTasks.insert(taskSnapshot.id);
    }
    const double startedAt = scheduler.now();
    const auto wallStartedAt = std::chrono::steady_clock::now();
    auto wallDeadline = std::chrono::steady_clock::time_point::max();
    const double maximumRepresentableWallSeconds =
        std::chrono::duration<double>(std::chrono::steady_clock::time_point::max() - wallStartedAt).count();
    if (runOptions.maxWallSeconds > 0.0 && runOptions.maxWallSeconds < maximumRepresentableWallSeconds)
        wallDeadline = wallStartedAt +
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(runOptions.maxWallSeconds));
    const auto beforeWallDeadline = [&] {
        return std::chrono::steady_clock::now() < wallDeadline;
    };
    const uint64_t resumeBaseline = scheduler.stats().totalResumes;
    const TaskExecutionMetadata metadata = impl_->context.taskMetadata(call->coroutine);
    const TaskId mainTask = scheduler.spawnImmediate(std::move(callback), "main", {}, metadata);

    LuauMainResult result;
    result.task = mainTask;
    bool mainCompleted = false;
    while (true)
    {
        result.resumes = static_cast<std::size_t>(scheduler.stats().totalResumes - resumeBaseline);
        const std::optional<TaskSnapshot> snapshot = scheduler.task(mainTask);
        if (!snapshot)
        {
            result.state = LuauMainState::Failed;
            result.error = "main scheduler task disappeared";
            break;
        }
        if (snapshot->status == TaskStatus::Completed)
            mainCompleted = true;
        if (snapshot->status == TaskStatus::Failed || snapshot->status == TaskStatus::Cancelled)
        {
            result.state = LuauMainState::Failed;
            result.error = !capture->error.empty() ? capture->error : snapshot->error;
            break;
        }
        bool backgroundFailed = false;
        for (const TaskSnapshot& taskSnapshot : scheduler.tasks())
        {
            if (taskSnapshot.id != mainTask && !preexistingTerminalTasks.contains(taskSnapshot.id) &&
                taskSnapshot.status == TaskStatus::Failed)
            {
                result.state = LuauMainState::Failed;
                result.error = taskSnapshot.error.empty() ? "background task failed" : taskSnapshot.error;
                backgroundFailed = true;
                break;
            }
        }
        if (backgroundFailed)
            break;
        if (result.resumes >= runOptions.maxResumes)
        {
            result.state = LuauMainState::SteadyState;
            break;
        }

        if (scheduler.step())
            continue;
        bool hasNonTerminalBackground = false;
        bool hasExternalWait = snapshot->status == TaskStatus::WaitingExternal;
        std::string backgroundError;
        for (const TaskSnapshot& taskSnapshot : scheduler.tasks())
        {
            if (taskSnapshot.id == mainTask)
                continue;
            if (!preexistingTerminalTasks.contains(taskSnapshot.id) && taskSnapshot.status == TaskStatus::Failed && backgroundError.empty())
                backgroundError = taskSnapshot.error.empty() ? "background task failed" : taskSnapshot.error;
            if (taskSnapshot.status != TaskStatus::Completed && taskSnapshot.status != TaskStatus::Cancelled && taskSnapshot.status != TaskStatus::Failed)
            {
                hasNonTerminalBackground = true;
                hasExternalWait = hasExternalWait || taskSnapshot.status == TaskStatus::WaitingExternal;
            }
        }
        if (!backgroundError.empty())
        {
            result.state = LuauMainState::Failed;
            result.error = std::move(backgroundError);
            break;
        }
        const bool hasActiveExecution = !mainCompleted || hasNonTerminalBackground;
        const bool runServiceFrameArmed = impl_->armRunServiceFrame(hasActiveExecution);
        if (runOptions.advanceVirtualTimers && scheduler.clock()->mode() == ClockMode::Virtual)
        {
            const std::optional<double> nextDue = scheduler.nextTimerDue();
            const double deadline = startedAt + runOptions.maxVirtualSeconds;
            if (runServiceFrameArmed && impl_->nextRunServiceFrameDue <= deadline + 1e-12 &&
                (!nextDue || impl_->nextRunServiceFrameDue <= *nextDue + 1e-12))
            {
                if (impl_->nextRunServiceFrameDue > scheduler.now())
                    scheduler.advanceBy(impl_->nextRunServiceFrameDue - scheduler.now());
                impl_->scheduleRunServiceFrame(shared_from_this());
                continue;
            }
            if (nextDue && *nextDue <= deadline + 1e-12 && scheduler.advanceToNextTimer())
                continue;
            if (nextDue && scheduler.now() < deadline)
                scheduler.advanceBy(deadline - scheduler.now());
        }
        if (scheduler.clock()->mode() == ClockMode::Realtime && runServiceFrameArmed && beforeWallDeadline())
        {
            const double remaining = impl_->nextRunServiceFrameDue - scheduler.now();
            if (remaining <= 1e-6)
            {
                impl_->scheduleRunServiceFrame(shared_from_this());
                continue;
            }
            std::this_thread::sleep_for(std::min(std::chrono::duration<double>(remaining), std::chrono::duration<double>(0.001)));
            continue;
        }
        if (scheduler.clock()->mode() == ClockMode::Realtime && scheduler.nextTimerDue() && beforeWallDeadline())
        {
            const double remaining = std::max(0.0, *scheduler.nextTimerDue() - scheduler.now());
            std::this_thread::sleep_for(std::min(std::chrono::duration<double>(remaining), std::chrono::duration<double>(0.001)));
            continue;
        }
        if (hasExternalWait && beforeWallDeadline())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        if (mainCompleted)
            result.state = hasNonTerminalBackground ? LuauMainState::SteadyState : LuauMainState::Completed;
        else
            result.state = snapshot->status == TaskStatus::Suspended || snapshot->status == TaskStatus::WaitingModule ||
                    snapshot->status == TaskStatus::WaitingExternal
                ? LuauMainState::Blocked
                : LuauMainState::SteadyState;
        break;
    }
    const std::optional<TaskSnapshot> finalSnapshot = scheduler.task(mainTask);
    mainCompleted = mainCompleted || (finalSnapshot && finalSnapshot->status == TaskStatus::Completed);
    result.mainCompleted = mainCompleted;
    if (mainCompleted)
        result.registryReferences = std::move(capture->results);
    result.elapsedVirtualSeconds = std::max(0.0, scheduler.now() - startedAt);
    return result;
}

int LuauRuntimeBridge::pushMainResults(lua_State* destination, const LuauMainResult& result) const
{
    for (int reference : result.registryReferences)
    {
        lua_getref(impl_->context.mainState(), reference);
        if (destination != impl_->context.mainState())
            lua_xmove(impl_->context.mainState(), destination, 1);
    }
    return static_cast<int>(result.registryReferences.size());
}

void LuauRuntimeBridge::releaseMainResults(LuauMainResult& result)
{
    for (int reference : result.registryReferences)
        impl_->release(reference);
    result.registryReferences.clear();
}

std::optional<TaskId> LuauRuntimeBridge::taskForThread(lua_State* thread) const
{
    auto found = impl_->threadTasks.find(thread);
    return found == impl_->threadTasks.end() ? std::nullopt : std::optional(found->second);
}

RuntimeContext& LuauRuntimeBridge::context()
{
    return impl_->context;
}

const LuauRuntimeBridgeOptions& LuauRuntimeBridge::options() const
{
    return impl_->options;
}

LuauRuntimeBridge* LuauRuntimeBridge::from(lua_State* state)
{
    RuntimeContext* contextValue = RuntimeContext::from(state);
    return contextValue ? contextValue->subsystem<LuauRuntimeBridge>(kSubsystemKey) : nullptr;
}

LuauRuntimeBridge::SignalUserdata* LuauRuntimeBridge::checkSignal(lua_State* state, int index)
{
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge)
        luaL_error(state, "Luau runtime bridge is not installed");
    void* pointer = lua_touserdatatagged(state, index, bridge->impl_->options.signalUserdataTag);
    if (!pointer)
        luaL_typeerror(state, index, "RBXScriptSignal");
    return static_cast<SignalUserdata*>(pointer);
}

LuauRuntimeBridge::ConnectionUserdata* LuauRuntimeBridge::checkConnection(lua_State* state, int index)
{
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge)
        luaL_error(state, "Luau runtime bridge is not installed");
    void* pointer = lua_touserdatatagged(state, index, bridge->impl_->options.connectionUserdataTag);
    if (!pointer)
        luaL_typeerror(state, index, "RBXScriptConnection");
    return static_cast<ConnectionUserdata*>(pointer);
}

int LuauRuntimeBridge::signalIndex(lua_State* state)
{
    checkSignal(state, 1);
    const char* key = luaL_checkstring(state, 2);
    if (std::string_view(key) == "Connect")
        lua_pushcfunction(state, signalConnect, "Connect");
    else if (std::string_view(key) == "Once")
        lua_pushcfunction(state, signalOnce, "Once");
    else if (std::string_view(key) == "Wait")
        lua_pushcfunction(state, signalWait, "Wait");
    else
        lua_pushnil(state);
    return 1;
}

int LuauRuntimeBridge::signalNewIndex(lua_State* state)
{
    luaL_error(state, "RBXScriptSignal is read-only");
    return 0;
}

int LuauRuntimeBridge::signalToString(lua_State* state)
{
    SignalUserdata* userdata = checkSignal(state, 1);
    lua_pushfstring(state, "Signal %s", userdata->value->name().c_str());
    return 1;
}

int LuauRuntimeBridge::signalEqual(lua_State* state)
{
    SignalUserdata* first = checkSignal(state, 1);
    SignalUserdata* second = checkSignal(state, 2);
    lua_pushboolean(state, first->value == second->value);
    return 1;
}

int LuauRuntimeBridge::signalConnect(lua_State* state)
{
    SignalUserdata* userdata = checkSignal(state, 1);
    luaL_checktype(state, 2, LUA_TFUNCTION);
    LuauRuntimeBridge* rawBridge = from(state);
    std::shared_ptr<LuauRuntimeBridge> bridge = rawBridge->shared_from_this();
    const int connectionFunction = rawBridge->impl_->retain(state, 2);
    std::weak_ptr<LuauRuntimeBridge> weakBridge = bridge;
    const ThreadContext& sourceThread = rawBridge->context().thread(state);
    ScriptEnvironment sourceScript = sourceThread.script;
    SecurityDescriptor sourceSecurity = sourceThread.security;
    ActorLane sourceLane = sourceThread.actorLane;
    SignalTaskFactory factory = [weakBridge, connectionFunction, sourceScript = std::move(sourceScript), sourceSecurity, sourceLane](
                                    const SignalArguments& arguments) -> TaskCallback {
        std::shared_ptr<LuauRuntimeBridge> owner = weakBridge.lock();
        if (!owner)
            return [](const ResumeData&) { return TaskStep::fail("signal bridge was destroyed"); };
        const int callFunction = owner->impl_->cloneReference(connectionFunction);
        std::shared_ptr<Impl::LuaCall> call = owner->impl_->makeCall(callFunction, arguments, owner);
        ThreadContext& child = owner->context().thread(call->coroutine);
        child.script = sourceScript;
        child.security = sourceSecurity;
        child.actorLane = sourceLane;
        return [call](const ResumeData& data) { return call->resume(data); };
    };

    SignalConnection connection;
    try
    {
        connection = userdata->value->connect(std::move(factory), "RBXScriptSignal connection");
    }
    catch (...)
    {
        rawBridge->impl_->release(connectionFunction);
        throw;
    }
    connection.setDisconnectCallback([weakBridge, connectionFunction] {
        if (std::shared_ptr<LuauRuntimeBridge> owner = weakBridge.lock())
            owner->impl_->release(connectionFunction);
    });
    void* storage = lua_newuserdatatagged(state, sizeof(ConnectionUserdata), rawBridge->impl_->options.connectionUserdataTag);
    new (storage) ConnectionUserdata{std::move(connection)};
    lua_getuserdatametatable(state, rawBridge->impl_->options.connectionUserdataTag);
    lua_setmetatable(state, -2);
    return 1;
}

int LuauRuntimeBridge::signalOnce(lua_State* state)
{
    SignalUserdata* userdata = checkSignal(state, 1);
    luaL_checktype(state, 2, LUA_TFUNCTION);
    LuauRuntimeBridge* rawBridge = from(state);
    std::shared_ptr<LuauRuntimeBridge> bridge = rawBridge->shared_from_this();
    const int connectionFunction = rawBridge->impl_->retain(state, 2);
    std::weak_ptr<LuauRuntimeBridge> weakBridge = bridge;
    const ThreadContext& sourceThread = rawBridge->context().thread(state);
    ScriptEnvironment sourceScript = sourceThread.script;
    SecurityDescriptor sourceSecurity = sourceThread.security;
    ActorLane sourceLane = sourceThread.actorLane;
    SignalTaskFactory factory = [weakBridge, connectionFunction, sourceScript = std::move(sourceScript), sourceSecurity, sourceLane](
                                    const SignalArguments& arguments) -> TaskCallback {
        std::shared_ptr<LuauRuntimeBridge> owner = weakBridge.lock();
        if (!owner)
            return [](const ResumeData&) { return TaskStep::fail("signal bridge was destroyed"); };
        const int callFunction = owner->impl_->cloneReference(connectionFunction);
        std::shared_ptr<Impl::LuaCall> call = owner->impl_->makeCall(callFunction, arguments, owner);
        ThreadContext& child = owner->context().thread(call->coroutine);
        child.script = sourceScript;
        child.security = sourceSecurity;
        child.actorLane = sourceLane;
        return [call](const ResumeData& data) { return call->resume(data); };
    };
    SignalConnection connection = userdata->value->once(std::move(factory), "RBXScriptSignal once connection");
    connection.setDisconnectCallback([weakBridge, connectionFunction] {
        if (std::shared_ptr<LuauRuntimeBridge> owner = weakBridge.lock())
            owner->impl_->release(connectionFunction);
    });
    void* storage = lua_newuserdatatagged(state, sizeof(ConnectionUserdata), rawBridge->impl_->options.connectionUserdataTag);
    new (storage) ConnectionUserdata{std::move(connection)};
    lua_getuserdatametatable(state, rawBridge->impl_->options.connectionUserdataTag);
    lua_setmetatable(state, -2);
    return 1;
}

int LuauRuntimeBridge::signalWait(lua_State* state)
{
    SignalUserdata* userdata = checkSignal(state, 1);
    LuauRuntimeBridge* bridge = from(state);
    std::shared_ptr<LuauRuntimeBridge> owner = bridge->shared_from_this();
    Scheduler& scheduler = bridge->impl_->context.scheduler();
    std::optional<TaskId> task = scheduler.currentTask();
    if (!task)
    {
        luaL_error(state, "RBXScriptSignal:Wait must run in a scheduled coroutine");
        return 0;
    }
    ThreadContext* threadContext = RuntimeContext::threadFrom(state);
    const std::optional<TaskSnapshot> running = scheduler.task(*task);
    if (!threadContext || !running)
    {
        luaL_error(state, "RBXScriptSignal:Wait coroutine has no runtime context");
        return 0;
    }
    if (running->execution.threadContextId != threadContext->id)
    {
        std::shared_ptr<Impl::LuaCall> call = bridge->impl_->adoptCall(state, owner);
        TaskCallback callback = [call](const ResumeData& data) {
            return call->resume(data);
        };
        task = scheduler.adoptSuspended(
            std::move(callback), TaskStatus::WaitingSignal, userdata->value->name(), "manual signal waiter", bridge->context().taskMetadata(state));
        call->bindTask(owner, *task);
        if (!userdata->value->wait(*task))
        {
            scheduler.cancel(*task, "unable to register signal waiter");
            luaL_error(state, "unable to register signal waiter");
            return 0;
        }
        return lua_yield(state, 0);
    }
    if (!userdata->value->wait(*task))
    {
        luaL_error(state, "unable to register signal waiter");
        return 0;
    }
    bridge->impl_->yieldRequests[state] = LuaYieldRequest{LuaYieldKind::Signal, 0.0, userdata->value->name()};
    return lua_yield(state, 0);
}

int LuauRuntimeBridge::signalDestroy(lua_State* state)
{
    checkSignal(state, 1)->~SignalUserdata();
    return 0;
}

int LuauRuntimeBridge::connectionIndex(lua_State* state)
{
    ConnectionUserdata* userdata = checkConnection(state, 1);
    const char* key = luaL_checkstring(state, 2);
    if (std::string_view(key) == "Connected")
        lua_pushboolean(state, userdata->value.connected());
    else if (std::string_view(key) == "Disconnect")
        lua_pushcfunction(state, connectionDisconnect, "Disconnect");
    else
        lua_pushnil(state);
    return 1;
}

int LuauRuntimeBridge::connectionNewIndex(lua_State* state)
{
    luaL_error(state, "RBXScriptConnection is read-only");
    return 0;
}

int LuauRuntimeBridge::connectionToString(lua_State* state)
{
    checkConnection(state, 1);
    lua_pushliteral(state, "Connection");
    return 1;
}

int LuauRuntimeBridge::connectionDisconnect(lua_State* state)
{
    checkConnection(state, 1)->value.disconnect();
    return 0;
}

int LuauRuntimeBridge::connectionDestroy(lua_State* state)
{
    checkConnection(state, 1)->~ConnectionUserdata();
    return 0;
}

int LuauRuntimeBridge::nativeSignalNew(lua_State* state)
{
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge)
    {
        luaL_error(state, "Luau runtime bridge is not installed");
        return 0;
    }
    size_t nameLength = 0;
    const char* name = lua_gettop(state) >= 1 && !lua_isnil(state, 1) ? luaL_checklstring(state, 1, &nameLength) : "Signal";
    if (lua_gettop(state) < 1 || lua_isnil(state, 1))
        nameLength = 6;
    if (nameLength == 0 || nameLength > 256 || std::find(name, name + nameLength, '\0') != name + nameLength)
    {
        luaL_error(state, "native signal name must be 1-256 bytes without NUL characters");
        return 0;
    }
    const bool deferred = lua_gettop(state) >= 2 && lua_toboolean(state, 2);
    bridge->pushSignal(state,
        bridge->context().createSignal(std::string(name, nameLength), deferred ? SignalBehavior::Deferred : SignalBehavior::Immediate));
    return 1;
}

int LuauRuntimeBridge::nativeSignalFire(lua_State* state)
{
    SignalUserdata* signalValue = checkSignal(state, 1);
    LuauRuntimeBridge* bridge = from(state);
    bridge->fire(state, signalValue->value, 2, std::max(0, lua_gettop(state) - 1));
    return 0;
}

int LuauRuntimeBridge::nativeSignalDisconnectAll(lua_State* state)
{
    SignalUserdata* signalValue = checkSignal(state, 1);
    signalValue->value->disconnectAll(true);
    return 0;
}

int LuauRuntimeBridge::nativeRunServiceConfigure(lua_State* state)
{
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge)
    {
        luaL_error(state, "Luau runtime bridge is not installed");
        return 0;
    }
    luaL_checktype(state, 1, LUA_TFUNCTION);
    if (lua_gettop(state) != 8)
    {
        luaL_error(state, "native RunService configuration requires a callback and seven phase signals");
        return 0;
    }
    std::vector<std::shared_ptr<NativeSignal>> signals;
    signals.reserve(7);
    for (int index = 2; index <= 8; ++index)
    {
        SignalUserdata* signal = checkSignal(state, index);
        signal->value->setBehavior(SignalBehavior::Immediate);
        signals.push_back(signal->value);
    }
    bridge->impl_->release(bridge->impl_->runServiceCallbackReference);
    bridge->impl_->runServiceCallbackReference = bridge->impl_->retain(state, 1);
    bridge->impl_->runServiceSignals = std::move(signals);
    bridge->impl_->runServiceBindingCount = 0;
    bridge->impl_->runServiceFrameArmed = false;
    const ThreadContext& source = bridge->context().thread(state);
    bridge->impl_->runServiceScript = source.script;
    bridge->impl_->runServiceSecurity = source.security;
    bridge->impl_->runServiceActorLane = source.actorLane;
    return 0;
}

int LuauRuntimeBridge::nativeRunServiceSetBindingCount(lua_State* state)
{
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge)
    {
        luaL_error(state, "Luau runtime bridge is not installed");
        return 0;
    }
    uint64_t count = 0;
    if (lua_isinteger64(state, 1))
    {
        int exact = 0;
        const int64_t integer = lua_tointeger64(state, 1, &exact);
        if (!exact || integer < 0)
        {
            luaL_error(state, "RunService binding count must be a non-negative integer");
            return 0;
        }
        count = static_cast<uint64_t>(integer);
    }
    else
    {
        const double number = luaL_checknumber(state, 1);
        if (!std::isfinite(number) || number < 0.0 || std::floor(number) != number ||
            number > static_cast<double>(std::numeric_limits<std::size_t>::max()))
        {
            luaL_error(state, "RunService binding count must be a non-negative integer");
            return 0;
        }
        count = static_cast<uint64_t>(number);
    }
    if (count > 100000)
    {
        luaL_error(state, "RunService binding count exceeds the runtime limit");
        return 0;
    }
    bridge->impl_->runServiceBindingCount = static_cast<std::size_t>(count);
    if (count == 0)
        bridge->impl_->runServiceFrameArmed = false;
    return 0;
}

int LuauRuntimeBridge::nativeModuleDeclare(lua_State* state)
{
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge)
    {
        luaL_error(state, "Luau runtime bridge is not installed");
        return 0;
    }
    size_t nameLength = 0;
    size_t sourceLength = 0;
    const char* name = luaL_checklstring(state, 1, &nameLength);
    const char* source = luaL_checklstring(state, 2, &sourceLength);
    ModuleRegistry& modules = bridge->context().modules();
    ModuleId id = bridge->impl_->nextModuleId;
    while (id != 0 && modules.contains(id))
        ++id;
    if (id == 0 || static_cast<double>(id) > 9007199254740991.0)
    {
        luaL_error(state, "native ModuleScript id space is exhausted");
        return 0;
    }
    if (!modules.declare(id, std::string(name, nameLength)))
    {
        luaL_error(state, "native ModuleScript declaration collided");
        return 0;
    }
    modules.setSource(modules.hostSourceAccess(), id, std::string(source, sourceLength));
    bridge->impl_->nextModuleId = id + 1;
    lua_pushinteger64(state, static_cast<int64_t>(id));
    return 1;
}

int LuauRuntimeBridge::nativeModuleRequire(lua_State* state)
{
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge)
    {
        luaL_error(state, "Luau runtime bridge is not installed");
        return 0;
    }
    const ModuleId module = checkModuleId(state, 1);
    Scheduler& scheduler = bridge->context().scheduler();
    const std::optional<TaskId> task = scheduler.currentTask();
    ThreadContext* thread = RuntimeContext::threadFrom(state);
    const std::optional<TaskSnapshot> running = task ? scheduler.task(*task) : std::nullopt;
    if (!task || !thread || !running)
    {
        luaL_error(state, "require must run in a native scheduled coroutine");
        return 0;
    }
    if (running->execution.threadContextId != thread->id)
    {
        luaL_error(state, "require from a manually resumed coroutine is not supported");
        return 0;
    }

    const RequireDecision decision = bridge->context().modules().require(module, thread->script.evaluatingModule, *task);
    switch (decision.action)
    {
    case RequireAction::StartLoading:
        bridge->impl_->moduleEvaluationStacks[state].push_back(module);
        thread->script.evaluatingModule = module;
        scheduler.setTaskMetadata(*task, bridge->context().taskMetadata(state));
        lua_pushboolean(state, true);
        return 1;
    case RequireAction::ReturnCached:
        return bridge->impl_->pushCachedModule(state, module);
    case RequireAction::Wait:
        bridge->impl_->yieldRequests[state] = LuaYieldRequest{LuaYieldKind::Module, 0.0, "ModuleScript:" + std::to_string(module)};
        return lua_yield(state, 0);
    case RequireAction::RaiseCachedError:
    case RequireAction::CycleError:
    case RequireAction::UnknownModule:
        luaL_error(state, "%s", decision.error.empty() ? "ModuleScript require failed" : decision.error.c_str());
        return 0;
    }
    luaL_error(state, "ModuleScript require returned an invalid decision");
    return 0;
}

int LuauRuntimeBridge::nativeModuleContinue(lua_State* state, int status)
{
    (void)status;
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge)
    {
        luaL_error(state, "Luau runtime bridge is not installed");
        return 0;
    }
    // Luau currently preserves the original C argument below resume values,
    // while the scheduler's module wake protocol appends {success, moduleId,
    // [error]}. Accept both layouts explicitly so a VM stack-policy change
    // cannot reinterpret the success boolean as an id.
    int moduleIndex = 1;
    if (lua_isboolean(state, 1))
    {
        if (lua_gettop(state) < 2)
        {
            luaL_error(state, "ModuleScript wake result omitted its module id");
            return 0;
        }
        moduleIndex = 2;
    }
    const ModuleId module = checkModuleId(state, moduleIndex);
    const ModuleState moduleState = bridge->context().modules().state(module);
    if (moduleState == ModuleState::Loaded)
        return bridge->impl_->pushCachedModule(state, module);
    if (moduleState == ModuleState::Failed)
    {
        const std::optional<std::string> error = bridge->context().modules().cachedError(module);
        luaL_error(state, "%s", error ? error->c_str() : "ModuleScript failed");
        return 0;
    }
    luaL_error(state, "ModuleScript waiter resumed before the module reached a terminal state");
    return 0;
}

int LuauRuntimeBridge::nativeModuleFinish(lua_State* state)
{
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge)
    {
        luaL_error(state, "Luau runtime bridge is not installed");
        return 0;
    }
    const ModuleId module = checkModuleId(state, 1);
    const bool succeeded = lua_toboolean(state, 2);
    const double returnCountValue = luaL_checknumber(state, 3);
    if (!std::isfinite(returnCountValue) || returnCountValue < 0.0 || std::floor(returnCountValue) != returnCountValue ||
        returnCountValue > static_cast<double>(std::numeric_limits<std::size_t>::max()))
    {
        luaL_error(state, "ModuleScript return count must be a non-negative integer");
        return 0;
    }
    const std::optional<TaskId> task = bridge->context().scheduler().currentTask();
    if (!task)
    {
        luaL_error(state, "ModuleScript completion must run in its native loader task");
        return 0;
    }

    bool accepted = false;
    if (succeeded)
    {
        if (lua_gettop(state) < 4)
            lua_pushnil(state);
        auto pack = bridge->impl_->capture(state, 4, 1, bridge->shared_from_this());
        accepted = bridge->context().modules().finishSuccess(module, *task,
            RuntimeValue::opaque<const Impl::LuaArgumentPack>(pack, "LuaSignalArguments"), static_cast<std::size_t>(returnCountValue));
    }
    else
    {
        size_t errorLength = 0;
        const char* error = luaL_checklstring(state, 4, &errorLength);
        accepted = bridge->context().modules().finishFailure(module, *task, std::string(error, errorLength));
    }
    if (!accepted)
    {
        luaL_error(state, "ModuleScript completion did not match its active loader");
        return 0;
    }
    try
    {
        bridge->impl_->restoreEvaluatingModule(state, module);
    }
    catch (const std::exception& exception)
    {
        luaL_error(state, "%s", exception.what());
        return 0;
    }
    bridge->context().scheduler().setTaskMetadata(*task, bridge->context().taskMetadata(state));
    if (bridge->context().modules().state(module) == ModuleState::Loaded)
    {
        lua_pushboolean(state, true);
        return 1;
    }
    const std::optional<std::string> error = bridge->context().modules().cachedError(module);
    lua_pushboolean(state, false);
    lua_pushstring(state, error ? error->c_str() : "ModuleScript failed");
    return 2;
}

int LuauRuntimeBridge::nativeHttpRequest(lua_State* state)
{
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge)
    {
        luaL_error(state, "Luau runtime bridge is not installed");
        return 0;
    }
    NetworkBroker* broker = bridge->context().network();
    if (!broker)
    {
        luaL_error(state, "HTTP request failed (offline): native network broker is not installed");
        return 0;
    }
    luaL_checktype(state, 1, LUA_TTABLE);
    const int optionsIndex = lua_absindex(state, 1);
    NetworkRequest request;

    lua_getfield(state, optionsIndex, "Url");
    size_t length = 0;
    const char* text = luaL_checklstring(state, -1, &length);
    request.url.assign(text, length);
    lua_pop(state, 1);

    lua_getfield(state, optionsIndex, "Method");
    if (!lua_isnil(state, -1))
    {
        text = luaL_checklstring(state, -1, &length);
        request.method.assign(text, length);
    }
    lua_pop(state, 1);

    lua_getfield(state, optionsIndex, "Body");
    if (!lua_isnil(state, -1))
    {
        text = luaL_checklstring(state, -1, &length);
        request.body.assign(text, length);
    }
    lua_pop(state, 1);

    lua_getfield(state, optionsIndex, "Headers");
    if (!lua_isnil(state, -1))
    {
        luaL_checktype(state, -1, LUA_TTABLE);
        const int headersIndex = lua_absindex(state, -1);
        lua_pushnil(state);
        while (lua_next(state, headersIndex) != 0)
        {
            if (!lua_isstring(state, -2) || !lua_isstring(state, -1))
            {
                lua_pop(state, 2);
                luaL_error(state, "RequestAsync Headers keys and values must be strings");
                return 0;
            }
            size_t nameLength = 0;
            size_t valueLength = 0;
            const char* name = lua_tolstring(state, -2, &nameLength);
            const char* value = lua_tolstring(state, -1, &valueLength);
            request.headers.emplace(std::string(name, nameLength), std::string(value, valueLength));
            lua_pop(state, 1);
        }
    }
    lua_pop(state, 1);

    lua_getfield(state, optionsIndex, "Cookies");
    if (!lua_isnil(state, -1))
    {
        std::string cookies;
        if (lua_isstring(state, -1))
        {
            const char* cookieText = lua_tolstring(state, -1, &length);
            cookies.assign(cookieText, length);
        }
        else if (lua_istable(state, -1))
        {
            std::vector<std::pair<std::string, std::string>> entries;
            const int cookiesIndex = lua_absindex(state, -1);
            lua_pushnil(state);
            while (lua_next(state, cookiesIndex) != 0)
            {
                if (!lua_isstring(state, -2) || !lua_isstring(state, -1))
                {
                    lua_pop(state, 2);
                    luaL_error(state, "request Cookies keys and values must be strings");
                    return 0;
                }
                size_t nameLength = 0;
                size_t valueLength = 0;
                const char* name = lua_tolstring(state, -2, &nameLength);
                const char* value = lua_tolstring(state, -1, &valueLength);
                entries.emplace_back(std::string(name, nameLength), std::string(value, valueLength));
                lua_pop(state, 1);
            }
            std::sort(entries.begin(), entries.end());
            for (const auto& [name, value] : entries)
            {
                if (!cookies.empty())
                    cookies += "; ";
                cookies += name + "=" + value;
            }
        }
        else
        {
            lua_pop(state, 1);
            luaL_error(state, "request Cookies must be a table or string");
            return 0;
        }
        if (!cookies.empty())
        {
            auto existing = findHeader(request.headers, "Cookie");
            if (existing == request.headers.end())
                request.headers.emplace("Cookie", std::move(cookies));
            else if (!existing->second.empty())
                existing->second += "; " + cookies;
            else
                existing->second = std::move(cookies);
        }
    }
    lua_pop(state, 1);

    lua_getfield(state, optionsIndex, "Timeout");
    if (!lua_isnil(state, -1))
    {
        const double seconds = luaL_checknumber(state, -1);
        if (!std::isfinite(seconds) || seconds <= 0.0 || seconds > static_cast<double>(std::numeric_limits<int64_t>::max()) / 1000.0)
        {
            lua_pop(state, 1);
            luaL_error(state, "RequestAsync Timeout must be a positive finite number");
            return 0;
        }
        request.timeout = std::chrono::milliseconds(static_cast<int64_t>(std::ceil(seconds * 1000.0)));
    }
    lua_pop(state, 1);

    lua_getfield(state, optionsIndex, "RedirectLimit");
    if (!lua_isnil(state, -1))
    {
        const double redirects = luaL_checknumber(state, -1);
        if (!std::isfinite(redirects) || redirects < 0.0 || redirects > static_cast<double>(std::numeric_limits<std::size_t>::max()) ||
            std::floor(redirects) != redirects)
        {
            lua_pop(state, 1);
            luaL_error(state, "RequestAsync RedirectLimit must be a non-negative finite integer");
            return 0;
        }
        request.redirectLimit = static_cast<std::size_t>(redirects);
    }
    lua_pop(state, 1);

    request.headers = bridge->context().executor().applyRequestPersona(request.headers);
    if (findHeader(request.headers, "User-Agent") == request.headers.end())
        request.headers.emplace("User-Agent", "Roblox/WinInet");
    std::shared_ptr<const NetworkRequest> observedRequest;
    if (bridge->context().options().executionMode == ExecutionMode::Diagnostic && bridge->impl_->options.httpResponseObserver)
        observedRequest = std::make_shared<const NetworkRequest>(request);

    Scheduler& scheduler = bridge->context().scheduler();
    std::optional<TaskId> task = scheduler.currentTask();
    if (!task)
    {
        luaL_error(state, "RequestAsync must run in a native scheduled coroutine");
        return 0;
    }
    ThreadContext* threadContext = RuntimeContext::threadFrom(state);
    const std::optional<TaskSnapshot> running = scheduler.task(*task);
    if (!threadContext || !running)
    {
        luaL_error(state, "RequestAsync coroutine has no runtime context");
        return 0;
    }

    std::shared_ptr<LuauRuntimeBridge> owner = bridge->shared_from_this();
    bool adopted = false;
    if (running->execution.threadContextId != threadContext->id)
    {
        std::shared_ptr<Impl::LuaCall> call = bridge->impl_->adoptCall(state, owner);
        TaskCallback callback = [call](const ResumeData& data) { return call->resume(data); };
        task = scheduler.adoptSuspended(
            std::move(callback), TaskStatus::WaitingExternal, request.url, "manual HTTP request", bridge->context().taskMetadata(state));
        call->bindTask(owner, *task);
        adopted = true;
    }

    const std::string requestUrl = request.url;
    auto pending = std::make_shared<Impl::HttpPending>();
    pending->task = *task;
    std::weak_ptr<LuauRuntimeBridge> weakOwner = owner;
    try
    {
        pending->request = broker->submit(std::move(request), [weakOwner, pending, requestUrl, observedRequest](NetworkResult result) mutable {
            std::shared_ptr<LuauRuntimeBridge> callbackOwner = weakOwner.lock();
            if (!callbackOwner)
                return;
            Scheduler& callbackScheduler = callbackOwner->context().scheduler();
            if (pending->cancellationObserver != 0)
                callbackScheduler.removeCancellationObserver(pending->task, pending->cancellationObserver);
            if (result && observedRequest && callbackOwner->context().options().executionMode == ExecutionMode::Diagnostic &&
                callbackOwner->impl_->options.httpResponseObserver)
            {
                try
                {
                    callbackOwner->impl_->options.httpResponseObserver(*observedRequest, result.response);
                }
                catch (...)
                {
                    // Capturing diagnostics must never alter request semantics.
                }
            }
            callbackOwner->impl_->traceNetwork(result, requestUrl);
            ResumeData data;
            data.arguments = callbackOwner->impl_->networkResultValues(std::move(result), callbackOwner, requestUrl);
            data.sourceName = "http";
            callbackScheduler.resume(pending->task, std::move(data), QueueKind::External);
        });
        pending->cancellationObserver = scheduler.addCancellationObserver(*task, [weakOwner, pending] {
            if (std::shared_ptr<LuauRuntimeBridge> callbackOwner = weakOwner.lock())
            {
                if (NetworkBroker* activeBroker = callbackOwner->context().network())
                    activeBroker->cancel(pending->request);
            }
        });
    }
    catch (const std::exception& exception)
    {
        if (adopted)
            scheduler.cancel(*task, "HTTP submission failed");
        luaL_error(state, "HTTP request submission failed: %s", exception.what());
        return 0;
    }

    if (!adopted)
        bridge->impl_->yieldRequests[state] = LuaYieldRequest{LuaYieldKind::External, 0.0, requestUrl};
    return lua_yield(state, 0);
}

int LuauRuntimeBridge::nativeHttpContinue(lua_State* state, int status)
{
    (void)status;
    const int top = lua_gettop(state);
    // Luau preserves the original C-function arguments below values supplied
    // to lua_resume. Our completion protocol always appends {ok, value}.
    const int successIndex = top - 1;
    const int valueIndex = top;
    if (successIndex < 1 || !lua_isboolean(state, successIndex))
    {
        luaL_error(state, "native HTTP completion returned an invalid result");
        return 0;
    }
    if (!lua_toboolean(state, successIndex))
    {
        const char* message = lua_tostring(state, valueIndex);
        luaL_error(state, "%s", message ? message : "HTTP request failed");
        return 0;
    }
    lua_pushvalue(state, valueIndex);
    return 1;
}

int LuauRuntimeBridge::taskSpawn(lua_State* state)
{
    if (!lua_isfunction(state, 1) && !lua_isthread(state, 1))
    {
        luaL_error(state, "invalid argument #1 to 'spawn' (function or thread expected)");
        return 0;
    }
    LuauRuntimeBridge* bridge = from(state);
    Impl::ScheduledTask scheduled = bridge->impl_->schedule(state, 1, 2, lua_gettop(state) - 1, QueueKind::Spawn, 0.0);
    lua_getref(bridge->context().mainState(), scheduled.returnedThreadReference);
    lua_xmove(bridge->context().mainState(), state, 1);
    bridge->impl_->release(scheduled.returnedThreadReference);
    return 1;
}

int LuauRuntimeBridge::taskDefer(lua_State* state)
{
    if (!lua_isfunction(state, 1) && !lua_isthread(state, 1))
    {
        luaL_error(state, "invalid argument #1 to 'defer' (function or thread expected)");
        return 0;
    }
    LuauRuntimeBridge* bridge = from(state);
    Impl::ScheduledTask scheduled = bridge->impl_->schedule(state, 1, 2, lua_gettop(state) - 1, QueueKind::Deferred, 0.0);
    lua_getref(bridge->context().mainState(), scheduled.returnedThreadReference);
    lua_xmove(bridge->context().mainState(), state, 1);
    bridge->impl_->release(scheduled.returnedThreadReference);
    return 1;
}

int LuauRuntimeBridge::taskDelay(lua_State* state)
{
    // Roblox accepts an omitted delay as zero, then diagnoses the required
    // callback at argument #2. Luraph and other protected loaders fingerprint
    // this exact C-closure contract.
    const double seconds = luaL_optnumber(state, 1, 0.0);
    if (!std::isfinite(seconds) || seconds < 0.0)
    {
        luaL_error(state, "invalid argument #1 to 'delay' (non-negative finite number expected)");
        return 0;
    }
    if (!lua_isfunction(state, 2) && !lua_isthread(state, 2))
    {
        luaL_error(state, "invalid argument #2 to 'delay' (function or thread expected)");
        return 0;
    }
    LuauRuntimeBridge* bridge = from(state);
    Impl::ScheduledTask scheduled = bridge->impl_->schedule(state, 2, 3, lua_gettop(state) - 2, QueueKind::Timer, seconds);
    lua_getref(bridge->context().mainState(), scheduled.returnedThreadReference);
    lua_xmove(bridge->context().mainState(), state, 1);
    bridge->impl_->release(scheduled.returnedThreadReference);
    return 1;
}

int LuauRuntimeBridge::taskWait(lua_State* state)
{
    double seconds = lua_gettop(state) >= 1 ? luaL_checknumber(state, 1) : 0.0;
    return from(state)->yieldWait(state, seconds);
}

int LuauRuntimeBridge::yieldWait(lua_State* state, double seconds)
{
    if (!std::isfinite(seconds) || seconds < 0.0)
    {
        luaL_error(state, "invalid argument #1 to 'wait' (non-negative finite number expected)");
        return 0;
    }
    Scheduler& scheduler = impl_->context.scheduler();
    const std::optional<TaskId> current = scheduler.currentTask();
    if (!current)
    {
        // Transitional compatibility for the legacy Lua scheduler: its resume
        // loop recognizes this token. Native runMain never takes this branch.
        lua_newtable(state);
        lua_pushliteral(state, "wait");
        lua_setfield(state, -2, "kind");
        lua_pushnumber(state, seconds);
        lua_setfield(state, -2, "duration");
        return lua_yield(state, 1);
    }
    ThreadContext* threadContext = RuntimeContext::threadFrom(state);
    const std::optional<TaskSnapshot> running = scheduler.task(*current);
    if (!threadContext || !running)
    {
        luaL_error(state, "task.wait coroutine has no runtime context");
        return 0;
    }
    if (running->execution.threadContextId != threadContext->id)
    {
        std::shared_ptr<LuauRuntimeBridge> owner = shared_from_this();
        std::shared_ptr<Impl::LuaCall> call = impl_->adoptCall(state, owner);
        TaskCallback callback = [call](const ResumeData& data) {
            return call->resume(data);
        };
        ResumeData resumeData;
        resumeData.returnWaitedSeconds = true;
        const TaskId adopted = scheduler.delay(
            seconds, std::move(callback), "manual task.wait", std::move(resumeData), context().taskMetadata(state));
        call->bindTask(owner, adopted);
        return lua_yield(state, 0);
    }
    impl_->yieldRequests[state] = LuaYieldRequest{LuaYieldKind::Wait, seconds, {}};
    return lua_yield(state, 0);
}

int LuauRuntimeBridge::taskCancel(lua_State* state)
{
    lua_State* target = lua_tothread(state, 1);
    if (!target)
    {
        luaL_typeerror(state, 1, "thread");
        return 0;
    }
    LuauRuntimeBridge* bridge = from(state);
    auto found = bridge->impl_->threadTasks.find(target);
    if (found != bridge->impl_->threadTasks.end())
        bridge->impl_->context.scheduler().cancel(found->second, "task.cancel");
    return 0;
}

int LuauRuntimeBridge::coroutineClose(lua_State* state)
{
    LuauRuntimeBridge* bridge = from(state);
    if (!bridge || !bridge->impl_->coroutineCloseFunction)
    {
        luaL_error(state, "Luau runtime bridge is not installed");
        return 0;
    }

    // Capture the pointer only for host bookkeeping. The retained scheduler
    // reference keeps a mapped thread alive until cancellation releases it.
    // Invalid arguments and non-closeable running/normal threads are handled
    // entirely by the stock function below and therefore never mutate queues.
    lua_State* target = lua_tothread(state, 1);

    // Invoke Luau's pinned native implementation directly. Going through
    // lua_call would add a second Lua-visible C frame; protected error handlers
    // can observe that difference and, in particular, nested xpcall handlers
    // may report "error in error handling" instead of close's stock error.
    const int resultCount = bridge->impl_->coroutineCloseFunction(state);

    // Reaching here means stock coroutine.close reset the target, including
    // its legal false,error result for an errored coroutine. Canceling invokes
    // LuaCall's observer, which immediately removes timers/waiters and releases
    // bridge references without changing the already-produced Lua results.
    if (target)
    {
        auto found = bridge->impl_->threadTasks.find(target);
        if (found != bridge->impl_->threadTasks.end())
            bridge->context().scheduler().cancel(found->second, "coroutine.close");
    }
    return resultCount;
}

int LuauRuntimeBridge::taskSynchronize(lua_State* state)
{
    if (ThreadContext* contextValue = RuntimeContext::threadFrom(state))
    {
        contextValue->actorLane = ActorLane::Synchronized;
        LuauRuntimeBridge* bridge = from(state);
        if (const std::optional<TaskId> task = bridge->context().scheduler().currentTask())
            bridge->context().scheduler().setTaskMetadata(*task, bridge->context().taskMetadata(state));
    }
    return taskWait(state);
}

int LuauRuntimeBridge::taskDesynchronize(lua_State* state)
{
    if (ThreadContext* contextValue = RuntimeContext::threadFrom(state))
    {
        contextValue->actorLane = ActorLane::Desynchronized;
        LuauRuntimeBridge* bridge = from(state);
        if (const std::optional<TaskId> task = bridge->context().scheduler().currentTask())
            bridge->context().scheduler().setTaskMetadata(*task, bridge->context().taskMetadata(state));
    }
    return taskWait(state);
}

} // namespace rbx::runtime
