#pragma once

#include "runtime_context.hpp"

#include "lua.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rbx::runtime
{

struct LuauRuntimeBridgeOptions
{
    int signalUserdataTag = 40;
    int connectionUserdataTag = 41;
    bool installTaskLibrary = true;
    // Invoked on the scheduler owner thread after a successful HTTP response.
    // Diagnostic hosts can capture response bytes without worker-thread Lua or
    // process-global mutations. Faithful mode never invokes this observer.
    std::function<void(const NetworkRequest&, const NetworkResponse&)> httpResponseObserver;
};

enum class LuauMainState
{
    Completed,
    SteadyState,
    Blocked,
    Failed,
};

struct LuauMainRunOptions
{
    std::size_t maxResumes = 100000;
    double maxVirtualSeconds = 30.0;
    // Independent host-wall budget used only while waiting for realtime timers
    // or external completions. Zero disables this bridge-level wall deadline;
    // the VM interrupt/watchdog may still enforce a process policy.
    double maxWallSeconds = 30.0;
    bool advanceVirtualTimers = true;
};

struct LuauMainResult
{
    LuauMainState state = LuauMainState::Failed;
    TaskId task = 0;
    std::vector<int> registryReferences;
    std::string error;
    std::size_t resumes = 0;
    double elapsedVirtualSeconds = 0.0;
    bool mainCompleted = false;
};

// Concrete Luau bridge for the native Scheduler and NativeSignal primitives.
// It recognizes yields initiated by task.wait and RBXScriptSignal:Wait;
// unrecognized coroutine.yield calls become caller-controlled suspended tasks.
class LuauRuntimeBridge : public std::enable_shared_from_this<LuauRuntimeBridge>
{
public:
    static constexpr std::string_view kSubsystemKey = "runtime.luau-bridge";

    static std::shared_ptr<LuauRuntimeBridge> create(RuntimeContext& context, LuauRuntimeBridgeOptions options = {});
    ~LuauRuntimeBridge();

    LuauRuntimeBridge(const LuauRuntimeBridge&) = delete;
    LuauRuntimeBridge& operator=(const LuauRuntimeBridge&) = delete;

    void install();
    void shutdown();
    bool installed() const;

    void pushSignal(lua_State* state, std::shared_ptr<NativeSignal> signal);
    bool isSignal(lua_State* state, int index) const;
    std::shared_ptr<NativeSignal> signal(lua_State* state, int index) const;

    // Copies values at [firstArgument, firstArgument + argumentCount) into VM
    // registry references and fires without exposing a script-visible Fire API.
    std::size_t fire(lua_State* state, const std::shared_ptr<NativeSignal>& signal, int firstArgument, int argumentCount);
    std::size_t fire(const std::shared_ptr<NativeSignal>& signal, RuntimeValues arguments = {});

    bool resumeCallerControlled(TaskId task, RuntimeValues arguments = {});
    std::optional<TaskId> taskForThread(lua_State* thread) const;

    // Records a native task.wait-style suspension for the current coroutine.
    // Engine C APIs use this to yield without inserting a script-visible Lua
    // forwarding frame into debug.info or tracebacks.
    int yieldWait(lua_State* state, double seconds);

    // Schedules a loaded closure (at closureIndex) as the native main task and
    // drives ready work plus virtual timers until a terminal/steady/block state.
    // Return values remain exact Lua registry references, including nil holes,
    // functions, userdata, and tables.
    LuauMainResult runMain(
        lua_State* state, int closureIndex, int firstArgument = 0, int argumentCount = 0, LuauMainRunOptions options = {});
    int pushMainResults(lua_State* destination, const LuauMainResult& result) const;
    void releaseMainResults(LuauMainResult& result);

    RuntimeContext& context();
    const LuauRuntimeBridgeOptions& options() const;

private:
    struct Impl;
    struct SignalUserdata;
    struct ConnectionUserdata;

    LuauRuntimeBridge(RuntimeContext& context, LuauRuntimeBridgeOptions options);

    static LuauRuntimeBridge* from(lua_State* state);
    static SignalUserdata* checkSignal(lua_State* state, int index);
    static ConnectionUserdata* checkConnection(lua_State* state, int index);

    static int signalIndex(lua_State* state);
    static int signalNewIndex(lua_State* state);
    static int signalToString(lua_State* state);
    static int signalEqual(lua_State* state);
    static int signalConnect(lua_State* state);
    static int signalOnce(lua_State* state);
    static int signalWait(lua_State* state);
    static int signalDestroy(lua_State* state);

    static int connectionIndex(lua_State* state);
    static int connectionNewIndex(lua_State* state);
    static int connectionToString(lua_State* state);
    static int connectionDisconnect(lua_State* state);
    static int connectionDestroy(lua_State* state);

    static int nativeSignalNew(lua_State* state);
    static int nativeSignalFire(lua_State* state);
    static int nativeSignalDisconnectAll(lua_State* state);
    static int nativeRunServiceConfigure(lua_State* state);
    static int nativeRunServiceSetBindingCount(lua_State* state);
    static int nativeModuleDeclare(lua_State* state);
    static int nativeModuleRequire(lua_State* state);
    static int nativeModuleContinue(lua_State* state, int status);
    static int nativeModuleFinish(lua_State* state);
    static int nativeHttpRequest(lua_State* state);
    static int nativeHttpContinue(lua_State* state, int status);

    static int taskSpawn(lua_State* state);
    static int taskDefer(lua_State* state);
    static int taskDelay(lua_State* state);
    static int taskWait(lua_State* state);
    static int taskCancel(lua_State* state);
    static int taskSynchronize(lua_State* state);
    static int taskDesynchronize(lua_State* state);
    static int coroutineClose(lua_State* state);

    std::unique_ptr<Impl> impl_;
};

} // namespace rbx::runtime
