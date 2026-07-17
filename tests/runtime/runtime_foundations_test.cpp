#include "runtime/clock.hpp"
#include "runtime/executor_compat.hpp"
#include "runtime/luau_runtime_bridge.hpp"
#include "runtime/memory_filesystem.hpp"
#include "runtime/module_registry.hpp"
#include "runtime/network_broker.hpp"
#include "runtime/runtime_context.hpp"
#include "runtime/scheduler.hpp"
#include "runtime/security.hpp"
#include "runtime/signal.hpp"

#include "Luau/Compiler.h"
#include "lua.h"
#include "lualib.h"

#include <atomic>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace rbx::runtime;

namespace
{

#define CHECK(condition)                                                                                                                   \
    do                                                                                                                                     \
    {                                                                                                                                      \
        if (!(condition))                                                                                                                  \
            throw std::runtime_error(std::string("CHECK failed: ") + #condition + " at line " + std::to_string(__LINE__));             \
    } while (false)

TaskCallback completes()
{
    return [](const ResumeData&) { return TaskStep::complete(); };
}

void schedulerTests()
{
    auto clock = std::make_shared<VirtualClock>(1000);
    Scheduler scheduler(clock);
    std::vector<std::string> order;

    scheduler.defer([&](const ResumeData&) {
        order.push_back("defer");
        return TaskStep::complete();
    });
    scheduler.spawn([&](const ResumeData&) {
        order.push_back("spawn");
        return TaskStep::complete();
    });
    CHECK(scheduler.step());
    CHECK(order == std::vector<std::string>{"spawn"});
    CHECK(scheduler.step());
    CHECK(order == (std::vector<std::string>{"spawn", "defer"}));

    int immediate = 0;
    TaskId immediateTask = scheduler.spawnImmediate([&](const ResumeData&) {
        ++immediate;
        return TaskStep::complete();
    });
    CHECK(immediate == 1);
    CHECK(scheduler.task(immediateTask)->status == TaskStatus::Completed);

    int waitStep = 0;
    double waited = 0.0;
    TaskId timer = scheduler.spawnImmediate([&](const ResumeData& data) {
        if (waitStep++ == 0)
            return TaskStep::wait(0.1);
        waited = data.waitedSeconds;
        return TaskStep::complete();
    });
    CHECK(scheduler.task(timer)->status == TaskStatus::WaitingTimer);
    CHECK(scheduler.timerCount() == 1);
    CHECK(scheduler.advanceToNextTimer());
    scheduler.runUntilIdle();
    CHECK(waited >= 0.1);

    TaskId cancelledTimer = scheduler.delay(10.0, completes());
    CHECK(scheduler.timerCount() == 1);
    CHECK(scheduler.cancel(cancelledTimer));
    CHECK(scheduler.timerCount() == 0);

    TaskId arbitrary = scheduler.spawnImmediate([](const ResumeData&) { return TaskStep::arbitraryYield(); });
    CHECK(scheduler.task(arbitrary)->status == TaskStatus::Suspended);
    scheduler.runUntilIdle();
    CHECK(scheduler.task(arbitrary)->resumeCount == 1);
    CHECK(scheduler.resumeManual(arbitrary));
    scheduler.runUntilIdle();
    CHECK(scheduler.task(arbitrary)->resumeCount == 2);

    std::vector<std::string> phases;
    for (RunPhase phase : {RunPhase::Heartbeat, RunPhase::PreSimulation, RunPhase::PreRender, RunPhase::PreAnimation, RunPhase::RenderStepped,
             RunPhase::Stepped, RunPhase::PostSimulation})
    {
        scheduler.schedulePhase(phase, [&, phase](const ResumeData&) {
            phases.emplace_back(toString(phase));
            return TaskStep::complete();
        });
    }
    scheduler.runUntilIdle();
    CHECK(phases == (std::vector<std::string>{
                        "PreRender", "RenderStepped", "PreAnimation", "PreSimulation", "Stepped", "PostSimulation", "Heartbeat"}));

    SecurityPolicy security;
    TaskExecutionMetadata metadata;
    metadata.threadContextId = 44;
    metadata.security = security.descriptor(SecurityIdentity::LocalScript);
    TaskId parent = scheduler.spawnImmediate(
        [&](const ResumeData&) {
            scheduler.spawn(completes(), "child");
            return TaskStep::complete();
        },
        "parent", {}, metadata);
    CHECK(scheduler.task(parent)->execution.threadContextId == 44);
    auto all = scheduler.tasks();
    auto child = std::find_if(all.begin(), all.end(), [](const TaskSnapshot& snapshot) { return snapshot.name == "child"; });
    CHECK(child != all.end());
    CHECK(child->execution.security.identity == SecurityIdentity::LocalScript);

    int recursiveCalls = 0;
    std::function<TaskStep(const ResumeData&)> recursive;
    recursive = [&](const ResumeData&) {
        if (++recursiveCalls < 256)
            scheduler.spawnImmediate(recursive, "recursive");
        return TaskStep::complete();
    };
    scheduler.spawnImmediate(recursive, "recursive-root");
    scheduler.runUntilIdle(512);
    CHECK(recursiveCalls == 256);
}

void signalTests()
{
    auto clock = std::make_shared<VirtualClock>();
    Scheduler scheduler(clock);
    auto signal = std::make_shared<NativeSignal>(scheduler, "Changed");
    int calls = 0;
    SignalConnection connection = signal->connect([&](const SignalArguments&) {
        return [&](const ResumeData&) {
            ++calls;
            return TaskStep::complete();
        };
    });
    signal->fire({RuntimeValue(3)});
    CHECK(calls == 1); // Immediate signals begin callbacks before Fire returns.
    CHECK(connection.connected());
    connection.disconnect();
    signal->fire();
    CHECK(calls == 1);

    int onceCalls = 0;
    SignalConnection once = signal->once([&](const SignalArguments&) {
        return [&](const ResumeData&) {
            ++onceCalls;
            return TaskStep::complete();
        };
    });
    signal->fire();
    signal->fire();
    CHECK(onceCalls == 1);
    CHECK(!once.connected());

    TaskId waiter = 0;
    waiter = scheduler.spawnImmediate([&](const ResumeData& data) {
        if (data.source == QueueKind::Signal)
            return TaskStep::complete();
        CHECK(signal->wait(waiter == 0 ? scheduler.currentTask().value() : waiter));
        return TaskStep::waitSignal("Changed");
    });
    CHECK(signal->snapshot().waiterCount == 1);
    CHECK(scheduler.cancel(waiter));
    CHECK(signal->snapshot().waiterCount == 0);
    signal->fire();
    CHECK(scheduler.task(waiter)->status == TaskStatus::Cancelled);

    TaskId stranded = scheduler.spawnImmediate([&](const ResumeData&) {
        CHECK(signal->wait(scheduler.currentTask().value()));
        return TaskStep::waitSignal("Changed");
    });
    signal.reset();
    CHECK(scheduler.task(stranded)->status == TaskStatus::Cancelled);

    NativeSignal stackSignal(scheduler, "Bad");
    bool rejected = false;
    try
    {
        stackSignal.connect([](const SignalArguments&) { return completes(); });
    }
    catch (const std::logic_error&)
    {
        rejected = true;
    }
    CHECK(rejected);
}

void moduleTests()
{
    auto clock = std::make_shared<VirtualClock>();
    Scheduler scheduler(clock);
    ModuleRegistry modules(scheduler);
    for (ModuleId id = 1; id <= 11; ++id)
        CHECK(modules.declare(id, "M" + std::to_string(id)));

    TaskId loader = scheduler.spawn(completes(), "loader");
    CHECK(modules.require(1, std::nullopt, loader).action == RequireAction::StartLoading);
    CHECK(modules.finishSuccess(1, loader, RuntimeValue(false)));
    RequireDecision cachedFalse = modules.require(1, std::nullopt, loader);
    CHECK(cachedFalse.action == RequireAction::ReturnCached);
    CHECK(cachedFalse.cachedValue && cachedFalse.cachedValue->getIf<bool>() && !*cachedFalse.cachedValue->getIf<bool>());

    TaskId nilLoader = scheduler.spawn(completes());
    CHECK(modules.require(2, std::nullopt, nilLoader).action == RequireAction::StartLoading);
    CHECK(modules.finishSuccess(2, nilLoader, RuntimeValue::nil(), 1));
    CHECK(modules.state(2) == ModuleState::Loaded);
    RequireDecision cachedNil = modules.require(2, std::nullopt, nilLoader);
    CHECK(cachedNil.action == RequireAction::ReturnCached);
    CHECK(cachedNil.cachedValue && cachedNil.cachedValue->isNil());

    TaskId noReturnLoader = scheduler.spawn(completes());
    CHECK(modules.require(11, std::nullopt, noReturnLoader).action == RequireAction::StartLoading);
    CHECK(modules.finishSuccess(11, noReturnLoader, RuntimeValue::nil(), 0));
    CHECK(modules.state(11) == ModuleState::Failed);

    TaskId twoReturnLoader = scheduler.spawn(completes());
    CHECK(modules.require(3, std::nullopt, twoReturnLoader).action == RequireAction::StartLoading);
    CHECK(modules.finishSuccess(3, twoReturnLoader, RuntimeValue(1), 2));
    CHECK(modules.state(3) == ModuleState::Failed);

    TaskId a = scheduler.spawn(completes());
    TaskId b = scheduler.spawn(completes());
    CHECK(modules.require(4, std::nullopt, a).action == RequireAction::StartLoading);
    CHECK(modules.require(5, 4, b).action == RequireAction::StartLoading);
    CHECK(modules.require(4, 5, b).action == RequireAction::CycleError);

    TaskId d = scheduler.spawn(completes());
    TaskId c = scheduler.spawn(completes());
    CHECK(modules.require(6, std::nullopt, d).action == RequireAction::StartLoading);
    CHECK(modules.require(7, 6, c).action == RequireAction::StartLoading);
    CHECK(modules.require(8, 6, c).action == RequireAction::StartLoading);
    CHECK(modules.require(9, 7, d).action == RequireAction::StartLoading);
    CHECK(modules.require(9, 8, c).action == RequireAction::Wait); // diamond, not a cycle

    TaskId concurrentLoader = scheduler.spawn(completes());
    TaskId concurrentWaiter = scheduler.spawn([](const ResumeData& data) {
        return data.source == QueueKind::Module ? TaskStep::complete() : TaskStep::waitModule("M10");
    });
    CHECK(modules.require(10, std::nullopt, concurrentLoader).action == RequireAction::StartLoading);
    CHECK(modules.require(10, std::nullopt, concurrentWaiter).action == RequireAction::Wait);
    CHECK(modules.finishFailure(10, concurrentLoader, "fixture failure"));
    scheduler.runUntilIdle();
    CHECK(modules.require(10, std::nullopt, concurrentWaiter).action == RequireAction::RaiseCachedError);

    ModuleRegistry cancellationModules(scheduler);
    cancellationModules.declare(20, "Cancelled");
    TaskId cancelledLoader = scheduler.spawn(completes());
    CHECK(cancellationModules.require(20, std::nullopt, cancelledLoader).action == RequireAction::StartLoading);
    scheduler.cancel(cancelledLoader);
    CHECK(cancellationModules.state(20) == ModuleState::Failed);

    TaskId survivesRegistry = scheduler.spawn(completes());
    {
        ModuleRegistry temporary(scheduler);
        temporary.declare(30, "Temporary");
        CHECK(temporary.require(30, std::nullopt, survivesRegistry).action == RequireAction::StartLoading);
    }
    CHECK(scheduler.cancel(survivesRegistry)); // no raw-this observer remains
}

void filesystemAndExecutorTests()
{
    MemoryFilesystem filesystem({8, 8, 8, 64});
    CHECK(filesystem.writeFile("a/b.txt", "1234"));
    CHECK(filesystem.readFile("a/b.txt").contents == "1234");
    CHECK(!filesystem.writeFile("created/then/fails.txt", "123456789"));
    CHECK(!filesystem.exists("created"));
    CHECK(!filesystem.writeFile("q/r.txt", "12345678"));
    CHECK(!filesystem.exists("q"));
    CHECK(!MemoryFilesystem::normalize("../host-secret"));
    CHECK(!MemoryFilesystem::normalize("/etc/passwd"));
    CHECK(!MemoryFilesystem::normalize("C:\\Windows"));

    ExecutorCompatibility generic({
        RuntimeProfile::ExecutorClient,
        ExecutionMode::Faithful,
        ExecutorPreset::Generic,
        FilesystemPolicy::ProfileDefault,
        {},
    });
    CHECK(generic.surface().filesystem != nullptr);
    CHECK(generic.surface().requestHeaders.empty());
    CHECK(generic.classifyClosure({true, false, true}) == ClosureKind::Luau);
    CHECK(generic.classifyClosure({true, true, true}) == ClosureKind::Unknown);

    ExecutorCompatibility opium({
        RuntimeProfile::ExecutorClient,
        ExecutionMode::Faithful,
        ExecutorPreset::Opiumware,
        FilesystemPolicy::Memory,
        {},
        729,
    });
    CHECK(opium.surface().requestHeaders.contains("X-Executor"));
    CHECK(opium.surface().requestHeaders.at("Opiumware-Fingerprint").size() == 96);
    CHECK(opium.surface().requestHeaders.at("Opiumware-Fingerprint") == opium.surface().requestHeaders.at("Opiumware-User-Identifier"));
    ExecutorCompatibility sameOpium({
        RuntimeProfile::ExecutorClient,
        ExecutionMode::Faithful,
        ExecutorPreset::Opiumware,
        FilesystemPolicy::Memory,
        {},
        729,
    });
    CHECK(opium.surface().requestHeaders == sameOpium.surface().requestHeaders);

    SecurityPolicy policy;
    SecurityDescriptor local = policy.descriptor(SecurityIdentity::LocalScript);
    SecurityDescriptor attemptedUpgrade = policy.inherit(local, SecurityIdentity::RobloxScript);
    CHECK(attemptedUpgrade.identity == SecurityIdentity::LocalScript);
    CHECK(!attemptedUpgrade.capabilities.contains(Capability::RobloxScript));
}

void networkTests()
{
    auto get = [](std::string url) {
        NetworkRequest request;
        request.url = std::move(url);
        return request;
    };
    NetworkPolicyConfig policy;
    policy.mode = NetworkMode::Live;
    NetworkGuard guard(policy);
    CHECK(guard.authorizeRequest(get("https://example.com/path")));
    CHECK(!guard.authorizeRequest(get("http://127.0.0.1/")));
    CHECK(!guard.authorizeRequest(get("http://2130706433/")));
    CHECK(!guard.authorizeRequest(get("http://[0:0:0:0:0:0:0:1]/")));
    CHECK(!guard.authorizeHop("https://example.com", {"10.0.0.1"}));
    CHECK(!guard.authorizeHop("https://example.com", {"0:0:0:0:0:0:0:1"}));
    CHECK(!guard.authorizeHop("https://example.com", {"::ffff:127.0.0.1"}));
    CHECK(!guard.authorizeHop("https://example.com", {"::127.0.0.1"}));
    CHECK(!guard.authorizeHop("https://example.com", {"64:ff9b::169.254.169.254"}));
    CHECK(!guard.authorizeHop("https://example.com", {"64:ff9b::a9fe:a9fe"}));
    CHECK(!guard.authorizeHop("https://example.com", {"fc00::1"}));
    CHECK(!guard.authorizeHop("https://example.com", {"fe80::1"}));
    CHECK(!guard.authorizeHop("https://example.com", {"2001:db8::1"}));
    CHECK(!NetworkGuard::isPublicAddress("1:2:3:4:5:6:7:8:"));
    CHECK(guard.authorizeHop("https://example.com", {"93.184.216.34"}));
    CHECK(guard.authorizeHop("https://example.com", {"2606:4700:4700::1111"}));

    NetworkPolicyConfig allowlist;
    allowlist.mode = NetworkMode::Allowlist;
    allowlist.allowedHosts = {"api.example.com", "*.fixtures.test"};
    NetworkGuard restricted(allowlist);
    CHECK(restricted.authorizeRequest(get("https://api.example.com/v1")));
    CHECK(restricted.authorizeRequest(get("https://a.fixtures.test/v1")));
    NetworkResult blocked = restricted.authorizeRequest(get("https://example.net"));
    CHECK(blocked.error == NetworkError::HostNotAllowed);
    CHECK(blocked.requiredHost == "example.net");
}

std::string compile(const std::string& source)
{
    Luau::CompileOptions options;
    return Luau::compile(source, options);
}

void contextAndBridgeTests()
{
    lua_State* first = luaL_newstate();
    lua_State* second = luaL_newstate();
    CHECK(first && second);
    luaL_openlibs(first);
    luaL_openlibs(second);

    RuntimeContextOptions options;
    options.profile = RuntimeProfile::ExecutorClient;
    options.executionMode = ExecutionMode::Diagnostic;
    options.filesystem = FilesystemPolicy::Memory;
    RuntimeContext firstContext(first, options);
    RuntimeContext secondContext(second, options);
    firstContext.attach();
    secondContext.attach();
    CHECK(RuntimeContext::from(first) == &firstContext);
    CHECK(RuntimeContext::from(second) == &secondContext);
    CHECK(RuntimeContext::from(first) != RuntimeContext::from(second));
    firstContext.emplaceSubsystem<int>("engine-state", 17);
    secondContext.emplaceSubsystem<int>("engine-state", 29);
    CHECK(*firstContext.subsystem<int>("engine-state") == 17);
    CHECK(*secondContext.subsystem<int>("engine-state") == 29);

    NetworkPolicyConfig networkPolicy;
    networkPolicy.mode = NetworkMode::Allowlist;
    networkPolicy.allowedHosts = {"fixture.test"};
    auto fixtureTransport = std::make_shared<FixtureHttpTransport>();
    NetworkResult fixtureResponse;
    fixtureResponse.response.statusCode = 200;
    fixtureResponse.response.statusMessage = "OK";
    fixtureResponse.response.body = "fixture-body";
    fixtureResponse.response.headers.emplace("content-type", "text/plain");
    fixtureResponse.response.hops.push_back(NetworkHop{"https://fixture.test/value", {"93.184.216.34"}});
    fixtureTransport->add("https://fixture.test/value", NetworkFixture{fixtureResponse});
    firstContext.installNetwork(networkPolicy, fixtureTransport);

    lua_newthread(first);
    lua_State* coroutine = lua_tothread(first, -1);
    CHECK(RuntimeContext::threadFrom(coroutine));
    CHECK(RuntimeContext::threadFrom(coroutine)->security.identity == SecurityIdentity::ExecutorSandbox);
    lua_pop(first, 1);

    const std::thread::id ownerThread = std::this_thread::get_id();
    std::size_t observedHttpResponses = 0;
    bool observedHttpOnOwner = true;
    bool observedCookie = false;
    LuauRuntimeBridgeOptions bridgeOptions;
    bridgeOptions.httpResponseObserver = [&](const NetworkRequest& request, const NetworkResponse& response) {
        ++observedHttpResponses;
        observedHttpOnOwner = observedHttpOnOwner && std::this_thread::get_id() == ownerThread;
        auto cookie = request.headers.find("Cookie");
        observedCookie = cookie != request.headers.end() && cookie->second == "session=abc";
        CHECK(response.body == "fixture-body");
    };
    auto bridge = LuauRuntimeBridge::create(firstContext, bridgeOptions);
    auto changed = firstContext.createSignal("Changed");
    bridge->pushSignal(first, changed);
    lua_setglobal(first, "Changed");

    const std::string source = R"(
        observed = "none"
        local httpResponse = __rbx_native_http_request({
            Url = "https://fixture.test/value",
            Method = "GET",
            Headers = { ["X-Test"] = "yes" },
            Cookies = { session = "abc" },
            Timeout = 2,
            RedirectLimit = 2,
        })
        nativeHttpOk = httpResponse.Success and httpResponse.StatusCode == 200
            and httpResponse.StatusMessage == "OK" and httpResponse.Body == "fixture-body"
            and httpResponse.Headers["content-type"] == "text/plain" and type(httpResponse.Cookies) == "table"
        local blockedOk, blockedError = pcall(function()
            __rbx_native_http_request({ Url = "https://blocked.test/value" })
        end)
        nativeHttpBlocked = not blockedOk and string.find(tostring(blockedError), "required%-host=blocked.test") ~= nil
        local cancelledHttp = task.spawn(function()
            __rbx_native_http_request({ Url = "https://fixture.test/value" })
            cancelledHttpResumed = true
        end)
        task.cancel(cancelledHttp)

        local sharedModule = __rbx_native_module_declare("Shared", "task.wait(); return false")
        nativeModuleId = sharedModule
        local moduleValues = {}
        local moduleCompleted = 0
        task.spawn(function()
            local shouldLoad = __rbx_native_module_require(sharedModule)
            assert(shouldLoad == true)
            task.wait(0.01)
            assert(__rbx_native_module_finish(sharedModule, true, 1, false))
            moduleValues[1] = false
            moduleCompleted += 1
        end)
        task.spawn(function()
            local shouldLoad, value = __rbx_native_module_require(sharedModule)
            assert(shouldLoad == false and value == false)
            moduleValues[2] = value
            moduleCompleted += 1
        end)
        while moduleCompleted < 2 do task.wait() end
        local cachedLoad, cachedValue = __rbx_native_module_require(sharedModule)
        nativeModuleConcurrent = cachedLoad == false and cachedValue == false

        local nilModule = __rbx_native_module_declare("Nil", "return nil")
        assert(__rbx_native_module_require(nilModule) == true)
        assert(__rbx_native_module_finish(nilModule, true, 1, nil))
        local nilLoad, nilValue = __rbx_native_module_require(nilModule)
        nativeModuleNil = nilLoad == false and nilValue == nil

        local multipleModule = __rbx_native_module_declare("Multiple", "return 1, 2")
        assert(__rbx_native_module_require(multipleModule) == true)
        local multipleFinished, multipleError = __rbx_native_module_finish(multipleModule, true, 2, 1)
        local multipleCached, cachedError = pcall(__rbx_native_module_require, multipleModule)
        nativeModuleMultiple = not multipleFinished and string.find(tostring(multipleError), "exactly one value", 1, true)
            and not multipleCached and string.find(tostring(cachedError), "exactly one value", 1, true)

        local native = __rbx_native_signal_new("PrivilegedSignal")
        nativeSignal = native
        nativeOrder = {}
        local nativeConnection = native:Connect(function(value)
            table.insert(nativeOrder, "connect:" .. value)
        end)
        native:Once(function(value)
            table.insert(nativeOrder, "once:" .. value)
        end)
        local cancelledNativeWait = task.spawn(function()
            native:Wait()
            cancelledNativeWaitResumed = true
        end)
        task.cancel(cancelledNativeWait)
        task.spawn(function()
            nativeWaitValue = native:Wait()
        end)
        assert(native.Fire == nil and not pcall(function() native.Fire = function() end end))
        assert(not pcall(function() nativeConnection.Connected = false end))
        __rbx_native_signal_fire(native, "first")
        __rbx_native_signal_fire(native, "second")
        assert(table.concat(nativeOrder, ",") == "connect:first,once:first,connect:second")
        __rbx_native_signal_disconnect_all(native)
        nativeDisconnected = not nativeConnection.Connected

        local teardown = __rbx_native_signal_new("TeardownSignal")
        task.spawn(function()
            teardown:Wait()
            teardownWaitResumed = true
        end)
        __rbx_native_signal_disconnect_all(teardown)

        local deferred = __rbx_native_signal_new("DeferredSignal", true)
        deferredOrder = {}
        deferred:Connect(function() table.insert(deferredOrder, "callback") end)
        __rbx_native_signal_fire(deferred)
        table.insert(deferredOrder, "after-fire")

        local connection = Changed:Connect(function(value)
            observed = value
        end)
        local waited = task.spawn(function()
            waitedValue = Changed:Wait()
        end)
        local timed = task.spawn(function()
            local elapsed = task.wait(0.05)
            timerElapsed = elapsed
        end)
        cancelledDelay = false
        local cancelled = task.delay(1, function() cancelledDelay = true end)
        task.cancel(cancelled)
        task.spawn(function()
            local manual = coroutine.create(function()
                task.wait(0.02)
                manualWaitDone = true
            end)
            assert(coroutine.resume(manual))
        end)
        task.spawn(function()
            local manual = coroutine.create(function()
                manualSignalValue = Changed:Wait()
            end)
            assert(coroutine.resume(manual))
        end)
        return connection.Connected, type(waited), type(timed), false, nil, 7
    )";
    std::string bytecode = compile(source);
    CHECK(luau_load(first, "=foundation-test", bytecode.data(), bytecode.size(), 0) == LUA_OK);
    LuauMainResult mainResult = bridge->runMain(first, -1);
    if (mainResult.state != LuauMainState::SteadyState)
    {
        std::cerr << "main state=" << static_cast<int>(mainResult.state) << " completed=" << mainResult.mainCompleted << " error=" << mainResult.error
                  << " resumes=" << mainResult.resumes << " elapsed=" << mainResult.elapsedVirtualSeconds << '\n';
        for (const TaskSnapshot& snapshot : firstContext.scheduler().tasks())
            std::cerr << "task " << snapshot.id << " " << snapshot.name << " " << toString(snapshot.status) << " " << snapshot.error << '\n';
    }
    CHECK(mainResult.state == LuauMainState::SteadyState);
    CHECK(mainResult.mainCompleted);
    CHECK(mainResult.registryReferences.size() == 6);
    lua_pop(first, 1); // loaded closure
    CHECK(bridge->pushMainResults(first, mainResult) == 6);
    CHECK(lua_toboolean(first, -6));
    CHECK(std::string(lua_tostring(first, -5)) == "thread");
    CHECK(std::string(lua_tostring(first, -4)) == "thread");
    CHECK(!lua_toboolean(first, -3));
    CHECK(lua_isnil(first, -2));
    CHECK(lua_tointeger(first, -1) == 7);
    lua_pop(first, 6);
    lua_getglobal(first, "nativeHttpOk");
    CHECK(lua_toboolean(first, -1));
    lua_pop(first, 1);
    CHECK(observedHttpResponses == 1);
    CHECK(observedHttpOnOwner);
    CHECK(observedCookie);
    lua_getglobal(first, "nativeHttpBlocked");
    CHECK(lua_toboolean(first, -1));
    lua_pop(first, 1);
    lua_getglobal(first, "cancelledHttpResumed");
    CHECK(lua_isnil(first, -1));
    lua_pop(first, 1);
    lua_getglobal(first, "nativeModuleConcurrent");
    CHECK(lua_toboolean(first, -1));
    lua_pop(first, 1);
    lua_getglobal(first, "nativeModuleNil");
    CHECK(lua_toboolean(first, -1));
    lua_pop(first, 1);
    lua_getglobal(first, "nativeModuleMultiple");
    CHECK(lua_toboolean(first, -1));
    lua_pop(first, 1);
    CHECK(firstContext.modules().snapshots().size() == 3);
    CHECK(firstContext.modules().state(1) == ModuleState::Loaded);
    CHECK(firstContext.modules().state(2) == ModuleState::Loaded);
    CHECK(firstContext.modules().state(3) == ModuleState::Failed);
    lua_getglobal(first, "nativeWaitValue");
    CHECK(std::string(lua_tostring(first, -1)) == "first");
    lua_pop(first, 1);
    lua_getglobal(first, "cancelledNativeWaitResumed");
    CHECK(lua_isnil(first, -1));
    lua_pop(first, 1);
    lua_getglobal(first, "teardownWaitResumed");
    CHECK(lua_isnil(first, -1));
    lua_pop(first, 1);
    lua_getglobal(first, "nativeDisconnected");
    CHECK(lua_toboolean(first, -1));
    lua_pop(first, 1);
    lua_getglobal(first, "deferredOrder");
    lua_rawgeti(first, -1, 1);
    CHECK(std::string(lua_tostring(first, -1)) == "after-fire");
    lua_pop(first, 1);
    lua_rawgeti(first, -1, 2);
    CHECK(std::string(lua_tostring(first, -1)) == "callback");
    lua_pop(first, 2);

    lua_pushnil(first);
    lua_setglobal(first, "__rbx_native_signal_new");
    lua_pushnil(first);
    lua_setglobal(first, "__rbx_native_signal_fire");
    lua_pushnil(first);
    lua_setglobal(first, "__rbx_native_signal_disconnect_all");
    lua_pushnil(first);
    lua_setglobal(first, "__rbx_native_http_request");
    lua_getglobal(first, "nativeSignal");
    lua_getfield(first, -1, "Fire");
    CHECK(lua_isnil(first, -1));
    lua_pop(first, 2);

    lua_pushliteral(first, "payload");
    CHECK(bridge->fire(first, changed, -1, 1) >= 2);
    lua_pop(first, 1);
    firstContext.scheduler().runUntilIdle();
    if (firstContext.scheduler().timerCount() > 0)
    {
        CHECK(firstContext.scheduler().advanceToNextTimer());
        firstContext.scheduler().runUntilIdle();
    }
    lua_getglobal(first, "observed");
    CHECK(std::string(lua_tostring(first, -1)) == "payload");
    lua_pop(first, 1);
    lua_getglobal(first, "manualSignalValue");
    CHECK(std::string(lua_tostring(first, -1)) == "payload");
    lua_pop(first, 1);
    lua_getglobal(first, "waitedValue");
    CHECK(std::string(lua_tostring(first, -1)) == "payload");
    lua_pop(first, 1);
    lua_getglobal(first, "timerElapsed");
    CHECK(lua_isnumber(first, -1));
    CHECK(lua_tonumber(first, -1) >= 0.05);
    lua_pop(first, 1);
    lua_getglobal(first, "manualWaitDone");
    CHECK(lua_toboolean(first, -1));
    lua_pop(first, 1);
    lua_getglobal(first, "cancelledDelay");
    CHECK(!lua_toboolean(first, -1));
    lua_pop(first, 1);

    lua_getglobal(first, "Changed");
    lua_getfield(first, -1, "Fire");
    CHECK(lua_isnil(first, -1));
    lua_pop(first, 2);

    const std::string failingBytecode = compile("error('expected-main-failure')");
    CHECK(luau_load(first, "=failure-test", failingBytecode.data(), failingBytecode.size(), 0) == LUA_OK);
    LuauMainRunOptions oneResume;
    oneResume.maxResumes = 1;
    LuauMainResult failedMain = bridge->runMain(first, -1, 0, 0, oneResume);
    CHECK(failedMain.state == LuauMainState::Failed);
    CHECK(failedMain.error.find("expected-main-failure") != std::string::npos);
    lua_pop(first, 1);

    const std::string childFailureBytecode = compile("task.spawn(function() error('expected-child-failure') end); return true");
    CHECK(luau_load(first, "=child-failure-test", childFailureBytecode.data(), childFailureBytecode.size(), 0) == LUA_OK);
    LuauMainRunOptions childFailureBudget;
    childFailureBudget.maxResumes = 1;
    LuauMainResult childFailure = bridge->runMain(first, -1, 0, 0, childFailureBudget);
    CHECK(childFailure.state == LuauMainState::Failed);
    CHECK(childFailure.error.find("expected-child-failure") != std::string::npos);
    bridge->releaseMainResults(childFailure);
    lua_pop(first, 1);

    const std::string longTimerBytecode = compile("task.wait(100); return 'late'");
    CHECK(luau_load(first, "=timer-budget-test", longTimerBytecode.data(), longTimerBytecode.size(), 0) == LUA_OK);
    LuauMainRunOptions timerBudget;
    timerBudget.maxVirtualSeconds = 0.0;
    LuauMainResult timerMain = bridge->runMain(first, -1, 0, 0, timerBudget);
    if (timerMain.state != LuauMainState::SteadyState)
        std::cerr << "timer budget state=" << static_cast<int>(timerMain.state) << " error=" << timerMain.error
                  << " elapsed=" << timerMain.elapsedVirtualSeconds << " resumes=" << timerMain.resumes << '\n';
    CHECK(timerMain.state == LuauMainState::SteadyState);
    CHECK(!timerMain.mainCompleted);
    CHECK(timerMain.elapsedVirtualSeconds <= 0.000001);
    CHECK(firstContext.scheduler().cancel(timerMain.task));
    lua_pop(first, 1);

    bridge->releaseMainResults(mainResult);
    bridge->shutdown();
    firstContext.removeSubsystem(LuauRuntimeBridge::kSubsystemKey);
    bridge.reset();
    firstContext.detach();
    secondContext.detach();
    lua_close(first);
    lua_close(second);
}

void detachedContextLuaCloseTests()
{
    lua_State* state = luaL_newstate();
    CHECK(state);
    luaL_openlibs(state);

    auto context = std::make_unique<RuntimeContext>(state, RuntimeContextOptions{});
    context->attach();
    auto bridge = LuauRuntimeBridge::create(*context);
    std::shared_ptr<NativeSignal> signal = context->createSignal("LateLuaSignal");
    std::weak_ptr<NativeSignal> retainedByLua = signal;
    bridge->pushSignal(state, signal);
    lua_setglobal(state, "LateLuaSignal");
    signal.reset();

    const std::string bytecode = compile("LateConnection = LateLuaSignal:Connect(function() end)");
    CHECK(luau_load(state, "=late-signal-teardown", bytecode.data(), bytecode.size(), 0) == LUA_OK);
    CHECK(lua_pcall(state, 0, 0, 0) == LUA_OK);

    bridge->shutdown();
    context->removeSubsystem(LuauRuntimeBridge::kSubsystemKey);
    bridge.reset();
    context->detach(); // clears every scheduler-side signal slot and waiter
    context.reset();   // deliberately destroy Scheduler before Lua userdata
    CHECK(!retainedByLua.expired());
    lua_close(state);  // must not dereference the former Scheduler
    CHECK(retainedByLua.expired());
}

} // namespace

int main()
{
    try
    {
        schedulerTests();
        signalTests();
        moduleTests();
        filesystemAndExecutorTests();
        networkTests();
        contextAndBridgeTests();
        detachedContextLuaCloseTests();
        std::cout << "runtime foundation tests passed\n";
        return EXIT_SUCCESS;
    }
    catch (const std::exception& exception)
    {
        std::cerr << exception.what() << '\n';
        return EXIT_FAILURE;
    }
}
