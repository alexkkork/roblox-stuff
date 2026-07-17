#pragma once

#include "scheduler.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace rbx::runtime
{

enum class SignalBehavior
{
    Immediate,
    Deferred,
};

using SignalArguments = RuntimeValues;
using SignalTaskFactory = std::function<TaskCallback(const SignalArguments&)>;

class NativeSignal;

class SignalConnection
{
public:
    SignalConnection() = default;

    bool connected() const;
    void disconnect();
    uint64_t id() const;
    void setDisconnectCallback(std::function<void()> callback);

    explicit operator bool() const;

private:
    struct State;
    explicit SignalConnection(std::shared_ptr<State> state);

    std::shared_ptr<State> state_;
    friend class NativeSignal;
};

struct SignalSnapshot
{
    std::string name;
    SignalBehavior behavior = SignalBehavior::Immediate;
    std::size_t connectionCount = 0;
    std::size_t waiterCount = 0;
    uint64_t fireCount = 0;
};

class NativeSignal : public std::enable_shared_from_this<NativeSignal>
{
public:
    explicit NativeSignal(Scheduler& scheduler, std::string name = {}, SignalBehavior behavior = SignalBehavior::Immediate);
    ~NativeSignal();

    NativeSignal(const NativeSignal&) = delete;
    NativeSignal& operator=(const NativeSignal&) = delete;

    SignalConnection connect(SignalTaskFactory factory, std::string callbackName = {});
    SignalConnection once(SignalTaskFactory factory, std::string callbackName = {});

    // The task must return TaskStep::waitSignal after registering. Cancellation
    // observers remove the waiter synchronously, so a cancelled task cannot be
    // revived by a later fire.
    bool wait(TaskId task);
    bool removeWaiter(TaskId task);

    // Fire is intentionally a host-only C++ operation. The Luau userdata bridge
    // exposes Connect/Once/Wait, never Fire or internal connection storage.
    std::size_t fire(SignalArguments arguments = {});
    void disconnectAll(bool cancelWaiters = true);

    void setBehavior(SignalBehavior behavior);
    SignalBehavior behavior() const;
    const std::string& name() const;
    SignalSnapshot snapshot() const;

private:
    struct Slot;
    struct Waiter;

    void disconnect(uint64_t id);
    void pruneDisconnected();

    Scheduler& scheduler_;
    std::string name_;
    SignalBehavior behavior_;
    uint64_t nextConnectionId_ = 1;
    uint64_t fireCount_ = 0;
    std::vector<Slot> slots_;
    std::vector<Waiter> waiters_;
};

} // namespace rbx::runtime
