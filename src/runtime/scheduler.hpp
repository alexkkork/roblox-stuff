#pragma once

#include "clock.hpp"
#include "runtime_value.hpp"
#include "security.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace rbx::runtime
{

using TaskId = uint64_t;
using Sequence = uint64_t;
using CancellationObserverId = uint64_t;

enum class QueueKind : uint8_t
{
    Spawn,
    Deferred,
    Timer,
    RunServicePhase,
    Signal,
    Module,
    External,
    Manual,
};

enum class RunPhase : uint8_t
{
    PreRender,
    RenderStepped,
    PreAnimation,
    PreSimulation,
    Stepped,
    PostSimulation,
    Heartbeat,
};

enum class TaskStatus : uint8_t
{
    Queued,
    Running,
    WaitingTimer,
    WaitingSignal,
    WaitingModule,
    WaitingExternal,
    Suspended,
    Completed,
    Cancelled,
    Failed,
};

struct ResumeData
{
    RuntimeValues arguments;
    double waitedSeconds = 0.0;
    // Timer entries serve two distinct Luau contracts: task.wait resumes with
    // the measured elapsed time, while task.delay resumes with only the
    // caller-supplied arguments. Keep that distinction explicit instead of
    // inferring it from QueueKind::Timer.
    bool returnWaitedSeconds = false;
    QueueKind source = QueueKind::Spawn;
    std::string sourceName;
};

struct TaskExecutionMetadata
{
    uint64_t threadContextId = 0;
    uint64_t scriptInstanceId = 0;
    SecurityDescriptor security;
    uint8_t actorLane = 0;
};

struct TaskStep
{
    enum class Kind : uint8_t
    {
        Complete,
        Wait,
        WaitSignal,
        WaitModule,
        WaitExternal,
        YieldNextCycle,
        ArbitraryYield,
        Error,
    };

    Kind kind = Kind::Complete;
    double durationSeconds = 0.0;
    std::string waitKey;
    std::string error;

    static TaskStep complete();
    static TaskStep wait(double seconds);
    static TaskStep waitSignal(std::string key = {});
    static TaskStep waitModule(std::string key = {});
    static TaskStep waitExternal(std::string key = {});
    static TaskStep yieldNextCycle();
    static TaskStep arbitraryYield();
    static TaskStep fail(std::string message);
};

using TaskCallback = std::function<TaskStep(const ResumeData&)>;
using ExternalCallback = std::function<void()>;

struct SchedulerOptions
{
    double frameDurationSeconds = 1.0 / 60.0;
    std::size_t maxEvents = 4096;
    std::size_t maxTasks = 100000;
    std::size_t maxImmediateDepth = 64;
};

struct TaskSnapshot
{
    TaskId id = 0;
    TaskStatus status = TaskStatus::Queued;
    QueueKind lastQueue = QueueKind::Spawn;
    Sequence sequence = 0;
    std::string name;
    std::string waitKey;
    std::string error;
    double createdAt = 0.0;
    double lastResumedAt = 0.0;
    std::size_t resumeCount = 0;
    TaskExecutionMetadata execution;
};

struct SchedulerEvent
{
    Sequence sequence = 0;
    double time = 0.0;
    TaskId task = 0;
    std::string kind;
    std::string detail;
};

struct SchedulerStats
{
    std::size_t queued = 0;
    std::size_t running = 0;
    std::size_t waiting = 0;
    std::size_t suspended = 0;
    std::size_t completed = 0;
    std::size_t cancelled = 0;
    std::size_t failed = 0;
    std::size_t externalPending = 0;
    uint64_t totalResumes = 0;
};

class Scheduler
{
public:
    explicit Scheduler(std::shared_ptr<RuntimeClock> clock, SchedulerOptions options = {});
    ~Scheduler();

    Scheduler(const Scheduler&) = delete;
    Scheduler& operator=(const Scheduler&) = delete;

    TaskId spawn(TaskCallback callback, std::string name = {}, ResumeData initial = {}, std::optional<TaskExecutionMetadata> metadata = std::nullopt);
    TaskId spawnImmediate(TaskCallback callback, std::string name = {}, ResumeData initial = {}, std::optional<TaskExecutionMetadata> metadata = std::nullopt);
    TaskId defer(TaskCallback callback, std::string name = {}, ResumeData initial = {}, std::optional<TaskExecutionMetadata> metadata = std::nullopt);
    TaskId delay(
        double seconds, TaskCallback callback, std::string name = {}, ResumeData initial = {}, std::optional<TaskExecutionMetadata> metadata = std::nullopt);
    TaskId schedulePhase(
        RunPhase phase, TaskCallback callback, std::string name = {}, ResumeData initial = {}, std::optional<TaskExecutionMetadata> metadata = std::nullopt);
    TaskId adoptSuspended(TaskCallback callback, TaskStatus status, std::string waitKey = {}, std::string name = {},
        std::optional<TaskExecutionMetadata> metadata = std::nullopt);

    bool resume(TaskId task, ResumeData data, QueueKind queue = QueueKind::Manual);
    bool resumeImmediate(TaskId task, ResumeData data = {});
    bool resumeAfter(TaskId task, double seconds, ResumeData data = {});
    bool resumeManual(TaskId task, ResumeData data = {});
    bool cancel(TaskId task, std::string reason = "cancelled");
    bool forget(TaskId task);
    bool setTaskMetadata(TaskId task, TaskExecutionMetadata metadata);
    std::optional<TaskId> currentTask() const;
    std::optional<TaskExecutionMetadata> currentTaskMetadata() const;

    CancellationObserverId addCancellationObserver(TaskId task, std::function<void()> observer);
    bool removeCancellationObserver(TaskId task, CancellationObserverId observer);

    // Safe to call from worker threads. The callback only runs when the owner
    // thread polls or steps the scheduler.
    void postExternal(ExternalCallback callback, double virtualDelaySeconds = 0.0, std::string name = {});
    std::size_t pollExternal();

    bool step();
    std::size_t runUntilIdle(std::size_t maxResumes = 100000);
    bool advanceToNextTimer();
    bool advanceBy(double seconds);
    std::size_t runFrame(std::size_t maxResumes = 100000);

    bool ownsCurrentThread() const;
    double now() const;
    const std::shared_ptr<RuntimeClock>& clock() const;
    const SchedulerOptions& options() const;

    std::optional<TaskSnapshot> task(TaskId id) const;
    std::vector<TaskSnapshot> tasks() const;
    std::vector<SchedulerEvent> events() const;
    SchedulerStats stats() const;
    std::size_t queuedCount() const;
    std::size_t timerCount() const;
    std::optional<double> nextTimerDue() const;
    std::size_t taskCount() const;

private:
    struct TaskRecord
    {
        TaskSnapshot snapshot;
        TaskCallback callback;
        ResumeData lastResume;
        double waitStarted = 0.0;
        std::unordered_map<CancellationObserverId, std::function<void()>> cancellationObservers;
    };

    struct QueueEntry
    {
        TaskId task = 0;
        Sequence sequence = 0;
        QueueKind queue = QueueKind::Spawn;
        ResumeData data;
        double waitStarted = 0.0;
    };

    struct ExternalEntry
    {
        Sequence sequence = 0;
        ExternalCallback callback;
        double delay = 0.0;
        std::string name;
    };

    using TimerKey = std::pair<double, Sequence>;

    TaskId createTask(TaskCallback callback, std::string name, std::optional<TaskExecutionMetadata> metadata);
    bool execute(QueueEntry entry);
    void enqueue(TaskId task, QueueKind queue, ResumeData data);
    void enqueueTimer(TaskId task, double due, ResumeData data, double waitStarted);
    void promoteTimers();
    void promoteDeferred();
    void promotePhaseQueue();
    void processStepResult(TaskId task, TaskStep result);
    void removeQueuedEntries(TaskId task);
    void record(TaskId task, std::string kind, std::string detail = {});
    Sequence nextSequence();
    void assertOwnerThread() const;
    static bool terminal(TaskStatus status);

    std::shared_ptr<RuntimeClock> clock_;
    SchedulerOptions options_;
    std::thread::id ownerThread_;
    TaskId nextTaskId_ = 1;
    Sequence nextSequence_ = 1;
    CancellationObserverId nextObserverId_ = 1;
    uint64_t totalResumes_ = 0;
    std::size_t immediateDepth_ = 0;
    std::optional<TaskId> currentTask_;

    std::unordered_map<TaskId, TaskRecord> tasks_;
    std::deque<QueueEntry> ready_;
    std::deque<QueueEntry> deferred_;
    std::map<TimerKey, QueueEntry> timers_;
    std::map<std::pair<int, Sequence>, QueueEntry> phases_;
    std::vector<SchedulerEvent> events_;

    mutable std::mutex externalMutex_;
    std::deque<ExternalEntry> external_;
    std::atomic<bool> shuttingDown_{false};
    std::atomic<Sequence> externalSequence_{1};
};

std::string_view toString(QueueKind kind);
std::string_view toString(TaskStatus status);
std::string_view toString(RunPhase phase);

} // namespace rbx::runtime
