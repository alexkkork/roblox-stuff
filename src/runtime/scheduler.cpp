#include "scheduler.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <utility>

namespace rbx::runtime
{

TaskStep TaskStep::complete()
{
    return {};
}

TaskStep TaskStep::wait(double seconds)
{
    TaskStep result;
    result.kind = Kind::Wait;
    result.durationSeconds = seconds;
    return result;
}

TaskStep TaskStep::waitSignal(std::string key)
{
    TaskStep result;
    result.kind = Kind::WaitSignal;
    result.waitKey = std::move(key);
    return result;
}

TaskStep TaskStep::waitModule(std::string key)
{
    TaskStep result;
    result.kind = Kind::WaitModule;
    result.waitKey = std::move(key);
    return result;
}

TaskStep TaskStep::waitExternal(std::string key)
{
    TaskStep result;
    result.kind = Kind::WaitExternal;
    result.waitKey = std::move(key);
    return result;
}

TaskStep TaskStep::yieldNextCycle()
{
    TaskStep result;
    result.kind = Kind::YieldNextCycle;
    return result;
}

TaskStep TaskStep::arbitraryYield()
{
    TaskStep result;
    result.kind = Kind::ArbitraryYield;
    return result;
}

TaskStep TaskStep::fail(std::string message)
{
    TaskStep result;
    result.kind = Kind::Error;
    result.error = std::move(message);
    return result;
}

Scheduler::Scheduler(std::shared_ptr<RuntimeClock> clock, SchedulerOptions options)
    : clock_(std::move(clock))
    , options_(options)
    , ownerThread_(std::this_thread::get_id())
{
    if (!clock_)
        throw std::invalid_argument("scheduler requires a clock");
    if (!std::isfinite(options_.frameDurationSeconds) || options_.frameDurationSeconds <= 0.0)
        throw std::invalid_argument("frame duration must be positive and finite");
    if (options_.maxTasks == 0)
        throw std::invalid_argument("maxTasks must be non-zero");
    if (options_.maxImmediateDepth == 0)
        throw std::invalid_argument("maxImmediateDepth must be non-zero");
}

Scheduler::~Scheduler()
{
    shuttingDown_.store(true, std::memory_order_release);
    std::lock_guard lock(externalMutex_);
    external_.clear();
}

TaskId Scheduler::createTask(TaskCallback callback, std::string name, std::optional<TaskExecutionMetadata> metadata)
{
    assertOwnerThread();
    if (!callback)
        throw std::invalid_argument("task callback cannot be empty");
    if (tasks_.size() >= options_.maxTasks)
        throw std::runtime_error("scheduler task limit reached");

    const TaskId id = nextTaskId_++;
    TaskRecord recordValue;
    recordValue.snapshot.id = id;
    recordValue.snapshot.name = std::move(name);
    recordValue.snapshot.createdAt = now();
    if (metadata)
        recordValue.snapshot.execution = std::move(*metadata);
    else if (currentTask_)
    {
        auto parent = tasks_.find(*currentTask_);
        if (parent != tasks_.end())
            recordValue.snapshot.execution = parent->second.snapshot.execution;
    }
    recordValue.callback = std::move(callback);
    tasks_.emplace(id, std::move(recordValue));
    return id;
}

TaskId Scheduler::spawn(TaskCallback callback, std::string name, ResumeData initial, std::optional<TaskExecutionMetadata> metadata)
{
    const TaskId id = createTask(std::move(callback), std::move(name), std::move(metadata));
    enqueue(id, QueueKind::Spawn, std::move(initial));
    return id;
}

TaskId Scheduler::spawnImmediate(TaskCallback callback, std::string name, ResumeData initial, std::optional<TaskExecutionMetadata> metadata)
{
    const TaskId id = createTask(std::move(callback), std::move(name), std::move(metadata));
    if (immediateDepth_ >= options_.maxImmediateDepth)
    {
        enqueue(id, QueueKind::Spawn, std::move(initial));
        record(id, "immediate_depth_deferred", std::to_string(immediateDepth_));
        return id;
    }
    const Sequence sequence = nextSequence();
    initial.source = QueueKind::Spawn;
    TaskRecord& recordValue = tasks_.at(id);
    recordValue.snapshot.status = TaskStatus::Queued;
    recordValue.snapshot.lastQueue = QueueKind::Spawn;
    recordValue.snapshot.sequence = sequence;
    record(id, "queue", "spawn-immediate");
    execute(QueueEntry{id, sequence, QueueKind::Spawn, std::move(initial)});
    return id;
}

TaskId Scheduler::defer(TaskCallback callback, std::string name, ResumeData initial, std::optional<TaskExecutionMetadata> metadata)
{
    const TaskId id = createTask(std::move(callback), std::move(name), std::move(metadata));
    enqueue(id, QueueKind::Deferred, std::move(initial));
    return id;
}

TaskId Scheduler::delay(
    double seconds, TaskCallback callback, std::string name, ResumeData initial, std::optional<TaskExecutionMetadata> metadata)
{
    if (!std::isfinite(seconds) || seconds < 0.0)
        throw std::invalid_argument("delay must be finite and non-negative");
    const TaskId id = createTask(std::move(callback), std::move(name), std::move(metadata));
    const double duration = std::max(options_.frameDurationSeconds, seconds);
    enqueueTimer(id, now() + duration, std::move(initial), now());
    return id;
}

TaskId Scheduler::schedulePhase(
    RunPhase phase, TaskCallback callback, std::string name, ResumeData initial, std::optional<TaskExecutionMetadata> metadata)
{
    const TaskId id = createTask(std::move(callback), std::move(name), std::move(metadata));
    TaskRecord& recordValue = tasks_.at(id);
    const Sequence sequence = nextSequence();
    recordValue.snapshot.status = TaskStatus::Queued;
    recordValue.snapshot.lastQueue = QueueKind::RunServicePhase;
    recordValue.snapshot.sequence = sequence;
    initial.source = QueueKind::RunServicePhase;
    initial.sourceName = std::string(toString(phase));
    phases_.emplace(std::make_pair(static_cast<int>(phase), sequence), QueueEntry{id, sequence, QueueKind::RunServicePhase, std::move(initial)});
    record(id, "phase_queue", std::string(toString(phase)));
    return id;
}

TaskId Scheduler::adoptSuspended(
    TaskCallback callback, TaskStatus status, std::string waitKey, std::string name, std::optional<TaskExecutionMetadata> metadata)
{
    if (status != TaskStatus::WaitingSignal && status != TaskStatus::WaitingModule && status != TaskStatus::WaitingExternal &&
        status != TaskStatus::Suspended)
        throw std::invalid_argument("adoptSuspended requires a non-timer suspended status");
    const TaskId id = createTask(std::move(callback), std::move(name), std::move(metadata));
    TaskRecord& recordValue = tasks_.at(id);
    recordValue.snapshot.status = status;
    recordValue.snapshot.waitKey = std::move(waitKey);
    recordValue.snapshot.sequence = nextSequence();
    record(id, "adopt", std::string(toString(status)));
    return id;
}

void Scheduler::enqueue(TaskId taskId, QueueKind queue, ResumeData data)
{
    assertOwnerThread();
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || terminal(found->second.snapshot.status))
        return;

    const Sequence sequence = nextSequence();
    data.source = queue;
    found->second.snapshot.status = TaskStatus::Queued;
    found->second.snapshot.lastQueue = queue;
    found->second.snapshot.sequence = sequence;
    found->second.snapshot.waitKey.clear();
    QueueEntry entry{taskId, sequence, queue, std::move(data)};
    if (queue == QueueKind::Deferred)
        deferred_.push_back(std::move(entry));
    else
        ready_.push_back(std::move(entry));
    record(taskId, "queue", std::string(toString(queue)));
}

void Scheduler::enqueueTimer(TaskId taskId, double due, ResumeData data, double waitStarted)
{
    assertOwnerThread();
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || terminal(found->second.snapshot.status))
        return;

    const Sequence sequence = nextSequence();
    data.source = QueueKind::Timer;
    found->second.snapshot.status = TaskStatus::WaitingTimer;
    found->second.snapshot.lastQueue = QueueKind::Timer;
    found->second.snapshot.sequence = sequence;
    found->second.snapshot.waitKey = "timer";
    found->second.waitStarted = waitStarted;
    timers_.emplace(TimerKey{due, sequence}, QueueEntry{taskId, sequence, QueueKind::Timer, std::move(data), waitStarted});
    record(taskId, "timer", std::to_string(due));
}

bool Scheduler::resume(TaskId taskId, ResumeData data, QueueKind queue)
{
    assertOwnerThread();
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || terminal(found->second.snapshot.status) || found->second.snapshot.status == TaskStatus::Running)
        return false;
    removeQueuedEntries(taskId);
    enqueue(taskId, queue, std::move(data));
    return true;
}

bool Scheduler::resumeImmediate(TaskId taskId, ResumeData data)
{
    assertOwnerThread();
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || terminal(found->second.snapshot.status) || found->second.snapshot.status == TaskStatus::Running)
        return false;

    removeQueuedEntries(taskId);
    if (immediateDepth_ >= options_.maxImmediateDepth)
    {
        enqueue(taskId, QueueKind::Spawn, std::move(data));
        record(taskId, "immediate_depth_deferred", std::to_string(immediateDepth_));
        return true;
    }

    const Sequence sequence = nextSequence();
    data.source = QueueKind::Spawn;
    TaskRecord& recordValue = found->second;
    recordValue.snapshot.status = TaskStatus::Queued;
    recordValue.snapshot.lastQueue = QueueKind::Spawn;
    recordValue.snapshot.sequence = sequence;
    recordValue.snapshot.waitKey.clear();
    record(taskId, "queue", "spawn-immediate");
    return execute(QueueEntry{taskId, sequence, QueueKind::Spawn, std::move(data)});
}

bool Scheduler::resumeAfter(TaskId taskId, double seconds, ResumeData data)
{
    assertOwnerThread();
    if (!std::isfinite(seconds) || seconds < 0.0)
        return false;
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || terminal(found->second.snapshot.status) || found->second.snapshot.status == TaskStatus::Running)
        return false;

    removeQueuedEntries(taskId);
    const double duration = std::max(options_.frameDurationSeconds, seconds);
    enqueueTimer(taskId, now() + duration, std::move(data), now());
    return true;
}

bool Scheduler::resumeManual(TaskId taskId, ResumeData data)
{
    assertOwnerThread();
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || found->second.snapshot.status != TaskStatus::Suspended)
        return false;
    return resume(taskId, std::move(data), QueueKind::Manual);
}

bool Scheduler::cancel(TaskId taskId, std::string reason)
{
    assertOwnerThread();
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || terminal(found->second.snapshot.status))
        return false;

    removeQueuedEntries(taskId);
    found->second.snapshot.status = TaskStatus::Cancelled;
    found->second.snapshot.error = std::move(reason);
    found->second.snapshot.waitKey.clear();
    record(taskId, "cancel", found->second.snapshot.error);

    auto observers = std::move(found->second.cancellationObservers);
    found->second.cancellationObservers.clear();
    for (auto& [_, observer] : observers)
    {
        if (observer)
            observer();
    }
    return true;
}

bool Scheduler::forget(TaskId taskId)
{
    assertOwnerThread();
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || !terminal(found->second.snapshot.status))
        return false;
    tasks_.erase(found);
    return true;
}

bool Scheduler::setTaskMetadata(TaskId taskId, TaskExecutionMetadata metadata)
{
    assertOwnerThread();
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || (found->second.snapshot.status == TaskStatus::Running && currentTask_ != taskId))
        return false;
    found->second.snapshot.execution = std::move(metadata);
    return true;
}

std::optional<TaskId> Scheduler::currentTask() const
{
    assertOwnerThread();
    return currentTask_;
}

std::optional<TaskExecutionMetadata> Scheduler::currentTaskMetadata() const
{
    assertOwnerThread();
    if (!currentTask_)
        return std::nullopt;
    auto found = tasks_.find(*currentTask_);
    return found == tasks_.end() ? std::nullopt : std::optional(found->second.snapshot.execution);
}

CancellationObserverId Scheduler::addCancellationObserver(TaskId taskId, std::function<void()> observer)
{
    assertOwnerThread();
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || terminal(found->second.snapshot.status) || !observer)
        return 0;
    const CancellationObserverId id = nextObserverId_++;
    found->second.cancellationObservers.emplace(id, std::move(observer));
    return id;
}

bool Scheduler::removeCancellationObserver(TaskId taskId, CancellationObserverId observer)
{
    assertOwnerThread();
    auto found = tasks_.find(taskId);
    return found != tasks_.end() && found->second.cancellationObservers.erase(observer) != 0;
}

void Scheduler::postExternal(ExternalCallback callback, double virtualDelaySeconds, std::string name)
{
    if (!callback || shuttingDown_.load(std::memory_order_acquire))
        return;
    if (!std::isfinite(virtualDelaySeconds) || virtualDelaySeconds < 0.0)
        throw std::invalid_argument("external delay must be finite and non-negative");

    // External sequence is used only to preserve the mutex insertion order. It
    // intentionally does not touch nextSequence_, which belongs to the owner.
    ExternalEntry entry{externalSequence_.fetch_add(1, std::memory_order_relaxed), std::move(callback), virtualDelaySeconds, std::move(name)};
    std::lock_guard lock(externalMutex_);
    external_.push_back(std::move(entry));
}

std::size_t Scheduler::pollExternal()
{
    assertOwnerThread();
    std::deque<ExternalEntry> incoming;
    {
        std::lock_guard lock(externalMutex_);
        incoming.swap(external_);
    }
    std::stable_sort(incoming.begin(), incoming.end(), [](const ExternalEntry& lhs, const ExternalEntry& rhs) {
        return lhs.sequence < rhs.sequence;
    });

    const std::size_t count = incoming.size();
    while (!incoming.empty())
    {
        ExternalEntry entry = std::move(incoming.front());
        incoming.pop_front();
        TaskCallback callback = [action = std::move(entry.callback)](const ResumeData&) mutable {
            action();
            return TaskStep::complete();
        };
        if (entry.delay > 0.0)
            delay(entry.delay, std::move(callback), entry.name.empty() ? "external" : std::move(entry.name));
        else
        {
            ResumeData initial;
            initial.source = QueueKind::External;
            spawn(std::move(callback), entry.name.empty() ? "external" : std::move(entry.name), std::move(initial));
        }
    }
    return count;
}

void Scheduler::promoteTimers()
{
    const double current = now();
    auto iterator = timers_.begin();
    while (iterator != timers_.end() && iterator->first.first <= current + 1e-12)
    {
        QueueEntry entry = std::move(iterator->second);
        iterator = timers_.erase(iterator);
        auto found = tasks_.find(entry.task);
        if (found == tasks_.end() || found->second.snapshot.status != TaskStatus::WaitingTimer)
            continue;
        entry.data.waitedSeconds = std::max(0.0, current - entry.waitStarted);
        entry.data.source = QueueKind::Timer;
        found->second.snapshot.status = TaskStatus::Queued;
        found->second.snapshot.waitKey.clear();
        ready_.push_back(std::move(entry));
    }
}

void Scheduler::promoteDeferred()
{
    while (!deferred_.empty())
    {
        ready_.push_back(std::move(deferred_.front()));
        deferred_.pop_front();
    }
}

void Scheduler::promotePhaseQueue()
{
    for (auto& [_, entry] : phases_)
        ready_.push_back(std::move(entry));
    phases_.clear();
}

bool Scheduler::step()
{
    assertOwnerThread();
    pollExternal();
    promoteTimers();
    if (ready_.empty())
        promoteDeferred();
    if (ready_.empty())
        promotePhaseQueue();
    if (ready_.empty())
        return false;

    QueueEntry entry = std::move(ready_.front());
    ready_.pop_front();
    execute(std::move(entry));
    return true;
}

bool Scheduler::execute(QueueEntry entry)
{
    auto found = tasks_.find(entry.task);
    if (found == tasks_.end() || found->second.snapshot.status != TaskStatus::Queued || found->second.snapshot.sequence != entry.sequence)
        return false;

    found->second.snapshot.status = TaskStatus::Running;
    found->second.snapshot.lastQueue = entry.queue;
    found->second.snapshot.lastResumedAt = now();
    found->second.snapshot.resumeCount++;
    found->second.lastResume = entry.data;
    TaskCallback callback = found->second.callback;
    totalResumes_++;
    record(entry.task, "resume", std::string(toString(entry.queue)));

    TaskStep result;
    const std::optional<TaskId> previousTask = currentTask_;
    currentTask_ = entry.task;
    ++immediateDepth_;
    try
    {
        result = callback(entry.data);
    }
    catch (const std::exception& exception)
    {
        result = TaskStep::fail(exception.what());
    }
    catch (...)
    {
        result = TaskStep::fail("unknown native task exception");
    }
    --immediateDepth_;
    currentTask_ = previousTask;
    processStepResult(entry.task, std::move(result));
    return true;
}

void Scheduler::processStepResult(TaskId taskId, TaskStep result)
{
    auto found = tasks_.find(taskId);
    if (found == tasks_.end() || found->second.snapshot.status != TaskStatus::Running)
        return;
    TaskRecord& taskRecord = found->second;
    TaskSnapshot& snapshot = taskRecord.snapshot;
    switch (result.kind)
    {
    case TaskStep::Kind::Complete:
        snapshot.status = TaskStatus::Completed;
        snapshot.waitKey.clear();
        taskRecord.cancellationObservers.clear();
        record(snapshot.id, "complete");
        break;
    case TaskStep::Kind::Wait:
    {
        if (!std::isfinite(result.durationSeconds) || result.durationSeconds < 0.0)
        {
            snapshot.status = TaskStatus::Failed;
            snapshot.error = "task wait duration must be finite and non-negative";
            record(snapshot.id, "error", snapshot.error);
            break;
        }
        const double duration = std::max(options_.frameDurationSeconds, result.durationSeconds);
        ResumeData resumeData;
        resumeData.returnWaitedSeconds = true;
        enqueueTimer(snapshot.id, now() + duration, std::move(resumeData), now());
        break;
    }
    case TaskStep::Kind::WaitSignal:
        snapshot.status = TaskStatus::WaitingSignal;
        snapshot.waitKey = std::move(result.waitKey);
        record(snapshot.id, "signal_wait", snapshot.waitKey);
        break;
    case TaskStep::Kind::WaitModule:
        snapshot.status = TaskStatus::WaitingModule;
        snapshot.waitKey = std::move(result.waitKey);
        record(snapshot.id, "module_wait", snapshot.waitKey);
        break;
    case TaskStep::Kind::WaitExternal:
        snapshot.status = TaskStatus::WaitingExternal;
        snapshot.waitKey = std::move(result.waitKey);
        record(snapshot.id, "external_wait", snapshot.waitKey);
        break;
    case TaskStep::Kind::YieldNextCycle:
        enqueue(snapshot.id, QueueKind::Deferred, {});
        break;
    case TaskStep::Kind::ArbitraryYield:
        snapshot.status = TaskStatus::Suspended;
        snapshot.waitKey = "caller-controlled-yield";
        record(snapshot.id, "yield", snapshot.waitKey);
        break;
    case TaskStep::Kind::Error:
        snapshot.status = TaskStatus::Failed;
        snapshot.error = result.error.empty() ? "task failed" : std::move(result.error);
        snapshot.waitKey.clear();
        taskRecord.cancellationObservers.clear();
        record(snapshot.id, "error", snapshot.error);
        break;
    }
}

std::size_t Scheduler::runUntilIdle(std::size_t maxResumes)
{
    assertOwnerThread();
    std::size_t count = 0;
    while (count < maxResumes && step())
        ++count;
    return count;
}

bool Scheduler::advanceToNextTimer()
{
    assertOwnerThread();
    pollExternal();
    if (clock_->mode() != ClockMode::Virtual || timers_.empty())
        return false;
    return clock_->advanceTo(timers_.begin()->first.first);
}

bool Scheduler::advanceBy(double seconds)
{
    assertOwnerThread();
    if (!std::isfinite(seconds) || seconds < 0.0 || clock_->mode() != ClockMode::Virtual)
        return false;
    return clock_->advanceTo(now() + seconds);
}

std::size_t Scheduler::runFrame(std::size_t maxResumes)
{
    assertOwnerThread();
    if (clock_->mode() == ClockMode::Virtual)
        clock_->advanceTo(now() + options_.frameDurationSeconds);
    return runUntilIdle(maxResumes);
}

void Scheduler::removeQueuedEntries(TaskId taskId)
{
    auto removeDeque = [taskId](std::deque<QueueEntry>& queue) {
        queue.erase(std::remove_if(queue.begin(), queue.end(), [taskId](const QueueEntry& entry) {
                        return entry.task == taskId;
                    }),
            queue.end());
    };
    removeDeque(ready_);
    removeDeque(deferred_);
    for (auto iterator = timers_.begin(); iterator != timers_.end();)
        iterator = iterator->second.task == taskId ? timers_.erase(iterator) : std::next(iterator);
    for (auto iterator = phases_.begin(); iterator != phases_.end();)
        iterator = iterator->second.task == taskId ? phases_.erase(iterator) : std::next(iterator);
}

void Scheduler::record(TaskId taskId, std::string kind, std::string detail)
{
    if (options_.maxEvents == 0)
        return;
    if (events_.size() == options_.maxEvents)
        events_.erase(events_.begin());
    events_.push_back(SchedulerEvent{nextSequence(), now(), taskId, std::move(kind), std::move(detail)});
}

Sequence Scheduler::nextSequence()
{
    return nextSequence_++;
}

bool Scheduler::ownsCurrentThread() const
{
    return ownerThread_ == std::this_thread::get_id();
}

void Scheduler::assertOwnerThread() const
{
    if (!ownsCurrentThread())
        throw std::logic_error("scheduler state may only be accessed by its owner thread");
}

double Scheduler::now() const
{
    return clock_->now();
}

const std::shared_ptr<RuntimeClock>& Scheduler::clock() const
{
    return clock_;
}

const SchedulerOptions& Scheduler::options() const
{
    return options_;
}

std::optional<TaskSnapshot> Scheduler::task(TaskId id) const
{
    assertOwnerThread();
    auto found = tasks_.find(id);
    return found == tasks_.end() ? std::nullopt : std::optional(found->second.snapshot);
}

std::vector<TaskSnapshot> Scheduler::tasks() const
{
    assertOwnerThread();
    std::vector<TaskSnapshot> result;
    result.reserve(tasks_.size());
    for (const auto& [_, taskRecord] : tasks_)
        result.push_back(taskRecord.snapshot);
    std::sort(result.begin(), result.end(), [](const TaskSnapshot& lhs, const TaskSnapshot& rhs) {
        return lhs.id < rhs.id;
    });
    return result;
}

std::vector<SchedulerEvent> Scheduler::events() const
{
    assertOwnerThread();
    return events_;
}

SchedulerStats Scheduler::stats() const
{
    assertOwnerThread();
    SchedulerStats result;
    for (const auto& [_, taskRecord] : tasks_)
    {
        switch (taskRecord.snapshot.status)
        {
        case TaskStatus::Queued:
            result.queued++;
            break;
        case TaskStatus::Running:
            result.running++;
            break;
        case TaskStatus::WaitingTimer:
        case TaskStatus::WaitingSignal:
        case TaskStatus::WaitingModule:
        case TaskStatus::WaitingExternal:
            result.waiting++;
            break;
        case TaskStatus::Suspended:
            result.suspended++;
            break;
        case TaskStatus::Completed:
            result.completed++;
            break;
        case TaskStatus::Cancelled:
            result.cancelled++;
            break;
        case TaskStatus::Failed:
            result.failed++;
            break;
        }
    }
    {
        std::lock_guard lock(externalMutex_);
        result.externalPending = external_.size();
    }
    result.totalResumes = totalResumes_;
    return result;
}

std::size_t Scheduler::queuedCount() const
{
    assertOwnerThread();
    return ready_.size() + deferred_.size() + phases_.size();
}

std::size_t Scheduler::timerCount() const
{
    assertOwnerThread();
    return timers_.size();
}

std::optional<double> Scheduler::nextTimerDue() const
{
    assertOwnerThread();
    return timers_.empty() ? std::nullopt : std::optional(timers_.begin()->first.first);
}

std::size_t Scheduler::taskCount() const
{
    assertOwnerThread();
    return tasks_.size();
}

bool Scheduler::terminal(TaskStatus status)
{
    return status == TaskStatus::Completed || status == TaskStatus::Cancelled || status == TaskStatus::Failed;
}

std::string_view toString(QueueKind kind)
{
    switch (kind)
    {
    case QueueKind::Spawn:
        return "spawn";
    case QueueKind::Deferred:
        return "deferred";
    case QueueKind::Timer:
        return "timer";
    case QueueKind::RunServicePhase:
        return "run-service-phase";
    case QueueKind::Signal:
        return "signal";
    case QueueKind::Module:
        return "module";
    case QueueKind::External:
        return "external";
    case QueueKind::Manual:
        return "manual";
    }
    return "unknown";
}

std::string_view toString(TaskStatus status)
{
    switch (status)
    {
    case TaskStatus::Queued:
        return "queued";
    case TaskStatus::Running:
        return "running";
    case TaskStatus::WaitingTimer:
        return "waiting-timer";
    case TaskStatus::WaitingSignal:
        return "waiting-signal";
    case TaskStatus::WaitingModule:
        return "waiting-module";
    case TaskStatus::WaitingExternal:
        return "waiting-external";
    case TaskStatus::Suspended:
        return "suspended";
    case TaskStatus::Completed:
        return "completed";
    case TaskStatus::Cancelled:
        return "cancelled";
    case TaskStatus::Failed:
        return "failed";
    }
    return "unknown";
}

std::string_view toString(RunPhase phase)
{
    switch (phase)
    {
    case RunPhase::PreSimulation:
        return "PreSimulation";
    case RunPhase::Stepped:
        return "Stepped";
    case RunPhase::PostSimulation:
        return "PostSimulation";
    case RunPhase::Heartbeat:
        return "Heartbeat";
    case RunPhase::PreAnimation:
        return "PreAnimation";
    case RunPhase::PreRender:
        return "PreRender";
    case RunPhase::RenderStepped:
        return "RenderStepped";
    }
    return "Unknown";
}

} // namespace rbx::runtime
