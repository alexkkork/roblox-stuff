local observations = {}

local spawned = coroutine.create(function(first, second)
    assert(first == "spawn" and second == 1)
    table.insert(observations, "spawn:first")
    local resumedFirst, resumedSecond = coroutine.yield("caller-controlled")
    assert(resumedFirst == "spawn-resume" and resumedSecond == 2)
    table.insert(observations, "spawn:second")
end)

assert(task.spawn(spawned, "spawn", 1) == spawned)
assert(coroutine.status(spawned) == "suspended")
assert(observations[1] == "spawn:first")
assert(task.spawn(spawned, "spawn-resume", 2) == spawned)
assert(coroutine.status(spawned) == "dead")
assert(observations[2] == "spawn:second")

local deferred = coroutine.create(function(first, second)
    assert(first == "defer" and second == 3)
    table.insert(observations, "defer")
end)
assert(task.defer(deferred, "defer", 3) == deferred)
assert(coroutine.status(deferred) == "suspended")

local delayed = coroutine.create(function(first, second)
    assert(first == "delay" and second == 4)
    table.insert(observations, "delay")
end)
assert(task.delay(0.02, delayed, "delay", 4) == delayed)
assert(coroutine.status(delayed) == "suspended")

local delayedResumeValue
local delayedResume = task.spawn(function()
    delayedResumeValue = coroutine.yield("pause")
end)
assert(coroutine.status(delayedResume) == "suspended")
assert(task.delay(0, delayedResume, "delayed-resume") == delayedResume)

-- Drain deferred work and both native timers. This also verifies that a
-- task.delay coroutine receives its supplied arguments rather than the
-- elapsed-time value reserved for task.wait.
local elapsed = task.wait(0.05)
assert(elapsed >= 0.05)
assert(coroutine.status(deferred) == "dead")
assert(coroutine.status(delayed) == "dead")
assert(coroutine.status(delayedResume) == "dead")
assert(delayedResumeValue == "delayed-resume")
assert(table.find(observations, "defer"))
assert(table.find(observations, "delay"))

local functionStillWorks = false
local functionThread = task.spawn(function(value)
    functionStillWorks = value
end, true)
assert(type(functionThread) == "thread" and coroutine.status(functionThread) == "dead")
assert(functionStillWorks)

print("release729-task-coroutine-scheduling-ok")
return true
