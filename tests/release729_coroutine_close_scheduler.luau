assert(type(coroutine.close) == "function")
assert(iscclosure(coroutine.close))
assert(not islclosure(coroutine.close))
assert(debug.info(coroutine.close, "s") == "[C]")

local handlerCalls = 0
local missingOk, missingError = xpcall(function()
    coroutine.close(nil)
end, function(message)
    handlerCalls += 1
    return message
end)
assert(not missingOk)
assert(handlerCalls == 1)
assert(string.find(missingError, "invalid argument #1 to 'close' (thread expected, got nil)", 1, true))

local runningOk, runningError = pcall(coroutine.close, coroutine.running())
assert(not runningOk)
assert(string.find(runningError, "cannot close running coroutine", 1, true))

local failedValue = {}
local failed = coroutine.create(function()
    error(failedValue)
end)
local resumeOk, resumeError = coroutine.resume(failed)
assert(not resumeOk and resumeError == failedValue)
local failedCloseOk, failedCloseError = coroutine.close(failed)
assert(not failedCloseOk and failedCloseError == failedValue)
assert(coroutine.close(failed))

local completed = task.spawn(function()
    return "ignored task result"
end)
assert(coroutine.status(completed) == "dead")
assert(coroutine.close(completed))

local yieldedResumed = false
local yielded = task.spawn(function()
    coroutine.yield()
    yieldedResumed = true
end)
assert(coroutine.status(yielded) == "suspended")
assert(coroutine.close(yielded))
assert(coroutine.status(yielded) == "dead")

local deferredRan = false
local deferred = task.defer(function()
    deferredRan = true
end)
assert(coroutine.status(deferred) == "suspended")
assert(coroutine.close(deferred))
assert(coroutine.status(deferred) == "dead")

local delayedRan = false
local delayed = task.delay(30, function()
    delayedRan = true
end)
assert(coroutine.status(delayed) == "suspended")
local delayedCloseOk, delayedCloseError = coroutine.close(delayed)
assert(delayedCloseOk and delayedCloseError == nil)
assert(coroutine.status(delayed) == "dead")

task.wait()
assert(not yieldedResumed)
assert(not deferredRan)
assert(not delayedRan)
print("release729-coroutine-close-scheduler-ok")
