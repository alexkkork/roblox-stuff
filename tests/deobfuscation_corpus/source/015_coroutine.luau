-- corpus: coroutine; variant: 1
local thread = coroutine.create(function()
  coroutine.yield(16)
  return 17
end)
local _, first = coroutine.resume(thread)
local _, second = coroutine.resume(thread)
print(first, second)
