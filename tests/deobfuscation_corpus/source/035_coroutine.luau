-- corpus: coroutine; variant: 2
local thread = coroutine.create(function()
  coroutine.yield(36)
  return 37
end)
local _, first = coroutine.resume(thread)
local _, second = coroutine.resume(thread)
print(first, second)
