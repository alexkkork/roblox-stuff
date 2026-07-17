-- corpus: coroutine; variant: 5
local thread = coroutine.create(function()
  coroutine.yield(96)
  return 97
end)
local _, first = coroutine.resume(thread)
local _, second = coroutine.resume(thread)
print(first, second)
