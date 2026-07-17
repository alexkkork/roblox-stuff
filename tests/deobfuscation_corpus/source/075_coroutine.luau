-- corpus: coroutine; variant: 4
local thread = coroutine.create(function()
  coroutine.yield(76)
  return 77
end)
local _, first = coroutine.resume(thread)
local _, second = coroutine.resume(thread)
print(first, second)
