-- corpus: coroutine; variant: 3
local thread = coroutine.create(function()
  coroutine.yield(56)
  return 57
end)
local _, first = coroutine.resume(thread)
local _, second = coroutine.resume(thread)
print(first, second)
