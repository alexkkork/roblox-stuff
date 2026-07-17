-- corpus: closure; variant: 1
local function counter(start)
  local value = start
  return function(step) value += step; return value end
end
local nextValue = counter(8)
print(nextValue(2), nextValue(3))
