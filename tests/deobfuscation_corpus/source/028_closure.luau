-- corpus: closure; variant: 2
local function counter(start)
  local value = start
  return function(step) value += step; return value end
end
local nextValue = counter(28)
print(nextValue(2), nextValue(3))
