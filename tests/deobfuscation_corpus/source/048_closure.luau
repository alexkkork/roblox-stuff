-- corpus: closure; variant: 3
local function counter(start)
  local value = start
  return function(step) value += step; return value end
end
local nextValue = counter(48)
print(nextValue(2), nextValue(3))
