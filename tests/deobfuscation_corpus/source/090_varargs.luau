-- corpus: varargs; variant: 5
local function sum(...)
  local total = 90
  for _, value in ipairs({...}) do total += value end
  return total
end
print(sum(1, 2, 3))
