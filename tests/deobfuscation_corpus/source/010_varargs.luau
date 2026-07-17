-- corpus: varargs; variant: 1
local function sum(...)
  local total = 10
  for _, value in ipairs({...}) do total += value end
  return total
end
print(sum(1, 2, 3))
