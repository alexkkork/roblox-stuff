-- corpus: varargs; variant: 2
local function sum(...)
  local total = 30
  for _, value in ipairs({...}) do total += value end
  return total
end
print(sum(1, 2, 3))
