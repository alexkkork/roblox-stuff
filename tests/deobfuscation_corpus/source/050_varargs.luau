-- corpus: varargs; variant: 3
local function sum(...)
  local total = 50
  for _, value in ipairs({...}) do total += value end
  return total
end
print(sum(1, 2, 3))
