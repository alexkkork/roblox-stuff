-- corpus: varargs; variant: 4
local function sum(...)
  local total = 70
  for _, value in ipairs({...}) do total += value end
  return total
end
print(sum(1, 2, 3))
