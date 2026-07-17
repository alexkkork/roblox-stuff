-- corpus: array_reduce; variant: 1
local values = {3, 4, 5, 6}
local total = 0
for _, value in ipairs(values) do total += value end
print(total)
