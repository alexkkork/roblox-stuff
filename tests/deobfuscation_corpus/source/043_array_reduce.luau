-- corpus: array_reduce; variant: 3
local values = {43, 44, 45, 46}
local total = 0
for _, value in ipairs(values) do total += value end
print(total)
