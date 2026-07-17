-- corpus: array_reduce; variant: 2
local values = {23, 24, 25, 26}
local total = 0
for _, value in ipairs(values) do total += value end
print(total)
