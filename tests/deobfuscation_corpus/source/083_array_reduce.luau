-- corpus: array_reduce; variant: 5
local values = {83, 84, 85, 86}
local total = 0
for _, value in ipairs(values) do total += value end
print(total)
