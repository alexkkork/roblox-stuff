-- corpus: array_reduce; variant: 4
local values = {63, 64, 65, 66}
local total = 0
for _, value in ipairs(values) do total += value end
print(total)
