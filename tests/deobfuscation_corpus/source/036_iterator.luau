-- corpus: iterator; variant: 2
local data = { x = 36, y = 37, z = 38 }
local total = 0
for _, value in pairs(data) do total += value end
print(total)
