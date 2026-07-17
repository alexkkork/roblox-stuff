-- corpus: iterator; variant: 4
local data = { x = 76, y = 77, z = 78 }
local total = 0
for _, value in pairs(data) do total += value end
print(total)
