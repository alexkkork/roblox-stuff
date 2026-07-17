-- corpus: iterator; variant: 5
local data = { x = 96, y = 97, z = 98 }
local total = 0
for _, value in pairs(data) do total += value end
print(total)
