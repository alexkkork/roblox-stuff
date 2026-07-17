-- corpus: iterator; variant: 1
local data = { x = 16, y = 17, z = 18 }
local total = 0
for _, value in pairs(data) do total += value end
print(total)
