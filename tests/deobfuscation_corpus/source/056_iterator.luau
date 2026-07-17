-- corpus: iterator; variant: 3
local data = { x = 56, y = 57, z = 58 }
local total = 0
for _, value in pairs(data) do total += value end
print(total)
