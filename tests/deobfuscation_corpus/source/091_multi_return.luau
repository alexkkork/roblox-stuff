-- corpus: multi_return; variant: 5
local function values() return 91, 92, 93 end
local a, b, c = values()
print(c, b, a)
