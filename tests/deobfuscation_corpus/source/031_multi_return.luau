-- corpus: multi_return; variant: 2
local function values() return 31, 32, 33 end
local a, b, c = values()
print(c, b, a)
