-- corpus: multi_return; variant: 4
local function values() return 71, 72, 73 end
local a, b, c = values()
print(c, b, a)
