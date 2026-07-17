-- corpus: multi_return; variant: 3
local function values() return 51, 52, 53 end
local a, b, c = values()
print(c, b, a)
