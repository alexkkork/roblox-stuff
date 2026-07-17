-- corpus: multi_return; variant: 1
local function values() return 11, 12, 13 end
local a, b, c = values()
print(c, b, a)
