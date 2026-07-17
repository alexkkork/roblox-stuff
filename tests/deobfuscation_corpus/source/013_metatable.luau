-- corpus: metatable; variant: 1
local object = setmetatable({ value = 13 }, {
  __index = function(_, key) if key == "double" then return 26 end end
})
print(object.value, object.double)
