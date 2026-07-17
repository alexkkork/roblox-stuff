-- corpus: metatable; variant: 3
local object = setmetatable({ value = 53 }, {
  __index = function(_, key) if key == "double" then return 106 end end
})
print(object.value, object.double)
