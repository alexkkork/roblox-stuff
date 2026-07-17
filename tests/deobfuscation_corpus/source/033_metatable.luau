-- corpus: metatable; variant: 2
local object = setmetatable({ value = 33 }, {
  __index = function(_, key) if key == "double" then return 66 end end
})
print(object.value, object.double)
