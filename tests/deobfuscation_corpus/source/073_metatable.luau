-- corpus: metatable; variant: 4
local object = setmetatable({ value = 73 }, {
  __index = function(_, key) if key == "double" then return 146 end end
})
print(object.value, object.double)
