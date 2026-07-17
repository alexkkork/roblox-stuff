-- corpus: metatable; variant: 5
local object = setmetatable({ value = 93 }, {
  __index = function(_, key) if key == "double" then return 186 end end
})
print(object.value, object.double)
