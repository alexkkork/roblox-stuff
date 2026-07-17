local exact = [[
local message = "exact source smoke"
return message
]]

local fn = loadstring(exact, "=exact_source_smoke")
return fn()
