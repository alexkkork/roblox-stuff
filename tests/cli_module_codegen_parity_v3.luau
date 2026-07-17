local module = workspace.Modules.FalseModule
local first = require(module)
local second = require(module)

assert(first == false and second == false)
print("cli-module-codegen-parity-v3-ok", tostring(first), tostring(second))
return first, second
