local module = game:GetService("ReplicatedStorage"):WaitForChild("SidecarModule")
assert(not pcall(function() return module.Source end), "ModuleScript.Source leaked to LocalScript")
local first = require(module)
local second = require(module)
assert(first == false and second == false, "legal false module return was not cached")
print("module-sidecar-v2-ok")
return true
