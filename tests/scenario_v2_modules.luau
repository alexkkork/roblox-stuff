local modules = workspace:FindFirstChild("Modules")
assert(modules, "scenario v2 folder was not created")

local module = modules:FindFirstChild("FalseModule")
assert(module and module.ClassName == "ModuleScript", "scenario v2 ModuleScript was not created")

local readable = pcall(function()
    return module.Source
end)
assert(not readable, "scenario v2 host-only ModuleScript source leaked to LocalScript")
assert(require(module) == false, "scenario v2 module_sources did not preserve a legal false return")

print("scenario-v2-modules-ok")
