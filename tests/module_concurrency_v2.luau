local modules = workspace.ModuleTests

_G.slowLoads = 0
local values = {}
local completed = 0
for index = 1, 2 do
    task.spawn(function()
        values[index] = require(modules.Slow)
        completed += 1
    end)
end
while completed < 2 do task.wait() end
assert(values[1] == false and values[2] == false)
assert(_G.slowLoads == 1)
assert(require(modules.Slow) == false and _G.slowLoads == 1)

_G.trueLoads = 0
local trueValues = {}
local trueCompleted = 0
for index = 1, 2 do
    task.spawn(function()
        trueValues[index] = require(modules.TrueValue)
        trueCompleted += 1
    end)
end
while trueCompleted < 2 do task.wait() end
assert(trueValues[1] == true and trueValues[2] == true)
assert(_G.trueLoads == 1)
assert(require(modules.TrueValue) == true and _G.trueLoads == 1)

local nilLoads = 0
_G.nilLoaded = function() nilLoads += 1 end
assert(require(modules.NilValue) == nil)
assert(require(modules.NilValue) == nil and nilLoads == 1)

local multiOk, multiError = pcall(require, modules.Multiple)
assert(not multiOk and string.find(tostring(multiError), "exactly one value", 1, true))
local cachedOk, cachedError = pcall(require, modules.Multiple)
assert(not cachedOk and string.find(tostring(cachedError), "exactly one value", 1, true))
assert(_G.multiLoads == 1)

local cycleOk, cycleError = pcall(require, modules.CycleA)
assert(not cycleOk and string.find(tostring(cycleError), "required recursively", 1, true))

for _, name in ipairs({"__rbx_native_module_declare", "__rbx_native_module_require", "__rbx_native_module_finish"}) do
    assert(_G[name] == nil, name .. " leaked into the script environment")
end

print("module-concurrency-v2-ok")
