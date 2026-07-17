assert(type(game) == "userdata")
assert(typeof(game) == "Instance")
assert(game.PlaceId == 12345 and game.GameId == 67890)
assert(game.JobId == "runtime-v2-test")

local mainEnvironment = getfenv(0)
assert(mainEnvironment ~= _G)
assert(getmetatable(_G) == nil)
runtimeOnlyGlobal = 73
assert(rawget(_G, "runtimeOnlyGlobal") == nil)
_G.runtimeSharedMarker = {}

local Players = game:GetService("Players")
assert(Players.LocalPlayer.Name == "RuntimeTester")
assert(Players.LocalPlayer.UserId == 4242)

local module = workspace.Modules.Answer
assert(module.ClassName == "ModuleScript")
assert(not pcall(function() return module.Source end))
assert(module:GetAttribute("Fixture") == true)
assert(module:HasTag("Scenario"))
local first = require(module)
local second = require(module)
assert(first == second and first.value == 42)
assert(first.environment ~= mainEnvironment)
assert(first.shared == _G and first.shared.runtimeSharedMarker == _G.runtimeSharedMarker)
assert(first.module == module and first.leaked == nil)

local HttpService = game:GetService("HttpService")
assert(HttpService:GetAsync("https://fixture.test/value") == "fixture-ok")

local order = {}
table.insert(order, "start")
task.defer(function() table.insert(order, "defer") end)
task.spawn(function()
    table.insert(order, "spawn")
    task.wait()
    table.insert(order, "spawn-resume")
end)
task.delay(0, function() table.insert(order, "delay") end)
table.insert(order, "after")
task.wait(0.05)
assert(order[1] == "start" and order[2] == "spawn" and order[3] == "after")
assert(table.find(order, "defer") and table.find(order, "delay") and table.find(order, "spawn-resume"))

local folder = Instance.new("Folder", workspace)
folder.Name = "Contract"
local added, removed = 0, 0
folder.ChildAdded:Connect(function() added += 1 end)
folder.ChildRemoved:Connect(function() removed += 1 end)
local part = Instance.new("Part")
part.Name = "Block"
part:SetAttribute("Level", 7)
part:AddTag("Enemy")
part.Parent = folder
assert(part:IsA("BasePart"))
assert(folder.Block == part)
assert(part:GetFullName() == "game.Workspace.Contract.Block")
assert(part:GetAttribute("Level") == 7 and part:HasTag("Enemy"))

local clone = folder:Clone()
clone.Name = "ContractClone"
clone.Parent = workspace
assert(clone.Block ~= part)
assert(clone.Block:GetAttribute("Level") == 7)
assert(clone.Block:HasTag("Enemy"))

local hit = workspace:Raycast(Vector3.new(0, 0, -10), Vector3.new(0, 0, 20))
assert(hit ~= nil and hit.Instance ~= nil and typeof(hit.Position) == "Vector3")

local bindable = Instance.new("BindableEvent")
local payload
bindable.Event:Connect(function(value) payload = value end)
bindable:Fire("bound")
task.wait()
assert(payload == "bound")

part:Destroy()
task.wait()
assert(folder:FindFirstChild("Block") == nil)
assert(added == 1 and removed == 1)

assert(type(__rbx_instance_new) == "nil")
assert(type(__rbx_execute) == "nil")
assert(type(__rbx_http_request) == "nil")

print("runtime-v2-contract-ok", table.concat(order, ","))
return {
    contract = true,
    order = order,
    place = game.PlaceId,
}
