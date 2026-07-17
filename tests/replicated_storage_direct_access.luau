local replicatedStorage = game.ReplicatedStorage
assert(replicatedStorage ~= nil, "game.ReplicatedStorage must exist")
assert(replicatedStorage == game:GetService("ReplicatedStorage"))

local packages = Instance.new("Folder", replicatedStorage)
packages.Name = "Packages"
assert(game.ReplicatedStorage.Packages == packages)
assert(game:GetService("ReplicatedStorage").Packages == packages)

local shared = replicatedStorage:FindFirstChild("Shared")
if shared then
    assert(shared.Packages ~= nil)
    local networker = require(shared.Packages.Networker)
    assert(type(networker.FireServer) == "function")
end

print("replicated-storage-direct-access-ok")
