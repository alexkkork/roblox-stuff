local networker = require(game:GetService("ReplicatedStorage").Shared.Packages.Networker)

assert(networker[19372] == networker)
assert(networker.FireServer == networker)
assert(networker:FireServer("RE/PickupBoxes") == nil)
assert(workspace.CoreObjects ~= nil)
assert(workspace.Plots ~= nil)
assert(workspace.Eggs ~= nil)

print("wyn-networker-proxy-ok")
