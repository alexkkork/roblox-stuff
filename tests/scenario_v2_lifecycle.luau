local Players = game:GetService("Players")
local UserInputService = game:GetService("UserInputService")
local HttpService = game:GetService("HttpService")

local added, removed, characterAdded, inputBegan = 0, 0, 0, 0
Players.PlayerAdded:Connect(function(player)
    if player.Name == "FixtureGuest" then
        added += 1
        player.CharacterAdded:Connect(function(character)
            if character.Name == "FixtureCharacter" then characterAdded += 1 end
        end)
    end
end)
Players.PlayerRemoving:Connect(function(player)
    if player.Name == "FixtureGuest" then removed += 1 end
end)
UserInputService.InputBegan:Connect(function(input, processed)
    if input.KeyCode == Enum.KeyCode.A and processed == false then inputBegan += 1 end
end)

task.wait(0.06)
local guest = Players:GetPlayerByUserId(72942)
assert(guest and guest.Character and guest.Character.Name == "FixtureCharacter")
assert(added == 1 and characterAdded == 1 and inputBegan == 1)
assert(workspace.RuntimeFixtures.Probe.Transparency == 0.75)

local started = time()
assert(HttpService:GetAsync("https://fixture.test/slow") == "slow-ok")
assert(time() - started >= 0.015)
local failed, message = pcall(HttpService.GetAsync, HttpService, "https://fixture.test/error")
assert(not failed and string.find(tostring(message), "fixture-network-error", 1, true))

local first, second = workspace.RuntimeFixtures.Echo:InvokeServer("request")
assert(first == "remote-ok" and second == 729)

task.wait(0.10)
assert(Players:GetPlayerByUserId(72942) == nil and removed == 1)
assert(#Players:GetPlayers() == 1 and Players:GetPlayers()[1] == Players.LocalPlayer)

print("scenario-v2-lifecycle-ok")
