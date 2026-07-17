local starterPlayer = game:GetService("StarterPlayer")
local children = starterPlayer:GetChildren()

print("STARTER_PLAYER", starterPlayer.Name, #children)
for index, child in ipairs(children) do
	print("STARTER_PLAYER_CHILD", index, child.Name, child.ClassName, child.Archivable)
end
