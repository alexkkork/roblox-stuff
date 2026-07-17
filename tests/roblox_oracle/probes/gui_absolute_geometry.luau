local frame = Instance.new("Frame")

for _, property in ipairs({
	"Size",
	"Position",
	"AnchorPoint",
	"AbsoluteSize",
	"AbsolutePosition",
	"AbsoluteRotation",
}) do
	local ok, value = pcall(function()
		return frame[property]
	end)
	print("GUI_DEFAULT", property, ok, value, typeof(value))
end

local screenGui = Instance.new("ScreenGui")
frame.Size = UDim2.fromOffset(120, 45)
frame.Position = UDim2.fromOffset(10, 20)
frame.AnchorPoint = Vector2.new(0.5, 0.5)
frame.Rotation = 15
print("GUI_EXPLICIT_UNPARENTED", frame.AbsoluteSize, frame.AbsolutePosition, frame.AbsoluteRotation)

frame.Parent = screenGui
print("GUI_SCREEN_UNPARENTED", frame.AbsoluteSize, frame.AbsolutePosition, frame.AbsoluteRotation)

screenGui.Parent = game:GetService("StarterGui")
print("GUI_SCREEN_STARTER", frame.AbsoluteSize, frame.AbsolutePosition, frame.AbsoluteRotation)

local parent = Instance.new("Frame")
parent.Size = UDim2.fromOffset(300, 200)
parent.Position = UDim2.fromOffset(50, 60)
parent.Parent = screenGui
frame.Parent = parent
frame.Size = UDim2.new(0.5, 10, 0.25, 5)
frame.Position = UDim2.new(0.25, 3, 0.5, 4)
print("GUI_NESTED", parent.AbsoluteSize, parent.AbsolutePosition, frame.AbsoluteSize, frame.AbsolutePosition, frame.AbsoluteRotation)
